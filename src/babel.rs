mod base;
mod packet;
mod params;

#[cfg(test)]
mod tests;

use std::{
    assert_matches,
    cell::Cell,
    collections::{HashMap, HashSet, VecDeque, hash_map},
    hash::Hash,
    mem,
    net::Ipv6Addr,
    num::NonZeroU8,
    task::{Context, Poll},
    time::Duration,
};

use ipnet::Ipv6Net;
use slotmap::{SecondaryMap, SlotMap, SparseSecondaryMap, sparse_secondary};
use tokio::time::Instant;
use tokio_util::time::{DelayQueue, delay_queue::Key as TimerKey};

use crate::babel::{
    base::{
        Ae, COST_INFINITY, HelloEffect, HelloHistory, Interval, METRIC_INFINITY, RouterId, Seqno,
        timestamp_now,
    },
    packet::{PacketDecoder, PacketEncoder, PacketItem, Update, tlv::Tlv},
    params::{DurationKey, F64Key, IntervalKey, Params, U8Key},
};

slotmap::new_key_type! {
    /// Identifies a neighbour internally.
    pub struct NeighKey;
}

/// A one-to-one mapping between internal neighbour keys and external ones that
/// identify the same neighbours elsewhere, such as WireGuard public keys.
pub struct NeighKeyMap<K> {
    inward: HashMap<K, NeighKey>,
    outward: SecondaryMap<NeighKey, K>,
}

impl<K: Copy + Eq + Hash> NeighKeyMap<K> {
    pub fn new() -> Self {
        Self {
            inward: HashMap::new(),
            outward: SecondaryMap::new(),
        }
    }

    /// Maps `external` and `internal` to each other. Neither may be mapped already.
    pub fn insert(&mut self, external: K, internal: NeighKey) {
        assert!(
            !self.inward.contains_key(&external) && !self.outward.contains_key(internal),
            "keys should not be mapped already"
        );
        self.inward.insert(external, internal);
        self.outward.insert(internal, external);
    }

    /// Returns the corresponding internal key, if any.
    pub fn internal(&self, external: K) -> Option<NeighKey> {
        self.inward.get(&external).copied()
    }

    /// Returns the corresponding external key, if any.
    pub fn external(&self, internal: NeighKey) -> Option<K> {
        self.outward.get(internal).copied()
    }
}

struct NeighValue {
    hello_history: HelloHistory,
    txcost: u16,
    /// The link cost, as last computed by [`Self::update_cost`].
    cost: u16,
    last_hello_interval: Option<Interval>,
    hello_timer_key: Option<TimerKey>,
    ihu_timer_key: Option<TimerKey>,
    packet_buf: PacketBuf,
    origin_receive_timestamps: Option<(u32, u32)>,
    rtt: Option<f64>,
}

impl NeighValue {
    fn new(params: &Params) -> Self {
        Self {
            hello_history: HelloHistory::new(),
            txcost: COST_INFINITY,
            cost: COST_INFINITY,
            last_hello_interval: None,
            hello_timer_key: None,
            ihu_timer_key: None,
            packet_buf: PacketBuf {
                // Leave room for IPv6 and UDP headers (RFC 8966 §4).
                encoder: PacketEncoder::new(params.get_mtu() as usize - 48),
                flush_timer_key: None,
            },
            origin_receive_timestamps: None,
            rtt: None,
        }
    }

    /// Flushes the neighbour entry, except for the Hello history, which accounts for
    /// the Hello that caused the flush, if any, and the packet buffer, whose TLVs are
    /// still to be sent.
    fn flush(&mut self, timers: &mut DelayQueue<Timeout>) {
        if let Some(key) = self.hello_timer_key.take() {
            timers.remove(&key);
        }
        if let Some(key) = self.ihu_timer_key.take() {
            timers.remove(&key);
        }
        self.txcost = COST_INFINITY;
        self.last_hello_interval = None;
        self.origin_receive_timestamps = None;
        self.rtt = None;
    }

    /// Computes the rxcost by 2-out-of-3 link sensing with a nominal cost of 96
    /// (RFC 8966 Appendix A.2.1, Appendix B).
    fn rxcost(&self) -> u16 {
        const NOMINAL_COST: u16 = 96;

        let last_3 = self.hello_history.bits() & 0b111;
        if last_3.count_ones() >= 2 {
            NOMINAL_COST
        } else {
            COST_INFINITY
        }
    }

    /// Maps the smoothed RTT to a penalty: none up to rtt-min, rising linearly
    /// to max-rtt-penalty at rtt-max, and constant above (RFC 9616 §4.2).
    fn rtt_penalty(&self) -> u16 {
        const RTT_MIN: f64 = 10_000.0;
        const RTT_MAX: f64 = 120_000.0;
        const MAX_RTT_PENALTY: f64 = 150.0;

        let Some(rtt) = self.rtt else {
            return 0;
        };
        let penalty =
            (rtt.clamp(RTT_MIN, RTT_MAX) - RTT_MIN) / (RTT_MAX - RTT_MIN) * MAX_RTT_PENALTY;
        penalty.round_ties_even() as u16
    }

    /// Updates the link cost: infinite if the rxcost is infinite, and otherwise
    /// the txcost as with k-out-of-j link sensing (RFC 8966 Appendix A.2.1), plus
    /// the RTT penalty (RFC 9616 §4.2). Returns whether the cost has changed.
    fn update_cost(&mut self) -> bool {
        let old_cost = self.cost;
        self.cost = if self.rxcost() == COST_INFINITY {
            COST_INFINITY
        } else {
            // The cost MUST be strictly positive (RFC 8966 §3.4.3).
            self.txcost.saturating_add(self.rtt_penalty()).max(1)
        };
        self.cost != old_cost
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SourceKey {
    prefix: Ipv6Net,
    router_id: RouterId,
}

struct SourceValue {
    seqno: Seqno,
    metric: u16,
    gc_timer_key: TimerKey,
}

struct RouteValue {
    router_id: RouterId,
    advertised_metric: u16,
    // These are kept in cells and can be modified through a shared borrow, so that
    // `select_route` can update them up front and keep the borrow for later comparison.
    metric: Cell<u16>,
    /// The smoothed metric at `metric_smoothed_at`, since when `metric` has not changed.
    metric_smoothed: Cell<f32>,
    /// A timestamp, as returned by [`timestamp_now`].
    metric_smoothed_at: Cell<u32>,
    seqno: Seqno,
    expiry_timer_key: TimerKey,
}

impl RouteValue {
    /// Returns the smoothed metric at `now`, smoothing the metric exponentially with
    /// the time constant `tau` (RFC 8966 Appendix A.3).
    fn ms_at(&self, now: u32, tau: u32) -> f32 {
        let ms = self.metric_smoothed.get();
        let dt = now.wrapping_sub(self.metric_smoothed_at.get());
        if dt == 0 {
            return ms;
        }
        // Since the metric m has been constant since t0:
        // ms(t) = m + (ms(t0) - m) exp(-(t - t0) / τ)
        let m = self.metric.get() as f32;
        m + (ms - m) * (-(dt as f32) / (tau as f32)).exp()
    }

    /// Sets the metric at `now`, after smoothing the previous one up to then.
    /// This must be done whenever the route is updated.
    fn set_metric(&self, metric: u16, now: u32, tau: u32) {
        // Timestamps wrap around every 2^32 µs, about 72 minutes. A route is updated
        // within its expiry time, at most 3.5 × 655.35 s, about 38 minutes, or removed,
        // so re-anchoring once older than 2^30 µs keeps the anchor within range.
        const MAX_ANCHOR_AGE: u32 = 1 << 30;

        if metric == self.metric.get()
            && now.wrapping_sub(self.metric_smoothed_at.get()) < MAX_ANCHOR_AGE
        {
            // The smoothed metric continues to follow the same curve.
            return;
        }
        self.metric_smoothed.set(self.ms_at(now, tau));
        self.metric_smoothed_at.set(now);
        self.metric.set(metric);
    }

    /// Checks whether the route is feasible (RFC 8966 §3.5.1). The feasibility
    /// distances change as updates are sent, so this is checked whenever it matters.
    fn is_feasible(&self, prefix: Ipv6Net, source_table: &HashMap<SourceKey, SourceValue>) -> bool {
        let key = SourceKey {
            prefix,
            router_id: self.router_id,
        };
        source_table.get(&key).is_none_or(|source| {
            source.seqno.lt(self.seqno)
                || (self.seqno == source.seqno && self.advertised_metric < source.metric)
        })
    }

    /// Checks whether the route may be selected, that is, whether it is feasible and its
    /// metric is finite (RFC 8966 §3.6).
    fn is_usable(&self, prefix: Ipv6Net, source_table: &HashMap<SourceKey, SourceValue>) -> bool {
        self.metric.get() != METRIC_INFINITY && self.is_feasible(prefix, source_table)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteState {
    Local,
    Selected(NeighKey),
    Held(TimerKey),
    Removed,
}

impl RouteState {
    /// Returns the selected next-hop neighbour, if any.
    fn selected(self) -> Option<NeighKey> {
        match self {
            Self::Selected(key) => Some(key),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Advert {
    router_id: RouterId,
    seqno: Seqno,
    metric: u16,
}

struct PrefixRouteTable {
    routes: SparseSecondaryMap<NeighKey, RouteValue>,
    state: RouteState,
    advert: Option<Advert>,
}

impl PrefixRouteTable {
    fn new() -> Self {
        Self {
            routes: SparseSecondaryMap::new(),
            state: RouteState::Removed,
            advert: None,
        }
    }
}

struct RouteTable {
    by_prefix: HashMap<Ipv6Net, PrefixRouteTable>,
    neigh_prefixes: SecondaryMap<NeighKey, HashSet<Ipv6Net>>,
}

impl RouteTable {
    fn new() -> Self {
        Self {
            by_prefix: HashMap::new(),
            neigh_prefixes: SecondaryMap::new(),
        }
    }

    fn insert_local(&mut self, prefix: Ipv6Net) -> bool {
        match self.by_prefix.entry(prefix) {
            hash_map::Entry::Occupied(_) => false,
            hash_map::Entry::Vacant(e) => {
                let mut table = PrefixRouteTable::new();
                table.state = RouteState::Local;
                e.insert(table);
                true
            }
        }
    }

    fn get_or_insert_with(
        &mut self,
        prefix: Ipv6Net,
        key: NeighKey,
        f: impl FnOnce() -> RouteValue,
    ) -> Option<&mut RouteValue> {
        let table = self
            .by_prefix
            .entry(prefix)
            .or_insert_with(PrefixRouteTable::new);

        match table.routes.entry(key).unwrap() {
            sparse_secondary::Entry::Occupied(e) => Some(e.into_mut()),
            sparse_secondary::Entry::Vacant(e) => {
                assert!(self.neigh_prefixes[key].insert(prefix));
                e.insert(f());
                None
            }
        }
    }

    fn remove(&mut self, prefix: &Ipv6Net, key: NeighKey) -> Option<RouteValue> {
        let route = self.by_prefix.get_mut(prefix)?.routes.remove(key)?;
        assert!(self.neigh_prefixes[key].remove(prefix));
        Some(route)
    }
}

struct PendingSeqnoRequestValue {
    seqno: Seqno,
    neigh_key: Option<NeighKey>,
    resends_left: u8,
    timer_key: TimerKey,
}

struct PacketBuf {
    encoder: PacketEncoder,
    // `None` iff `encoder.is_empty()`.
    flush_timer_key: Option<TimerKey>,
}

impl PacketBuf {
    fn flush(&mut self, key: NeighKey, outputs: &mut VecDeque<Output>) {
        assert!(
            !self.encoder.is_empty(),
            "empty buffer should not be flushed"
        );

        let buf = self.encoder.finalize().to_vec().into_boxed_slice();
        outputs.push_back(Output::Packet(key, buf));
        self.encoder.clear();
    }

    fn put(
        &mut self,
        key: NeighKey,
        outputs: &mut VecDeque<Output>,
        timers: &mut DelayQueue<Timeout>,
        params: &Params,
        f: impl Fn(&mut PacketEncoder) -> bool,
    ) {
        let was_empty = self.encoder.is_empty();

        // In all other cases, the TLV SHOULD be sent out within one-half of the
        // Multicast Hello interval (RFC 8966 §3.1).
        //
        // We take half of that and multiply it by 0.75 ~ 1.25, as outgoing TLVs SHOULD
        // be sent with a random delay (RFC 8966 §3.1).
        //
        // A Hello then waits at most 0.3125 Hello intervals, so consecutive Hellos
        // are at most 1.3125 intervals apart, within the 1.5 intervals after which a
        // neighbour counts a Hello as missed.
        let timeout = || {
            params
                .get_duration(DurationKey::HelloInterval)
                .mul_f64(rand::random_range(0.1875..=0.3125))
        };

        if !f(&mut self.encoder) {
            // Encoding failed. The buffer is full. Flush it now.
            self.flush(key, outputs);

            timers.reset(&self.flush_timer_key.unwrap(), timeout());

            assert!(
                f(&mut self.encoder),
                "encoding into empty buffer should succeed"
            );
        } else if was_empty {
            // Encoding succeeded. The buffer was empty. Set a timer to flush it.
            assert!(self.flush_timer_key.is_none());

            self.flush_timer_key = Some(timers.insert(Timeout::OutgoingPacket(key), timeout()));
        }
    }

    fn schedule_flush(&mut self, timers: &mut DelayQueue<Timeout>, timeout: Duration) {
        if self.encoder.is_empty() {
            return;
        }

        let key = self.flush_timer_key.unwrap();

        // Take half of the timeout and add some jitter as in `put`.
        let timeout = timeout.mul_f64(rand::random_range(0.375..=0.625));
        let new_deadline = Instant::now() + timeout;
        let deadline = timers.deadline(&key);

        if new_deadline < deadline {
            timers.reset_at(&key, new_deadline);
        }
    }
}

pub enum Timeout {
    OutgoingHello,
    OutgoingUpdate,
    IncomingHello(NeighKey),
    IncomingIhu(NeighKey),
    SourceGc(SourceKey),
    RouteExpiry(Ipv6Net, NeighKey),
    RouteHold(Ipv6Net),
    SeqnoRequest(SourceKey),
    OutgoingPacket(NeighKey),
}

pub enum Output {
    Packet(NeighKey, Box<[u8]>),
    RouteSelect(Ipv6Net, NeighKey),
    RouteHold(Ipv6Net),
    RouteRemove(Ipv6Net),
}

pub struct State {
    params: Params,
    router_id: RouterId,
    seqno: Seqno,
    hello_seqno: Seqno,
    hello_timer_key: TimerKey,
    hellos_until_ihu: u8,
    update_timer_key: TimerKey,
    neigh_table: SlotMap<NeighKey, NeighValue>,
    source_table: HashMap<SourceKey, SourceValue>,
    route_table: RouteTable,
    pending_seqno_request_table: HashMap<SourceKey, PendingSeqnoRequestValue>,
    outputs: VecDeque<Output>,
    timers: DelayQueue<Timeout>,
    /// The current timestamp, as returned by [`timestamp_now`],
    /// taken as a packet or a timeout starts being handled.
    /// For a packet, it is the receive timestamp (RFC 9616 §3.1).
    now: u32,
    // Temporary states for each received packet.
    /// The prefixes whose routes through the sender have been added, modified or removed
    /// by updates other than wildcard retractions. One prefix may appear more than once.
    updated_prefixes: Vec<Ipv6Net>,
    /// The prefixes whose routes through the sender have been removed
    /// by the first wildcard retraction, if any.
    wildcard_retracted_prefixes: Option<HashSet<Ipv6Net>>,
    hello_timestamp: Option<u32>,
    ihu_timestamps: Option<(u32, u32)>,
}

impl State {
    pub fn new(params: Params, router_id: RouterId, seqno: Option<Seqno>) -> Self {
        let mut timers = DelayQueue::new();

        let hello_timer_key = timers.insert(Timeout::OutgoingHello, Duration::ZERO);
        let update_timer_key = timers.insert(Timeout::OutgoingUpdate, Duration::ZERO);

        let hellos_until_ihu = params.get_u8(U8Key::HellosPerIhu);

        Self {
            params,
            router_id,
            seqno: seqno.unwrap_or_else(|| Seqno::new(rand::random())),
            hello_seqno: Seqno::new(rand::random()),
            hello_timer_key,
            hellos_until_ihu,
            update_timer_key,
            neigh_table: SlotMap::with_key(),
            source_table: HashMap::new(),
            route_table: RouteTable::new(),
            pending_seqno_request_table: HashMap::new(),
            outputs: VecDeque::new(),
            timers,
            now: 0,
            updated_prefixes: Vec::new(),
            wildcard_retracted_prefixes: None,
            hello_timestamp: None,
            ihu_timestamps: None,
        }
    }

    pub fn add_neigh(&mut self) -> NeighKey {
        let key = self.neigh_table.insert(NeighValue::new(&self.params));
        self.route_table.neigh_prefixes.insert(key, HashSet::new());
        key
    }

    pub fn add_local_route(&mut self, prefix: Ipv6Net) -> bool {
        self.route_table.insert_local(prefix.trunc())
    }

    pub fn poll_timeout(&mut self, cx: &mut Context<'_>) -> Poll<Option<Timeout>> {
        self.timers
            .poll_expired(cx)
            .map(|o| o.map(|e| e.into_inner()))
    }

    pub fn poll_output(&mut self) -> Option<Output> {
        self.outputs.pop_front()
    }

    pub fn handle_timeout(&mut self, timeout: Timeout) {
        self.now = timestamp_now();

        match timeout {
            Timeout::OutgoingHello => {
                let hello_tlv = Tlv::Hello {
                    seqno: self.hello_seqno,
                    interval: Some(self.params.get_interval(IntervalKey::Hello)),
                    transmit_timestamp: Some(0),
                };

                self.hellos_until_ihu -= 1;
                let ihu_interval = if self.hellos_until_ihu == 0 {
                    self.hellos_until_ihu = self.params.get_u8(U8Key::HellosPerIhu);
                    Some(self.params.get_interval(IntervalKey::Ihu))
                } else {
                    None
                };

                for (key, neigh) in &mut self.neigh_table {
                    let rxcost = neigh.rxcost();
                    let origin_receive_timestamps = neigh.origin_receive_timestamps;

                    neigh.packet_buf.put(
                        key,
                        &mut self.outputs,
                        &mut self.timers,
                        &self.params,
                        |e| {
                            let hello_tlv = hello_tlv.clone();
                            if let Some(interval) = ihu_interval {
                                let ihu_tlv = Tlv::Ihu {
                                    ae: Ae::Wildcard,
                                    rxcost,
                                    interval,
                                    address: [0; 8],
                                    origin_receive_timestamps,
                                };
                                e.put_tlvs(&[hello_tlv, ihu_tlv])
                            } else {
                                e.put_tlv(&hello_tlv)
                            }
                        },
                    )
                }

                self.hello_seqno += 1;
                self.hello_timer_key = self.timers.insert(
                    Timeout::OutgoingHello,
                    self.params.get_duration(DurationKey::HelloInterval),
                );
            }
            Timeout::OutgoingUpdate => {
                self.dump_routes(None);

                self.update_timer_key = self.timers.insert(
                    Timeout::OutgoingUpdate,
                    self.params.get_duration(DurationKey::UpdateInterval),
                );
            }
            Timeout::IncomingHello(key) => {
                let neigh = &mut self.neigh_table[key];

                if neigh.hello_history.missed() == HelloEffect::Flush {
                    neigh.hello_timer_key = None;
                    neigh.flush(&mut self.timers);

                    for prefix in self.remove_neigh_routes(key) {
                        self.select_route(prefix, Some(key));
                    }
                } else {
                    let timeout = neigh.last_hello_interval.unwrap().to_duration();
                    neigh.hello_timer_key =
                        Some(self.timers.insert(Timeout::IncomingHello(key), timeout));

                    if neigh.update_cost() {
                        self.neigh_cost_changed(key);
                    }
                }
            }
            Timeout::IncomingIhu(key) => {
                let neigh = &mut self.neigh_table[key];

                neigh.ihu_timer_key = None;
                neigh.txcost = COST_INFINITY;

                if neigh.update_cost() {
                    self.neigh_cost_changed(key);
                }
            }
            Timeout::SourceGc(key) => {
                assert!(self.source_table.remove(&key).is_some());
                self.select_route(key.prefix, None);
            }
            Timeout::RouteExpiry(prefix, key) => {
                assert!(self.route_table.remove(&prefix, key).is_some());
                self.select_route(prefix, Some(key));
            }
            Timeout::RouteHold(prefix) => {
                let table = self.route_table.by_prefix.get_mut(&prefix).unwrap();
                assert_matches!(table.state, RouteState::Held(_));

                self.outputs.push_back(Output::RouteRemove(prefix));

                if table.routes.is_empty() {
                    // Nothing is left to keep the entry for.
                    self.route_table.by_prefix.remove(&prefix);
                } else {
                    table.state = RouteState::Removed;
                    table.advert = None;
                }
            }
            Timeout::SeqnoRequest(_source_key) => todo!(),
            Timeout::OutgoingPacket(key) => {
                let buf = &mut self.neigh_table[key].packet_buf;
                buf.flush_timer_key = None;
                buf.flush(key, &mut self.outputs);
            }
        }
    }

    pub fn handle_packet(&mut self, from: NeighKey, buf: &[u8]) {
        // Malformed packets, and TLVs that fail to decode or are otherwise
        // ignored, are silently ignored (RFC 8966 §4.2, §4.3, §4.4, §4.6).
        let Some(decoder) = PacketDecoder::new(buf) else {
            return;
        };

        self.now = timestamp_now();

        for res in decoder {
            let Ok(item) = res else {
                continue;
            };
            match item {
                PacketItem::Tlv(tlv) => self.handle_tlv(from, &tlv),
                PacketItem::Update(update) => self.handle_update(from, &update),
            }
        }

        // Delay-based metric extension (RFC 9616).
        if let (Some(t2p), Some((t1, t1p))) = (self.hello_timestamp, self.ihu_timestamps) {
            let t2 = self.now;

            let d = t2.wrapping_sub(t1);
            let dp = t2p.wrapping_sub(t1p);

            const T: u32 = 3 * 60_000_000;
            const ALPHA: f64 = 0.836;

            if d <= T && dp <= T {
                let rtt = &mut self.neigh_table[from].rtt;
                let rtt_n = d.saturating_sub(dp) as f64;

                if let Some(rtt) = rtt {
                    // RTT := α RTT + (1 - α) RTTn
                    *rtt = ALPHA * (*rtt - rtt_n) + rtt_n;
                } else {
                    *rtt = Some(rtt_n);
                }
            }
        }

        // Route selection waits until the whole packet has been handled, so that it uses
        // the link cost as changed by the packet's Hellos, IHUs and timestamps. It runs
        // first for every route through the sender if the cost has changed, as they all
        // have a new metric now.
        if self.neigh_table[from].update_cost() {
            self.neigh_cost_changed(from);
        }

        // Then for the prefixes retracted by the first wildcard retraction, if any.
        if let Some(prefixes) = self.wildcard_retracted_prefixes.take() {
            for prefix in prefixes {
                self.select_route(prefix, Some(from));
            }
        }

        // And finally for the prefixes updated by non-wildcard updates. Selection may
        // run more than once for a prefix, but running again is harmless: nothing has
        // changed since the last run, so it makes the same choice and outputs nothing.
        // It is also rare: it only happens in a packet that both changes the link cost
        // and carries updates, or one that updates a prefix more than once.
        // Deduplication, by contrast, would cost something on every packet.
        let mut prefixes = mem::take(&mut self.updated_prefixes);
        for prefix in prefixes.drain(..) {
            self.select_route(prefix, Some(from));
        }
        self.updated_prefixes = prefixes;

        self.hello_timestamp = None;
        self.ihu_timestamps = None;
    }

    fn handle_tlv(&mut self, from: NeighKey, tlv: &Tlv) {
        match *tlv {
            Tlv::Pad1 | Tlv::PadN { .. } | Tlv::RouterId { .. } => {}
            Tlv::Update { .. } => unreachable!(),
            Tlv::AcknowledgementRequest { opaque, interval } => {
                let timeout = interval.to_duration();
                let tlv = Tlv::Acknowledgement { opaque };
                self.send(Some(from), None, Some(timeout), &PacketItem::Tlv(tlv));
            }
            Tlv::Acknowledgement { .. } => {
                // Ignore it as we never send a request.
            }
            Tlv::Hello {
                seqno,
                interval,
                transmit_timestamp,
            } => {
                let neigh = &mut self.neigh_table[from];

                if neigh.hello_history.received(seqno) == HelloEffect::Flush {
                    neigh.flush(&mut self.timers);
                }

                if let Some(interval) = interval {
                    neigh.last_hello_interval = Some(interval);

                    // Reset the neighbour's hello timer to 1.5 times the advertised
                    // Interval (the extra margin allows for delay due to jitter)
                    // (RFC 8966 Appendix A.1). See also `PacketBuf::put`.
                    let timeout = interval.to_duration().mul_f64(1.5);

                    if let Some(timer_key) = neigh.hello_timer_key {
                        self.timers.reset(&timer_key, timeout);
                    } else {
                        neigh.hello_timer_key =
                            Some(self.timers.insert(Timeout::IncomingHello(from), timeout));
                    }
                }

                if let Some(t) = transmit_timestamp {
                    neigh.origin_receive_timestamps = Some((t, self.now));
                    self.hello_timestamp = Some(t);
                }
            }
            Tlv::Ihu {
                ae: _,
                rxcost,
                interval,
                address: _,
                origin_receive_timestamps,
            } => {
                let neigh = &mut self.neigh_table[from];

                let timeout = interval
                    .to_duration()
                    .mul_f64(self.params.get_f64(F64Key::IhuHoldTimeMultiplier));

                if let Some(timer_key) = neigh.ihu_timer_key {
                    self.timers.reset(&timer_key, timeout);
                } else {
                    neigh.ihu_timer_key =
                        Some(self.timers.insert(Timeout::IncomingIhu(from), timeout));
                }

                if let Some(ts) = origin_receive_timestamps {
                    self.ihu_timestamps = Some(ts);
                }

                neigh.txcost = rxcost;
            }
            Tlv::RouteRequest { ae, plen, prefix } => {
                self.handle_route_request(from, ae, plen, prefix);
            }
            Tlv::SeqnoRequest {
                ae,
                plen,
                seqno,
                hop_count,
                router_id,
                prefix,
            } => {
                if ae != Ae::Ipv6 {
                    return;
                }
                let prefix = Ipv6Net::new_assert(Ipv6Addr::from_octets(prefix), plen);
                self.handle_seqno_request(from, seqno, hop_count, router_id, prefix);
            }
        }
    }

    /// Answers a route request (RFC 8966 §3.8.1.1, RFC 9229 §2.3).
    fn handle_route_request(&mut self, from: NeighKey, ae: Ae, plen: u8, prefix: [u8; 16]) {
        if ae == Ae::Wildcard {
            // TODO: Full route table dumps SHOULD be rate-limited.
            self.dump_routes(Some(from));
            return;
        }

        let advert = match ae {
            Ae::Ipv6 => {
                let prefix = Ipv6Net::new_assert(Ipv6Addr::from_octets(prefix), plen);
                let table = self.route_table.by_prefix.get(&prefix);
                let advert = table.and_then(|table| self.advert_for_prefix(table));

                if let Some(advert) = advert {
                    self.update_source_table(prefix, advert);
                }
                advert
            }
            Ae::Ipv4 | Ae::V4ViaV6 => None,
            Ae::Wildcard | Ae::LinkLocalIpv6 => unreachable!(),
        };

        // The local router-id and seqno are used for retracting an unknown route.
        let advert = advert.unwrap_or(Advert {
            router_id: self.router_id,
            seqno: self.seqno,
            metric: METRIC_INFINITY,
        });

        let update = Update {
            ae,
            plen,
            interval: self.params.get_interval(IntervalKey::Update),
            seqno: advert.seqno,
            metric: advert.metric,
            prefix,
            router_id: Some(advert.router_id),
        };

        self.send(Some(from), None, None, &PacketItem::Update(update));
    }

    /// Answers a seqno request (RFC 8966 §3.8.1.2).
    fn handle_seqno_request(
        &mut self,
        from: NeighKey,
        seqno: Seqno,
        hop_count: NonZeroU8,
        router_id: RouterId,
        prefix: Ipv6Net,
    ) {
        let Some(table) = self.route_table.by_prefix.get(&prefix) else {
            return;
        };

        let Some(mut advert) = self.advert_for_prefix(table) else {
            return;
        };

        if advert.metric == METRIC_INFINITY {
            return;
        }

        if advert.router_id != router_id || !advert.seqno.lt(seqno) {
            self.send_update(Some(from), None, true, prefix, advert);
            return;
        } else if self.router_id == router_id {
            self.seqno += 1;
            advert.seqno = self.seqno;

            self.send_update(Some(from), None, true, prefix, advert);
            return;
        }

        let Some(hop_count) = NonZeroU8::new(hop_count.get() - 1) else {
            return;
        };

        // TODO: A node SHOULD compare every incoming seqno request against its list of
        // recently forwarded seqno requests and avoid forwarding the request if it is
        // redundant (i.e., if the node has recently sent a request with the same prefix,
        // router-id, and a seqno that is not smaller modulo 2^16).

        // Forward the request to the next hop of a route that is not through the requester,
        // a feasible one if there is any, with the smallest metric.
        let feasible = |r: &RouteValue| r.is_feasible(prefix, &self.source_table);
        let Some((to, _)) = table
            .routes
            .iter()
            .filter(|&(k, _)| k != from)
            .min_by_key(|&(k, r)| (!feasible(r), r.metric.get(), k))
        else {
            return;
        };

        self.send_seqno_request(Some(to), true, prefix, router_id, seqno, Some(hop_count));
    }

    fn send_seqno_request(
        &mut self,
        to: Option<NeighKey>,
        urgent: bool,
        prefix: Ipv6Net,
        router_id: RouterId,
        seqno: Seqno,
        hop_count: Option<NonZeroU8>,
    ) {
        const DEFAULT_HOP_COUNT: NonZeroU8 = NonZeroU8::new(64).unwrap();

        let timeout = urgent.then(|| self.params.get_duration(DurationKey::UrgentTimeout));

        let tlv = Tlv::SeqnoRequest {
            ae: Ae::Ipv6,
            plen: prefix.prefix_len(),
            seqno,
            hop_count: hop_count.unwrap_or(DEFAULT_HOP_COUNT),
            router_id,
            prefix: prefix.addr().octets(),
        };

        self.send(to, None, timeout, &PacketItem::Tlv(tlv));
    }

    /// Handles an update (RFC 8966 §3.5.3), recording its prefix for route selection at
    /// the end of the packet.
    fn handle_update(&mut self, from: NeighKey, update: &Update) {
        let Update {
            ae,
            plen,
            interval,
            seqno,
            metric,
            prefix,
            router_id,
        } = *update;

        if ae == Ae::Wildcard {
            // Wildcard retraction.
            assert_eq!(metric, METRIC_INFINITY);

            let prefixes = self.remove_neigh_routes(from);

            // If this is not the first wildcard retraction in the packet, it only removes
            // routes added by updates since the first one, whose prefixes are already
            // recorded in `updated_prefixes`, so we don't need to record them again.
            if self.wildcard_retracted_prefixes.is_none() {
                self.wildcard_retracted_prefixes = Some(prefixes);
            }
            return;
        }

        if ae != Ae::Ipv6 {
            return;
        }

        let prefix = Ipv6Net::new_assert(Ipv6Addr::from_octets(prefix), plen);

        if metric == METRIC_INFINITY {
            if let Some(route) = self.route_table.remove(&prefix, from) {
                self.timers.remove(&route.expiry_timer_key);
                self.updated_prefixes.push(prefix);
            }
            return;
        }

        let router_id = router_id.unwrap();

        if router_id == self.router_id {
            // Do not maintain a route supposedly to the node itself.
            return;
        }

        let expiry_time = interval
            .to_duration()
            .mul_f64(self.params.get_f64(F64Key::RouteExpiryTimeMultiplier));

        if let Some(route) = self
            .route_table
            .get_or_insert_with(prefix, from, || RouteValue {
                router_id,
                advertised_metric: metric,
                metric: Cell::new(METRIC_INFINITY),
                metric_smoothed: Cell::new(METRIC_INFINITY as f32),
                metric_smoothed_at: Cell::new(self.now),
                seqno,
                expiry_timer_key: self
                    .timers
                    .insert(Timeout::RouteExpiry(prefix, from), expiry_time),
            })
        {
            route.router_id = router_id;
            route.advertised_metric = metric;
            route.seqno = seqno;

            self.timers.reset(&route.expiry_timer_key, expiry_time);
        }

        self.updated_prefixes.push(prefix);
    }

    /// Removes the routes through a neighbour along with their expiry timers,
    /// returning their prefixes.
    fn remove_neigh_routes(&mut self, key: NeighKey) -> HashSet<Ipv6Net> {
        let prefixes = mem::take(&mut self.route_table.neigh_prefixes[key]);
        for prefix in &prefixes {
            let table = self.route_table.by_prefix.get_mut(prefix).unwrap();
            let route = table.routes.remove(key).unwrap();
            self.timers.remove(&route.expiry_timer_key);
        }
        prefixes
    }

    fn neigh_cost_changed(&mut self, key: NeighKey) {
        let prefixes = mem::take(&mut self.route_table.neigh_prefixes[key]);
        for prefix in &prefixes {
            self.select_route(*prefix, Some(key));
        }
        self.route_table.neigh_prefixes[key] = prefixes;
    }

    /// Runs route selection (RFC 8966 §3.6) for a prefix, after its route through the
    /// `changed` neighbour has been added, modified or removed, or that neighbour's link
    /// cost has changed, or, with no `changed` neighbour, after a source table entry for
    /// the prefix has expired.
    ///
    /// Selection is incremental. While the selected route or the changed one is usable,
    /// only these two are compared, with hysteresis. All routes are considered only when
    /// the selected route changes and becomes unusable, or when a source table entry
    /// expires while nothing is selected. A better route that has not changed is only
    /// switched to when it is next updated, which its neighbour does at least once per
    /// Update interval.
    fn select_route(&mut self, prefix: Ipv6Net, changed: Option<NeighKey>) {
        // A prefix may have no entry: a source table entry can outlive it, and selection
        // may have already removed it for a prefix recorded more than once in a packet.
        let Some(table) = self.route_table.by_prefix.get_mut(&prefix) else {
            return;
        };

        // The route through the changed neighbour, unless it has been removed.
        let changed_route = changed.and_then(|key| table.routes.get(key));

        if let (Some(key), Some(route)) = (changed, changed_route) {
            let cost = self.neigh_table[key].cost;
            let metric = route.advertised_metric.saturating_add(cost);
            route.set_metric(metric, self.now, self.params.get_tau());
        }

        if table.state == RouteState::Local {
            return;
        }

        let usable = |r: &RouteValue| r.is_usable(prefix, &self.source_table);
        let best_usable = || {
            // If no route to a given destination is selected, then select the route with
            // the smallest metric, ignoring the smoothed metric.
            table
                .routes
                .iter()
                .filter(|(_, r)| usable(r))
                .min_by_key(|&(k, r)| (r.metric.get(), k))
        };

        // The route through the changed neighbour, if it is still there and usable.
        let candidate = changed.zip(changed_route).filter(|(_, r)| usable(r));

        let selection = match table.state {
            RouteState::Local => unreachable!(),
            // The selected route has not changed, so it is still usable: only advertising
            // tightens feasibility, and advertising the selected route keeps it feasible.
            // This includes the expiry of a source table entry, with no changed route.
            RouteState::Selected(key) if changed != Some(key) => {
                let selected = &table.routes[key];
                debug_assert!(usable(selected));

                let ms = |r: &RouteValue| r.ms_at(self.now, self.params.get_tau());

                // If a route R is selected, then switch to a route R' only when both
                // m(R') < m(R) and ms(R') < ms(R).
                if let Some((_, route)) = candidate
                    && route.metric < selected.metric
                    && ms(route) < ms(selected)
                {
                    candidate
                } else {
                    Some((key, selected))
                }
            }
            // The selected route has changed. Keep it if it is still usable, or else
            // select the best usable route.
            RouteState::Selected(_) => candidate.or_else(best_usable),
            // Nothing is selected, so no route is usable: one only becomes usable without
            // changing as its source table entry expires. So select the changed route if
            // it is usable, or after such an expiry, the best usable route.
            RouteState::Held(_) | RouteState::Removed => match changed {
                Some(_) => candidate,
                None => best_usable(),
            },
        };

        let mut update_urgent = None;

        if let Some((key, route)) = selection {
            match table.state {
                RouteState::Local => unreachable!(),
                RouteState::Selected(_) => {
                    let old_router_id = table.advert.unwrap().router_id;
                    if route.router_id != old_router_id {
                        // Whenever it changes the selected router-id for a given destination,
                        // a node MUST send an update as an urgent TLV (RFC 8966 §3.7.2).
                        update_urgent = Some(true);
                    }
                }
                RouteState::Held(key) => {
                    self.timers.remove(&key);
                    // The prefix is reachable again after a retraction. A node MAY send a
                    // triggered update when the metric for a given prefix changes in a
                    // significant manner (RFC 8966 §3.7.2), so tell neighbours now rather
                    // than at the next periodic update.
                    update_urgent = Some(false);
                }
                RouteState::Removed => {
                    // The prefix is newly reachable, so likewise announce it now.
                    update_urgent = Some(false);
                }
            }

            if table.state != RouteState::Selected(key) {
                self.outputs.push_back(Output::RouteSelect(prefix, key));
            }

            table.state = RouteState::Selected(key);
            table.advert = Some(Advert {
                router_id: route.router_id,
                seqno: route.seqno,
                metric: route.metric.get(),
            });
        } else if let RouteState::Selected(_) = table.state {
            // When a route is retracted, a node SHOULD send a triggered update
            // (RFC 8966 §3.7.2).
            update_urgent = Some(false);

            self.outputs.push_back(Output::RouteHold(prefix));

            table.state = RouteState::Held(self.timers.insert(
                Timeout::RouteHold(prefix),
                self.params.get_duration(DurationKey::RouteHoldTime),
            ));
            table.advert.as_mut().unwrap().metric = METRIC_INFINITY;
        }

        // A removed prefix without routes has nothing left to keep its entry for.
        let empty = table.state == RouteState::Removed && table.routes.is_empty();

        if let Some(urgent) = update_urgent {
            // Split horizon (RFC 8966 §3.7.4).
            let not_to = table.state.selected();
            let advert = table.advert.unwrap();
            self.send_update(None, not_to, urgent, prefix, advert);
        }

        if empty {
            self.route_table.by_prefix.remove(&prefix);
        }
    }

    fn send_update(
        &mut self,
        to: Option<NeighKey>,
        not_to: Option<NeighKey>,
        urgent: bool,
        prefix: Ipv6Net,
        advert: Advert,
    ) {
        self.update_source_table(prefix, advert);

        let timeout = urgent.then(|| self.params.get_duration(DurationKey::UrgentTimeout));

        let update = Update {
            ae: Ae::Ipv6,
            plen: prefix.prefix_len(),
            interval: self.params.get_interval(IntervalKey::Update),
            seqno: advert.seqno,
            metric: advert.metric,
            prefix: prefix.addr().octets(),
            router_id: Some(advert.router_id),
        };

        self.send(to, not_to, timeout, &PacketItem::Update(update));
    }

    /// Sends a full dump of the routes that this node advertises,
    /// to every neighbour or to the given one.
    fn dump_routes(&mut self, to: Option<NeighKey>) {
        struct Update {
            prefix: Ipv6Net,
            router_id: RouterId,
            seqno: Seqno,
            metric: u16,
            not_to: Option<NeighKey>,
        }

        let mut updates: Vec<_> = self
            .route_table
            .by_prefix
            .iter()
            .filter_map(|(&prefix, table)| {
                self.advert_for_prefix(table).map(|advert| Update {
                    prefix,
                    router_id: advert.router_id,
                    seqno: advert.seqno,
                    metric: advert.metric,
                    // Split horizon (RFC 8966 §3.7.4).
                    not_to: table.state.selected(),
                })
            })
            .collect();

        // By router-id, those with the router-id omitted first, then by prefix, whose
        // derived order is by address, then by length.
        updates.sort_unstable_by_key(|u| {
            let omitted = u.router_id.get() == u.prefix.addr().to_bits() as u64;
            (u.router_id, !omitted, u.prefix)
        });

        for u in updates {
            let advert = Advert {
                router_id: u.router_id,
                seqno: u.seqno,
                metric: u.metric,
            };
            self.send_update(to, u.not_to, false, u.prefix, advert);
        }
    }

    fn send(
        &mut self,
        to: Option<NeighKey>,
        not_to: Option<NeighKey>,
        timeout: Option<Duration>,
        item: &PacketItem,
    ) {
        let mut send = |key, neigh: &mut NeighValue| {
            neigh.packet_buf.put(
                key,
                &mut self.outputs,
                &mut self.timers,
                &self.params,
                |e| match item {
                    PacketItem::Tlv(tlv) => e.put_tlv(tlv),
                    PacketItem::Update(update) => e.put_update(update),
                },
            );

            if let Some(timeout) = timeout {
                neigh.packet_buf.schedule_flush(&mut self.timers, timeout);
            }
        };

        if let Some(key) = to {
            if not_to != Some(key) {
                send(key, &mut self.neigh_table[key]);
            }
        } else {
            for (key, neigh) in &mut self.neigh_table {
                if not_to != Some(key) {
                    send(key, neigh);
                }
            }
        }
    }

    /// Returns the router-id, seqno, and metric to advertise for the prefix,
    /// or the local router-id and seqno and a zero metric for a local route,
    /// or `None` for a removed route.
    fn advert_for_prefix(&self, table: &PrefixRouteTable) -> Option<Advert> {
        match table.state {
            // A route injected by this node (RFC 8966 §3.7).
            RouteState::Local => Some(Advert {
                router_id: self.router_id,
                seqno: self.seqno,
                metric: 0,
            }),
            _ => table.advert,
        }
    }

    fn update_source_table(&mut self, prefix: Ipv6Net, advert: Advert) {
        let Advert {
            router_id,
            seqno,
            metric,
        } = advert;

        if metric != METRIC_INFINITY {
            let key = SourceKey { prefix, router_id };
            let gc_time = self.params.get_duration(DurationKey::SourceGcTime);

            match self.source_table.entry(key) {
                hash_map::Entry::Occupied(e) => {
                    let v = e.into_mut();
                    if v.seqno.lt(seqno) {
                        v.seqno = seqno;
                        v.metric = metric;
                    } else if v.seqno == seqno && v.metric > metric {
                        v.metric = metric;
                    }
                    self.timers.reset(&v.gc_timer_key, gc_time);
                }
                hash_map::Entry::Vacant(e) => {
                    e.insert(SourceValue {
                        seqno,
                        metric,
                        gc_timer_key: self.timers.insert(Timeout::SourceGc(key), gc_time),
                    });
                }
            }
        }
    }
}
