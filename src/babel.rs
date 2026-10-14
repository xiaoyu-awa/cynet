mod base;
mod packet;
mod params;

#[cfg(test)]
mod tests;

use std::{
    assert_matches,
    cmp::Ordering,
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    net::Ipv6Addr,
    task::{Context, Poll},
    time::Duration,
};

use ipnet::Ipv6Net;
use tokio::time::Instant;
use tokio_util::time::{DelayQueue, delay_queue::Key as TimerKey};

use crate::{
    babel::{
        base::{
            Ae, COST_INFINITY, HelloEffect, HelloHistory, Interval, METRIC_INFINITY, RouterId,
            Seqno, timestamp_now,
        },
        packet::{PacketDecoder, PacketEncoder, PacketItem, Update, tlv::Tlv},
        params::{DurationKey, F64Key, IntervalKey, Params, U8Key},
    },
    wireguard::LinkKey,
};

struct NeighbourValue {
    hello_history: HelloHistory,
    txcost: u16,
    last_hello_interval: Option<Interval>,
    hello_timer_key: Option<TimerKey>,
    ihu_timer_key: Option<TimerKey>,
    packet_buf: PacketBuf,
    origin_receive_timestamps: Option<(u32, u32)>,
    rtt: Option<f64>,
}

impl NeighbourValue {
    fn new(params: &Params) -> Self {
        Self {
            hello_history: HelloHistory::new(),
            txcost: COST_INFINITY,
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

    /// Computes the link cost: infinite if the rxcost or the txcost is, and otherwise
    /// the txcost as with k-out-of-j link sensing (RFC 8966 Appendix A.2.1), plus the
    /// RTT penalty (RFC 9616 §4.2).
    fn cost(&self) -> u16 {
        if self.rxcost() == COST_INFINITY {
            return COST_INFINITY;
        }
        // The cost MUST be strictly positive (RFC 8966 §3.4.3).
        self.txcost.saturating_add(self.rtt_penalty()).max(1)
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
    metric: u16,
    metric_smoothed: f64,
    seqno: Seqno,
    feasible: bool,
    expiry_timer_key: TimerKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteState {
    Local,
    Selected(LinkKey),
    Held(TimerKey),
    Removed,
}

struct PrefixRouteTable {
    table: HashMap<LinkKey, RouteValue>,
    state: RouteState,
    update: Option<(RouterId, Seqno, u16)>,
    metric_smoothed_at: Instant,
}

impl PrefixRouteTable {
    fn new() -> Self {
        Self {
            table: HashMap::new(),
            state: RouteState::Removed,
            update: None,
            metric_smoothed_at: Instant::now(),
        }
    }
}

struct RouteTable {
    by_prefix: HashMap<Ipv6Net, PrefixRouteTable>,
    neigh_prefixes: HashMap<LinkKey, HashSet<Ipv6Net>>,
}

impl RouteTable {
    fn new() -> Self {
        Self {
            by_prefix: HashMap::new(),
            neigh_prefixes: HashMap::new(),
        }
    }

    fn insert_local(&mut self, prefix: Ipv6Net) -> bool {
        match self.by_prefix.entry(prefix) {
            Entry::Occupied(_) => false,
            Entry::Vacant(e) => {
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
        neigh: LinkKey,
        f: impl FnOnce() -> RouteValue,
    ) -> Option<&mut RouteValue> {
        let table = self
            .by_prefix
            .entry(prefix)
            .or_insert_with(PrefixRouteTable::new);

        match table.table.entry(neigh) {
            Entry::Occupied(e) => Some(e.into_mut()),
            Entry::Vacant(e) => {
                e.insert(f());
                assert!(self.neigh_prefixes.entry(neigh).or_default().insert(prefix));
                None
            }
        }
    }

    fn remove(&mut self, prefix: &Ipv6Net, neigh: &LinkKey) -> Option<RouteValue> {
        let route = self.by_prefix.get_mut(prefix)?.table.remove(neigh)?;
        assert!(self.neigh_prefixes.get_mut(neigh).unwrap().remove(prefix));
        Some(route)
    }

    /// Returns the prefixes of the routes through a neighbour.
    fn neighbour_prefixes(&self, neigh: &LinkKey) -> Vec<Ipv6Net> {
        let Some(prefixes) = self.neigh_prefixes.get(neigh) else {
            return Vec::new();
        };
        prefixes.iter().copied().collect()
    }
}

struct PendingSeqnoRequestValue {
    seqno: Seqno,
    neighbour: Option<LinkKey>,
    resends_left: u8,
    timer_key: TimerKey,
}

struct PacketBuf {
    encoder: PacketEncoder,
    // `None` iff `encoder.is_empty()`.
    flush_timer_key: Option<TimerKey>,
}

impl PacketBuf {
    fn flush(&mut self, key: &LinkKey, outputs: &mut VecDeque<Output>) {
        assert!(
            !self.encoder.is_empty(),
            "empty buffer should not be flushed"
        );

        let buf = self.encoder.finalize().to_vec().into_boxed_slice();
        outputs.push_back(Output::Packet(*key, buf));
        self.encoder.clear();
    }

    fn put(
        &mut self,
        key: &LinkKey,
        outputs: &mut VecDeque<Output>,
        timers: &mut DelayQueue<Timeout>,
        params: &Params,
        f: impl Fn(&mut PacketEncoder) -> bool,
    ) {
        let was_empty = self.encoder.is_empty();

        let timeout = || {
            params
                .get_duration(DurationKey::HelloInterval)
                .mul_f64(params.get_f64(F64Key::BufferTimeoutMultiplier))
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

            self.flush_timer_key = Some(timers.insert(Timeout::OutgoingPacket(*key), timeout()));
        }
    }

    fn schedule_flush(&mut self, timers: &mut DelayQueue<Timeout>, timeout: Duration) {
        if self.encoder.is_empty() {
            return;
        }

        let key = self.flush_timer_key.unwrap();

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
    IncomingHello(LinkKey),
    IncomingIhu(LinkKey),
    SourceGc(SourceKey),
    RouteExpiry(Ipv6Net, LinkKey),
    RouteHold(Ipv6Net),
    SeqnoRequest(SourceKey),
    OutgoingPacket(LinkKey),
}

pub enum Output {
    Packet(LinkKey, Box<[u8]>),
    RouteSelect(Ipv6Net, LinkKey),
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
    neighbour_table: HashMap<LinkKey, NeighbourValue>,
    source_table: HashMap<SourceKey, SourceValue>,
    route_table: RouteTable,
    pending_seqno_request_table: HashMap<SourceKey, PendingSeqnoRequestValue>,
    outputs: VecDeque<Output>,
    timers: DelayQueue<Timeout>,
    // Temporary states for each received packet.
    receive_timestamp: u32,
    hello_timestamp: Option<u32>,
    ihu_timestamps: Option<(u32, u32)>,
    updated_prefixes: HashSet<Ipv6Net>,
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
            neighbour_table: HashMap::new(),
            source_table: HashMap::new(),
            route_table: RouteTable::new(),
            pending_seqno_request_table: HashMap::new(),
            outputs: VecDeque::new(),
            timers,
            receive_timestamp: 0,
            hello_timestamp: None,
            ihu_timestamps: None,
            updated_prefixes: HashSet::new(),
        }
    }

    pub fn add_neighbour(&mut self, key: LinkKey) -> bool {
        match self.neighbour_table.entry(key) {
            Entry::Occupied(_) => false,
            Entry::Vacant(e) => {
                e.insert(NeighbourValue::new(&self.params));
                true
            }
        }
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

                for (key, neigh) in &mut self.neighbour_table {
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
                self.send_periodic_updates();

                self.update_timer_key = self.timers.insert(
                    Timeout::OutgoingUpdate,
                    self.params.get_duration(DurationKey::UpdateInterval),
                );
            }
            Timeout::IncomingHello(key) => {
                let neigh = self.neighbour_table.get_mut(&key).unwrap();

                let prefixes = if neigh.hello_history.missed() == HelloEffect::Flush {
                    neigh.hello_timer_key = None;
                    neigh.flush(&mut self.timers);

                    self.remove_neighbour_routes(&key)
                } else {
                    let timeout = neigh.last_hello_interval.unwrap().to_duration();
                    neigh.hello_timer_key =
                        Some(self.timers.insert(Timeout::IncomingHello(key), timeout));

                    self.route_table.neighbour_prefixes(&key)
                };

                self.select_routes(&prefixes);
            }
            Timeout::IncomingIhu(key) => {
                let neigh = self.neighbour_table.get_mut(&key).unwrap();
                neigh.ihu_timer_key = None;
                neigh.txcost = COST_INFINITY;

                self.select_routes(&self.route_table.neighbour_prefixes(&key));
            }
            Timeout::SourceGc(key) => {
                assert!(self.source_table.remove(&key).is_some());
            }
            Timeout::RouteExpiry(prefix, key) => {
                assert!(self.route_table.remove(&prefix, &key).is_some());
                self.select_routes(&[prefix]);
            }
            Timeout::RouteHold(prefix) => {
                let table = self.route_table.by_prefix.get_mut(&prefix).unwrap();
                assert_matches!(table.state, RouteState::Held(_));

                self.outputs.push_back(Output::RouteRemove(prefix));

                if table.table.is_empty() {
                    // Nothing is left to keep the entry for.
                    self.route_table.by_prefix.remove(&prefix);
                } else {
                    table.state = RouteState::Removed;
                    table.update = None;
                }
            }
            Timeout::SeqnoRequest(_key) => todo!(),
            Timeout::OutgoingPacket(key) => {
                let buf = &mut self.neighbour_table.get_mut(&key).unwrap().packet_buf;
                buf.flush_timer_key = None;
                buf.flush(&key, &mut self.outputs);
            }
        }
    }

    pub fn handle_packet(&mut self, key: &LinkKey, buf: &[u8]) {
        self.receive_timestamp = timestamp_now();

        // Malformed packets, and TLVs that fail to decode or are otherwise
        // ignored, are silently ignored (RFC 8966 §4.2, §4.3, §4.4, §4.6).
        let Some(decoder) = PacketDecoder::new(buf) else {
            return;
        };

        for res in decoder {
            let Ok(item) = res else {
                continue;
            };
            match item {
                PacketItem::Tlv(tlv) => self.handle_tlv(key, &tlv),
                PacketItem::Update(update) => self.handle_update(key, &update),
            }
        }

        // Delay-based metric extension (RFC 9616).
        if let (Some(t2p), Some((t1, t1p))) = (self.hello_timestamp, self.ihu_timestamps) {
            let t2 = self.receive_timestamp;

            let d = t2.wrapping_sub(t1);
            let dp = t2p.wrapping_sub(t1p);

            const T: u32 = 3 * 60_000_000;
            const ALPHA: f64 = 0.836;

            if d <= T && dp <= T {
                let rtt = &mut self.neighbour_table.get_mut(key).unwrap().rtt;
                let rtt_n = d.saturating_sub(dp) as f64;

                if let Some(rtt) = rtt {
                    // RTT := α RTT + (1 - α) RTTn
                    *rtt = ALPHA * (*rtt - rtt_n) + rtt_n;
                } else {
                    *rtt = Some(rtt_n);
                }
            }
        }

        self.hello_timestamp = None;
        self.ihu_timestamps = None;

        let prefixes: Vec<_> = self.updated_prefixes.drain().collect();
        self.select_routes(&prefixes);
    }

    fn handle_tlv(&mut self, key: &LinkKey, tlv: &Tlv) {
        let neigh = self.neighbour_table.get_mut(key).unwrap();

        match *tlv {
            Tlv::Pad1 | Tlv::PadN { .. } | Tlv::RouterId { .. } => {}
            Tlv::Update { .. } => unreachable!(),
            Tlv::AcknowledgementRequest { opaque, interval } => {
                neigh.packet_buf.put(
                    key,
                    &mut self.outputs,
                    &mut self.timers,
                    &self.params,
                    |e| e.put_tlv(&Tlv::Acknowledgement { opaque }),
                );

                let timeout = interval
                    .to_duration()
                    .mul_f64(self.params.get_f64(F64Key::BufferTimeoutMultiplier));

                neigh.packet_buf.schedule_flush(&mut self.timers, timeout);
            }
            Tlv::Acknowledgement { .. } => {
                // Ignore it as we never send a request.
            }
            Tlv::Hello {
                seqno,
                interval,
                transmit_timestamp,
            } => {
                if neigh.hello_history.received(seqno) == HelloEffect::Flush {
                    neigh.flush(&mut self.timers);
                }

                if let Some(interval) = interval {
                    neigh.last_hello_interval = Some(interval);

                    let timeout = interval
                        .to_duration()
                        .mul_f64(self.params.get_f64(F64Key::HelloTimeoutMultiplier));

                    if let Some(timer_key) = neigh.hello_timer_key {
                        self.timers.reset(&timer_key, timeout);
                    } else {
                        neigh.hello_timer_key =
                            Some(self.timers.insert(Timeout::IncomingHello(*key), timeout));
                    }
                }

                if let Some(t) = transmit_timestamp {
                    neigh.origin_receive_timestamps = Some((t, self.receive_timestamp));
                    self.hello_timestamp = Some(t);
                }

                // The link cost may change.
                let prefixes = self.route_table.neighbour_prefixes(key);
                self.updated_prefixes.extend(prefixes);
            }
            Tlv::Ihu {
                ae: _,
                rxcost,
                interval,
                address: _,
                origin_receive_timestamps,
            } => {
                let timeout = interval
                    .to_duration()
                    .mul_f64(self.params.get_f64(F64Key::IhuHoldTimeMultiplier));

                if let Some(timer_key) = neigh.ihu_timer_key {
                    self.timers.reset(&timer_key, timeout);
                } else {
                    neigh.ihu_timer_key =
                        Some(self.timers.insert(Timeout::IncomingIhu(*key), timeout));
                }

                if let Some(ts) = origin_receive_timestamps {
                    self.ihu_timestamps = Some(ts);
                }

                neigh.txcost = rxcost;

                // The link cost may change.
                let prefixes = self.route_table.neighbour_prefixes(key);
                self.updated_prefixes.extend(prefixes);
            }
            Tlv::RouteRequest { .. } => todo!(),
            Tlv::SeqnoRequest { .. } => todo!(),
        }
    }

    fn handle_update(&mut self, neigh: &LinkKey, update: &Update) {
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
            let prefixes = self.remove_neighbour_routes(neigh);
            self.updated_prefixes.extend(prefixes);
            return;
        }

        if ae != Ae::Ipv6 {
            return;
        }

        let prefix = Ipv6Net::new_assert(Ipv6Addr::from_octets(prefix), plen);

        if metric == METRIC_INFINITY {
            if let Some(route) = self.route_table.remove(&prefix, neigh) {
                self.timers.remove(&route.expiry_timer_key);
                self.updated_prefixes.insert(prefix);
            }
            return;
        }

        let router_id = router_id.unwrap();

        let expiry_time = interval
            .to_duration()
            .mul_f64(self.params.get_f64(F64Key::RouteExpiryTimeMultiplier));

        if let Some(route) = self
            .route_table
            .get_or_insert_with(prefix, *neigh, || RouteValue {
                router_id,
                advertised_metric: metric,
                metric: METRIC_INFINITY,
                metric_smoothed: METRIC_INFINITY as f64,
                seqno,
                // Computed at route selection.
                feasible: false,
                expiry_timer_key: self
                    .timers
                    .insert(Timeout::RouteExpiry(prefix, *neigh), expiry_time),
            })
        {
            route.router_id = router_id;
            route.advertised_metric = metric;
            route.seqno = seqno;

            self.timers.reset(&route.expiry_timer_key, expiry_time);
        }

        self.updated_prefixes.insert(prefix);
    }

    /// Removes the routes through a neighbour along with their expiry timers,
    /// returning their prefixes.
    fn remove_neighbour_routes(&mut self, neigh: &LinkKey) -> Vec<Ipv6Net> {
        let Some(prefixes) = self.route_table.neigh_prefixes.get_mut(neigh) else {
            return Vec::new();
        };

        let mut removed = Vec::with_capacity(prefixes.len());
        for prefix in prefixes.drain() {
            let table = self.route_table.by_prefix.get_mut(&prefix).unwrap();
            let route = table.table.remove(neigh).unwrap();
            self.timers.remove(&route.expiry_timer_key);
            removed.push(prefix);
        }
        removed
    }

    /// Runs route selection (RFC 8966 §3.6) for the given prefixes, after updating
    /// the metric and feasibility of their routes.
    fn select_routes(&mut self, prefixes: &[Ipv6Net]) {
        let tau = self
            .params
            .get_duration(DurationKey::RouteHysteresisTimeConstant);
        let now = Instant::now();

        for &prefix in prefixes {
            let table = self.route_table.by_prefix.get_mut(&prefix).unwrap();

            let k = (-(now - table.metric_smoothed_at).div_duration_f64(tau)).exp_m1();
            table.metric_smoothed_at = now;

            for (neigh, route) in &mut table.table {
                // Route hysteresis (RFC 8966 Appendix A.3):
                //  α = 1 - exp(-ΔT / τ)
                // ms = α m + (1 - α) ms
                //    = ms + expm1(-ΔT / τ) * (ms - m)
                route.metric_smoothed += k * (route.metric_smoothed - route.metric as f64);

                let cost = self.neighbour_table[neigh].cost();
                route.metric = route.advertised_metric.saturating_add(cost);

                // The feasibility distances change as updates are sent,
                // so a route may become unfeasible after it is received.
                route.feasible = self
                    .source_table
                    .get(&SourceKey {
                        prefix,
                        router_id: route.router_id,
                    })
                    .is_none_or(|source| {
                        source.seqno.lt(route.seqno)
                            || (route.seqno == source.seqno
                                && route.advertised_metric < source.metric)
                    });
            }

            if table.state == RouteState::Local {
                continue;
            }

            let current = match table.state {
                RouteState::Selected(neigh) => table
                    .table
                    .get_key_value(&neigh)
                    .filter(|(_, r)| r.feasible && r.metric != METRIC_INFINITY),
                _ => None,
            };

            // If no route to a given destination is selected,
            // then select the route with the smallest metric,
            // ignoring the smoothed metric. If a route R is selected,
            // then switch to a route R' only when both m(R') < m(R) and ms(R') < ms(R).
            let selection = if let Some((_, route)) = current {
                table
                    .table
                    .iter()
                    .filter(|(_, r)| {
                        r.feasible
                            && r.metric < route.metric
                            && r.metric_smoothed < route.metric_smoothed
                    })
                    .min_by(|(ka, ra), (kb, rb)| {
                        ra.metric_smoothed
                            .total_cmp(&rb.metric_smoothed)
                            .then(ra.metric.cmp(&rb.metric))
                            .then(ka.as_bytes().cmp(kb.as_bytes()))
                    })
                    .or(current)
            } else {
                table
                    .table
                    .iter()
                    .filter(|(_, r)| r.feasible && r.metric != METRIC_INFINITY)
                    .min_by(|(ka, ra), (kb, rb)| {
                        ra.metric
                            .cmp(&rb.metric)
                            .then(ra.metric_smoothed.total_cmp(&rb.metric_smoothed))
                            .then(ka.as_bytes().cmp(kb.as_bytes()))
                    })
            };

            let mut update_urgent = None;

            if let Some((neigh, route)) = selection {
                match table.state {
                    RouteState::Local => unreachable!(),
                    RouteState::Selected(_) => {
                        let (old_router_id, _, _) = table.update.unwrap();
                        if route.router_id != old_router_id {
                            // Router-id changed. Send an urgent triggered update.
                            update_urgent = Some(true);
                        }
                    }
                    RouteState::Held(key) => {
                        self.timers.remove(&key);
                        // New route ending a hold. Send a triggered update.
                        update_urgent = Some(false);
                    }
                    RouteState::Removed => {
                        // New route. Send a triggered update.
                        update_urgent = Some(false);
                    }
                }

                if table.state != RouteState::Selected(*neigh) {
                    self.outputs.push_back(Output::RouteSelect(prefix, *neigh));
                }

                table.state = RouteState::Selected(*neigh);
                table.update = Some((route.router_id, route.seqno, route.metric));
            } else if let RouteState::Selected(_) = table.state {
                // Retraction. Send a triggered update.
                update_urgent = Some(false);

                self.outputs.push_back(Output::RouteHold(prefix));

                table.state = RouteState::Held(self.timers.insert(
                    Timeout::RouteHold(prefix),
                    self.params.get_duration(DurationKey::RouteHoldTime),
                ));
                table.update.as_mut().unwrap().2 = METRIC_INFINITY;
            }

            // A removed prefix without routes has nothing left to keep its entry for.
            let empty = table.state == RouteState::Removed && table.table.is_empty();

            if let Some(urgent) = update_urgent {
                let (router_id, seqno, metric) = table.update.unwrap();
                let next_hop = selection.map(|t| *t.0);
                self.send_triggered_update(urgent, next_hop, prefix, router_id, seqno, metric);
            }

            if empty {
                self.route_table.by_prefix.remove(&prefix);
            }
        }
    }

    fn send_triggered_update(
        &mut self,
        urgent: bool,
        next_hop: Option<LinkKey>,
        prefix: Ipv6Net,
        router_id: RouterId,
        seqno: Seqno,
        metric: u16,
    ) {
        self.update_source_table(prefix, router_id, seqno, metric);

        let update = Update {
            ae: Ae::Ipv6,
            plen: prefix.prefix_len(),
            interval: self.params.get_interval(IntervalKey::Update),
            seqno,
            metric,
            prefix: prefix.addr().octets(),
            router_id: Some(router_id),
        };

        let urgent_timeout = urgent.then(|| self.params.get_duration(DurationKey::UrgentTimeout));

        for (key, neigh) in &mut self.neighbour_table {
            // Split horizon (RFC 8966 §3.7.4).
            if next_hop == Some(*key) {
                continue;
            }

            neigh.packet_buf.put(
                key,
                &mut self.outputs,
                &mut self.timers,
                &self.params,
                |e| e.put_update(&update),
            );

            if let Some(timeout) = urgent_timeout {
                neigh.packet_buf.schedule_flush(&mut self.timers, timeout);
            }
        }
    }

    fn send_periodic_updates(&mut self) {
        struct Update {
            prefix: Ipv6Net,
            router_id: RouterId,
            seqno: Seqno,
            metric: u16,
            router_id_omitted: bool,
        }

        impl Ord for Update {
            fn cmp(&self, other: &Self) -> Ordering {
                self.router_id
                    .cmp(&other.router_id)
                    .then(other.router_id_omitted.cmp(&self.router_id_omitted))
                    .then(self.prefix.addr().cmp(&other.prefix.addr()))
                    .then(self.prefix.prefix_len().cmp(&other.prefix.prefix_len()))
            }
        }

        impl PartialOrd for Update {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Eq for Update {}

        impl PartialEq for Update {
            fn eq(&self, other: &Self) -> bool {
                self.prefix == other.prefix && self.router_id == other.router_id
            }
        }

        let mut updates: Vec<_> = self
            .route_table
            .by_prefix
            .iter()
            .filter_map(|(prefix, table)| {
                let update = match table.state {
                    // A route injected by this node (RFC 8966 §3.7).
                    RouteState::Local => Some((self.router_id, self.seqno, 0)),
                    _ => table.update,
                };
                update.map(|(router_id, seqno, metric)| Update {
                    prefix: *prefix,
                    router_id,
                    seqno,
                    metric,
                    router_id_omitted: router_id.get()
                        == u64::from_be_bytes(*prefix.addr().octets().last_chunk().unwrap()),
                })
            })
            .collect();

        updates.sort_unstable();

        let interval = self.params.get_interval(IntervalKey::Update);

        for Update {
            prefix,
            router_id,
            seqno,
            metric,
            ..
        } in updates
        {
            let state = self.route_table.by_prefix[&prefix].state;

            self.update_source_table(prefix, router_id, seqno, metric);

            let update = packet::Update {
                ae: Ae::Ipv6,
                plen: prefix.prefix_len(),
                interval,
                seqno,
                metric,
                prefix: prefix.addr().octets(),
                router_id: Some(router_id),
            };

            for (key, neigh) in &mut self.neighbour_table {
                // Split horizon (RFC 8966 §3.7.4).
                if state == RouteState::Selected(*key) {
                    continue;
                }

                neigh.packet_buf.put(
                    key,
                    &mut self.outputs,
                    &mut self.timers,
                    &self.params,
                    |e| e.put_update(&update),
                );
            }
        }
    }

    fn update_source_table(
        &mut self,
        prefix: Ipv6Net,
        router_id: RouterId,
        seqno: Seqno,
        metric: u16,
    ) {
        if metric != METRIC_INFINITY {
            let key = SourceKey { prefix, router_id };
            let gc_time = self.params.get_duration(DurationKey::SourceGcTime);

            match self.source_table.entry(key) {
                Entry::Occupied(e) => {
                    let v = e.into_mut();
                    if v.seqno.lt(seqno) {
                        v.seqno = seqno;
                        v.metric = metric;
                    } else if v.seqno == seqno && v.metric > metric {
                        v.metric = metric;
                    }
                    self.timers.reset(&v.gc_timer_key, gc_time);
                }
                Entry::Vacant(e) => {
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
