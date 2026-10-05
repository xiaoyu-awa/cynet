mod base;
mod packet;
mod params;

#[cfg(test)]
mod tests;

use std::{
    collections::{HashMap, VecDeque},
    net::Ipv6Addr,
    task::{Context, Poll},
    time::Duration,
};

use tokio::time::Instant;
use tokio_util::time::{DelayQueue, delay_queue::Key as TimerKey};

use crate::{
    babel::{
        base::{
            Ae, COST_INFINITY, HelloEffect, HelloHistory, Interval, RouterId, Seqno, timestamp_now,
        },
        packet::{PacketDecoder, PacketEncoder, PacketItem, tlv::Tlv},
        params::{DurationKey, F64Key, IntervalKey, Params, U8Key},
    },
    wireguard::LinkKey,
};

pub struct NeighbourValue {
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
        // The cost MUST be strictly positive (RFC 8966 §3.4.3),
        // even if the neighbour sends an rxcost of 0.
        self.txcost.max(1).saturating_add(self.rtt_penalty())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SourceKey {
    prefix: Ipv6Addr,
    plen: u8,
    router_id: RouterId,
}

pub struct SourceValue {
    seqno: Seqno,
    metric: u16,
    gc_timer_key: TimerKey,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RouteKey {
    prefix: Ipv6Addr,
    plen: u8,
    neighbour: LinkKey,
}

pub struct RouteValue {
    router_id: RouterId,
    metric: u16,
    seqno: Seqno,
    selected: bool,
    expiry_timer_key: TimerKey,
}

pub struct PendingSeqnoRequestValue {
    seqno: Seqno,
    neighbour: Option<LinkKey>,
    resends_left: u8,
    timer_key: TimerKey,
}

pub struct PacketBuf {
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
        assert!(
            !self.encoder.is_empty(),
            "empty buffer should not be scheduled for flush"
        );
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
    RouteExpiry(RouteKey),
    SeqnoRequest(SourceKey),
    OutgoingPacket(LinkKey),
}

pub enum Output {
    Packet(LinkKey, Box<[u8]>),
}

pub struct State {
    params: Params,
    seqno: Seqno,
    hello_seqno: Seqno,
    hello_timer_key: TimerKey,
    hellos_until_ihu: u8,
    update_timer_key: TimerKey,
    neighbour_table: HashMap<LinkKey, NeighbourValue>,
    source_table: HashMap<SourceKey, SourceValue>,
    route_table: HashMap<RouteKey, RouteValue>,
    pending_seqno_request_table: HashMap<SourceKey, PendingSeqnoRequestValue>,
    outputs: VecDeque<Output>,
    timers: DelayQueue<Timeout>,
    receive_timestamp: u32,
    hello_timestamp: Option<u32>,
    ihu_timestamps: Option<(u32, u32)>,
}

impl State {
    pub fn new(params: Params, seqno: Option<Seqno>) -> Self {
        let mut timers = DelayQueue::new();

        let hello_timer_key = timers.insert(Timeout::OutgoingHello, Duration::ZERO);
        let update_timer_key = timers.insert(Timeout::OutgoingUpdate, Duration::ZERO);

        let hellos_until_ihu = params.get_u8(U8Key::HellosPerIhu);

        Self {
            params,
            seqno: seqno.unwrap_or_else(|| Seqno::new(rand::random())),
            hello_seqno: Seqno::new(rand::random()),
            hello_timer_key,
            hellos_until_ihu,
            update_timer_key,
            neighbour_table: HashMap::new(),
            source_table: HashMap::new(),
            route_table: HashMap::new(),
            pending_seqno_request_table: HashMap::new(),
            outputs: VecDeque::new(),
            timers,
            receive_timestamp: 0,
            hello_timestamp: None,
            ihu_timestamps: None,
        }
    }

    pub fn add_neighbour(&mut self, key: LinkKey) -> bool {
        if self.neighbour_table.contains_key(&key) {
            return false;
        }
        self.neighbour_table
            .insert(key, NeighbourValue::new(&self.params));
        true
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
                // TODO: Send periodic updates (RFC 8966 §3.7.1).

                self.update_timer_key = self.timers.insert(
                    Timeout::OutgoingUpdate,
                    self.params.get_duration(DurationKey::UpdateInterval),
                );
            }
            Timeout::IncomingHello(key) => {
                let neigh = self.neighbour_table.get_mut(&key).unwrap();

                if neigh.hello_history.missed() == HelloEffect::Flush {
                    neigh.hello_timer_key = None;
                    neigh.flush(&mut self.timers);
                } else {
                    let timeout = neigh.last_hello_interval.unwrap().to_duration();
                    neigh.hello_timer_key =
                        Some(self.timers.insert(Timeout::IncomingHello(key), timeout));
                }

                // TODO: Run the route selection procedure.
            }
            Timeout::IncomingIhu(key) => {
                let neigh = self.neighbour_table.get_mut(&key).unwrap();
                neigh.ihu_timer_key = None;
                neigh.txcost = COST_INFINITY;

                // TODO: Run the route selection procedure.
            }
            Timeout::SourceGc(_key) => todo!(),
            Timeout::RouteExpiry(_key) => todo!(),
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
        self.hello_timestamp = None;
        self.ihu_timestamps = None;

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
                PacketItem::Update(_) => todo!("handle update"),
            }
        }

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
                    *rtt = ALPHA * *rtt + (1.0 - ALPHA) * rtt_n;
                } else {
                    *rtt = Some(rtt_n);
                }
            }
        }
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
            Tlv::Acknowledgement { .. } => todo!(),
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

                // TODO: Run the route selection procedure.
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

                // TODO: Run the route selection procedure.
            }
            Tlv::RouteRequest { .. } => todo!(),
            Tlv::SeqnoRequest { .. } => todo!(),
        }
    }
}
