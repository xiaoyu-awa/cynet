mod base;
mod defaults;
mod packet;
mod tlv;

use std::{
    collections::{HashMap, VecDeque},
    net::Ipv6Addr,
};

use tokio_util::time::{DelayQueue, delay_queue::Key as TimerKey};

use crate::{
    babel::{
        base::{HelloHistory, RouterId, Seqno},
        tlv::Tlv,
    },
    wireguard::LinkKey,
};

pub struct NeighbourValue {
    hello_history: HelloHistory,
    txcost: u16,
    hello_timer_key: TimerKey,
    ihu_timer_key: TimerKey,
}

pub struct NeighbourTable {
    table: HashMap<LinkKey, NeighbourValue>,
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

pub struct SourceTable {
    table: HashMap<SourceKey, SourceValue>,
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

pub struct RouteTable {
    table: HashMap<RouteKey, RouteValue>,
}

pub struct PendingSeqnoRequestValue {
    seqno: Seqno,
    neighbour: Option<LinkKey>,
    resends_left: u8,
    timer_key: TimerKey,
}

pub struct PendingSeqnoRequestTable {
    table: HashMap<SourceKey, PendingSeqnoRequestValue>,
}

pub enum Timeout {
    OutgoingHello,
    OutgoingUpdate,
    IncomingHello(LinkKey),
    IncomingIhu(LinkKey),
    SourceGc(SourceKey),
    RouteExpiry(RouteKey),
    SeqnoRequest(SourceKey),
    OutgoingTlv,
}

pub struct State {
    seqno: Seqno,
    hello_seqno: Seqno,
    hello_timer_key: TimerKey,
    hellos_until_ihu: u8,
    update_timer_key: TimerKey,
    neighbour_table: NeighbourTable,
    source_table: SourceTable,
    route_table: RouteTable,
    pending_seqno_request_table: PendingSeqnoRequestTable,
    timeout_queue: DelayQueue<Timeout>,
    tlv_buffer: VecDeque<(Tlv, Option<LinkKey>)>,
}
