//! A view of a Babel router's state, as returned by
//! [`State::snapshot`](crate::babel::State::snapshot).

use std::time::Duration;

use ipnet::IpNet;

use crate::babel::{RouterId, Seqno};

/// A view of a Babel router's state, with neighbours identified by `K`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot<K> {
    /// The router-id of this node.
    pub router_id: RouterId,
    /// The seqno of this node.
    pub seqno: Seqno,
    /// Every neighbour.
    pub neighbours: Vec<NeighbourSnapshot<K>>,
    /// Every prefix with an entry in the route table, in order.
    pub prefixes: Vec<PrefixSnapshot<K>>,
}

/// A neighbour in a [`Snapshot`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeighbourSnapshot<K> {
    /// The neighbour.
    pub key: K,
    /// The link cost, which is [`u16::MAX`] if the link is unusable.
    pub cost: u16,
    /// The smoothed round-trip time, if known (RFC 9616).
    pub rtt: Option<Duration>,
    /// The cost of hearing the neighbour, by link sensing, which is [`u16::MAX`] if too few of its
    /// Hellos arrived.
    pub rxcost: u16,
    /// The cost of reaching the neighbour, as it last said, which is [`u16::MAX`] if unknown.
    pub txcost: u16,
    /// What the round-trip time adds to the link cost (RFC 9616 §4.2).
    pub rtt_penalty: u16,
    /// Which of the last 16 Hellos arrived, with the most recent in the least significant bit.
    pub hello_history: u16,
    /// Whether the neighbour is yet to acknowledge a startup packet, until when nothing else it
    /// sends is taken in.
    pub in_startup: bool,
}

/// A prefix in a [`Snapshot`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixSnapshot<K> {
    /// The prefix.
    pub prefix: IpNet,
    /// How this node treats the prefix.
    pub status: PrefixStatus<K>,
    /// Every route learnt for the prefix, selected or not, in order of neighbour.
    pub routes: Vec<RouteSnapshot<K>>,
}

/// How a node treats a prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixStatus<K> {
    /// The node originates a route for the prefix.
    Injected,
    /// The route through this neighbour is selected.
    Selected(K),
    /// The prefix is held, unreachable, after its selected route was lost.
    Held,
    /// No route is selected.
    None,
}

/// A route in a [`Snapshot`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteSnapshot<K> {
    /// The neighbour it is learnt from.
    pub via: K,
    /// The router-id of its source.
    pub router_id: RouterId,
    /// The seqno of its source.
    pub seqno: Seqno,
    /// The metric through the neighbour, which is [`u16::MAX`] if the route is unusable.
    pub metric: u16,
    /// The smoothed metric, rounded, which route selection compares (RFC 8966 Appendix A.3).
    pub smoothed_metric: u16,
    /// Whether the route is feasible (RFC 8966 §3.5.1). This says nothing with an infinite metric,
    /// when the route can't be selected anyway.
    pub feasible: bool,
}
