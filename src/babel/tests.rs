use std::{array::from_ref, future::poll_fn, task::Poll};

use rand::{RngExt, SeedableRng, rngs::StdRng};
use tokio::time::timeout_at;

use super::*;

const NOMINAL_COST: u16 = 96;
const INF: u16 = COST_INFINITY;

/// The rxcost, txcost and link cost of a link that is up with a negligible RTT.
const UP: (u16, u16, u16) = (NOMINAL_COST, NOMINAL_COST, NOMINAL_COST);

fn prefix(s: &str) -> Ipv6Net {
    s.parse().unwrap()
}

/// Creates a new state for node `i`.
fn state(i: usize) -> State {
    State::new(Params::new(), RouterId::new((i + 1) as u64).unwrap(), None)
}

/// A packet sent by a node, whether or not it was delivered.
struct Sent {
    time: Instant,
    from: usize,
    to: usize,
    buf: Box<[u8]>,
}

/// An entry in a node's forwarding table, as set by its route outputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fib {
    Via(usize),
    Unreachable,
}

/// A change to a node's forwarding table.
struct FibChange {
    time: Instant,
    node: usize,
    prefix: Ipv6Net,
    entry: Option<Fib>,
}

enum Event {
    Timeout(usize, Timeout),
    Arrival(usize, usize, Box<[u8]>),
}

/// Returns what arrives of a packet sent from one node to another, if anything.
type Filter = fn(usize, usize, Box<[u8]>) -> Option<Box<[u8]>>;

/// Nodes connected by point-to-point links, driven by a paused clock.
///
/// Whenever a forwarding table changes, they are all checked to be free of loops.
/// After every event, the node's route table is checked to keep no empty entries.
struct Net {
    nodes: Vec<State>,
    /// The neighbour keys of each node, mapped to and from the indices of their neighbours.
    key_maps: Vec<NeighKeyMap<usize>>,
    /// The one-way latency of each link direction that is up.
    links: HashMap<(usize, usize), Duration>,
    filter: Filter,
    in_flight: DelayQueue<(usize, usize, Box<[u8]>)>,
    sent: Vec<Sent>,
    /// The prefixes each node originates.
    locals: Vec<Vec<Ipv6Net>>,
    fibs: Vec<HashMap<Ipv6Net, Fib>>,
    fib_changes: Vec<FibChange>,
}

impl Net {
    fn new(n: usize) -> Self {
        Self {
            nodes: (0..n).map(state).collect(),
            key_maps: (0..n).map(|_| NeighKeyMap::new()).collect(),
            links: HashMap::new(),
            filter: |_, _, buf| Some(buf),
            in_flight: DelayQueue::new(),
            sent: Vec::new(),
            locals: vec![Vec::new(); n],
            fibs: vec![HashMap::new(); n],
            fib_changes: Vec::new(),
        }
    }

    /// Adds node `j` as a neighbour of node `i`, which may be outside the simulation.
    fn add_neighbour(&mut self, i: usize, j: usize) {
        let key = self.nodes[i].add_neigh();
        self.key_maps[i].insert(j, key);
    }

    fn connect(&mut self, a: usize, b: usize, latency: Duration) {
        self.add_neighbour(a, b);
        self.add_neighbour(b, a);
        self.links.insert((a, b), latency);
        self.links.insert((b, a), latency);
    }

    /// Returns the neighbour key of node `i` for node `j`.
    fn key(&self, i: usize, j: usize) -> NeighKey {
        self.key_maps[i].internal(j).unwrap()
    }

    /// Returns the index of the node that a neighbour key of node `i` is for.
    fn index(&self, i: usize, key: NeighKey) -> usize {
        self.key_maps[i].external(key).unwrap()
    }

    fn originate(&mut self, i: usize, prefix: Ipv6Net) {
        assert!(self.nodes[i].add_local_route(prefix));
        self.locals[i].push(prefix);
        self.process_outputs(i);
    }

    /// Runs the network for `duration`, handling every event in order.
    async fn run_for(&mut self, duration: Duration) {
        let deadline = Instant::now() + duration;
        while let Ok(event) = timeout_at(deadline, self.next_event()).await {
            self.handle(event);
        }
    }

    async fn next_event(&mut self) -> Event {
        poll_fn(|cx| {
            for (i, node) in self.nodes.iter_mut().enumerate() {
                if let Poll::Ready(Some(timeout)) = node.poll_timeout(cx) {
                    return Poll::Ready(Event::Timeout(i, timeout));
                }
            }
            if let Poll::Ready(Some(expired)) = self.in_flight.poll_expired(cx) {
                let (from, to, buf) = expired.into_inner();
                return Poll::Ready(Event::Arrival(from, to, buf));
            }
            Poll::Pending
        })
        .await
    }

    fn handle(&mut self, event: Event) {
        let i = match event {
            Event::Timeout(i, timeout) => {
                self.nodes[i].handle_timeout(timeout);
                i
            }
            Event::Arrival(from, to, buf) => {
                let key = self.key(to, from);
                self.nodes[to].handle_packet(key, &buf);
                to
            }
        };
        self.process_outputs(i);
    }

    /// Hands a packet to node `to` as if it came from node `from`.
    fn inject(&mut self, from: usize, to: usize, buf: &[u8]) {
        let key = self.key(to, from);
        self.nodes[to].handle_packet(key, buf);
        self.process_outputs(to);
    }

    /// Sends the packets output by node `from` over the links that are up,
    /// and applies its route outputs to its forwarding table.
    fn process_outputs(&mut self, from: usize) {
        let mut fib_changed = false;

        while let Some(output) = self.nodes[from].poll_output() {
            let (prefix, entry) = match output {
                Output::Packet(dst, buf) => {
                    self.transmit(from, self.index(from, dst), buf);
                    continue;
                }
                Output::RouteSelect(prefix, neigh) => {
                    (prefix, Some(Fib::Via(self.index(from, neigh))))
                }
                Output::RouteHold(prefix) => (prefix, Some(Fib::Unreachable)),
                Output::RouteRemove(prefix) => (prefix, None),
                // Other outputs concern neither the links nor the forwarding tables.
                #[allow(unreachable_patterns)]
                _ => continue,
            };

            let fib = &mut self.fibs[from];
            let old = fib.get(&prefix).copied();
            match entry {
                Some(Fib::Via(_)) => assert_ne!(old, entry, "route should change"),
                Some(Fib::Unreachable) => assert_matches!(old, Some(Fib::Via(_))),
                None => assert!(old.is_some(), "route to remove should exist"),
            }
            match entry {
                Some(entry) => fib.insert(prefix, entry),
                None => fib.remove(&prefix),
            };

            self.fib_changes.push(FibChange {
                time: Instant::now(),
                node: from,
                prefix,
                entry,
            });
            fib_changed = true;
        }

        if fib_changed {
            self.assert_loop_free();
        }

        for (prefix, table) in &self.nodes[from].route_table.by_prefix {
            let empty = table.state == RouteState::Removed && table.routes.is_empty();
            assert!(
                !empty,
                "node {from} should not keep an empty entry for {prefix}"
            );
        }
    }

    fn transmit(&mut self, from: usize, to: usize, buf: Box<[u8]>) {
        if let Some(&latency) = self.links.get(&(from, to))
            && let Some(buf) = (self.filter)(from, to, buf.clone())
        {
            self.in_flight.insert((from, to, buf), latency);
        }
        self.sent.push(Sent {
            time: Instant::now(),
            from,
            to,
            buf,
        });
    }

    /// Returns the nodes that a packet to `dst` goes through from node `i`,
    /// starting with node `i`, and ending where it is delivered or dropped.
    /// Each node forwards it by the longest matching prefix, whether local or in
    /// its forwarding table, and drops it if that is unreachable.
    fn path(&self, i: usize, dst: Ipv6Addr) -> Vec<usize> {
        let mut path = vec![i];
        loop {
            let j = *path.last().unwrap();
            let longest = |prefixes: &mut dyn Iterator<Item = &Ipv6Net>| {
                prefixes
                    .filter(|prefix| prefix.contains(&dst))
                    .map(Ipv6Net::prefix_len)
                    .max()
            };
            let local = self.locals.get(j).and_then(|l| longest(&mut l.iter()));
            let route = self.fibs.get(j).and_then(|fib| {
                let plen = longest(&mut fib.keys())?;
                fib.iter()
                    .find(|(p, _)| p.prefix_len() == plen && p.contains(&dst))
            });

            match route {
                Some((prefix, &Fib::Via(k))) if local < Some(prefix.prefix_len()) => {
                    assert!(
                        !path.contains(&k),
                        "forwarding loop to {dst}: {path:?}, {k}"
                    );
                    path.push(k);
                }
                _ => return path,
            }
        }
    }

    /// Returns the node that a packet to `dst` from node `i` is delivered to, if any.
    fn delivered_to(&self, i: usize, dst: Ipv6Addr) -> Option<usize> {
        let j = *self.path(i, dst).last().unwrap();
        let local = self
            .locals
            .get(j)?
            .iter()
            .any(|prefix| prefix.contains(&dst));
        local.then_some(j)
    }

    fn assert_loop_free(&self) {
        let prefixes = self.fibs.iter().flat_map(HashMap::keys);
        let prefixes: HashSet<_> = prefixes.chain(self.locals.iter().flatten()).collect();
        for prefix in prefixes {
            for i in 0..self.nodes.len() {
                self.path(i, prefix.addr());
            }
        }
    }

    fn fib(&self, i: usize, prefix: Ipv6Net) -> Option<Fib> {
        self.fibs[i].get(&prefix).copied()
    }

    /// Returns node `i`'s entry for node `j`.
    fn neigh(&self, i: usize, j: usize) -> &NeighValue {
        &self.nodes[i].neigh_table[self.key(i, j)]
    }

    /// Returns node `i`'s rxcost, txcost and link cost for node `j`.
    fn costs(&self, i: usize, j: usize) -> (u16, u16, u16) {
        let neigh = self.neigh(i, j);
        (neigh.rxcost(), neigh.txcost, neigh.cost)
    }
}

/// Decodes the TLVs of a packet, which should all decode cleanly, leaving out Updates.
fn tlvs(buf: &[u8]) -> Vec<Tlv> {
    PacketDecoder::new(buf)
        .expect("packet should be well-formed")
        .filter_map(|item| match item.expect("TLV should decode") {
            PacketItem::Tlv(tlv) => Some(tlv),
            PacketItem::Update(_) => None,
        })
        .collect()
}

/// Decodes the Updates of a packet, which should all decode cleanly.
fn updates(buf: &[u8]) -> Vec<Update> {
    PacketDecoder::new(buf)
        .expect("packet should be well-formed")
        .filter_map(|item| match item.expect("TLV should decode") {
            PacketItem::Tlv(_) => None,
            PacketItem::Update(update) => Some(update),
        })
        .collect()
}

/// Builds a packet with the given body.
fn packet(body: &[u8]) -> Vec<u8> {
    let mut buf = vec![42, 2];
    buf.extend((body.len() as u16).to_be_bytes());
    buf.extend(body);
    buf
}

/// Builds a packet with a Route Request.
fn route_request(ae: Ae, plen: u8, prefix: &[u8]) -> Vec<u8> {
    packet(&[&[9, 2 + prefix.len() as u8, ae as u8, plen], prefix].concat())
}

/// Builds an Update for an IPv6 prefix.
fn update(prefix: Ipv6Net, router_id: u64, seqno: u16, metric: u16, interval: u16) -> Update {
    Update {
        ae: Ae::Ipv6,
        plen: prefix.prefix_len(),
        interval: Interval::new(interval).unwrap(),
        seqno: Seqno::new(seqno),
        metric,
        prefix: prefix.addr().octets(),
        router_id: RouterId::new(router_id),
    }
}

/// Returns whether an Update is for the given IPv6 prefix.
fn is_for(update: &Update, prefix: Ipv6Net) -> bool {
    update.ae == Ae::Ipv6
        && update.plen == prefix.prefix_len()
        && update.prefix == prefix.addr().octets()
}

/// Re-encodes a packet without its retractions.
fn without_retractions(buf: Box<[u8]>) -> Box<[u8]> {
    let mut encoder = PacketEncoder::new(buf.len() + 512);
    for item in PacketDecoder::new(&buf).unwrap() {
        match item.unwrap() {
            PacketItem::Update(update) if update.metric == METRIC_INFINITY => {}
            PacketItem::Update(update) => assert!(encoder.put_update(&update)),
            // Router-ids are established along with the updates.
            PacketItem::Tlv(Tlv::RouterId { .. }) => {}
            PacketItem::Tlv(tlv) => assert!(encoder.put_tlv(&tlv)),
        }
    }
    encoder.finalize().into()
}

/// A neighbour outside the simulation, whose packets a test scripts.
struct Scripted {
    index: usize,
    hello_seqno: Seqno,
    /// The rxcost of the IHU sent with each Hello, or `None` to send no IHU.
    rxcost: Option<u16>,
}

impl Scripted {
    fn new(index: usize) -> Self {
        Self {
            index,
            hello_seqno: Seqno::new(0),
            rxcost: Some(NOMINAL_COST),
        }
    }

    /// Sends node `to` a packet built by [`Self::packet`].
    fn send(&mut self, net: &mut Net, to: usize, updates: &[Update]) {
        let buf = self.packet(updates);
        net.inject(self.index, to, &buf);
    }

    /// Builds a packet with the given updates, followed by a scheduled Hello and an
    /// IHU with `self.rxcost`, if any. With the nominal rxcost, the neighbour stays up
    /// if one is sent every 4 s.
    fn packet(&mut self, updates: &[Update]) -> Vec<u8> {
        let mut encoder = PacketEncoder::new(1400);
        for update in updates {
            assert!(encoder.put_update(update));
        }
        let hello = Tlv::Hello {
            seqno: self.hello_seqno,
            interval: Interval::new(400),
            transmit_timestamp: None,
        };
        assert!(encoder.put_tlv(&hello));
        if let Some(rxcost) = self.rxcost {
            assert!(encoder.put_tlv(&ihu(rxcost)));
        }
        self.hello_seqno += 1;
        encoder.finalize().to_vec()
    }
}

#[test]
fn link_cost() {
    // Each row gives the Hello history bits, the txcost and the RTT in milliseconds,
    // followed by the expected rxcost and link cost.
    #[rustfmt::skip]
    let rows = [
        // At least two of the last three Hellos make the rxcost finite.
        (0b111, 96, None, NOMINAL_COST, 96),
        (0b011, 96, None, NOMINAL_COST, 96),
        (0b101, 96, None, NOMINAL_COST, 96),
        (0b110, 96, None, NOMINAL_COST, 96),
        (0b001, 96, None, INF, INF),
        (0b100, 96, None, INF, INF),
        (0b1111_1000, 96, None, INF, INF),
        // The link cost is the txcost, but strictly positive.
        (0b111, 256, None, NOMINAL_COST, 256),
        (0b111, 0, None, NOMINAL_COST, 1),
        (0b111, INF, None, NOMINAL_COST, INF),
        // The RTT adds up to 150 to it, linearly from 10 to 120 ms.
        (0b111, 96, Some(-1.0), NOMINAL_COST, 96),
        (0b111, 96, Some(10.0), NOMINAL_COST, 96),
        (0b111, 96, Some(65.0), NOMINAL_COST, 96 + 75),
        (0b111, 96, Some(120.0), NOMINAL_COST, 96 + 150),
        (0b111, 96, Some(1000.0), NOMINAL_COST, 96 + 150),
        (0b111, 256, Some(65.0), NOMINAL_COST, 256 + 75),
        (0b111, INF - 100, Some(1000.0), NOMINAL_COST, INF),
        (0b100, 96, Some(65.0), INF, INF),
    ];

    for (bits, txcost, rtt_ms, rxcost, cost) in rows {
        let mut neigh = NeighValue::new(&Params::new());

        // Receive or miss a Hello for each bit, the most recent last.
        for (i, seqno) in (0..16).rev().zip(0..) {
            let _ = match bits >> i & 1 {
                1 => neigh.hello_history.received(Seqno::new(seqno)),
                _ => neigh.hello_history.missed(),
            };
        }
        assert_eq!(neigh.hello_history.bits(), bits);

        neigh.txcost = txcost;
        neigh.rtt = rtt_ms.map(|rtt: f64| rtt * 1000.0);
        neigh.update_cost();

        let row = (bits, txcost, rtt_ms);
        assert_eq!((neigh.rxcost(), neigh.cost), (rxcost, cost), "{row:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn neighbours_acquire_each_other() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::from_millis(30));
    net.run_for(Duration::from_secs(20)).await;

    // An RTT of 60 ms adds 150 × (60 − 10) / (120 − 10) ≈ 68 to the link cost
    // (RFC 9616 §4.2), but not to the rxcost sent to the neighbour. The link
    // then stays up at that cost.
    for _ in 0..60 {
        net.run_for(Duration::from_secs(1)).await;
        for (i, j) in [(0, 1), (1, 0)] {
            assert_eq!(net.neigh(i, j).rtt.map(f64::round), Some(60_000.0));
            assert_eq!(net.costs(i, j), (NOMINAL_COST, NOMINAL_COST, 164));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn hellos_and_ihus_follow_the_rfcs() {
    const LATENCY: Duration = Duration::from_millis(30);

    let mut net = Net::new(2);
    net.connect(0, 1, LATENCY);
    net.run_for(Duration::from_secs(60)).await;

    /// Returns the seqno, interval and transmit timestamp of the Hellos among TLVs.
    fn hellos(tlvs: &[Tlv]) -> Vec<(Seqno, Option<Interval>, Option<u32>)> {
        let hellos = tlvs.iter().filter_map(|tlv| match *tlv {
            Tlv::Hello {
                seqno,
                interval,
                transmit_timestamp,
            } => Some((seqno, interval, transmit_timestamp)),
            _ => None,
        });
        hellos.collect()
    }

    // The transmit timestamps of node 1's timestamped Hellos, and when they arrived
    // at node 0.
    let neighbour_hellos: Vec<_> = (net.sent.iter())
        .filter(|sent| sent.from == 1)
        .flat_map(|sent| {
            let arrival = sent.time + LATENCY;
            let hellos = hellos(&tlvs(&sent.buf)).into_iter();
            hellos.filter_map(move |(.., t)| Some((t?, arrival)))
        })
        .collect();
    let (_, first_arrival) = neighbour_hellos[0];

    // The send time, seqno and transmit timestamp of node 0's Hellos.
    let mut sent_hellos: Vec<(Instant, Seqno, u32)> = Vec::new();
    let mut sent_ihus = 0;

    for sent in net.sent.iter().filter(|sent| sent.from == 0) {
        let tlvs = tlvs(&sent.buf);

        // A packet carries at most one Hello (RFC 8966 §4.6.5), timestamped when it
        // is sent (RFC 9616 §3.2), with the seqno incremented for every Hello.
        let hellos = hellos(&tlvs);
        assert!(hellos.len() <= 1, "packet should carry at most one Hello");

        if let Some(&(seqno, interval, timestamp)) = hellos.first() {
            assert_eq!(interval, Interval::new(400));
            let timestamp = timestamp.expect("Hello should be timestamped");

            if let Some(&(first_time, first_seqno, first_timestamp)) = sent_hellos.first() {
                assert_eq!(seqno, first_seqno + sent_hellos.len() as u16);
                assert_eq!(
                    timestamp.wrapping_sub(first_timestamp),
                    (sent.time - first_time).as_micros() as u32
                );
            }
            sent_hellos.push((sent.time, seqno, timestamp));
        }

        for tlv in &tlvs {
            let Tlv::Ihu {
                ae,
                rxcost,
                interval,
                origin_receive_timestamps,
                ..
            } = *tlv
            else {
                continue;
            };
            sent_ihus += 1;

            // The rxcost comes from 2-out-of-3 link sensing, leaving out the RTT.
            assert_eq!(ae, Ae::Wildcard);
            assert!(rxcost == NOMINAL_COST || rxcost == INF);
            assert_eq!(interval, Interval::new(1200).unwrap());

            match origin_receive_timestamps {
                // A timestamped IHU is sent along with a timestamped Hello, and echoes
                // the timestamps of a Hello from the neighbour, sent one latency
                // before it arrived (RFC 9616 §3.2).
                Some((origin, receive)) => {
                    assert_eq!(hellos.len(), 1);
                    assert!(neighbour_hellos.iter().any(|&(t, _)| t == origin));
                    assert_eq!(receive.wrapping_sub(origin), LATENCY.as_micros() as u32);
                }
                // Once a timestamped Hello has arrived, IHUs MUST carry timestamps
                // (RFC 9616 §3.2), apart from those buffered already, which are sent
                // within half a Hello interval (RFC 8966 §3.1).
                None => assert!(sent.time < first_arrival + Duration::from_secs(2)),
            }
        }
    }

    assert!(sent_hellos.len() >= 14 && sent_ihus >= 4);
}

#[tokio::test(start_paused = true)]
async fn one_way_loss_makes_link_unusable() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31)).await;

    // Node 0 stops hearing node 1. Two missed Hellos make its rxcost infinite,
    // which its next IHU tells node 1, and the IHU hold time makes its txcost
    // infinite.
    let latency = net.links.remove(&(1, 0)).unwrap();
    net.run_for(Duration::from_secs(45)).await;
    assert_eq!(net.costs(0, 1), (INF, INF, INF));
    assert_eq!(net.costs(1, 0), (NOMINAL_COST, INF, INF));

    net.links.insert((1, 0), latency);
    net.run_for(Duration::from_secs(30)).await;
    assert_eq!(net.costs(0, 1), UP);
    assert_eq!(net.costs(1, 0), UP);
}

#[tokio::test(start_paused = true)]
async fn silent_neighbour_is_flushed_and_reacquired() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31)).await;

    // 16 missed Hellos empty the history, which flushes the neighbour entry.
    let links = std::mem::take(&mut net.links);
    net.run_for(Duration::from_secs(80)).await;
    for (i, j) in [(0, 1), (1, 0)] {
        let neigh = net.neigh(i, j);
        assert_eq!(neigh.hello_history.bits(), 0);
        assert_eq!((neigh.txcost, neigh.rtt), (INF, None));
        assert!(neigh.hello_timer_key.is_none() && neigh.ihu_timer_key.is_none());
    }

    net.links = links;
    net.run_for(Duration::from_secs(30)).await;
    assert_eq!(net.costs(0, 1), UP);
    assert_eq!(net.costs(1, 0), UP);
}

#[tokio::test(start_paused = true)]
async fn rebooted_neighbour_is_reacquired() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31)).await;

    // Node 1 reboots, and its Hello seqno jumps.
    let hello_seqno = net.nodes[1].hello_seqno + 1000;
    net.nodes[1] = state(1);
    net.nodes[1].hello_seqno = hello_seqno;
    net.key_maps[1] = NeighKeyMap::new();
    net.add_neighbour(1, 0);

    // Its first Hello flushes node 0's entry for it, restarting the history.
    net.run_for(Duration::from_secs(3)).await;
    let neigh = net.neigh(0, 1);
    assert_eq!(neigh.hello_history.bits(), 0b1);
    assert_eq!((neigh.txcost, neigh.rtt), (INF, None));

    net.run_for(Duration::from_secs(30)).await;
    assert_eq!(net.costs(0, 1), UP);
    assert_eq!(net.costs(1, 0), UP);
}

/// Builds an IHU with the given rxcost.
fn ihu(rxcost: u16) -> Tlv {
    Tlv::Ihu {
        ae: Ae::Wildcard,
        rxcost,
        interval: Interval::new(1200).unwrap(),
        address: [0; 8],
        origin_receive_timestamps: None,
    }
}

#[tokio::test(start_paused = true)]
async fn rebooted_neighbour_routes_wait_for_the_link() {
    let p = prefix("fd00:1::/64");

    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31)).await;

    // Node 1 reboots, its Hello seqno jumps, and it originates P. Its first packet has an
    // update for P, followed by a Hello, which flushes node 0's entry for it.
    let hello_seqno = net.nodes[1].hello_seqno + 1000;
    net.nodes[1] = state(1);
    net.nodes[1].hello_seqno = hello_seqno;
    net.key_maps[1] = NeighKeyMap::new();
    net.add_neighbour(1, 0);
    net.originate(1, p);
    let changes = net.fib_changes.len();

    // Routes are selected once the whole packet has been handled, when the link cost is
    // infinite. It stays so until node 0 has received enough Hellos and an IHU, so node 0
    // selects the route only then, and never briefly before.
    net.run_for(Duration::from_secs(30)).await;
    let entries: Vec<_> = net.fib_changes[changes..]
        .iter()
        .filter(|change| (change.node, change.prefix) == (0, p))
        .map(|change| change.entry)
        .collect();
    assert_eq!(entries, [Some(Fib::Via(1))]);
}

#[tokio::test(start_paused = true)]
async fn rebooted_neighbour_old_routes_are_held_at_its_first_packet() {
    let p = prefix("fd00:1::/64");

    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.originate(1, p);
    net.run_for(Duration::from_secs(31)).await;
    assert_eq!(net.fib(0, p), Some(Fib::Via(1)));

    // Node 1 reboots without P, and its Hello seqno jumps.
    let hello_seqno = net.nodes[1].hello_seqno + 1000;
    net.nodes[1] = state(1);
    net.nodes[1].hello_seqno = hello_seqno;
    net.key_maps[1] = NeighKeyMap::new();
    net.add_neighbour(1, 0);
    net.locals[1].clear();

    // Its first packet, flushed within 2 s, has a Hello that flushes node 0's entry for
    // it, so the link cost becomes infinite. Node 0's route to P through it, learnt
    // before the reboot, then has an infinite metric, and P is held at once.
    net.run_for(Duration::from_secs(3)).await;
    assert_eq!(net.costs(0, 1).2, INF);
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
}

/// Sets up node 0 with neighbour 8 up, outside the simulation, and no routes.
async fn neighbour_8_up() -> Net {
    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    let mut n8 = Scripted::new(8);
    for _ in 0..4 {
        n8.send(&mut net, 0, &[]);
        net.run_for(Duration::from_secs(4)).await;
    }
    assert_eq!(net.costs(0, 8), UP);
    net
}

#[tokio::test(start_paused = true)]
async fn ihu_applies_to_updates_in_the_same_packet() {
    let p = prefix("fd00:8::/64");
    let mut net = neighbour_8_up().await;

    // Neighbour 8 sends an update for P, followed by an IHU with an infinite rxcost, as
    // it has stopped hearing node 0. The link cost is then infinite, so node 0 does not
    // select the route, not even briefly.
    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_update(&update(p, 8, 1, 100, 400)));
    assert!(encoder.put_tlv(&ihu(INF)));
    net.inject(8, 0, encoder.finalize());
    assert_eq!(net.costs(0, 8), (NOMINAL_COST, INF, INF));
    assert!(net.fib_changes.iter().all(|change| change.prefix != p));
}

#[tokio::test(start_paused = true)]
async fn announcing_and_retracting_a_prefix_in_one_packet_selects_nothing() {
    let p = prefix("fd00:8::/64");
    let mut net = neighbour_8_up().await;

    // Neighbour 8 announces P and retracts it in the same packet. Selection then runs for
    // P twice, and the first run removes its entry, which has no routes left.
    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_update(&update(p, 8, 1, 100, 400)));
    assert!(encoder.put_update(&update(p, 8, 1, METRIC_INFINITY, 400)));
    net.inject(8, 0, encoder.finalize());
    assert!(net.fib_changes.iter().all(|change| change.prefix != p));
    assert!(!net.nodes[0].route_table.by_prefix.contains_key(&p));
}

#[tokio::test(start_paused = true)]
async fn wildcard_retractions_remove_routes_added_between_them() {
    let (p, q) = (prefix("fd00:8::/64"), prefix("fd00:88::/64"));
    let mut net = neighbour_8_up().await;
    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_update(&update(q, 8, 1, 100, 400)));
    net.inject(8, 0, encoder.finalize());
    assert_eq!(net.fib(0, q), Some(Fib::Via(8)));

    // Neighbour 8 retracts all its routes, announces P, and retracts all its routes
    // again, in one packet. The second retraction removes the route to P, so neither
    // route is left, and P is never selected.
    let wildcard = Update {
        ae: Ae::Wildcard,
        plen: 0,
        prefix: [0; 16],
        router_id: None,
        ..update(p, 8, 1, METRIC_INFINITY, 400)
    };
    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_update(&wildcard));
    assert!(encoder.put_update(&update(p, 8, 1, 100, 400)));
    assert!(encoder.put_update(&wildcard));
    net.inject(8, 0, encoder.finalize());
    assert_eq!(net.fib(0, q), Some(Fib::Unreachable));
    assert!(net.fib_changes.iter().all(|change| change.prefix != p));
    assert!(!net.nodes[0].route_table.by_prefix.contains_key(&p));
}

#[tokio::test(start_paused = true)]
async fn acknowledgement_requests_are_answered_in_time() {
    // Node 1 is outside the simulation and only sends the requests.
    let mut net = Net::new(1);
    net.add_neighbour(0, 1);

    // More requests than one packet can hold Acknowledgments for.
    let interval = Interval::new(100).unwrap();
    let mut encoder = PacketEncoder::new(4096);
    for opaque in 0..400 {
        assert!(encoder.put_tlv(&Tlv::AcknowledgementRequest { opaque, interval }));
    }

    let start = Instant::now();
    net.inject(1, 0, encoder.finalize());
    net.run_for(interval.to_duration()).await;

    let mut opaques = Vec::new();

    for sent in net.sent.iter().filter(|sent| sent.from == 0) {
        // Packets fit the MTU less the IPv6 and UDP headers (RFC 8966 §4).
        assert!(sent.buf.len() <= Params::new().get_mtu() as usize - 48);

        let acks = tlvs(&sent.buf).into_iter().filter_map(|tlv| match tlv {
            Tlv::Acknowledgement { opaque } => Some(opaque),
            _ => None,
        });
        let len = opaques.len();
        opaques.extend(acks);

        // Acknowledgments are sent before the interval elapses, with a margin.
        if opaques.len() > len {
            assert!(sent.time - start <= interval.to_duration() / 2);
        }
    }

    assert_eq!(opaques, Vec::from_iter(0..400));
}

#[tokio::test(start_paused = true)]
async fn ignored_packets_and_tlvs_change_nothing() {
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.run_for(Duration::from_secs(31)).await;

    let bits = net.neigh(0, 1).hello_history.bits();

    #[rustfmt::skip]
    let packets = [
        // Wrong magic, wrong version, and a body overrunning the datagram.
        vec![43, 2, 0, 0],
        vec![42, 1, 0, 0],
        vec![42, 2, 0, 1],
        packet(&[
            // A TLV of unknown type.
            99, 2, 0, 0,
            // A Unicast Hello.
            4, 6, 0x80, 0, 0, 1, 1, 0x90,
            // A Hello with an unknown mandatory sub-TLV.
            4, 8, 0, 0, 0, 1, 1, 0x90, 0x80, 0,
            // An Update with a finite metric but no router-id.
            8, 10, 2, 0, 0, 0, 1, 0x90, 0, 1, 0, 96,
            // An IHU overrunning the packet.
            5, 20, 0,
        ]),
    ];
    for buf in packets {
        net.inject(1, 0, &buf);
    }

    assert_eq!(net.neigh(0, 1).hello_history.bits(), bits);
    assert_eq!(net.costs(0, 1), UP);
}

/// The Route Hold time, which is 4 times the Update interval.
const ROUTE_HOLD_TIME: Duration = Duration::from_secs(64);

#[tokio::test(start_paused = true)]
async fn routes_propagate_without_flapping() {
    let p = prefix("fd00:3::/64");
    let router_id = RouterId::new(4).unwrap();

    let mut net = Net::new(4);
    for i in 0..3 {
        net.connect(i, i + 1, Duration::ZERO);
    }
    net.originate(3, p);
    net.run_for(Duration::from_secs(60)).await;

    assert_eq!(net.path(0, p.addr()), [0, 1, 2, 3]);
    let changes = net.fib_changes.len();

    // Routes then stay put, beyond the source GC time.
    net.run_for(Duration::from_secs(300)).await;
    assert_eq!(net.fib_changes.len(), changes);

    // Each node advertises P with the originator's router-id and seqno, and a metric
    // adding the cost of the link it learnt P over (RFC 8966 §3.7), but not back over
    // that link (§3.7.4).
    let seqno = net.nodes[3].seqno;
    for (from, to, metric) in [(3, 2, 0), (2, 1, 96), (1, 0, 192)] {
        let sent_updates: Vec<_> = (net.sent.iter())
            .filter(|sent| (sent.from, sent.to) == (from, to))
            .flat_map(|sent| updates(&sent.buf))
            .filter(|update| is_for(update, p))
            .collect();
        assert!(sent_updates.len() >= 20);
        for update in sent_updates {
            assert_eq!((update.router_id, update.seqno), (Some(router_id), seqno));
            assert_eq!(update.metric, metric);
        }

        let back = (net.sent.iter())
            .filter(|sent| (sent.from, sent.to) == (to, from))
            .flat_map(|sent| updates(&sent.buf));
        assert!(!back.into_iter().any(|update| is_for(&update, p)));
    }

    // Feasibility distances are kept for as long as routes are advertised (§3.7.3).
    for (i, metric) in [(3, 0), (2, 96), (1, 192)] {
        let source = &net.nodes[i].source_table[&SourceKey {
            prefix: p,
            router_id,
        }];
        assert_eq!((source.seqno, source.metric), (seqno, metric));
    }
}

#[tokio::test(start_paused = true)]
async fn failed_link_retracts_routes_and_holds_prefix() {
    let p = prefix("fd00:2::/64");

    let mut net = Net::new(3);
    net.connect(0, 1, Duration::ZERO);
    net.connect(1, 2, Duration::ZERO);
    net.originate(2, p);
    net.run_for(Duration::from_secs(60)).await;
    assert_eq!(net.path(0, p.addr()), [0, 1, 2]);

    // Node 1 loses node 2 after two missed Hellos, and retracts P, which node 0 learns
    // of. Both hold P as unreachable (RFC 8966 §3.5.4).
    net.links.remove(&(1, 2));
    net.links.remove(&(2, 1));
    let failure = Instant::now();
    net.run_for(Duration::from_secs(15)).await;
    assert_eq!(net.fib(1, p), Some(Fib::Unreachable));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));

    net.run_for(Duration::from_secs(90)).await;

    for i in [0, 1] {
        let changes: Vec<_> = (net.fib_changes.iter())
            .filter(|change| (change.node, change.prefix) == (i, p) && change.time > failure)
            .collect();
        let [held, removed] = changes[..] else {
            panic!("node {i} should hold P, then remove it");
        };
        assert_eq!((held.entry, removed.entry), (Some(Fib::Unreachable), None));
        assert_eq!(removed.time - held.time, ROUTE_HOLD_TIME);

        // While P is held, it is only retracted, with the router-id of the route lost,
        // at once and with every periodic dump (RFC 8966 §3.7), and afterwards not
        // mentioned at all.
        let mut retractions = 0;
        for sent in net
            .sent
            .iter()
            .filter(|sent| sent.from == i && sent.time > held.time)
        {
            for update in updates(&sent.buf).iter().filter(|update| is_for(update, p)) {
                let router_id = RouterId::new(3);
                assert_eq!(
                    (update.metric, update.router_id),
                    (METRIC_INFINITY, router_id)
                );
                // Allow for the buffering of a retraction put before the removal.
                assert!(sent.time <= removed.time + Duration::from_secs(2));
                retractions += 1;
            }
        }
        assert!(retractions >= 4);
    }
}

#[tokio::test(start_paused = true)]
async fn held_prefix_outlasts_routes_through_the_node() {
    let p = prefix("fd00:2::/64");

    // Node 0 originates a default route, which covers P.
    let mut net = Net::new(3);
    net.connect(0, 1, Duration::ZERO);
    net.connect(1, 2, Duration::ZERO);
    net.originate(0, prefix("::/0"));
    net.originate(2, p);
    net.run_for(Duration::from_secs(60)).await;
    assert_eq!(net.path(0, p.addr()), [0, 1, 2]);

    // Node 0 misses node 1's retractions, so it keeps routing P through node 1 until the
    // route expires. Were node 1 to stop holding P before, it would route P along the
    // default route back to node 0, which the forwarding loop check would catch.
    net.filter = |from, _, buf| {
        Some(if from == 1 {
            without_retractions(buf)
        } else {
            buf
        })
    };
    net.links.remove(&(1, 2));
    net.links.remove(&(2, 1));
    net.run_for(Duration::from_secs(120)).await;

    // The first change of node `i` away from routing P through node `i + 1`.
    let change = |i: usize| {
        let mut changes = net
            .fib_changes
            .iter()
            .filter(|change| (change.node, change.prefix) == (i, p));
        changes.find(|change| change.entry != Some(Fib::Via(i + 1)))
    };
    let held = change(1).unwrap();
    let expired = change(0).unwrap();
    let removed = (net.fib_changes.iter())
        .find(|change| (change.node, change.prefix, change.entry) == (1, p, None))
        .unwrap();

    // The route through node 1 lasts until it expires, 3.5 Update intervals after
    // node 0 last heard of it, but no longer than the hold.
    assert!(expired.time - held.time >= Duration::from_secs(40));
    assert!(expired.time < removed.time);
}

#[tokio::test(start_paused = true)]
async fn retractions_and_expiry_unselect_routes() {
    let p = prefix("fd00:9::/64");
    // An interval of 4 s makes the route expire 14 s after the last update.
    let announcement = update(p, 42, 1, 0, 400);
    let retraction = update(p, 42, 1, METRIC_INFINITY, 400);
    let wildcard_retraction = Update {
        ae: Ae::Wildcard,
        plen: 0,
        prefix: [0; 16],
        router_id: None,
        ..retraction
    };

    let mut net = Net::new(1);
    net.add_neighbour(0, 9);
    let mut neighbour = Scripted::new(9);

    // Announcements are selected once the neighbour is up.
    for _ in 0..3 {
        neighbour.send(&mut net, 0, from_ref(&announcement));
        net.run_for(Duration::from_secs(4)).await;
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // A retraction unselects the route at once.
    neighbour.send(&mut net, 0, from_ref(&retraction));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
    net.run_for(Duration::from_secs(4)).await;

    // A new route is unaffected by the expiry of the one retracted.
    for _ in 0..6 {
        neighbour.send(&mut net, 0, from_ref(&announcement));
        assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
        net.run_for(Duration::from_secs(4)).await;
    }

    // So is a wildcard retraction.
    neighbour.send(&mut net, 0, from_ref(&wildcard_retraction));
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
    net.run_for(Duration::from_secs(4)).await;

    // A route that is not refreshed expires.
    neighbour.send(&mut net, 0, from_ref(&announcement));
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
    for _ in 0..3 {
        net.run_for(Duration::from_secs(4)).await;
        neighbour.send(&mut net, 0, &[]);
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
    net.run_for(Duration::from_secs(4)).await;
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
}

#[tokio::test(start_paused = true)]
async fn unfeasible_routes_are_never_selected() {
    let p = prefix("fd00:9::/64");
    // Neighbour 9 announces P once, with an interval long enough for it not to expire.
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 400);

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));

    n9.send(&mut net, 0, from_ref(&far));
    for round in 0..40 {
        if round > 0 {
            n9.send(&mut net, 0, &[]);
        }
        let updates: &[Update] = if round >= 2 { from_ref(&near) } else { &[] };
        n8.send(&mut net, 0, updates);
        net.run_for(Duration::from_secs(4)).await;
    }

    // Node 0 switched to the nearer route, and has advertised it.
    assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
    let last = (net.sent.iter())
        .filter(|sent| sent.from == 0 && sent.to == 9)
        .flat_map(|sent| updates(&sent.buf))
        .rfind(|update| is_for(update, p));
    assert_eq!(last.map(|update| update.metric), Some(196));

    // Once neighbour 8 is lost, the far route is not feasible anymore, since it is not
    // strictly better than what node 0 has advertised (RFC 8966 §3.5.1, §3.6).
    for _ in 0..5 {
        n9.send(&mut net, 0, &[]);
        net.run_for(Duration::from_secs(4)).await;
    }
    assert_eq!(net.fib(0, p), Some(Fib::Unreachable));
}

/// Runs node 0 for `secs` seconds, with neighbours 8 and 9 sending a Hello and an IHU
/// every 4 s, preceded by the given updates in their first packets only.
async fn exchange(
    net: &mut Net,
    n8: &mut Scripted,
    n9: &mut Scripted,
    secs: u64,
    updates8: &[Update],
    updates9: &[Update],
) {
    for round in 0..secs / 4 {
        let first = round == 0;
        n9.send(net, 0, if first { updates9 } else { &[] });
        n8.send(net, 0, if first { updates8 } else { &[] });
        net.run_for(Duration::from_secs(4)).await;
    }
}

/// Sets up node 0 with neighbours 8 and 9, which announce P once each, with an interval
/// long enough for the routes not to expire. The route through neighbour 9 comes up
/// first, and is selected. Both smoothed metrics have converged after 160 s.
async fn two_routes(far: &Update, near: &Update) -> (Net, Scripted, Scripted) {
    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        160,
        from_ref(far),
        from_ref(near),
    )
    .await;
    (net, n8, n9)
}

#[tokio::test(start_paused = true)]
async fn unfeasible_update_unselects_route() {
    let p = prefix("fd00:9::/64");
    let far = update(p, 43, 1, 2000, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let (mut net, _, mut n9) = two_routes(&far, &near).await;
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // Node 0 advertises P with metric 196, so an update from neighbour 9 with metric 300
    // is unfeasible, and MUST unselect the route at once (RFC 8966 §3.5.3), although it
    // is still the best. The route through neighbour 8 is selected instead.
    n9.send(&mut net, 0, &[update(p, 42, 1, 300, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(8)));
}

#[tokio::test(start_paused = true)]
async fn worse_selected_route_is_replaced_at_the_next_update_of_a_better_one() {
    let p = prefix("fd00:9::/64");
    let far = update(p, 43, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let (mut net, mut n8, mut n9) = two_routes(&far, &near).await;
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // At 162 s, the link to neighbour 9 gets worse, raising the route's metric from 196
    // to 1100, above 596 through neighbour 8. The route stays selected while usable.
    // Neighbour 8 refreshes its route every 4 s, and node 0 compares it with the
    // selected route each time. At 162 and 166 s, the selected route's smoothed metric,
    // 1100 - 904 exp(-t / 12 s), is still below 596. At 170 s, it is about 636, so node 0
    // switches then (RFC 8966 Appendix A.3).
    net.run_for(Duration::from_secs(2)).await;
    n9.rxcost = Some(1000);
    let start = Instant::now();
    let changes = net.fib_changes.len();
    for _ in 0..5 {
        exchange(&mut net, &mut n8, &mut n9, 4, from_ref(&far), &[]).await;
    }

    let [switch] = &net.fib_changes[changes..] else {
        panic!("node 0 should switch once");
    };
    assert_eq!(switch.entry, Some(Fib::Via(8)));
    assert_eq!(switch.time - start, Duration::from_secs(8));
}

#[tokio::test(start_paused = true)]
async fn router_id_change_by_hysteresis_is_advertised_urgently() {
    let p = prefix("fd00:9::/64");
    let far = update(p, 43, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);

    // As above, with node 1 receiving node 0's updates.
    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        160,
        from_ref(&far),
        from_ref(&near),
    )
    .await;
    assert_eq!(net.path(1, p.addr()), [1, 0, 9]);

    // The link to neighbour 9 gets worse, and node 0 switches to the route through
    // neighbour 8, with another router-id, when that route is next updated.
    net.run_for(Duration::from_secs(2)).await;
    n9.rxcost = Some(1000);
    let changes = net.fib_changes.len();
    for _ in 0..5 {
        exchange(&mut net, &mut n8, &mut n9, 4, from_ref(&far), &[]).await;
    }
    let switch = net.fib_changes[changes..]
        .iter()
        .find(|change| (change.node, change.entry) == (0, Some(Fib::Via(8))))
        .expect("node 0 should switch to the route through neighbour 8");

    // The new router-id is advertised as an urgent TLV (RFC 8966 §3.7.2), within the
    // urgent timeout of 0.2 s.
    let sent = net.sent.iter().find(|sent| {
        let updates = updates(&sent.buf);
        let mut updates = updates.iter().filter(|update| is_for(update, p));
        (sent.from, sent.to) == (0, 1)
            && sent.time >= switch.time
            && updates.any(|update| update.router_id == RouterId::new(43))
    });
    let sent = sent.expect("new router-id should be advertised");
    assert!(sent.time - switch.time <= Duration::from_millis(200));
}

#[tokio::test(start_paused = true)]
async fn hysteresis_needs_a_lower_metric_as_well() {
    let p = prefix("fd00:9::/64");

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));

    // Both links come up at 4 s, the one to neighbour 9 first, and its route, of metric
    // 596, is selected. The route through neighbour 8 has metric 196, but its smoothed
    // metric starts at infinity, and it is not updated again for a while.
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 43, 1, 100, 0x8000);
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        72,
        from_ref(&near),
        from_ref(&far),
    )
    .await;
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // By 72 s, its smoothed metric, 196 + 65339 exp(-68 s / 12 s) ≈ 422, is below 596.
    // It is then updated with metric 1096, above 596. Node 0 keeps its route, since it
    // switches only when both m(R') < m(R) and ms(R') < ms(R) (RFC 8966 Appendix A.3).
    n8.send(&mut net, 0, &[update(p, 43, 1, 1000, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
}

#[tokio::test(start_paused = true)]
async fn hysteresis_never_switches_to_unfeasible_routes() {
    let p = prefix("fd00:9::/64");
    // Both routes have the same source, and node 0 advertises P with metric 196 through
    // neighbour 9, so the route through neighbour 8 is unfeasible.
    let far = update(p, 42, 1, 500, 0x8000);
    let near = update(p, 42, 1, 100, 0x8000);
    let (mut net, mut n8, mut n9) = two_routes(&far, &near).await;
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // The link to neighbour 9 gets worse, raising the route's metric to 1100, above 596
    // through neighbour 8. The routes are refreshed meanwhile. Node 0 keeps the route
    // through neighbour 9, which is still feasible, and never switches, even briefly, to
    // one that is not.
    n9.rxcost = Some(1000);
    let changes = net.fib_changes.len();
    for _ in 0..15 {
        exchange(
            &mut net,
            &mut n8,
            &mut n9,
            4,
            from_ref(&far),
            from_ref(&near),
        )
        .await;
    }
    assert_eq!(net.fib_changes.len(), changes);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
}

#[tokio::test(start_paused = true)]
async fn metric_changed_by_a_timeout_is_smoothed_from_then() {
    let p = prefix("fd00:8::/64");

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        32,
        &[update(p, 8, 1, 100, 0x8000)],
        &[],
    )
    .await;
    assert_eq!(net.fib(0, p), Some(Fib::Via(8)));

    // Neighbour 8 falls silent, while neighbour 9 keeps sending packets, 3 s apart.
    // Missed Hellos make the link cost to neighbour 8 infinite, and the metric of the
    // route through it as well. The smoothed metric follows from the time of the
    // timeout, not of the last packet received (RFC 8966 Appendix A.3).
    let changes = net.fib_changes.len();
    for _ in 0..4 {
        net.run_for(Duration::from_secs(3)).await;
        n9.send(&mut net, 0, &[]);
    }
    let [lost] = &net.fib_changes[changes..] else {
        panic!("node 0 should lose the route once");
    };
    let route = &net.nodes[0].route_table.by_prefix[&p].routes[net.key(0, 8)];
    assert_eq!(route.metric.get(), METRIC_INFINITY);
    let age = timestamp_now().wrapping_sub(route.metric_smoothed_at.get());
    assert_eq!(
        Duration::from_micros(age.into()),
        Instant::now() - lost.time
    );
}

#[tokio::test(start_paused = true)]
async fn source_expiry_keeps_hysteresis() {
    let p = prefix("fd00:9::/64");

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));

    // The route through neighbour 9 is selected, and then changes router-id, so node 0's
    // source table entry for the old one expires 3 minutes after it last advertised it.
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        40,
        &[update(p, 43, 1, 2000, 0x8000)],
        &[update(p, 42, 1, 100, 0x8000)],
    )
    .await;
    exchange(
        &mut net,
        &mut n8,
        &mut n9,
        4,
        &[],
        &[update(p, 44, 1, 100, 0x8000)],
    )
    .await;
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
    let node = &net.nodes[0];
    let source = SourceKey {
        prefix: p,
        router_id: RouterId::new(42).unwrap(),
    };
    let expiry = node
        .timers
        .deadline(&node.source_table[&source].gc_timer_key);

    // Shortly before, the route through neighbour 8 gets a metric of 146, below 196, but
    // its smoothed metric is still far above. Node 0 keeps its route, also when the entry
    // expires (RFC 8966 Appendix A.3).
    while Instant::now() + Duration::from_secs(8) < expiry {
        exchange(&mut net, &mut n8, &mut n9, 4, &[], &[]).await;
    }
    n8.send(&mut net, 0, &[update(p, 43, 1, 50, 0x8000)]);
    exchange(&mut net, &mut n8, &mut n9, 12, &[], &[]).await;
    assert!(!net.nodes[0].source_table.contains_key(&source));
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
}

#[tokio::test(start_paused = true)]
async fn smoothed_metrics_survive_timestamp_wraparound() {
    let p = prefix("fd00:9::/64");
    let near = update(p, 42, 1, 100, 0x8000);
    let far = update(p, 43, 1, 500, 0x8000);

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));
    exchange(&mut net, &mut n8, &mut n9, 16, &[], from_ref(&near)).await;
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // Timestamps wrap around every 2^32 µs, about 72 minutes. The route through
    // neighbour 9 keeps its metric of 196 for longer than that, refreshed every 16 s.
    // The route through neighbour 8 appears a few minutes before, with metric 596.
    let route = &net.nodes[0].route_table.by_prefix[&p].routes[net.key(0, 9)];
    let age = timestamp_now().wrapping_sub(route.metric_smoothed_at.get());
    let anchored = Instant::now() - Duration::from_micros(age.into());
    let wrapped = anchored + Duration::from_micros(1 << 32) + Duration::from_secs(1);
    while Instant::now() < wrapped {
        let soon = wrapped - Instant::now() < Duration::from_secs(300);
        let updates8: &[Update] = if soon { from_ref(&far) } else { &[] };
        exchange(&mut net, &mut n8, &mut n9, 16, updates8, from_ref(&near)).await;
    }

    // Just after the wraparound, the route through neighbour 8 gets a metric of 146.
    // Both smoothed metrics have long converged, to 196 and 596, so node 0 keeps its
    // route (RFC 8966 Appendix A.3).
    n8.send(&mut net, 0, &[update(p, 43, 1, 50, 0x8000)]);
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));
}

#[tokio::test(start_paused = true)]
async fn router_id_change_is_advertised_urgently() {
    let p = prefix("fd00:9::/64");

    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.add_neighbour(0, 9);
    let mut neighbour = Scripted::new(9);

    for _ in 0..10 {
        neighbour.send(&mut net, 0, &[update(p, 42, 1, 0, 400)]);
        net.run_for(Duration::from_secs(4)).await;
    }
    assert_eq!(net.path(1, p.addr()), [1, 0, 9]);

    // A new router-id for the selected route is advertised as an urgent TLV
    // (RFC 8966 §3.7.2), within the urgent timeout of 0.2 s.
    neighbour.send(&mut net, 0, &[update(p, 43, 1, 0, 400)]);
    let change = Instant::now();
    net.run_for(Duration::from_secs(4)).await;

    let first = net.sent.iter().find(|sent| {
        let updates = updates(&sent.buf);
        let mut updates = updates.iter().filter(|update| is_for(update, p));
        sent.from == 0 && updates.any(|update| update.router_id == RouterId::new(43))
    });
    let first = first.expect("new router-id should be advertised");
    assert_eq!(first.to, 1);
    assert!(first.time - change <= Duration::from_millis(200));

    // Neither update goes back to neighbour 9 (§3.7.4).
    for sent in net.sent.iter().filter(|sent| sent.to == 9) {
        assert!(!updates(&sent.buf).iter().any(|update| is_for(update, p)));
    }
}

#[tokio::test(start_paused = true)]
async fn better_routes_are_adopted_after_hysteresis() {
    let p = prefix("fd00:9::/64");

    let mut net = Net::new(1);
    net.add_neighbour(0, 8);
    net.add_neighbour(0, 9);
    let (mut n8, mut n9) = (Scripted::new(8), Scripted::new(9));

    // Routes of metrics 596 through neighbour 9 and 1096 through neighbour 8, long
    // enough for their smoothed metrics to converge.
    for _ in 0..50 {
        n8.send(&mut net, 0, &[update(p, 42, 1, 1000, 400)]);
        n9.send(&mut net, 0, &[update(p, 42, 1, 500, 400)]);
        net.run_for(Duration::from_secs(4)).await;
    }
    assert_eq!(net.fib(0, p), Some(Fib::Via(9)));

    // The route through neighbour 8 drops to 196. Its smoothed metric, with a time
    // constant of 12 s (RFC 8966 Appendix A.3), is 196 + 900 exp(-t / 12 s), and falls
    // below 596 after 12 s × ln(9 / 4) ≈ 9.7 s. Routes are selected every 4 s, as the
    // neighbours' packets arrive, so the switch happens 12 s after the drop.
    for round in 0..4 {
        n8.send(&mut net, 0, &[update(p, 42, 1, 100, 400)]);
        n9.send(&mut net, 0, &[update(p, 42, 1, 500, 400)]);
        let expected = if round < 3 { 9 } else { 8 };
        assert_eq!(
            net.fib(0, p),
            Some(Fib::Via(expected)),
            "after {} s",
            round * 4
        );
        net.run_for(Duration::from_secs(4)).await;
    }
}

#[tokio::test(start_paused = true)]
async fn originator_rebooted_with_older_seqno_is_reacquired() {
    let p = prefix("fd00:2::/64");

    let mut net = Net::new(3);
    net.connect(0, 1, Duration::ZERO);
    net.connect(1, 2, Duration::ZERO);
    net.originate(2, p);
    net.run_for(Duration::from_secs(60)).await;
    assert_eq!(net.path(0, p.addr()), [0, 1, 2]);

    // Node 2 reboots with the same router-id, but a seqno 1000 older than before.
    let seqno = Seqno::new(net.nodes[2].seqno.get().wrapping_sub(1000));
    let hello_seqno = net.nodes[2].hello_seqno + 1000;
    net.nodes[2] = State::new(Params::new(), net.nodes[2].router_id, Some(seqno));
    net.nodes[2].hello_seqno = hello_seqno;
    net.key_maps[2] = NeighKeyMap::new();
    net.add_neighbour(2, 1);
    assert!(net.nodes[2].add_local_route(p));
    let reboot = Instant::now();

    // Its updates are unfeasible at nodes 1 and 0, which have advertised P with the
    // newer seqno (RFC 8966 §3.5.1), so P becomes unreachable.
    net.run_for(Duration::from_secs(60)).await;
    assert_eq!(net.delivered_to(0, p.addr()), None);

    // Each node's feasibility distance for P expires 3 minutes after the node last
    // advertised P with a finite metric, which it did before holding P. Its route through
    // the next node then becomes feasible, and is selected at once. Node 1 holds P before
    // node 0, and its triggered update is flushed within 2 s.
    net.run_for(Duration::from_secs(240)).await;
    assert_eq!(net.path(0, p.addr()), [0, 1, 2]);
    let mut changes = net
        .fib_changes
        .iter()
        .filter(|change| (change.node, change.prefix) == (0, p) && change.time >= reboot);
    let held = changes.next().unwrap();
    assert_eq!(held.entry, Some(Fib::Unreachable));
    let recovered = changes.next_back().unwrap();
    assert_eq!(recovered.entry, Some(Fib::Via(1)));
    assert!(recovered.time - held.time <= Duration::from_secs(3 * 60 + 2));
}

#[tokio::test(start_paused = true)]
async fn random_link_failures_cause_no_loops() {
    const N: usize = 6;
    let edges = [
        (0, 1),
        (1, 2),
        (2, 3),
        (3, 4),
        (4, 5),
        (5, 0),
        (0, 3),
        (1, 4),
    ];
    let mut rng = StdRng::seed_from_u64(1);

    let mut net = Net::new(N);
    for (a, b) in edges {
        net.connect(a, b, Duration::from_millis(rng.random_range(0..60)));
    }
    let links = net.links.clone();

    // Every node originates a prefix, and node 0 a default route covering them all.
    let prefixes: Vec<_> = (0..N).map(|i| prefix(&format!("fd00:{i}::/64"))).collect();
    for (i, &p) in prefixes.iter().enumerate() {
        net.originate(i, p);
    }
    net.originate(0, prefix("::/0"));

    // Links fail and recover at random, while the harness checks for forwarding loops
    // whenever a forwarding table changes.
    for _ in 0..60 {
        let (a, b) = edges[rng.random_range(0..edges.len())];
        if net.links.remove(&(a, b)).is_some() {
            net.links.remove(&(b, a));
        } else {
            net.links.insert((a, b), links[&(a, b)]);
            net.links.insert((b, a), links[&(b, a)]);
        }
        net.run_for(Duration::from_secs(rng.random_range(5..30)))
            .await;
    }

    // Once all links are back, every node reaches every prefix. Without seqno requests,
    // a node that lost a prefix may have to wait for its feasibility distance to be
    // garbage-collected first, 3 minutes after it last advertised the prefix.
    net.links = links;
    net.run_for(Duration::from_secs(400)).await;
    for i in 0..N {
        for (j, p) in prefixes.iter().enumerate() {
            assert_eq!(net.delivered_to(i, p.addr()), Some(j), "from {i} to {p}");
        }
    }
}

/// Sets up node 0 with a route learnt from node 1, a local route, and neighbour 9,
/// outside the simulation. Returns the learnt and local prefixes, between periodic
/// dumps, which are sent every 16 s and flushed within 2 s.
async fn requested_net() -> (Net, Ipv6Net, Ipv6Net) {
    let learnt = prefix("fd00:1::/64");
    let local = prefix("fd00::/64");

    let mut net = Net::new(2);
    net.connect(0, 1, Duration::ZERO);
    net.add_neighbour(0, 9);
    net.originate(0, local);
    net.originate(1, learnt);
    net.run_for(Duration::from_secs(20)).await;
    assert_eq!(net.fib(0, learnt), Some(Fib::Via(1)));

    (net, learnt, local)
}

/// Returns the updates that node `from` sent to node `to` since `start`.
fn updates_sent(net: &Net, from: usize, to: usize, start: Instant) -> Vec<Update> {
    let sent = net.sent.iter();
    let sent = sent.filter(|sent| (sent.from, sent.to) == (from, to) && sent.time >= start);
    sent.flat_map(|sent| updates(&sent.buf)).collect()
}

#[tokio::test(start_paused = true)]
async fn route_requests_are_answered() {
    let (mut net, learnt, local) = requested_net().await;
    let unknown = prefix("fd00:9::/64");
    let interval = 1600;

    let start = Instant::now();
    for p in [learnt, local, unknown] {
        let request = route_request(Ae::Ipv6, 64, &p.addr().octets()[..8]);
        net.inject(9, 0, &request);
    }
    net.inject(9, 0, &route_request(Ae::Ipv4, 8, &[10]));
    net.inject(9, 0, &route_request(Ae::V4ViaV6, 16, &[10, 1]));
    // So is a request from the neighbour that the route was learnt from, although
    // updates are otherwise not sent back to it (RFC 8966 §3.7.4).
    net.inject(
        1,
        0,
        &route_request(Ae::Ipv6, 64, &learnt.addr().octets()[..8]),
    );
    net.run_for(Duration::from_secs(3)).await;

    // Each request is answered with the route that node 0 advertises, or else with
    // a retraction carrying its own router-id and seqno, and the same AE
    // (RFC 8966 §3.8.1.1, RFC 9229 §2.3).
    let (seqno_0, seqno_1) = (net.nodes[0].seqno.get(), net.nodes[1].seqno.get());
    let ipv4_retraction = |ae, plen, octets: &[u8]| {
        let mut prefix = [0; 16];
        prefix[..octets.len()].copy_from_slice(octets);
        Update {
            ae,
            plen,
            prefix,
            ..update(unknown, 1, seqno_0, METRIC_INFINITY, interval)
        }
    };
    assert_eq!(
        updates_sent(&net, 0, 9, start),
        [
            update(learnt, 2, seqno_1, 96, interval),
            update(local, 1, seqno_0, 0, interval),
            update(unknown, 1, seqno_0, METRIC_INFINITY, interval),
            ipv4_retraction(Ae::Ipv4, 8, &[10]),
            ipv4_retraction(Ae::V4ViaV6, 16, &[10, 1]),
        ]
    );
    assert_eq!(
        updates_sent(&net, 0, 1, start),
        [update(learnt, 2, seqno_1, 96, interval)]
    );
}

#[tokio::test(start_paused = true)]
async fn wildcard_route_requests_are_answered_with_full_dumps() {
    let (mut net, learnt, local) = requested_net().await;

    // A wildcard request is answered with a full dump, sent to the requester only.
    let start = Instant::now();
    net.inject(9, 0, &route_request(Ae::Wildcard, 0, &[]));
    net.run_for(Duration::from_secs(3)).await;

    // A dump of both prefixes, in whichever order.
    let dumped = |net: &Net, to, start| {
        let mut prefixes: Vec<_> = (updates_sent(net, 0, to, start).into_iter())
            .map(|update| (update.plen, update.prefix))
            .collect();
        prefixes.sort();
        prefixes
    };
    let [local, learnt] = [local, learnt].map(|p| (p.prefix_len(), p.addr().octets()));
    assert_eq!(dumped(&net, 9, start), [local, learnt]);
    assert_eq!(updates_sent(&net, 0, 1, start), []);

    // So is one from the neighbour that a route was learnt from, but without that route,
    // as in periodic dumps (RFC 8966 §3.7.4).
    let start = Instant::now();
    net.inject(1, 0, &route_request(Ae::Wildcard, 0, &[]));
    net.run_for(Duration::from_secs(3)).await;
    assert_eq!(dumped(&net, 1, start), [local]);
}
