use std::{future::poll_fn, task::Poll};

use tokio::time::timeout_at;

use super::*;

const NOMINAL_COST: u16 = 96;
const INF: u16 = COST_INFINITY;

/// The rxcost, txcost and link cost of a link that is up with a negligible RTT.
const UP: (u16, u16, u16) = (NOMINAL_COST, NOMINAL_COST, NOMINAL_COST);

/// Returns the link key of node `i`.
fn key(i: usize) -> LinkKey {
    LinkKey::from([i as u8; 32])
}

/// A packet sent by a node, whether or not it was delivered.
struct Sent {
    time: Instant,
    from: usize,
    to: usize,
    buf: Box<[u8]>,
}

enum Event {
    Timeout(usize, Timeout),
    Arrival(usize, usize, Box<[u8]>),
}

/// Nodes connected by point-to-point links, driven by a paused clock.
struct Net {
    nodes: Vec<State>,
    /// The one-way latency of each link direction that is up.
    links: HashMap<(usize, usize), Duration>,
    in_flight: DelayQueue<(usize, usize, Box<[u8]>)>,
    sent: Vec<Sent>,
}

impl Net {
    fn new(n: usize) -> Self {
        Self {
            nodes: (0..n).map(|_| State::new(Params::new(), None)).collect(),
            links: HashMap::new(),
            in_flight: DelayQueue::new(),
            sent: Vec::new(),
        }
    }

    fn connect(&mut self, a: usize, b: usize, latency: Duration) {
        assert!(self.nodes[a].add_neighbour(key(b)));
        assert!(self.nodes[b].add_neighbour(key(a)));
        self.links.insert((a, b), latency);
        self.links.insert((b, a), latency);
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
                self.nodes[to].handle_packet(&key(from), &buf);
                to
            }
        };
        self.transmit(i);
    }

    /// Hands a packet to node `to` as if it came from node `from`.
    fn inject(&mut self, from: usize, to: usize, buf: &[u8]) {
        self.nodes[to].handle_packet(&key(from), buf);
        self.transmit(to);
    }

    /// Sends the packets output by node `from` over the links that are up.
    fn transmit(&mut self, from: usize) {
        while let Some(output) = self.nodes[from].poll_output() {
            // Other outputs do not go over the links.
            #[expect(irrefutable_let_patterns)]
            let Output::Packet(dst, buf) = output else {
                continue;
            };

            let to = dst.as_bytes()[0] as usize;
            if let Some(&latency) = self.links.get(&(from, to)) {
                self.in_flight.insert((from, to, buf.clone()), latency);
            }
            self.sent.push(Sent {
                time: Instant::now(),
                from,
                to,
                buf,
            });
        }
    }

    /// Returns node `i`'s entry for node `j`.
    fn neigh(&self, i: usize, j: usize) -> &NeighbourValue {
        &self.nodes[i].neighbour_table[&key(j)]
    }

    /// Returns node `i`'s rxcost, txcost and link cost for node `j`.
    fn costs(&self, i: usize, j: usize) -> (u16, u16, u16) {
        let neigh = self.neigh(i, j);
        (neigh.rxcost(), neigh.txcost, neigh.cost())
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

/// Builds a packet with the given body.
fn packet(body: &[u8]) -> Vec<u8> {
    let mut buf = vec![42, 2];
    buf.extend((body.len() as u16).to_be_bytes());
    buf.extend(body);
    buf
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
        let mut neigh = NeighbourValue::new(&Params::new());

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

        let row = (bits, txcost, rtt_ms);
        assert_eq!((neigh.rxcost(), neigh.cost()), (rxcost, cost), "{row:?}");
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
    net.nodes[1] = State::new(Params::new(), None);
    net.nodes[1].hello_seqno = hello_seqno;
    assert!(net.nodes[1].add_neighbour(key(0)));

    // Its first Hello flushes node 0's entry for it, restarting the history.
    net.run_for(Duration::from_secs(3)).await;
    let neigh = net.neigh(0, 1);
    assert_eq!(neigh.hello_history.bits(), 0b1);
    assert_eq!((neigh.txcost, neigh.rtt), (INF, None));

    net.run_for(Duration::from_secs(30)).await;
    assert_eq!(net.costs(0, 1), UP);
    assert_eq!(net.costs(1, 0), UP);
}

#[tokio::test(start_paused = true)]
async fn acknowledgement_requests_are_answered_in_time() {
    // Node 1 is outside the simulation and only sends the requests.
    let mut net = Net::new(1);
    assert!(net.nodes[0].add_neighbour(key(1)));

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
