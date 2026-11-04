use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use ipnet::IpNet;
use tokio::{
    sync::mpsc,
    task::LocalSet,
    time::{sleep, timeout},
};

use super::{Input, now, run, snapshot, spawn};
use crate::babel::{
    Interval, Output, Params, RouterId,
    packet::PacketDecoder,
    packet::PacketItem,
    packet::tlv::Tlv,
    snapshot::{PrefixStatus, Snapshot},
};

fn prefix(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn router_id(n: u64) -> RouterId {
    RouterId::new(n).unwrap()
}

/// Short intervals, so that a test advances the paused clock as little as it needs to.
fn params() -> Params {
    let mut params = Params::new();
    params.set_hello_interval(Interval::new(100).unwrap());
    params
}

/// A driver running as a local task of a test's paused runtime.
struct Driver {
    inputs: mpsc::Sender<Input<usize>>,
    events: mpsc::Receiver<Output<usize>>,
}

impl Driver {
    fn start(n: u64) -> Self {
        Self::start_originating(n, vec![])
    }

    /// Starts a driver that originates routes for `prefixes`.
    fn start_originating(n: u64, prefixes: Vec<IpNet>) -> Self {
        let (inputs_tx, inputs_rx) = mpsc::channel(64);
        let (events_tx, events_rx) = mpsc::channel(64);
        tokio::task::spawn_local(run(params(), router_id(n), prefixes, inputs_rx, events_tx));
        Self {
            inputs: inputs_tx,
            events: events_rx,
        }
    }

    async fn send(&self, input: Input<usize>) {
        self.inputs.send(input).await.unwrap();
    }

    async fn snapshot(&self) -> Snapshot<usize> {
        snapshot(&self.inputs).await.unwrap()
    }

    /// Returns the next event, which should come before a long time has passed.
    async fn next_event(&mut self) -> Output<usize> {
        timeout(Duration::from_secs(600), self.events.recv())
            .await
            .expect("an event should come")
            .expect("the driver should be running")
    }
}

async fn local_test(f: impl Future<Output = ()>) {
    LocalSet::new().run_until(f).await;
}

fn is_packet_to(event: &Output<usize>, peer: usize) -> bool {
    matches!(event, Output::Packet(to, _) if *to == peer)
}

#[tokio::test(start_paused = true)]
async fn adding_a_neighbour_twice_changes_nothing() {
    local_test(async {
        let mut driver = Driver::start(1);
        assert!(driver.snapshot().await.neighbours.is_empty());

        driver.send(Input::AddNeighbour(7)).await;
        // A new neighbour is sent a wildcard retraction at once.
        assert!(is_packet_to(&driver.next_event().await, 7));
        let once = driver.snapshot().await;
        assert_eq!(once.neighbours.len(), 1);
        assert_eq!(once.neighbours[0].key, 7);

        driver.send(Input::AddNeighbour(7)).await;
        assert_eq!(driver.snapshot().await.neighbours, once.neighbours);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn removed_neighbours_hear_nothing_more_and_can_come_back() {
    local_test(async {
        let mut driver = Driver::start(1);

        // Removing an unknown neighbour changes nothing.
        driver.send(Input::RemoveNeighbour(7)).await;
        assert!(driver.snapshot().await.neighbours.is_empty());

        driver.send(Input::AddNeighbour(7)).await;
        assert!(is_packet_to(&driver.next_event().await, 7));

        driver.send(Input::RemoveNeighbour(7)).await;
        assert!(driver.snapshot().await.neighbours.is_empty());

        // Its timers went with it, and the Hello and dump in its buffer too.
        assert!(
            timeout(Duration::from_secs(60), driver.events.recv())
                .await
                .is_err()
        );

        // It is a new neighbour when it comes back, and is sent a wildcard retraction again.
        driver.send(Input::AddNeighbour(7)).await;
        assert!(is_packet_to(&driver.next_event().await, 7));
        assert_eq!(driver.snapshot().await.neighbours.len(), 1);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn removing_a_neighbour_holds_its_routes() {
    local_test(async {
        let p = prefix("fd00:1::/64");
        let mut a = Driver::start_originating(1, vec![p]);
        let mut b = Driver::start(2);

        a.send(Input::AddNeighbour(2)).await;
        b.send(Input::AddNeighbour(1)).await;
        relay_until(
            &mut a,
            &mut b,
            |event| matches!(event, Output::RouteSelect(q, 1) if *q == p),
        )
        .await;

        b.send(Input::RemoveNeighbour(1)).await;
        let snapshot = b.snapshot().await;
        assert_eq!(snapshot.prefixes[0].status, PrefixStatus::Held);

        // Packets from before the removal may be waiting, but once the hold is over, it's over.
        loop {
            match b.next_event().await {
                Output::RouteRemove(q) if q == p => break,
                Output::RouteSelect(..) => panic!("no route should be selected"),
                _ => {}
            }
        }
    })
    .await;
}

/// A peer can get in touch before the caller has added it, which isn't lost on this node: its sender
/// becomes a neighbour first, and its request for an acknowledgement is answered.
#[tokio::test(start_paused = true)]
async fn a_packet_from_a_new_peer_adds_it_and_is_handled() {
    local_test(async {
        let p = prefix("fd00:1::/64");
        let mut a = Driver::start_originating(1, vec![p]);
        let mut b = Driver::start(2);

        a.send(Input::AddNeighbour(2)).await;

        let Output::Packet(2, mut packet) = a.next_event().await else {
            panic!("expected a startup packet to neighbour 2");
        };
        b.send(Input::Packet {
            from: 1,
            buf: packet.timestamp(now()).into(),
            received_at: now(),
        })
        .await;

        let snapshot = b.snapshot().await;
        assert_eq!(snapshot.neighbours.len(), 1);
        assert_eq!(snapshot.neighbours[0].key, 1);

        // Node 2's startup packet, and its acknowledgement of node 1's, take them both on from there.
        relay_until(
            &mut a,
            &mut b,
            |event| matches!(event, Output::RouteSelect(q, 1) if *q == p),
        )
        .await;

        // The caller may notice the peer later, which changes nothing.
        b.send(Input::AddNeighbour(1)).await;
        assert_eq!(b.snapshot().await.neighbours.len(), 1);
    })
    .await;
}

/// Relays packets between two drivers until `done` holds for an event of node `b`.
async fn relay_until(a: &mut Driver, b: &mut Driver, done: impl Fn(&Output<usize>) -> bool) {
    let deadline = sleep(Duration::from_secs(600));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            event = a.events.recv() => {
                if let Some(Output::Packet(2, mut packet)) = event {
                    let buf = packet.timestamp(now()).into();
                    b.send(Input::Packet { from: 1, buf, received_at: now() }).await;
                }
            }
            event = b.events.recv() => {
                let event = event.unwrap();
                if done(&event) {
                    return;
                }
                if let Output::Packet(1, mut packet) = event {
                    let buf = packet.timestamp(now()).into();
                    a.send(Input::Packet { from: 2, buf, received_at: now() }).await;
                }
            }
            () = &mut deadline => panic!("the condition should come true in time"),
        }
    }
}

#[tokio::test(start_paused = true)]
async fn two_drivers_acquire_each_other_and_exchange_routes() {
    local_test(async {
        let p = prefix("fd00:1::/64");
        let mut a = Driver::start_originating(1, vec![p]);
        let mut b = Driver::start(2);

        a.send(Input::AddNeighbour(2)).await;
        b.send(Input::AddNeighbour(1)).await;

        relay_until(
            &mut a,
            &mut b,
            |event| matches!(event, Output::RouteSelect(q, 1) if *q == p),
        )
        .await;

        let snapshot = a.snapshot().await;
        assert_eq!(snapshot.router_id, router_id(1));
        assert!(
            snapshot
                .prefixes
                .iter()
                .any(|entry| { entry.prefix == p && entry.status == PrefixStatus::Injected })
        );

        let snapshot = b.snapshot().await;
        let entry = snapshot.prefixes.iter().find(|e| e.prefix == p).unwrap();
        assert_eq!(entry.status, PrefixStatus::Selected(1));
        assert_eq!(entry.routes.len(), 1);
        assert_eq!(entry.routes[0].via, 1);
        assert_eq!(entry.routes[0].router_id, router_id(1));
        assert!(snapshot.neighbours[0].cost < u16::MAX);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn martian_routes_are_not_learned() {
    local_test(async {
        let good = prefix("fd00:1::/64");

        // Node 1 is made to advertise link-local and multicast prefixes, which a correct
        // configuration rejects, and an ordinary one to tell when node 2 has heard it.
        let injected = vec![prefix("fe80::1/128"), prefix("ff02::/16"), good];
        let mut a = Driver::start_originating(1, injected);
        let mut b = Driver::start(2);

        a.send(Input::AddNeighbour(2)).await;
        b.send(Input::AddNeighbour(1)).await;

        relay_until(
            &mut a,
            &mut b,
            |event| matches!(event, Output::RouteSelect(q, 1) if *q == good),
        )
        .await;

        let prefixes: Vec<_> = b
            .snapshot()
            .await
            .prefixes
            .iter()
            .map(|e| e.prefix)
            .collect();
        assert_eq!(prefixes, [good]);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_says_goodbye_and_removes_routes() {
    local_test(async {
        let p = prefix("fd00:1::/64");
        let mut a = Driver::start_originating(1, vec![p]);
        let mut b = Driver::start(2);

        a.send(Input::AddNeighbour(2)).await;
        b.send(Input::AddNeighbour(1)).await;

        relay_until(
            &mut a,
            &mut b,
            |event| matches!(event, Output::RouteSelect(q, 1) if *q == p),
        )
        .await;

        // Unlike a closed channel, this leaves the sender in place, as the data plane does.
        b.send(Input::Shutdown).await;

        let mut goodbye = false;
        let mut removed = false;
        while let Some(event) = b.events.recv().await {
            match event {
                Output::RouteRemove(q) if q == p => removed = true,
                Output::Packet(1, packet) => {
                    // The goodbye is a wildcard retraction and a Hello with a short interval.
                    goodbye |= PacketDecoder::new(packet.as_bytes()).unwrap().any(|item| {
                        matches!(
                            item,
                            Ok(PacketItem::Tlv(Tlv::Hello { interval, .. }))
                                if interval == Interval::new(1)
                        )
                    });
                }
                _ => {}
            }
        }
        assert!(goodbye);
        assert!(removed);

        // The driver has stopped, but the sender it was given can still be used in vain.
        assert!(b.inputs.is_closed());
    })
    .await;
}

#[test]
fn thread_exits_when_the_input_channel_closes() {
    let (inputs, inputs_rx) = mpsc::channel::<Input<usize>>(1);
    let (events_tx, mut events) = mpsc::channel(1);
    let handle = spawn(params(), router_id(1), vec![], inputs_rx, events_tx).unwrap();

    assert_eq!(handle.thread().name(), Some("babel"));

    drop(inputs);
    // With no neighbours, nothing is said on the way out, and the events channel closes.
    assert!(events.blocking_recv().is_none());
    handle.join().unwrap();
}

#[test]
fn thread_exits_when_the_events_channel_closes() {
    let (inputs, inputs_rx) = mpsc::channel(1);
    let (events_tx, events) = mpsc::channel(1);
    let handle = spawn(params(), router_id(1), vec![], inputs_rx, events_tx).unwrap();

    drop(events);
    // Adding a neighbour produces an event to send, which fails.
    inputs.blocking_send(Input::AddNeighbour(1usize)).unwrap();
    handle.join().unwrap();
}

/// Packets are translated in both directions: the event names the peer, and the snapshot's
/// neighbours and routes are given by peer rather than by internal key.
#[tokio::test(start_paused = true)]
async fn neighbours_are_identified_by_peer() {
    local_test(async {
        let mut driver = Driver::start(1);
        let mut seen = HashMap::new();

        for peer in [10, 20] {
            driver.send(Input::AddNeighbour(peer)).await;
        }
        while seen.len() < 2 {
            if let Output::Packet(peer, _) = driver.next_event().await {
                seen.insert(peer, ());
            }
        }

        let mut keys: Vec<_> = (driver.snapshot().await.neighbours.iter())
            .map(|neigh| neigh.key)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, [10, 20]);
    })
    .await;
}

/// A receive timestamp older than the current time is taken as given, and does not stop the
/// driver from handling what comes after it.
#[tokio::test(start_paused = true)]
async fn old_receive_timestamps_are_accepted() {
    local_test(async {
        let mut a = Driver::start(1);
        let b = Driver::start(2);

        a.send(Input::AddNeighbour(2)).await;
        b.send(Input::AddNeighbour(1)).await;

        let Output::Packet(2, mut packet) = a.next_event().await else {
            panic!("expected a packet to neighbour 2");
        };

        let received_at: Instant = now();
        sleep(Duration::from_secs(1)).await;
        b.send(Input::Packet {
            from: 1,
            buf: packet.timestamp(received_at).into(),
            received_at,
        })
        .await;
        assert_eq!(b.snapshot().await.neighbours.len(), 1);
    })
    .await;
}
