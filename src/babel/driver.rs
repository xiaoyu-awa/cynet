//! Runs a [`State`] on a dedicated thread, so that its handlers never stall the data plane.
//!
//! Some handlers do work proportional to the size of the network in one call, up to several
//! milliseconds at the scale traffic allows, which is too long to spend on a worker thread
//! shared with WireGuard.

#[cfg(test)]
mod tests;

use std::{future, hash::Hash, io, thread, time::Instant};

use ipnet::IpNet;
use tokio::{
    runtime,
    sync::{mpsc, oneshot},
    time::sleep_until,
};

use crate::babel::{NeighKey, NeighKeyMap, Output, Params, RouterId, State, snapshot::Snapshot};

/// What a driver can be asked to do. `K` identifies a neighbour.
pub enum Input<K> {
    /// Adds a neighbour, unless it is already known.
    AddNeighbour(K),
    /// Removes a neighbour, if it is known (see [`State::remove_neighbour`]).
    RemoveNeighbour(K),
    /// Handles a Babel packet from a neighbour, which is added first if it is unknown: a peer can
    /// get in touch while this node is still looking up endpoints, before adding its neighbours.
    Packet {
        /// The neighbour it came from.
        from: K,
        /// Its octets, from the Babel header on.
        buf: Box<[u8]>,
        /// When it arrived, as its receive timestamp.
        received_at: Instant,
    },
    /// Replies with a view of the router's state.
    Snapshot(oneshot::Sender<Snapshot<K>>),
    /// Says goodbye to every neighbour and stops (see [`State::shutdown`]).
    ///
    /// Closing the channel has the same effect, but the data plane keeps a sender for as long as
    /// it runs, and it has to outlive the driver to send the goodbyes.
    Shutdown,
}

/// Starts a driver on a thread of its own, which ends after [`Input::Shutdown`], or when `inputs`
/// is closed, or `outputs` is. The caller joins the returned handle.
///
/// It is given the arguments of [`State::new`], rather than a `State`, so that its timers start on
/// the driver's clock, and the prefixes that this node originates, whose routes are injected before
/// any input can add a neighbour (see [`State::inject_route`]).
pub fn spawn<K: Copy + Eq + Hash + Send + 'static>(
    params: Params,
    router_id: RouterId,
    prefixes: Vec<IpNet>,
    inputs: mpsc::Receiver<Input<K>>,
    outputs: mpsc::Sender<Output<K>>,
) -> io::Result<thread::JoinHandle<()>> {
    let runtime = runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;

    thread::Builder::new()
        .name("babel".to_owned())
        .spawn(move || runtime.block_on(run(params, router_id, prefixes, inputs, outputs)))
}

/// Asks a driver for a view of the router's state, or returns `None` if it has stopped.
pub async fn snapshot<K>(inputs: &mpsc::Sender<Input<K>>) -> Option<Snapshot<K>> {
    let (reply, snapshot) = oneshot::channel();
    inputs.send(Input::Snapshot(reply)).await.ok()?;
    snapshot.await.ok()
}

/// Returns the current time on Tokio's clock, which a test can pause.
pub fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Returns the external key of a neighbour, which every neighbour has.
fn external<K: Copy + Eq + Hash>(keys: &NeighKeyMap<K>, key: NeighKey) -> K {
    *keys
        .external(key)
        .expect("every neighbour should have an external key")
}

/// Returns the internal key of a neighbour, adding it if it is unknown.
fn get_or_add_neighbour<K: Copy + Eq + Hash>(
    state: &mut State,
    keys: &mut NeighKeyMap<K>,
    peer: K,
) -> NeighKey {
    keys.internal(&peer).unwrap_or_else(|| {
        let key = state.add_neighbour(now());
        keys.insert(peer, key);
        key
    })
}

/// Runs the driver's main loop.
async fn run<K: Copy + Eq + Hash>(
    params: Params,
    router_id: RouterId,
    prefixes: Vec<IpNet>,
    mut inputs: mpsc::Receiver<Input<K>>,
    outputs: mpsc::Sender<Output<K>>,
) {
    let mut state = State::new(now(), params, router_id, None);
    let mut keys = NeighKeyMap::new();

    for prefix in prefixes {
        state.inject_route(prefix);
    }

    loop {
        // This sleeps until the next timeout afresh each time, as handling an input can bring it
        // forward, for example when an urgent TLV is buffered. With no neighbours, no timer is
        // set, and only an input can wake the loop.
        let deadline = state.poll_timeout();
        let timeout = async {
            match deadline {
                Some(deadline) => sleep_until(deadline.into()).await,
                None => future::pending().await,
            }
        };

        tokio::select! {
            () = timeout => {
                state.handle_timeout(now());
            }
            input = inputs.recv() => match input {
                Some(Input::AddNeighbour(peer)) => {
                    get_or_add_neighbour(&mut state, &mut keys, peer);
                }
                Some(Input::RemoveNeighbour(peer)) => {
                    if let Some(key) = keys.internal(&peer) {
                        state.remove_neighbour(now(), key);
                        keys.remove_by_external(&peer);
                    }
                }
                Some(Input::Packet { from, buf, received_at }) => {
                    let key = get_or_add_neighbour(&mut state, &mut keys, from);
                    state.handle_packet(now(), received_at, key, &buf);
                }
                Some(Input::Snapshot(reply)) => {
                    let _ = reply.send(state.snapshot(now(), |key| external(&keys, key)));
                }
                Some(Input::Shutdown) | None => break,
            },
        }

        while let Some(output) = state.poll_output() {
            let output = output.with_key(|key| external(&keys, key));
            if outputs.send(output).await.is_err() {
                return;
            }
        }
    }

    for output in state.shutdown(now()) {
        let output = output.with_key(|key| external(&keys, key));
        if outputs.send(output).await.is_err() {
            return;
        }
    }
}
