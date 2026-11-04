//! The data plane: decides where each packet goes, in place of WireGuard's cryptokey routing.
//!
//! A packet from a peer is a Babel packet, for delivery to this host, or to be forwarded to another
//! peer, without the kernel's help. A packet from the host goes to a peer. What cannot go anywhere
//! is answered with an ICMP error, following Linux.
//!
//! Babel's traffic stays inside the tunnels, between link-local addresses derived from public keys
//! (see [`link_local_address`]). These are never assigned to the interface, so the kernel never
//! sees it.

mod icmp;
mod ip;
mod link;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use gotatun::{
    device::{self, Verdict},
    packet::{Ip, Packet},
    tun::MtuWatcher,
    x25519::PublicKey,
};
use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};
use prefix_trie::joint::{JointPrefixMap, JointPrefixSet};
use tokio::sync::mpsc;

use crate::{
    babel::{
        RouterId,
        driver::{self, Input},
    },
    router::{
        icmp::{DUMMY_V4, IcmpError, Limiter},
        ip::IpPacket,
    },
};

pub use crate::router::link::link_local_address;

/// A route in the forwarding table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Route {
    /// The next hop is this peer.
    Peer(PublicKey),
    /// The prefix is on this host: one of its addresses, or a network directly attached to it.
    Local,
    /// The prefix is held unreachable by Babel, which keeps a less specific route from taking
    /// over, as that could form a loop (RFC 8966 §3.5.4).
    Held,
}

/// What a [`Router`] needs to know about this node.
pub struct RouterConfig<'a> {
    /// The public key of this node.
    pub public_key: PublicKey,
    /// The addresses of its interface.
    pub addresses: &'a [IpAddr],
    /// The prefixes of the networks directly attached to it.
    pub attached: &'a [IpNet],
    /// The sources from which a packet may be delivered to this host.
    pub mesh: &'a [IpNet],
    /// Its router-id.
    pub router_id: RouterId,
}

/// The forwarding table.
type Fib = JointPrefixMap<IpNet, Route>;

/// Returns the route with the longest match for an address, if any.
fn lookup(fib: &Fib, addr: IpAddr) -> Option<Route> {
    fib.get_lpm(&addr.into()).map(|(_, &route)| route)
}

/// Decides where each packet goes (see the [module docs](self)).
pub struct Router {
    /// The longest match for a destination decides where a packet goes. It is locked only
    /// briefly, and never across an await.
    fib: RwLock<Fib>,
    mesh: JointPrefixSet<IpNet>,
    /// The source of ICMPv4 errors from this node.
    icmp_source_v4: Ipv4Addr,
    /// The source of ICMPv6 errors from this node.
    icmp_source_v6: Ipv6Addr,
    /// The link-local address of this node.
    link_local: Ipv6Addr,
    /// Where Babel packets go. A full channel drops them, as Babel tolerates loss, and the data
    /// plane must never wait for it.
    babel: mpsc::Sender<Input<PublicKey>>,
    limiter: Mutex<Limiter>,
}

impl Router {
    /// Creates a router, with a route for each address and attached network of this node, and
    /// no others until they are selected. Babel packets are sent to `babel`.
    pub fn new(config: RouterConfig<'_>, babel: mpsc::Sender<Input<PublicKey>>) -> Self {
        let mut fib = Fib::new();
        for prefix in local_prefixes(config.addresses, config.attached) {
            fib.insert(prefix, Route::Local);
        }

        let mut mesh = JointPrefixSet::new();
        for prefix in config.mesh {
            mesh.insert(*prefix);
        }

        let first_v4 = config.addresses.iter().find_map(|addr| match addr {
            IpAddr::V4(addr) => Some(*addr),
            IpAddr::V6(_) => None,
        });
        let first_v6 = config.addresses.iter().find_map(|addr| match addr {
            IpAddr::V4(_) => None,
            IpAddr::V6(addr) => Some(*addr),
        });

        Self {
            fib: RwLock::new(fib),
            mesh,
            icmp_source_v4: first_v4.unwrap_or(DUMMY_V4),
            icmp_source_v6: first_v6.unwrap_or_else(|| icmp::dummy_v6(config.router_id)),
            link_local: link_local_address(&config.public_key),
            babel,
            limiter: Mutex::new(Limiter::new(driver::now())),
        }
    }

    /// Selects a peer as the next hop to a prefix.
    pub fn select_route(&self, prefix: IpNet, peer: PublicKey) {
        self.fib.write().insert(prefix, Route::Peer(peer));
    }

    /// Holds a prefix, unreachable.
    pub fn hold_route(&self, prefix: IpNet) {
        self.fib.write().insert(prefix, Route::Held);
    }

    /// Removes the route to a prefix.
    pub fn remove_route(&self, prefix: IpNet) {
        self.fib.write().remove(&prefix);
    }

    /// Wraps a Babel packet for a peer.
    pub fn babel_packet_to(&self, peer: &PublicKey, payload: &[u8]) -> Packet<Ip> {
        link::babel_packet(self.link_local, link_local_address(peer), payload)
    }

    /// Hands a Babel packet from a peer to the driver, if it is one.
    fn handle_link_local(&self, from: &PublicKey, packet: IpPacket) {
        let received_at = driver::now();

        if let Some(buf) = link::babel_payload(packet, link_local_address(from), self.link_local) {
            let _ = self.babel.try_send(Input::Packet {
                from: *from,
                buf,
                received_at,
            });
        }
    }

    /// Builds an ICMP error about `packet`, if it may be answered and the limiter allows it.
    fn icmp_error(&self, packet: &IpPacket, error: IcmpError) -> Option<Packet<Ip>> {
        if !icmp::eligible(packet) {
            return None;
        }
        let allowed = self
            .limiter
            .lock()
            .allow(error, packet.source(), driver::now());
        allowed.then(|| match packet {
            IpPacket::V4(packet) => icmp::build_v4(self.icmp_source_v4, packet, error),
            IpPacket::V6(packet) => icmp::build_v6(self.icmp_source_v6, packet, error),
        })
    }

    /// Answers a packet from a peer with an ICMP error, along `source_route`, the route to its
    /// source.
    fn answer_peer(
        &self,
        source_route: Option<Route>,
        packet: &IpPacket,
        error: IcmpError,
    ) -> Verdict {
        let Some(Route::Peer(next_hop)) = source_route else {
            return Verdict::Consumed;
        };
        self.icmp_error(packet, error)
            .map_or(Verdict::Consumed, |reply| Verdict::ToPeer(next_hop, reply))
    }
}

impl device::Router for Router {
    fn route_from_peer(
        &self,
        from: &PublicKey,
        packet: Packet<Ip>,
        mtu: &mut MtuWatcher,
    ) -> Verdict {
        let Some(mut packet) = IpPacket::parse(packet) else {
            return Verdict::Consumed;
        };
        let (source, destination) = (packet.source(), packet.destination());

        if ip::is_link_local(source) || ip::is_link_local(destination) {
            self.handle_link_local(from, packet);
            return Verdict::Consumed;
        }

        if ip::martian_source(source) || ip::martian_destination(destination) {
            return Verdict::Consumed;
        }

        // A node with no address of the family cannot source its errors from anywhere better
        // than a dummy address, which no other node owns, and no filter could list.
        let dummy_error = icmp::is_dummy_error(&packet);

        let (source_route, route) = {
            let fib = self.fib.read();
            (lookup(&fib, source), lookup(&fib, destination))
        };

        // A packet from a peer has no business coming from this host, or from the networks
        // attached to it, unless a more specific route takes it elsewhere.
        if !dummy_error && source_route == Some(Route::Local) {
            return Verdict::Consumed;
        }

        // The route is looked up first, then the hop limit, then the MTU, as in Linux.
        match route {
            Some(Route::Local) => {
                // A packet only passing through this node is not filtered, so that a node not
                // yet told of a new prefix in `mesh` still carries it.
                if dummy_error || self.mesh.is_covered(&source.into()) {
                    Verdict::ToTun(packet.into_ip())
                } else {
                    Verdict::Consumed
                }
            }
            Some(Route::Peer(next_hop)) => {
                if packet.hop_limit() <= 1 {
                    return self.answer_peer(source_route, &packet, IcmpError::TimeExceeded);
                }

                let mtu = mtu.get();
                if packet.too_big(mtu) {
                    return self.answer_peer(source_route, &packet, IcmpError::TooBig(mtu));
                }

                packet.decrement_hop_limit();
                Verdict::ToPeer(next_hop, packet.into_ip())
            }
            Some(Route::Held) => {
                self.answer_peer(source_route, &packet, IcmpError::HostUnreachable)
            }
            None => self.answer_peer(source_route, &packet, IcmpError::NetUnreachable),
        }
    }

    fn route_from_tun(&self, packet: Packet<Ip>) -> Verdict {
        let Some(destination) = packet.destination() else {
            return Verdict::Consumed;
        };

        if ip::is_link_local(destination) || ip::martian_destination(destination) {
            return Verdict::Consumed;
        }

        let route = lookup(&self.fib.read(), destination);
        let error = match route {
            // The kernel has already decremented the hop limit, if it was forwarding.
            Some(Route::Peer(next_hop)) => return Verdict::ToPeer(next_hop, packet),
            Some(Route::Held) => IcmpError::HostUnreachable,
            // A route to this host that the kernel sent here anyway would otherwise go round
            // through the kernel again.
            Some(Route::Local) | None => IcmpError::NetUnreachable,
        };

        // The error goes back through the TUN: the packet's source is this host or a network that
        // the kernel forwards for, wherever the forwarding table says.
        IpPacket::parse(packet)
            .and_then(|packet| self.icmp_error(&packet, error))
            .map_or(Verdict::Consumed, Verdict::ToTun)
    }
}

/// Returns the prefixes on this host: a host route for each address, and each attached network.
pub fn local_prefixes<'a>(
    addresses: &'a [IpAddr],
    attached: &'a [IpNet],
) -> impl Iterator<Item = IpNet> + 'a {
    let hosts = addresses.iter().map(|&addr| IpNet::from(addr));
    hosts.chain(attached.iter().map(|prefix| prefix.trunc()))
}
