use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use gotatun::{
    device::{Router as _, Verdict},
    packet::Packet,
    tun::MtuWatcher,
    x25519::{PublicKey, StaticSecret},
};
use ipnet::IpNet;
use tokio::sync::mpsc;
use zerocopy::IntoBytes;

use super::{
    Router, RouterConfig,
    icmp::{DUMMY_V4, IcmpError, Limiter},
    ip::IpPacket,
    link::{BABEL_PORT, babel_packet},
    link_local_address,
};
use crate::babel::{RouterId, driver::Input};

const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMPV6: u8 = 58;

const DF: u16 = 0x4000;
const MF: u16 = 0x2000;

const MTU: u16 = 1400;

fn key(n: u8) -> PublicKey {
    PublicKey::from(&StaticSecret::from([n; 32]))
}

/// The Internet checksum, written apart from the code under test.
fn checksum(chunks: &[&[u8]]) -> u16 {
    let bytes: Vec<u8> = chunks.concat();
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IPv4 packet, with TOS and an identification of 0x1234 that tests can ignore.
#[derive(Clone)]
struct V4 {
    source: &'static str,
    destination: &'static str,
    protocol: u8,
    ttl: u8,
    tos: u8,
    flags_and_offset: u16,
    options: Vec<u8>,
    payload: Vec<u8>,
}

impl V4 {
    fn new(source: &'static str, destination: &'static str) -> Self {
        Self {
            source,
            destination,
            protocol: UDP,
            ttl: 64,
            tos: 0,
            flags_and_offset: DF,
            options: Vec::new(),
            payload: vec![0xab; 32],
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let header_len = 20 + self.options.len();
        let mut b = vec![0; header_len];
        b[0] = 0x40 | (header_len / 4) as u8;
        b[1] = self.tos;
        b[2..4].copy_from_slice(&((header_len + self.payload.len()) as u16).to_be_bytes());
        b[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        b[6..8].copy_from_slice(&self.flags_and_offset.to_be_bytes());
        b[8] = self.ttl;
        b[9] = self.protocol;
        b[12..16].copy_from_slice(&self.source.parse::<Ipv4Addr>().unwrap().octets());
        b[16..20].copy_from_slice(&self.destination.parse::<Ipv4Addr>().unwrap().octets());
        b[20..header_len].copy_from_slice(&self.options);
        let check = checksum(&[&b]);
        b[10..12].copy_from_slice(&check.to_be_bytes());
        b.extend_from_slice(&self.payload);
        b
    }
}

/// An IPv6 packet.
#[derive(Clone)]
struct V6 {
    source: &'static str,
    destination: &'static str,
    next_header: u8,
    hop_limit: u8,
    payload: Vec<u8>,
}

impl V6 {
    fn new(source: &'static str, destination: &'static str) -> Self {
        Self {
            source,
            destination,
            next_header: UDP,
            hop_limit: 64,
            payload: vec![0xab; 32],
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut b = vec![0x60, 0, 0, 0];
        b.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        b.extend_from_slice(&[self.next_header, self.hop_limit]);
        b.extend_from_slice(&self.source.parse::<Ipv6Addr>().unwrap().octets());
        b.extend_from_slice(&self.destination.parse::<Ipv6Addr>().unwrap().octets());
        b.extend_from_slice(&self.payload);
        b
    }
}

/// A [`Verdict`], with packets as octets, for comparison.
#[derive(Debug, Eq, PartialEq)]
enum Got {
    Tun(Vec<u8>),
    Peer(PublicKey, Vec<u8>),
    Consumed,
}

impl Got {
    fn new(verdict: Verdict) -> Self {
        match verdict {
            Verdict::ToTun(packet) => Self::Tun(packet.as_bytes().to_vec()),
            Verdict::ToPeer(to, packet) => Self::Peer(to, packet.as_bytes().to_vec()),
            Verdict::Consumed => Self::Consumed,
        }
    }

    #[track_caller]
    fn tun(self) -> Vec<u8> {
        match self {
            Self::Tun(bytes) => bytes,
            got => panic!("expected a packet to the TUN, got {got:?}"),
        }
    }

    #[track_caller]
    fn peer(self, expected: PublicKey) -> Vec<u8> {
        match self {
            Self::Peer(to, bytes) if to == expected => bytes,
            got => panic!("expected a packet to {expected:?}, got {got:?}"),
        }
    }
}

fn ip_packet(bytes: &[u8]) -> Packet<gotatun::packet::Ip> {
    Packet::copy_from(bytes).try_into_ip().unwrap()
}

/// A router on node `me`, with peers `a` and `b`, and these routes:
///
/// - 10.42.0.2 and fd42::2 through `a`, and 10.42.0.3 and fd42::3 through `b`
/// - 10.42.0.9 and fd42::9 held
/// - 10.43.0.2 and fd43::2 through `a`, and 10.43.0.1 and fd43::1 through `b`, outside `mesh`
struct Fixture {
    router: Router,
    babel: mpsc::Receiver<Input<PublicKey>>,
    me: PublicKey,
    a: PublicKey,
    b: PublicKey,
}

impl Fixture {
    fn new() -> Self {
        Self::with(
            &["10.42.0.1", "fd42::1"],
            &["192.168.7.0/24", "fd99::/64"],
            &["10.42.0.0/16", "fd42::/48", "192.168.0.0/16", "fd99::/16"],
        )
    }

    fn with(addresses: &[&str], attached: &[&str], mesh: &[&str]) -> Self {
        let addresses: Vec<IpAddr> = addresses.iter().map(|a| a.parse().unwrap()).collect();
        let attached: Vec<IpNet> = attached.iter().map(|a| a.parse().unwrap()).collect();
        let mesh: Vec<IpNet> = mesh.iter().map(|a| a.parse().unwrap()).collect();
        let (me, a, b) = (key(1), key(2), key(3));

        let (babel_tx, babel) = mpsc::channel(4);
        let router = Router::new(
            RouterConfig {
                public_key: me,
                addresses: &addresses,
                attached: &attached,
                mesh: &mesh,
                router_id: RouterId::new(0x1122_3344_5566_7788).unwrap(),
            },
            babel_tx,
        );

        for prefix in ["10.42.0.2/32", "fd42::2/128", "10.43.0.2/32", "fd43::2/128"] {
            router.select_route(prefix.parse().unwrap(), a);
        }
        for prefix in ["10.42.0.3/32", "fd42::3/128", "10.43.0.1/32", "fd43::1/128"] {
            router.select_route(prefix.parse().unwrap(), b);
        }
        for prefix in ["10.42.0.9/32", "fd42::9/128"] {
            router.hold_route(prefix.parse().unwrap());
        }

        Self {
            router,
            babel,
            me,
            a,
            b,
        }
    }

    fn route_peer(&self, peer: PublicKey, bytes: &[u8]) -> Got {
        let mut mtu = MtuWatcher::new(MTU);
        Got::new(
            self.router
                .route_from_peer(&peer, ip_packet(bytes), &mut mtu),
        )
    }

    fn route_a(&self, bytes: &[u8]) -> Got {
        self.route_peer(self.a, bytes)
    }

    fn route_b(&self, bytes: &[u8]) -> Got {
        self.route_peer(self.b, bytes)
    }

    fn route_tun(&self, bytes: &[u8]) -> Got {
        Got::new(self.router.route_from_tun(ip_packet(bytes)))
    }
}

/// The fields of an ICMPv4 error, checked for being well formed along the way.
struct IcmpV4 {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    tos: u8,
    ty: u8,
    code: u8,
    rest: u32,
    quoted: Vec<u8>,
}

#[track_caller]
fn icmp_v4(reply: &[u8]) -> IcmpV4 {
    assert_eq!(reply[0], 0x45);
    assert_eq!(
        u16::from_be_bytes([reply[2], reply[3]]) as usize,
        reply.len()
    );
    // DF is clear and it is not a fragment.
    assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0);
    assert_eq!(reply[8], 64);
    assert_eq!(reply[9], ICMP);
    assert_eq!(checksum(&[&reply[..20]]), 0);
    assert_eq!(checksum(&[&reply[20..]]), 0);
    IcmpV4 {
        source: Ipv4Addr::from_octets(reply[12..16].try_into().unwrap()),
        destination: Ipv4Addr::from_octets(reply[16..20].try_into().unwrap()),
        tos: reply[1],
        ty: reply[20],
        code: reply[21],
        rest: u32::from_be_bytes(reply[24..28].try_into().unwrap()),
        quoted: reply[28..].to_vec(),
    }
}

/// The fields of an ICMPv6 error, checked for being well formed along the way.
struct IcmpV6 {
    source: Ipv6Addr,
    destination: Ipv6Addr,
    ty: u8,
    code: u8,
    rest: u32,
    quoted: Vec<u8>,
}

#[track_caller]
fn icmp_v6(reply: &[u8]) -> IcmpV6 {
    assert_eq!(reply[0] >> 4, 6);
    assert_eq!(
        u16::from_be_bytes([reply[4], reply[5]]) as usize,
        reply.len() - 40
    );
    assert_eq!(reply[6], ICMPV6);
    assert_eq!(reply[7], 64);
    let pseudo_end = [0, 0, 0, ICMPV6];
    let length = ((reply.len() - 40) as u32).to_be_bytes();
    assert_eq!(
        checksum(&[&reply[8..40], &length, &pseudo_end, &reply[40..]]),
        0
    );
    IcmpV6 {
        source: Ipv6Addr::from_octets(reply[8..24].try_into().unwrap()),
        destination: Ipv6Addr::from_octets(reply[24..40].try_into().unwrap()),
        ty: reply[40],
        code: reply[41],
        rest: u32::from_be_bytes(reply[44..48].try_into().unwrap()),
        quoted: reply[48..].to_vec(),
    }
}

#[test]
fn forwarding_decrements_the_ttl_and_keeps_the_checksum_valid() {
    let f = Fixture::new();
    let packet = V4::new("10.42.0.2", "10.42.0.3").bytes();
    let forwarded = f.route_a(&packet).peer(f.b);

    assert_eq!(forwarded.len(), packet.len());
    assert_eq!(forwarded[8], 63);
    assert_eq!(checksum(&[&forwarded[..20]]), 0);
    // Nothing else changes.
    assert_eq!(forwarded[..8], packet[..8]);
    assert_eq!(forwarded[9], packet[9]);
    assert_eq!(forwarded[12..], packet[12..]);
}

#[test]
fn forwarding_decrements_the_hop_limit() {
    let f = Fixture::new();
    let packet = V6::new("fd42::2", "fd42::3").bytes();
    let forwarded = f.route_a(&packet).peer(f.b);

    assert_eq!(forwarded[7], 63);
    assert_eq!(forwarded[..7], packet[..7]);
    assert_eq!(forwarded[8..], packet[8..]);
}

/// The incremental update must leave a valid checksum whatever it started from.
#[test]
fn incremental_checksum_stays_valid_for_every_value() {
    for id in 0..=u16::MAX {
        let mut bytes = V4::new("10.42.0.2", "10.42.0.3").bytes();
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
        bytes[10..12].fill(0);
        let check = checksum(&[&bytes[..20]]);
        bytes[10..12].copy_from_slice(&check.to_be_bytes());

        let Some(mut packet) = IpPacket::parse(ip_packet(&bytes)) else {
            panic!("the packet should parse");
        };
        packet.decrement_hop_limit();
        let bytes = packet.into_ip();
        assert_eq!(checksum(&[&bytes.as_bytes()[..20]]), 0, "id {id}");
    }
}

/// WireGuard pads packets, and the padding must count for nothing.
#[test]
fn padding_is_cut_off() {
    let f = Fixture::new();

    let packet = V4::new("10.42.0.2", "10.42.0.1").bytes();
    let mut padded = packet.clone();
    padded.resize(packet.len() + 12, 0);
    assert_eq!(f.route_a(&padded).tun(), packet);

    let packet = V6::new("fd42::2", "fd42::1").bytes();
    let mut padded = packet.clone();
    padded.resize(packet.len() + 12, 0);
    assert_eq!(f.route_a(&padded).tun(), packet);

    let packet = V4::new("10.42.0.2", "10.42.0.3").bytes();
    let mut padded = packet.clone();
    padded.resize(packet.len() + 12, 0);
    assert_eq!(f.route_a(&padded).peer(f.b).len(), packet.len());
}

#[test]
fn ipv4_options_are_forwarded_unprocessed() {
    let f = Fixture::new();
    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    // A record-route option, padded to 4 octets.
    packet.options = vec![7, 3, 4, 0];
    let packet = packet.bytes();

    let forwarded = f.route_a(&packet).peer(f.b);
    assert_eq!(forwarded[8], 63);
    assert_eq!(checksum(&[&forwarded[..24]]), 0);
    assert_eq!(forwarded[20..], packet[20..]);

    let mut local = V4::new("10.42.0.2", "10.42.0.1");
    local.options = vec![7, 3, 4, 0];
    let local = local.bytes();
    assert_eq!(f.route_a(&local).tun(), local);
}

#[test]
fn local_delivery_leaves_the_packet_alone() {
    let f = Fixture::new();

    // Even with a TTL of 1, since nothing is forwarded yet.
    for destination in ["10.42.0.1", "192.168.7.5"] {
        let mut packet = V4::new("10.42.0.2", destination);
        packet.ttl = 1;
        let packet = packet.bytes();
        assert_eq!(f.route_a(&packet).tun(), packet);
    }
    for destination in ["fd42::1", "fd99::5"] {
        let mut packet = V6::new("fd42::2", destination);
        packet.hop_limit = 1;
        let packet = packet.bytes();
        assert_eq!(f.route_a(&packet).tun(), packet);
    }
}

#[test]
fn ttl_running_out_gives_time_exceeded() {
    let f = Fixture::new();
    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    packet.ttl = 1;
    let packet = packet.bytes();

    let icmp = icmp_v4(&f.route_a(&packet).peer(f.a));
    assert_eq!(icmp.source, Ipv4Addr::new(10, 42, 0, 1));
    assert_eq!(icmp.destination, Ipv4Addr::new(10, 42, 0, 2));
    assert_eq!((icmp.ty, icmp.code, icmp.rest), (11, 0, 0));
    assert_eq!(icmp.quoted, packet);

    let f = Fixture::new();
    let mut packet = V6::new("fd42::2", "fd42::3");
    packet.hop_limit = 1;
    let packet = packet.bytes();

    let icmp = icmp_v6(&f.route_a(&packet).peer(f.a));
    assert_eq!(icmp.source, "fd42::1".parse::<Ipv6Addr>().unwrap());
    assert_eq!(icmp.destination, "fd42::2".parse::<Ipv6Addr>().unwrap());
    assert_eq!((icmp.ty, icmp.code, icmp.rest), (3, 0, 0));
    assert_eq!(icmp.quoted, packet);

    // A TTL of 0 is treated alike, and a TTL of 2 goes through.
    let f = Fixture::new();
    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    packet.ttl = 0;
    assert_eq!(icmp_v4(&f.route_a(&packet.bytes()).peer(f.a)).ty, 11);
    packet.ttl = 2;
    assert_eq!(f.route_a(&packet.bytes()).peer(f.b)[8], 1);
}

#[test]
fn errors_follow_the_route_to_the_source_not_the_arrival() {
    let f = Fixture::new();
    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    packet.ttl = 1;

    // From peer b, but the route to its source is through peer a.
    let icmp = icmp_v4(&f.route_b(&packet.bytes()).peer(f.a));
    assert_eq!(icmp.destination, Ipv4Addr::new(10, 42, 0, 2));
}

#[test]
fn no_route_back_means_no_error() {
    let f = Fixture::new();

    for source in ["10.42.0.200", "10.42.0.9"] {
        let mut packet = V4::new(source, "10.42.0.3");
        packet.ttl = 1;
        assert_eq!(f.route_a(&packet.bytes()), Got::Consumed, "from {source}");
    }
}

#[test]
fn unreachable_destinations_give_errors() {
    let f = Fixture::new();

    let icmp = icmp_v4(
        &f.route_a(&V4::new("10.42.0.2", "10.42.0.200").bytes())
            .peer(f.a),
    );
    assert_eq!((icmp.ty, icmp.code), (3, 0));

    let icmp = icmp_v4(
        &f.route_a(&V4::new("10.42.0.2", "10.42.0.9").bytes())
            .peer(f.a),
    );
    assert_eq!((icmp.ty, icmp.code), (3, 1));

    let icmp = icmp_v6(
        &f.route_a(&V6::new("fd42::2", "fd42::200").bytes())
            .peer(f.a),
    );
    assert_eq!((icmp.ty, icmp.code), (1, 0));

    let icmp = icmp_v6(&f.route_a(&V6::new("fd42::2", "fd42::9").bytes()).peer(f.a));
    assert_eq!((icmp.ty, icmp.code), (1, 0));
}

/// Linux looks up the route, then checks the hop limit, then the MTU.
#[test]
fn route_errors_come_before_the_hop_limit_and_that_before_the_mtu() {
    let f = Fixture::new();

    let mut packet = V4::new("10.42.0.2", "10.42.0.200");
    packet.ttl = 1;
    assert_eq!(icmp_v4(&f.route_a(&packet.bytes()).peer(f.a)).ty, 3);

    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    packet.ttl = 1;
    packet.payload = vec![0; usize::from(MTU)];
    assert_eq!(icmp_v4(&f.route_a(&packet.bytes()).peer(f.a)).ty, 11);
}

#[test]
fn packets_too_big_give_errors_unless_they_may_be_fragmented() {
    let f = Fixture::new();

    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    packet.payload = vec![0; usize::from(MTU) - 20];
    assert_eq!(f.route_a(&packet.bytes()).peer(f.b)[8], 63);

    packet.payload.push(0);
    let icmp = icmp_v4(&f.route_a(&packet.bytes()).peer(f.a));
    assert_eq!((icmp.ty, icmp.code), (3, 4));
    assert_eq!(icmp.rest, u32::from(MTU));

    packet.flags_and_offset = 0;
    assert_eq!(f.route_a(&packet.bytes()).peer(f.b)[8], 63);

    let mut packet = V6::new("fd42::2", "fd42::3");
    packet.payload = vec![0; usize::from(MTU) - 40];
    assert_eq!(f.route_a(&packet.bytes()).peer(f.b)[7], 63);

    packet.payload.push(0);
    let icmp = icmp_v6(&f.route_a(&packet.bytes()).peer(f.a));
    assert_eq!((icmp.ty, icmp.code), (2, 0));
    assert_eq!(icmp.rest, u32::from(MTU));
}

/// A packet that fits, padded past the MTU, is not too big.
#[test]
fn padding_does_not_make_a_packet_too_big() {
    let f = Fixture::new();
    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    packet.payload = vec![0; usize::from(MTU) - 20];
    let mut padded = packet.bytes();
    padded.resize(usize::from(MTU) + 8, 0);
    assert_eq!(f.route_a(&padded).peer(f.b)[8], 63);
}

#[test]
fn errors_quote_no_more_than_allowed() {
    let f = Fixture::new();

    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    packet.ttl = 1;
    packet.payload = vec![0xcd; 1000];
    let packet = packet.bytes();
    let reply = f.route_a(&packet).peer(f.a);
    assert_eq!(reply.len(), 576);
    assert_eq!(icmp_v4(&reply).quoted, packet[..548]);

    let mut packet = V6::new("fd42::2", "fd42::3");
    packet.hop_limit = 1;
    packet.payload = vec![0xcd; 1300];
    let packet = packet.bytes();
    let reply = f.route_a(&packet).peer(f.a);
    assert_eq!(reply.len(), 1280);
    assert_eq!(icmp_v6(&reply).quoted, packet[..1232]);
}

#[test]
fn icmpv4_errors_keep_part_of_the_tos() {
    let f = Fixture::new();
    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    packet.ttl = 1;
    packet.tos = 0xff;
    assert_eq!(icmp_v4(&f.route_a(&packet.bytes()).peer(f.a)).tos, 0xde);

    packet.tos = 0;
    assert_eq!(icmp_v4(&f.route_a(&packet.bytes()).peer(f.a)).tos, 0xc0);
}

#[test]
fn delivery_filters_sources_by_mesh() {
    let f = Fixture::new();

    assert_eq!(
        f.route_a(&V4::new("10.99.0.1", "10.42.0.1").bytes()),
        Got::Consumed
    );
    assert_eq!(
        f.route_a(&V6::new("fd77::1", "fd42::1").bytes()),
        Got::Consumed
    );
    assert_eq!(
        f.route_a(&V4::new("10.99.0.1", "192.168.7.5").bytes()),
        Got::Consumed
    );

    let packet = V4::new("10.42.0.2", "192.168.7.5").bytes();
    assert_eq!(f.route_a(&packet).tun(), packet);
}

/// A node not yet told of a new prefix in `mesh` must still carry its traffic.
#[test]
fn transit_is_not_filtered_by_mesh() {
    let f = Fixture::new();

    assert_eq!(
        f.route_a(&V4::new("10.43.0.2", "10.43.0.1").bytes())
            .peer(f.b)[8],
        63
    );
    assert_eq!(
        f.route_a(&V6::new("fd43::2", "fd43::1").bytes()).peer(f.b)[7],
        63
    );
    // Nor is a source this node has no route to.
    assert_eq!(
        f.route_a(&V4::new("10.99.0.1", "10.42.0.3").bytes())
            .peer(f.b)[8],
        63
    );
    // But this host does not accept it itself.
    assert_eq!(
        f.route_a(&V4::new("10.43.0.2", "10.42.0.1").bytes()),
        Got::Consumed
    );

    // Errors are sent for it all the same.
    let mut packet = V4::new("10.43.0.2", "10.43.0.1");
    packet.ttl = 1;
    assert_eq!(icmp_v4(&f.route_a(&packet.bytes()).peer(f.a)).ty, 11);
}

#[test]
fn sources_on_this_host_are_dropped() {
    let f = Fixture::new();

    for (source, destination) in [
        // Addresses of this host, in transit and on delivery.
        ("10.42.0.1", "10.42.0.3"),
        ("10.42.0.1", "10.42.0.1"),
        // Attached networks, which `mesh` covers here.
        ("192.168.7.5", "10.42.0.3"),
        ("192.168.7.5", "10.42.0.1"),
        ("192.168.7.5", "192.168.7.6"),
    ] {
        let packet = V4::new(source, destination).bytes();
        assert_eq!(
            f.route_a(&packet),
            Got::Consumed,
            "{source} to {destination}"
        );
    }

    for (source, destination) in [
        ("fd42::1", "fd42::3"),
        ("fd42::1", "fd42::1"),
        ("fd99::5", "fd42::3"),
        ("fd99::5", "fd42::1"),
    ] {
        let packet = V6::new(source, destination).bytes();
        assert_eq!(
            f.route_a(&packet),
            Got::Consumed,
            "{source} to {destination}"
        );
    }

    // No error is sent about them either.
    let mut packet = V4::new("192.168.7.5", "10.42.0.3");
    packet.ttl = 1;
    assert_eq!(f.route_a(&packet.bytes()), Got::Consumed);
}

/// An exit node's wide attached network must not drop mesh sources with routes of their own.
#[test]
fn more_specific_routes_take_sources_out_of_attached_networks() {
    let f = Fixture::with(
        &["10.42.0.1", "fd42::1"],
        &["0.0.0.0/0", "::/0"],
        &["0.0.0.0/0", "::/0"],
    );

    let packet = V4::new("10.42.0.2", "8.8.8.8").bytes();
    assert_eq!(f.route_a(&packet).tun(), packet);
    let packet = V6::new("fd42::2", "2001:4860:4860::8888").bytes();
    assert_eq!(f.route_a(&packet).tun(), packet);

    // With no route of its own, the source falls within the attached network.
    assert_eq!(
        f.route_a(&V4::new("8.8.4.4", "8.8.8.8").bytes()),
        Got::Consumed
    );
    assert_eq!(
        f.route_a(&V6::new("2001:4860:4860::8844", "2001:4860:4860::8888").bytes()),
        Got::Consumed
    );
}

#[test]
fn martian_addresses_are_dropped() {
    let f = Fixture::new();
    // With a default route, each would be forwarded if it weren't dropped.
    f.router.select_route("0.0.0.0/0".parse().unwrap(), f.b);
    f.router.select_route("::/0".parse().unwrap(), f.b);

    for source in ["224.0.0.1", "255.255.255.255", "0.1.2.3", "127.0.0.1"] {
        let packet = V4::new(source, "10.42.0.3").bytes();
        assert_eq!(f.route_a(&packet), Got::Consumed, "from {source}");
    }
    for destination in ["224.0.0.1", "255.255.255.255", "0.1.2.3", "127.0.0.1"] {
        let packet = V4::new("10.42.0.2", destination).bytes();
        assert_eq!(f.route_a(&packet), Got::Consumed, "to {destination}");
        assert_eq!(f.route_tun(&packet), Got::Consumed, "to {destination}");
    }
    for source in ["::", "::1", "ff02::1", "::ffff:10.42.0.2"] {
        let packet = V6::new(source, "fd42::3").bytes();
        assert_eq!(f.route_a(&packet), Got::Consumed, "from {source}");
    }
    for destination in ["::", "::1", "ff02::1"] {
        let packet = V6::new("fd42::2", destination).bytes();
        assert_eq!(f.route_a(&packet), Got::Consumed, "to {destination}");
        assert_eq!(f.route_tun(&packet), Got::Consumed, "to {destination}");
    }

    // These aren't martian.
    assert_eq!(
        f.route_a(&V4::new("10.42.0.2", "8.8.8.8").bytes())
            .peer(f.b)[8],
        63
    );
}

/// A UDP datagram with a given source port and destination port.
fn udp(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&source_port.to_be_bytes());
    b.extend_from_slice(&destination_port.to_be_bytes());
    b.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(payload);
    b
}

/// An IPv6 packet between link-local addresses.
fn link_local_packet(source: Ipv6Addr, destination: Ipv6Addr, next: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0x60, 0, 0, 0];
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.extend_from_slice(&[next, 1]);
    b.extend_from_slice(&source.octets());
    b.extend_from_slice(&destination.octets());
    b.extend_from_slice(payload);
    b
}

#[test]
fn babel_packets_go_to_the_driver() {
    let mut f = Fixture::new();
    let payload = [42, 2, 0, 0];
    let packet = babel_packet(
        link_local_address(&f.a),
        link_local_address(&f.me),
        &payload,
    );

    assert_eq!(f.route_a(packet.as_bytes()), Got::Consumed);

    let Ok(Input::Packet { from, buf, .. }) = f.babel.try_recv() else {
        panic!("the driver should get the packet");
    };
    assert_eq!(from, f.a);
    assert_eq!(*buf, payload);

    // Padding after the packet doesn't reach the driver.
    let mut padded = packet.as_bytes().to_vec();
    padded.resize(padded.len() + 12, 0);
    assert_eq!(f.route_a(&padded), Got::Consumed);
    let Ok(Input::Packet { buf, .. }) = f.babel.try_recv() else {
        panic!("the driver should get the packet");
    };
    assert_eq!(*buf, payload);
}

#[test]
fn other_link_local_traffic_is_dropped() {
    let mut f = Fixture::new();
    let (me, a, b) = (
        link_local_address(&f.me),
        link_local_address(&f.a),
        link_local_address(&f.b),
    );
    let babel = udp(BABEL_PORT, BABEL_PORT, &[42, 2, 0, 0]);
    let multicast: Ipv6Addr = "ff02::1:6".parse().unwrap();
    let global: Ipv6Addr = "fd42::2".parse().unwrap();

    let mut wrong_length = babel.clone();
    wrong_length[5] = 99;

    for (name, packet) in [
        // Babel packets that claim to be from another node.
        ("wrong source", link_local_packet(b, me, UDP, &babel)),
        ("our own source", link_local_packet(me, me, UDP, &babel)),
        // To someone else, or to a multicast group, which Babel here doesn't use.
        ("wrong destination", link_local_packet(a, b, UDP, &babel)),
        ("multicast", link_local_packet(a, multicast, UDP, &babel)),
        // Only UDP with the Babel port on both sides.
        ("not UDP", link_local_packet(a, me, TCP, &babel)),
        ("ICMPv6", link_local_packet(a, me, ICMPV6, &[128, 0, 0, 0])),
        (
            "wrong source port",
            link_local_packet(a, me, UDP, &udp(1234, BABEL_PORT, &[42, 2, 0, 0])),
        ),
        (
            "wrong destination port",
            link_local_packet(a, me, UDP, &udp(BABEL_PORT, 1234, &[42, 2, 0, 0])),
        ),
        ("wrong length", link_local_packet(a, me, UDP, &wrong_length)),
        ("too short", link_local_packet(a, me, UDP, &[0; 4])),
        // Link-local on one side only.
        ("global source", link_local_packet(global, me, UDP, &babel)),
        (
            "global destination",
            link_local_packet(a, global, UDP, &babel),
        ),
    ] {
        assert_eq!(f.route_a(&packet), Got::Consumed, "{name}");
        assert!(f.babel.try_recv().is_err(), "{name}");
    }
}

/// The Babel port between ordinary addresses means nothing.
#[test]
fn babel_port_between_other_addresses_is_data() {
    let mut f = Fixture::new();

    let mut packet = V6::new("fd42::2", "fd42::1");
    packet.payload = udp(BABEL_PORT, BABEL_PORT, &[42, 2, 0, 0]);
    let packet = packet.bytes();

    assert_eq!(f.route_a(&packet).tun(), packet);
    assert!(f.babel.try_recv().is_err());
}

/// A full channel to the driver must not block the data plane.
#[test]
fn babel_packets_are_dropped_when_the_driver_falls_behind() {
    let f = Fixture::new();
    let packet = babel_packet(
        link_local_address(&f.a),
        link_local_address(&f.me),
        &[42, 2, 0, 0],
    );

    for _ in 0..16 {
        assert_eq!(f.route_a(packet.as_bytes()), Got::Consumed);
    }
}

#[test]
fn babel_packet_is_well_formed() {
    let (source, destination) = (link_local_address(&key(1)), link_local_address(&key(2)));
    let payload = [42, 2, 0, 3, 1, 2, 3];
    let packet = babel_packet(source, destination, &payload);
    let b = packet.as_bytes();

    assert_eq!(b[0] >> 4, 6);
    assert_eq!(u16::from_be_bytes([b[4], b[5]]) as usize, 8 + payload.len());
    assert_eq!(b[6], UDP);
    // RFC 8966 §4: network-layer hop count set to 1.
    assert_eq!(b[7], 1);
    assert_eq!(b[8..24], source.octets());
    assert_eq!(b[24..40], destination.octets());
    assert_eq!(u16::from_be_bytes([b[40], b[41]]), BABEL_PORT);
    assert_eq!(u16::from_be_bytes([b[42], b[43]]), BABEL_PORT);
    assert_eq!(
        u16::from_be_bytes([b[44], b[45]]) as usize,
        8 + payload.len()
    );
    assert_eq!(b[48..], payload);

    let length = ((8 + payload.len()) as u32).to_be_bytes();
    assert_eq!(
        checksum(&[&b[8..40], &length, &[0, 0, 0, UDP], &b[40..]]),
        0
    );
}

#[test]
fn link_local_addresses_are_derived_from_public_keys() {
    let addr = link_local_address(&key(1));
    assert!(addr.is_unicast_link_local());
    assert_eq!(addr.segments()[..4], [0xfe80, 0, 0, 0]);
    assert_ne!(addr, link_local_address(&key(2)));

    // Every node has to compute this alike, so the derivation must not change.
    assert_eq!(addr, LINK_LOCAL_OF_KEY_1.parse::<Ipv6Addr>().unwrap());
}

const LINK_LOCAL_OF_KEY_1: &str = "fe80::41cb:773a:6288:2d5d";

#[test]
fn packets_from_the_tun_go_to_the_next_hop_unchanged() {
    let f = Fixture::new();

    let mut packet = V4::new("10.42.0.1", "10.42.0.3");
    packet.ttl = 1;
    let packet = packet.bytes();
    assert_eq!(f.route_tun(&packet).peer(f.b), packet);

    let mut packet = V6::new("fd42::1", "fd42::3");
    packet.hop_limit = 1;
    let packet = packet.bytes();
    assert_eq!(f.route_tun(&packet).peer(f.b), packet);
}

#[test]
fn packets_from_the_tun_with_no_route_are_answered_on_the_tun() {
    let f = Fixture::new();

    for (destination, code) in [
        ("10.42.0.200", 0),
        ("10.42.0.9", 1),
        // A route on this host, which the kernel should not have sent here, must not loop.
        ("192.168.7.5", 0),
    ] {
        let packet = V4::new("10.42.0.1", destination).bytes();
        let icmp = icmp_v4(&f.route_tun(&packet).tun());
        assert_eq!(icmp.source, Ipv4Addr::new(10, 42, 0, 1), "to {destination}");
        assert_eq!(icmp.destination, Ipv4Addr::new(10, 42, 0, 1));
        assert_eq!((icmp.ty, icmp.code), (3, code), "to {destination}");
        assert_eq!(icmp.quoted, packet);
    }

    let f = Fixture::new();
    for destination in ["fd42::200", "fd42::9", "fd99::5"] {
        let packet = V6::new("fd42::1", destination).bytes();
        let icmp = icmp_v6(&f.route_tun(&packet).tun());
        assert_eq!(icmp.source, "fd42::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(icmp.destination, "fd42::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!((icmp.ty, icmp.code), (1, 0), "to {destination}");
    }

    // A host behind this node gets the answer too, through the kernel.
    let packet = V4::new("192.168.7.5", "10.42.0.200").bytes();
    let icmp = icmp_v4(&f.route_tun(&packet).tun());
    assert_eq!(icmp.source, Ipv4Addr::new(10, 42, 0, 1));
    assert_eq!(icmp.destination, Ipv4Addr::new(192, 168, 7, 5));
}

#[test]
fn packets_from_the_tun_that_cannot_be_routed_are_dropped_silently() {
    let f = Fixture::new();

    for packet in [
        V6::new("fd42::1", "fe80::1").bytes(),
        V6::new("fd42::1", "ff02::16").bytes(),
        V6::new("fe80::1", "fe80::2").bytes(),
    ] {
        assert_eq!(f.route_tun(&packet), Got::Consumed);
    }
    for packet in [
        V4::new("10.42.0.1", "224.0.0.251").bytes(),
        V4::new("10.42.0.1", "255.255.255.255").bytes(),
    ] {
        assert_eq!(f.route_tun(&packet), Got::Consumed);
    }

    // An unreachable destination, but no source that could be answered.
    for source in ["0.0.0.0", "224.0.0.1"] {
        assert_eq!(
            f.route_tun(&V4::new(source, "10.42.0.200").bytes()),
            Got::Consumed,
            "from {source}"
        );
    }
    for source in ["::", "ff02::1"] {
        assert_eq!(
            f.route_tun(&V6::new(source, "fd42::200").bytes()),
            Got::Consumed,
            "from {source}"
        );
    }
}

#[test]
fn errors_use_the_first_address_of_the_family() {
    let f = Fixture::with(
        &["fd42::1", "10.42.0.1", "fd42::5", "10.42.0.5"],
        &[],
        &["10.42.0.0/16", "fd42::/48"],
    );

    let packet = V4::new("10.42.0.2", "10.42.0.200").bytes();
    assert_eq!(
        icmp_v4(&f.route_a(&packet).peer(f.a)).source,
        Ipv4Addr::new(10, 42, 0, 1)
    );
    let packet = V6::new("fd42::2", "fd42::200").bytes();
    assert_eq!(
        icmp_v6(&f.route_a(&packet).peer(f.a)).source,
        "fd42::1".parse::<Ipv6Addr>().unwrap()
    );
}

#[test]
fn errors_from_a_node_with_no_address_use_a_dummy_source() {
    let f = Fixture::with(&[], &[], &["10.42.0.0/16", "fd42::/48"]);

    let packet = V4::new("10.42.0.2", "10.42.0.200").bytes();
    assert_eq!(icmp_v4(&f.route_a(&packet).peer(f.a)).source, DUMMY_V4);

    let packet = V6::new("fd42::2", "fd42::200").bytes();
    assert_eq!(
        icmp_v6(&f.route_a(&packet).peer(f.a)).source,
        "100:0:0:1:1122:3344:5566:7788".parse::<Ipv6Addr>().unwrap()
    );

    // An address of the other family doesn't help.
    let f = Fixture::with(&["fd42::1"], &[], &["10.42.0.0/16", "fd42::/48"]);
    let packet = V4::new("10.42.0.2", "10.42.0.200").bytes();
    assert_eq!(icmp_v4(&f.route_a(&packet).peer(f.a)).source, DUMMY_V4);
}

#[test]
fn only_icmp_errors_may_come_from_a_dummy_source() {
    let f = Fixture::new();

    let error = |source, protocol, ty: u8| {
        let mut packet = V4::new(source, "10.42.0.1");
        packet.protocol = protocol;
        packet.payload = vec![ty, 0, 0, 0, 0, 0, 0, 0];
        packet.bytes()
    };
    let packet = error("192.0.0.8", ICMP, 11);
    assert_eq!(f.route_a(&packet).tun(), packet);
    let packet = error("192.0.0.8", ICMP, 3);
    assert_eq!(f.route_a(&packet).tun(), packet);
    assert_eq!(f.route_a(&error("192.0.0.8", ICMP, 8)), Got::Consumed);
    assert_eq!(f.route_a(&error("192.0.0.8", UDP, 11)), Got::Consumed);
    // An address next to the dummy one gets no such treatment, nor does an error from elsewhere.
    assert_eq!(f.route_a(&error("192.0.0.9", ICMP, 11)), Got::Consumed);
    assert_eq!(f.route_a(&error("10.99.0.1", ICMP, 11)), Got::Consumed);

    let error = |source, next_header, ty: u8| {
        let mut packet = V6::new(source, "fd42::1");
        packet.next_header = next_header;
        packet.payload = vec![ty, 0, 0, 0, 0, 0, 0, 0];
        packet.bytes()
    };
    let packet = error("100:0:0:1:1:2:3:4", ICMPV6, 3);
    assert_eq!(f.route_a(&packet).tun(), packet);
    assert_eq!(
        f.route_a(&error("100:0:0:1:1:2:3:4", ICMPV6, 128)),
        Got::Consumed
    );
    assert_eq!(
        f.route_a(&error("100:0:0:1:1:2:3:4", UDP, 3)),
        Got::Consumed
    );
    assert_eq!(
        f.route_a(&error("100:0:0:2:1:2:3:4", ICMPV6, 3)),
        Got::Consumed
    );
}

/// A wide attached network must not swallow errors from a dummy source.
#[test]
fn dummy_sources_are_exempt_from_the_local_source_check() {
    let f = Fixture::with(&["10.42.0.1"], &["0.0.0.0/0"], &["10.42.0.0/16"]);

    let mut packet = V4::new("192.0.0.8", "10.42.0.1");
    packet.protocol = ICMP;
    packet.payload = vec![11, 0, 0, 0, 0, 0, 0, 0];
    let packet = packet.bytes();
    assert_eq!(f.route_a(&packet).tun(), packet);
}

/// The time exceeded error about an IPv4 packet with the given fields, if any.
fn time_exceeded_about(packet: &mut V4) -> Got {
    let f = Fixture::new();
    packet.ttl = 1;
    f.route_a(&packet.bytes())
}

#[test]
fn only_first_fragments_get_ipv4_errors() {
    let mut packet = V4::new("10.42.0.2", "10.42.0.3");

    packet.flags_and_offset = MF;
    assert_eq!(
        icmp_v4(&time_exceeded_about(&mut packet).peer(key(2))).ty,
        11
    );

    packet.flags_and_offset = MF | 1;
    assert_eq!(time_exceeded_about(&mut packet), Got::Consumed);

    packet.flags_and_offset = 8;
    assert_eq!(time_exceeded_about(&mut packet), Got::Consumed);
}

#[test]
fn ipv4_errors_are_not_answered() {
    for (ty, answered) in [
        // Errors, including the unassigned types `icmp_pointers` counts as such.
        (3, false),
        (4, false),
        (5, false),
        (11, false),
        (12, false),
        (1, false),
        (19, false),
        (255, false),
        // Informational messages.
        (0, true),
        (8, true),
        (13, true),
        (18, true),
    ] {
        let mut packet = V4::new("10.42.0.2", "10.42.0.3");
        packet.protocol = ICMP;
        packet.payload = vec![ty, 0, 0, 0];
        let got = time_exceeded_about(&mut packet);
        assert_eq!(got != Got::Consumed, answered, "type {ty}");
    }

    // An ICMP packet too short to have a type is not answered.
    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    packet.protocol = ICMP;
    packet.payload = vec![];
    assert_eq!(time_exceeded_about(&mut packet), Got::Consumed);

    // The type is found past any options.
    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    packet.protocol = ICMP;
    packet.options = vec![1, 1, 1, 0];
    packet.payload = vec![3, 0, 0, 0];
    assert_eq!(time_exceeded_about(&mut packet), Got::Consumed);
    packet.payload = vec![8, 0, 0, 0];
    assert_ne!(time_exceeded_about(&mut packet), Got::Consumed);
}

/// Whether a packet with these IPv6 contents gets an error.
fn answered_v6(next_header: u8, payload: Vec<u8>) -> bool {
    let f = Fixture::new();
    let mut packet = V6::new("fd42::2", "fd42::3");
    packet.hop_limit = 1;
    packet.next_header = next_header;
    packet.payload = payload;
    f.route_a(&packet.bytes()) != Got::Consumed
}

#[test]
fn ipv6_errors_are_not_answered() {
    const HOP_BY_HOP: u8 = 0;
    const ROUTING: u8 = 43;
    const FRAGMENT: u8 = 44;
    const AUTHENTICATION: u8 = 51;
    const NO_NEXT_HEADER: u8 = 59;
    const DESTINATION: u8 = 60;

    let error = vec![1, 0, 0, 0];
    let info = vec![128, 0, 0, 0];

    assert!(answered_v6(UDP, vec![0; 8]));
    assert!(!answered_v6(ICMPV6, error.clone()));
    assert!(answered_v6(ICMPV6, info.clone()));
    // No ICMPv6 type to look at.
    assert!(!answered_v6(ICMPV6, vec![]));

    // Past extension headers of 8 octets.
    for header in [HOP_BY_HOP, ROUTING, DESTINATION] {
        let headed = |rest: &[u8]| [&[ICMPV6, 0, 0, 0, 0, 0, 0, 0], rest].concat();
        assert!(!answered_v6(header, headed(&error)), "{header}");
        assert!(answered_v6(header, headed(&info)), "{header}");
    }

    // An Authentication Header's length counts in units of 4 octets, minus 2.
    let headed = |rest: &[u8]| [&[ICMPV6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], rest].concat();
    assert!(!answered_v6(AUTHENTICATION, headed(&error)));
    assert!(answered_v6(AUTHENTICATION, headed(&info)));

    // In a first fragment, the type is there to check.
    let fragment = |offset_and_flags: u16, rest: &[u8]| {
        let [hi, lo] = offset_and_flags.to_be_bytes();
        [&[ICMPV6, 0, hi, lo, 0, 0, 0, 1], rest].concat()
    };
    assert!(!answered_v6(FRAGMENT, fragment(1, &error)));
    assert!(answered_v6(FRAGMENT, fragment(1, &info)));
    // If the first fragment ends before the type, there is nothing to say it's an error.
    assert!(answered_v6(FRAGMENT, fragment(1, &[])));
    // Unlike in IPv4, Linux does answer other fragments, which have no type to check.
    assert!(answered_v6(FRAGMENT, fragment(8, &error)));

    // With no next header, or a chain cut short, there is no ICMPv6 message.
    assert!(answered_v6(NO_NEXT_HEADER, vec![]));
    assert!(answered_v6(HOP_BY_HOP, vec![ICMPV6]));
}

#[test]
fn limiter_allows_a_burst_per_destination_then_one_per_second() {
    let start = Instant::now();
    let mut limiter = Limiter::new(start);
    let dest: IpAddr = "10.42.0.2".parse().unwrap();
    let other: IpAddr = "fd42::2".parse().unwrap();

    for i in 0..6 {
        assert!(
            limiter.allow(IcmpError::TimeExceeded, dest, start),
            "message {i}"
        );
    }
    assert!(!limiter.allow(IcmpError::NetUnreachable, dest, start));
    assert!(!limiter.allow(
        IcmpError::NetUnreachable,
        dest,
        start + Duration::from_millis(999)
    ));

    // Other destinations are not affected.
    assert!(limiter.allow(IcmpError::TimeExceeded, other, start));

    let later = start + Duration::from_secs(2);
    assert!(limiter.allow(IcmpError::HostUnreachable, dest, later));
    assert!(limiter.allow(IcmpError::HostUnreachable, dest, later));
    assert!(!limiter.allow(IcmpError::HostUnreachable, dest, later));

    // Tokens stop building up at the burst.
    let much_later = start + Duration::from_secs(60);
    for _ in 0..6 {
        assert!(limiter.allow(IcmpError::TimeExceeded, dest, much_later));
    }
    assert!(!limiter.allow(IcmpError::TimeExceeded, dest, much_later));
}

#[test]
fn limiter_allows_a_global_burst_then_refills() {
    let start = Instant::now();
    let mut limiter = Limiter::new(start);

    let destination = |n: u32| IpAddr::V4(Ipv4Addr::from_bits(0x0a00_0000 + n));

    // Each message costs 0 to 2 credits, out of 50. Many destinations are used, so that their own
    // limits (and collisions) don't get in the way before the global one does.
    let mut allowed = 0;
    let mut denied_in_a_row = 0;
    let mut n = 0;
    while denied_in_a_row < 8 {
        n += 1;
        if limiter.allow(IcmpError::TimeExceeded, destination(n), start) {
            allowed += 1;
            denied_in_a_row = 0;
        } else {
            denied_in_a_row += 1;
        }
    }
    assert!((25..250).contains(&allowed), "{allowed} messages allowed");

    // Before 20 ms has passed, nothing is refilled.
    n += 1;
    assert!(!limiter.allow(
        IcmpError::TimeExceeded,
        destination(n),
        start + Duration::from_millis(19)
    ));

    // After that, the credit grows by one per millisecond.
    n += 1;
    assert!(limiter.allow(
        IcmpError::TimeExceeded,
        destination(n),
        start + Duration::from_millis(40)
    ));
}

#[test]
fn limiter_never_limits_path_mtu_errors() {
    let start = Instant::now();
    let mut limiter = Limiter::new(start);
    let dest: IpAddr = "10.42.0.2".parse().unwrap();

    for _ in 0..1000 {
        assert!(limiter.allow(IcmpError::TooBig(1400), dest, start));
    }
}

#[test]
fn errors_are_rate_limited_per_destination() {
    let f = Fixture::new();
    let mut packet = V4::new("10.42.0.2", "10.42.0.3");
    packet.ttl = 1;
    let packet = packet.bytes();

    for _ in 0..6 {
        assert_ne!(f.route_a(&packet), Got::Consumed);
    }
    assert_eq!(f.route_a(&packet), Got::Consumed);

    // Another destination still gets an answer, and path MTU errors are never held back.
    let mut other = V4::new("10.42.0.3", "10.42.0.2");
    other.ttl = 1;
    assert_ne!(f.route_a(&other.bytes()), Got::Consumed);

    let mut too_big = V4::new("10.42.0.2", "10.42.0.3");
    too_big.payload = vec![0; usize::from(MTU)];
    assert_ne!(f.route_a(&too_big.bytes()), Got::Consumed);
}

#[test]
fn route_changes_take_effect() {
    let f = Fixture::new();
    let packet = V4::new("10.42.0.2", "10.77.0.1").bytes();
    let specific: IpNet = "10.77.0.1/32".parse().unwrap();
    let wide: IpNet = "10.77.0.0/16".parse().unwrap();

    f.router.select_route(wide, f.b);
    f.router.select_route(specific, f.a);
    assert_eq!(f.route_a(&packet).peer(f.a)[8], 63);

    // A held route keeps the wider one from taking over.
    f.router.hold_route(specific);
    assert_eq!(icmp_v4(&f.route_a(&packet).peer(f.a)).code, 1);

    // Once removed, it doesn't.
    f.router.remove_route(specific);
    assert_eq!(f.route_a(&packet).peer(f.b)[8], 63);

    // Removing a route that isn't there changes nothing.
    f.router.remove_route(specific);
    assert_eq!(f.route_a(&packet).peer(f.b)[8], 63);
}

/// Whatever comes out of a tunnel or the TUN, nothing panics.
#[test]
fn arbitrary_packets_do_not_panic() {
    let f = Fixture::new();
    let mut mtu = MtuWatcher::new(MTU);

    for i in 0..50_000u32 {
        let len = rand::random_range(20..=120);
        let mut bytes: Vec<u8> = (0..len).map(|_| rand::random()).collect();

        // Most random packets fail on their version, so favour the valid ones.
        bytes[0] = match i % 4 {
            0 => 0x45,
            1 => 0x40 | (bytes[0] & 0x0f),
            2 => 0x60 | (bytes[0] & 0x0f),
            _ => bytes[0],
        };

        // And give most of them a length that fits.
        if i % 8 != 0 {
            match bytes[0] >> 4 {
                4 => bytes[2..4].copy_from_slice(&(len as u16).to_be_bytes()),
                6 if len >= 40 => {
                    bytes[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
                }
                _ => {}
            }
        }

        // And aim half of them at places where they get further.
        if i % 2 == 0 && bytes[0] >> 4 == 4 {
            bytes[12..16].copy_from_slice(&[10, 42, 0, 2]);
            bytes[16..20].copy_from_slice(&[10, 42, 0, rand::random_range(1..=9)]);
            bytes[8] = rand::random_range(0..=2);
        }
        if i % 2 == 0 && bytes[0] >> 4 == 6 && len >= 40 {
            bytes[8..24].copy_from_slice(&"fd42::2".parse::<Ipv6Addr>().unwrap().octets());
            bytes[24..40].copy_from_slice(&"fd42::3".parse::<Ipv6Addr>().unwrap().octets());
            bytes[7] = rand::random_range(0..=2);
        }

        let packet = Packet::copy_from(&bytes[..]).try_into_ip().unwrap();
        let _ = f.router.route_from_peer(&f.a, packet, &mut mtu);
        let packet = Packet::copy_from(&bytes[..]).try_into_ip().unwrap();
        let _ = f.router.route_from_tun(packet);
    }
}
