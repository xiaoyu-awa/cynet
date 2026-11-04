//! Babel's link-local addresses, and the IPv6 and UDP headers its packets travel in.
//!
//! Babel runs inside the tunnels, so these packets are built and taken apart here, with no socket
//! or kernel involved.

use std::net::Ipv6Addr;

use blake2::{Blake2s256, Digest};
use bytes::BytesMut;
use gotatun::{
    packet::{Ip, IpNextProtocol, Ipv6Header, Packet, PseudoHeaderV6, UdpHeader, checksum_udp},
    x25519::PublicKey,
};
use zerocopy::IntoBytes;

use crate::{
    babel::LINK_HEADERS_LEN,
    router::ip::{IpPacket, into_ip, ipv6_header},
};

const _: () = assert!(Ipv6Header::LEN + UdpHeader::LEN == LINK_HEADERS_LEN);

/// The UDP port of Babel (RFC 8966 §5).
pub const BABEL_PORT: u16 = 6696;

/// Returns a node's link-local address: `fe80::/64`, followed by the first 64 bits of a hash of
/// its public key. Interface identifiers are opaque (RFC 7136), so no bit is special.
pub fn link_local_address(public_key: &PublicKey) -> Ipv6Addr {
    let hash = Blake2s256::new()
        .chain_update(b"cynet babel link-local address")
        .chain_update(public_key.as_bytes())
        .finalize();

    let mut octets = [0; 16];
    octets[..2].copy_from_slice(&[0xfe, 0x80]);
    octets[8..].copy_from_slice(&hash[..8]);
    Ipv6Addr::from_octets(octets)
}

/// Wraps a Babel packet in IPv6 and UDP headers, for a link: with a hop count of 1 and the Babel
/// port on both sides (RFC 8966 §4).
pub fn babel_packet(source: Ipv6Addr, destination: Ipv6Addr, payload: &[u8]) -> Packet<Ip> {
    let udp_len = UdpHeader::LEN + payload.len();

    let ip_header = ipv6_header(source, destination, IpNextProtocol::Udp, 1, udp_len);

    let mut buf = BytesMut::with_capacity(Ipv6Header::LEN + udp_len);
    buf.extend_from_slice(ip_header.as_bytes());
    buf.extend_from_slice(UdpHeader::new(BABEL_PORT, BABEL_PORT, udp_len as u16, 0).as_bytes());
    buf.extend_from_slice(payload);

    let udp = &buf[Ipv6Header::LEN..];
    let pseudo_header = PseudoHeaderV6::from_bytes(
        source.to_bits().into(),
        destination.to_bits().into(),
        IpNextProtocol::Udp,
        udp,
    );
    let checksum = checksum_udp(pseudo_header, udp);
    buf[Ipv6Header::LEN + 6..Ipv6Header::LEN + 8].copy_from_slice(&checksum.to_be_bytes());

    into_ip(buf)
}

/// Returns what a Babel packet carries, if `packet` is one over this link: it must come from
/// `source`, to `destination`, with the Babel port on both sides (RFC 8966 §4).
pub fn babel_payload(
    packet: IpPacket,
    source: Ipv6Addr,
    destination: Ipv6Addr,
) -> Option<Box<[u8]>> {
    let IpPacket::V6(packet) = packet else {
        return None;
    };
    if packet.header.source() != source || packet.header.destination() != destination {
        return None;
    }
    let packet = packet.try_into_udp().ok()?;
    let udp = &packet.payload;
    (udp.header.source_port == BABEL_PORT && udp.header.destination_port == BABEL_PORT)
        .then(|| (&udp.payload).into())
}
