//! IP packets and addresses, as the forwarding path sees them.

use std::net::{IpAddr, Ipv6Addr};

use bytes::BytesMut;
use gotatun::packet::{
    Decoder, Ip, IpNextProtocol, Ipv4, Ipv4Decoder, Ipv4Header, Ipv6, Ipv6Decoder, Ipv6Header,
    Ipv6VersionTrafficFlow, Packet,
};
use zerocopy::IntoBytes;

/// Returns an IPv6 header, with no traffic class or flow label.
pub fn ipv6_header(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: IpNextProtocol,
    hop_limit: u8,
    payload_len: usize,
) -> Ipv6Header {
    Ipv6Header {
        version_traffic_flow: Ipv6VersionTrafficFlow::new().with_version(6),
        payload_length: (payload_len as u16).into(),
        next_header,
        hop_limit,
        source_address: source.to_bits().into(),
        destination_address: destination.to_bits().into(),
    }
}

/// Returns a buffer as an IP packet. It must begin with a full IP header.
pub fn into_ip(buf: BytesMut) -> Packet<Ip> {
    Packet::from_bytes(buf)
        .try_into_ip()
        .expect("a packet with a full IP header should be long enough")
}

/// Checks whether an address is IPv6 link-local.
pub fn is_link_local(addr: IpAddr) -> bool {
    matches!(addr, IpAddr::V6(addr) if addr.is_unicast_link_local())
}

/// Checks whether a packet from a peer must be dropped for its source address, as in Linux
/// (`ip_route_input_slow`, `ip6_rcv_core`).
pub fn martian_source(addr: IpAddr) -> bool {
    martian_destination(addr) || matches!(addr, IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some())
}

/// Checks whether a packet must be dropped for its destination address, as in Linux
/// (`ip_route_input_slow`, `ip6_rcv_core`). Multicast and broadcast have no meaning across the
/// tunnels, and are not worth an error.
pub fn martian_destination(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => {
            addr.is_multicast()
                || addr.is_broadcast()
                || addr.is_loopback()
                || addr.octets()[0] == 0
        }
        IpAddr::V6(addr) => addr.is_unspecified() || addr.is_loopback() || addr.is_multicast(),
    }
}

/// An IPv4 or IPv6 packet, whose buffer holds exactly the packet, with no padding after it.
pub enum IpPacket {
    /// An IPv4 packet. Its payload begins with any options.
    V4(Packet<Ipv4>),
    /// An IPv6 packet.
    V6(Packet<Ipv6>),
}

impl IpPacket {
    /// Checks the version and lengths of a packet, and cuts off any padding. Checksums are not
    /// checked, as the Poly1305 tag proves that the packet was not modified in transit.
    pub fn parse(packet: Packet<Ip>) -> Option<Self> {
        match packet.header.version() {
            4 => {
                // Unlike gotatun's own use of it, this allows IPv4 options.
                let decoder = Ipv4Decoder {
                    version: false,
                    ihl: false,
                    checksum: false,
                    length: true,
                    truncate: true,
                };
                let packet: Packet<Ipv4> = decoder.decode_owned(packet).ok()?;
                (usize::from(packet.header.ihl()) * 4 >= Ipv4Header::LEN)
                    .then_some(Self::V4(packet))
            }
            6 => {
                let decoder = Ipv6Decoder {
                    version: false,
                    length: true,
                    truncate: true,
                };
                decoder.decode_owned(packet).ok().map(Self::V6)
            }
            _ => None,
        }
    }

    /// Returns the source address.
    pub fn source(&self) -> IpAddr {
        match self {
            Self::V4(packet) => packet.header.source().into(),
            Self::V6(packet) => packet.header.source().into(),
        }
    }

    /// Returns the destination address.
    pub fn destination(&self) -> IpAddr {
        match self {
            Self::V4(packet) => packet.header.destination().into(),
            Self::V6(packet) => packet.header.destination().into(),
        }
    }

    /// Returns the IPv4 TTL or IPv6 hop limit.
    pub fn hop_limit(&self) -> u8 {
        match self {
            Self::V4(packet) => packet.header.time_to_live,
            Self::V6(packet) => packet.header.hop_limit,
        }
    }

    /// Decrements the IPv4 TTL, updating the checksum as `ip_decrease_ttl` does, or the IPv6 hop
    /// limit. The hop limit must not be zero.
    pub fn decrement_hop_limit(&mut self) {
        match self {
            Self::V4(packet) => {
                let check = u32::from(packet.header.header_checksum.get()) + 0x0100;
                let check = check + u32::from(check >= 0xffff);
                packet.header.header_checksum = (check as u16).into();
                packet.header.time_to_live -= 1;
            }
            Self::V6(packet) => packet.header.hop_limit -= 1,
        }
    }

    /// Checks whether the packet may not go out over a link of this MTU. An IPv4 packet that
    /// allows fragmentation is never too big: it is left to the outer layer to fragment
    /// (the tunnel's own UDP packet), rather than fragmented here as Linux would.
    pub fn too_big(&self, mtu: u16) -> bool {
        match self {
            Self::V4(packet) => {
                packet.as_bytes().len() > usize::from(mtu) && packet.header.dont_fragment()
            }
            Self::V6(packet) => packet.as_bytes().len() > usize::from(mtu),
        }
    }

    /// Returns the packet.
    pub fn into_ip(self) -> Packet<Ip> {
        match self {
            Self::V4(packet) => packet.into(),
            Self::V6(packet) => packet.into(),
        }
    }
}
