//! ICMP errors, following Linux: `__icmp_send` in `net/ipv4/icmp.c`, `icmp6_send` in
//! `net/ipv6/icmp.c`, and `inet_peer_xrlim_allow` in `net/ipv4/inetpeer.c`.

use std::{
    hash::{BuildHasher, RandomState},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use bytes::BytesMut;
use gotatun::packet::{
    Ip, IpNextProtocol, Ipv4, Ipv4DscpEcn, Ipv4Header, Ipv6, Ipv6Header, Packet, PseudoHeaderV6,
    checksum,
};
use ipnet::Ipv6Net;
use zerocopy::{IntoBytes, transmute};

use crate::{
    babel::RouterId,
    router::ip::{IpPacket, into_ip, ipv6_header, martian_source},
};

/// The source of ICMPv4 errors from a node with no IPv4 address (RFC 9229 §3, RFC 7600 §4.8).
pub const DUMMY_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 8);

/// The prefix of the source of ICMPv6 errors from a node with no IPv6 address, followed by its
/// router-id. This is IANA's Dummy IPv6 Prefix (RFC 9780), registered as a source only. Nothing
/// ever answers an ICMP error, so that suits this use, although no RFC specifies it.
const DUMMY_V6_PREFIX: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x100, 0, 0, 1, 0, 0, 0, 0), 64);

/// The length of an ICMP header, including the field after the checksum.
const ICMP_HEADER_LEN: usize = 8;

/// How much of the original packet an ICMPv4 error quotes, so that it stays within 576 octets
/// (RFC 1812 §4.3.2.3).
const MAX_QUOTED_V4: usize = 576 - Ipv4Header::LEN - ICMP_HEADER_LEN;

/// How much of the original packet an ICMPv6 error quotes, so that it stays within the minimum
/// MTU (RFC 4443 §2.4).
const MAX_QUOTED_V6: usize = 1280 - Ipv6Header::LEN - ICMP_HEADER_LEN;

/// `sysctl_ip_default_ttl` and `hop_limit`, as set by default.
const HOP_LIMIT: u8 = 64;

/// `IPTOS_TOS_MASK`, the part of the original TOS that an ICMPv4 error keeps.
const TOS_MASK: u8 = 0x1e;

/// `IPTOS_PREC_INTERNETCONTROL`, the precedence of an ICMPv4 error.
const TOS_INTERNET_CONTROL: u8 = 0xc0;

/// The number of messages per second allowed globally (`icmp_msgs_per_sec`), as in Linux 6.12.
/// Mainline has since raised this and the burst to 10,000, but this runs in userspace, and
/// traffic counts here.
const GLOBAL_PER_SEC: u32 = 1000;

/// The most messages allowed at once globally (`icmp_msgs_burst`).
const GLOBAL_BURST: i32 = 50;

/// The shortest time after which the global credit is refilled, 20 ms.
const GLOBAL_MIN_REFILL: Duration = Duration::from_millis(20);

/// The time between messages allowed per destination, in milliseconds (`icmp_ratelimit`).
const DESTINATION_TIMEOUT_MS: u32 = 1000;

/// The most tokens a destination can hold, which is `XRLIM_BURST_FACTOR` messages' worth: how many
/// may be sent at once.
const DESTINATION_MAX_TOKENS: u32 = DESTINATION_TIMEOUT_MS * 6;

/// The number of buckets for destinations. They are fixed in number, so that a flood of spoofed
/// sources can't grow memory, and shared on a hash collision, which only makes the limit stricter.
const DESTINATION_BUCKETS: usize = 4096;

/// An ICMP error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcmpError {
    /// No route to the destination.
    NetUnreachable,
    /// The route to the destination is held unreachable.
    HostUnreachable,
    /// The TTL or hop limit ran out.
    TimeExceeded,
    /// The packet exceeds this MTU, and may not be fragmented.
    TooBig(u16),
}

impl IcmpError {
    /// Returns the ICMPv4 type, code and the field after the checksum.
    fn fields_v4(self) -> (u8, u8, u32) {
        match self {
            Self::NetUnreachable => (3, 0, 0),
            Self::HostUnreachable => (3, 1, 0),
            Self::TimeExceeded => (11, 0, 0),
            Self::TooBig(mtu) => (3, 4, mtu.into()),
        }
    }

    /// Returns the ICMPv6 type, code and the field after the checksum.
    fn fields_v6(self) -> (u8, u8, u32) {
        match self {
            Self::NetUnreachable | Self::HostUnreachable => (1, 0, 0),
            Self::TimeExceeded => (3, 0, 0),
            Self::TooBig(mtu) => (2, 0, mtu.into()),
        }
    }
}

/// Returns the source of ICMPv6 errors from a node with no IPv6 address.
pub fn dummy_v6(router_id: RouterId) -> Ipv6Addr {
    Ipv6Addr::from_bits(DUMMY_V6_PREFIX.addr().to_bits() | u128::from(router_id.get()))
}

/// Checks whether a packet is an ICMP error from a dummy address (see [`DUMMY_V4`] and
/// [`DUMMY_V6_PREFIX`]), which only ICMP errors may come from.
pub fn is_dummy_error(packet: &IpPacket) -> bool {
    match packet {
        IpPacket::V4(packet) => {
            packet.header.source() == DUMMY_V4
                && packet.header.protocol == IpNextProtocol::Icmp
                && first_payload_octet_v4(packet).is_some_and(is_error_type_v4)
        }
        IpPacket::V6(packet) => {
            DUMMY_V6_PREFIX.contains(&packet.header.source())
                && packet.header.next_header == IpNextProtocol::Icmpv6
                && packet
                    .payload
                    .first()
                    .is_some_and(|&ty| is_error_type_v6(ty))
        }
    }
}

/// Checks whether an ICMPv4 type is that of an error, as in `icmp_pointers`, which takes any
/// unknown type for one.
fn is_error_type_v4(ty: u8) -> bool {
    !matches!(ty, 0 | 8 | 13..=18)
}

/// Checks whether an ICMPv6 type is that of an error (RFC 4443 §2.1).
fn is_error_type_v6(ty: u8) -> bool {
    ty < 128
}

/// Returns the first octet of the payload of an IPv4 packet, past any options.
fn first_payload_octet_v4(packet: &Ipv4) -> Option<u8> {
    let header_len = usize::from(packet.header.ihl()) * 4;
    packet.as_bytes().get(header_len).copied()
}

/// Checks whether a packet may be answered with an ICMP error: not one sent from an address that
/// doesn't identify a node, or itself an error.
pub fn eligible(packet: &IpPacket) -> bool {
    !martian_source(packet.source())
        && match packet {
            IpPacket::V4(packet) => eligible_v4(packet),
            IpPacket::V6(packet) => eligible_v6(packet),
        }
}

fn eligible_v4(packet: &Ipv4) -> bool {
    // Only reply to fragment 0.
    if packet.header.fragment_offset() != 0 {
        return false;
    }

    // If we send an ICMP error to an ICMP error a mess would result.
    if packet.header.protocol == IpNextProtocol::Icmp {
        return first_payload_octet_v4(packet).is_some_and(|ty| !is_error_type_v4(ty));
    }

    true
}

fn eligible_v6(packet: &Ipv6) -> bool {
    // This follows `is_ineligible`, which takes `ipv6_skip_exthdr`'s result as is. Unlike in IPv4,
    // a fragment other than the first is answered too, as it has no ICMPv6 header to check.
    let Some((next_header, start, fragment_offset)) = skip_extension_headers(packet) else {
        return true;
    };
    if next_header != IpNextProtocol::Icmpv6 {
        return true;
    }
    match packet.as_bytes().get(start) {
        Some(&ty) => !is_error_type_v6(ty),
        None => fragment_offset != 0,
    }
}

/// Walks a packet's extension headers as `ipv6_skip_exthdr` does. Returns the next header value,
/// its offset, and the Fragment Offset field as is, or `None` if the walk runs off the end of
/// the packet, or finds no next header.
fn skip_extension_headers(packet: &Ipv6) -> Option<(IpNextProtocol, usize, u16)> {
    let bytes = packet.as_bytes();
    let mut next_header = packet.header.next_header;
    let mut start = Ipv6Header::LEN;
    let mut fragment_offset = 0;

    while matches!(
        next_header,
        IpNextProtocol::Hopopt
            | IpNextProtocol::Ipv6Route
            | IpNextProtocol::Ipv6Frag
            | IpNextProtocol::Ah
            | IpNextProtocol::Ipv6NoNxt
            | IpNextProtocol::Ipv6Opts
    ) {
        if next_header == IpNextProtocol::Ipv6NoNxt {
            return None;
        }
        let [this_next, this_len] = *bytes.get(start..start + 2)?.first_chunk()?;

        let header_len = match next_header {
            IpNextProtocol::Ipv6Frag => {
                let field = bytes.get(start + 2..start + 4)?;
                fragment_offset = u16::from_be_bytes([field[0], field[1]]);
                // A fragment other than the first has no next header to look at.
                if fragment_offset & !0x7 != 0 {
                    break;
                }
                8
            }
            IpNextProtocol::Ah => (usize::from(this_len) + 2) * 4,
            _ => (usize::from(this_len) + 1) * 8,
        };

        next_header = transmute!(this_next);
        start += header_len;
    }

    Some((next_header, start, fragment_offset))
}

/// Builds an ICMPv4 error about a packet.
pub fn build_v4(source: Ipv4Addr, original: &Ipv4, error: IcmpError) -> Packet<Ip> {
    let (ty, code, rest) = error.fields_v4();

    let quoted = original.as_bytes();
    let quoted = &quoted[..quoted.len().min(MAX_QUOTED_V4)];

    let mut header = Ipv4Header::new_for_length(
        source,
        original.header.source(),
        IpNextProtocol::Icmp,
        (ICMP_HEADER_LEN + quoted.len()) as u16,
    );
    let tos = original.header.dscp_and_ecn.into_bits() & TOS_MASK;
    header.dscp_and_ecn = Ipv4DscpEcn::from_bits(tos | TOS_INTERNET_CONTROL);
    header.identification = rand::random::<u16>().into();
    header.time_to_live = HOP_LIMIT;
    header.header_checksum = header.compute_checksum().into();

    let mut buf = BytesMut::with_capacity(Ipv4Header::LEN + ICMP_HEADER_LEN + quoted.len());
    buf.extend_from_slice(header.as_bytes());
    put_icmp(&mut buf, ty, code, rest, quoted);

    let icmp = &buf[Ipv4Header::LEN..];
    let check = checksum(&[icmp]);
    set_icmp_checksum(&mut buf, Ipv4Header::LEN, check);

    into_ip(buf)
}

/// Builds an ICMPv6 error about a packet.
pub fn build_v6(source: Ipv6Addr, original: &Ipv6, error: IcmpError) -> Packet<Ip> {
    let (ty, code, rest) = error.fields_v6();

    let quoted = original.as_bytes();
    let quoted = &quoted[..quoted.len().min(MAX_QUOTED_V6)];
    let icmp_len = ICMP_HEADER_LEN + quoted.len();

    let header = ipv6_header(
        source,
        original.header.source(),
        IpNextProtocol::Icmpv6,
        HOP_LIMIT,
        icmp_len,
    );

    let mut buf = BytesMut::with_capacity(Ipv6Header::LEN + icmp_len);
    buf.extend_from_slice(header.as_bytes());
    put_icmp(&mut buf, ty, code, rest, quoted);

    let icmp = &buf[Ipv6Header::LEN..];
    let pseudo_header = PseudoHeaderV6::from_bytes(
        header.source_address,
        header.destination_address,
        IpNextProtocol::Icmpv6,
        icmp,
    );
    let check = checksum(&[pseudo_header.as_bytes(), icmp]);
    set_icmp_checksum(&mut buf, Ipv6Header::LEN, check);

    into_ip(buf)
}

fn put_icmp(buf: &mut BytesMut, ty: u8, code: u8, rest: u32, quoted: &[u8]) {
    buf.extend_from_slice(&[ty, code, 0, 0]);
    buf.extend_from_slice(&rest.to_be_bytes());
    buf.extend_from_slice(quoted);
}

fn set_icmp_checksum(buf: &mut BytesMut, icmp_start: usize, check: u16) {
    buf[icmp_start + 2..icmp_start + 4].copy_from_slice(&check.to_be_bytes());
}

/// One destination's tokens, in milliseconds.
#[derive(Clone, Copy)]
struct Bucket {
    tokens: u32,
    /// When it was last touched, in milliseconds from the start of the limiter, modulo 2^32.
    last: u32,
}

/// Limits ICMP errors as Linux does: a global token bucket, then one per destination.
/// Errors for path MTU discovery are never limited, since dropping one can blackhole a connection.
pub struct Limiter {
    credit: i32,
    stamp: Instant,
    start: Instant,
    buckets: Box<[Bucket]>,
    hasher: RandomState,
}

impl Limiter {
    /// Creates a limiter at `now`, with every bucket full.
    pub fn new(now: Instant) -> Self {
        Self {
            credit: GLOBAL_BURST,
            stamp: now,
            start: now,
            buckets: vec![
                Bucket {
                    tokens: DESTINATION_MAX_TOKENS,
                    last: 0,
                };
                DESTINATION_BUCKETS
            ]
            .into_boxed_slice(),
            hasher: RandomState::new(),
        }
    }

    /// Checks whether an error may be sent to `destination` at `now`, and if so, charges for it.
    pub fn allow(&mut self, error: IcmpError, destination: IpAddr, now: Instant) -> bool {
        if matches!(error, IcmpError::TooBig(_)) {
            return true;
        }

        if !self.global_allow(now) || !self.destination_allow(destination, now) {
            return false;
        }

        // Charging at random keeps the global limit from revealing how many errors were sent, as
        // an attacker could tell open UDP ports with that (CVE-2020-25705).
        self.credit -= rand::random_range(0..3);
        true
    }

    /// Follows `icmp_global_allow`.
    fn global_allow(&mut self, now: Instant) -> bool {
        if self.credit > 0 {
            return true;
        }

        let delta = now
            .saturating_duration_since(self.stamp)
            .min(Duration::from_secs(1));
        if delta < GLOBAL_MIN_REFILL {
            return false;
        }

        let refill = u64::from(GLOBAL_PER_SEC) * delta.as_millis() as u64 / 1000;
        self.stamp = now;
        self.credit = (self.credit + refill as i32).min(GLOBAL_BURST);
        true
    }

    /// Follows `inet_peer_xrlim_allow`.
    fn destination_allow(&mut self, destination: IpAddr, now: Instant) -> bool {
        let index = self.hasher.hash_one(destination) as usize % DESTINATION_BUCKETS;
        let bucket = &mut self.buckets[index];

        let now = now.saturating_duration_since(self.start).as_millis() as u32;
        let delta = now.wrapping_sub(bucket.last);
        bucket.last = now;

        bucket.tokens = bucket
            .tokens
            .saturating_add(delta)
            .min(DESTINATION_MAX_TOKENS);

        if bucket.tokens >= DESTINATION_TIMEOUT_MS {
            bucket.tokens -= DESTINATION_TIMEOUT_MS;
            true
        } else {
            false
        }
    }
}
