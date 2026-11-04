use std::{
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU8,
    time::Instant,
};

use super::*;
use crate::babel::base::{Ae::*, timestamp};

const P: u8 = 0x80;
const R: u8 = 0x40;

const METRIC: u16 = 96;
const INF: u16 = METRIC_INFINITY;

// Parser state slots.
const ROUTER_ID: u8 = 1;
const PREFIX_IPV4: u8 = 2;
const PREFIX_IPV6: u8 = 4;
const PREFIX_V4_VIA_V6: u8 = 8;

type Item = Result<PacketItem, PacketDecodeError>;

/// What the packet decoder should yield for a TLV.
enum Yields {
    /// The TLV as is.
    Tlv,
    /// The error from the stateless decoder.
    Stateless,
    /// The Update TLV, ignored for lack of parser state.
    Stateful,
    /// The update, resolved with the parser state.
    Update(Update),
}

fn interval() -> Interval {
    Interval::new(400).unwrap()
}

fn router_id(n: u64) -> Tlv {
    Tlv::RouterId {
        router_id: RouterId::new(n).unwrap(),
    }
}

/// Parses an IPv6 or IPv4 address into the octets of a prefix.
fn addr(s: &str) -> [u8; 16] {
    if let Ok(addr) = s.parse::<Ipv6Addr>() {
        addr.octets()
    } else {
        let mut prefix = [0; 16];
        prefix[..4].copy_from_slice(&s.parse::<Ipv4Addr>().unwrap().octets());
        prefix
    }
}

/// Returns an Update TLV with Interval 400 and Seqno 7.
fn update_tlv(ae: Ae, flags: u8, plen: u8, omitted: u8, metric: u16, bytes: &[u8]) -> Tlv {
    let mut prefix = [0; 16];
    prefix[..bytes.len()].copy_from_slice(bytes);
    Tlv::Update {
        ae,
        flags: UpdateFlags::from_bits(flags),
        plen,
        omitted,
        interval: interval(),
        seqno: Seqno::new(7),
        metric,
        prefix,
    }
}

/// Returns an update with Interval 400 and Seqno 7.
fn update(ae: Ae, plen: u8, metric: u16, prefix: &str, router_id: Option<u64>) -> Update {
    Update {
        ae,
        plen,
        interval: interval(),
        seqno: Seqno::new(7),
        metric,
        prefix: addr(prefix),
        router_id: router_id.map(|n| RouterId::new(n).unwrap()),
    }
}

fn encode(tlv: &Tlv) -> Vec<u8> {
    let mut bytes = vec![0; tlv.encoded_len()];
    tlv.encode(&mut bytes);
    bytes
}

/// Encodes a TLV with an unknown mandatory sub-TLV appended.
fn encode_with_mandatory_sub_tlv(tlv: &Tlv) -> Vec<u8> {
    let mut bytes = encode(tlv);
    bytes[1] += 2;
    bytes.extend([0x80, 0]);
    bytes
}

fn packet(tlvs: &[Vec<u8>]) -> Vec<u8> {
    let body = tlvs.concat();
    let mut packet = vec![MAGIC, VERSION];
    packet.extend((body.len() as u16).to_be_bytes());
    packet.extend(body);
    packet
}

fn decode(packet: &[u8]) -> Vec<Item> {
    PacketDecoder::new(packet).unwrap().collect()
}

/// Decodes the TLVs in a packet body without the parser state.
fn decode_stateless(packet: &[u8]) -> Vec<Tlv> {
    let mut body = &packet[4..];
    let mut tlvs = vec![];
    while !body.is_empty() {
        tlvs.push(Tlv::decode(&mut body).unwrap());
    }
    tlvs
}

/// Asserts that a packet of the given encoded TLVs decodes as expected.
fn assert_decodes(cases: &[(Vec<u8>, Yields)]) {
    let tlvs: Vec<_> = cases.iter().map(|(bytes, _)| bytes.clone()).collect();
    let expected: Vec<Item> = cases
        .iter()
        .map(|(bytes, yields)| {
            let tlv = Tlv::decode(&mut &bytes[..]);
            match yields {
                Yields::Tlv => Ok(PacketItem::Tlv(tlv.unwrap())),
                Yields::Stateless => Err(PacketDecodeError::Stateless(tlv.unwrap_err())),
                Yields::Stateful => Err(PacketDecodeError::Stateful(tlv.unwrap())),
                Yields::Update(update) => Ok(PacketItem::Update(update.clone())),
            }
        })
        .collect();
    assert_eq!(decode(&packet(&tlvs)), expected);
}

fn encode_updates(updates: &[Update]) -> Vec<u8> {
    let mut encoder = PacketEncoder::new(512);
    for update in updates {
        assert!(encoder.put_update(update));
    }
    encoder.finalize().as_bytes().to_vec()
}

/// Decodes the updates in a packet, skipping the Router-Id TLVs put along with them.
fn decode_updates(packet: &[u8]) -> Vec<Update> {
    decode(packet)
        .into_iter()
        .filter_map(|item| match item {
            Ok(PacketItem::Update(update)) => Some(update),
            Ok(PacketItem::Tlv(Tlv::RouterId { .. })) => None,
            item => panic!("unexpected {item:?}"),
        })
        .collect()
}

#[test]
fn packet_header() {
    let ack = Tlv::Acknowledgement { opaque: 1 };

    // The packet trailer is ignored.
    let mut with_trailer = packet(&[encode(&ack)]);
    with_trailer.extend([0xff; 3]);
    assert_eq!(decode(&with_trailer), [Ok(PacketItem::Tlv(ack))]);

    assert_eq!(decode(&packet(&[])), []);

    assert!(PacketDecoder::new(&[43, 2, 0, 0]).is_none());
    assert!(PacketDecoder::new(&[42, 1, 0, 0]).is_none());
    assert!(PacketDecoder::new(&[42, 2, 0]).is_none());
    // The body length exceeds the packet.
    assert!(PacketDecoder::new(&[42, 2, 0, 5, 0, 0, 0, 0]).is_none());
}

#[test]
fn decode_tlvs_other_than_updates() {
    let interval = Interval::new(1200).unwrap();

    assert_decodes(&[
        (encode(&Tlv::Pad1), Yields::Tlv),
        (encode(&Tlv::PadN { length: 2 }), Yields::Tlv),
        (
            encode(&Tlv::AcknowledgementRequest {
                opaque: 1,
                interval,
            }),
            Yields::Tlv,
        ),
        (encode(&Tlv::Acknowledgement { opaque: 1 }), Yields::Tlv),
        (encode(&hello(Some(2))), Yields::Tlv),
        (encode(&ihu(Some((1, 2)))), Yields::Tlv),
        // Next Hop TLVs are unknown, and decoding goes on after them.
        (vec![7, 6, 1, 0, 10, 0, 0, 1], Yields::Stateless),
        (encode(&router_id(1)), Yields::Tlv),
        (
            encode(&Tlv::RouteRequest {
                ae: Wildcard,
                plen: 0,
                prefix: [0; 16],
            }),
            Yields::Tlv,
        ),
        (
            encode(&Tlv::SeqnoRequest {
                ae: Ipv6,
                plen: 128,
                seqno: Seqno::new(1),
                hop_count: NonZeroU8::new(64).unwrap(),
                router_id: RouterId::new(1).unwrap(),
                prefix: addr("2001:db8::1"),
            }),
            Yields::Tlv,
        ),
    ]);
}

#[test]
fn decode_expands_compressed_prefixes() {
    // Retractions need no router-id.
    assert_decodes(&[
        // There is no default prefix yet.
        (
            encode(&update_tlv(Ipv6, 0, 64, 2, INF, &[0x0d, 0xb8, 0, 1, 0, 2])),
            Yields::Stateful,
        ),
        (
            encode(&update_tlv(Ipv6, P, 64, 0, INF, &addr("2001:db8:1:2::"))),
            Yields::Update(update(Ipv6, 64, INF, "2001:db8:1:2::", None)),
        ),
        // Bits beyond Plen are cleared after the omitted octets are filled in.
        (
            encode(&update_tlv(Ipv6, 0, 60, 6, INF, &[0x00, 0x3f])),
            Yields::Update(update(Ipv6, 60, INF, "2001:db8:1:30::", None)),
        ),
        (
            encode(&update_tlv(Ipv6, P, 128, 8, INF, &[0, 0, 0, 0, 0, 0, 0, 1])),
            Yields::Update(update(Ipv6, 128, INF, "2001:db8:1:2::1", None)),
        ),
        (
            encode(&update_tlv(Ipv6, 0, 128, 15, INF, &[2])),
            Yields::Update(update(Ipv6, 128, INF, "2001:db8:1:2::2", None)),
        ),
        // AE 1 and AE 4 have separate default prefixes...
        (
            encode(&update_tlv(Ipv4, P, 24, 0, INF, &[10, 1, 2])),
            Yields::Update(update(Ipv4, 24, INF, "10.1.2.0", None)),
        ),
        (
            encode(&update_tlv(V4ViaV6, 0, 24, 2, INF, &[3])),
            Yields::Stateful,
        ),
        (
            encode(&update_tlv(V4ViaV6, P, 16, 0, INF, &[192, 168])),
            Yields::Update(update(V4ViaV6, 16, INF, "192.168.0.0", None)),
        ),
        (
            encode(&update_tlv(Ipv4, 0, 32, 3, INF, &[4])),
            Yields::Update(update(Ipv4, 32, INF, "10.1.2.4", None)),
        ),
        // ...that do not affect the IPv6 one.
        (
            encode(&update_tlv(Ipv6, 0, 128, 15, INF, &[3])),
            Yields::Update(update(Ipv6, 128, INF, "2001:db8:1:2::3", None)),
        ),
        (
            encode(&update_tlv(Wildcard, 0, 0, 0, INF, &[])),
            Yields::Update(update(Wildcard, 0, INF, "::", None)),
        ),
    ]);
}

#[test]
fn decode_resolves_router_ids() {
    let default_route = encode(&update_tlv(Ipv6, 0, 0, 0, METRIC, &[]));

    assert_decodes(&[
        // There is no router-id yet...
        (default_route.clone(), Yields::Stateful),
        // ...which retractions do not need.
        (
            encode(&update_tlv(Ipv6, 0, 0, 0, INF, &[])),
            Yields::Update(update(Ipv6, 0, INF, "::", None)),
        ),
        (encode(&router_id(1)), Yields::Tlv),
        (
            default_route.clone(),
            Yields::Update(update(Ipv6, 0, METRIC, "::", Some(1))),
        ),
        // The Router-Id flag establishes the router-id for the TLV itself.
        (
            encode(&update_tlv(Ipv6, R, 128, 0, METRIC, &addr("2001:db8::5"))),
            Yields::Update(update(Ipv6, 128, METRIC, "2001:db8::5", Some(5))),
        ),
        (
            default_route.clone(),
            Yields::Update(update(Ipv6, 0, METRIC, "::", Some(5))),
        ),
        (encode(&router_id(2)), Yields::Tlv),
        (
            default_route.clone(),
            Yields::Update(update(Ipv6, 0, METRIC, "::", Some(2))),
        ),
        // IPv4 addresses are stored on the right of the router-id.
        (
            encode(&update_tlv(Ipv4, R, 32, 0, METRIC, &[10, 0, 0, 9])),
            Yields::Update(update(Ipv4, 32, METRIC, "10.0.0.9", Some(0x0a00_0009))),
        ),
        // Retractions carry the router-id too, once there is one.
        (
            encode(&update_tlv(Ipv6, 0, 0, 0, INF, &[])),
            Yields::Update(update(Ipv6, 0, INF, "::", Some(0x0a00_0009))),
        ),
        // An invalid router-id computed from the prefix undefines the router-id.
        (
            encode(&update_tlv(Ipv6, R, 64, 0, METRIC, &addr("2001:db8::"))),
            Yields::Stateful,
        ),
        (default_route.clone(), Yields::Stateful),
        (encode(&router_id(3)), Yields::Tlv),
        (
            default_route.clone(),
            Yields::Update(update(Ipv6, 0, METRIC, "::", Some(3))),
        ),
        // So does a prefix that cannot be computed.
        (
            encode(&update_tlv(V4ViaV6, R, 32, 1, METRIC, &[1, 2, 3])),
            Yields::Stateful,
        ),
        (default_route, Yields::Stateful),
    ]);
}

#[test]
fn decode_updates_parser_state_for_ignored_tlvs() {
    assert_decodes(&[
        // An Update TLV ignored for lack of a router-id sets the default prefix.
        (
            encode(&update_tlv(Ipv6, P, 64, 0, METRIC, &addr("2001:db8::"))),
            Yields::Stateful,
        ),
        (
            encode(&update_tlv(Ipv6, 0, 128, 8, INF, &[0, 0, 0, 0, 0, 0, 0, 1])),
            Yields::Update(update(Ipv6, 128, INF, "2001:db8::1", None)),
        ),
        // So does one ignored for an unknown mandatory sub-TLV, and it sets the router-id too.
        (
            encode_with_mandatory_sub_tlv(&update_tlv(Ipv6, P | R, 128, 15, METRIC, &[5])),
            Yields::Stateless,
        ),
        (
            encode(&update_tlv(Ipv6, 0, 128, 15, METRIC, &[6])),
            Yields::Update(update(Ipv6, 128, METRIC, "2001:db8::6", Some(5))),
        ),
        (
            encode_with_mandatory_sub_tlv(&router_id(7)),
            Yields::Stateless,
        ),
        (
            encode(&update_tlv(Ipv6, 0, 128, 15, METRIC, &[8])),
            Yields::Update(update(Ipv6, 128, METRIC, "2001:db8::8", Some(7))),
        ),
        // An Update TLV with a zero Interval.
        (
            vec![8, 11, 2, P | R, 128, 15, 0, 0, 0, 7, 0, 96, 9],
            Yields::Stateless,
        ),
        (
            encode(&update_tlv(Ipv6, 0, 128, 15, METRIC, &[0x0a])),
            Yields::Update(update(Ipv6, 128, METRIC, "2001:db8::a", Some(9))),
        ),
    ]);
}

#[test]
fn decode_undefines_parser_state_for_malformed_tlvs() {
    let setup = [
        encode(&router_id(1)),
        encode(&update_tlv(Ipv4, P, 24, 0, INF, &[10, 1, 2])),
        encode(&update_tlv(Ipv6, P, 32, 0, INF, &[0x20, 0x01, 0x0d, 0xb8])),
        encode(&update_tlv(V4ViaV6, P, 16, 0, INF, &[192, 168])),
    ];
    // Each probe depends on one slot, in the order of the slot bits.
    let probes = [
        encode(&update_tlv(Ipv6, 0, 0, 0, METRIC, &[])),
        encode(&update_tlv(Ipv4, 0, 24, 3, INF, &[])),
        encode(&update_tlv(Ipv6, 0, 32, 4, INF, &[])),
        encode(&update_tlv(V4ViaV6, 0, 16, 2, INF, &[])),
    ];

    #[rustfmt::skip]
    let cases: [(&[u8], u8); 6] = [
        (&[6, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], ROUTER_ID),
        (&[8, 0], ROUTER_ID | PREFIX_IPV4 | PREFIX_IPV6 | PREFIX_V4_VIA_V6),
        (&[8, 1, 1], ROUTER_ID | PREFIX_IPV4),
        (&[8, 10, 2, P, 8, 2, 1, 0x90, 0, 7, 0xff, 0xff], PREFIX_IPV6),
        (&[8, 11, 4, P | R, 16, 0, 1, 0x90, 0, 7, 0, 96, 192], ROUTER_ID | PREFIX_V4_VIA_V6),
        (&[8, 10, 9, P | R, 0, 0, 1, 0x90, 0, 7, 0xff, 0xff], ROUTER_ID),
    ];

    for (malformed, undefined) in cases {
        let tlvs = [&setup[..], &[malformed.to_vec()], &probes[..]].concat();
        let items = decode(&packet(&tlvs));

        for (i, item) in items[items.len() - probes.len()..].iter().enumerate() {
            let defined = undefined & (1 << i) == 0;
            assert_eq!(
                matches!(item, Ok(PacketItem::Update(_))),
                defined,
                "slot {i} after {malformed:02x?}"
            );
        }
    }
}

#[test]
fn put_update_round_trips_in_any_order() {
    let mut updates = vec![
        // A wildcard retraction goes first, and the rest are sorted as hinted.
        update(Wildcard, 0, INF, "::", None),
        update(Ipv6, 128, METRIC, "2001:db8::1", Some(1)),
        update(Ipv6, 48, METRIC, "2001:db8:1::", Some(1)),
        update(Ipv6, 64, METRIC, "2001:db8:1:2::", Some(1)),
        update(Ipv6, 64, INF, "2001:db8:1:3::", Some(1)),
        update(Ipv6, 0, METRIC, "::", Some(2)),
        update(V4ViaV6, 24, METRIC, "10.0.1.0", Some(2)),
        update(Ipv6, 64, INF, "2001:db8:0:9::", Some(2)),
        update(Ipv6, 61, METRIC, "2001:db8:1:8::", Some(2)),
        update(Ipv4, 32, INF, "10.0.0.1", Some(0x0a00_0001)),
    ];

    assert_eq!(decode_updates(&encode_updates(&updates)), updates);
    updates[1..].reverse();
    assert_eq!(decode_updates(&encode_updates(&updates)), updates);
}

#[test]
fn put_update_compresses() {
    let packet = encode_updates(&[
        update(Ipv6, 128, METRIC, "2001:db8::1", Some(1)),
        update(Ipv6, 64, METRIC, "2001:db8::", Some(1)),
        update(Ipv6, 64, METRIC, "2001:db8:0:1::", Some(2)),
        update(Ipv6, 64, INF, "2001:db8:0:2::", None),
        update(Ipv6, 64, METRIC, "2001:db8:0:3::", Some(2)),
        update(Ipv6, 64, INF, "2001:db8:0:4::", Some(3)),
        update(Ipv6, 128, INF, "2001:db8::5", Some(5)),
        update(Ipv6, 32, INF, "2001:db9::", Some(5)),
        update(Ipv6, 128, INF, "2001:db8::6", Some(5)),
    ]);

    assert_eq!(
        decode_stateless(&packet),
        [
            // The router-id coincides with the one computed from the prefix.
            update_tlv(Ipv6, P | R, 128, 0, METRIC, &addr("2001:db8::1")),
            update_tlv(Ipv6, P, 64, 8, METRIC, &[]),
            router_id(2),
            update_tlv(Ipv6, P, 64, 7, METRIC, &[1]),
            // A retraction without a router-id leaves it as is...
            update_tlv(Ipv6, P, 64, 7, INF, &[2]),
            update_tlv(Ipv6, P, 64, 7, METRIC, &[3]),
            // ...and one with a router-id establishes it like an announcement.
            router_id(3),
            update_tlv(Ipv6, P, 64, 7, INF, &[4]),
            update_tlv(Ipv6, P | R, 128, 7, INF, &[0, 0, 0, 0, 0, 0, 0, 0, 5]),
            // A prefix shorter than /48 does not replace the default prefix...
            update_tlv(Ipv6, 0, 32, 3, INF, &[0xb9]),
            update_tlv(Ipv6, P, 128, 15, INF, &[6]),
        ]
    );

    // ...unless there is none yet.
    let packet = encode_updates(&[
        update(Ipv6, 32, METRIC, "2001:db8::", Some(1)),
        update(Ipv6, 64, METRIC, "2001:db8:0:1::", Some(1)),
    ]);

    assert_eq!(
        decode_stateless(&packet),
        [
            router_id(1),
            update_tlv(Ipv6, P, 32, 0, METRIC, &[0x20, 0x01, 0x0d, 0xb8]),
            update_tlv(Ipv6, P, 64, 7, METRIC, &[1]),
        ]
    );

    // IPv4 prefixes are not compressed, but may establish the router-id too.
    let packet = encode_updates(&[
        update(V4ViaV6, 24, METRIC, "10.0.1.0", Some(1)),
        update(V4ViaV6, 24, METRIC, "10.0.2.0", Some(1)),
        update(Ipv4, 32, INF, "10.0.0.1", Some(0x0a00_0001)),
    ]);

    assert_eq!(
        decode_stateless(&packet),
        [
            router_id(1),
            update_tlv(V4ViaV6, 0, 24, 0, METRIC, &[10, 0, 1]),
            update_tlv(V4ViaV6, 0, 24, 0, METRIC, &[10, 0, 2]),
            update_tlv(Ipv4, R, 32, 0, INF, &[10, 0, 0, 1]),
        ]
    );
}

#[test]
fn put_update_puts_nothing_if_not_all_fits() {
    let mut encoder = PacketEncoder::new(512);
    let mut put = vec![];

    // Each update needs a Router-Id TLV.
    let rejected = loop {
        let i = put.len() as u64 + 1;
        let next = update(
            Ipv6,
            128,
            METRIC,
            &format!("2001:db8::{i:x}"),
            Some(i + 0x100),
        );
        if !encoder.put_update(&next) {
            break next;
        }
        put.push(next);
    };

    // The Update TLV (13 octets) would fit, but not with the Router-Id TLV (12 octets).
    assert!((13..25).contains(&encoder.remaining()));
    // The failed put leaves the parser state as is, so retrying fails likewise.
    assert!(!encoder.put_update(&rejected));
    assert_eq!(decode_updates(encoder.finalize().as_bytes()), put);

    // The parser state is reset for the next packet.
    encoder.clear();
    let last = put.last().unwrap().clone();
    assert!(encoder.put_update(&last));
    assert!(encoder.put_update(&rejected));
    assert_eq!(
        decode_updates(encoder.finalize().as_bytes()),
        [last, rejected]
    );
}

fn hello(transmit_timestamp: Option<u32>) -> Tlv {
    Tlv::Hello {
        seqno: Seqno::new(1),
        interval: Some(interval()),
        transmit_timestamp,
    }
}

fn ihu(origin_receive_timestamps: Option<(u32, u32)>) -> Tlv {
    Tlv::Ihu {
        ae: Wildcard,
        rxcost: METRIC,
        interval: interval(),
        address: [0; 8],
        origin_receive_timestamps,
    }
}

/// Decodes a packet carrying a timestamped Hello, returning the Hello's
/// transmit timestamp and the items.
fn items(tlvs: impl IntoIterator<Item = Tlv>) -> Vec<Item> {
    tlvs.into_iter()
        .map(|tlv| Ok(PacketItem::Tlv(tlv)))
        .collect()
}

#[test]
fn put_tlv_fills_packet_exactly() {
    let tlvs = [ihu(Some((1, 2))), Tlv::PadN { length: 5 }];

    let mut encoder = PacketEncoder::new(512);
    let mut put = vec![hello(Some(0))];
    assert!(encoder.put_tlv(&put[0]));

    for tlv in tlvs.iter().cycle() {
        if !encoder.put_tlv(tlv) {
            // Nothing is put if not all fits.
            assert!(!encoder.put_tlvs(&[Tlv::Pad1, tlv.clone()]));
            break;
        }
        put.push(tlv.clone());
    }
    while encoder.put_tlv(&Tlv::Pad1) {
        put.push(Tlv::Pad1);
    }

    let packet = encoder.finalize();
    assert_eq!(packet.as_bytes().len(), 512);
    assert_eq!(decode(packet.as_bytes()), items(put));
}

#[test]
fn packets_are_timestamped_as_sent() {
    let ack = Tlv::Acknowledgement { opaque: 1 };
    let at = Instant::now();

    // The Transmit Timestamp put is a placeholder, filled in as the packet is sent, and a
    // timestamped IHU may follow the Hello it is put along with.
    let mut encoder = PacketEncoder::new(512);
    assert!(encoder.put_tlv(&ack));
    assert!(encoder.put_tlvs(&[Tlv::Pad1, hello(Some(0)), ihu(Some((1, 2)))]));
    let mut packet = encoder.finalize();
    let tlvs = |t| items([ack.clone(), Tlv::Pad1, hello(Some(t)), ihu(Some((1, 2)))]);
    assert_eq!(decode(packet.as_bytes()), tlvs(0));
    assert_eq!(decode(packet.timestamp(at)), tlvs(timestamp(at)));

    // Each packet may carry a Hello, and a timestamped IHU may be put after it,
    // but not another Hello.
    encoder.clear();
    assert!(encoder.put_tlv(&hello(Some(0))));
    assert!(encoder.put_tlv(&ihu(Some((3, 4)))));
    assert!(!encoder.put_tlvs(&[Tlv::Pad1, hello(None)]));
    assert_eq!(
        decode(encoder.finalize().timestamp(at)),
        items([hello(Some(timestamp(at))), ihu(Some((3, 4)))])
    );

    // A Hello without a timestamp is left as is, and an untimestamped IHU needs no timestamped Hello.
    encoder.clear();
    assert!(encoder.put_tlvs(&[hello(None), ihu(None)]));
    assert_eq!(
        decode(encoder.finalize().timestamp(at)),
        items([hello(None), ihu(None)])
    );

    // Nothing is timestamped if the Hello does not fit.
    encoder.clear();
    let padding = [Tlv::PadN { length: 250 }, Tlv::PadN { length: 250 }];
    assert!(encoder.put_tlvs(&padding));
    assert!(!encoder.put_tlv(&hello(Some(0))));
    assert_eq!(decode(encoder.finalize().timestamp(at)), items(padding));
}

macro_rules! put_tlvs_panics {
    ($($name:ident: $tlvs:expr => $message:literal,)*) => {$(
        #[test]
        #[should_panic(expected = $message)]
        fn $name() {
            let _ = PacketEncoder::new(512).put_tlvs(&$tlvs);
        }
    )*};
}

put_tlvs_panics! {
    put_tlvs_panics_with_router_id:
        [router_id(1)] => "Router-Id and Update TLVs should be put with put_update",
    put_tlvs_panics_with_update:
        [update_tlv(Ipv6, 0, 0, 0, INF, &[])] => "Router-Id and Update TLVs should be put with put_update",
    put_tlvs_panics_with_wildcard_update_with_flags:
        [update_tlv(Wildcard, 0x80, 0, 0, INF, &[])]
            => "Router-Id and Update TLVs should be put with put_update",
    put_tlvs_panics_with_two_hellos:
        [hello(None), hello(None)] => "TLVs put together should not include more than one Hello",
    put_tlvs_panics_with_timestamped_ihu_before_hello:
        [ihu(Some((1, 2))), hello(Some(0))]
            => "timestamped IHU should be put after a timestamped Hello",
    put_tlvs_panics_with_timestamped_ihu_after_untimestamped_hello:
        [hello(None), ihu(Some((1, 2)))]
            => "timestamped IHU should be put after a timestamped Hello",
}

#[test]
#[should_panic(expected = "packet buffer size should be between 512 and 65535")]
fn new_panics_with_small_buffer() {
    PacketEncoder::new(511);
}

#[test]
#[should_panic(expected = "Update should not carry AE 3")]
fn put_update_panics_with_ae_3() {
    let _ = PacketEncoder::new(512).put_update(&update(LinkLocalIpv6, 64, INF, "fe80::", None));
}

#[test]
#[should_panic(expected = "Update should not carry a prefix with bits set beyond Plen")]
fn put_update_panics_with_unmasked_prefix() {
    let _ = PacketEncoder::new(512).put_update(&update(Ipv6, 64, METRIC, "2001:db8::1", Some(1)));
}

#[test]
#[should_panic(expected = "Update with finite metric should carry a router-id")]
fn put_update_panics_without_router_id_for_finite_metric() {
    let _ = PacketEncoder::new(512).put_update(&update(Ipv6, 64, METRIC, "2001:db8::", None));
}

/// A wildcard retraction can go with other TLVs, all at once or not at all, and comes out as it
/// does from `put_update`.
#[test]
fn put_tlvs_takes_a_wildcard_retraction() {
    let tlv = update_tlv(Wildcard, 0, 0, 0, INF, &[]);

    let mut from_tlv = PacketEncoder::new(512);
    assert!(from_tlv.put_tlv(&tlv));
    assert_eq!(
        from_tlv.finalize().as_bytes(),
        encode_updates(&[update(Wildcard, 0, INF, "::", None)])
    );

    // It leaves the parser state as it is, so what follows can still be compressed against what
    // came before.
    let announce = |e: &mut PacketEncoder, prefix| {
        assert!(e.put_update(&update(Ipv6, 64, 1, prefix, Some(1))));
    };
    let mut encoder = PacketEncoder::new(1400);
    announce(&mut encoder, "2001:db8::");
    let before = encoder.remaining();
    announce(&mut encoder, "2001:db8:0:1::");
    let compressed = before - encoder.remaining();
    assert!(encoder.put_tlv(&tlv));
    let before = encoder.remaining();
    announce(&mut encoder, "2001:db8:0:2::");
    assert_eq!(before - encoder.remaining(), compressed);

    // If it all doesn't fit, nothing goes in, though the retraction alone would have.
    let mut encoder = PacketEncoder::new(512);
    for length in [200, 200, 80] {
        assert!(encoder.put_tlv(&Tlv::PadN { length }));
    }
    let remaining = encoder.remaining();
    assert!(tlv.encoded_len() <= remaining);
    assert!(remaining < tlv.encoded_len() + hello(Some(0)).encoded_len());
    assert!(!encoder.put_tlvs(&[tlv, hello(Some(0))]));
    assert_eq!(encoder.remaining(), remaining);
}

/// A Hello to move a neighbour's expected seqno doesn't count as the packet's Hello.
#[test]
fn unscheduled_hellos_with_no_timestamp_do_not_count_as_the_packets_hello() {
    let far = Tlv::Hello {
        seqno: Seqno::new(1),
        interval: None,
        transmit_timestamp: None,
    };

    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_tlvs(&[far.clone(), hello(Some(0))]));
    assert!(!encoder.put_tlv(&hello(Some(0))));
    assert!(encoder.put_tlv(&far));
    assert!(encoder.put_tlv(&ihu(Some((1, 2)))));

    // One with a timestamp does.
    let mut encoder = PacketEncoder::new(1400);
    assert!(encoder.put_tlv(&Tlv::Hello {
        seqno: Seqno::new(1),
        interval: None,
        transmit_timestamp: Some(0),
    }));
    assert!(!encoder.put_tlv(&hello(Some(0))));
}
