use super::*;
use crate::babel::base::Ae::{Ipv4, Ipv6, LinkLocalIpv6, V4ViaV6, Wildcard};
use TlvDecodeError::{Ignored, Malformed, Overrun, Unknown};

const P: u8 = UPDATE_FLAG_PREFIX;
const R: u8 = UPDATE_FLAG_ROUTER_ID;

const RID: u64 = 0x0123_4567_89ab_cdef;

// Parser state slots.
const ROUTER_ID: u8 = 1;
const PREFIX_IPV4: u8 = 2;
const PREFIX_IPV6: u8 = 4;
const PREFIX_V4_VIA_V6: u8 = 8;

fn interval(n: u16) -> Interval {
    Interval::new(n).unwrap()
}

fn router_id(n: u64) -> RouterId {
    RouterId::new(n).unwrap()
}

fn prefix(bytes: &[u8]) -> [u8; 16] {
    let mut prefix = [0; 16];
    prefix[..bytes.len()].copy_from_slice(bytes);
    prefix
}

fn hello(interval: Option<u16>, transmit_timestamp: Option<u32>) -> Tlv {
    Tlv::Hello {
        seqno: Seqno::new(0x0102),
        interval: interval.and_then(Interval::new),
        transmit_timestamp,
    }
}

fn ihu(ae: Ae, address: [u8; 8], origin_receive_timestamps: Option<(u32, u32)>) -> Tlv {
    Tlv::Ihu {
        ae,
        rxcost: 96,
        interval: interval(1200),
        address,
        origin_receive_timestamps,
    }
}

/// Returns an Update TLV with Interval 400 and Seqno 7.
fn update(ae: Ae, flags: u8, plen: u8, omitted: u8, metric: u16, bytes: &[u8]) -> Tlv {
    Tlv::Update {
        ae,
        flags: UpdateFlags::from_bits(flags),
        plen,
        omitted,
        interval: interval(400),
        seqno: Seqno::new(7),
        metric,
        prefix: prefix(bytes),
        nonexclusive: false,
    }
}

/// Returns a Seqno Request TLV with Seqno 0x0102, Hop Count 64, and router-id `RID`.
fn seqno_request(ae: Ae, plen: u8, bytes: &[u8]) -> Tlv {
    Tlv::SeqnoRequest {
        ae,
        plen,
        seqno: Seqno::new(0x0102),
        hop_count: NonZeroU8::new(64).unwrap(),
        router_id: router_id(RID),
        prefix: prefix(bytes),
    }
}

/// Returns a Conflict Alert TLV with Hops Away 3.
fn conflict_alert(ae: Ae, plen: u8, bytes: &[u8]) -> Tlv {
    Tlv::ConflictAlert {
        ae,
        plen,
        hops_away: NonZeroU8::new(3).unwrap(),
        prefix: prefix(bytes),
    }
}

/// Returns `tlv`, an Update TLV, marked nonexclusive.
fn nonexclusive(mut tlv: Tlv) -> Tlv {
    let Tlv::Update { nonexclusive, .. } = &mut tlv else {
        unreachable!()
    };
    *nonexclusive = true;
    tlv
}

/// Encodes a TLV into a buffer of exactly its encoded length.
fn encode_tlv(tlv: &Tlv) -> Vec<u8> {
    let mut buf = vec![0; tlv.encoded_len()];
    assert_eq!(tlv.encode(&mut buf), buf.len());
    buf
}

/// Encodes a TLV with a sub-TLV appended.
fn encode_tlv_with_sub_tlv(tlv: &Tlv, sub_tlv: &[u8]) -> Vec<u8> {
    let mut bytes = encode_tlv(tlv);
    bytes[1] += sub_tlv.len() as u8;
    bytes.extend_from_slice(sub_tlv);
    bytes
}

/// Decodes a TLV, asserting that it spans the whole input.
fn decode_tlv(mut bytes: &[u8]) -> Result<Tlv, TlvDecodeError> {
    let result = Tlv::decode(&mut bytes);
    assert!(bytes.is_empty(), "TLV should span the whole input");
    result
}

/// Returns the error for an Update TLV that is ignored but modifies the parser state.
fn update_modifier(tlv: &Tlv) -> TlvDecodeError {
    let Tlv::Update {
        ae,
        flags,
        plen,
        omitted,
        prefix,
        ..
    } = *tlv
    else {
        unreachable!()
    };
    TlvDecodeError::IgnoredStateModifying(StateModifier::Update {
        ae,
        flags,
        plen,
        omitted,
        prefix,
    })
}

/// Returns the error for a TLV that is ignored and undefines the given slots.
fn undefine(slots: u8) -> TlvDecodeError {
    TlvDecodeError::IgnoredStateModifying(StateModifier::Undefine {
        router_id: slots & ROUTER_ID != 0,
        prefix_ipv4: slots & PREFIX_IPV4 != 0,
        prefix_ipv6: slots & PREFIX_IPV6 != 0,
        prefix_v4_via_v6: slots & PREFIX_V4_VIA_V6 != 0,
    })
}

#[test]
fn wire_format() {
    #[rustfmt::skip]
    let cases: Vec<(Tlv, &[u8])> = vec![
        (Tlv::Pad1, &[0]),
        (Tlv::PadN { length: 0 }, &[1, 0]),
        (Tlv::PadN { length: 3 }, &[1, 3, 0, 0, 0]),
        (
            Tlv::AcknowledgementRequest { opaque: 0x1234, interval: interval(200) },
            &[2, 6, 0, 0, 0x12, 0x34, 0, 200],
        ),
        (Tlv::Acknowledgement { opaque: 0x1234 }, &[3, 2, 0x12, 0x34]),
        (hello(Some(400), None), &[4, 6, 0, 0, 1, 2, 1, 0x90]),
        // Interval 0 means an unscheduled Hello.
        (
            hello(None, Some(0xdead_beef)),
            &[4, 12, 0, 0, 1, 2, 0, 0, 3, 4, 0xde, 0xad, 0xbe, 0xef],
        ),
        (ihu(Wildcard, [0; 8], None), &[5, 6, 0, 0, 0, 96, 4, 0xb0]),
        (
            ihu(Wildcard, [0; 8], Some((1, 2))),
            &[5, 16, 0, 0, 0, 96, 4, 0xb0, 3, 8, 0, 0, 0, 1, 0, 0, 0, 2],
        ),
        (
            Tlv::RouterId { router_id: router_id(RID) },
            &[6, 10, 0, 0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        ),
        (
            update(Wildcard, 0, 0, 0, METRIC_INFINITY, &[]),
            &[8, 10, 0, 0, 0, 0, 1, 0x90, 0, 7, 0xff, 0xff],
        ),
        (
            update(Ipv6, P | R, 128, 0, 96, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4]),
            &[
                8, 26, 2, 0xc0, 128, 0, 1, 0x90, 0, 7, 0, 96,
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4,
            ],
        ),
        // Bits beyond Plen are left for the parser state to clear.
        (
            update(Ipv6, 0, 60, 6, 96, &[0x00, 0x3f]),
            &[8, 12, 2, 0, 60, 6, 1, 0x90, 0, 7, 0, 96, 0x00, 0x3f],
        ),
        (
            update(Ipv4, P, 24, 0, 96, &[10, 1, 2]),
            &[8, 13, 1, 0x80, 24, 0, 1, 0x90, 0, 7, 0, 96, 10, 1, 2],
        ),
        (
            update(V4ViaV6, 0, 32, 4, METRIC_INFINITY, &[]),
            &[8, 10, 4, 0, 32, 4, 1, 0x90, 0, 7, 0xff, 0xff],
        ),
        // A nonexclusive update carries a Nonexclusive sub-TLV, with no body.
        (
            nonexclusive(update(Ipv4, P, 24, 0, 96, &[10, 1, 2])),
            &[8, 15, 1, 0x80, 24, 0, 1, 0x90, 0, 7, 0, 96, 10, 1, 2, 112, 0],
        ),
        (Tlv::RouteRequest { ae: Wildcard, plen: 0, prefix: [0; 16] }, &[9, 2, 0, 0]),
        (
            Tlv::RouteRequest { ae: Ipv6, plen: 48, prefix: prefix(&[0x20, 0x01, 0x0d, 0xb8, 0, 1]) },
            &[9, 8, 2, 48, 0x20, 0x01, 0x0d, 0xb8, 0, 1],
        ),
        (
            seqno_request(Ipv4, 32, &[10, 0, 0, 1]),
            &[
                10, 18, 1, 32, 1, 2, 64, 0,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                10, 0, 0, 1,
            ],
        ),
        (
            seqno_request(Ipv6, 64, &[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2]),
            &[
                10, 22, 2, 64, 1, 2, 64, 0,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2,
            ],
        ),
        (conflict_alert(Ipv4, 32, &[10, 0, 0, 1]), &[224, 8, 1, 32, 3, 0, 10, 0, 0, 1]),
        (
            conflict_alert(Ipv6, 64, &[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2]),
            &[224, 12, 2, 64, 3, 0, 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2],
        ),
    ];

    for (tlv, bytes) in cases {
        assert_eq!(encode_tlv(&tlv), bytes, "encoding {tlv:?}");
        assert_eq!(decode_tlv(bytes), Ok(tlv));
    }
}

#[test]
fn decode_tolerates_what_it_may_ignore() {
    #[rustfmt::skip]
    let cases: Vec<(&[u8], Tlv)> = vec![
        // MBZ and Reserved fields are ignored.
        (&[1, 2, 0xff, 0xff], Tlv::PadN { length: 2 }),
        (
            &[2, 6, 0xff, 0xff, 0x12, 0x34, 0, 200],
            Tlv::AcknowledgementRequest { opaque: 0x1234, interval: interval(200) },
        ),
        // Unknown flags are ignored.
        (&[4, 6, 0x7f, 0xff, 1, 2, 1, 0x90], hello(Some(400), None)),
        (
            &[8, 10, 0, 0x3f, 0, 0, 1, 0x90, 0, 7, 0xff, 0xff],
            update(Wildcard, 0, 0, 0, METRIC_INFINITY, &[]),
        ),
        // A PadN sub-TLV in place of a Timestamp sub-TLV is ignored.
        (&[4, 12, 0, 0, 1, 2, 1, 0x90, 1, 4, 0, 0, 0, 0], hello(Some(400), None)),
        // Pad1, PadN, unknown non-mandatory, and misplaced Timestamp sub-TLVs are ignored.
        (
            &[3, 14, 0x12, 0x34, 0, 1, 1, 0, 0x7f, 0, 3, 4, 0, 0, 0, 1],
            Tlv::Acknowledgement { opaque: 0x1234 },
        ),
        // Timestamp sub-TLVs longer than expected are accepted (RFC 9616 §6.1).
        (
            &[4, 14, 0, 0, 1, 2, 1, 0x90, 3, 6, 0xde, 0xad, 0xbe, 0xef, 0, 0],
            hello(Some(400), Some(0xdead_beef)),
        ),
        (
            &[5, 18, 0, 0, 0, 96, 4, 0xb0, 3, 10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0],
            ihu(Wildcard, [0; 8], Some((1, 2))),
        ),
        // Those shorter than expected are ignored, but not the rest of the TLV.
        (
            &[4, 16, 0, 0, 1, 2, 1, 0x90, 3, 2, 0xde, 0xad, 3, 4, 0, 0, 0, 5],
            hello(Some(400), Some(5)),
        ),
        (&[5, 12, 0, 0, 0, 96, 4, 0xb0, 3, 4, 0, 0, 0, 1], ihu(Wildcard, [0; 8], None)),
        // IHU TLVs with AE 3 carry an address.
        (
            &[5, 14, 3, 0, 0, 96, 4, 0xb0, 0, 0, 0, 0, 0, 0, 0, 1],
            ihu(LinkLocalIpv6, [0, 0, 0, 0, 0, 0, 0, 1], None),
        ),
        // Requests with AE 4 are accepted, though never sent.
        (
            &[9, 5, 4, 24, 10, 1, 2],
            Tlv::RouteRequest { ae: V4ViaV6, plen: 24, prefix: prefix(&[10, 1, 2]) },
        ),
        // Bits beyond Plen in requests are cleared.
        (
            &[9, 3, 2, 4, 0xff],
            Tlv::RouteRequest { ae: Ipv6, plen: 4, prefix: prefix(&[0xf0]) },
        ),
        (
            &[
                10, 16, 2, 12, 1, 2, 64, 0,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x20, 0x1f,
            ],
            seqno_request(Ipv6, 12, &[0x20, 0x10]),
        ),
        (&[224, 6, 2, 12, 3, 0, 0x20, 0x1f], conflict_alert(Ipv6, 12, &[0x20, 0x10])),
        // The Reserved field of a Conflict Alert is ignored.
        (&[224, 8, 1, 32, 3, 0xff, 10, 0, 0, 1], conflict_alert(Ipv4, 32, &[10, 0, 0, 1])),
        // Conflict Alerts with AE 4 are accepted too, though never sent.
        (&[224, 7, 4, 24, 3, 0, 10, 1, 2], conflict_alert(V4ViaV6, 24, &[10, 1, 2])),
        // Nonexclusive sub-TLVs with a body are accepted, leaving room for one later.
        (
            &[8, 17, 1, 0x80, 24, 0, 1, 0x90, 0, 7, 0, 96, 10, 1, 2, 112, 2, 0, 0],
            nonexclusive(update(Ipv4, P, 24, 0, 96, &[10, 1, 2])),
        ),
        // Those on other TLVs are ignored.
        (&[4, 8, 0, 0, 1, 2, 1, 0x90, 112, 0], hello(Some(400), None)),
    ];

    for (bytes, tlv) in cases {
        assert_eq!(decode_tlv(bytes), Ok(tlv), "decoding {bytes:02x?}");
    }
}

#[test]
fn decode_errors() {
    let announcement = update(
        Ipv6,
        P | R,
        64,
        0,
        96,
        &[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2],
    );

    #[rustfmt::skip]
    let cases: Vec<(Vec<u8>, TlvDecodeError)> = vec![
        // Framing.
        (vec![4], Overrun),
        (vec![4, 12, 0, 0], Overrun),
        // Next Hop TLVs are not implemented.
        (vec![7, 6, 1, 0, 10, 0, 0, 1], Unknown),
        (vec![0xff, 1, 0], Unknown),

        // Malformed bodies.
        (vec![2, 4, 0, 0, 0x12, 0x34], Malformed),
        (vec![2, 6, 0, 0, 0x12, 0x34, 0, 0], Malformed),
        (vec![3, 1, 0x12], Malformed),
        (vec![4, 4, 0, 0, 1, 2], Malformed),
        // Unicast Hellos are not implemented.
        (vec![4, 6, 0x80, 0, 1, 2, 1, 0x90], Malformed),
        (vec![5, 6, 0, 0, 0, 96, 0, 0], Malformed),
        // IHU TLVs with AE other than 0 and 3 are not implemented.
        (vec![5, 10, 1, 0, 0, 96, 4, 0xb0, 10, 0, 0, 1], Malformed),
        (vec![5, 6, 3, 0, 0, 96, 4, 0xb0], Malformed),
        (vec![5, 6, 9, 0, 0, 96, 4, 0xb0], Malformed),
        (vec![9, 2, 9, 0], Malformed),
        (vec![9, 3, 0, 8, 0], Malformed),
        (vec![9, 7, 1, 33, 10, 0, 0, 1, 0], Malformed),
        (vec![9, 10, 3, 64, 0, 0, 0, 0, 0, 0, 0, 1], Malformed),
        (vec![9, 4, 2, 48, 0x20, 0x01], Malformed),
        (vec![10, 14, 0, 0, 1, 2, 64, 0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef], Malformed),
        (vec![10, 18, 1, 40, 1, 2, 64, 0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 10, 0, 0, 1], Malformed),
        (vec![10, 18, 1, 32, 1, 2, 0, 0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 10, 0, 0, 1], Malformed),
        (vec![10, 18, 1, 32, 1, 2, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1], Malformed),
        (vec![10, 18, 1, 32, 1, 2, 64, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 10, 0, 0, 1], Malformed),
        (vec![10, 16, 2, 128, 1, 2, 64, 0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x20, 0x01], Malformed),
        (vec![224, 3, 1, 32, 3], Malformed),
        (vec![224, 4, 0, 0, 3, 0], Malformed),
        (vec![224, 12, 3, 64, 3, 0, 0, 0, 0, 0, 0, 0, 0, 1], Malformed),
        (vec![224, 8, 1, 32, 0, 0, 10, 0, 0, 1], Malformed),
        (vec![224, 9, 1, 33, 3, 0, 10, 0, 0, 1, 0], Malformed),
        (vec![224, 6, 2, 48, 3, 0, 0x20, 0x01], Malformed),

        // Unknown mandatory or overrunning sub-TLVs.
        (encode_tlv_with_sub_tlv(&hello(Some(400), None), &[0x80, 0]), Ignored),
        (encode_tlv_with_sub_tlv(&hello(Some(400), None), &[1, 1]), Ignored),
        (encode_tlv_with_sub_tlv(&hello(Some(400), None), &[1]), Ignored),
        (encode_tlv_with_sub_tlv(&conflict_alert(Ipv4, 32, &[10, 0, 0, 1]), &[0x80, 0]), Ignored),

        // Ignored Router-Id TLVs still establish the router-id...
        (
            encode_tlv_with_sub_tlv(&Tlv::RouterId { router_id: router_id(RID) }, &[0x80, 0]),
            TlvDecodeError::IgnoredStateModifying(StateModifier::RouterId { router_id: router_id(RID) }),
        ),
        // ...unless they are malformed.
        (vec![6, 2, 0, 0], undefine(ROUTER_ID)),
        (vec![6, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], undefine(ROUTER_ID)),
        (vec![6, 10, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], undefine(ROUTER_ID)),

        // Ignored Update TLVs still establish the default prefix and router-id...
        (encode_tlv_with_sub_tlv(&announcement, &[0x80, 0]), update_modifier(&announcement)),
        (encode_tlv_with_sub_tlv(&announcement, &[1, 1]), update_modifier(&announcement)),
        (
            vec![8, 18, 2, P | R, 64, 0, 0, 0, 0, 7, 0, 96, 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2],
            update_modifier(&announcement),
        ),
        // ...unless they are malformed, in which case the slots they may set are undefined.
        (vec![8, 0], undefine(ROUTER_ID | PREFIX_IPV4 | PREFIX_IPV6 | PREFIX_V4_VIA_V6)),
        (vec![8, 1, 2], undefine(ROUTER_ID | PREFIX_IPV6)),
        (vec![8, 1, 4], undefine(ROUTER_ID | PREFIX_V4_VIA_V6)),
        (vec![8, 1, 9], undefine(ROUTER_ID)),
        (vec![8, 10, 9, P, 0, 0, 1, 0x90, 0, 7, 0xff, 0xff], undefine(0)),
        (vec![8, 18, 3, R, 64, 0, 1, 0x90, 0, 7, 0, 96, 0, 0, 0, 0, 0, 0, 0, 1], undefine(ROUTER_ID)),
        (vec![8, 15, 1, P, 33, 0, 1, 0x90, 0, 7, 0, 96, 10, 0, 0, 1, 0], undefine(PREFIX_IPV4)),
        (vec![8, 10, 2, P | R, 8, 2, 1, 0x90, 0, 7, 0, 96], undefine(ROUTER_ID | PREFIX_IPV6)),
        (vec![8, 11, 2, R, 64, 0, 1, 0x90, 0, 7, 0, 96, 0x20], undefine(ROUTER_ID)),
        (vec![8, 10, 0, P | R, 0, 0, 1, 0x90, 0, 7, 0, 96], undefine(ROUTER_ID)),
        (vec![8, 11, 0, 0, 8, 0, 1, 0x90, 0, 7, 0xff, 0xff, 0], undefine(0)),
    ];

    for (bytes, error) in cases {
        assert_eq!(decode_tlv(&bytes), Err(error), "decoding {bytes:02x?}");
    }
}

macro_rules! encode_panics {
    ($($name:ident: $tlv:expr => $message:literal,)*) => {$(
        #[test]
        #[should_panic(expected = $message)]
        fn $name() {
            encode_tlv(&$tlv);
        }
    )*};
}

encode_panics! {
    encode_ihu_with_nonzero_ae:
        ihu(LinkLocalIpv6, [0; 8], None) => "IHU should carry AE 0",
    encode_wildcard_update_with_finite_metric:
        update(Wildcard, 0, 0, 0, 96, &[]) => "Update with AE 0 should carry infinite metric",
    encode_update_with_ae_3:
        update(LinkLocalIpv6, 0, 0, 0, 96, &[]) => "Update should not carry AE 3",
    encode_update_with_overlarge_plen:
        update(Ipv4, 0, 33, 0, 96, &[]) => "Update should not carry overlarge Plen",
    encode_update_omitting_too_much:
        update(Ipv6, 0, 8, 2, 96, &[]) => "Update should not omit more octets",
    encode_route_request_with_ae_4:
        Tlv::RouteRequest { ae: V4ViaV6, plen: 0, prefix: [0; 16] }
            => "Route Request should not carry AE 3 or 4",
    encode_route_request_with_overlarge_plen:
        Tlv::RouteRequest { ae: Wildcard, plen: 8, prefix: [0; 16] }
            => "Route Request should not carry overlarge Plen",
    encode_route_request_with_unmasked_prefix:
        Tlv::RouteRequest { ae: Ipv6, plen: 4, prefix: prefix(&[0xff]) }
            => "Route Request should not carry a prefix with bits set beyond Plen",
    encode_seqno_request_with_ae_0:
        seqno_request(Wildcard, 0, &[]) => "Seqno Request should not carry AE 0, 3, or 4",
    encode_seqno_request_with_overlarge_plen:
        seqno_request(Ipv6, 129, &[]) => "Seqno Request should not carry overlarge Plen",
    encode_seqno_request_with_unmasked_prefix:
        seqno_request(Ipv6, 12, &[0x20, 0x1f])
            => "Seqno Request should not carry a prefix with bits set beyond Plen",
    encode_conflict_alert_with_ae_4:
        conflict_alert(V4ViaV6, 24, &[10, 1, 2]) => "Conflict Alert should not carry AE 0, 3, or 4",
    encode_conflict_alert_with_overlarge_plen:
        conflict_alert(Ipv4, 33, &[]) => "Conflict Alert should not carry overlarge Plen",
    encode_conflict_alert_with_unmasked_prefix:
        conflict_alert(Ipv6, 12, &[0x20, 0x1f])
            => "Conflict Alert should not carry a prefix with bits set beyond Plen",
}
