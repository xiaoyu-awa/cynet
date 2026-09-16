use std::num::NonZeroU8;

use bytes::{Buf, BufMut};
use strum::{EnumDiscriminants, FromRepr};

use crate::babel::base::{AddressEncoding, Interval, RouterId, Seqno};

const HELLO_FLAG_UNICAST: u16 = 0x8000;

bitflags::bitflags! {
    #[derive(Clone, Debug, Copy, Eq, PartialEq)]
    pub struct UpdateFlags: u8 {
        const PREFIX = 0x80;
        const ROUTER_ID = 0x40;
    }
}

const METRIC_INFINITE: u16 = 0xffff;

const MANDATORY_BIT: u8 = 0x80;

/// A TLV contained in a Babel packet.
///
/// Next Hop TLVs are irrelevant for this implementation.
#[derive(Clone, Debug, EnumDiscriminants, Eq, PartialEq)]
#[repr(u8)]
#[strum_discriminants(derive(FromRepr), name(TlvKind), vis(pub(self)))]
pub enum Tlv {
    Pad1 = 0,
    PadN {
        /// The length of the body in octets, exclusive of the Type and Length fields.
        length: u8,
    } = 1,
    AcknowledgementRequest {
        /// An arbitrary value that will be echoed in the receiver's Acknowledgment TLV.
        opaque: u16,
        /// A time interval in centiseconds after which the sender will assume that this packet has been lost. This MUST NOT be 0. The receiver MUST send an Acknowledgment TLV before this time has elapsed (with a margin allowing for propagation time).
        interval: Interval,
    } = 2,
    Acknowledgement {
        /// Set to the Opaque value of the Acknowledgment Request that prompted this Acknowledgment.
        opaque: u16,
    } = 3,
    /// A Hello TLV.
    ///
    /// Unicast Hellos are irrelevant for this implementation. The Flags field is send as 0. Hello TLVs with the Unicast flag set are silently ignored.
    Hello {
        /// The sending node's outgoing Multicast Hello seqno.
        seqno: Seqno,
        /// If `Some`, this is an upper bound, expressed in centiseconds, on the time after which the sending node will send a new scheduled Hello TLV with the same setting of the Unicast flag. If this is `None`, then this Hello represents an unscheduled Hello and doesn't carry any new information about times at which Hellos are sent.
        interval: Option<Interval>,
        /// Field within an optional Timestamp sub-TLV.
        ///
        /// The time at which the packet containing this sub-TLV was sent, according to the sender's clock.
        transmit_timestamp: Option<u32>,
    } = 4,
    /// An IHU TLV.
    ///
    /// The AE field is sent as 0. IHU TLVs with a nonzero value in the AE field are silently ignored.
    Ihu {
        /// The rxcost according to the sending node of the interface whose address is specified in the Address field. The value FFFF hexadecimal (infinity) indicates that this interface is unreachable.
        rxcost: u16,
        /// An upper bound, expressed in centiseconds, on the time after which the sending node will send a new IHU; this MUST NOT be 0. The receiving node will use this value in order to compute a hold time for this symmetric association.
        interval: Interval,
        /// Fields within an optional Timestamp sub-TLV.
        ///
        /// Origin Timestamp: A copy of the Transmit Timestamp of the last Timestamp sub-TLV contained in a Hello TLV received from the node to which the enclosing IHU TLV applies.
        ///
        /// Receive Timestamp: The time, according to the sender's clock, at which the last timestamped Hello TLV was received from the node to which the enclosing IHU TLV applies.
        origin_receive_timestamps: Option<(u32, u32)>,
    } = 5,
    RouterId {
        /// The router-id for routes advertised in subsequent Update TLVs. This MUST NOT consist of all zeroes or all ones.
        router_id: RouterId,
    } = 6,
    Update {
        /// The encoding of the Prefix field.
        ae: AddressEncoding,
        /// The individual bits of this field specify special handling of this TLV (see below).
        ///
        /// P (Prefix) flag (80 hexadecimal): if set, then this Update TLV establishes a new default prefix for subsequent Update TLVs with a matching address encoding within the same packet, even if this TLV is otherwise ignored due to an unknown mandatory sub-TLV;
        ///
        /// R (Router-Id) flag (40 hexadecimal): if set, then this TLV establishes a new default router-id for this TLV and subsequent Update TLVs in the same packet, even if this TLV is otherwise ignored due to an unknown mandatory sub-TLV. This router-id is computed from the first address of the advertised prefix as follows:
        ///
        /// - if the length of the address is 8 octets or more, then the new router-id is taken from the 8 last octets of the address;
        /// - if the length of the address is smaller than 8 octets, then the new router-id consists of the required number of zero octets followed by the address, i.e., the address is stored on the right of the router-id. For example, for an IPv4 address, the router-id consists of 4 octets of zeroes followed by the IPv4 address.
        flags: UpdateFlags,
        /// The length in bits of the advertised prefix. If AE is 3 (link-local IPv6), the Omitted field MUST be 0.
        plen: u8,
        /// The number of octets that have been omitted at the beginning of the advertised prefix and that should be taken from a preceding Update TLV in the same address family with the Prefix flag set.
        omitted: u8,
        /// An upper bound, expressed in centiseconds, on the time after which the sending node will send a new update for this prefix. This MUST NOT be 0. The receiving node will use this value to compute a hold time for the route table entry. The value FFFF hexadecimal (infinity) expresses that this announcement will not be repeated unless a request is received (Section 3.8.2.3).
        interval: u16,
        /// The originator's sequence number for this update.
        seqno: Seqno,
        /// The sender's metric for this route. The value FFFF hexadecimal (infinity) means that this is a route retraction.
        metric: u16,
        /// The prefix being advertised. This field's size is (Plen/8 - Omitted) rounded upwards.
        prefix: [u8; 16],
    } = 8,
    RouteRequest {
        /// The encoding of the Prefix field. The value 0 specifies that this is a request for a full route table dump (a wildcard request).
        ae: AddressEncoding,
        /// The length in bits of the requested prefix.
        plen: u8,
        /// The prefix being requested. This field's size is Plen/8 rounded upwards.
        prefix: [u8; 16],
    } = 9,
    SeqnoRequest {
        /// The encoding of the Prefix field. This MUST NOT be 0.
        ae: AddressEncoding,
        /// The length in bits of the requested prefix.
        plen: u8,
        /// The sequence number that is being requested.
        seqno: Seqno,
        /// The maximum number of times that this TLV may be forwarded, plus 1. This MUST NOT be 0.
        hop_count: NonZeroU8,
        /// The Router-Id that is being requested. This MUST NOT consist of all zeroes or all ones.
        router_id: RouterId,
        /// The prefix being requested. This field's size is Plen/8 rounded upwards.
        prefix: [u8; 16],
    } = 10,
}

fn octets(plen: u8) -> usize {
    (plen as usize).div_ceil(8)
}

impl Tlv {
    pub fn encoded_len(&self) -> usize {
        match *self {
            Self::Pad1 => 1,
            Self::PadN { length } => 2 + length as usize,
            Self::AcknowledgementRequest { .. } => 8,
            Self::Acknowledgement { .. } => 4,
            Self::Hello {
                transmit_timestamp, ..
            } => 8 + transmit_timestamp.map_or(0, |_| 4),
            Self::Ihu {
                origin_receive_timestamps,
                ..
            } => 8 + origin_receive_timestamps.map_or(0, |_| 8),
            Self::RouterId { .. } => 12,
            Self::Update { plen, omitted, .. } => 12 + octets(plen).strict_sub(omitted as usize),
            Self::RouteRequest { plen, .. } => 4 + octets(plen),
            Self::SeqnoRequest { plen, .. } => 16 + octets(plen),
        }
    }

    pub fn encode(&self, buf: &mut [u8]) -> usize {
        buf[0] = TlvKind::from(self) as u8; // Type

        if *self == Self::Pad1 {
            return 1;
        }

        let len = encode_payload(self, &mut buf[2..]);

        debug_assert!(len < 256);
        debug_assert_eq!(len + 2, self.encoded_len());

        buf[1] = len as u8; // Length
        len + 2
    }

    pub fn decode(buf: &mut &[u8]) -> Result<Tlv, TlvDecodeError> {
        decode(buf)
    }
}

fn encode_payload(tlv: &Tlv, mut buf: &mut [u8]) -> usize {
    let init_buf_len = buf.len();

    match *tlv {
        Tlv::Pad1 => unreachable!(),
        Tlv::PadN { length } => buf.put_bytes(0, length as usize), // MBZ
        Tlv::AcknowledgementRequest { opaque, interval } => {
            buf.put_u16(0); // Reserved
            buf.put_u16(opaque);
            buf.put_u16(interval.get());
        }
        Tlv::Acknowledgement { opaque } => buf.put_u16(opaque),
        Tlv::Hello {
            seqno,
            interval,
            transmit_timestamp,
        } => {
            buf.put_u16(0); // Flags
            buf.put_u16(seqno.get());
            buf.put_u16(interval.map_or(0, |i| i.get()));

            if let Some(transmit_timestamp) = transmit_timestamp {
                buf.put_u8(SubTlvKind::Timestamp as u8); // Type
                buf.put_u8(4); // Length
                buf.put_u32(transmit_timestamp);
            }
        }
        Tlv::Ihu {
            rxcost,
            interval,
            origin_receive_timestamps,
        } => {
            buf.put_u8(AddressEncoding::Wildcard as u8); // AE
            buf.put_u8(0); // Reserved
            buf.put_u16(rxcost);
            buf.put_u16(interval.get());

            if let Some((origin_timestamp, receive_timestamp)) = origin_receive_timestamps {
                buf.put_u8(SubTlvKind::Timestamp as u8); // Type
                buf.put_u8(8); // Length
                buf.put_u32(origin_timestamp);
                buf.put_u32(receive_timestamp);
            }
        }
        Tlv::RouterId { router_id } => {
            buf.put_u16(0); // Reserved
            buf.put_u64(router_id.get());
        }
        Tlv::Update {
            ae,
            flags,
            plen,
            omitted,
            interval,
            seqno,
            metric,
            prefix,
        } => {
            match ae {
                AddressEncoding::Wildcard => {
                    assert!(
                        metric == METRIC_INFINITE && plen == 0 && omitted == 0,
                        "Update with AE 0 should carry infinite metric, plen=0, and omitted=0"
                    );
                }
                AddressEncoding::Ipv4 | AddressEncoding::Ipv6 => {
                    assert!(
                        verify_plen(ae, plen),
                        "Update with AE 1 or 2 should not carry overlarge plen"
                    );
                }
                AddressEncoding::LinkLocalIpv6 => {
                    panic!("Update should not carry AE 3");
                }
            }

            assert!(interval != 0, "Update should carry nonzero interval");

            buf.put_u8(ae as u8);
            buf.put_u8(flags.bits());
            buf.put_u8(plen);
            buf.put_u8(omitted);
            buf.put_u16(interval);
            buf.put_u16(seqno.get());
            buf.put_u16(metric);
            buf.put_slice(&prefix[omitted as usize..octets(plen)]);
        }
        Tlv::RouteRequest { ae, plen, prefix } => {
            assert!(
                ae != AddressEncoding::LinkLocalIpv6,
                "Route Request should not carry AE 3"
            );

            assert!(
                verify_plen(ae, plen),
                "Route Request should not carry overlarge plen"
            );

            buf.put_u8(ae as u8);
            buf.put_u8(plen);
            buf.put_slice(&prefix[..octets(plen)]);
        }
        Tlv::SeqnoRequest {
            ae,
            plen,
            seqno,
            hop_count,
            router_id,
            prefix,
        } => {
            assert!(
                ae != AddressEncoding::Wildcard && ae != AddressEncoding::LinkLocalIpv6,
                "Seqno Request should not carry AE 0 or 3"
            );

            assert!(
                verify_plen(ae, plen),
                "Seqno Request should not carry overlarge plen"
            );

            buf.put_u8(ae as u8);
            buf.put_u8(plen);
            buf.put_u16(seqno.get());
            buf.put_u8(hop_count.get());
            buf.put_u8(0); // Reserved
            buf.put_u64(router_id.get());
            buf.put_slice(&prefix[..octets(plen)]);
        }
    }

    init_buf_len - buf.len()
}

fn verify_plen(ae: AddressEncoding, plen: u8) -> bool {
    let plen_max = match ae {
        AddressEncoding::Wildcard => 0,
        AddressEncoding::Ipv4 => 32,
        AddressEncoding::Ipv6 => 128,
        AddressEncoding::LinkLocalIpv6 => unreachable!(),
    };
    plen <= plen_max
}

fn decode(buf: &mut &[u8]) -> Result<Tlv, TlvDecodeError> {
    let kind = buf.try_get_u8().map_err(|_| TlvDecodeError::Malformed)?;

    if kind == TlvKind::Pad1 as u8 {
        return Ok(Tlv::Pad1);
    }

    let len = buf.try_get_u8().map_err(|_| TlvDecodeError::Malformed)?;

    let Some((payload, rem)) = buf.split_at_checked(len as usize) else {
        // Malformed TLV running past the end. Skip to the end.
        *buf = &[];
        return Err(TlvDecodeError::Malformed);
    };
    *buf = rem;

    // Shadow it so we can never use the wrong slice.
    let mut buf = payload;

    let Some(kind) = TlvKind::from_repr(kind) else {
        return Err(TlvDecodeError::Unknown);
    };

    let mut tlv = match kind {
        TlvKind::RouterId => {
            let mut decode = || {
                let _reserved = buf.try_get_u16().ok()?;
                let router_id = buf.try_get_u64().ok()?;

                Some(Tlv::RouterId {
                    router_id: RouterId::new(router_id)?,
                })
            };

            // When the payload fails to decode, undefine the router-id slot.
            decode().ok_or(TlvDecodeError::MalformedStateUpdate(StateSlots {
                router_id: true,
                prefix_ipv4: false,
                prefix_ipv6: false,
            }))?
        }
        TlvKind::Update => {
            let mut decode = || {
                // When AE is unavailable, undefine all slots.
                let mut slots = StateSlots {
                    router_id: true,
                    prefix_ipv4: true,
                    prefix_ipv6: true,
                };

                let ae = buf.try_get_u8().map_err(|_| slots)?;
                let ae = AddressEncoding::new(ae);

                // When Flags is unavailable, undefine the router-id slot
                // and the default prefix slot (if any) specified by the AE.
                slots.prefix_ipv4 = ae == Some(AddressEncoding::Ipv4);
                slots.prefix_ipv6 = ae == Some(AddressEncoding::Ipv6);

                let flags = buf.try_get_u8().map_err(|_| slots)?;
                let flags = UpdateFlags::from_bits_retain(flags);

                // When AE is unknown or the payload fails to decode, undefine
                // the router-id slot if the Router-Id flag is set, and the default
                // prefix slot (if any) specified by the AE if the Prefix flag is set.
                if !flags.contains(UpdateFlags::ROUTER_ID) {
                    slots.router_id = false;
                }

                if !flags.contains(UpdateFlags::PREFIX) {
                    slots.prefix_ipv4 = false;
                    slots.prefix_ipv6 = false;
                }

                let ae = ae.ok_or(slots)?;
                decode_update_payload(ae, flags, &mut buf).ok_or(slots)
            };

            let tlv = decode().map_err(TlvDecodeError::MalformedStateUpdate)?;

            // If the interval is zero, ignore the Update TLV
            // but still allow it to update the parser state.
            if matches!(tlv, Tlv::Update { interval: 0, .. }) {
                return Err(TlvDecodeError::Ignored(tlv));
            }

            tlv
        }
        _ => decode_stateless_payload(kind, &mut buf).ok_or(TlvDecodeError::Malformed)?,
    };

    while !buf.is_empty() {
        if decode_sub_tlv(&mut tlv, &mut buf) == Err(SubTlvDecodeError::UnknownMandatory) {
            return Err(TlvDecodeError::Ignored(tlv));
        }
    }

    Ok(tlv)
}

fn decode_update_payload(ae: AddressEncoding, flags: UpdateFlags, buf: &mut &[u8]) -> Option<Tlv> {
    let plen = buf.try_get_u8().ok()?;
    let omitted = buf.try_get_u8().ok()?;
    let interval = buf.try_get_u16().ok()?;
    let seqno = buf.try_get_u16().ok()?;
    let metric = buf.try_get_u16().ok()?;

    let mut prefix = [0; 16];

    match ae {
        AddressEncoding::Wildcard => {
            if metric != METRIC_INFINITE || plen != 0 || omitted != 0 {
                return None;
            }
        }
        AddressEncoding::Ipv4 | AddressEncoding::Ipv6 => {
            if !verify_plen(ae, plen) {
                return None;
            }

            let omitted = omitted as usize;
            let plen_octets = octets(plen);

            if omitted > plen_octets {
                return None;
            }

            let slice = &mut prefix[omitted..plen_octets];
            buf.try_copy_to_slice(slice).ok()?;

            // Don't clear the low-order bits here, but only
            // after the omitted octets are filled in.
        }
        AddressEncoding::LinkLocalIpv6 => return None,
    }

    Some(Tlv::Update {
        ae,
        flags,
        plen,
        omitted,
        interval,
        seqno: Seqno::new(seqno),
        metric,
        prefix,
    })
}

fn decode_stateless_payload(kind: TlvKind, buf: &mut &[u8]) -> Option<Tlv> {
    Some(match kind {
        TlvKind::Pad1 => unreachable!(),
        TlvKind::PadN => Tlv::PadN {
            length: buf.len() as u8,
        },
        TlvKind::AcknowledgementRequest => {
            let _reserved = buf.try_get_u16().ok()?;
            let opaque = buf.try_get_u16().ok()?;
            let interval = buf.try_get_u16().ok()?;

            Tlv::AcknowledgementRequest {
                opaque,
                interval: Interval::new(interval)?,
            }
        }
        TlvKind::Acknowledgement => {
            let opaque = buf.try_get_u16().ok()?;

            Tlv::Acknowledgement { opaque }
        }
        TlvKind::Hello => {
            let flags = buf.try_get_u16().ok()?;
            let seqno = buf.try_get_u16().ok()?;
            let interval = buf.try_get_u16().ok()?;

            if flags & HELLO_FLAG_UNICAST != 0 {
                return None;
            }

            Tlv::Hello {
                seqno: Seqno::new(seqno),
                interval: Interval::new(interval),
                transmit_timestamp: None,
            }
        }
        TlvKind::Ihu => {
            let ae = buf.try_get_u8().ok()?;
            let _reserved = buf.try_get_u8().ok()?;
            let rxcost = buf.try_get_u16().ok()?;
            let interval = buf.try_get_u16().ok()?;

            if ae != AddressEncoding::Wildcard as u8 {
                return None;
            }

            Tlv::Ihu {
                rxcost,
                interval: Interval::new(interval)?,
                origin_receive_timestamps: None,
            }
        }
        TlvKind::RouterId | TlvKind::Update => unreachable!(),
        TlvKind::RouteRequest => {
            let ae = buf.try_get_u8().ok()?;
            let plen = buf.try_get_u8().ok()?;

            let ae = AddressEncoding::new(ae)?;

            if ae == AddressEncoding::LinkLocalIpv6 {
                return None;
            }

            if !verify_plen(ae, plen) {
                return None;
            }

            let mut prefix = [0; 16];
            buf.try_copy_to_slice(&mut prefix[..octets(plen)]).ok()?;

            Tlv::RouteRequest { ae, plen, prefix }
        }
        TlvKind::SeqnoRequest => {
            let ae = buf.try_get_u8().ok()?;
            let plen = buf.try_get_u8().ok()?;
            let seqno = buf.try_get_u16().ok()?;
            let hop_count = buf.try_get_u8().ok()?;
            let _reserved = buf.try_get_u8().ok()?;
            let router_id = buf.try_get_u64().ok()?;

            let ae = AddressEncoding::new(ae)?;

            if ae == AddressEncoding::Wildcard || ae == AddressEncoding::LinkLocalIpv6 {
                return None;
            }

            if !verify_plen(ae, plen) {
                return None;
            }

            let mut prefix = [0; 16];
            buf.try_copy_to_slice(&mut prefix[..octets(plen)]).ok();

            Tlv::SeqnoRequest {
                ae,
                plen,
                seqno: Seqno::new(seqno),
                hop_count: NonZeroU8::new(hop_count)?,
                router_id: RouterId::new(router_id)?,
                prefix,
            }
        }
    })
}

/// A set of parser state slots.
#[derive(Clone, Copy, Debug)]
pub struct StateSlots {
    /// Whether the router-id slot is included.
    pub router_id: bool,
    /// Whether the IPv4 default prefix slot is included.
    pub prefix_ipv4: bool,
    /// Whether the IPv6 default prefix slot is included.
    pub prefix_ipv6: bool,
}

/// An error occurred when decoding a TLV.
#[derive(Clone, Debug)]
pub enum TlvDecodeError {
    /// The TLV is malformed.
    Malformed,
    /// The TLV is malformed and undefines the named parser state slots.
    MalformedStateUpdate(StateSlots),
    /// The TLV has an unknown type.
    Unknown,
    /// The TLV is ignored due to an unknown mandatory sub-TLV, a sub-TLV
    /// overrunning the TLV boundary, or the interval field being zero
    /// in an Update TLV, but may still update the parser state.
    Ignored(Tlv),
}

fn decode_sub_tlv(tlv: &mut Tlv, buf: &mut &[u8]) -> Result<(), SubTlvDecodeError> {
    let kind = buf.try_get_u8().map_err(|_| SubTlvDecodeError::Malformed)?;

    if kind == SubTlvKind::Pad1 as u8 {
        return Ok(());
    }

    let len = buf.try_get_u8().map_err(|_| SubTlvDecodeError::Malformed)?;

    let Some((payload, rem)) = buf.split_at_checked(len as usize) else {
        // Malformed sub-TLV running past the end. Skip to the end.
        *buf = &[];
        return Err(SubTlvDecodeError::Malformed);
    };
    *buf = rem;

    // Shadow it so we can never use the wrong slice.
    let mut buf = payload;

    if kind & MANDATORY_BIT != 0 {
        return Err(SubTlvDecodeError::UnknownMandatory);
    }

    let Some(kind) = SubTlvKind::from_repr(kind) else {
        return Err(SubTlvDecodeError::Unknown);
    };

    if kind == SubTlvKind::Timestamp {
        decode_timestamp_payload(tlv, &mut buf).ok_or(SubTlvDecodeError::Malformed)?;
    }

    Ok(())
}

fn decode_timestamp_payload(tlv: &mut Tlv, buf: &mut &[u8]) -> Option<()> {
    match tlv {
        Tlv::Hello {
            transmit_timestamp, ..
        } => {
            let t = buf.try_get_u32().ok()?;
            *transmit_timestamp = Some(t);
        }
        Tlv::Ihu {
            origin_receive_timestamps,
            ..
        } => {
            let t1 = buf.try_get_u32().ok()?;
            let t2 = buf.try_get_u32().ok()?;
            *origin_receive_timestamps = Some((t1, t2));
        }
        _ => return None,
    };

    Some(())
}

#[derive(Clone, Copy, Debug, Eq, FromRepr, PartialEq)]
#[repr(u8)]
enum SubTlvKind {
    Pad1 = 0,
    PadN = 1,
    Timestamp = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubTlvDecodeError {
    Malformed,
    UnknownMandatory,
    Unknown,
}
