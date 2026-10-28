#[cfg(test)]
mod tests;

use std::num::NonZeroU8;

use bytes::{Buf, BufMut};
use strum::{EnumDiscriminants, FromRepr};

use crate::babel::base::{Ae, Interval, METRIC_INFINITY, RouterId, Seqno};

const HELLO_FLAG_UNICAST: u16 = 0x8000;

const UPDATE_FLAG_PREFIX: u8 = 0x80;
const UPDATE_FLAG_ROUTER_ID: u8 = 0x40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateFlags {
    pub prefix: bool,
    pub router_id: bool,
}

impl UpdateFlags {
    pub fn from_bits(n: u8) -> Self {
        Self {
            prefix: n & UPDATE_FLAG_PREFIX != 0,
            router_id: n & UPDATE_FLAG_ROUTER_ID != 0,
        }
    }

    pub fn bits(self) -> u8 {
        self.prefix as u8 * UPDATE_FLAG_PREFIX + self.router_id as u8 * UPDATE_FLAG_ROUTER_ID
    }
}

const MANDATORY_BIT: u8 = 0x80;

/// A TLV contained in a Babel packet.
///
/// For this implementation, all links are point-to-point, so there is only one next hop over each link. There is no need for a Next Hop TLV when we use IPv6 exclusively for all control traffic and AE 4 (v4-via-v6) for IPv4 routes, hence the following treatment.
///
/// Next Hop TLVs are never sent and are silently ignored on reception.
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
    /// Unicast Hellos are irrelevant for this implementation. The Flags field is sent as 0. Hello TLVs with the Unicast flag set are silently ignored.
    Hello {
        /// The sending node's outgoing Hello seqno.
        seqno: Seqno,
        /// If `Some`, this is an upper bound, expressed in centiseconds, on the time after which the sending node will send a new scheduled Hello TLV with the same setting of the Unicast flag. If this is `None`, then this Hello represents an unscheduled Hello and doesn't carry any new information about times at which Hellos are sent.
        interval: Option<Interval>,
        /// Field within an optional Timestamp sub-TLV.
        ///
        /// The time at which the packet containing this sub-TLV was sent, according to the sender's clock.
        transmit_timestamp: Option<u32>,
    } = 4,
    Ihu {
        /// The encoding of the Address field. This should be 1 or 3 in most cases. As an optimisation, it MAY be 0 if the TLV is sent to a unicast address, if the association is over a point-to-point link, or when bidirectional reachability is ascertained by means outside of the Babel protocol.
        ///
        /// For this implementation, this should only be 0 or 3. It must be sent as 0. IHU TLVs with an AE other than 0 and 3 are silently ignored.
        ae: Ae,
        /// The rxcost according to the sending node of the interface whose address is specified in the Address field. The value FFFF hexadecimal (infinity) indicates that this interface is unreachable.
        rxcost: u16,
        /// An upper bound, expressed in centiseconds, on the time after which the sending node will send a new IHU; this MUST NOT be 0. The receiving node will use this value in order to compute a hold time for this symmetric association.
        interval: Interval,
        /// The address of the destination node, in the format specified by the AE field. Address compression is not allowed.
        address: [u8; 8],
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
        ae: Ae,
        /// The individual bits of this field specify special handling of this TLV (see below).
        ///
        /// P (Prefix) flag (80 hexadecimal): if set, then this Update TLV establishes a new default prefix for subsequent Update TLVs with a matching address encoding within the same packet, even if this TLV is otherwise ignored due to an unknown mandatory sub-TLV;
        ///
        /// R (Router-Id) flag (40 hexadecimal): if set, then this TLV establishes a new default router-id for this TLV and subsequent Update TLVs in the same packet, even if this TLV is otherwise ignored due to an unknown mandatory sub-TLV. This router-id is computed from the first address of the advertised prefix as follows:
        ///
        /// - if the length of the address is 8 octets or more, then the new router-id is taken from the 8 last octets of the address;
        /// - if the length of the address is smaller than 8 octets, then the new router-id consists of the required number of zero octets followed by the address, i.e., the address is stored on the right of the router-id. For example, for an IPv4 address, the router-id consists of 4 octets of zeroes followed by the IPv4 address.
        flags: UpdateFlags,
        /// The length in bits of the advertised prefix.
        plen: u8,
        /// The number of octets that have been omitted at the beginning of the advertised prefix and that should be taken from a preceding Update TLV in the same address family with the Prefix flag set.
        omitted: u8,
        /// An upper bound, expressed in centiseconds, on the time after which the sending node will send a new update for this prefix. This MUST NOT be 0. The receiving node will use this value to compute a hold time for the route table entry. The value FFFF hexadecimal (infinity) expresses that this announcement will not be repeated unless a request is received (Section 3.8.2.3).
        interval: Interval,
        /// The originator's sequence number for this update.
        seqno: Seqno,
        /// The sender's metric for this route. The value FFFF hexadecimal (infinity) means that this is a route retraction.
        metric: u16,
        /// The prefix being advertised. This field's size is (Plen/8 - Omitted) rounded upwards.
        ///
        /// This field's value starts from index 0 of the array.
        prefix: [u8; 16],
    } = 8,
    RouteRequest {
        /// The encoding of the Prefix field. The value 0 specifies that this is a request for a full route table dump (a wildcard request).
        ae: Ae,
        /// The length in bits of the requested prefix.
        plen: u8,
        /// The prefix being requested. This field's size is Plen/8 rounded upwards.
        ///
        /// This field's value starts from index 0 of the array. Any bits beyond Plen must be cleared, and are cleared on decoding.
        prefix: [u8; 16],
    } = 9,
    SeqnoRequest {
        /// The encoding of the Prefix field. This MUST NOT be 0.
        ae: Ae,
        /// The length in bits of the requested prefix.
        plen: u8,
        /// The sequence number that is being requested.
        seqno: Seqno,
        /// The maximum number of times that this TLV may be forwarded, plus 1. This MUST NOT be 0.
        hop_count: NonZeroU8,
        /// The Router-Id that is being requested. This MUST NOT consist of all zeroes or all ones.
        router_id: RouterId,
        /// The prefix being requested. This field's size is Plen/8 rounded upwards.
        ///
        /// This field's value starts from index 0 of the array. Any bits beyond Plen must be cleared, and are cleared on decoding.
        prefix: [u8; 16],
    } = 10,
}

/// Returns the smallest number of octets that are enough to hold a prefix of length `plen`.
pub(super) fn octets(plen: u8) -> usize {
    (plen as usize).div_ceil(8)
}

/// Clears the bits of a prefix beyond `plen`.
pub(super) fn mask_prefix(mut prefix: [u8; 16], plen: u8) -> [u8; 16] {
    let plen_octets = octets(plen);

    prefix[plen_octets..].fill(0);
    if !plen.is_multiple_of(8) {
        prefix[plen_octets - 1] &= 0xff << (8 - plen % 8);
    }

    prefix
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
            } => 8 + transmit_timestamp.map_or(0, |_| 6),
            Self::Ihu {
                origin_receive_timestamps,
                ..
            } => 8 + origin_receive_timestamps.map_or(0, |_| 10),
            Self::RouterId { .. } => 12,
            Self::Update { plen, omitted, .. } => {
                12 + octets(plen).saturating_sub(omitted as usize)
            }
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

    pub fn decode(buf: &mut &[u8]) -> Result<Self, TlvDecodeError> {
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
            ae,
            rxcost,
            interval,
            address: _,
            origin_receive_timestamps,
        } => {
            assert!(ae == Ae::Wildcard, "IHU should carry AE 0");

            buf.put_u8(ae as u8); // AE
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
                Ae::Wildcard => {
                    assert!(
                        metric == METRIC_INFINITY && plen == 0 && omitted == 0,
                        "Update with AE 0 should carry infinite metric, Plen=0, and Omitted=0"
                    );
                }
                Ae::Ipv4 | Ae::Ipv6 | Ae::V4ViaV6 => {
                    assert!(
                        plen <= ae.max_plen(),
                        "Update should not carry overlarge Plen"
                    );

                    assert!(
                        omitted as usize <= octets(plen),
                        "Update should not omit more octets than enough to hold the prefix"
                    );
                }
                Ae::LinkLocalIpv6 => {
                    panic!("Update should not carry AE 3");
                }
            }

            buf.put_u8(ae as u8);
            buf.put_u8(flags.bits());
            buf.put_u8(plen);
            buf.put_u8(omitted);
            buf.put_u16(interval.get());
            buf.put_u16(seqno.get());
            buf.put_u16(metric);
            buf.put_slice(&prefix[..octets(plen) - omitted as usize]);
        }
        Tlv::RouteRequest { ae, plen, prefix } => {
            assert!(
                ae != Ae::LinkLocalIpv6 && ae != Ae::V4ViaV6,
                "Route Request should not carry AE 3 or 4"
            );

            assert!(
                plen <= ae.max_plen(),
                "Route Request should not carry overlarge Plen"
            );

            assert!(
                prefix == mask_prefix(prefix, plen),
                "Route Request should not carry a prefix with bits set beyond Plen"
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
                ae != Ae::Wildcard && ae != Ae::LinkLocalIpv6 && ae != Ae::V4ViaV6,
                "Seqno Request should not carry AE 0, 3, or 4"
            );

            assert!(
                plen <= ae.max_plen(),
                "Seqno Request should not carry overlarge Plen"
            );

            assert!(
                prefix == mask_prefix(prefix, plen),
                "Seqno Request should not carry a prefix with bits set beyond Plen"
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

fn decode(buf: &mut &[u8]) -> Result<Tlv, TlvDecodeError> {
    let kind = buf.try_get_u8().map_err(|_| TlvDecodeError::Overrun)?;

    if kind == TlvKind::Pad1 as u8 {
        return Ok(Tlv::Pad1);
    }

    let len = buf.try_get_u8().map_err(|_| TlvDecodeError::Overrun)?;

    let Some((payload, rem)) = buf.split_at_checked(len as usize) else {
        // Payload overruns the buffer. Skip to the end.
        *buf = &[];
        return Err(TlvDecodeError::Overrun);
    };
    *buf = rem;

    // Shadow it so we can never use the wrong slice.
    let mut buf = payload;

    let Some(kind) = TlvKind::from_repr(kind) else {
        return Err(TlvDecodeError::Unknown);
    };

    let mut tlv = match kind {
        TlvKind::RouterId => {
            let mut decode_body = || {
                let _reserved = buf.try_get_u16().ok()?;
                let router_id = buf.try_get_u64().ok()?;

                Some(Tlv::RouterId {
                    router_id: RouterId::new(router_id)?,
                })
            };

            // When the body is malformed, undefine the router-id slot.
            decode_body().ok_or(TlvDecodeError::IgnoredStateModifying(
                StateModifier::Undefine {
                    router_id: true,
                    prefix_ipv4: false,
                    prefix_ipv6: false,
                    prefix_v4_via_v6: false,
                },
            ))?
        }
        TlvKind::Update => {
            decode_update_body(&mut buf).map_err(TlvDecodeError::IgnoredStateModifying)?
        }
        _ => decode_state_irrelevant_body(kind, &mut buf).ok_or(TlvDecodeError::Malformed)?,
    };

    while !buf.is_empty() {
        if let Err(SubTlvDecodeError::Overrun | SubTlvDecodeError::UnknownMandatory) =
            decode_sub_tlv(&mut tlv, &mut buf)
        {
            return Err(match tlv {
                Tlv::RouterId { router_id } => {
                    TlvDecodeError::IgnoredStateModifying(StateModifier::RouterId { router_id })
                }
                Tlv::Update {
                    ae,
                    flags,
                    plen,
                    omitted,
                    prefix,
                    ..
                } => TlvDecodeError::IgnoredStateModifying(StateModifier::Update {
                    ae,
                    flags,
                    plen,
                    omitted,
                    prefix,
                }),
                _ => TlvDecodeError::Ignored,
            });
        }
    }

    Ok(tlv)
}

fn decode_update_body(buf: &mut &[u8]) -> Result<Tlv, StateModifier> {
    // When AE is unavailable, undefine all slots.
    let ae = buf.try_get_u8().map_err(|_| StateModifier::Undefine {
        router_id: true,
        prefix_ipv4: true,
        prefix_ipv6: true,
        prefix_v4_via_v6: true,
    })?;
    let ae = Ae::new(ae);

    // When Flags is unavailable, undefine the router-id slot and
    // the default prefix slot specified by the AE (if any).
    let flags = buf.try_get_u8().map_err(|_| StateModifier::Undefine {
        router_id: true,
        prefix_ipv4: ae == Some(Ae::Ipv4),
        prefix_ipv6: ae == Some(Ae::Ipv6),
        prefix_v4_via_v6: ae == Some(Ae::V4ViaV6),
    })?;
    let flags = UpdateFlags::from_bits(flags);

    let mut decode_rest = || {
        let ae = ae?;

        let plen = buf.try_get_u8().ok()?;
        let omitted = buf.try_get_u8().ok()?;
        let interval = buf.try_get_u16().ok()?;
        let seqno = buf.try_get_u16().ok()?;
        let metric = buf.try_get_u16().ok()?;

        let mut prefix = [0; 16];

        match ae {
            Ae::Wildcard => {
                if metric != METRIC_INFINITY || plen != 0 || omitted != 0 {
                    return None;
                }
            }
            Ae::Ipv4 | Ae::Ipv6 | Ae::V4ViaV6 => {
                if plen > ae.max_plen() {
                    return None;
                }

                let omitted = omitted as usize;
                let plen_octets = octets(plen);

                if omitted > plen_octets {
                    return None;
                }

                let prefix = &mut prefix[..plen_octets - omitted];
                buf.try_copy_to_slice(prefix).ok()?;

                // Don't clear the low-order bits here, but only
                // after the omitted octets are filled in.
            }
            Ae::LinkLocalIpv6 => return None,
        }

        // When Interval is zero, ignore the TLV but allow it
        // to update the parser state like a normal one.
        Some(if let Some(interval) = Interval::new(interval) {
            Ok(Tlv::Update {
                ae,
                flags,
                plen,
                omitted,
                interval,
                seqno: Seqno::new(seqno),
                metric,
                prefix,
            })
        } else {
            Err(StateModifier::Update {
                ae,
                flags,
                plen,
                omitted,
                prefix,
            })
        })
    };

    // When AE is unknown or the body is malformed, undefine the router-id
    // slot if the Router-Id flag is set, and the default prefix slot
    // specified by the AE (if any) if the Prefix flag is set.
    decode_rest().ok_or_else(|| StateModifier::Undefine {
        router_id: flags.router_id,
        prefix_ipv4: ae == Some(Ae::Ipv4) && flags.prefix,
        prefix_ipv6: ae == Some(Ae::Ipv6) && flags.prefix,
        prefix_v4_via_v6: ae == Some(Ae::V4ViaV6) && flags.prefix,
    })?
}

fn decode_state_irrelevant_body(kind: TlvKind, buf: &mut &[u8]) -> Option<Tlv> {
    Some(match kind {
        TlvKind::Pad1 => unreachable!(),
        TlvKind::PadN => {
            let length = buf.len() as u8;

            // Skip the MBZ field.
            *buf = &[];

            Tlv::PadN { length }
        }
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

            let ae = Ae::new(ae)?;

            let mut address = [0; 8];

            match ae {
                Ae::Wildcard => {}
                Ae::LinkLocalIpv6 => buf.try_copy_to_slice(&mut address).ok()?,
                _ => return None,
            }

            Tlv::Ihu {
                ae,
                rxcost,
                interval: Interval::new(interval)?,
                address,
                origin_receive_timestamps: None,
            }
        }
        TlvKind::RouterId | TlvKind::Update => unreachable!(),
        TlvKind::RouteRequest => {
            let ae = buf.try_get_u8().ok()?;
            let plen = buf.try_get_u8().ok()?;

            let ae = Ae::new(ae)?;

            if ae == Ae::LinkLocalIpv6 {
                return None;
            }

            if plen > ae.max_plen() {
                return None;
            }

            let mut prefix = [0; 16];
            buf.try_copy_to_slice(&mut prefix[..octets(plen)]).ok()?;

            Tlv::RouteRequest {
                ae,
                plen,
                prefix: mask_prefix(prefix, plen),
            }
        }
        TlvKind::SeqnoRequest => {
            let ae = buf.try_get_u8().ok()?;
            let plen = buf.try_get_u8().ok()?;
            let seqno = buf.try_get_u16().ok()?;
            let hop_count = buf.try_get_u8().ok()?;
            let _reserved = buf.try_get_u8().ok()?;
            let router_id = buf.try_get_u64().ok()?;

            let ae = Ae::new(ae)?;

            if ae == Ae::Wildcard || ae == Ae::LinkLocalIpv6 {
                return None;
            }

            if plen > ae.max_plen() {
                return None;
            }

            let mut prefix = [0; 16];
            buf.try_copy_to_slice(&mut prefix[..octets(plen)]).ok()?;

            Tlv::SeqnoRequest {
                ae,
                plen,
                seqno: Seqno::new(seqno),
                hop_count: NonZeroU8::new(hop_count)?,
                router_id: RouterId::new(router_id)?,
                prefix: mask_prefix(prefix, plen),
            }
        }
    })
}

/// Specifies a way to modify the parser state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateModifier {
    /// Modifies the parser state like a Router-Id TLV with the same value in the field.
    RouterId { router_id: RouterId },
    /// Modifies the parser state like an Update TLV with the same values in the fields.
    Update {
        ae: Ae,
        flags: UpdateFlags,
        plen: u8,
        omitted: u8,
        prefix: [u8; 16],
    },
    /// Undefines the parser state slots whose corresponding fields are set to `true`.
    Undefine {
        router_id: bool,
        prefix_ipv4: bool,
        prefix_ipv6: bool,
        prefix_v4_via_v6: bool,
    },
}

/// An error occurred when decoding a TLV.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlvDecodeError {
    /// The buffer is overrun while reading the TLV's type, length, or payload.
    Overrun,
    /// The TLV's type is unknown.
    Unknown,
    /// The TLV's body is malformed; it does not modify the parser state.
    Malformed,
    /// The TLV is ignored due to a sub-TLV overrunning the TLV boundary or
    /// an unknown mandatory sub-TLV; it does not modify the parser state.
    Ignored,
    /// The TLV is ignored due to a sub-TLV overrunning the TLV boundary,
    /// an unknown mandatory sub-TLV, or a malformed body; it modifies
    /// the parser state as specified by the [`StateModifier`].
    IgnoredStateModifying(StateModifier),
}

fn decode_sub_tlv(tlv: &mut Tlv, buf: &mut &[u8]) -> Result<(), SubTlvDecodeError> {
    let kind = buf.try_get_u8().map_err(|_| SubTlvDecodeError::Overrun)?;

    if kind == SubTlvKind::Pad1 as u8 {
        return Ok(());
    }

    let len = buf.try_get_u8().map_err(|_| SubTlvDecodeError::Overrun)?;

    let Some((body, rem)) = buf.split_at_checked(len as usize) else {
        // Body overruns the buffer. Skip to the end.
        *buf = &[];
        return Err(SubTlvDecodeError::Overrun);
    };
    *buf = rem;

    // Shadow it so we can never use the wrong slice.
    let mut buf = body;

    let Some(kind) = SubTlvKind::from_repr(kind) else {
        return Err(if kind & MANDATORY_BIT == 0 {
            SubTlvDecodeError::Unknown
        } else {
            SubTlvDecodeError::UnknownMandatory
        });
    };

    if kind == SubTlvKind::Timestamp {
        decode_timestamp_body(tlv, &mut buf).ok_or(SubTlvDecodeError::Malformed)?;
    }

    Ok(())
}

fn decode_timestamp_body(tlv: &mut Tlv, buf: &mut &[u8]) -> Option<()> {
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

/// An error occurred when decoding a sub-TLV.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubTlvDecodeError {
    /// The buffer is overrun while reading the sub-TLV's type, length, or body.
    Overrun,
    /// The sub-TLV's body is malformed.
    Malformed,
    /// The sub-TLV's type is unknown and does not have the mandatory bit set.
    Unknown,
    /// The sub-TLV's type is unknown and has the mandatory bit set.
    UnknownMandatory,
}
