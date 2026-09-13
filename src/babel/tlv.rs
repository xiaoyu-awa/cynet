use std::num::NonZeroU8;

use bytes::BufMut;
use strum::{EnumDiscriminants, FromRepr};

use crate::babel::{AddressEncoding, Interval, RouterId, Seqno};

bitflags::bitflags! {
    #[derive(Clone, Debug, Copy, Eq, PartialEq)]
    pub struct UpdateFlags: u8 {
        const PREFIX = 0x80;
        const ROUTER_ID = 0x40;
    }
}

/// A TLV contained in a Babel packet.
///
/// Next Hop is excluded as it is irrelevant for this implementation.
#[derive(Clone, Debug, EnumDiscriminants, Eq, PartialEq)]
#[repr(u8)]
#[strum_discriminants(derive(FromRepr), name(TlvKind), vis(pub(self)))]
pub enum Tlv {
    Pad1 = 0,
    PadN {
        /// The length of the MBZ field.
        length: u8,
    } = 1,
    AcknowledgementRequest {
        /// An arbitrary value that will be echoed in the receiver's Acknowledgment TLV.
        opaque: u16,
        /// A time interval after which the sender will assume that this packet has been lost. The receiver MUST send an Acknowledgment TLV before this time has elapsed (with a margin allowing for propagation time).
        interval: Interval,
    } = 2,
    Acknowledgement {
        /// Set to the Opaque value of the Acknowledgment Request that prompted this Acknowledgment.
        opaque: u16,
    } = 3,
    /// A Hello TLV.
    ///
    /// The Flags field is send as 0. Hello TLVs with the Unicast flag set are silently ignored. All flags other than the Unicast flag are silently ignored.
    Hello {
        /// The sending node's outgoing Hello seqno.
        seqno: Seqno,
        /// If `Some`, this is an upper bound on the time after which the sending node will send a new scheduled Hello TLV. If this is `None`, then this Hello represents an unscheduled Hello and doesn't carry any new information about times at which Hellos are sent.
        interval: Option<Interval>,
    } = 4,
    /// An IHU TLV.
    ///
    /// The AE field is sent as 0. IHU TLVs with a nonzero value in the AE field are silently ignored.
    Ihu {
        /// The rxcost according to the sending node of the interface whose address is specified in the Address field. The value FFFF hexadecimal (infinity) indicates that this interface is unreachable.
        rxcost: u16,
        /// An upper bound on the time after which the sending node will send a new IHU; this MUST NOT be 0. The receiving node will use this value in order to compute a hold time for this symmetric association.
        interval: Interval,
    } = 5,
    RouterId {
        /// The router-id for routes advertised in subsequent Update TLVs
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
        /// The length in bits of the advertised prefix.
        plen: u8,
        /// The number of octets that have been omitted at the beginning of the advertised prefix and that should be taken from a preceding Update TLV in the same address family with the Prefix flag set.
        omitted: u8,
        /// An upper bound on the time after which the sending node will send a new update for this prefix. The value FFFF hexadecimal (infinity) expresses that this announcement will not be repeated unless a request is received.
        interval: Interval,
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
        /// The maximum number of times that this TLV may be forwarded, plus 1.
        hop_count: NonZeroU8,
        /// The Router-Id that is being requested.
        router_id: RouterId,
        /// The prefix being requested. This field's size is Plen/8 rounded upwards.
        prefix: [u8; 16],
    } = 10,
}

impl Tlv {
    fn encoded_len(&self) -> usize {
        match *self {
            Self::Pad1 => 1,
            Self::PadN { length } => 2 + length as usize,
            Self::AcknowledgementRequest { .. } => 8,
            Self::Acknowledgement { .. } => 4,
            Self::Hello { .. } => 8,
            Self::Ihu { .. } => 8,
            Self::RouterId { .. } => 12,
            Self::Update { plen, omitted, .. } => 12 + (plen.div_ceil(8) - omitted) as usize,
            Self::RouteRequest { plen, .. } => 4 + plen.div_ceil(8) as usize,
            Self::SeqnoRequest { plen, .. } => 16 + plen.div_ceil(8) as usize,
        }
    }

    pub fn encode(&self, mut buf: &mut [u8]) -> usize {
        let encoded_len = self.encoded_len();
        if buf.len() < encoded_len {
            return 0;
        }

        let init_buf_len = buf.len();

        buf.put_u8(TlvKind::from(self) as u8); // Type

        if *self == Self::Pad1 {
            return 1;
        }

        let body_len = u8::try_from(encoded_len.strict_sub(2))
            .expect("TLV body length should be less than 256");
        buf.put_u8(body_len); // Length

        match *self {
            Self::Pad1 => unreachable!(),
            Self::PadN { length } => buf.put_bytes(0, length as usize), // MBZ
            Self::AcknowledgementRequest { opaque, interval } => {
                buf.put_u16(0); // Reserved
                buf.put_u16(opaque);
                buf.put_u16(interval.get());
            }
            Self::Acknowledgement { opaque } => buf.put_u16(opaque),
            Self::Hello { seqno, interval } => {
                buf.put_u16(0); // Flags
                buf.put_u16(seqno.get());
                buf.put_u16(interval.map_or(0, |i| i.get()));
            }
            Self::Ihu { rxcost, interval } => {
                buf.put_u8(0); // AE
                buf.put_u8(0); // Reserved
                buf.put_u16(rxcost);
                buf.put_u16(interval.get());
            }
            Self::RouterId { router_id } => {
                buf.put_u16(0); // Reserved
                buf.put_u64(router_id.get());
            }
            Self::Update {
                ae,
                flags,
                plen,
                omitted,
                interval,
                seqno,
                metric,
                prefix,
            } => {
                buf.put_u8(ae as u8);
                buf.put_u8(flags.bits());
                buf.put_u8(plen);
                buf.put_u8(omitted);
                buf.put_u16(interval.get());
                buf.put_u16(seqno.get());
                buf.put_u16(metric);
                buf.put_slice(&prefix[omitted as usize..plen.div_ceil(8) as usize]);
            }
            Self::RouteRequest { ae, plen, prefix } => {
                buf.put_u8(ae as u8);
                buf.put_u8(plen);
                buf.put_slice(&prefix[..plen.div_ceil(8) as usize]);
            }
            Self::SeqnoRequest {
                ae,
                plen,
                seqno,
                hop_count,
                router_id,
                prefix,
            } => {
                buf.put_u8(ae as u8);
                buf.put_u8(plen);
                buf.put_u16(seqno.get());
                buf.put_u8(hop_count.get());
                buf.put_u8(0); // Reserved
                buf.put_u64(router_id.get());
                buf.put_slice(&prefix[..plen.div_ceil(8) as usize]);
            }
        }

        assert_eq!(encoded_len, init_buf_len - buf.len());
        encoded_len
    }
}
