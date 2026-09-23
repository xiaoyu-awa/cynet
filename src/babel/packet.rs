pub mod tlv;

use std::num::NonZeroUsize;

use crate::babel::{
    base::{self, AddressEncoding, Interval, RouterId, Seqno},
    packet::tlv::{
        METRIC_INFINITE, StateModifier, SubTlvKind, Tlv, TlvDecodeError, TlvKind, UpdateFlags,
        octets,
    },
};

/// Magic number for Babel.
const MAGIC: u8 = 42;

/// Current version of Babel.
const VERSION: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Update {
    /// The encoding of the Prefix field.
    pub ae: AddressEncoding,
    /// The length in bits of the advertised prefix.
    pub plen: u8,
    /// An upper bound, expressed in centiseconds, on the time after which the sending node will send a new update for this prefix. This MUST NOT be 0. The receiving node will use this value to compute a hold time for the route table entry. The value FFFF hexadecimal (infinity) expresses that this announcement will not be repeated unless a request is received (Section 3.8.2.3).
    pub interval: Interval,
    /// The originator's sequence number for this update.
    pub seqno: Seqno,
    /// The sender's metric for this route. The value FFFF hexadecimal (infinity) means that this is a route retraction.
    pub metric: u16,
    /// The prefix being advertised. This field's size is Plen/8 rounded upwards.
    ///
    /// This field's value starts from index 0 of the array.
    ///
    /// The prefix being advertised by an Update TLV is computed as follows:
    ///
    /// - the first Omitted octets of the prefix are taken from the previous Update TLV with the Prefix flag set and the same address encoding, even if it was ignored due to an unknown mandatory sub-TLV; if the Omitted field is not zero and there is no such TLV, then this Update MUST be ignored;
    /// - the next (Plen/8 - Omitted) rounded upwards octets are taken from the Prefix field;
    /// - if Plen is not a multiple of 8, then any bits beyond Plen (i.e., the low-order (8 - Plen MOD 8) bits of the last octet) are cleared;
    /// - the remaining octets are set to 0.
    pub prefix: [u8; 16],
    /// The router-id of the originating node for this announcement, or `None` if this is a retraction.
    ///
    /// If the Metric field is finite, the router-id of the originating node for this announcement is taken from the prefix advertised by this Update if the Router-Id flag is set, computed as described above. Otherwise, it is taken either from the preceding Router-Id TLV, or the preceding Update TLV with the Router-Id flag set, whichever comes last, even if that TLV is otherwise ignored due to an unknown mandatory sub-TLV; if there is no suitable TLV, then this update is ignored.
    pub router_id: Option<RouterId>,
}

pub enum PacketItem {
    Tlv(Tlv),
    Update(Update),
}

pub enum PacketDecodeError {
    Stateless(TlvDecodeError),
    Stateful(Tlv),
}

pub struct PacketEncoder {
    buf: Box<[u8]>,
    len: usize,
    timestamp_offset: Option<NonZeroUsize>,
    router_id: Option<RouterId>,
    prefix_ipv6: Option<[u8; 16]>,
}

impl PacketEncoder {
    pub fn new(size: usize) -> Self {
        assert!(
            (512..=65535).contains(&size),
            "packet buffer size should be between 512 and 65535"
        );

        let mut buf = vec![0; size].into_boxed_slice();

        buf[0] = MAGIC;
        buf[1] = VERSION;

        Self {
            buf,
            len: 4,
            timestamp_offset: None,
            router_id: None,
            prefix_ipv6: None,
        }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.len
    }

    pub fn put_tlv(&mut self, tlv: &Tlv) -> bool {
        if tlv.encoded_len() > self.remaining() {
            return false;
        }

        self.len += tlv.encode(&mut self.buf[self.len..]);
        true
    }

    pub fn put_tlvs(&mut self, tlvs: &[Tlv]) -> bool {
        let total_len: usize = tlvs.iter().map(|t| t.encoded_len()).sum();
        if total_len > self.remaining() {
            return false;
        }

        for tlv in tlvs {
            self.len += tlv.encode(&mut self.buf[self.len..]);
        }
        true
    }

    /// Marks the next TLV as a Hello for timestamping when `finalize` is called.
    pub fn mark_next_as_hello_for_timestamping(&mut self) {
        self.timestamp_offset = NonZeroUsize::new(self.len + 8);
    }

    pub fn put_update(&mut self, update: &Update) -> bool {
        todo!()
    }

    pub fn finalize(&mut self) -> &[u8] {
        let body_len = self.len as u16 - 4;
        self.buf[2..4].copy_from_slice(&body_len.to_be_bytes());

        if let Some(timestamp_offset) = self.timestamp_offset {
            let i = timestamp_offset.get();

            assert_eq!(self.buf[i - 8], TlvKind::Hello as u8);
            self.buf[i] = SubTlvKind::Timestamp as u8;

            let t = base::timestamp_now();
            self.buf[i + 2..i + 6].copy_from_slice(&t.to_be_bytes());
        }

        &self.buf[..self.len]
    }

    pub fn clear(&mut self) {
        self.len = 4;
        self.timestamp_offset = None;
    }
}

pub struct PacketDecoder<'a> {
    buf: &'a [u8],
    router_id: Option<RouterId>,
    prefix_ipv4: Option<[u8; 4]>,
    prefix_ipv6: Option<[u8; 16]>,
    prefix_v4_via_v6: Option<[u8; 4]>,
}

impl<'a> PacketDecoder<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        match buf {
            [MAGIC, VERSION, a, b, buf @ ..] => {
                let len = u16::from_be_bytes([*a, *b]);
                let buf = buf.get(..len as usize)?;
                Some(Self {
                    buf,
                    router_id: None,
                    prefix_ipv4: None,
                    prefix_ipv6: None,
                    prefix_v4_via_v6: None,
                })
            }
            _ => None,
        }
    }

    fn next_tlv(&mut self) -> Option<Result<Tlv, TlvDecodeError>> {
        if self.buf.is_empty() {
            None
        } else {
            Some(Tlv::decode(&mut self.buf))
        }
    }

    /// Returns the current default prefix for `ae`, or `None`
    /// if it is undefined or `ae` does not allow compression.
    fn default_prefix(&self, ae: AddressEncoding) -> Option<&[u8]> {
        match ae {
            AddressEncoding::Ipv4 => self.prefix_ipv4.as_ref().map(|p| &p[..]),
            AddressEncoding::Ipv6 => self.prefix_ipv6.as_ref().map(|p| &p[..]),
            AddressEncoding::V4ViaV6 => self.prefix_v4_via_v6.as_ref().map(|p| &p[..]),
            AddressEncoding::Wildcard | AddressEncoding::LinkLocalIpv6 => None,
        }
    }

    /// Sets the default prefix for `ae`, doing nothing if `ae` does not allow compression.
    fn set_default_prefix(&mut self, ae: AddressEncoding, prefix: Option<&[u8; 16]>) {
        match ae {
            AddressEncoding::Ipv4 => self.prefix_ipv4 = prefix.map(|p| *p.first_chunk().unwrap()),
            AddressEncoding::Ipv6 => self.prefix_ipv6 = prefix.copied(),
            AddressEncoding::V4ViaV6 => {
                self.prefix_v4_via_v6 = prefix.map(|p| *p.first_chunk().unwrap());
            }
            AddressEncoding::Wildcard | AddressEncoding::LinkLocalIpv6 => {}
        }
    }

    /// Computes the prefix advertised by an Update TLV, returning `None`
    /// if the omitted octets cannot be taken from a default prefix.
    fn expand_prefix(
        &self,
        ae: AddressEncoding,
        plen: u8,
        omitted: u8,
        prefix: [u8; 16],
    ) -> Option<[u8; 16]> {
        let omitted = omitted as usize;
        let plen_octets = octets(plen);

        let mut expanded = [0; 16];

        if omitted != 0 {
            expanded[..omitted].copy_from_slice(&self.default_prefix(ae)?[..omitted]);
        }
        expanded[omitted..plen_octets].copy_from_slice(&prefix[..plen_octets - omitted]);

        if !plen.is_multiple_of(8) {
            expanded[plen_octets - 1] &= 0xff << (8 - plen % 8);
        }

        Some(expanded)
    }

    /// Updates the parser state like an Update TLV with the given fields,
    /// returning the advertised prefix, or `None` if it cannot be computed.
    fn update_state(
        &mut self,
        ae: AddressEncoding,
        flags: UpdateFlags,
        plen: u8,
        omitted: u8,
        prefix: [u8; 16],
    ) -> Option<[u8; 16]> {
        // Expand the prefix before setting a new default prefix,
        // so that the omitted octets are taken from the previous one.
        let prefix = self.expand_prefix(ae, plen, omitted, prefix);

        // When the prefix cannot be computed, undefine the slots
        // that this TLV would have set.
        if flags.prefix {
            self.set_default_prefix(ae, prefix.as_ref());
        }
        if flags.router_id {
            self.router_id = prefix.and_then(|p| router_id_from_prefix(ae, &p));
        }

        prefix
    }

    /// Updates the parser state as specified by a [`StateModifier`].
    fn apply(&mut self, modifier: &StateModifier) {
        match *modifier {
            StateModifier::RouterId { router_id } => self.router_id = Some(router_id),
            StateModifier::Update {
                ae,
                flags,
                plen,
                omitted,
                prefix,
            } => {
                self.update_state(ae, flags, plen, omitted, prefix);
            }
            StateModifier::Undefine {
                router_id,
                prefix_ipv4,
                prefix_ipv6,
                prefix_v4_via_v6,
            } => {
                if router_id {
                    self.router_id = None;
                }
                if prefix_ipv4 {
                    self.prefix_ipv4 = None;
                }
                if prefix_ipv6 {
                    self.prefix_ipv6 = None;
                }
                if prefix_v4_via_v6 {
                    self.prefix_v4_via_v6 = None;
                }
            }
        }
    }
}

/// Computes a router-id from the first address of a prefix,
/// returning `None` if it is invalid.
fn router_id_from_prefix(ae: AddressEncoding, prefix: &[u8; 16]) -> Option<RouterId> {
    let n = match ae {
        AddressEncoding::Ipv4 | AddressEncoding::V4ViaV6 => {
            u32::from_be_bytes(*prefix.first_chunk().unwrap()) as u64
        }
        AddressEncoding::Ipv6 => u64::from_be_bytes(*prefix.last_chunk().unwrap()),
        AddressEncoding::Wildcard | AddressEncoding::LinkLocalIpv6 => return None,
    };
    RouterId::new(n)
}

impl Iterator for PacketDecoder<'_> {
    type Item = Result<PacketItem, PacketDecodeError>;

    /// Decodes the next TLV in the packet body, updating the parser state.
    ///
    /// Update TLVs are yielded as [`PacketItem::Update`] with their prefix and
    /// router-id resolved from the parser state, and all other TLVs as
    /// [`PacketItem::Tlv`]. The parser state is updated even if the TLV is
    /// otherwise ignored, in which case an error is yielded.
    fn next(&mut self) -> Option<Self::Item> {
        let tlv = match self.next_tlv()? {
            Ok(tlv) => tlv,
            Err(e) => {
                if let TlvDecodeError::IgnoredStateModifying(modifier) = &e {
                    self.apply(modifier);
                }
                return Some(Err(PacketDecodeError::Stateless(e)));
            }
        };

        Some(Ok(match tlv {
            Tlv::RouterId { router_id } => {
                self.router_id = Some(router_id);
                PacketItem::Tlv(tlv)
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
                let Some(prefix) = self.update_state(ae, flags, plen, omitted, prefix) else {
                    return Some(Err(PacketDecodeError::Stateful(tlv)));
                };

                // The router-id is only used for a finite metric.
                let router_id = if metric == METRIC_INFINITE {
                    None
                } else if self.router_id.is_none() {
                    return Some(Err(PacketDecodeError::Stateful(tlv)));
                } else {
                    self.router_id
                };

                PacketItem::Update(Update {
                    ae,
                    plen,
                    interval,
                    seqno,
                    metric,
                    prefix,
                    router_id,
                })
            }
            _ => PacketItem::Tlv(tlv),
        }))
    }
}
