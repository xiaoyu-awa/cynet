pub mod tlv;

#[cfg(test)]
mod tests;

use std::{array, num::NonZeroUsize, time::Instant};

use crate::babel::{
    base::{Ae, Interval, METRIC_INFINITY, RouterId, Seqno, timestamp},
    packet::tlv::{StateModifier, Tlv, TlvDecodeError, UpdateFlags, mask_prefix, octets},
};

/// Magic number for Babel.
const MAGIC: u8 = 42;

/// Current version of Babel.
const VERSION: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Update {
    /// The encoding of the Prefix field.
    pub ae: Ae,
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
    /// The router-id of the originating node for this announcement, which may be `None` only when this is a retraction.
    ///
    /// If the Metric field is finite, the router-id of the originating node for this announcement is taken from the prefix advertised by this Update if the Router-Id flag is set, computed as described above. Otherwise, it is taken either from the preceding Router-Id TLV, or the preceding Update TLV with the Router-Id flag set, whichever comes last, even if that TLV is otherwise ignored due to an unknown mandatory sub-TLV; if there is no suitable TLV, then this update is ignored.
    ///
    /// For a retraction, the router-id is optional and not used by the protocol. Giving a retraction the router-id of the route it retracts lets it be sorted among that router's other updates, next to related prefixes, which may make it more compact. On decoding, a retraction carries whichever router-id is in effect, if any.
    pub router_id: Option<RouterId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketItem {
    Tlv(Tlv),
    Update(Update),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketDecodeError {
    Stateless(TlvDecodeError),
    Stateful(Tlv),
}

/// An encoded packet, whose Hello's Transmit Timestamp, if any, is left to be filled in
/// just before the packet is sent (RFC 9616 §3.2).
#[derive(Clone, Debug)]
pub struct Packet {
    buf: Box<[u8]>,
    /// The offset of the Transmit Timestamp, if any.
    timestamp_offset: Option<NonZeroUsize>,
}

impl Packet {
    /// Fills in the Transmit Timestamp, if any, with `at`, the time the packet is sent,
    /// and returns the packet's octets.
    pub fn timestamp(&mut self, at: Instant) -> &[u8] {
        if let Some(offset) = self.timestamp_offset {
            let i = offset.get();
            self.buf[i..i + 4].copy_from_slice(&timestamp(at).to_be_bytes());
        }
        &self.buf
    }

    /// Returns the packet's octets, with the Transmit Timestamp, if any, left as it is.
    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

pub struct PacketEncoder {
    buf: Box<[u8]>,
    len: usize,
    contains_hello: bool,
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
            contains_hello: false,
            timestamp_offset: None,
            router_id: None,
            prefix_ipv6: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 4
    }

    #[cfg(test)]
    fn remaining(&self) -> usize {
        self.buf.len() - self.len
    }

    /// Puts a TLV as [`put_tlvs`] does.
    ///
    /// [`put_tlvs`]: Self::put_tlvs
    #[must_use]
    pub fn put_tlv(&mut self, tlv: &Tlv) -> bool {
        self.put_tlvs(array::from_ref(tlv))
    }

    /// Puts TLVs, returning `false` without putting any of them if they do not all fit,
    /// or if they include a Hello and the packet already contains one, since multiple
    /// Hello TLVs SHOULD NOT be sent in the same packet (RFC 8966 §4.6.5).
    ///
    /// An unscheduled Hello with no timestamp doesn't count as one. It only exists to move
    /// a neighbour's expected Hello seqno, ahead of the Hello that flushes its entry (see
    /// [Reboots](super::State#reboots)).
    ///
    /// Router-Id and Update TLVs modify the parser state, which the encoder tracks
    /// for compression, so they must be put with [`put_update`] instead, apart from a
    /// wildcard retraction with no flags set, which leaves the parser state as it is.
    ///
    /// A Hello's Transmit Timestamp, if any, is a placeholder, to be filled in as the
    /// packet is sent (see [`Packet::timestamp`]). An IHU carrying timestamps MUST be
    /// sent in a packet that also contains a timestamped Hello (RFC 9616 §3.2), so it
    /// must be put after one, either in an earlier call or earlier in `tlvs`.
    ///
    /// [`put_update`]: Self::put_update
    #[must_use]
    pub fn put_tlvs(&mut self, tlvs: &[Tlv]) -> bool {
        let mut len = self.len;
        let mut includes_hello = false;
        let mut timestamp_offset = None;

        for tlv in tlvs {
            match tlv {
                Tlv::Update {
                    ae: Ae::Wildcard,
                    flags:
                        UpdateFlags {
                            prefix: false,
                            router_id: false,
                        },
                    ..
                } => {}
                Tlv::RouterId { .. } | Tlv::Update { .. } => {
                    panic!("Router-Id and Update TLVs should be put with put_update")
                }
                Tlv::Hello {
                    interval: None,
                    transmit_timestamp: None,
                    ..
                } => {}
                Tlv::Hello {
                    transmit_timestamp, ..
                } => {
                    if self.contains_hello {
                        return false;
                    }

                    assert!(
                        !includes_hello,
                        "TLVs put together should not include more than one Hello"
                    );
                    includes_hello = true;

                    if transmit_timestamp.is_some() {
                        // The Transmit Timestamp follows the 8-octet Hello TLV
                        // and the Type and Length of its sub-TLV.
                        timestamp_offset = NonZeroUsize::new(len + 10);
                    }
                }
                Tlv::Ihu {
                    origin_receive_timestamps: Some(_),
                    ..
                } => assert!(
                    self.timestamp_offset.is_some() || timestamp_offset.is_some(),
                    "timestamped IHU should be put after a timestamped Hello"
                ),
                _ => {}
            }

            let Some(buf) = self.buf.get_mut(len..len + tlv.encoded_len()) else {
                return false;
            };
            len += tlv.encode(buf);
        }

        if includes_hello {
            self.contains_hello = true;
            self.timestamp_offset = timestamp_offset;
        }

        self.len = len;
        true
    }

    /// Puts TLVs of any kind without checking them, returning `false`
    /// without putting any of them if they do not all fit.
    fn put_tlvs_raw(&mut self, tlvs: &[Tlv]) -> bool {
        let mut len = self.len;

        for tlv in tlvs {
            let Some(buf) = self.buf.get_mut(len..len + tlv.encoded_len()) else {
                return false;
            };
            len += tlv.encode(buf);
        }

        self.len = len;
        true
    }

    /// Puts an Update TLV, preceded by a Router-Id TLV if needed, returning `false`
    /// without putting either if they do not fit.
    ///
    /// AE 3 is not supported, and only AE 2 is compressed. The prefix must have all bits
    /// beyond Plen cleared, and the router-id must be present if the metric is finite.
    ///
    /// A retraction with a router-id establishes the router-id like an announcement,
    /// while one without a router-id leaves the current one as is.
    ///
    /// Updates are encoded correctly in any order. As a hint, they are encoded
    /// more compactly when sorted as follows:
    ///
    /// - by router-id (a retraction carrying one sorts among that router's other updates), since a new router-id may cost a Router-Id TLV;
    /// - then by whether the router-id coincides with the one computed from the prefix (true first), so that the Router-Id flag can establish it in place of a Router-Id TLV;
    /// - then by prefix octets, so that each prefix shares as many leading octets as possible with the previous one.
    ///
    /// Receivers apply updates in the order they are put, so sorting can change their effect. Before sorting, a caller must:
    ///
    /// - keep only the latest update for each prefix and Plen, so that an older one cannot end up after it;
    /// - drop the updates queued before an AE 0 wildcard retraction, which retracts them anyway, and put the retraction first, so that it cannot retract updates queued after it.
    #[must_use]
    pub fn put_update(&mut self, update: &Update) -> bool {
        let Update {
            ae,
            plen,
            interval,
            seqno,
            metric,
            prefix,
            router_id,
        } = *update;

        assert_ne!(ae, Ae::LinkLocalIpv6, "Update should not carry AE 3");
        assert!(
            plen <= ae.max_plen(),
            "Update should not carry overlarge Plen"
        );
        assert_eq!(
            prefix,
            mask_prefix(prefix, plen),
            "Update should not carry a prefix with bits set beyond Plen"
        );

        let mut flags = UpdateFlags {
            prefix: false,
            router_id: false,
        };
        let mut omitted = 0;

        if ae == Ae::Ipv6 {
            // TODO: babeld takes IPv4-mapped IPv6 prefixes (::ffff:0:0/96) for IPv4
            // routes, so it drops AE 2 updates for them, and rejects compressed AE 2
            // updates whose default prefix is one. Consider rejecting them here,
            // since IPv4 routes should be carried in AE 4 anyway.

            if let Some(default_prefix) = &self.prefix_ipv6 {
                omitted = default_prefix
                    .iter()
                    .zip(&prefix)
                    .take(octets(plen))
                    .take_while(|(a, b)| a == b)
                    .count();
            }

            // As babeld does, make this prefix the new default prefix
            // only if there is none yet or it is at least a /48.
            flags.prefix = self.prefix_ipv6.is_none() || plen >= 48;
        }

        // The router-id is only required for a finite metric,
        // but is established for a retraction too if present.
        assert!(
            metric == METRIC_INFINITY || router_id.is_some(),
            "Update with finite metric should carry a router-id"
        );

        let mut new_router_id = self.router_id;
        let mut tlv_router_id = None;

        if let Some(router_id) = router_id
            && self.router_id != Some(router_id)
        {
            if router_id_from_prefix(ae, &prefix) == Some(router_id) {
                flags.router_id = true;
            } else {
                tlv_router_id = Some(router_id);
            }
            new_router_id = Some(router_id);
        }

        let plen_octets = octets(plen);
        let mut tlv_prefix = [0; 16];
        tlv_prefix[..plen_octets - omitted].copy_from_slice(&prefix[omitted..plen_octets]);

        let update_tlv = Tlv::Update {
            ae,
            flags,
            plen,
            omitted: omitted as u8,
            interval,
            seqno,
            metric,
            prefix: tlv_prefix,
        };

        let fits = match tlv_router_id {
            Some(router_id) => self.put_tlvs_raw(&[Tlv::RouterId { router_id }, update_tlv]),
            None => self.put_tlvs_raw(&[update_tlv]),
        };

        if !fits {
            return false;
        }

        // Update the state only after the TLVs are put.
        self.router_id = new_router_id;
        if flags.prefix {
            self.prefix_ipv6 = Some(prefix);
        }
        true
    }

    /// Finalizes the packet, leaving its Transmit Timestamp, if any, to be filled in as
    /// it is sent (see [`Packet::timestamp`]).
    pub fn finalize(&mut self) -> Packet {
        let body_len = self.len as u16 - 4;
        self.buf[2..4].copy_from_slice(&body_len.to_be_bytes());

        Packet {
            buf: self.buf[..self.len].into(),
            timestamp_offset: self.timestamp_offset,
        }
    }

    pub fn clear(&mut self) {
        self.len = 4;
        self.contains_hello = false;
        self.timestamp_offset = None;
        self.router_id = None;
        self.prefix_ipv6 = None;
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
    fn default_prefix(&self, ae: Ae) -> Option<&[u8]> {
        match ae {
            Ae::Ipv4 => self.prefix_ipv4.as_ref().map(|p| &p[..]),
            Ae::Ipv6 => self.prefix_ipv6.as_ref().map(|p| &p[..]),
            Ae::V4ViaV6 => self.prefix_v4_via_v6.as_ref().map(|p| &p[..]),
            Ae::Wildcard | Ae::LinkLocalIpv6 => None,
        }
    }

    /// Sets the default prefix for `ae`, doing nothing if `ae` does not allow compression.
    fn set_default_prefix(&mut self, ae: Ae, prefix: Option<&[u8; 16]>) {
        match ae {
            Ae::Ipv4 => self.prefix_ipv4 = prefix.map(|p| *p.first_chunk().unwrap()),
            Ae::Ipv6 => self.prefix_ipv6 = prefix.copied(),
            Ae::V4ViaV6 => self.prefix_v4_via_v6 = prefix.map(|p| *p.first_chunk().unwrap()),
            Ae::Wildcard | Ae::LinkLocalIpv6 => {}
        }
    }

    /// Computes the prefix advertised by an Update TLV, returning `None`
    /// if the omitted octets cannot be taken from a default prefix.
    fn expand_prefix(&self, ae: Ae, plen: u8, omitted: u8, prefix: [u8; 16]) -> Option<[u8; 16]> {
        let omitted = omitted as usize;
        let plen_octets = octets(plen);

        let mut expanded = [0; 16];

        if omitted != 0 {
            expanded[..omitted].copy_from_slice(&self.default_prefix(ae)?[..omitted]);
        }
        expanded[omitted..plen_octets].copy_from_slice(&prefix[..plen_octets - omitted]);

        Some(mask_prefix(expanded, plen))
    }

    /// Updates the parser state like an Update TLV with the given fields,
    /// returning the advertised prefix, or `None` if it cannot be computed.
    fn update_state(
        &mut self,
        ae: Ae,
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
fn router_id_from_prefix(ae: Ae, prefix: &[u8; 16]) -> Option<RouterId> {
    let n = match ae {
        Ae::Ipv4 | Ae::V4ViaV6 => u32::from_be_bytes(*prefix.first_chunk().unwrap()) as u64,
        Ae::Ipv6 => u64::from_be_bytes(*prefix.last_chunk().unwrap()),
        Ae::Wildcard | Ae::LinkLocalIpv6 => return None,
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

                // The router-id is only required for a finite metric,
                // but is retained for a retraction too if present.
                if metric != METRIC_INFINITY && self.router_id.is_none() {
                    return Some(Err(PacketDecodeError::Stateful(tlv)));
                }

                PacketItem::Update(Update {
                    ae,
                    plen,
                    interval,
                    seqno,
                    metric,
                    prefix,
                    router_id: self.router_id,
                })
            }
            _ => PacketItem::Tlv(tlv),
        }))
    }
}
