pub mod tlv;

use std::num::NonZeroUsize;

use crate::babel::{
    base,
    packet::tlv::{SubTlvKind, Tlv, TlvDecodeError, TlvKind},
};

/// Magic number for Babel.
const MAGIC: u8 = 42;

/// Current version of Babel.
const VERSION: u8 = 2;

pub struct PacketEncoder {
    buf: Box<[u8]>,
    len: usize,
    timestamp_offset: Option<NonZeroUsize>,
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
}

impl<'a> PacketDecoder<'a> {
    pub fn new(buf: &'a [u8]) -> Option<Self> {
        match buf {
            [MAGIC, VERSION, a, b, buf @ ..] => {
                let len = u16::from_be_bytes([*a, *b]);
                let buf = buf.get(..len as usize)?;
                Some(Self { buf })
            }
            _ => None,
        }
    }

    pub fn get_tlv(&mut self) -> Option<Result<Tlv, TlvDecodeError>> {
        if self.buf.is_empty() {
            None
        } else {
            Some(Tlv::decode(&mut self.buf))
        }
    }
}
