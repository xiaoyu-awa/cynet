use crate::babel::tlv::{Tlv, TlvDecodeError};

/// Magic number for Babel.
const MAGIC: u8 = 42;

/// Current version of Babel.
const VERSION: u8 = 2;

pub struct PacketEncoder<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> PacketEncoder<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        assert!(
            buf.len() >= 512 && buf.len() <= 65535,
            "packet buffer size should be between 512 and 65535"
        );

        buf[0] = MAGIC;
        buf[1] = VERSION;

        Self { buf, len: 4 }
    }

    pub fn put_tlv(&mut self, tlv: Tlv) -> bool {
        if self.len + tlv.encoded_len() > self.buf.len() {
            return false;
        }

        self.len += tlv.encode(&mut self.buf[self.len..]);
        true
    }

    pub fn put_tlvs(&mut self, tlvs: &[Tlv]) -> bool {
        let total_len: usize = tlvs.iter().map(|t| t.encoded_len()).sum();
        if self.len + total_len > self.buf.len() {
            return false;
        }

        for tlv in tlvs {
            self.len += tlv.encode(&mut self.buf[self.len..]);
        }
        true
    }

    pub fn finalize(self) -> &'a [u8] {
        let body_len = self.len as u16 - 4;
        self.buf[2..4].copy_from_slice(&body_len.to_be_bytes());
        &self.buf[..self.len]
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
