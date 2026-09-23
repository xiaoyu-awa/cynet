use std::{
    num::{NonZeroU16, NonZeroU64},
    ops::{Add, Sub},
    sync::LazyLock,
    time::Duration,
};

use tokio::time::Instant;

/// A router-id, assumed unique across the routing domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RouterId(NonZeroU64);

impl RouterId {
    /// Creates a router-id from a `u64`, returning `None` if it equals `0` or `u64::MAX`.
    pub fn new(n: u64) -> Option<Self> {
        if n == u64::MAX {
            None
        } else {
            NonZeroU64::new(n).map(Self)
        }
    }

    /// Returns the router-id as a `u64`.
    pub fn get(self) -> u64 {
        self.0.get()
    }
}

/// An address encoding (AE).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressEncoding {
    /// Wildcard address. The value is 0 octets long.
    Wildcard = 0,
    /// IPv4 address. Compression is allowed. 4 octets or less.
    Ipv4 = 1,
    /// IPv6 address. Compression is allowed. 16 octets or less.
    Ipv6 = 2,
    /// Link-local IPv6 address. Compression is not allowed. The value is 8 octets long, a prefix of fe80::/64 is implied.
    LinkLocalIpv6 = 3,
    /// RFC 9229: v4-via-v6. Value encoding identical to AE 1.
    V4ViaV6 = 4,
}

impl AddressEncoding {
    /// Creates an `AddressEncoding` from a `u8`, returning `None` if it is greater than 3.
    pub fn new(n: u8) -> Option<Self> {
        Some(match n {
            0 => Self::Wildcard,
            1 => Self::Ipv4,
            2 => Self::Ipv6,
            3 => Self::LinkLocalIpv6,
            4 => Self::V4ViaV6,
            _ => return None,
        })
    }

    /// Returns the maximum prefix length supported by this address encoding.
    pub fn max_plen(self) -> u8 {
        match self {
            Self::Wildcard => 0,
            Self::Ipv4 | Self::V4ViaV6 => 32,
            Self::Ipv6 => 128,
            Self::LinkLocalIpv6 => panic!("Plen is undefined for AE 3"),
        }
    }
}

/// A sequence number (seqno).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Seqno(u16);

impl Seqno {
    /// Creates a seqno from a `u16`.
    pub fn new(n: u16) -> Self {
        Self(n)
    }

    /// Returns the seqno as a `u16`.
    pub fn get(self) -> u16 {
        self.0
    }

    /// Checks whether `self` is less than `other`.
    pub fn lt(self, other: Self) -> bool {
        other - self > 0
    }
}

impl Add<u16> for Seqno {
    type Output = Self;

    fn add(self, rhs: u16) -> Self {
        Self(self.0.wrapping_add(rhs))
    }
}

impl Sub<Seqno> for Seqno {
    type Output = i16;

    fn sub(self, rhs: Seqno) -> i16 {
        self.0.wrapping_sub(rhs.0).cast_signed()
    }
}

/// Nonzero relative time in centiseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interval(NonZeroU16);

const NANOS_PER_CENTI: u32 = 10_000_000;
const CENTIS_PER_SEC: u64 = 100;

impl Interval {
    /// Creates an `Interval` from a `u16`.
    pub fn new(n: u16) -> Option<Self> {
        NonZeroU16::new(n).map(Self)
    }

    /// Returns the contained number of centiseconds as a `u16`.
    pub fn get(self) -> u16 {
        self.0.get()
    }

    /// Converts this `Interval` exactly to a [`Duration`].
    pub const fn to_duration(self) -> Duration {
        let centis = self.0.get() as u64;
        let secs = centis / CENTIS_PER_SEC;
        let subsec_centis = (centis % CENTIS_PER_SEC) as u32;
        Duration::new(secs, subsec_centis * NANOS_PER_CENTI)
    }

    /// Converts a [`Duration`] to an `Interval`, returning `None` if exact conversion is not possible.
    pub fn from_duration(d: Duration) -> Option<Self> {
        const MAX_D: Duration = Interval(NonZeroU16::MAX).to_duration();

        if d.as_secs() <= MAX_D.as_secs()
            && (d.as_secs() != MAX_D.as_secs() || d.subsec_nanos() <= MAX_D.subsec_nanos())
            && d.subsec_nanos().is_multiple_of(NANOS_PER_CENTI)
        {
            let centis = d.as_secs() as u16 * CENTIS_PER_SEC as u16
                + (d.subsec_nanos() / NANOS_PER_CENTI) as u16;
            NonZeroU16::new(centis).map(Self)
        } else {
            None
        }
    }
}

/// The effect of a received Hello from a neighbour.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum HelloEffect {
    /// No effect.
    None,
    /// The neighbour entry should be flushed.
    Flush,
}

/// A Hello history with 16 entries.
pub struct HelloHistory {
    bits: u16,
    ne: Seqno,
}

impl HelloHistory {
    /// Creates an empty Hello history expecting seqno `nr + 1`.
    pub fn new(nr: Seqno) -> Self {
        Self {
            bits: 1,
            ne: nr + 1,
        }
    }

    /// Extracts the history bits, where a 1 bit represents a received Hello,
    /// a 0 bit a missed Hello, and the least significant bit the most recent Hello.
    pub fn bits(&self) -> u16 {
        self.bits
    }

    /// Returns the expected seqno.
    pub fn expected_seqno(&self) -> Seqno {
        self.ne
    }

    /// Updates the history with the seqno of a received Hello,
    /// returning an effect that should be applied to the state.
    pub fn received(&mut self, nr: Seqno) -> HelloEffect {
        let diff = nr - self.ne;
        let abs_diff = u32::from(diff.unsigned_abs());

        if abs_diff > 16 {
            *self = Self::new(nr);
            return HelloEffect::Flush;
        }

        if diff < 0 {
            self.bits = self.bits.unbounded_shr(abs_diff);
        } else {
            self.bits = self.bits.unbounded_shl(abs_diff);
        }

        self.bits = (self.bits << 1) | 1;
        self.ne = nr + 1;

        HelloEffect::None
    }

    /// Updates the history with a missed Hello,
    /// returning an effect that should be applied to the state.
    pub fn missed(&mut self) -> HelloEffect {
        self.bits <<= 1;
        self.ne = self.ne + 1;

        if self.bits == 0 {
            HelloEffect::Flush
        } else {
            HelloEffect::None
        }
    }
}

// TODO: It may be desirable to subtract a random offset from this,
// but that comes at the cost of nondeterminism. Hold off for now.
static TIMESTAMP_ORIGIN: LazyLock<Instant> = LazyLock::new(Instant::now);

pub fn timestamp_now() -> u32 {
    TIMESTAMP_ORIGIN.elapsed().as_micros() as u32
}
