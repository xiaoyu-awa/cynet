#[cfg(test)]
mod tests;

use std::{
    num::{NonZeroU16, NonZeroU64},
    ops::{Add, AddAssign, Sub},
    sync::LazyLock,
    time::Duration,
};

use tokio::time::Instant;

pub const COST_INFINITY: u16 = 0xffff;
pub const METRIC_INFINITY: u16 = 0xffff;

/// A router-id, assumed unique across the routing domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
pub enum Ae {
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

impl Ae {
    /// Creates an `Ae` from a `u8`, returning `None` if it is greater than `4`.
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

impl AddAssign<u16> for Seqno {
    fn add_assign(&mut self, rhs: u16) {
        self.0 = self.0.wrapping_add(rhs);
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
    /// Creates an `Interval` of `n` centiseconds, returning `None` if it equals `0`.
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

    /// Converts a [`Duration`] to an `Interval`, rounding towards zero,
    /// returning `None` if the result is out of range.
    pub fn from_duration(d: Duration) -> Option<Self> {
        const MAX_D: Duration = Duration::from_nanos(655_359_999_999);

        if d <= MAX_D {
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
    /// The rest of the neighbour entry should be flushed. The Hello history
    /// itself has already been restarted or emptied.
    Flush,
}

/// A Hello history with 16 entries.
pub struct HelloHistory {
    bits: u16,
    ne: Seqno,
}

impl HelloHistory {
    /// Creates an empty Hello history, which accepts any seqno next.
    pub fn new() -> Self {
        Self {
            bits: 0,
            ne: Seqno(0),
        }
    }

    /// Extracts the history bits, where a 1 bit represents a received Hello,
    /// a 0 bit a missed Hello, and the least significant bit the most recent Hello.
    pub fn bits(&self) -> u16 {
        self.bits
    }

    /// Returns the expected seqno.
    #[cfg(test)]
    pub fn expected_seqno(&self) -> Seqno {
        self.ne
    }

    /// Updates the history with the seqno of a received Hello,
    /// returning an effect that should be applied to the state.
    pub fn received(&mut self, nr: Seqno) -> HelloEffect {
        if self.bits == 0 {
            self.bits = 1;
            self.ne = nr + 1;
            return HelloEffect::None;
        }

        let diff = nr - self.ne;
        let abs_diff = u32::from(diff.unsigned_abs());

        if abs_diff > 16 {
            self.bits = 1;
            self.ne = nr + 1;
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
        self.ne += 1;

        if self.bits == 0 {
            HelloEffect::Flush
        } else {
            HelloEffect::None
        }
    }
}

/// The instant timestamps count from, and a random value added to them.
static TIMESTAMP_ORIGIN_OFFSET: LazyLock<(Instant, u32)> =
    LazyLock::new(|| (Instant::now(), rand::random()));

/// Returns the current time in microseconds, modulo 2^32, from an arbitrary origin.
pub fn timestamp_now() -> u32 {
    let (origin, offset) = *TIMESTAMP_ORIGIN_OFFSET;
    let now = Instant::now();

    // Only the paused clock of a test can read earlier than the origin, which the first
    // call sets. Count back from the origin then, rounding down as `as_micros` does when
    // counting forward, so that differences between timestamps stay exact.
    let micros = match now.checked_duration_since(origin) {
        Some(elapsed) => elapsed.as_micros() as u32,
        None => ((origin - now).as_nanos().div_ceil(1000) as u32).wrapping_neg(),
    };
    offset.wrapping_add(micros)
}
