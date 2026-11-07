use std::time::Duration;

use crate::babel::base::Interval;

/// The parameters of a Babel router. Only the MTU and the Hello interval can be set; the
/// others are fixed or derived from the Hello interval.
pub struct Params {
    mtu: u16,
    hello_interval: Interval,
    ihu_interval: Interval,
    update_interval: Interval,
    /// Whether the Hello and Update timers are randomized.
    randomize_timers: bool,
    tau: u32,
}

impl Params {
    /// The default MTU of the links, in octets.
    pub const DEFAULT_MTU: u16 = 1400;

    /// The smallest MTU of the links, in octets, which is the minimum MTU of IPv6 (RFC 8200 §5).
    pub const MIN_MTU: u16 = 1280;

    /// Returns the default parameters.
    #[expect(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            mtu: Self::DEFAULT_MTU,
            hello_interval: Interval::new(400).unwrap(),
            ihu_interval: Interval::new(400 * 3).unwrap(),
            update_interval: Interval::new(400 * 4).unwrap(),
            randomize_timers: true,
            tau: 4_000_000 * 3,
        }
    }

    /// Returns the MTU of the links, in octets.
    pub fn get_mtu(&self) -> u16 {
        self.mtu
    }

    /// Sets the MTU of the links, in octets.
    ///
    /// # Panics
    ///
    /// Panics if `mtu` is less than [`Self::MIN_MTU`].
    pub fn set_mtu(&mut self, mtu: u16) -> &mut Self {
        assert!(mtu >= Self::MIN_MTU);
        self.mtu = mtu;
        self
    }

    /// Sets the Hello interval.
    ///
    /// # Panics
    ///
    /// Panics if `i` exceeds 163.83 s, as the Update interval would not fit in an
    /// [`Interval`].
    pub fn set_hello_interval(&mut self, i: Interval) -> &mut Self {
        const MAX_I: u16 = u16::MAX / 4;

        assert!(i.get() <= MAX_I, "Hello interval should not exceed 163.83s");

        self.hello_interval = i;
        self.ihu_interval = Interval::new(i.get() * 3).unwrap();
        self.update_interval = Interval::new(i.get() * 4).unwrap();
        // 3 times the Hello interval, in microseconds.
        self.tau = i.get() as u32 * 3 * 10_000;
        self
    }

    /// Sets whether the Hello and Update timers are randomized. Tests turn this off, so
    /// that Hellos and full dumps of routes follow their intervals exactly.
    #[cfg(test)]
    pub(crate) fn set_randomize_timers(&mut self, randomize: bool) -> &mut Self {
        self.randomize_timers = randomize;
        self
    }

    pub(crate) fn get<K: Key>(&self, key: K) -> K::Value {
        key.get(self)
    }

    /// Returns how long after the last report of a conflict over a prefix it no longer seems to go
    /// on (see [Duplicate addresses](crate::babel::State#duplicate-addresses)): 3.5 Update
    /// intervals, as for the expiry of a route. A conflict is reported about once per Update
    /// interval, at each full dump that brings an update to reject, so this outlasts the gap that
    /// one or two lost packets leave.
    pub fn get_conflict_expiry(&self) -> Duration {
        self.update_interval
            .to_duration()
            .mul_f64(F64Key::RouteExpiryTimeMultiplier.get(self))
    }

    /// Returns the time constant for route hysteresis, in microseconds.
    /// Defaults to 3 times the Hello interval.
    pub(crate) fn get_tau(&self) -> u32 {
        self.tau
    }

    /// Returns the timeout of a seqno request with `resends_left` resends left: how long
    /// it waits before the next resend, or after the last one, how long it is kept. This
    /// is the initial request timeout, doubled every time the request has been resent
    /// (RFC 8966 Appendix B).
    pub(crate) fn seqno_request_timeout(&self, resends_left: u8) -> Duration {
        let resends = self.get(U8Key::RequestMaxResends) - resends_left;
        let factor = self.get(F64Key::RequestBackoffFactor);
        self.get(DurationKey::InitialRequestTimeout)
            .mul_f64(factor.powi(resends.into()))
    }

    /// Returns the duration multiplied by a random number in the range from 0 to 1, or
    /// the whole duration if timers are not randomized.
    pub(crate) fn random_part(&self, key: DurationKey) -> Duration {
        let d = self.get(key);
        if !self.randomize_timers {
            return d;
        }
        d.mul_f64(rand::random())
    }

    /// Returns the duration multiplied by a random number in the range of 1 ± 0.03125, or
    /// the exact duration if timers are not randomized.
    pub(crate) fn jittered(&self, key: DurationKey) -> Duration {
        const J: f64 = 0.03125;

        let d = self.get(key);
        if !self.randomize_timers {
            return d;
        }
        d.mul_f64(rand::random_range(1.0 - J..1.0 + J))
    }
}

pub trait Key {
    type Value;

    fn get(self, params: &Params) -> Self::Value;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurationKey {
    /// Hello interval. Defaults to 4 seconds.
    HelloInterval,
    /// Update interval. Defaults to 4 times the Hello interval.
    UpdateInterval,
    /// Initial request timeout. Defaults to 2 seconds.
    InitialRequestTimeout,
    /// Urgent timeout. Defaults to 0.2 seconds.
    UrgentTimeout,
    /// How long to wait for the acknowledgement of a startup packet before sending it again, which
    /// doubles each time, up to the Hello interval. Defaults to 0.25 seconds.
    StartupTimeout,
    /// Source GC time. Defaults to 3 minutes.
    SourceGcTime,
    /// Route hold time. Defaults to 4 times the Update interval.
    RouteHoldTime,
    /// How long after sending a Conflict Alert for a prefix to a neighbour no other is sent for
    /// it to that neighbour. Defaults to half the Update interval, so that the alerts of
    /// rejections recurring at the period of full dumps all get through.
    ConflictAlertInterval,
}

impl Key for DurationKey {
    type Value = Duration;

    fn get(self, params: &Params) -> Duration {
        match self {
            DurationKey::HelloInterval => params.hello_interval.to_duration(),
            DurationKey::UpdateInterval => params.update_interval.to_duration(),
            DurationKey::InitialRequestTimeout => Duration::from_secs(2),
            DurationKey::UrgentTimeout => Duration::from_millis(200),
            DurationKey::StartupTimeout => Duration::from_millis(250),
            DurationKey::SourceGcTime => Duration::from_mins(3),
            DurationKey::RouteHoldTime => params.update_interval.to_duration() * 4,
            DurationKey::ConflictAlertInterval => params.update_interval.to_duration() / 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntervalKey {
    /// Hello interval. Defaults to 4 seconds.
    Hello,
    /// IHU interval. Defaults to 3 times the Hello interval.
    Ihu,
    /// Update interval. Defaults to 4 times the Hello interval.
    Update,
}

impl Key for IntervalKey {
    type Value = Interval;

    fn get(self, params: &Params) -> Interval {
        match self {
            IntervalKey::Hello => params.hello_interval,
            IntervalKey::Ihu => params.ihu_interval,
            IntervalKey::Update => params.update_interval,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum F64Key {
    /// IHU Hold time, relative to the advertised IHU interval. Defaults to 3.5.
    IhuHoldTimeMultiplier,
    /// Route Expiry time, relative to the advertised Update interval. Defaults to 3.5.
    RouteExpiryTimeMultiplier,
    /// The time after which a selected route that has not been updated is requested
    /// from its neighbour, relative to the advertised Update interval. Defaults to 2.5.
    RouteNearExpiryTimeMultiplier,
    /// Request timeout, relative to the previous Request timeout
    /// when a request is resent. Defaults to 2.0.
    RequestBackoffFactor,
}

impl Key for F64Key {
    type Value = f64;

    fn get(self, _: &Params) -> f64 {
        match self {
            F64Key::IhuHoldTimeMultiplier => 3.5,
            F64Key::RouteExpiryTimeMultiplier => 3.5,
            F64Key::RouteNearExpiryTimeMultiplier => 2.5,
            F64Key::RequestBackoffFactor => 2.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum U8Key {
    /// The number of Hello TLVs sent per IHU TLV. Defaults to 3.
    HellosPerIhu,
    /// The maximum number of times a request can be resent. Defaults to 3.
    RequestMaxResends,
}

impl Key for U8Key {
    type Value = u8;

    fn get(self, _: &Params) -> u8 {
        match self {
            U8Key::HellosPerIhu => 3,
            U8Key::RequestMaxResends => 3,
        }
    }
}
