use std::time::Duration;

use crate::babel::base::Interval;

pub struct Params {
    mtu: u16,
    hello_interval: Interval,
    ihu_interval: Interval,
    update_interval: Interval,
    tau: u32,
}

impl Params {
    pub fn new() -> Self {
        Self {
            mtu: 1400,
            hello_interval: Interval::new(400).unwrap(),
            ihu_interval: Interval::new(400 * 3).unwrap(),
            update_interval: Interval::new(400 * 4).unwrap(),
            tau: 4_000_000 * 3,
        }
    }

    pub fn get_mtu(&self) -> u16 {
        self.mtu
    }

    pub fn set_mtu(&mut self, mtu: u16) -> &mut Self {
        assert!(mtu >= 1280);
        self.mtu = mtu;
        self
    }

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

    pub fn get_duration(&self, key: DurationKey) -> Duration {
        match key {
            DurationKey::HelloInterval => self.hello_interval.to_duration(),
            DurationKey::IhuInterval => self.ihu_interval.to_duration(),
            DurationKey::UpdateInterval => self.update_interval.to_duration(),
            DurationKey::InitialRequestTimeout => Duration::from_secs(2),
            DurationKey::UrgentTimeout => Duration::from_millis(200),
            DurationKey::SourceGcTime => Duration::from_mins(3),
            DurationKey::RouteHoldTime => self.update_interval.to_duration() * 4,
        }
    }

    pub fn get_interval(&self, key: IntervalKey) -> Interval {
        match key {
            IntervalKey::Hello => self.hello_interval,
            IntervalKey::Ihu => self.ihu_interval,
            IntervalKey::Update => self.update_interval,
        }
    }

    pub fn get_f64(&self, key: F64Key) -> f64 {
        match key {
            F64Key::IhuHoldTimeMultiplier => 3.5,
            F64Key::RouteExpiryTimeMultiplier => 3.5,
            F64Key::RequestBackoffFactor => 2.0,
        }
    }

    pub fn get_u8(&self, key: U8Key) -> u8 {
        match key {
            U8Key::HellosPerIhu => 3,
            U8Key::RequestMaxResends => 3,
        }
    }

    /// Returns the time constant for route hysteresis, in microseconds.
    /// Defaults to 3 times the Hello interval.
    pub fn get_tau(&self) -> u32 {
        self.tau
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurationKey {
    /// Hello interval. Defaults to 4 seconds.
    HelloInterval,
    /// IHU interval. Defaults to 3 times the Hello interval.
    IhuInterval,
    /// Update interval. Defaults to 4 times the Hello interval.
    UpdateInterval,
    /// Initial request timeout. Defaults to 2 seconds.
    InitialRequestTimeout,
    /// Urgent timeout. Defaults to 0.2 seconds.
    UrgentTimeout,
    /// Source GC time. Defaults to 3 minutes.
    SourceGcTime,
    /// Route hold time. Defaults to 4 times the Update interval.
    RouteHoldTime,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum F64Key {
    /// IHU Hold time, relative to the advertised IHU interval. Defaults to 3.5.
    IhuHoldTimeMultiplier,
    /// Route Expiry time, relative to the advertised Update interval. Defaults to 3.5.
    RouteExpiryTimeMultiplier,
    /// Request timeout, relative to the previous Request timeout
    /// when a request is resent. Defaults to 2.0.
    RequestBackoffFactor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum U8Key {
    /// The number of Hello TLVs sent per IHU TLV. Defaults to 3.
    HellosPerIhu,
    /// The maximum number of times a request can be resent. Defaults to 3.
    RequestMaxResends,
}
