use std::time::Duration;

use crate::babel::base::Interval;

pub struct Params {
    mtu: u16,
    hello_interval: Duration,
}

impl Params {
    pub fn new() -> Self {
        Self {
            mtu: 1400,
            hello_interval: Duration::from_secs(4),
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

    pub fn set_hello_interval(&mut self, d: Duration) -> &mut Self {
        self.hello_interval = d;
        for key in [IntervalKey::Hello, IntervalKey::Ihu, IntervalKey::Update] {
            // Verify all intervals are within range.
            let _ = self.get_interval(key);
        }
        self
    }

    pub fn get_duration(&self, key: DurationKey) -> Duration {
        match key {
            DurationKey::HelloInterval => self.hello_interval,
            DurationKey::IhuInterval => {
                self.hello_interval * self.get_u8(U8Key::HellosPerIhu) as u32
            }
            DurationKey::UpdateInterval => self.hello_interval * 4,
            DurationKey::InitialRequestTimeout => Duration::from_secs(2),
            DurationKey::UrgentTimeout => Duration::from_millis(200),
            DurationKey::SourceGcTime => Duration::from_mins(3),
            DurationKey::RouteHoldTime => self.hello_interval * 4 * 4,
            DurationKey::RouteHysteresisTimeConstant => self.hello_interval * 3,
        }
    }

    pub fn get_interval(&self, key: IntervalKey) -> Interval {
        let dur_key = match key {
            IntervalKey::Hello => DurationKey::HelloInterval,
            IntervalKey::Ihu => DurationKey::IhuInterval,
            IntervalKey::Update => DurationKey::UpdateInterval,
        };
        let int = Interval::from_duration(self.get_duration(dur_key))
            .expect("interval should be within range");

        assert_ne!(
            (key, int.get()),
            (IntervalKey::Update, u16::MAX),
            "Update interval should not be 0xFFFF"
        );
        int
    }

    pub fn get_f64(&self, key: F64Key) -> f64 {
        match key {
            F64Key::IhuHoldTimeMultiplier => 3.5,
            F64Key::RouteExpiryTimeMultiplier => 3.5,
            F64Key::RequestBackoffFactor => 2.0,
            F64Key::HelloTimeoutMultiplier => 1.5,
            F64Key::BufferTimeoutMultiplier => 0.5,
        }
    }

    pub fn get_u8(&self, key: U8Key) -> u8 {
        match key {
            U8Key::HellosPerIhu => 3,
            U8Key::RequestMaxResends => 3,
        }
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
    /// Route hysteresis time constant. Defaults to 3 times the Hello interval.
    RouteHysteresisTimeConstant,
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
    /// The maximum timeout within which a Hello TLV should be received,
    /// relative to the advertised Hello interval. Defaults to 1.5.
    HelloTimeoutMultiplier,
    /// The maximum timeout within which a TLV should be sent out, relative to
    /// the Hello interval or the Acknowledgement Request interval. Defaults to 0.5.
    BufferTimeoutMultiplier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum U8Key {
    /// The number of Hello TLVs sent per IHU TLV. Defaults to 3.
    HellosPerIhu,
    /// The maximum number of times a request can be resent. Defaults to 3.
    RequestMaxResends,
}
