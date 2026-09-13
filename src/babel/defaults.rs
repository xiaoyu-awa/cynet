use std::time::Duration;

pub const MULTICAST_HELLO_INTERVAL: Duration = Duration::from_secs(4);

// Relative to the Multicast Hello interval.
pub const IHU_INTERVAL_FACTOR: u8 = 3;

// Relative to the Multicast Hello interval.
pub const UPDATE_INTERVAL_FACTOR: u32 = 4;

// Relative to the advertised IHU interval.
pub const IHU_HOLD_TIME_FACTOR: f64 = 3.5;

// Relative to the advertised Update interval.
pub const ROUTE_EXPIRY_TIME_FACTOR: f64 = 3.5;

pub const INITIAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

pub const MAX_REQUEST_TIMEOUT_COUNT: u8 = 3;

pub const URGENT_TIMEOUT: Duration = Duration::from_millis(200);

pub const SOURCE_GC_TIME: Duration = Duration::from_mins(3);
