/// A deterministic clock trait for no_std environments.
pub trait Clock {
    fn now_micros(&self) -> u64;
}

#[cfg(feature = "std")]
pub struct StdClock;

#[cfg(feature = "std")]
impl Clock for StdClock {
    fn now_micros(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Clock moved backwards")
            .as_micros() as u64
    }
}

pub struct ManualClock {
    pub micros: u64,
}

impl Clock for ManualClock {
    fn now_micros(&self) -> u64 {
        self.micros
    }
}
