use std::sync::atomic::{AtomicU64, Ordering};

pub struct ChronosMetrics {
    pub packets_processed: AtomicU64,
    pub active_sessions: AtomicU64,
    pub timing_leak_variance: AtomicU64, // scaled fixed-point
}

impl ChronosMetrics {
    pub fn new() -> Self {
        Self {
            packets_processed: AtomicU64::new(0),
            active_sessions: AtomicU64::new(0),
            timing_leak_variance: AtomicU64::new(0),
        }
    }

    pub fn increment_packets(&self) {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn to_prometheus_format(&self) -> String {
        format!(
            "chronos_packets_total {}\nchronos_sessions_active {}\n",
            self.packets_processed.load(Ordering::Relaxed),
            self.active_sessions.load(Ordering::Relaxed)
        )
    }
}
