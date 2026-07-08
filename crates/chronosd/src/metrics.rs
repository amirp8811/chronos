use chronos_core::mix_policy::MixTelemetry;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::udp_relay::UdpRelayMetrics;

#[allow(dead_code)]
pub struct ChronosMetrics {
    pub packets_processed: AtomicU64,
    pub active_sessions: AtomicU64,
    pub timing_leak_variance: AtomicU64, // scaled fixed-point
    pub mix_flushes_full: AtomicU64,
    pub mix_flushes_reduced: AtomicU64,
    pub mix_flushes_cover: AtomicU64,
    pub mix_cover_packets: AtomicU64,
    pub mix_real_packets: AtomicU64,
}

#[allow(dead_code)]
impl ChronosMetrics {
    pub fn new() -> Self {
        Self {
            packets_processed: AtomicU64::new(0),
            active_sessions: AtomicU64::new(0),
            timing_leak_variance: AtomicU64::new(0),
            mix_flushes_full: AtomicU64::new(0),
            mix_flushes_reduced: AtomicU64::new(0),
            mix_flushes_cover: AtomicU64::new(0),
            mix_cover_packets: AtomicU64::new(0),
            mix_real_packets: AtomicU64::new(0),
        }
    }

    pub fn increment_packets(&self) {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_mix_telemetry(&self, t: &MixTelemetry) {
        self.mix_flushes_full
            .store(t.flushes_full, Ordering::Relaxed);
        self.mix_flushes_reduced
            .store(t.flushes_reduced, Ordering::Relaxed);
        self.mix_flushes_cover
            .store(t.flushes_cover, Ordering::Relaxed);
        self.mix_cover_packets
            .store(t.total_cover_packets_emitted, Ordering::Relaxed);
        self.mix_real_packets
            .store(t.total_real_packets_flushed, Ordering::Relaxed);
    }

    pub fn to_prometheus_format(&self) -> String {
        format!(
            "chronos_packets_total {}\n\
chronos_sessions_active {}\n\
chronos_mix_flushes_full {}\n\
chronos_mix_flushes_reduced {}\n\
chronos_mix_flushes_cover {}\n\
chronos_mix_cover_packets_total {}\n\
chronos_mix_real_packets_total {}\n",
            self.packets_processed.load(Ordering::Relaxed),
            self.active_sessions.load(Ordering::Relaxed),
            self.mix_flushes_full.load(Ordering::Relaxed),
            self.mix_flushes_reduced.load(Ordering::Relaxed),
            self.mix_flushes_cover.load(Ordering::Relaxed),
            self.mix_cover_packets.load(Ordering::Relaxed),
            self.mix_real_packets.load(Ordering::Relaxed),
        )
    }
}

impl Default for ChronosMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal Prometheus-ish text exporter over TCP for relay metrics.
pub async fn serve_metrics(
    bind: &str,
    metrics: Arc<Mutex<UdpRelayMetrics>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(bind).await?;
    loop {
        let (mut socket, _) = listener.accept().await?;
        let snapshot = {
            let guard = metrics.lock().unwrap_or_else(|e| e.into_inner());
            format!(
                "chronos_udp_packets_received {}\nchronos_udp_packets_forwarded {}\nchronos_udp_acks_sent {}\nchronos_udp_errors_sent {}\nchronos_udp_no_route_errors {}\nchronos_udp_queue_full_errors {}\nchronos_udp_route_packets_peeled {}\nchronos_udp_data_packets_delivered {}\n",
                guard.packets_received,
                guard.packets_forwarded,
                guard.acks_sent,
                guard.errors_sent,
                guard.no_route_errors,
                guard.queue_full_errors,
                guard.route_packets_peeled,
                guard.data_packets_delivered,
            )
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            snapshot.len(),
            snapshot
        );
        let _ = socket.write_all(response.as_bytes()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chronos_core::mix_policy::MixTelemetry;

    #[test]
    fn prometheus_includes_mix_series() {
        let m = ChronosMetrics::new();
        let t = MixTelemetry {
            flushes_full: 3,
            total_cover_packets_emitted: 10,
            ..Default::default()
        };
        m.record_mix_telemetry(&t);
        let s = m.to_prometheus_format();
        assert!(s.contains("chronos_mix_flushes_full 3"));
        assert!(s.contains("chronos_mix_cover_packets_total 10"));
    }
}
