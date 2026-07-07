//! Minimal Prometheus-compatible metrics rendering/server for chronosd.

use crate::udp_relay::UdpRelayMetrics;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

pub fn render_prometheus(metrics: UdpRelayMetrics) -> String {
    let fields = [
        ("packets_received", metrics.packets_received),
        ("packets_forwarded", metrics.packets_forwarded),
        ("acks_sent", metrics.acks_sent),
        ("errors_sent", metrics.errors_sent),
        ("no_route_errors", metrics.no_route_errors),
        ("queue_full_errors", metrics.queue_full_errors),
        ("route_packets_peeled", metrics.route_packets_peeled),
        ("data_packets_delivered", metrics.data_packets_delivered),
    ];
    let mut out = String::new();
    for (name, value) in fields {
        out.push_str(&format!("# TYPE chronosd_{name} counter\n"));
        out.push_str(&format!("chronosd_{name} {value}\n"));
    }
    out
}

pub async fn serve_metrics(
    bind_addr: &str,
    metrics: Arc<Mutex<UdpRelayMetrics>>,
) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(bind_addr).await?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let snapshot = *metrics.lock().expect("metrics lock");
        let body = render_prometheus(snapshot);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prometheus_renderer_includes_counters() {
        let metrics = UdpRelayMetrics {
            packets_received: 1,
            packets_forwarded: 2,
            acks_sent: 3,
            errors_sent: 4,
            no_route_errors: 5,
            queue_full_errors: 6,
            route_packets_peeled: 7,
            data_packets_delivered: 8,
        };
        let text = render_prometheus(metrics);
        assert!(text.contains("chronosd_packets_received 1"));
        assert!(text.contains("chronosd_queue_full_errors 6"));
        assert!(text.contains("chronosd_data_packets_delivered 8"));
    }
}
