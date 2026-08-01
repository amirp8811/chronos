#![deny(unsafe_code)]
//! `chronosd` — experimental relay daemon.

#[cfg(test)]
mod dataplane_probe;
#[cfg(test)]
mod mixing_engine;
#[cfg(test)]
mod nic_control;

use chronos_core::NodeKeyMaterial;
use chronosd::config::{ChronosdConfig, load_chronosd_config};
use chronosd::{metrics, udp_relay};
use log::{info, warn};

fn parse_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = value.as_bytes()[index * 2];
        let low = value.as_bytes()[index * 2 + 1];
        *byte = (hex_nibble(high)? << 4) | hex_nibble(low)?;
    }
    Some(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================================");
    println!("         CHRONOS v7.0: CORE RELAY DAEMON (`chronosd`)         ");
    println!("================================================================================");

    info!("Initializing CHRONOS core relay daemon on bare-metal / cloud infrastructure...");

    let config_path =
        std::env::var("CHRONOSD_CONFIG").unwrap_or_else(|_| "configs/chronosd.toml".to_string());
    let config = load_chronosd_config(&config_path).unwrap_or_else(|e| {
        warn!(
            "Could not load chronosd config at {} ({:?}); using defaults.",
            config_path, e
        );
        ChronosdConfig::default()
    });
    let key_dir = std::env::var("CHRONOSD_KEY_DIR").unwrap_or_else(|_| config.key_dir.clone());
    let _node_keys = NodeKeyMaterial::load_or_generate(&key_dir)
        .map_err(|e| format!("key store error: {e:?}"))?;
    info!(
        "Loaded node '{}' ({}) role={} jurisdiction={} key_dir={}",
        config.node_name, config.node_id_fp, config.operating_role, config.jurisdiction, key_dir
    );

    let configured_bind = std::env::var("CHRONOSD_UDP_RELAY_BIND")
        .ok()
        .or_else(|| config.udp_relay_bind.clone());
    if let Some(bind_addr) = configured_bind {
        let route_table = if std::env::var("CHRONOSD_STATIC_ROUTES").is_ok() {
            udp_relay::StaticRouteTable::from_env("CHRONOSD_STATIC_ROUTES")
        } else {
            udp_relay::StaticRouteTable::from_spec(&config.static_routes)
        };
        info!(
            "Starting experimental UDP relay service on {} with {} static routes.",
            bind_addr,
            route_table.len()
        );
        let mut relay = udp_relay::ChronosUdpRelay::bind_with_runtime_config(
            &bind_addr,
            route_table,
            config.route_replay_max_entries,
            std::time::Duration::from_secs(config.route_replay_ttl_seconds),
            config.outbound_queue_max,
        )
        .await?;
        relay.enable_handshake(_node_keys.clone())?;
        relay.set_session_enforcement(config.enforce_sessions);
        if config.send_delay_ms > 0 {
            relay.enable_send_delay(std::time::Duration::from_millis(config.send_delay_ms));
        }
        if config.enable_pow_client_puzzles {
            let env_name = config
                .pow_secret_env
                .as_deref()
                .ok_or("PoW is enabled but security.pow_secret_env is not configured")?;
            let secret_value = std::env::var(env_name)
                .map_err(|_| format!("PoW is enabled but {env_name} is unavailable"))?;
            let server_secret = parse_hex_32(&secret_value)
                .ok_or("PoW secret must be exactly 32 bytes of hexadecimal")?;
            let mut relay_id = [0u8; 16];
            let fingerprint = config.node_id_fp.as_bytes();
            let length = fingerprint.len().min(relay_id.len());
            relay_id[..length].copy_from_slice(&fingerprint[..length]);
            relay.enable_pow_admission(udp_relay::PowAdmissionConfig::new(
                relay_id,
                server_secret,
                config.pow_default_difficulty_zero_bits,
                config.pow_window_seconds,
            )?)?;
        }
        let route_secret_count = if std::env::var("CHRONOSD_ROUTE_SECRETS").is_ok() {
            relay.apply_route_secrets_from_env("CHRONOSD_ROUTE_SECRETS")?
        } else {
            relay.apply_route_secrets_spec(&config.route_secrets)?
        };
        info!(
            "UDP relay bound to {} with {} route-hop secrets.",
            relay.local_addr()?,
            route_secret_count
        );
        if let Some(metrics_bind) = config.metrics_bind.clone() {
            let metrics_handle = relay.metrics_handle();
            tokio::spawn(async move {
                let _ = metrics::serve_metrics(&metrics_bind, metrics_handle).await;
            });
        }
        relay.run_forever().await?;
        return Ok(());
    }

    info!(
        "Relay is inactive: set CHRONOSD_UDP_RELAY_BIND or runtime.udp_relay_bind to start the experimental UDP service."
    );
    Ok(())
}
