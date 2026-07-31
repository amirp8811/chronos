#![deny(unsafe_code)]
//! `chronosd` — experimental relay daemon.

mod cache_resctrl;
mod config;
mod dataplane_probe;
mod metrics;
mod mixing_engine;
mod nic_control;
mod queue;
mod socket_tiering;
mod toeplitz_rss;
mod udp_relay;

use cache_resctrl::L3CacheLocker;
use chronos_core::NodeKeyMaterial;
use chronos_core::framing::UmemFrameDescriptor;
use chronos_sys_dataplane::af_xdp_proto::plan_af_xdp;
use chronos_sys_dataplane::io_uring_proto::plan_io_uring;
use config::{ChronosdConfig, load_chronosd_config};
use dataplane_probe::choose_data_plane;
use log::{info, warn};
use mixing_engine::BitonicSortingEngine;
use socket_tiering::SocketTieringManager;
use std::time::Duration;
use toeplitz_rss::ToeplitzSaltShuffler;

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

    // 1. Initialize L3 Cache Locking
    let cache_locker = L3CacheLocker::new(config.l3_cache_slice_mb);
    if let Err(e) = cache_locker.lock_to_current_thread() {
        warn!(
            "L3 cache locking skipped: {}. Proceeding in non-isolated CAT mode.",
            e
        );
    }

    // 2. Initialize Data-Plane Tiering Policy
    let probe = choose_data_plane(&config.interface, &config.preferred_engine);
    let io_plan = plan_io_uring(&config.interface, &config.preferred_engine, 64);
    let xdp_plan = plan_af_xdp(&config.interface, &config.preferred_engine, 64);
    info!(
        "Data-plane probe selected {:?}: {} | io_uring(enabled={}, buffers={}) | af_xdp(enabled={}, frames={})",
        probe.mode,
        probe.reason,
        io_plan.enabled,
        io_plan.registered_buffers,
        xdp_plan.enabled,
        xdp_plan.umem_frames
    );
    let mut socket_manager = SocketTieringManager::new(&config.interface);
    socket_manager.initialize()?;

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

    // 3. Initialize Dynamic Toeplitz Salt Shuffler
    let mut toeplitz =
        ToeplitzSaltShuffler::new(&config.interface, config.toeplitz_rss_threshold_req_sec);

    // 4. Initialize SIMD Bitonic Mixing Engine
    let mixing_engine = BitonicSortingEngine::new(5.0, 64);

    info!("Daemon prototype initialized; running local demonstration loop.");

    // Simulate 3 iterations of monitoring & sorting
    let mut simulated_umem_pool: Vec<UmemFrameDescriptor> =
        (0..64).map(|_| UmemFrameDescriptor::new()).collect();
    for epoch in 1..=3 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        info!(
            "Demonstration epoch #{:02} active | model wire budget: 1,280B",
            epoch
        );

        let _ = mixing_engine.sort_micro_batch_in_place(&mut simulated_umem_pool);

        if epoch == 2 {
            toeplitz.check_and_shuffle(180_000, 4);
        }
    }

    info!("Daemon simulation loop completed cleanly. Terminating.");
    Ok(())
}
