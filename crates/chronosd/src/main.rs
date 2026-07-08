//! `chronosd` — Core Bare-Metal Relay Daemon
//! CHRONOS-SPEC-v7.0 Section 3

mod af_xdp_proto;
mod cache_resctrl;
mod config;
mod dataplane_probe;
mod io_uring_proto;
mod metrics;
mod mixing_engine;
mod nic_control;
mod queue;
mod socket_tiering;
mod toeplitz_rss;
mod udp_relay;

use af_xdp_proto::plan_af_xdp;
use cache_resctrl::L3CacheLocker;
use chronos_core::framing::UmemFrameDescriptor;
use chronos_core::{NodeKeyMaterial, PowChallenge};
use config::{ChronosdConfig, load_chronosd_config};
use dataplane_probe::choose_data_plane;
use io_uring_proto::plan_io_uring;
use log::{info, warn};
use mixing_engine::BitonicSortingEngine;
use socket_tiering::SocketTieringManager;
use std::time::Duration;
use toeplitz_rss::ToeplitzSaltShuffler;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================================");
    println!("         CHRONOS v7.0: CORE RELAY DAEMON (`chronosd`) - LEVEL 14         ");
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
        if config.tdm_slot_ms > 0 {
            relay.enable_tdm_pacing(std::time::Duration::from_millis(config.tdm_slot_ms));
        }
        if config.enable_pow_client_puzzles {
            let mut relay_id = [0u8; 16];
            let fp = config.node_id_fp.as_bytes();
            let n = fp.len().min(16);
            relay_id[..n].copy_from_slice(&fp[..n]);
            relay.enable_pow_admission(PowChallenge {
                relay_id,
                unix_window: 0,
                difficulty_zero_bits: config.pow_default_difficulty_zero_bits,
                token: [0; 32],
            });
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

    info!("Daemon initialized successfully. Entering active TDM event loop.");

    // Simulate 3 iterations of monitoring & sorting
    let mut simulated_umem_pool: Vec<UmemFrameDescriptor> =
        (0..64).map(|_| UmemFrameDescriptor::new()).collect();
    for epoch in 1..=3 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        info!(
            "Epoch #{:02} active | Pacing: 81.92 ns TDM | Wire Budget: 1,280B | Saturation: 100%",
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
