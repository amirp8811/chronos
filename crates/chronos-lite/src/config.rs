//! Minimal std-only configuration loader for `chronos-lite`.
//!
//! This intentionally parses only the simple TOML subset used by the bundled
//! `configs/chronos-lite.toml` file. It avoids adding a general TOML dependency
//! while still wiring real configuration into the daemon.

use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChronosLiteConfig {
    pub node_name: String,
    pub node_id_fp: String,
    pub operating_role: String,
    pub jurisdiction: String,
    pub interface: String,
    pub engine: String,
    pub sqpoll_enabled: bool,
    pub register_memory_buffers: bool,
    pub enable_dpf_pir_engine: bool,
    pub max_shard_buckets: usize,
    pub epoch_snapshot_interval_sec: u64,
    pub merkle_root_publishing: bool,
    pub http_cache_control_ttl_sec: u64,
    pub enable_webrtc_ice_stun_turn: bool,
    pub turn_reflector_guard_endpoints: Vec<String>,
}

impl Default for ChronosLiteConfig {
    fn default() -> Self {
        Self {
            node_name: "chronos-lite-local".to_string(),
            node_id_fp: "local-dev-node.chr".to_string(),
            operating_role: "dpf_storage_relay".to_string(),
            jurisdiction: "local".to_string(),
            interface: "lo".to_string(),
            engine: "tokio_udp_local".to_string(),
            sqpoll_enabled: false,
            register_memory_buffers: false,
            enable_dpf_pir_engine: true,
            max_shard_buckets: 100_000,
            epoch_snapshot_interval_sec: 60,
            merkle_root_publishing: true,
            http_cache_control_ttl_sec: 600,
            enable_webrtc_ice_stun_turn: false,
            turn_reflector_guard_endpoints: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Io(String),
    InvalidLine(String),
    InvalidBool(String),
    InvalidInteger(String),
    InvalidArray(String),
}

pub fn load_chronos_lite_config(path: impl AsRef<Path>) -> Result<ChronosLiteConfig, ConfigError> {
    let text = fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    parse_chronos_lite_config(&text)
}

pub fn parse_chronos_lite_config(text: &str) -> Result<ChronosLiteConfig, ConfigError> {
    let mut cfg = ChronosLiteConfig::default();
    let mut section = String::new();
    let mut pending_array: Option<(String, Vec<String>)> = None;

    for raw_line in text.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if let Some((key, values)) = &mut pending_array {
            if line == "]" {
                apply_array(&mut cfg, key, values.clone())?;
                pending_array = None;
                continue;
            }
            let value = line.trim_end_matches(',').trim();
            values.push(parse_string(value)?);
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| ConfigError::InvalidLine(line.to_string()))?;
        let key = key.trim();
        let value = value.trim();
        let fq_key = format!("{section}.{key}");

        if value == "[" {
            pending_array = Some((fq_key, Vec::new()));
            continue;
        }

        apply_scalar(&mut cfg, &fq_key, value)?;
    }

    if let Some((key, _)) = pending_array {
        return Err(ConfigError::InvalidArray(key));
    }

    Ok(cfg)
}

fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '"' => in_string = !in_string,
            '#' if !in_string => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn parse_string(value: &str) -> Result<String, ConfigError> {
    let value = value.trim();
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        Ok(value[1..value.len() - 1].to_string())
    } else {
        Err(ConfigError::InvalidLine(value.to_string()))
    }
}

fn parse_bool(value: &str) -> Result<bool, ConfigError> {
    match value.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(ConfigError::InvalidBool(other.to_string())),
    }
}

fn parse_u64(value: &str) -> Result<u64, ConfigError> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| ConfigError::InvalidInteger(value.to_string()))
}

fn parse_usize(value: &str) -> Result<usize, ConfigError> {
    value
        .trim()
        .parse::<usize>()
        .map_err(|_| ConfigError::InvalidInteger(value.to_string()))
}

fn apply_scalar(cfg: &mut ChronosLiteConfig, key: &str, value: &str) -> Result<(), ConfigError> {
    match key {
        "node.node_name" => cfg.node_name = parse_string(value)?,
        "node.node_id_fp" => cfg.node_id_fp = parse_string(value)?,
        "node.operating_role" => cfg.operating_role = parse_string(value)?,
        "node.jurisdiction" => cfg.jurisdiction = parse_string(value)?,
        "data_plane.interface" => cfg.interface = parse_string(value)?,
        "data_plane.engine" => cfg.engine = parse_string(value)?,
        "data_plane.sqpoll_enabled" => cfg.sqpoll_enabled = parse_bool(value)?,
        "data_plane.register_memory_buffers" => cfg.register_memory_buffers = parse_bool(value)?,
        "storage_relay.enable_dpf_pir_engine" => cfg.enable_dpf_pir_engine = parse_bool(value)?,
        "storage_relay.max_shard_buckets" => cfg.max_shard_buckets = parse_usize(value)?,
        "storage_relay.epoch_snapshot_interval_sec" => {
            cfg.epoch_snapshot_interval_sec = parse_u64(value)?;
        }
        "storage_relay.merkle_root_publishing" => cfg.merkle_root_publishing = parse_bool(value)?,
        "storage_relay.http_cache_control_ttl_sec" => {
            cfg.http_cache_control_ttl_sec = parse_u64(value)?;
        }
        "nat_traversal.enable_webrtc_ice_stun_turn" => {
            cfg.enable_webrtc_ice_stun_turn = parse_bool(value)?;
        }
        _ => {}
    }
    Ok(())
}

fn apply_array(
    cfg: &mut ChronosLiteConfig,
    key: &str,
    values: Vec<String>,
) -> Result<(), ConfigError> {
    match key {
        "nat_traversal.turn_reflector_guard_endpoints" => {
            cfg.turn_reflector_guard_endpoints = values;
            Ok(())
        }
        _ => Err(ConfigError::InvalidArray(key.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[node]
node_name = "node-a"
node_id_fp = "node-a.chr"
operating_role = "dpf_storage_relay" # inline comment
jurisdiction = "EU"

[data_plane]
interface = "wlan0"
engine = "io_uring_direct_batching"
sqpoll_enabled = true
register_memory_buffers = false

[storage_relay]
enable_dpf_pir_engine = true
max_shard_buckets = 123
epoch_snapshot_interval_sec = 60
merkle_root_publishing = true
http_cache_control_ttl_sec = 600

[nat_traversal]
enable_webrtc_ice_stun_turn = true
turn_reflector_guard_endpoints = [
  "turn:guard1.example:3478",
  "turn:guard2.example:3478"
]
"#;

    #[test]
    fn parses_bundled_config_subset() {
        let cfg = parse_chronos_lite_config(SAMPLE).expect("config");
        assert_eq!(cfg.node_name, "node-a");
        assert_eq!(cfg.interface, "wlan0");
        assert!(cfg.sqpoll_enabled);
        assert!(!cfg.register_memory_buffers);
        assert_eq!(cfg.max_shard_buckets, 123);
        assert_eq!(cfg.turn_reflector_guard_endpoints.len(), 2);
    }

    #[test]
    fn rejects_invalid_bool() {
        let err = parse_chronos_lite_config("[data_plane]\nsqpoll_enabled = maybe")
            .expect_err("invalid bool");
        assert_eq!(err, ConfigError::InvalidBool("maybe".to_string()));
    }

    #[test]
    fn defaults_missing_values() {
        let cfg =
            parse_chronos_lite_config("[node]\nnode_name = \"minimal\"").expect("minimal config");
        assert_eq!(cfg.node_name, "minimal");
        assert_eq!(cfg.max_shard_buckets, 100_000);
    }
}
