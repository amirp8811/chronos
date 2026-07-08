//! Minimal std-only configuration loader for `chronosd`.

use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct ChronosdConfig {
    pub node_name: String,
    pub node_id_fp: String,
    pub operating_role: String,
    pub jurisdiction: String,
    pub interface: String,
    pub preferred_engine: String,
    pub enable_resctrl_l3_locking: bool,
    pub l3_cache_slice_mb: f64,
    pub enable_toeplitz_salt_shuffling: bool,
    pub toeplitz_rss_threshold_req_sec: u64,
    pub key_dir: String,
    pub udp_relay_bind: Option<String>,
    pub static_routes: String,
    pub route_secrets: String,
    pub route_replay_max_entries: usize,
    pub route_replay_ttl_seconds: u64,
    pub outbound_queue_max: usize,
    pub metrics_bind: Option<String>,
    pub enforce_sessions: bool,
    pub tdm_slot_ms: u64,
    pub enable_pow_client_puzzles: bool,
    pub pow_default_difficulty_zero_bits: u32,
}

impl Default for ChronosdConfig {
    fn default() -> Self {
        Self {
            node_name: "chronosd-local".to_string(),
            node_id_fp: "local-chronosd.chr".to_string(),
            operating_role: "core_relay".to_string(),
            jurisdiction: "local".to_string(),
            interface: "lo".to_string(),
            preferred_engine: "tokio_udp".to_string(),
            enable_resctrl_l3_locking: false,
            l3_cache_slice_mb: 4.0,
            enable_toeplitz_salt_shuffling: false,
            toeplitz_rss_threshold_req_sec: 31_250,
            key_dir: ".chronosd-keys".to_string(),
            udp_relay_bind: None,
            static_routes: String::new(),
            route_secrets: String::new(),
            route_replay_max_entries: 4096,
            route_replay_ttl_seconds: 300,
            outbound_queue_max: 1024,
            metrics_bind: None,
            enforce_sessions: false,
            tdm_slot_ms: 0,
            enable_pow_client_puzzles: false,
            pow_default_difficulty_zero_bits: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    Io(String),
    InvalidLine(String),
    InvalidBool(String),
    InvalidInteger(String),
    InvalidFloat(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ConfigError {}

pub fn load_chronosd_config(path: impl AsRef<Path>) -> Result<ChronosdConfig, ConfigError> {
    let text = fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    parse_chronosd_config(&text)
}

pub fn parse_chronosd_config(text: &str) -> Result<ChronosdConfig, ConfigError> {
    let mut cfg = ChronosdConfig::default();
    let mut section = String::new();
    for raw_line in text.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| ConfigError::InvalidLine(line.to_string()))?;
        apply_scalar(
            &mut cfg,
            &format!("{}.{}", section, key.trim()),
            value.trim(),
        )?;
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
    let v = value.trim();
    if v.starts_with('"') && v.ends_with('"') && v.len() >= 2 {
        Ok(v[1..v.len() - 1].to_string())
    } else {
        Err(ConfigError::InvalidLine(v.to_string()))
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
        .parse()
        .map_err(|_| ConfigError::InvalidInteger(value.to_string()))
}
fn parse_usize(value: &str) -> Result<usize, ConfigError> {
    value
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidInteger(value.to_string()))
}
fn parse_f64(value: &str) -> Result<f64, ConfigError> {
    value
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidFloat(value.to_string()))
}

fn apply_scalar(cfg: &mut ChronosdConfig, key: &str, value: &str) -> Result<(), ConfigError> {
    match key {
        "node.node_name" => cfg.node_name = parse_string(value)?,
        "node.node_id_fp" => cfg.node_id_fp = parse_string(value)?,
        "node.operating_role" => cfg.operating_role = parse_string(value)?,
        "node.jurisdiction" => cfg.jurisdiction = parse_string(value)?,
        "data_plane.interface" => cfg.interface = parse_string(value)?,
        "data_plane.preferred_engine" => cfg.preferred_engine = parse_string(value)?,
        "hardware_hardening.enable_resctrl_l3_locking" => {
            cfg.enable_resctrl_l3_locking = parse_bool(value)?
        }
        "hardware_hardening.l3_cache_slice_mb" => cfg.l3_cache_slice_mb = parse_f64(value)?,
        "hardware_hardening.enable_toeplitz_salt_shuffling" => {
            cfg.enable_toeplitz_salt_shuffling = parse_bool(value)?
        }
        "hardware_hardening.toeplitz_rss_threshold_req_sec" => {
            cfg.toeplitz_rss_threshold_req_sec = parse_u64(value)?
        }
        "runtime.key_dir" => cfg.key_dir = parse_string(value)?,
        "runtime.udp_relay_bind" => cfg.udp_relay_bind = Some(parse_string(value)?),
        "runtime.static_routes" => cfg.static_routes = parse_string(value)?,
        "runtime.route_secrets" => cfg.route_secrets = parse_string(value)?,
        "runtime.route_replay_max_entries" => cfg.route_replay_max_entries = parse_usize(value)?,
        "runtime.route_replay_ttl_seconds" => cfg.route_replay_ttl_seconds = parse_u64(value)?,
        "runtime.outbound_queue_max" => cfg.outbound_queue_max = parse_usize(value)?,
        "runtime.metrics_bind" => cfg.metrics_bind = Some(parse_string(value)?),
        "runtime.enforce_sessions" => cfg.enforce_sessions = parse_bool(value)?,
        "runtime.tdm_slot_ms" => cfg.tdm_slot_ms = parse_u64(value)?,
        "security.enable_pow_client_puzzles" => cfg.enable_pow_client_puzzles = parse_bool(value)?,
        "security.pow_default_difficulty_zero_bits" => {
            cfg.pow_default_difficulty_zero_bits = parse_u64(value)? as u32;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_chronosd_config_subset() {
        let cfg = parse_chronosd_config(
            r#"
[node]
node_name = "relay-a"
node_id_fp = "relay-a.chr"
operating_role = "core_relay"
jurisdiction = "GB"
[data_plane]
interface = "eth0"
preferred_engine = "tokio_udp"
[hardware_hardening]
enable_resctrl_l3_locking = true
l3_cache_slice_mb = 8.0
enable_toeplitz_salt_shuffling = true
toeplitz_rss_threshold_req_sec = 123
[runtime]
key_dir = "/tmp/chronosd-test"
udp_relay_bind = "127.0.0.1:7000"
static_routes = "1=127.0.0.1:7001"
route_replay_max_entries = 9
route_replay_ttl_seconds = 10
outbound_queue_max = 7
tdm_slot_ms = 2
"#,
        )
        .expect("cfg");
        assert_eq!(cfg.node_name, "relay-a");
        assert_eq!(cfg.udp_relay_bind.as_deref(), Some("127.0.0.1:7000"));
        assert_eq!(cfg.route_replay_max_entries, 9);
        assert_eq!(cfg.outbound_queue_max, 7);
        assert_eq!(cfg.tdm_slot_ms, 2);
        assert!(cfg.enable_resctrl_l3_locking);
    }
    #[test]
    fn rejects_invalid_bool() {
        assert_eq!(
            parse_chronosd_config("[hardware_hardening]\nenable_resctrl_l3_locking = maybe")
                .expect_err("bad"),
            ConfigError::InvalidBool("maybe".to_string())
        );
    }
}
