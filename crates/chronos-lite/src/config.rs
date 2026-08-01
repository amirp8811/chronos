//! Small, strict configuration parser retained for local parser testing.
//!
//! `chronos-lite` does not expose a runtime service. This parser accepts only
//! basic node metadata and rejects unknown settings rather than suggesting
//! unsupported transport, storage, or network features exist.

use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChronosLiteConfig {
    pub node_name: String,
    pub node_id_fp: String,
    pub operating_role: String,
    pub jurisdiction: String,
}

impl Default for ChronosLiteConfig {
    fn default() -> Self {
        Self {
            node_name: "chronos-lite-local".to_string(),
            node_id_fp: "local-dev-node.chr".to_string(),
            operating_role: "prototype".to_string(),
            jurisdiction: "local".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Io(String),
    InvalidLine(String),
    InvalidKey(String),
}

pub fn load_chronos_lite_config(path: impl AsRef<Path>) -> Result<ChronosLiteConfig, ConfigError> {
    let text = fs::read_to_string(path).map_err(|error| ConfigError::Io(error.to_string()))?;
    parse_chronos_lite_config(&text)
}

pub fn parse_chronos_lite_config(text: &str) -> Result<ChronosLiteConfig, ConfigError> {
    let mut config = ChronosLiteConfig::default();
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
        let value = parse_string(value.trim())?;
        match format!("{}.{}", section, key.trim()).as_str() {
            "node.node_name" => config.node_name = value,
            "node.node_id_fp" => config.node_id_fp = value,
            "node.operating_role" => config.operating_role = value,
            "node.jurisdiction" => config.jurisdiction = value,
            other => return Err(ConfigError::InvalidKey(other.to_string())),
        }
    }
    Ok(config)
}

fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    for (index, character) in line.char_indices() {
        match character {
            '"' => in_string = !in_string,
            '#' if !in_string => return &line[..index],
            _ => {}
        }
    }
    line
}

fn parse_string(value: &str) -> Result<String, ConfigError> {
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        Ok(value[1..value.len() - 1].to_string())
    } else {
        Err(ConfigError::InvalidLine(value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_node_metadata() {
        let config = parse_chronos_lite_config(
            r#"
[node]
node_name = "node-a"
node_id_fp = "node-a.chr"
operating_role = "local-test"
jurisdiction = "local"
"#,
        )
        .expect("config");
        assert_eq!(config.node_name, "node-a");
        assert_eq!(config.operating_role, "local-test");
    }

    #[test]
    fn rejects_unknown_and_malformed_settings() {
        assert_eq!(
            parse_chronos_lite_config("[network]\ntransport = \"udp\"").expect_err("unknown"),
            ConfigError::InvalidKey("network.transport".to_string())
        );
        assert!(matches!(
            parse_chronos_lite_config("[node]\nnode_name = unquoted"),
            Err(ConfigError::InvalidLine(_))
        ));
    }
}
