#![deny(unsafe_code)]
//! Local authenticated directory-record prototype binary.
//!
//! No directory service starts unless `CHRONOS_DIR_API_BIND` is set explicitly.

use chronos_dir::api::{DirectoryApiConfig, serve_directory_api};
use chronos_dir::store::DirectoryStore;
use log::info;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(bind_addr) = std::env::var("CHRONOS_DIR_API_BIND") else {
        info!("Directory prototype is inactive; set CHRONOS_DIR_API_BIND to run the local API.");
        return Ok(());
    };

    let api_config = DirectoryApiConfig {
        allow_unsafe_plaintext_mutation: std::env::var(
            "CHRONOS_DIR_ALLOW_UNSAFE_PLAINTEXT_MUTATION",
        )
        .map(|value| value == "1")
        .unwrap_or(false),
        allow_remote_prune: std::env::var("CHRONOS_DIR_ALLOW_REMOTE_PRUNE")
            .map(|value| value == "1")
            .unwrap_or(false),
        ..DirectoryApiConfig::default()
    };
    let db_path = std::env::var("CHRONOS_DIR_DB").ok().map(PathBuf::from);
    let initial_store = match &db_path {
        Some(path) if path.exists() => {
            DirectoryStore::load_from_file(path, unix_now(), api_config.max_record_lifetime_seconds)
                .map_err(|error| format!("refusing invalid directory database: {error}"))?
        }
        _ => DirectoryStore::new(),
    };

    info!("Starting local authenticated directory API on {bind_addr}");
    serve_directory_api(
        &bind_addr,
        Arc::new(Mutex::new(initial_store)),
        api_config,
        db_path,
    )
    .await?;
    Ok(())
}
