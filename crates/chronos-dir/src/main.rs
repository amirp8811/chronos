#![deny(unsafe_code)]
//! Local authenticated directory-record prototype.
//!
//! No directory consensus service is started by this binary. Set
//! `CHRONOS_DIR_API_BIND` explicitly to start the local TCP test API.

mod api;
#[cfg(test)]
mod consensus_store;
mod signed_record;
mod store;

use api::{DirectoryApiConfig, serve_directory_api};
use log::info;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use store::DirectoryStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(bind_addr) = std::env::var("CHRONOS_DIR_API_BIND") else {
        info!("Directory prototype is inactive; set CHRONOS_DIR_API_BIND to run the local API.");
        return Ok(());
    };

    let db_path = std::env::var("CHRONOS_DIR_DB").ok();
    let initial_store = if let Some(path) = &db_path {
        if PathBuf::from(path).exists() {
            DirectoryStore::load_from_file(path)
                .map_err(|error| format!("refusing invalid directory database: {error}"))?
        } else {
            DirectoryStore::new()
        }
    } else {
        DirectoryStore::new()
    };
    let store = Arc::new(Mutex::new(initial_store));
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
    info!("Starting local authenticated directory API on {bind_addr}");
    serve_directory_api(&bind_addr, store, api_config, db_path.map(PathBuf::from)).await?;
    Ok(())
}
