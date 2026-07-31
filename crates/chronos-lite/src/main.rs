#![deny(unsafe_code)]
//! Experimental local client-side scaffold.
//!
//! `chronos-lite` does not provide a supported relay, storage, browser gateway,
//! or deployed client. Its algorithm modules are retained for unit tests while
//! the executable reports its intentionally limited status.

mod config;
#[cfg(test)]
mod dpf_store;
#[cfg(test)]
mod secure_udp;

use config::{ChronosLiteConfig, load_chronos_lite_config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::var("CHRONOS_LITE_CONFIG")
        .unwrap_or_else(|_| "configs/chronos-lite.toml".to_string());
    let config =
        load_chronos_lite_config(&config_path).unwrap_or_else(|_| ChronosLiteConfig::default());

    println!("CHRONOS lite experimental scaffold");
    println!("node: {} ({})", config.node_name, config.node_id_fp);
    println!("status: no relay, transport, storage service, or browser gateway is started.");
    println!("run `cargo test -p chronos-lite` for local algorithm tests.");
    Ok(())
}
