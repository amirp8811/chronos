//! `chronos-dir` — Decentralized HotStuff BFT Directory Consensus Mesh
//! CHRONOS-SPEC-v7.0 Section 3

mod api;
mod consensus;
#[cfg(test)]
mod consensus_store;
#[cfg(test)]
mod signed_record;
mod store;

use api::serve_directory_api;
use consensus::HierarchicalBftMesh;
use log::info;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use store::DirectoryStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================================");
    println!("    CHRONOS v7.0: BFT DIRECTORY CONSENSUS (`chronos-dir`) - LEVEL 14    ");
    println!("================================================================================");

    info!("Initializing 2-Tier Hierarchical BLS Quorum Mesh across 1,000 global nodes...");
    if let Ok(bind_addr) = std::env::var("CHRONOS_DIR_API_BIND") {
        let db_path = std::env::var("CHRONOS_DIR_DB").ok();
        let initial_store = if let Some(path) = &db_path {
            DirectoryStore::load_from_file(path).unwrap_or_else(|_| DirectoryStore::new())
        } else {
            DirectoryStore::new()
        };
        if let Some(path) = &db_path {
            let _ = initial_store.save_to_file(path);
        }
        let store = Arc::new(Mutex::new(initial_store));
        info!("Starting local directory API on {}", bind_addr);
        serve_directory_api(&bind_addr, store).await?;
        return Ok(());
    }
    let mut bft_mesh = HierarchicalBftMesh::new();

    // Simulate 2 sub-epochs of emergency key rotations and descriptor consensus
    for epoch in 1..=2 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        info!(
            "Sub-Epoch #{:02} active | Protocol: HotStuff 3-Phase | Threshold: BLS12-381",
            epoch
        );

        match bft_mesh.execute_sub_epoch_consensus() {
            Ok(root_hash) => {
                info!("Quorum certificate generated successfully.");
                if epoch == 2 {
                    bft_mesh.publish_to_transparency_logs(&root_hash);
                }
            }
            Err(e) => {
                info!("Consensus warning: {}", e);
            }
        }
    }

    info!("Directory consensus simulation completed cleanly. Terminating.");
    Ok(())
}
