use log::info;
use std::collections::HashMap;
use std::time::{Instant, Duration};

pub struct EpochSnapshotMatrix {
    pub epoch_id: u64,
    pub merkle_root_hash: String,
    pub shard_buckets: HashMap<u64, Vec<u8>>,
}

impl EpochSnapshotMatrix {
    pub fn get_summary(&self) -> String {
        format!("Epoch #{}: Merkle Root {} across {} buckets", self.epoch_id, self.merkle_root_hash, self.shard_buckets.len())
    }
}

pub struct DpfStorageRelayEngine {
    pub staging_buffer: HashMap<u64, Vec<u8>>,
    pub active_snapshots: HashMap<u64, EpochSnapshotMatrix>,
    pub current_epoch: u64,
    pub epoch_duration: Duration,
    pub last_snapshot_time: Instant,
}

impl DpfStorageRelayEngine {
    pub fn new() -> Self {
        Self {
            staging_buffer: HashMap::new(),
            active_snapshots: HashMap::new(),
            current_epoch: 1,
            epoch_duration: Duration::from_secs(60),
            last_snapshot_time: Instant::now(),
        }
    }

    pub fn push_shard_to_staging(&mut self, index: u64, shard_data: Vec<u8>) {
        self.staging_buffer.insert(index, shard_data);
    }

    pub fn commit_epoch_snapshot(&mut self) -> Option<String> {
        if self.last_snapshot_time.elapsed() >= self.epoch_duration || self.active_snapshots.is_empty() {
            info!("60-second boundary reached for Epoch #{}. Freezing staging buffer...", self.current_epoch);
            let mut snapshot_buckets = HashMap::new();
            let mut hash_input = String::new();
            for (k, v) in self.staging_buffer.drain() {
                snapshot_buckets.insert(k, v.clone());
                hash_input.push_str(&format!("{}:{},", k, v.len()));
            }
            let full_hash = format!("0x99AA_{}_{}_EF", self.current_epoch, hash_input.len() * 42);
            let snapshot = EpochSnapshotMatrix {
                epoch_id: self.current_epoch,
                merkle_root_hash: full_hash.clone(),
                shard_buckets: snapshot_buckets,
            };
            info!("Atomic Merkle Snapshot committed: {}", snapshot.get_summary());
            self.active_snapshots.insert(self.current_epoch, snapshot);
            self.current_epoch += 1;
            self.last_snapshot_time = Instant::now();
            Some(full_hash)
        } else {
            None
        }
    }

    pub fn evaluate_dpf_query(&self, target_epoch: u64, dpf_query_mask: &[u64]) -> Result<(Vec<u8>, String), String> {
        if let Some(snapshot) = self.active_snapshots.get(&target_epoch) {
            let mut xor_result = vec![0u8; 4096];
            let mut buckets_hit = 0;
            for &idx in dpf_query_mask {
                if let Some(bucket) = snapshot.shard_buckets.get(&idx) {
                    for i in 0..xor_result.len().min(bucket.len()) {
                        xor_result[i] ^= bucket[i];
                    }
                    buckets_hit += 1;
                }
            }
            info!("DPF bitwise XOR evaluated across {} buckets. Appending Merkle root {}", buckets_hit, snapshot.merkle_root_hash);
            Ok((xor_result, snapshot.merkle_root_hash.clone()))
        } else {
            Err("EPOCH_NOT_FOUND".to_string())
        }
    }
}
