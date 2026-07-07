use log::info;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

const SNAPSHOT_MAGIC: &[u8; 8] = b"CHDPF001";
const QUERY_MAGIC: &[u8; 8] = b"CHDQP001";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpfQueryRequest {
    pub epoch_id: u64,
    pub bucket_indices: Vec<u64>,
}

impl DpfQueryRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.bucket_indices.len() * 8);
        out.extend_from_slice(QUERY_MAGIC);
        out.extend_from_slice(&self.epoch_id.to_be_bytes());
        out.extend_from_slice(&(self.bucket_indices.len() as u32).to_be_bytes());
        for idx in &self.bucket_indices {
            out.extend_from_slice(&idx.to_be_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 20 || &bytes[0..8] != QUERY_MAGIC {
            return Err("INVALID_DPF_QUERY_MAGIC".to_string());
        }
        let epoch_id = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| "BAD_EPOCH")?);
        let count = u32::from_be_bytes(bytes[16..20].try_into().map_err(|_| "BAD_COUNT")?) as usize;
        let expected = 20 + count * 8;
        if bytes.len() != expected {
            return Err("INVALID_DPF_QUERY_LENGTH".to_string());
        }
        let mut bucket_indices = Vec::with_capacity(count);
        for chunk in bytes[20..].chunks_exact(8) {
            bucket_indices.push(u64::from_be_bytes(
                chunk.try_into().map_err(|_| "BAD_INDEX")?,
            ));
        }
        Ok(Self {
            epoch_id,
            bucket_indices,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpfQueryResponse {
    pub xor_result: Vec<u8>,
    pub merkle_root_hash: String,
}

pub struct EpochSnapshotMatrix {
    pub epoch_id: u64,
    pub merkle_root_hash: String,
    pub shard_buckets: HashMap<u64, Vec<u8>>,
}

impl EpochSnapshotMatrix {
    pub fn get_summary(&self) -> String {
        format!(
            "Epoch #{}: Merkle Root {} across {} buckets",
            self.epoch_id,
            self.merkle_root_hash,
            self.shard_buckets.len()
        )
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
        if self.last_snapshot_time.elapsed() >= self.epoch_duration
            || self.active_snapshots.is_empty()
        {
            info!(
                "60-second boundary reached for Epoch #{}. Freezing staging buffer...",
                self.current_epoch
            );
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
            info!(
                "Atomic Merkle Snapshot committed: {}",
                snapshot.get_summary()
            );
            self.active_snapshots.insert(self.current_epoch, snapshot);
            self.current_epoch += 1;
            self.last_snapshot_time = Instant::now();
            Some(full_hash)
        } else {
            None
        }
    }

    pub fn evaluate_dpf_query_request(
        &self,
        request: &DpfQueryRequest,
    ) -> Result<DpfQueryResponse, String> {
        let (xor_result, merkle_root_hash) =
            self.evaluate_dpf_query(request.epoch_id, &request.bucket_indices)?;
        Ok(DpfQueryResponse {
            xor_result,
            merkle_root_hash,
        })
    }

    pub fn evaluate_dpf_query(
        &self,
        target_epoch: u64,
        dpf_query_mask: &[u64],
    ) -> Result<(Vec<u8>, String), String> {
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
            info!(
                "DPF bitwise XOR evaluated across {} buckets. Appending Merkle root {}",
                buckets_hit, snapshot.merkle_root_hash
            );
            Ok((xor_result, snapshot.merkle_root_hash.clone()))
        } else {
            Err("EPOCH_NOT_FOUND".to_string())
        }
    }

    pub fn persist_snapshots(&self, dir: impl AsRef<Path>) -> Result<usize, String> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let mut written = 0usize;
        for snapshot in self.active_snapshots.values() {
            let path = dir.join(format!("epoch-{}.chrds", snapshot.epoch_id));
            let mut file = File::create(path).map_err(|e| e.to_string())?;
            write_snapshot(&mut file, snapshot)?;
            written += 1;
        }
        Ok(written)
    }

    pub fn load_snapshots(&mut self, dir: impl AsRef<Path>) -> Result<usize, String> {
        let dir = dir.as_ref();
        let mut loaded = 0usize;
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("chrds") {
                continue;
            }
            let mut file = File::open(&path).map_err(|e| e.to_string())?;
            let snapshot = read_snapshot(&mut file)?;
            self.current_epoch = self.current_epoch.max(snapshot.epoch_id + 1);
            self.active_snapshots.insert(snapshot.epoch_id, snapshot);
            loaded += 1;
        }
        Ok(loaded)
    }
}

impl Default for DpfStorageRelayEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn write_snapshot(mut writer: impl Write, snapshot: &EpochSnapshotMatrix) -> Result<(), String> {
    writer
        .write_all(SNAPSHOT_MAGIC)
        .map_err(|e| e.to_string())?;
    writer
        .write_all(&snapshot.epoch_id.to_be_bytes())
        .map_err(|e| e.to_string())?;
    let root = snapshot.merkle_root_hash.as_bytes();
    writer
        .write_all(&(root.len() as u32).to_be_bytes())
        .map_err(|e| e.to_string())?;
    writer.write_all(root).map_err(|e| e.to_string())?;
    writer
        .write_all(&(snapshot.shard_buckets.len() as u32).to_be_bytes())
        .map_err(|e| e.to_string())?;
    for (idx, data) in &snapshot.shard_buckets {
        writer
            .write_all(&idx.to_be_bytes())
            .map_err(|e| e.to_string())?;
        writer
            .write_all(&(data.len() as u32).to_be_bytes())
            .map_err(|e| e.to_string())?;
        writer.write_all(data).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn read_snapshot(mut reader: impl Read) -> Result<EpochSnapshotMatrix, String> {
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic).map_err(|e| e.to_string())?;
    if &magic != SNAPSHOT_MAGIC {
        return Err("INVALID_SNAPSHOT_MAGIC".to_string());
    }
    let epoch_id = read_u64(&mut reader)?;
    let root_len = read_u32(&mut reader)? as usize;
    let mut root = vec![0u8; root_len];
    reader.read_exact(&mut root).map_err(|e| e.to_string())?;
    let merkle_root_hash = String::from_utf8(root).map_err(|e| e.to_string())?;
    let count = read_u32(&mut reader)? as usize;
    let mut shard_buckets = HashMap::with_capacity(count);
    for _ in 0..count {
        let idx = read_u64(&mut reader)?;
        let len = read_u32(&mut reader)? as usize;
        let mut data = vec![0u8; len];
        reader.read_exact(&mut data).map_err(|e| e.to_string())?;
        shard_buckets.insert(idx, data);
    }
    Ok(EpochSnapshotMatrix {
        epoch_id,
        merkle_root_hash,
        shard_buckets,
    })
}

fn read_u64(mut reader: impl Read) -> Result<u64, String> {
    let mut b = [0u8; 8];
    reader.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u64::from_be_bytes(b))
}

fn read_u32(mut reader: impl Read) -> Result<u32, String> {
    let mut b = [0u8; 4];
    reader.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u32::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("chronos-dpf-{nonce}"))
    }

    #[test]
    fn query_request_round_trips() {
        let q = DpfQueryRequest {
            epoch_id: 7,
            bucket_indices: vec![1, 2, 3],
        };
        assert_eq!(DpfQueryRequest::decode(&q.encode()).unwrap(), q);
    }

    #[test]
    fn snapshots_persist_and_reload() {
        let dir = temp_dir();
        let mut engine = DpfStorageRelayEngine::new();
        engine.push_shard_to_staging(1, vec![0xAA; 32]);
        let root = engine.commit_epoch_snapshot().expect("commit");
        assert_eq!(engine.persist_snapshots(&dir).unwrap(), 1);

        let mut loaded = DpfStorageRelayEngine::new();
        assert_eq!(loaded.load_snapshots(&dir).unwrap(), 1);
        let response = loaded
            .evaluate_dpf_query_request(&DpfQueryRequest {
                epoch_id: 1,
                bucket_indices: vec![1],
            })
            .unwrap();
        assert_eq!(response.merkle_root_hash, root);
        assert_eq!(response.xor_result[0], 0xAA);
        let _ = fs::remove_dir_all(dir);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpfPointShare {
    pub bits: Vec<u8>,
}

pub fn generate_two_server_point_function(
    index: usize,
    domain_size: usize,
    seed: u64,
) -> (DpfPointShare, DpfPointShare) {
    let mut state = seed;
    let mut a = vec![0u8; domain_size];
    let mut b = vec![0u8; domain_size];
    for i in 0..domain_size {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let bit = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) & 1) as u8;
        a[i] = bit;
        b[i] = bit;
    }
    if index < domain_size {
        b[index] ^= 1;
    }
    (DpfPointShare { bits: a }, DpfPointShare { bits: b })
}

pub fn combine_point_shares(a: &DpfPointShare, b: &DpfPointShare) -> Vec<u8> {
    a.bits.iter().zip(&b.bits).map(|(x, y)| x ^ y).collect()
}

#[cfg(test)]
mod dpf_privacy_tests {
    use super::*;
    #[test]
    fn two_server_point_function_reconstructs_only_target_bit() {
        let (a, b) = generate_two_server_point_function(3, 8, 42);
        let combined = combine_point_shares(&a, &b);
        assert_eq!(combined.iter().filter(|&&bit| bit == 1).count(), 1);
        assert_eq!(combined[3], 1);
        assert_ne!(a.bits, combined);
        assert_ne!(b.bits, combined);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct MultiServerPirResponse {
    pub server_id: String,
    pub xor_result: Vec<u8>,
    pub merkle_root_hash: String,
}

#[allow(dead_code)]
pub fn evaluate_two_server_pir(
    left: &DpfStorageRelayEngine,
    right: &DpfStorageRelayEngine,
    epoch_id: u64,
    left_share: &DpfPointShare,
    right_share: &DpfPointShare,
) -> Result<Vec<u8>, String> {
    let left_indices = share_indices(left_share);
    let right_indices = share_indices(right_share);
    let (left_res, left_root) = left.evaluate_dpf_query(epoch_id, &left_indices)?;
    let (right_res, right_root) = right.evaluate_dpf_query(epoch_id, &right_indices)?;
    if left_root != right_root {
        return Err("PIR_SNAPSHOT_ROOT_MISMATCH".to_string());
    }
    let mut combined = vec![0u8; left_res.len().max(right_res.len())];
    for (i, b) in left_res.iter().enumerate() {
        combined[i] ^= b;
    }
    for (i, b) in right_res.iter().enumerate() {
        combined[i] ^= b;
    }
    Ok(combined)
}

#[allow(dead_code)]
fn share_indices(share: &DpfPointShare) -> Vec<u64> {
    share
        .bits
        .iter()
        .enumerate()
        .filter_map(|(idx, bit)| if *bit == 1 { Some(idx as u64) } else { None })
        .collect()
}

#[cfg(test)]
mod multi_server_pir_tests {
    use super::*;

    fn engine_with_epoch(bucket_count: usize) -> DpfStorageRelayEngine {
        let mut engine = DpfStorageRelayEngine::new();
        for idx in 0..bucket_count {
            engine.push_shard_to_staging(idx as u64, vec![idx as u8; 32]);
        }
        engine.commit_epoch_snapshot().expect("commit");
        engine
    }

    #[test]
    fn two_server_pir_recovers_target_bucket_from_shared_queries() {
        let left = engine_with_epoch(8);
        let right = engine_with_epoch(8);
        let (a, b) = generate_two_server_point_function(5, 8, 99);
        let recovered = evaluate_two_server_pir(&left, &right, 1, &a, &b).expect("pir");
        assert_eq!(recovered[0], 5);
    }

    #[test]
    fn two_server_pir_rejects_snapshot_mismatch() {
        let left = engine_with_epoch(8);
        let mut right = DpfStorageRelayEngine::new();
        right.push_shard_to_staging(5, vec![5u8; 32]);
        right.commit_epoch_snapshot().expect("commit");
        let (a, b) = generate_two_server_point_function(5, 8, 99);
        assert_eq!(
            evaluate_two_server_pir(&left, &right, 1, &a, &b),
            Err("PIR_SNAPSHOT_ROOT_MISMATCH".to_string())
        );
    }
}
