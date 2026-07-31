//! Local directory store for authenticated relay records.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRecord {
    pub node_id: String,
    pub address: SocketAddr,
    pub x25519_public: [u8; 32],
    /// SHA-256 digest of the advertised ML-KEM public key.
    pub ml_kem_public_hash: [u8; 32],
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayRecordError {
    EmptyNodeId,
    ZeroX25519PublicKey,
    ZeroMlKemPublicKeyHash,
    Expired {
        expires_at_unix: u64,
        now_unix: u64,
    },
    ExcessiveLifetime {
        expires_at_unix: u64,
        max_expires_at_unix: u64,
    },
}

impl RelayRecord {
    pub fn validate_public_material(&self) -> Result<(), RelayRecordError> {
        if self.node_id.is_empty() {
            return Err(RelayRecordError::EmptyNodeId);
        }
        if self.x25519_public.iter().all(|byte| *byte == 0) {
            return Err(RelayRecordError::ZeroX25519PublicKey);
        }
        if self.ml_kem_public_hash.iter().all(|byte| *byte == 0) {
            return Err(RelayRecordError::ZeroMlKemPublicKeyHash);
        }
        Ok(())
    }

    pub fn validate_freshness(
        &self,
        now_unix: u64,
        max_lifetime_seconds: u64,
    ) -> Result<(), RelayRecordError> {
        if self.expires_at_unix <= now_unix {
            return Err(RelayRecordError::Expired {
                expires_at_unix: self.expires_at_unix,
                now_unix,
            });
        }
        let max_expires_at_unix = now_unix.saturating_add(max_lifetime_seconds);
        if self.expires_at_unix > max_expires_at_unix {
            return Err(RelayRecordError::ExcessiveLifetime {
                expires_at_unix: self.expires_at_unix,
                max_expires_at_unix,
            });
        }
        Ok(())
    }
}

#[derive(Default, Clone)]
pub struct DirectoryStore {
    records: HashMap<String, RelayRecord>,
}

impl DirectoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// Stores a record only after its mandatory public material is validated.
    pub fn upsert(&mut self, record: RelayRecord) -> Result<(), RelayRecordError> {
        record.validate_public_material()?;
        self.records.insert(record.node_id.clone(), record);
        Ok(())
    }

    /// Development-only compatibility storage for the explicitly unsafe
    /// plaintext API. It is crate-private so production callers cannot bypass
    /// public-material validation.
    pub(crate) fn upsert_unsafe_for_development(&mut self, record: RelayRecord) {
        self.records.insert(record.node_id.clone(), record);
    }
    pub fn get(&self, node_id: &str, now: u64) -> Option<&RelayRecord> {
        self.records
            .get(node_id)
            .filter(|record| record.expires_at_unix > now)
    }
    pub fn prune_expired(&mut self, now: u64) {
        self.records
            .retain(|_, record| record.expires_at_unix > now);
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), String> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mut file = File::create(path).map_err(|error| error.to_string())?;
        file.write_all(b"CHDIR001")
            .map_err(|error| error.to_string())?;
        file.write_all(&(self.records.len() as u32).to_be_bytes())
            .map_err(|error| error.to_string())?;
        for record in self.records.values() {
            record
                .validate_public_material()
                .map_err(|error| format!("invalid record: {error:?}"))?;
            write_string(&mut file, &record.node_id)?;
            write_string(&mut file, &record.address.to_string())?;
            file.write_all(&record.x25519_public)
                .map_err(|error| error.to_string())?;
            file.write_all(&record.ml_kem_public_hash)
                .map_err(|error| error.to_string())?;
            file.write_all(&record.expires_at_unix.to_be_bytes())
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let mut file = File::open(path).map_err(|error| error.to_string())?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)
            .map_err(|error| error.to_string())?;
        if &magic != b"CHDIR001" {
            return Err("INVALID_DIRECTORY_MAGIC".to_string());
        }
        let count = read_u32(&mut file)? as usize;
        let mut store = Self::new();
        for _ in 0..count {
            let node_id = read_string(&mut file)?;
            let address = read_string(&mut file)?
                .parse()
                .map_err(|error| format!("{error}"))?;
            let mut x25519_public = [0u8; 32];
            let mut ml_kem_public_hash = [0u8; 32];
            file.read_exact(&mut x25519_public)
                .map_err(|error| error.to_string())?;
            file.read_exact(&mut ml_kem_public_hash)
                .map_err(|error| error.to_string())?;
            let record = RelayRecord {
                node_id,
                address,
                x25519_public,
                ml_kem_public_hash,
                expires_at_unix: read_u64(&mut file)?,
            };
            record
                .validate_public_material()
                .map_err(|error| format!("invalid persisted record: {error:?}"))?;
            store
                .upsert(record)
                .map_err(|error| format!("invalid persisted record: {error:?}"))?;
        }
        Ok(store)
    }
}

fn write_string(mut writer: impl Write, value: &str) -> Result<(), String> {
    writer
        .write_all(&(value.len() as u32).to_be_bytes())
        .map_err(|error| error.to_string())?;
    writer
        .write_all(value.as_bytes())
        .map_err(|error| error.to_string())
}
fn read_string(mut reader: impl Read) -> Result<String, String> {
    let len = read_u32(&mut reader)? as usize;
    let mut bytes = vec![0u8; len];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    String::from_utf8(bytes).map_err(|error| error.to_string())
}
fn read_u32(mut reader: impl Read) -> Result<u32, String> {
    let mut bytes = [0; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(u32::from_be_bytes(bytes))
}
fn read_u64(mut reader: impl Read) -> Result<u64, String> {
    let mut bytes = [0; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> RelayRecord {
        RelayRecord {
            node_id: "n1".into(),
            address: "127.0.0.1:1".parse().expect("address"),
            x25519_public: [1; 32],
            ml_kem_public_hash: [2; 32],
            expires_at_unix: 10,
        }
    }

    #[test]
    fn directory_store_persists_valid_records_to_disk() {
        let path = std::env::temp_dir().join(format!("chronos-dir-{}.db", std::process::id()));
        let mut store = DirectoryStore::new();
        store.upsert(record()).expect("valid record");
        store.save_to_file(&path).expect("save");
        let loaded = DirectoryStore::load_from_file(&path).expect("load");
        assert_eq!(
            loaded.get("n1", 1).expect("record").address,
            "127.0.0.1:1".parse().expect("address")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn zero_public_material_is_rejected() {
        let mut invalid = record();
        invalid.x25519_public = [0; 32];
        assert_eq!(
            invalid.validate_public_material(),
            Err(RelayRecordError::ZeroX25519PublicKey)
        );
    }

    #[test]
    fn directory_store_looks_up_and_prunes_expired_records() {
        let mut store = DirectoryStore::new();
        store.upsert(record()).expect("valid record");
        assert_eq!(store.len(), 1);
        assert!(store.get("n1", 9).is_some());
        assert!(store.get("n1", 10).is_none());
        store.prune_expired(10);
        assert_eq!(store.len(), 0);
    }
}
