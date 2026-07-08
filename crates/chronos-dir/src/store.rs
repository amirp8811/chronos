//! Prototype local directory store for relay records.

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
    pub ml_kem_public_hash: [u8; 32],
    pub expires_at_unix: u64,
}

#[derive(Default)]
pub struct DirectoryStore {
    records: HashMap<String, RelayRecord>,
}

impl DirectoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn upsert(&mut self, record: RelayRecord) {
        self.records.insert(record.node_id.clone(), record);
    }
    pub fn get(&self, node_id: &str, now: u64) -> Option<&RelayRecord> {
        self.records
            .get(node_id)
            .filter(|r| r.expires_at_unix > now)
    }
    pub fn prune_expired(&mut self, now: u64) {
        self.records.retain(|_, r| r.expires_at_unix > now);
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), String> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut f = File::create(path).map_err(|e| e.to_string())?;
        f.write_all(b"CHDIR001").map_err(|e| e.to_string())?;
        f.write_all(&(self.records.len() as u32).to_be_bytes())
            .map_err(|e| e.to_string())?;
        for r in self.records.values() {
            write_string(&mut f, &r.node_id)?;
            write_string(&mut f, &r.address.to_string())?;
            f.write_all(&r.x25519_public).map_err(|e| e.to_string())?;
            f.write_all(&r.ml_kem_public_hash)
                .map_err(|e| e.to_string())?;
            f.write_all(&r.expires_at_unix.to_be_bytes())
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let mut f = File::open(path).map_err(|e| e.to_string())?;
        let mut magic = [0u8; 8];
        f.read_exact(&mut magic).map_err(|e| e.to_string())?;
        if &magic != b"CHDIR001" {
            return Err("INVALID_DIRECTORY_MAGIC".to_string());
        }
        let count = read_u32(&mut f)? as usize;
        let mut store = Self::new();
        for _ in 0..count {
            let node_id = read_string(&mut f)?;
            let address = read_string(&mut f)?.parse().map_err(|e| format!("{e}"))?;
            let mut x25519_public = [0u8; 32];
            let mut ml_kem_public_hash = [0u8; 32];
            f.read_exact(&mut x25519_public)
                .map_err(|e| e.to_string())?;
            f.read_exact(&mut ml_kem_public_hash)
                .map_err(|e| e.to_string())?;
            let expires_at_unix = read_u64(&mut f)?;
            store.upsert(RelayRecord {
                node_id,
                address,
                x25519_public,
                ml_kem_public_hash,
                expires_at_unix,
            });
        }
        Ok(store)
    }
}

fn write_string(mut w: impl Write, s: &str) -> Result<(), String> {
    w.write_all(&(s.len() as u32).to_be_bytes())
        .map_err(|e| e.to_string())?;
    w.write_all(s.as_bytes()).map_err(|e| e.to_string())
}
fn read_string(mut r: impl Read) -> Result<String, String> {
    let len = read_u32(&mut r)? as usize;
    let mut b = vec![0u8; len];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    String::from_utf8(b).map_err(|e| e.to_string())
}
fn read_u32(mut r: impl Read) -> Result<u32, String> {
    let mut b = [0; 4];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u32::from_be_bytes(b))
}
fn read_u64(mut r: impl Read) -> Result<u64, String> {
    let mut b = [0; 8];
    r.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(u64::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_store_persists_to_disk() {
        let path = std::env::temp_dir().join(format!("chronos-dir-{}.db", std::process::id()));
        let mut s = DirectoryStore::new();
        s.upsert(RelayRecord {
            node_id: "n2".into(),
            address: "127.0.0.1:2".parse().unwrap(),
            x25519_public: [2; 32],
            ml_kem_public_hash: [3; 32],
            expires_at_unix: 99,
        });
        s.save_to_file(&path).unwrap();
        let loaded = DirectoryStore::load_from_file(&path).unwrap();
        assert_eq!(
            loaded.get("n2", 1).unwrap().address,
            "127.0.0.1:2".parse().unwrap()
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn directory_store_upserts_looks_up_and_prunes() {
        let mut s = DirectoryStore::new();
        let r = RelayRecord {
            node_id: "n1".into(),
            address: "127.0.0.1:1".parse().unwrap(),
            x25519_public: [1; 32],
            ml_kem_public_hash: [2; 32],
            expires_at_unix: 10,
        };
        s.upsert(r);
        assert_eq!(s.len(), 1);
        assert!(s.get("n1", 9).is_some());
        assert!(s.get("n1", 10).is_none());
        s.prune_expired(10);
        assert_eq!(s.len(), 0);
    }
}
