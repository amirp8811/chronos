//! Authenticated persistence for signed relay descriptors.
//!
//! Only complete `SignedRelayRecord` values are persisted. The former
//! `CHDIR001` stripped-record format is rejected because it cannot establish
//! that a descriptor was authenticated before a restart.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;

use crate::signed_record::{SignedRecordError, SignedRelayRecord, verify_record_at};

const DIRECTORY_STORE_MAGIC_V2: &[u8; 8] = b"CHDIR002";
const DIRECTORY_STORE_MAGIC_V1: &[u8; 8] = b"CHDIR001";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryStoreError {
    Io(String),
    InvalidMagic,
    LegacyStrippedFormatRejected,
    InvalidRecordEncoding,
    TrailingData,
    SignedRecord(SignedRecordError),
    UnsignedDevelopmentRecordsCannotPersist,
}

impl fmt::Display for DirectoryStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for DirectoryStoreError {}

#[derive(Default, Clone)]
pub struct DirectoryStore {
    signed_records: HashMap<String, SignedRelayRecord>,
    // This is intentionally separate from authenticated state and is never
    // written to disk. It only exists for a caller that has explicitly enabled
    // the unsafe local-development line-protocol path.
    development_unsigned_records: HashMap<String, RelayRecord>,
}

impl DirectoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies and stores the complete signed record.
    pub fn upsert_signed(
        &mut self,
        signed: SignedRelayRecord,
        now_unix: u64,
        max_lifetime_seconds: u64,
    ) -> Result<(), SignedRecordError> {
        verify_record_at(&signed, now_unix, max_lifetime_seconds)?;
        self.signed_records
            .insert(signed.record.node_id.clone(), signed);
        Ok(())
    }

    /// Explicitly unsafe development-only state. It is crate-private and cannot
    /// be serialized as authenticated directory data.
    pub(crate) fn upsert_unsigned_for_local_development_only(&mut self, record: RelayRecord) {
        self.development_unsigned_records
            .insert(record.node_id.clone(), record);
    }

    pub fn get(&self, node_id: &str, now_unix: u64) -> Option<&RelayRecord> {
        self.signed_records
            .get(node_id)
            .map(|signed| &signed.record)
            .or_else(|| self.development_unsigned_records.get(node_id))
            .filter(|record| record.expires_at_unix > now_unix)
    }

    pub fn get_signed(&self, node_id: &str, now_unix: u64) -> Option<&SignedRelayRecord> {
        self.signed_records
            .get(node_id)
            .filter(|signed| signed.record.expires_at_unix > now_unix)
    }

    pub fn prune_expired(&mut self, now_unix: u64) {
        self.signed_records
            .retain(|_, signed| signed.record.expires_at_unix > now_unix);
        self.development_unsigned_records
            .retain(|_, record| record.expires_at_unix > now_unix);
    }

    pub fn len(&self) -> usize {
        self.signed_records.len() + self.development_unsigned_records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signed_records.is_empty() && self.development_unsigned_records.is_empty()
    }

    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), DirectoryStoreError> {
        if !self.development_unsigned_records.is_empty() {
            return Err(DirectoryStoreError::UnsignedDevelopmentRecordsCannotPersist);
        }
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let mut file = File::create(path).map_err(io_error)?;
        file.write_all(DIRECTORY_STORE_MAGIC_V2).map_err(io_error)?;
        file.write_all(&(self.signed_records.len() as u32).to_be_bytes())
            .map_err(io_error)?;
        for signed in self.signed_records.values() {
            write_signed_record(&mut file, signed)?;
        }
        file.sync_all().map_err(io_error)?;
        Ok(())
    }

    /// Loads only version-2 signed records and re-verifies each descriptor.
    pub fn load_from_file(
        path: impl AsRef<Path>,
        now_unix: u64,
        max_lifetime_seconds: u64,
    ) -> Result<Self, DirectoryStoreError> {
        let mut file = File::open(path).map_err(io_error)?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic).map_err(io_error)?;
        if &magic == DIRECTORY_STORE_MAGIC_V1 {
            return Err(DirectoryStoreError::LegacyStrippedFormatRejected);
        }
        if &magic != DIRECTORY_STORE_MAGIC_V2 {
            return Err(DirectoryStoreError::InvalidMagic);
        }
        let count = read_u32(&mut file)? as usize;
        let mut store = Self::new();
        for _ in 0..count {
            let signed = read_signed_record(&mut file)?;
            store
                .upsert_signed(signed, now_unix, max_lifetime_seconds)
                .map_err(DirectoryStoreError::SignedRecord)?;
        }
        let mut trailing = [0u8; 1];
        if file.read(&mut trailing).map_err(io_error)? != 0 {
            return Err(DirectoryStoreError::TrailingData);
        }
        Ok(store)
    }
}

fn io_error(error: std::io::Error) -> DirectoryStoreError {
    DirectoryStoreError::Io(error.to_string())
}

fn write_signed_record(
    writer: &mut impl Write,
    signed: &SignedRelayRecord,
) -> Result<(), DirectoryStoreError> {
    write_string(writer, &signed.record.node_id)?;
    write_string(writer, &signed.record.address.to_string())?;
    writer
        .write_all(&signed.record.x25519_public)
        .map_err(io_error)?;
    writer
        .write_all(&signed.record.ml_kem_public_hash)
        .map_err(io_error)?;
    writer
        .write_all(&signed.record.expires_at_unix.to_be_bytes())
        .map_err(io_error)?;
    write_string(writer, &signed.signer_id)?;
    writer.write_all(&signed.verifying_key).map_err(io_error)?;
    writer.write_all(&signed.signature).map_err(io_error)?;
    Ok(())
}

fn read_signed_record(reader: &mut impl Read) -> Result<SignedRelayRecord, DirectoryStoreError> {
    let node_id = read_string(reader)?;
    let address = read_string(reader)?
        .parse::<SocketAddr>()
        .map_err(|_| DirectoryStoreError::InvalidRecordEncoding)?;
    let mut x25519_public = [0u8; 32];
    let mut ml_kem_public_hash = [0u8; 32];
    let mut verifying_key = [0u8; 32];
    let mut signature = [0u8; 64];
    reader.read_exact(&mut x25519_public).map_err(io_error)?;
    reader
        .read_exact(&mut ml_kem_public_hash)
        .map_err(io_error)?;
    let expires_at_unix = read_u64(reader)?;
    let signer_id = read_string(reader)?;
    reader.read_exact(&mut verifying_key).map_err(io_error)?;
    reader.read_exact(&mut signature).map_err(io_error)?;
    Ok(SignedRelayRecord {
        record: RelayRecord {
            node_id,
            address,
            x25519_public,
            ml_kem_public_hash,
            expires_at_unix,
        },
        signer_id,
        verifying_key,
        signature,
    })
}

fn write_string(writer: &mut impl Write, value: &str) -> Result<(), DirectoryStoreError> {
    let length: u32 = value
        .len()
        .try_into()
        .map_err(|_| DirectoryStoreError::InvalidRecordEncoding)?;
    writer.write_all(&length.to_be_bytes()).map_err(io_error)?;
    writer.write_all(value.as_bytes()).map_err(io_error)
}

fn read_string(reader: &mut impl Read) -> Result<String, DirectoryStoreError> {
    const MAX_DIRECTORY_STRING_BYTES: usize = 4096;
    let length = read_u32(reader)? as usize;
    if length > MAX_DIRECTORY_STRING_BYTES {
        return Err(DirectoryStoreError::InvalidRecordEncoding);
    }
    let mut bytes = vec![0u8; length];
    reader.read_exact(&mut bytes).map_err(io_error)?;
    String::from_utf8(bytes).map_err(|_| DirectoryStoreError::InvalidRecordEncoding)
}

fn read_u32(reader: &mut impl Read) -> Result<u32, DirectoryStoreError> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes).map_err(io_error)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(reader: &mut impl Read) -> Result<u64, DirectoryStoreError> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes).map_err(io_error)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_record::sign_record;
    use ed25519_dalek::SigningKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    const NOW: u64 = 1_700_000_000;
    const MAX_LIFETIME: u64 = 300;

    fn temp_path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("chronos-dir-{label}-{nonce}.db"))
    }

    fn signed_record(expiry: u64) -> SignedRelayRecord {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        sign_record(
            RelayRecord {
                node_id: "n1".into(),
                address: "127.0.0.1:1".parse().expect("address"),
                x25519_public: [0x11; 32],
                ml_kem_public_hash: [0x22; 32],
                expires_at_unix: expiry,
            },
            "n1",
            &signing,
        )
    }

    fn saved_store(path: &Path) {
        let mut store = DirectoryStore::new();
        store
            .upsert_signed(signed_record(NOW + 60), NOW, MAX_LIFETIME)
            .expect("upsert signed");
        store.save_to_file(path).expect("save");
    }

    #[test]
    fn signed_record_round_trip_persists_and_reverifies() {
        let path = temp_path("roundtrip");
        saved_store(&path);
        let loaded = DirectoryStore::load_from_file(&path, NOW, MAX_LIFETIME).expect("load");
        let signed = loaded.get_signed("n1", NOW).expect("signed record");
        assert_eq!(signed.record.x25519_public, [0x11; 32]);
        assert_eq!(signed.signer_id, "n1");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn tampered_signature_in_database_is_rejected() {
        let path = temp_path("signature");
        saved_store(&path);
        let mut bytes = fs::read(&path).expect("read");
        *bytes.last_mut().expect("signature byte") ^= 1;
        fs::write(&path, bytes).expect("write");
        assert!(matches!(
            DirectoryStore::load_from_file(&path, NOW, MAX_LIFETIME),
            Err(DirectoryStoreError::SignedRecord(
                SignedRecordError::InvalidSignature
            ))
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn tampered_record_field_in_database_is_rejected() {
        let path = temp_path("record-field");
        saved_store(&path);
        let mut bytes = fs::read(&path).expect("read");
        let x25519_offset = bytes
            .windows(32)
            .position(|window| window == [0x11; 32])
            .expect("x25519 field");
        bytes[x25519_offset] ^= 1;
        fs::write(&path, bytes).expect("write");
        assert!(matches!(
            DirectoryStore::load_from_file(&path, NOW, MAX_LIFETIME),
            Err(DirectoryStoreError::SignedRecord(
                SignedRecordError::InvalidSignature
            ))
        ));
        let _ = fs::remove_file(path);
    }

    fn write_signed_database(path: &Path, signed: &SignedRelayRecord) {
        let mut file = File::create(path).expect("create");
        file.write_all(DIRECTORY_STORE_MAGIC_V2).expect("magic");
        file.write_all(&1u32.to_be_bytes()).expect("count");
        write_signed_record(&mut file, signed).expect("record");
        file.sync_all().expect("sync");
    }

    #[test]
    fn persisted_expired_excessive_zero_and_signer_mismatch_records_are_rejected() {
        let path = temp_path("persisted-invalid");
        let signing = SigningKey::from_bytes(&[9u8; 32]);

        let expired = sign_record(signed_record(NOW).record, "n1", &signing);
        write_signed_database(&path, &expired);
        assert!(matches!(
            DirectoryStore::load_from_file(&path, NOW, MAX_LIFETIME),
            Err(DirectoryStoreError::SignedRecord(
                SignedRecordError::Record(RelayRecordError::Expired { .. })
            ))
        ));

        let excessive = sign_record(signed_record(NOW + MAX_LIFETIME + 1).record, "n1", &signing);
        write_signed_database(&path, &excessive);
        assert!(matches!(
            DirectoryStore::load_from_file(&path, NOW, MAX_LIFETIME),
            Err(DirectoryStoreError::SignedRecord(
                SignedRecordError::Record(RelayRecordError::ExcessiveLifetime { .. })
            ))
        ));

        let mut zero_record = signed_record(NOW + 1).record;
        zero_record.x25519_public = [0; 32];
        let zero = sign_record(zero_record, "n1", &signing);
        write_signed_database(&path, &zero);
        assert!(matches!(
            DirectoryStore::load_from_file(&path, NOW, MAX_LIFETIME),
            Err(DirectoryStoreError::SignedRecord(
                SignedRecordError::Record(RelayRecordError::ZeroX25519PublicKey)
            ))
        ));

        let mut signer_mismatch = sign_record(signed_record(NOW + 1).record, "n1", &signing);
        signer_mismatch.signer_id = "other".to_string();
        write_signed_database(&path, &signer_mismatch);
        assert!(matches!(
            DirectoryStore::load_from_file(&path, NOW, MAX_LIFETIME),
            Err(DirectoryStoreError::SignedRecord(
                SignedRecordError::SignerDoesNotMatchNodeId
            ))
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn expired_zero_material_and_signer_mismatch_are_rejected_at_ingestion() {
        let mut store = DirectoryStore::new();
        assert!(matches!(
            store.upsert_signed(signed_record(NOW), NOW, MAX_LIFETIME),
            Err(SignedRecordError::Record(RelayRecordError::Expired { .. }))
        ));

        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let mut zero = signed_record(NOW + 1);
        zero.record.x25519_public = [0; 32];
        let zero = sign_record(zero.record, "n1", &signing);
        assert!(matches!(
            store.upsert_signed(zero, NOW, MAX_LIFETIME),
            Err(SignedRecordError::Record(
                RelayRecordError::ZeroX25519PublicKey
            ))
        ));

        let mut mismatch = signed_record(NOW + 1);
        mismatch.signer_id = "other".to_string();
        assert_eq!(
            store.upsert_signed(mismatch, NOW, MAX_LIFETIME),
            Err(SignedRecordError::SignerDoesNotMatchNodeId)
        );
    }

    #[test]
    fn legacy_stripped_format_is_not_trusted() {
        let path = temp_path("legacy");
        fs::write(&path, DIRECTORY_STORE_MAGIC_V1).expect("write legacy");
        assert!(matches!(
            DirectoryStore::load_from_file(&path, NOW, MAX_LIFETIME),
            Err(DirectoryStoreError::LegacyStrippedFormatRejected)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unsigned_development_records_cannot_be_persisted() {
        let path = temp_path("unsigned");
        let mut store = DirectoryStore::new();
        store.upsert_unsigned_for_local_development_only(RelayRecord {
            node_id: "local".into(),
            address: "127.0.0.1:1".parse().expect("address"),
            x25519_public: [0; 32],
            ml_kem_public_hash: [0; 32],
            expires_at_unix: NOW + 1,
        });
        assert_eq!(
            store.save_to_file(&path),
            Err(DirectoryStoreError::UnsignedDevelopmentRecordsCannotPersist)
        );
    }
}
