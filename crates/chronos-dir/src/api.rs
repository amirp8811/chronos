//! Local TCP directory API.
//!
//! This service is a prototype control plane, not a public directory protocol.
//! Authenticated descriptor publication uses:
//!
//! ```text
//! UPSERT_SIGNED <node_id> <address> <expires_unix> <x25519_hex_32>
//!               <mlkem_hash_hex_32> <signer_id> <ed25519_public_hex_32>
//!               <signature_hex_64>
//! ```
//!
//! `PRUNE` is deliberately not remotely enabled by default. The legacy plaintext
//! `UPSERT` exists only behind an explicit local-development switch and is never
//! accepted in the default configuration.

use crate::signed_record::{SignedRelayRecord, verify_record_at};
use crate::store::{DirectoryStore, RelayRecord};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryApiConfig {
    /// Development-only compatibility path for plaintext local mutations.
    pub allow_unsafe_plaintext_mutation: bool,
    /// Remote pruning is off even when signed upserts are enabled.
    pub allow_remote_prune: bool,
    pub max_record_lifetime_seconds: u64,
}

impl Default for DirectoryApiConfig {
    fn default() -> Self {
        Self {
            allow_unsafe_plaintext_mutation: false,
            allow_remote_prune: false,
            // One day is long enough for a local prototype while bounding stale
            // descriptor persistence.
            max_record_lifetime_seconds: 86_400,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryApiError {
    BadCommand,
    BadAddress,
    BadInteger,
    BadHex,
    MutationDisabled,
    RemotePruneDisabled,
    InvalidSignedRecord,
    Io(String),
}

impl std::fmt::Display for DirectoryApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for DirectoryApiError {}

pub fn handle_command(
    store: &mut DirectoryStore,
    line: &str,
    config: &DirectoryApiConfig,
    now_unix: u64,
) -> Result<String, DirectoryApiError> {
    let mut parts = line.split_whitespace();
    match parts.next() {
        Some("UPSERT_SIGNED") => {
            let record = RelayRecord {
                node_id: next_part(&mut parts)?.to_string(),
                address: next_part(&mut parts)?
                    .parse::<SocketAddr>()
                    .map_err(|_| DirectoryApiError::BadAddress)?,
                expires_at_unix: next_part(&mut parts)?
                    .parse::<u64>()
                    .map_err(|_| DirectoryApiError::BadInteger)?,
                x25519_public: parse_hex_array::<32>(next_part(&mut parts)?)?,
                ml_kem_public_hash: parse_hex_array::<32>(next_part(&mut parts)?)?,
            };
            let signer_id = next_part(&mut parts)?.to_string();
            let verifying_key = parse_hex_array::<32>(next_part(&mut parts)?)?;
            let signature = parse_hex_array::<64>(next_part(&mut parts)?)?;
            require_no_extra_parts(&mut parts)?;
            let signed = SignedRelayRecord {
                record,
                signer_id,
                verifying_key,
                signature,
            };
            verify_record_at(&signed, now_unix, config.max_record_lifetime_seconds)
                .map_err(|_| DirectoryApiError::InvalidSignedRecord)?;
            store
                .upsert(signed.record)
                .map_err(|_| DirectoryApiError::InvalidSignedRecord)?;
            Ok("OK\n".to_string())
        }
        Some("UPSERT") => {
            if !config.allow_unsafe_plaintext_mutation {
                return Err(DirectoryApiError::MutationDisabled);
            }
            let record = RelayRecord {
                node_id: next_part(&mut parts)?.to_string(),
                address: next_part(&mut parts)?
                    .parse::<SocketAddr>()
                    .map_err(|_| DirectoryApiError::BadAddress)?,
                expires_at_unix: next_part(&mut parts)?
                    .parse::<u64>()
                    .map_err(|_| DirectoryApiError::BadInteger)?,
                // Explicitly development-only compatibility fields. Production
                // storage never accepts these values through this command.
                x25519_public: [0; 32],
                ml_kem_public_hash: [0; 32],
            };
            require_no_extra_parts(&mut parts)?;
            if record.expires_at_unix <= now_unix {
                return Err(DirectoryApiError::InvalidSignedRecord);
            }
            store.upsert_unsafe_for_development(record);
            Ok("OK UNSAFE_LOCAL_DEVELOPMENT\n".to_string())
        }
        Some("GET") => {
            let node_id = next_part(&mut parts)?;
            let now = next_part(&mut parts)?
                .parse::<u64>()
                .map_err(|_| DirectoryApiError::BadInteger)?;
            require_no_extra_parts(&mut parts)?;
            if let Some(record) = store.get(node_id, now) {
                Ok(format!(
                    "FOUND {} {} {}\n",
                    record.node_id, record.address, record.expires_at_unix
                ))
            } else {
                Ok("NOT_FOUND\n".to_string())
            }
        }
        Some("PRUNE") => {
            if !config.allow_remote_prune {
                return Err(DirectoryApiError::RemotePruneDisabled);
            }
            let now = next_part(&mut parts)?
                .parse::<u64>()
                .map_err(|_| DirectoryApiError::BadInteger)?;
            require_no_extra_parts(&mut parts)?;
            store.prune_expired(now);
            Ok(format!("OK {}\n", store.len()))
        }
        _ => Err(DirectoryApiError::BadCommand),
    }
}

fn next_part<'a>(parts: &mut impl Iterator<Item = &'a str>) -> Result<&'a str, DirectoryApiError> {
    parts.next().ok_or(DirectoryApiError::BadCommand)
}

fn require_no_extra_parts<'a>(
    parts: &mut impl Iterator<Item = &'a str>,
) -> Result<(), DirectoryApiError> {
    if parts.next().is_some() {
        Err(DirectoryApiError::BadCommand)
    } else {
        Ok(())
    }
}

fn parse_hex_array<const N: usize>(input: &str) -> Result<[u8; N], DirectoryApiError> {
    if input.len() != N * 2 {
        return Err(DirectoryApiError::BadHex);
    }
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(input.as_bytes()[index * 2]).ok_or(DirectoryApiError::BadHex)?;
        let low = hex_nibble(input.as_bytes()[index * 2 + 1]).ok_or(DirectoryApiError::BadHex)?;
        *byte = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn serve_directory_api(
    bind_addr: &str,
    store: Arc<Mutex<DirectoryStore>>,
    config: DirectoryApiConfig,
    persistence_path: Option<PathBuf>,
) -> Result<(), DirectoryApiError> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|error| DirectoryApiError::Io(error.to_string()))?;
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|error| DirectoryApiError::Io(error.to_string()))?;
        let store = Arc::clone(&store);
        let config = config.clone();
        let persistence_path = persistence_path.clone();
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            if let Ok(len) = stream.read(&mut buffer).await
                && len > 0
            {
                let line = String::from_utf8_lossy(&buffer[..len]);
                let response = {
                    let mut guard = store.lock().expect("directory store lock");
                    let before_mutation = guard.clone();
                    match handle_command(&mut guard, &line, &config, unix_now()) {
                        Ok(response) => {
                            if let Some(path) = &persistence_path
                                && (line.starts_with("UPSERT") || line.starts_with("PRUNE"))
                                && let Err(error) = guard.save_to_file(path)
                            {
                                *guard = before_mutation;
                                format!("ERR persistence: {error}\n")
                            } else {
                                response
                            }
                        }
                        Err(error) => format!("ERR {error:?}\n"),
                    }
                };
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_record::sign_record;
    use ed25519_dalek::SigningKey;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn command_for(signed: &SignedRelayRecord) -> String {
        format!(
            "UPSERT_SIGNED {} {} {} {} {} {} {} {}",
            signed.record.node_id,
            signed.record.address,
            signed.record.expires_at_unix,
            hex(&signed.record.x25519_public),
            hex(&signed.record.ml_kem_public_hash),
            signed.signer_id,
            hex(&signed.verifying_key),
            hex(&signed.signature),
        )
    }

    fn signed_record() -> SignedRelayRecord {
        let signing = SigningKey::from_bytes(&[9; 32]);
        sign_record(
            RelayRecord {
                node_id: "n1".into(),
                address: "127.0.0.1:7000".parse().expect("address"),
                x25519_public: [1; 32],
                ml_kem_public_hash: [2; 32],
                expires_at_unix: 110,
            },
            "n1",
            &signing,
        )
    }

    #[test]
    fn unsigned_upsert_is_rejected_by_default() {
        let mut store = DirectoryStore::new();
        assert_eq!(
            handle_command(
                &mut store,
                "UPSERT n1 127.0.0.1:7000 110",
                &DirectoryApiConfig::default(),
                100,
            ),
            Err(DirectoryApiError::MutationDisabled)
        );
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn valid_signed_upsert_is_accepted_and_bad_signature_is_rejected() {
        let mut store = DirectoryStore::new();
        let signed = signed_record();
        assert_eq!(
            handle_command(
                &mut store,
                &command_for(&signed),
                &DirectoryApiConfig::default(),
                100,
            ),
            Ok("OK\n".to_string())
        );
        assert_eq!(store.get("n1", 100).expect("record").x25519_public, [1; 32]);

        let mut tampered = signed;
        tampered.signature[0] ^= 1;
        assert_eq!(
            handle_command(
                &mut store,
                &command_for(&tampered),
                &DirectoryApiConfig::default(),
                100,
            ),
            Err(DirectoryApiError::InvalidSignedRecord)
        );
    }

    #[test]
    fn zero_key_material_and_remote_prune_are_rejected_by_default() {
        let signing = SigningKey::from_bytes(&[10; 32]);
        let bad = sign_record(
            RelayRecord {
                node_id: "n2".into(),
                address: "127.0.0.1:7001".parse().expect("address"),
                x25519_public: [0; 32],
                ml_kem_public_hash: [2; 32],
                expires_at_unix: 110,
            },
            "n2",
            &signing,
        );
        let mut store = DirectoryStore::new();
        assert_eq!(
            handle_command(
                &mut store,
                &command_for(&bad),
                &DirectoryApiConfig::default(),
                100,
            ),
            Err(DirectoryApiError::InvalidSignedRecord)
        );
        assert_eq!(
            handle_command(&mut store, "PRUNE 100", &DirectoryApiConfig::default(), 100),
            Err(DirectoryApiError::RemotePruneDisabled)
        );
    }

    #[test]
    fn plaintext_mutation_requires_explicit_development_config() {
        let mut store = DirectoryStore::new();
        let config = DirectoryApiConfig {
            allow_unsafe_plaintext_mutation: true,
            allow_remote_prune: true,
            max_record_lifetime_seconds: 60,
        };
        assert_eq!(
            handle_command(&mut store, "UPSERT dev 127.0.0.1:7002 110", &config, 100),
            Ok("OK UNSAFE_LOCAL_DEVELOPMENT\n".to_string())
        );
        assert_eq!(
            handle_command(&mut store, "PRUNE 110", &config, 100),
            Ok("OK 0\n".to_string())
        );
    }
}
