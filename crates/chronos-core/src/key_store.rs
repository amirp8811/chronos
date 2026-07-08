//! Runtime node key generation and file persistence.
//!
//! This is the first key-management layer for local prototypes. It persists an
//! X25519 node secret and the ML-KEM-768 decapsulation seed with owner-only file
//! permissions on Unix platforms.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::handshake::X25519NodeSecret;
use crate::hybrid_route::MlKem768RouteKeypair;
use ed25519_dalek::SigningKey;

pub const X25519_KEY_FILE: &str = "x25519.nodekey";
pub const MLKEM768_SEED_FILE: &str = "mlkem768.seed";
pub const ED25519_IDENTITY_FILE: &str = "ed25519.identity";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStoreError {
    Io(String),
    InvalidLength {
        path: PathBuf,
        got: usize,
        expected: usize,
    },
    Random(String),
}

#[derive(Clone)]
pub struct NodeKeyMaterial {
    pub x25519: X25519NodeSecret,
    pub ml_kem_768: MlKem768RouteKeypair,
    pub identity_signing: SigningKey,
}

impl NodeKeyMaterial {
    pub fn generate() -> Result<Self, KeyStoreError> {
        let mut x25519_bytes = [0u8; 32];
        let mut identity_bytes = [0u8; 32];
        getrandom::getrandom(&mut x25519_bytes)
            .map_err(|e| KeyStoreError::Random(e.to_string()))?;
        getrandom::getrandom(&mut identity_bytes)
            .map_err(|e| KeyStoreError::Random(e.to_string()))?;
        Ok(Self {
            x25519: X25519NodeSecret::from_bytes(x25519_bytes),
            ml_kem_768: MlKem768RouteKeypair::generate(),
            identity_signing: SigningKey::from_bytes(&identity_bytes),
        })
    }

    pub fn save_to_dir(&self, dir: impl AsRef<Path>) -> Result<(), KeyStoreError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|e| KeyStoreError::Io(e.to_string()))?;
        write_secret_file(&dir.join(X25519_KEY_FILE), &self.x25519.to_bytes())?;
        write_secret_file(
            &dir.join(MLKEM768_SEED_FILE),
            &self.ml_kem_768.to_seed_bytes(),
        )?;
        write_secret_file(
            &dir.join(ED25519_IDENTITY_FILE),
            &self.identity_signing.to_bytes(),
        )?;
        Ok(())
    }

    pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<Self, KeyStoreError> {
        let dir = dir.as_ref();
        let x25519 = read_exact_secret::<32>(&dir.join(X25519_KEY_FILE))?;
        let mlkem = read_exact_secret::<64>(&dir.join(MLKEM768_SEED_FILE))?;
        let identity = read_exact_secret::<32>(&dir.join(ED25519_IDENTITY_FILE))?;
        Ok(Self {
            x25519: X25519NodeSecret::from_bytes(x25519),
            ml_kem_768: MlKem768RouteKeypair::from_seed_bytes(mlkem),
            identity_signing: SigningKey::from_bytes(&identity),
        })
    }

    pub fn load_or_generate(dir: impl AsRef<Path>) -> Result<Self, KeyStoreError> {
        match Self::load_from_dir(&dir) {
            Ok(keys) => Ok(keys),
            Err(_) => {
                let keys = Self::generate()?;
                keys.save_to_dir(dir)?;
                Ok(keys)
            }
        }
    }
}

fn read_exact_secret<const N: usize>(path: &Path) -> Result<[u8; N], KeyStoreError> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| KeyStoreError::Io(e.to_string()))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| KeyStoreError::Io(e.to_string()))?;
    if buf.len() != N {
        return Err(KeyStoreError::InvalidLength {
            path: path.to_path_buf(),
            got: buf.len(),
            expected: N,
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&buf);
    Ok(out)
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), KeyStoreError> {
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| KeyStoreError::Io(e.to_string()))?;
    file.write_all(bytes)
        .map_err(|e| KeyStoreError::Io(e.to_string()))?;
    file.sync_all()
        .map_err(|e| KeyStoreError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_route::encapsulate_route_secret;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_key_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("chronos-key-test-{nonce}"))
    }

    #[test]
    fn node_keys_save_and_load_round_trip() {
        let dir = temp_key_dir();
        let keys = NodeKeyMaterial::generate().expect("generate");
        keys.save_to_dir(&dir).expect("save");
        let loaded = NodeKeyMaterial::load_from_dir(&dir).expect("load");
        assert_eq!(loaded.x25519.to_bytes(), keys.x25519.to_bytes());
        assert_eq!(
            loaded.ml_kem_768.to_seed_bytes(),
            keys.ml_kem_768.to_seed_bytes()
        );
        assert_eq!(
            loaded.identity_signing.to_bytes(),
            keys.identity_signing.to_bytes()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn loaded_keys_work_for_hybrid_route_setup() {
        let dir = temp_key_dir();
        let receiver = NodeKeyMaterial::generate().expect("generate receiver");
        receiver.save_to_dir(&dir).expect("save");
        let loaded_receiver = NodeKeyMaterial::load_from_dir(&dir).expect("load");
        let sender = NodeKeyMaterial::generate().expect("generate sender");

        let init = encapsulate_route_secret(
            &loaded_receiver.ml_kem_768.encapsulation_key,
            &sender.x25519,
            loaded_receiver.x25519.public(),
            b"key-store-hybrid-test",
        )
        .expect("encapsulate");
        let recv = loaded_receiver
            .ml_kem_768
            .decapsulate_route_secret(
                &init.ml_kem_ciphertext,
                init.sender_x25519_public,
                &loaded_receiver.x25519,
                b"key-store-hybrid-test",
            )
            .expect("decapsulate");
        assert_eq!(init.route_secret, recv);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_rejects_wrong_key_length() {
        let dir = temp_key_dir();
        fs::create_dir_all(&dir).expect("mkdir");
        write_secret_file(&dir.join(X25519_KEY_FILE), &[1, 2, 3]).expect("write short");
        write_secret_file(&dir.join(MLKEM768_SEED_FILE), &[0u8; 64]).expect("write mlkem");
        write_secret_file(&dir.join(ED25519_IDENTITY_FILE), &[0u8; 32]).expect("write identity");
        let err = match NodeKeyMaterial::load_from_dir(&dir) {
            Ok(_) => panic!("short key unexpectedly loaded"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            KeyStoreError::InvalidLength { expected: 32, .. }
        ));
        let _ = fs::remove_dir_all(dir);
    }
}
