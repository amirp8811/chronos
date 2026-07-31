//! Runtime node key generation and file persistence.
//!
//! Key material is generated only for a completely absent key set. Corruption,
//! partial key sets, permission failures, and symbolic links are errors: silently
//! replacing any of those files would change a node identity.

use std::fs::{self, File, OpenOptions};
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
    Io {
        path: PathBuf,
        message: String,
    },
    InvalidLength {
        path: PathBuf,
        got: usize,
        expected: usize,
    },
    PartialKeySet {
        dir: PathBuf,
    },
    SymlinkRefused {
        path: PathBuf,
    },
    InsecurePermissions {
        path: PathBuf,
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
            .map_err(|error| KeyStoreError::Random(error.to_string()))?;
        getrandom::getrandom(&mut identity_bytes)
            .map_err(|error| KeyStoreError::Random(error.to_string()))?;
        Ok(Self {
            x25519: X25519NodeSecret::from_bytes(x25519_bytes),
            ml_kem_768: MlKem768RouteKeypair::generate(),
            identity_signing: SigningKey::from_bytes(&identity_bytes),
        })
    }

    pub fn save_to_dir(&self, dir: impl AsRef<Path>) -> Result<(), KeyStoreError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|error| io_error(dir, error))?;
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

    /// Loads an existing complete key set or creates a new complete key set.
    ///
    /// A partial key set is never repaired automatically. That behaviour prevents
    /// a damaged key file from silently rotating the stable relay identity.
    pub fn load_or_generate(dir: impl AsRef<Path>) -> Result<Self, KeyStoreError> {
        let dir = dir.as_ref();
        let paths = key_paths(dir);
        let presence = paths
            .iter()
            .map(|path| path_exists(path))
            .collect::<Result<Vec<_>, _>>()?;
        if presence.iter().all(|present| !present) {
            let keys = Self::generate()?;
            keys.save_to_dir(dir)?;
            return Ok(keys);
        }
        if presence.iter().all(|present| *present) {
            return Self::load_from_dir(dir);
        }
        Err(KeyStoreError::PartialKeySet {
            dir: dir.to_path_buf(),
        })
    }
}

fn key_paths(dir: &Path) -> [PathBuf; 3] {
    [
        dir.join(X25519_KEY_FILE),
        dir.join(MLKEM768_SEED_FILE),
        dir.join(ED25519_IDENTITY_FILE),
    ]
}

fn path_exists(path: &Path) -> Result<bool, KeyStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(path, error)),
    }
}

fn io_error(path: &Path, error: std::io::Error) -> KeyStoreError {
    KeyStoreError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

fn ensure_regular_file(path: &Path) -> Result<(), KeyStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(KeyStoreError::SymlinkRefused {
            path: path.to_path_buf(),
        });
    }
    if !metadata.file_type().is_file() {
        return Err(KeyStoreError::Io {
            path: path.to_path_buf(),
            message: "key path is not a regular file".to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyStoreError::InsecurePermissions {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

fn read_exact_secret<const N: usize>(path: &Path) -> Result<[u8; N], KeyStoreError> {
    ensure_regular_file(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|error| io_error(path, error))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|error| io_error(path, error))?;
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
    let parent = path.parent().ok_or_else(|| KeyStoreError::Io {
        path: path.to_path_buf(),
        message: "key path has no parent directory".to_string(),
    })?;
    fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
    if path_exists(path)? {
        // Do not replace a link or non-file. A normal existing file is safely
        // replaced by the atomic rename below, correcting its mode to 0600.
        let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
        if metadata.file_type().is_symlink() {
            return Err(KeyStoreError::SymlinkRefused {
                path: path.to_path_buf(),
            });
        }
        if !metadata.file_type().is_file() {
            return Err(KeyStoreError::Io {
                path: path.to_path_buf(),
                message: "key path is not a regular file".to_string(),
            });
        }
    }

    let temporary = temporary_path(path)?;
    let result = write_secret_file_atomic(&temporary, path, bytes, parent);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(path: &Path) -> Result<PathBuf, KeyStoreError> {
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix).map_err(|error| KeyStoreError::Random(error.to_string()))?;
    let name = path.file_name().ok_or_else(|| KeyStoreError::Io {
        path: path.to_path_buf(),
        message: "key path has no filename".to_string(),
    })?;
    Ok(path.with_file_name(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        hex_suffix(&suffix)
    )))
}

fn hex_suffix(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn write_secret_file_atomic(
    temporary: &Path,
    destination: &Path,
    bytes: &[u8],
    parent: &Path,
) -> Result<(), KeyStoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(temporary)
        .map_err(|error| io_error(temporary, error))?;
    file.write_all(bytes)
        .map_err(|error| io_error(temporary, error))?;
    file.sync_all()
        .map_err(|error| io_error(temporary, error))?;
    drop(file);

    fs::rename(temporary, destination).map_err(|error| io_error(destination, error))?;
    #[cfg(unix)]
    {
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| io_error(parent, error))?;
    }
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
    fn missing_directory_generates_complete_key_set() {
        let dir = temp_key_dir();
        let keys = NodeKeyMaterial::load_or_generate(&dir).expect("generate missing directory");
        assert!(dir.join(X25519_KEY_FILE).exists());
        assert_eq!(
            NodeKeyMaterial::load_from_dir(&dir)
                .expect("load")
                .identity_signing
                .to_bytes(),
            keys.identity_signing.to_bytes()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn empty_existing_directory_generates_complete_key_set() {
        let dir = temp_key_dir();
        fs::create_dir_all(&dir).expect("mkdir");
        NodeKeyMaterial::load_or_generate(&dir).expect("generate empty directory");
        assert!(dir.join(X25519_KEY_FILE).exists());
        assert!(dir.join(MLKEM768_SEED_FILE).exists());
        assert!(dir.join(ED25519_IDENTITY_FILE).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_or_partial_key_set_is_not_regenerated() {
        let dir = temp_key_dir();
        fs::create_dir_all(&dir).expect("mkdir");
        write_secret_file(&dir.join(X25519_KEY_FILE), &[1, 2, 3]).expect("write short");
        assert!(matches!(
            NodeKeyMaterial::load_or_generate(&dir),
            Err(KeyStoreError::PartialKeySet { .. })
        ));
        assert_eq!(
            fs::read(dir.join(X25519_KEY_FILE)).expect("read"),
            [1, 2, 3]
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn complete_malformed_key_set_returns_length_error_without_overwrite() {
        let dir = temp_key_dir();
        fs::create_dir_all(&dir).expect("mkdir");
        write_secret_file(&dir.join(X25519_KEY_FILE), &[1, 2, 3]).expect("write short");
        write_secret_file(&dir.join(MLKEM768_SEED_FILE), &[0u8; 64]).expect("write mlkem");
        write_secret_file(&dir.join(ED25519_IDENTITY_FILE), &[0u8; 32]).expect("write identity");
        assert!(matches!(
            NodeKeyMaterial::load_or_generate(&dir),
            Err(KeyStoreError::InvalidLength { expected: 32, .. })
        ));
        assert_eq!(
            fs::read(dir.join(X25519_KEY_FILE)).expect("read"),
            [1, 2, 3]
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn saved_key_files_are_owner_only_and_loose_files_are_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_key_dir();
        let keys = NodeKeyMaterial::generate().expect("keys");
        keys.save_to_dir(&dir).expect("save");
        let key_path = dir.join(X25519_KEY_FILE);
        assert_eq!(
            fs::metadata(&key_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("loosen");
        assert!(matches!(
            NodeKeyMaterial::load_from_dir(&dir),
            Err(KeyStoreError::InsecurePermissions { .. })
        ));
        keys.save_to_dir(&dir).expect("atomic save corrects mode");
        assert_eq!(
            fs::metadata(&key_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(dir);
    }
}
