//! Versioned fixed-size authenticated SHARD cell primitive.
//!
//! This is the first production-oriented packet primitive in the workspace. It
//! does **not** implement the full CHRONOS Sphinx-PQC route construction yet;
//! instead it provides the fixed 1,200-byte application-cell envelope with real
//! AEAD authentication/encryption so higher layers can stop relying on the older
//! SHA-256/XOR simulation path.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::framing::APP_CELL_PAYLOAD_SIZE;

pub const SECURE_CELL_MAGIC: [u8; 4] = *b"CHR7";
pub const SECURE_CELL_VERSION: u8 = 1;
pub const SECURE_CELL_HEADER_SIZE: usize = 36;
pub const SECURE_CELL_CIPHERTEXT_SIZE: usize = 944;
pub const SECURE_CELL_TAG_SIZE: usize = 16;
pub const SECURE_CELL_RESERVED_SIZE: usize = APP_CELL_PAYLOAD_SIZE
    - SECURE_CELL_HEADER_SIZE
    - SECURE_CELL_CIPHERTEXT_SIZE
    - SECURE_CELL_TAG_SIZE;
pub const SECURE_CELL_AAD_SIZE: usize = SECURE_CELL_HEADER_SIZE + SECURE_CELL_RESERVED_SIZE;

const HKDF_INFO_LINK_KEY: &[u8] = b"chronos-v7/link-aead/chacha20poly1305";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureCellError {
    PayloadTooLarge { got: usize, max: usize },
    InvalidKeyMaterial,
    InvalidMagic,
    UnsupportedVersion(u8),
    ReservedBytesNonZero,
    InvalidPayloadLength(u16),
    AuthenticationFailed,
}

/// Derive a 32-byte AEAD link key from a per-link shared secret plus route tag.
///
/// In the final spec implementation, `shared_secret` should come from the hybrid
/// ML-KEM/X25519 handshake. For now this function gives every caller a single,
/// testable HKDF boundary instead of ad-hoc hashing.
pub fn derive_link_key(
    shared_secret: &[u8],
    route_tag: &[u8; 16],
) -> Result<[u8; 32], SecureCellError> {
    if shared_secret.len() < 32 {
        return Err(SecureCellError::InvalidKeyMaterial);
    }

    let hk = Hkdf::<Sha256>::new(Some(route_tag), shared_secret);
    let mut out = [0u8; 32];
    hk.expand(HKDF_INFO_LINK_KEY, &mut out)
        .map_err(|_| SecureCellError::InvalidKeyMaterial)?;
    Ok(out)
}

/// A fixed 1,200-byte app cell with authenticated metadata and padded payload.
///
/// Layout:
///
/// ```text
/// 0..4      magic = "CHR7"
/// 4         version = 1
/// 5         flags
/// 6..8      plaintext payload length, big endian
/// 8..24     route/session tag
/// 24..36    96-bit AEAD nonce/sequence IV
/// 36..980   944-byte padded ciphertext
/// 980..996  ChaCha20-Poly1305 tag
/// 996..1200 reserved, all zero, authenticated by validation policy
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecureShardCell {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: u8,
    pub payload_len_be: [u8; 2],
    pub route_tag: [u8; 16],
    pub seq_iv: [u8; 12],
    pub ciphertext: [u8; SECURE_CELL_CIPHERTEXT_SIZE],
    pub auth_tag: [u8; SECURE_CELL_TAG_SIZE],
    pub reserved: [u8; SECURE_CELL_RESERVED_SIZE],
}

impl SecureShardCell {
    pub fn encrypt(
        key: &[u8; 32],
        route_tag: [u8; 16],
        seq: u64,
        flags: u8,
        payload: &[u8],
    ) -> Result<Self, SecureCellError> {
        if payload.len() > SECURE_CELL_CIPHERTEXT_SIZE {
            return Err(SecureCellError::PayloadTooLarge {
                got: payload.len(),
                max: SECURE_CELL_CIPHERTEXT_SIZE,
            });
        }

        let mut seq_iv = [0u8; 12];
        seq_iv[4..].copy_from_slice(&seq.to_be_bytes());

        let mut cell = Self {
            magic: SECURE_CELL_MAGIC,
            version: SECURE_CELL_VERSION,
            flags,
            payload_len_be: (payload.len() as u16).to_be_bytes(),
            route_tag,
            seq_iv,
            ciphertext: [0u8; SECURE_CELL_CIPHERTEXT_SIZE],
            auth_tag: [0u8; SECURE_CELL_TAG_SIZE],
            reserved: [0u8; SECURE_CELL_RESERVED_SIZE],
        };
        cell.ciphertext[..payload.len()].copy_from_slice(payload);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&cell.seq_iv),
                &cell.aad(),
                &mut cell.ciphertext,
            )
            .map_err(|_| SecureCellError::AuthenticationFailed)?;
        cell.auth_tag.copy_from_slice(&tag);
        Ok(cell)
    }

    pub fn decrypt(&self, key: &[u8; 32]) -> Result<Vec<u8>, SecureCellError> {
        self.validate_pre_auth_header()?;

        let mut plaintext = self.ciphertext;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&self.seq_iv),
                &self.aad(),
                &mut plaintext,
                Tag::from_slice(&self.auth_tag),
            )
            .map_err(|_| SecureCellError::AuthenticationFailed)?;

        let payload_len = self.payload_len() as usize;
        Ok(plaintext[..payload_len].to_vec())
    }

    pub fn payload_len(&self) -> u16 {
        u16::from_be_bytes(self.payload_len_be)
    }

    pub fn sequence(&self) -> u64 {
        u64::from_be_bytes(self.seq_iv[4..12].try_into().expect("fixed slice"))
    }

    pub fn to_app_cell_bytes(&self) -> [u8; APP_CELL_PAYLOAD_SIZE] {
        let mut out = [0u8; APP_CELL_PAYLOAD_SIZE];
        out[0..4].copy_from_slice(&self.magic);
        out[4] = self.version;
        out[5] = self.flags;
        out[6..8].copy_from_slice(&self.payload_len_be);
        out[8..24].copy_from_slice(&self.route_tag);
        out[24..36].copy_from_slice(&self.seq_iv);
        out[36..980].copy_from_slice(&self.ciphertext);
        out[980..996].copy_from_slice(&self.auth_tag);
        out[996..1200].copy_from_slice(&self.reserved);
        out
    }

    pub fn from_app_cell_bytes(
        bytes: &[u8; APP_CELL_PAYLOAD_SIZE],
    ) -> Result<Self, SecureCellError> {
        let cell = Self {
            magic: bytes[0..4].try_into().expect("fixed slice"),
            version: bytes[4],
            flags: bytes[5],
            payload_len_be: bytes[6..8].try_into().expect("fixed slice"),
            route_tag: bytes[8..24].try_into().expect("fixed slice"),
            seq_iv: bytes[24..36].try_into().expect("fixed slice"),
            ciphertext: bytes[36..980].try_into().expect("fixed slice"),
            auth_tag: bytes[980..996].try_into().expect("fixed slice"),
            reserved: bytes[996..1200].try_into().expect("fixed slice"),
        };
        cell.validate_pre_auth_header()?;
        Ok(cell)
    }

    fn validate_pre_auth_header(&self) -> Result<(), SecureCellError> {
        if self.magic != SECURE_CELL_MAGIC {
            return Err(SecureCellError::InvalidMagic);
        }
        if self.version != SECURE_CELL_VERSION {
            return Err(SecureCellError::UnsupportedVersion(self.version));
        }
        if self.payload_len() as usize > SECURE_CELL_CIPHERTEXT_SIZE {
            return Err(SecureCellError::InvalidPayloadLength(self.payload_len()));
        }
        Ok(())
    }

    fn aad(&self) -> [u8; SECURE_CELL_AAD_SIZE] {
        let mut aad = [0u8; SECURE_CELL_AAD_SIZE];
        aad[0..4].copy_from_slice(&self.magic);
        aad[4] = self.version;
        aad[5] = self.flags;
        aad[6..8].copy_from_slice(&self.payload_len_be);
        aad[8..24].copy_from_slice(&self.route_tag);
        aad[24..36].copy_from_slice(&self.seq_iv);
        aad[36..].copy_from_slice(&self.reserved);
        aad
    }
}

/// Sliding replay detector for monotonically sequenced cells.
///
/// The window accepts out-of-order delivery within the last `window_size` sequence
/// numbers, rejects exact duplicates, and rejects stale cells that have fallen out
/// of the window. It is intentionally independent of wall-clock time so tests and
/// relay pipelines have deterministic behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    Duplicate { seq: u64 },
    Stale { seq: u64, highest_seen: u64 },
    InvalidWindowSize(usize),
}

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest_seen: Option<u64>,
    seen_bitmap: u128,
    window_size: usize,
}

impl ReplayWindow {
    pub fn new(window_size: usize) -> Result<Self, ReplayError> {
        if !(1..=128).contains(&window_size) {
            return Err(ReplayError::InvalidWindowSize(window_size));
        }
        Ok(Self {
            highest_seen: None,
            seen_bitmap: 0,
            window_size,
        })
    }

    pub fn observe(&mut self, seq: u64) -> Result<(), ReplayError> {
        match self.highest_seen {
            None => {
                self.highest_seen = Some(seq);
                self.seen_bitmap = 1;
                Ok(())
            }
            Some(highest) if seq > highest => {
                let shift = seq - highest;
                self.seen_bitmap = if shift >= 128 {
                    0
                } else {
                    self.seen_bitmap << shift
                };
                self.seen_bitmap |= 1;
                self.highest_seen = Some(seq);
                Ok(())
            }
            Some(highest) => {
                let offset = highest - seq;
                if offset >= self.window_size as u64 || offset >= 128 {
                    return Err(ReplayError::Stale {
                        seq,
                        highest_seen: highest,
                    });
                }
                let mask = 1u128 << offset;
                if (self.seen_bitmap & mask) != 0 {
                    return Err(ReplayError::Duplicate { seq });
                }
                self.seen_bitmap |= mask;
                Ok(())
            }
        }
    }
}

/// Stateful receive-side helper: authenticate/decrypt first, then advance replay state.
pub struct SecureCellReceiver {
    key: [u8; 32],
    replay: ReplayWindow,
}

impl SecureCellReceiver {
    pub fn new(key: [u8; 32], replay_window_size: usize) -> Result<Self, ReplayError> {
        Ok(Self {
            key,
            replay: ReplayWindow::new(replay_window_size)?,
        })
    }

    pub fn open(&mut self, cell: &SecureShardCell) -> Result<Vec<u8>, ReceiveCellError> {
        let plaintext = cell.decrypt(&self.key).map_err(ReceiveCellError::Cell)?;
        self.replay
            .observe(cell.sequence())
            .map_err(ReceiveCellError::Replay)?;
        Ok(plaintext)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveCellError {
    Cell(SecureCellError),
    Replay(ReplayError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        derive_link_key(&[7u8; 32], &[9u8; 16]).expect("derive")
    }

    #[test]
    fn secure_cell_round_trips_fixed_size_bytes() {
        let key = test_key();
        let payload = b"authenticated CHRONOS payload";
        let cell = SecureShardCell::encrypt(&key, [1u8; 16], 42, 0xA0, payload).expect("encrypt");
        let bytes = cell.to_app_cell_bytes();
        assert_eq!(bytes.len(), APP_CELL_PAYLOAD_SIZE);

        let parsed = SecureShardCell::from_app_cell_bytes(&bytes).expect("parse");
        let decrypted = parsed.decrypt(&key).expect("decrypt");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn secure_cell_detects_ciphertext_tampering() {
        let key = test_key();
        let mut cell = SecureShardCell::encrypt(&key, [1u8; 16], 43, 0, b"msg").expect("encrypt");
        cell.ciphertext[0] ^= 0x80;
        assert_eq!(
            cell.decrypt(&key),
            Err(SecureCellError::AuthenticationFailed)
        );
    }

    #[test]
    fn secure_cell_detects_reserved_tampering() {
        let key = test_key();
        let mut cell = SecureShardCell::encrypt(&key, [1u8; 16], 46, 0, b"msg").expect("encrypt");
        cell.reserved[0] = 1;
        assert_eq!(
            cell.decrypt(&key),
            Err(SecureCellError::AuthenticationFailed)
        );
    }

    #[test]
    fn secure_cell_detects_authenticated_header_tampering() {
        let key = test_key();
        let mut cell = SecureShardCell::encrypt(&key, [1u8; 16], 44, 0, b"msg").expect("encrypt");
        cell.flags ^= 0x01;
        assert_eq!(
            cell.decrypt(&key),
            Err(SecureCellError::AuthenticationFailed)
        );
    }

    #[test]
    fn secure_cell_rejects_oversized_payload() {
        let key = test_key();
        let payload = vec![0u8; SECURE_CELL_CIPHERTEXT_SIZE + 1];
        assert!(matches!(
            SecureShardCell::encrypt(&key, [1u8; 16], 45, 0, &payload),
            Err(SecureCellError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn replay_window_accepts_out_of_order_once() {
        let mut replay = ReplayWindow::new(8).expect("window");
        for seq in [10, 12, 11, 9] {
            replay.observe(seq).expect("fresh sequence");
        }
        assert_eq!(replay.observe(11), Err(ReplayError::Duplicate { seq: 11 }));
        assert_eq!(
            replay.observe(3),
            Err(ReplayError::Stale {
                seq: 3,
                highest_seen: 12,
            })
        );
    }

    #[test]
    fn receiver_authenticates_then_rejects_replay() {
        let key = test_key();
        let cell = SecureShardCell::encrypt(&key, [2u8; 16], 77, 0, b"hello").expect("encrypt");
        let mut receiver = SecureCellReceiver::new(key, 32).expect("receiver");
        assert_eq!(receiver.open(&cell).expect("first open"), b"hello");
        assert_eq!(
            receiver.open(&cell),
            Err(ReceiveCellError::Replay(ReplayError::Duplicate { seq: 77 }))
        );
    }
}
