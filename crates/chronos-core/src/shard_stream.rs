//! Encrypted single-block SHARD stream codec.
//!
//! This module connects the fixed-size AEAD cell primitive to the GF(2^8)
//! 16-of-10 erasure codec. It is still a single-block local codec rather than
//! the full CHRONOS network scheduler, but it gives relays/clients a real,
//! authenticated path for turning one plaintext message into 16 encrypted shards
//! and recovering from any 10 valid shards.

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

use crate::gf28::ReedSolomon16_10;
use crate::secure_cell::{ReceiveCellError, SecureCellReceiver, SecureCellSender, SecureShardCell};

pub const SHARD_STREAM_MAGIC: [u8; 4] = *b"SHD7";
pub const SHARD_STREAM_K: usize = 10;
pub const SHARD_STREAM_N: usize = 16;
pub const SHARD_STREAM_HEADER_SIZE: usize = 24;
pub const SHARD_STREAM_MAX_SYMBOL_BYTES: usize = 944 - SHARD_STREAM_HEADER_SIZE;
pub const SHARD_STREAM_FLAG_PARITY: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardStreamError {
    MessageTooLarge { got: usize, max: usize },
    Cell(ReceiveCellError),
    InvalidShardPayload,
    InvalidShardMagic,
    InvalidShardIndex(u8),
    InvalidCodecParameters { k: u8, n: u8 },
    ConflictingBlockMetadata,
    DuplicateShardIndex(u8),
    InsufficientValidShards { got: usize, need: usize },
    ErasureDecode(String),
    InvalidRecoveredLength { got: usize, expected: usize },
    SequenceRangeExhausted,
    BlockIdExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShardPlaintext {
    block_id: u64,
    total_len: usize,
    symbol_len: usize,
    shard_index: usize,
    shard_bytes: Vec<u8>,
}

impl ShardPlaintext {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SHARD_STREAM_HEADER_SIZE + self.shard_bytes.len());
        out.extend_from_slice(&SHARD_STREAM_MAGIC);
        out.extend_from_slice(&self.block_id.to_be_bytes());
        out.extend_from_slice(&(self.total_len as u32).to_be_bytes());
        out.extend_from_slice(&(self.symbol_len as u16).to_be_bytes());
        out.push(self.shard_index as u8);
        out.push(SHARD_STREAM_K as u8);
        out.push(SHARD_STREAM_N as u8);
        out.push(0); // reserved
        out.extend_from_slice(&[0u8; 2]); // reserved/alignment
        out.extend_from_slice(&self.shard_bytes);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, ShardStreamError> {
        if bytes.len() < SHARD_STREAM_HEADER_SIZE {
            return Err(ShardStreamError::InvalidShardPayload);
        }
        if bytes[0..4] != SHARD_STREAM_MAGIC {
            return Err(ShardStreamError::InvalidShardMagic);
        }

        let block_id = u64::from_be_bytes(bytes[4..12].try_into().expect("fixed slice"));
        let total_len = u32::from_be_bytes(bytes[12..16].try_into().expect("fixed slice")) as usize;
        let symbol_len =
            u16::from_be_bytes(bytes[16..18].try_into().expect("fixed slice")) as usize;
        let shard_index = bytes[18] as usize;
        let k = bytes[19];
        let n = bytes[20];

        if k as usize != SHARD_STREAM_K || n as usize != SHARD_STREAM_N {
            return Err(ShardStreamError::InvalidCodecParameters { k, n });
        }
        if shard_index >= SHARD_STREAM_N {
            return Err(ShardStreamError::InvalidShardIndex(shard_index as u8));
        }
        if bytes[21..24].iter().any(|&b| b != 0) {
            return Err(ShardStreamError::InvalidShardPayload);
        }

        let shard_bytes = bytes[SHARD_STREAM_HEADER_SIZE..].to_vec();
        if shard_bytes.len() != symbol_len {
            return Err(ShardStreamError::InvalidShardPayload);
        }

        Ok(Self {
            block_id,
            total_len,
            symbol_len,
            shard_index,
            shard_bytes,
        })
    }
}

pub struct SecureShardBlockCodec {
    rs: ReedSolomon16_10,
}

impl SecureShardBlockCodec {
    pub fn new() -> Self {
        Self {
            rs: ReedSolomon16_10::new(),
        }
    }

    pub fn max_message_bytes(&self) -> usize {
        SHARD_STREAM_K * SHARD_STREAM_MAX_SYMBOL_BYTES
    }

    /// Encodes using externally managed sequence and block identifiers.
    ///
    /// This is intentionally explicit because reusing a sequence with the same
    /// AEAD key and route tag breaks nonce safety. Normal callers should use
    /// `SecureShardBlockEncoder`.
    pub fn encode_message_with_external_ids_and_sequence(
        &self,
        key: &[u8; 32],
        route_tag: [u8; 16],
        block_id: u64,
        sequence_base: u64,
        message: &[u8],
    ) -> Result<Vec<SecureShardCell>, ShardStreamError> {
        if sequence_base > u64::MAX - SHARD_STREAM_N as u64 {
            return Err(ShardStreamError::SequenceRangeExhausted);
        }
        let mut sender = SecureCellSender::with_next_sequence(*key, route_tag, sequence_base);
        self.encode_message_with_sender(&mut sender, block_id, message)
    }

    fn encode_message_with_sender(
        &self,
        sender: &mut SecureCellSender,
        block_id: u64,
        message: &[u8],
    ) -> Result<Vec<SecureShardCell>, ShardStreamError> {
        if message.len() > self.max_message_bytes() {
            return Err(ShardStreamError::MessageTooLarge {
                got: message.len(),
                max: self.max_message_bytes(),
            });
        }

        let symbol_len = message.len().div_ceil(SHARD_STREAM_K).max(1);
        if symbol_len > SHARD_STREAM_MAX_SYMBOL_BYTES {
            return Err(ShardStreamError::MessageTooLarge {
                got: message.len(),
                max: self.max_message_bytes(),
            });
        }

        let mut data_shards = Vec::with_capacity(SHARD_STREAM_K);
        for idx in 0..SHARD_STREAM_K {
            let start = idx * symbol_len;
            let end = (start + symbol_len).min(message.len());
            let mut shard = vec![0u8; symbol_len];
            if start < message.len() {
                shard[..end - start].copy_from_slice(&message[start..end]);
            }
            data_shards.push(shard);
        }

        let data_refs: Vec<&[u8]> = data_shards.iter().map(Vec::as_slice).collect();
        let encoded = self
            .rs
            .encode(&data_refs)
            .map_err(ShardStreamError::ErasureDecode)?;

        encoded
            .into_iter()
            .enumerate()
            .map(|(shard_index, shard_bytes)| {
                let plain = ShardPlaintext {
                    block_id,
                    total_len: message.len(),
                    symbol_len,
                    shard_index,
                    shard_bytes,
                };
                let flags = if shard_index >= SHARD_STREAM_K {
                    SHARD_STREAM_FLAG_PARITY | shard_index as u8
                } else {
                    shard_index as u8
                };
                sender
                    .seal(flags, &plain.encode())
                    .map_err(|e| ShardStreamError::Cell(ReceiveCellError::Cell(e)))
            })
            .collect()
    }

    pub fn decode_message(
        &self,
        key: [u8; 32],
        cells: &[SecureShardCell],
    ) -> Result<Vec<u8>, ShardStreamError> {
        let mut receiver = SecureCellReceiver::new(key, 128)
            .map_err(|e| ShardStreamError::Cell(ReceiveCellError::Replay(e)))?;
        let mut seen_indices = BTreeSet::new();
        let mut surviving: Vec<Option<Vec<u8>>> = vec![None; SHARD_STREAM_N];
        let mut block_meta: Option<(u64, usize, usize)> = None;
        let mut valid_count = 0usize;

        for cell in cells {
            let plaintext = match receiver.open(cell) {
                Ok(plaintext) => plaintext,
                Err(_) => continue,
            };
            let shard = ShardPlaintext::decode(&plaintext)?;

            let meta = (shard.block_id, shard.total_len, shard.symbol_len);
            if let Some(existing) = block_meta {
                if existing != meta {
                    return Err(ShardStreamError::ConflictingBlockMetadata);
                }
            } else {
                block_meta = Some(meta);
            }

            if !seen_indices.insert(shard.shard_index) {
                return Err(ShardStreamError::DuplicateShardIndex(
                    shard.shard_index as u8,
                ));
            }
            let shard_index = shard.shard_index;
            surviving[shard_index] = Some(shard.shard_bytes);
            valid_count += 1;

            if valid_count == SHARD_STREAM_K {
                break;
            }
        }

        if valid_count < SHARD_STREAM_K {
            return Err(ShardStreamError::InsufficientValidShards {
                got: valid_count,
                need: SHARD_STREAM_K,
            });
        }

        let (_, total_len, symbol_len) = block_meta.ok_or(ShardStreamError::InvalidShardPayload)?;
        let decoded = self
            .rs
            .decode(&surviving)
            .map_err(ShardStreamError::ErasureDecode)?;
        let mut message = Vec::with_capacity(SHARD_STREAM_K * symbol_len);
        for shard in decoded {
            message.extend_from_slice(&shard);
        }
        if message.len() < total_len {
            return Err(ShardStreamError::InvalidRecoveredLength {
                got: message.len(),
                expected: total_len,
            });
        }
        message.truncate(total_len);
        Ok(message)
    }
}

/// Stateful safe encoder for successive SHARD-Stream blocks.
///
/// It owns the secure-cell sender and monotonically advances a block identifier,
/// so normal callers never choose AEAD sequence values or block identifiers.
pub struct SecureShardBlockEncoder {
    codec: SecureShardBlockCodec,
    sender: SecureCellSender,
    next_block_id: u64,
}

impl SecureShardBlockEncoder {
    pub fn new(key: [u8; 32], route_tag: [u8; 16]) -> Self {
        Self::with_next_identifiers(key, route_tag, 0, 0)
    }

    /// Restores durable high-water marks for a previously used key domain.
    /// Both identifiers are required: restoring only a block identifier while
    /// resetting cell sequence numbers would risk AEAD nonce reuse.
    pub fn with_next_identifiers(
        key: [u8; 32],
        route_tag: [u8; 16],
        next_block_id: u64,
        next_sequence: u64,
    ) -> Self {
        Self {
            codec: SecureShardBlockCodec::new(),
            sender: SecureCellSender::with_next_sequence(key, route_tag, next_sequence),
            next_block_id,
        }
    }

    pub fn next_block_id(&self) -> u64 {
        self.next_block_id
    }

    pub fn next_sequence(&self) -> u64 {
        self.sender.next_sequence()
    }

    pub fn encode_message(
        &mut self,
        message: &[u8],
    ) -> Result<Vec<SecureShardCell>, ShardStreamError> {
        if self.next_block_id == u64::MAX {
            return Err(ShardStreamError::BlockIdExhausted);
        }
        let block_id = self.next_block_id;
        let cells = self
            .codec
            .encode_message_with_sender(&mut self.sender, block_id, message)?;
        self.next_block_id += 1;
        Ok(cells)
    }
}

impl Default for SecureShardBlockCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_cell::derive_link_key;

    fn key() -> [u8; 32] {
        derive_link_key(&[0x42u8; 32], &[0x24u8; 16]).expect("key")
    }

    #[test]
    fn shard_stream_recovers_from_any_ten_valid_cells() {
        let codec = SecureShardBlockCodec::new();
        let message = (0..4096).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let cells = codec
            .encode_message_with_external_ids_and_sequence(&key(), [0xAA; 16], 7, 1000, &message)
            .expect("encode");
        assert_eq!(cells.len(), SHARD_STREAM_N);

        let subset = vec![
            cells[0], cells[1], cells[3], cells[4], cells[6], cells[8], cells[10], cells[12],
            cells[14], cells[15],
        ];
        let recovered = codec.decode_message(key(), &subset).expect("decode");
        assert_eq!(recovered, message);
    }

    #[test]
    fn stateful_encoder_allocates_unique_sequences_and_block_ids() {
        let mut encoder = SecureShardBlockEncoder::new(key(), [0xE1; 16]);
        let first = encoder.encode_message(b"first block").expect("first");
        let second = encoder.encode_message(b"second block").expect("second");
        assert_eq!(first.len(), SHARD_STREAM_N);
        assert_eq!(second.len(), SHARD_STREAM_N);
        assert_eq!(first[0].sequence(), 0);
        assert_eq!(first[SHARD_STREAM_N - 1].sequence(), 15);
        assert_eq!(second[0].sequence(), 16);
        assert_eq!(encoder.next_sequence(), 32);
        assert_eq!(encoder.next_block_id(), 2);
        assert_ne!(first[0].sequence(), second[0].sequence());
    }

    #[test]
    fn external_sequence_range_is_explicit_and_checked() {
        let codec = SecureShardBlockCodec::new();
        assert_eq!(
            codec.encode_message_with_external_ids_and_sequence(
                &key(),
                [0xE2; 16],
                1,
                u64::MAX - 15,
                b"will not fit a full block",
            ),
            Err(ShardStreamError::SequenceRangeExhausted)
        );
    }

    #[test]
    fn shard_stream_skips_tampered_cells_when_enough_valid_remain() {
        let codec = SecureShardBlockCodec::new();
        let message = b"resilient authenticated erasure block".repeat(64);
        let mut cells = codec
            .encode_message_with_external_ids_and_sequence(&key(), [0xBB; 16], 8, 2000, &message)
            .expect("encode");
        cells[2].ciphertext[0] ^= 0x55;
        cells[5].auth_tag[0] ^= 0x55;

        let recovered = codec.decode_message(key(), &cells).expect("decode");
        assert_eq!(recovered, message);
    }

    #[test]
    fn shard_stream_fails_when_too_few_valid_cells_remain() {
        let codec = SecureShardBlockCodec::new();
        let message = b"too few shards".repeat(32);
        let cells = codec
            .encode_message_with_external_ids_and_sequence(&key(), [0xCC; 16], 9, 3000, &message)
            .expect("encode");
        let err = codec
            .decode_message(key(), &cells[..9])
            .expect_err("must fail");
        assert_eq!(
            err,
            ShardStreamError::InsufficientValidShards {
                got: 9,
                need: SHARD_STREAM_K,
            }
        );
    }

    #[test]
    fn shard_stream_rejects_oversized_single_block_message() {
        let codec = SecureShardBlockCodec::new();
        let msg = vec![0u8; codec.max_message_bytes() + 1];
        assert!(matches!(
            codec.encode_message_with_external_ids_and_sequence(&key(), [0xDD; 16], 10, 4000, &msg),
            Err(ShardStreamError::MessageTooLarge { .. })
        ));
    }
}
