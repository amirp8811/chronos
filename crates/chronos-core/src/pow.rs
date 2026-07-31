//! Prototype proof-of-work filtering helpers.
//!
//! The UDP relay uses the newer address-bound admission implementation in
//! `pow_admission`. This module remains a local filter model and fails closed if
//! retry-cookie mode is selected without caller-provided key material.

use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// In-memory Bloom-style nonce filter used by the local model.
pub struct SramCuckooBloomFilter {
    pub sram_bit_arrays: [Vec<AtomicU64>; 3],
    pub words_per_array: usize,
    pub current_epoch_idx: usize,
    pub last_rotation_time: Instant,
}

impl SramCuckooBloomFilter {
    pub fn new() -> Self {
        let words_per_array = 87_381;
        let sram_bit_arrays = [
            (0..words_per_array).map(|_| AtomicU64::new(0)).collect(),
            (0..words_per_array).map(|_| AtomicU64::new(0)).collect(),
            (0..words_per_array).map(|_| AtomicU64::new(0)).collect(),
        ];
        Self {
            sram_bit_arrays,
            words_per_array,
            current_epoch_idx: 0,
            last_rotation_time: Instant::now(),
        }
    }

    pub fn check_and_insert_nonce(&self, nonce: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(nonce.as_bytes());
        let hash = hasher.finalize();
        let indices = [
            u64::from_le_bytes(hash[0..8].try_into().expect("fixed slice")) as usize
                % (self.words_per_array * 64),
            u64::from_le_bytes(hash[8..16].try_into().expect("fixed slice")) as usize
                % (self.words_per_array * 64),
            u64::from_le_bytes(hash[16..24].try_into().expect("fixed slice")) as usize
                % (self.words_per_array * 64),
        ];
        let mut all_bits_were_set = true;
        for bit_index in indices {
            let word_index = bit_index / 64;
            let bit_mask = 1u64 << (bit_index % 64);
            let old = self.sram_bit_arrays[self.current_epoch_idx][word_index]
                .fetch_or(bit_mask, Ordering::Relaxed);
            if old & bit_mask == 0 {
                all_bits_were_set = false;
            }
        }
        !all_bits_were_set
    }

    pub fn rotate_epoch_if_needed(&mut self) {
        if self.last_rotation_time.elapsed() >= Duration::from_secs(30) {
            self.current_epoch_idx = (self.current_epoch_idx + 1) % 3;
            let oldest_index = (self.current_epoch_idx + 1) % 3;
            for word in &self.sram_bit_arrays[oldest_index] {
                word.store(0, Ordering::Relaxed);
            }
            self.last_rotation_time = Instant::now();
        }
    }
}

impl Default for SramCuckooBloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Local filter model with optional caller-provided retry-cookie key material.
pub struct PoWVerificationEngine {
    pub difficulty_zero_bits: u32,
    pub sram_filter: SramCuckooBloomFilter,
    pub is_table_full_stateless_mode: bool,
    retry_cookie_key: Option<[u8; 32]>,
}

impl PoWVerificationEngine {
    /// Creates an engine without retry-cookie generation.
    pub fn new(default_difficulty: u32) -> Self {
        Self {
            difficulty_zero_bits: default_difficulty,
            sram_filter: SramCuckooBloomFilter::new(),
            is_table_full_stateless_mode: false,
            retry_cookie_key: None,
        }
    }

    /// Creates an engine with caller-provided retry-cookie key material.
    pub fn with_retry_cookie_key(default_difficulty: u32, retry_cookie_key: [u8; 32]) -> Self {
        Self {
            retry_cookie_key: Some(retry_cookie_key),
            ..Self::new(default_difficulty)
        }
    }

    pub fn auto_scale_difficulty(&mut self, arrival_rate_req_sec: u64) {
        if arrival_rate_req_sec > 10_000 {
            self.difficulty_zero_bits = 24;
            self.is_table_full_stateless_mode = arrival_rate_req_sec > 50_000;
        } else {
            self.difficulty_zero_bits = 16;
            self.is_table_full_stateless_mode = false;
        }
    }

    /// Verifies a nonce against the local model's adjacent time windows.
    pub fn verify_client_nonce(
        &mut self,
        relay_pubkey: &str,
        unix_timestamp_sec: u64,
        nonce: &str,
    ) -> Result<String, &'static str> {
        self.sram_filter.rotate_epoch_if_needed();
        let current_window = unix_timestamp_sec / 30;
        let valid_windows = [
            current_window,
            current_window.saturating_sub(1),
            current_window.saturating_add(1),
        ];

        let pow_passed = valid_windows.into_iter().any(|window| {
            let mut hasher = Sha256::new();
            hasher.update(relay_pubkey.as_bytes());
            hasher.update(window.to_be_bytes());
            hasher.update(nonce.as_bytes());
            leading_zero_bits(&hasher.finalize()) >= self.difficulty_zero_bits
        });
        if !pow_passed {
            return Err("POW_INVALID");
        }
        if !self.sram_filter.check_and_insert_nonce(nonce) {
            return Err("REPLAY_DETECTED");
        }

        if self.is_table_full_stateless_mode {
            let retry_cookie_key = self
                .retry_cookie_key
                .ok_or("RETRY_COOKIE_KEY_UNAVAILABLE")?;
            let mut hasher = Sha256::new();
            hasher.update(retry_cookie_key);
            hasher.update(nonce.as_bytes());
            return Ok(format!("STATELESS_COOKIE:{:x}", hasher.finalize()[0]));
        }
        Ok("POW_VALID_ADMITTED".to_string())
    }
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut out = 0;
    for byte in bytes {
        if *byte == 0 {
            out += 8;
        } else {
            out += byte.leading_zeros();
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_cookie_mode_fails_closed_without_configured_key() {
        let mut engine = PoWVerificationEngine::new(0);
        engine.is_table_full_stateless_mode = true;
        assert_eq!(
            engine.verify_client_nonce("relay", 30, "one"),
            Err("RETRY_COOKIE_KEY_UNAVAILABLE")
        );
    }

    #[test]
    fn retry_cookie_mode_uses_caller_provided_key() {
        let mut engine = PoWVerificationEngine::with_retry_cookie_key(0, [7; 32]);
        engine.is_table_full_stateless_mode = true;
        assert!(matches!(
            engine.verify_client_nonce("relay", 30, "two"),
            Ok(cookie) if cookie.starts_with("STATELESS_COOKIE:")
        ));
    }
}
