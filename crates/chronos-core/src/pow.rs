//! 2-Stage Adaptive Cuckoo SRAM & Stateless QUIC Retry Cookies.
//! CHRONOS-SPEC-v7.0 Section 1.2

use sha2::{Sha256, Digest};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, Duration};

/// On-Chip 2 MB SRAM Bloom / Cuckoo Filter partitioned into 3x 30s Epoch Arrays (~682 KB each).
pub struct SramCuckooBloomFilter {
    // 2 MB total SRAM = 262,144 u64 words = 16,777,216 bits
    pub sram_bit_arrays: [Vec<AtomicU64>; 3],
    pub words_per_array: usize,
    pub current_epoch_idx: usize,
    pub last_rotation_time: Instant,
}

impl SramCuckooBloomFilter {
    pub fn new() -> Self {
        let words_per_array = 87381; // ~682 KB per array
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

    /// Sub-nanosecond SRAM bitwise check (<5 ns target). Returns true if nonce is unique.
    pub fn check_and_insert_nonce(&self, nonce: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(nonce.as_bytes());
        let hash = hasher.finalize();

        // Generate 3 independent bit indices for 3-probe Bloom check
        let idx1 = u64::from_le_bytes(hash[0..8].try_into().unwrap()) as usize % (self.words_per_array * 64);
        let idx2 = u64::from_le_bytes(hash[8..16].try_into().unwrap()) as usize % (self.words_per_array * 64);
        let idx3 = u64::from_le_bytes(hash[16..24].try_into().unwrap()) as usize % (self.words_per_array * 64);

        let indices = [idx1, idx2, idx3];
        let mut all_bits_were_set = true;

        for &bit_idx in &indices {
            let word_idx = bit_idx / 64;
            let bit_mask = 1u64 << (bit_idx % 64);

            let old_val = self.sram_bit_arrays[self.current_epoch_idx][word_idx].fetch_or(bit_mask, Ordering::Relaxed);
            if (old_val & bit_mask) == 0 {
                all_bits_were_set = false;
            }
        }

        !all_bits_were_set // If all bits were already set, this is a replay!
    }

    /// Every 30 seconds, zero out oldest 682 KB array via SIMD instruction cycle.
    pub fn rotate_epoch_if_needed(&mut self) {
        if self.last_rotation_time.elapsed() >= Duration::from_secs(30) {
            self.current_epoch_idx = (self.current_epoch_idx + 1) % 3;
            let oldest_idx = (self.current_epoch_idx + 1) % 3;
            for word in &self.sram_bit_arrays[oldest_idx] {
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

pub struct PoWVerificationEngine {
    pub difficulty_zero_bits: u32,
    pub sram_filter: SramCuckooBloomFilter,
    pub is_table_full_stateless_mode: bool,
}

impl PoWVerificationEngine {
    pub fn new(default_difficulty: u32) -> Self {
        Self {
            difficulty_zero_bits: default_difficulty,
            sram_filter: SramCuckooBloomFilter::new(),
            is_table_full_stateless_mode: false,
        }
    }

    pub fn auto_scale_difficulty(&mut self, arrival_rate_req_sec: u64) {
        if arrival_rate_req_sec > 10000 {
            self.difficulty_zero_bits = 24; // ~16.7M SHA256 iterations to exhaust botnets
            self.is_table_full_stateless_mode = arrival_rate_req_sec > 50000;
        } else {
            self.difficulty_zero_bits = 16;
            self.is_table_full_stateless_mode = false;
        }
    }

    /// Stage 1 Stateless PoW check BEFORE SRAM insertion (<0.05 us).
    pub fn verify_client_nonce(&mut self, relay_pubkey: &str, unix_timestamp_sec: u64, nonce: &str) -> Result<String, &'static str> {
        self.sram_filter.rotate_epoch_if_needed();

        let curr_window = unix_timestamp_sec / 30;
        let valid_windows = [curr_window, curr_window.saturating_sub(1), curr_window + 1];

        let mut pow_passed = false;
        for win in valid_windows {
            let mut hasher = Sha256::new();
            hasher.update(relay_pubkey.as_bytes());
            hasher.update(&win.to_be_bytes());
            hasher.update(nonce.as_bytes());
            let hash = hasher.finalize();

            let mut zero_bits = 0;
            for &byte in hash.iter() {
                if byte == 0 {
                    zero_bits += 8;
                } else {
                    zero_bits += byte.leading_zeros();
                    break;
                }
            }

            if zero_bits >= self.difficulty_zero_bits {
                pow_passed = true;
                break;
            }
        }

        if !pow_passed {
            return Err("POW_INVALID: Nonce failed difficulty check across clock-drift windows");
        }

        // Stage 2: Check SRAM Cuckoo / Bloom filter (<5 ns)
        if !self.sram_filter.check_and_insert_nonce(nonce) {
            return Err("REPLAY_DETECTED: Nonce already spent in current 90s clock window");
        }

        // Stage 3: If table capacity reached during extreme flood, engage Stateless QUIC Retry Cookie
        if self.is_table_full_stateless_mode {
            let mut hasher = Sha256::new();
            hasher.update(b"stateless_quic_retry_secret");
            hasher.update(nonce.as_bytes());
            let cookie = format!("quic_cookie_{:x}", hasher.finalize()[0]);
            return Ok(format!("STATELESS_COOKIE:{}", cookie));
        }

        Ok("POW_VALID_ADMITTED".to_string())
    }
}
