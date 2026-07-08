//! Hybrid Dual-Trigger HKDF Key Ratchet.
//! CHRONOS-SPEC-v7.0 Section 1.1 & 3.1

use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

pub struct SessionKeyRatchet {
    pub current_secret: [u8; 32],
    pub packet_sequence_count: u64,
    pub epoch_start_time: Instant,
    pub volume_threshold: u64,
    pub temporal_threshold: Duration,
}

impl SessionKeyRatchet {
    pub fn new(initial_secret: [u8; 32]) -> Self {
        Self {
            current_secret: initial_secret,
            packet_sequence_count: 0,
            epoch_start_time: Instant::now(),
            volume_threshold: 65536, // ~83.8 MB
            temporal_threshold: Duration::from_secs(60),
        }
    }

    pub fn check_and_ratchet(&mut self) -> bool {
        let volume_exceeded = self.packet_sequence_count >= self.volume_threshold;
        let temporal_exceeded = self.epoch_start_time.elapsed() >= self.temporal_threshold;

        if volume_exceeded || temporal_exceeded {
            let mut hasher = Sha256::new();
            hasher.update(self.current_secret);
            hasher.update(b"chronos_v7_ratchet_step");
            let result = hasher.finalize();
            self.current_secret.copy_from_slice(&result);

            self.packet_sequence_count = 0;
            self.epoch_start_time = Instant::now();
            true
        } else {
            false
        }
    }

    pub fn evolve_tag(&mut self, current_tag: &[u8; 16], seq: u64) -> [u8; 16] {
        self.packet_sequence_count += 1;
        self.check_and_ratchet();

        let mut hasher = Sha256::new();
        hasher.update(self.current_secret);
        hasher.update(current_tag);
        hasher.update(seq.to_be_bytes());
        let full_hash = hasher.finalize();

        let mut next_tag = [0u8; 16];
        next_tag.copy_from_slice(&full_hash[..16]);
        next_tag
    }
}
