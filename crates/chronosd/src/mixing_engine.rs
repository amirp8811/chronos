//! L3 Cache Micro-Batching, adaptive mix policy, and bitonic sorting network.
//! CHRONOS-SPEC-v7.0 Section 2.2 & 5.2

use chronos_core::framing::UmemFrameDescriptor;
use chronos_core::mix_policy::{
    AdaptiveMixConfig, AdaptiveMixDecision, AdaptiveMixer, MixProfile, MixTelemetry,
};
use log::info;
use std::time::Instant;

#[allow(dead_code)]
pub struct BitonicSortingEngine {
    pub batch_window_ms: f64,
    pub mixer: AdaptiveMixer,
    pub batch_start_time: Instant,
}

#[allow(dead_code)]
impl BitonicSortingEngine {
    pub fn new(window_ms: f64, target_k: usize) -> Self {
        let mut config = MixProfile::Normal.config();
        config.target_k = target_k.max(1);
        config.max_wait_ms = window_ms.max(1.0) as u64;
        Self {
            batch_window_ms: window_ms,
            mixer: AdaptiveMixer::new(config),
            batch_start_time: Instant::now(),
        }
    }

    pub fn with_profile(profile: MixProfile) -> Self {
        let config = profile.config();
        Self {
            batch_window_ms: config.max_wait_ms as f64,
            mixer: AdaptiveMixer::new(config),
            batch_start_time: Instant::now(),
        }
    }

    pub fn check_flush_policy(&mut self, current_batch_size: usize) -> AdaptiveMixDecision {
        // Align mixer batch size with caller-provided queue depth for decisioning.
        self.mixer.batch_size = current_batch_size;
        self.mixer.wait_ms = self.batch_start_time.elapsed().as_millis() as u64;
        let decision = self
            .mixer
            .config
            .decide(self.mixer.batch_size, self.mixer.wait_ms);
        let cover = if decision == AdaptiveMixDecision::CoverTrafficBackfill {
            self.mixer.config.cover_cells_needed(current_batch_size)
        } else {
            0
        };
        self.mixer.telemetry.record_decision(
            decision,
            current_batch_size,
            self.mixer.wait_ms,
            cover,
        );
        if matches!(
            decision,
            AdaptiveMixDecision::FullThreshold
                | AdaptiveMixDecision::ReducedThreshold
                | AdaptiveMixDecision::CoverTrafficBackfill
        ) {
            self.batch_start_time = Instant::now();
            self.mixer.batch_size = 0;
            self.mixer.wait_ms = 0;
        }
        info!(
            "Mixing engine decision: {:?} ({})",
            decision,
            self.mixer.summary()
        );
        decision
    }

    pub fn telemetry(&self) -> &MixTelemetry {
        &self.mixer.telemetry
    }

    pub fn config(&self) -> AdaptiveMixConfig {
        self.mixer.config
    }

    /// Execute constant-time bitonic sorting network over UMEM descriptor pool.
    pub fn sort_micro_batch_in_place(
        &self,
        frames: &mut [UmemFrameDescriptor],
    ) -> Result<f64, String> {
        let n = frames.len();
        if n == 0 || (n & (n - 1)) != 0 {
            return Err("Batch size must be a power of 2 for bitonic sorting network".to_string());
        }

        let start_t = Instant::now();

        let mut k = 2;
        while k <= n {
            let mut j = k / 2;
            while j > 0 {
                for i in 0..n {
                    let ixj = i ^ j;
                    if ixj > i {
                        let dir = (i & k) == 0;
                        let tag_i = frames[i].wire_datagram[0];
                        let tag_ixj = frames[ixj].wire_datagram[0];
                        if (dir && tag_i > tag_ixj) || (!dir && tag_i < tag_ixj) {
                            frames.swap(i, ixj);
                        }
                    }
                }
                j /= 2;
            }
            k *= 2;
        }

        let elapsed_us = start_t.elapsed().as_secs_f64() * 1_000_000.0;
        info!(
            "Bitonic sorting completed across {} frames in {:.2} us.",
            n, elapsed_us
        );
        Ok(elapsed_us)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_flushes_at_target_k() {
        let mut engine = BitonicSortingEngine::new(50.0, 4);
        assert_eq!(
            engine.check_flush_policy(4),
            AdaptiveMixDecision::FullThreshold
        );
        assert_eq!(engine.telemetry().flushes_full, 1);
    }

    #[test]
    fn engine_holds_when_underfilled_and_young() {
        let mut engine = BitonicSortingEngine::new(50.0, 100);
        // wait_ms is ~0 right after construction
        let d = engine.check_flush_policy(3);
        assert!(matches!(
            d,
            AdaptiveMixDecision::Hold | AdaptiveMixDecision::EmergencyHold
        ));
    }
}
