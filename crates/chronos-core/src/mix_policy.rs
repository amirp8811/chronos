//! Adaptive mixnet threshold policy to handle the latency-to-volume paradox.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveMixDecision {
    FullThreshold,
    ReducedThreshold,
    CoverTrafficBackfill,
    EmergencyHold,
}

pub struct AdaptiveMixConfig {
    pub target_k: usize,
    pub max_latency_ms: u64,
}

impl AdaptiveMixConfig {
    pub fn decide(&self, current_batch_size: usize, wait_time_ms: u64) -> AdaptiveMixDecision {
        if current_batch_size >= self.target_k {
            AdaptiveMixDecision::FullThreshold
        } else if wait_time_ms >= self.max_latency_ms {
            if current_batch_size > self.target_k / 10 {
                AdaptiveMixDecision::ReducedThreshold
            } else {
                AdaptiveMixDecision::CoverTrafficBackfill
            }
        } else if current_batch_size == 0 {
            AdaptiveMixDecision::EmergencyHold
        } else {
            AdaptiveMixDecision::EmergencyHold
        }
    }
}
