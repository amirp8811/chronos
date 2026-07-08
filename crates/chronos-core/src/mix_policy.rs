//! Adaptive mixnet threshold policy for the anonymity/latency trade-off.
//!
//! Fixed K + fixed max latency is unusable under low load: either the batch never
//! fills (unbounded latency) or the mixer flushes tiny batches (weak anonymity).
//! This module implements a load-aware policy with client profiles and telemetry.

#[cfg(not(feature = "std"))]
use alloc::format;
#[cfg(not(feature = "std"))]
use alloc::string::String;

/// Decision emitted by the adaptive mixer for the current batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveMixDecision {
    /// Batch reached the target threshold; flush real traffic only.
    FullThreshold,
    /// Max wait expired with a usable partial batch; flush reduced set.
    ReducedThreshold,
    /// Max wait expired with almost no real traffic; pad with cover cells.
    CoverTrafficBackfill,
    /// Hold: neither size nor latency budget requires a flush yet.
    Hold,
    /// Explicit hold when the batch is empty (no cover emission this tick).
    EmergencyHold,
}

/// Client-facing latency / anonymity profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MixProfile {
    /// Prefer low latency; smaller K and shorter max wait.
    Fast,
    /// Balanced defaults (SECURITY.md targets scaled for local prototypes).
    Normal,
    /// Prefer anonymity; larger K and longer max wait.
    HighAnonymity,
}

impl MixProfile {
    pub fn config(self) -> AdaptiveMixConfig {
        match self {
            MixProfile::Fast => AdaptiveMixConfig {
                target_k: 64,
                min_batch_size: 8,
                max_wait_ms: 20,
                reduced_fraction_num: 1,
                reduced_fraction_den: 4,
                cover_when_underfilled: true,
                adaptive_rate_factor_bps: 0,
            },
            MixProfile::Normal => AdaptiveMixConfig {
                target_k: 256,
                min_batch_size: 16,
                max_wait_ms: 50,
                reduced_fraction_num: 1,
                reduced_fraction_den: 10,
                cover_when_underfilled: true,
                adaptive_rate_factor_bps: 0,
            },
            MixProfile::HighAnonymity => AdaptiveMixConfig {
                target_k: 1024,
                min_batch_size: 64,
                max_wait_ms: 200,
                reduced_fraction_num: 1,
                reduced_fraction_den: 8,
                cover_when_underfilled: true,
                adaptive_rate_factor_bps: 0,
            },
        }
    }
}

/// Parameters controlling adaptive flush decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveMixConfig {
    /// Target batch size K for a full-threshold flush.
    pub target_k: usize,
    /// Absolute minimum real packets before a reduced flush is allowed.
    pub min_batch_size: usize,
    /// Maximum time to hold a non-empty batch before flushing or covering.
    pub max_wait_ms: u64,
    /// Numerator of the reduced-threshold fraction of `target_k`.
    pub reduced_fraction_num: usize,
    /// Denominator of the reduced-threshold fraction of `target_k`.
    pub reduced_fraction_den: usize,
    /// When true, underfilled timeout flushes emit cover backfill.
    pub cover_when_underfilled: bool,
    /// Observed ingress rate (packets per second * 1000). 0 = unused.
    /// When set, `effective_target_k` scales toward min_batch under low load.
    pub adaptive_rate_factor_bps: u64,
}

impl Default for AdaptiveMixConfig {
    fn default() -> Self {
        MixProfile::Normal.config()
    }
}

impl AdaptiveMixConfig {
    /// SECURITY.md-oriented production-scale defaults (large K).
    pub fn production_defaults() -> Self {
        Self {
            target_k: 25_000,
            min_batch_size: 256,
            max_wait_ms: 50,
            reduced_fraction_num: 1,
            reduced_fraction_den: 10,
            cover_when_underfilled: true,
            adaptive_rate_factor_bps: 0,
        }
    }

    /// Minimum size that qualifies as a reduced-threshold flush.
    pub fn reduced_threshold(&self) -> usize {
        let den = self.reduced_fraction_den.max(1);
        let raw = (self.target_k.saturating_mul(self.reduced_fraction_num)) / den;
        raw.max(self.min_batch_size).min(self.target_k)
    }

    /// Effective K after optional rate adaptation.
    ///
    /// Under very low ingress rates, K is scaled down toward `min_batch_size`
    /// so latency does not explode while still preferring larger batches when
    /// traffic is available.
    pub fn effective_target_k(&self) -> usize {
        if self.adaptive_rate_factor_bps == 0 {
            return self.target_k.max(1);
        }
        // Expected arrivals over max_wait: rate_pps * wait_s
        // rate is stored as milli-packets-per-second.
        let wait_ms = self.max_wait_ms.max(1);
        let expected = (self.adaptive_rate_factor_bps.saturating_mul(wait_ms)) / 1_000_000;
        let expected = expected as usize;
        if expected >= self.target_k {
            self.target_k
        } else if expected <= self.min_batch_size {
            self.min_batch_size.max(1)
        } else {
            expected.clamp(self.min_batch_size, self.target_k).max(1)
        }
    }

    /// Decide whether to flush, hold, or emit cover for the current batch.
    pub fn decide(&self, current_batch_size: usize, wait_time_ms: u64) -> AdaptiveMixDecision {
        let k = self.effective_target_k();
        if current_batch_size >= k {
            return AdaptiveMixDecision::FullThreshold;
        }
        if wait_time_ms < self.max_wait_ms {
            return if current_batch_size == 0 {
                AdaptiveMixDecision::EmergencyHold
            } else {
                AdaptiveMixDecision::Hold
            };
        }
        // Latency budget exhausted.
        if current_batch_size == 0 {
            return if self.cover_when_underfilled {
                AdaptiveMixDecision::CoverTrafficBackfill
            } else {
                AdaptiveMixDecision::EmergencyHold
            };
        }
        if current_batch_size >= self.reduced_threshold() {
            AdaptiveMixDecision::ReducedThreshold
        } else if self.cover_when_underfilled {
            AdaptiveMixDecision::CoverTrafficBackfill
        } else {
            AdaptiveMixDecision::ReducedThreshold
        }
    }

    /// How many cover cells to emit to reach effective K (0 if not covering).
    pub fn cover_cells_needed(&self, current_batch_size: usize) -> usize {
        let k = self.effective_target_k();
        k.saturating_sub(current_batch_size)
    }
}

/// Running telemetry for mixer behaviour (batch sizes, flush reasons).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MixTelemetry {
    pub flushes_full: u64,
    pub flushes_reduced: u64,
    pub flushes_cover: u64,
    pub holds: u64,
    pub total_real_packets_flushed: u64,
    pub total_cover_packets_emitted: u64,
    pub max_batch_seen: usize,
    pub last_flush_batch_size: usize,
    pub last_flush_wait_ms: u64,
}

impl MixTelemetry {
    pub fn record_decision(
        &mut self,
        decision: AdaptiveMixDecision,
        batch_size: usize,
        wait_ms: u64,
        cover_emitted: usize,
    ) {
        match decision {
            AdaptiveMixDecision::FullThreshold => {
                self.flushes_full = self.flushes_full.saturating_add(1);
                self.total_real_packets_flushed = self
                    .total_real_packets_flushed
                    .saturating_add(batch_size as u64);
                self.last_flush_batch_size = batch_size;
                self.last_flush_wait_ms = wait_ms;
            }
            AdaptiveMixDecision::ReducedThreshold => {
                self.flushes_reduced = self.flushes_reduced.saturating_add(1);
                self.total_real_packets_flushed = self
                    .total_real_packets_flushed
                    .saturating_add(batch_size as u64);
                self.last_flush_batch_size = batch_size;
                self.last_flush_wait_ms = wait_ms;
            }
            AdaptiveMixDecision::CoverTrafficBackfill => {
                self.flushes_cover = self.flushes_cover.saturating_add(1);
                self.total_real_packets_flushed = self
                    .total_real_packets_flushed
                    .saturating_add(batch_size as u64);
                self.total_cover_packets_emitted = self
                    .total_cover_packets_emitted
                    .saturating_add(cover_emitted as u64);
                self.last_flush_batch_size = batch_size;
                self.last_flush_wait_ms = wait_ms;
            }
            AdaptiveMixDecision::Hold | AdaptiveMixDecision::EmergencyHold => {
                self.holds = self.holds.saturating_add(1);
            }
        }
        if batch_size > self.max_batch_seen {
            self.max_batch_seen = batch_size;
        }
    }

    /// Bandwidth multiplier estimate: (real + cover) / real. 1.0 if no real traffic.
    pub fn bandwidth_multiplier(&self) -> f64 {
        let real = self.total_real_packets_flushed as f64;
        if real <= 0.0 {
            return 1.0;
        }
        (real + self.total_cover_packets_emitted as f64) / real
    }
}

/// Stateful adaptive mixer that tracks batch age and telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveMixer {
    pub config: AdaptiveMixConfig,
    pub batch_size: usize,
    pub wait_ms: u64,
    pub telemetry: MixTelemetry,
}

impl AdaptiveMixer {
    pub fn new(config: AdaptiveMixConfig) -> Self {
        Self {
            config,
            batch_size: 0,
            wait_ms: 0,
            telemetry: MixTelemetry::default(),
        }
    }

    pub fn with_profile(profile: MixProfile) -> Self {
        Self::new(profile.config())
    }

    /// Advance virtual time by `delta_ms` (for deterministic tests / simulators).
    pub fn tick(&mut self, delta_ms: u64) -> AdaptiveMixDecision {
        if self.batch_size > 0 || self.config.cover_when_underfilled {
            self.wait_ms = self.wait_ms.saturating_add(delta_ms);
        }
        let decision = self.config.decide(self.batch_size, self.wait_ms);
        let cover = if decision == AdaptiveMixDecision::CoverTrafficBackfill {
            self.config.cover_cells_needed(self.batch_size)
        } else {
            0
        };
        self.telemetry
            .record_decision(decision, self.batch_size, self.wait_ms, cover);
        if matches!(
            decision,
            AdaptiveMixDecision::FullThreshold
                | AdaptiveMixDecision::ReducedThreshold
                | AdaptiveMixDecision::CoverTrafficBackfill
        ) {
            self.batch_size = 0;
            self.wait_ms = 0;
        }
        decision
    }

    /// Enqueue one real packet into the current batch and re-evaluate.
    pub fn push_packet(&mut self) -> AdaptiveMixDecision {
        self.batch_size = self.batch_size.saturating_add(1);
        let decision = self.config.decide(self.batch_size, self.wait_ms);
        let cover = if decision == AdaptiveMixDecision::CoverTrafficBackfill {
            self.config.cover_cells_needed(self.batch_size)
        } else {
            0
        };
        self.telemetry
            .record_decision(decision, self.batch_size, self.wait_ms, cover);
        if matches!(
            decision,
            AdaptiveMixDecision::FullThreshold
                | AdaptiveMixDecision::ReducedThreshold
                | AdaptiveMixDecision::CoverTrafficBackfill
        ) {
            self.batch_size = 0;
            self.wait_ms = 0;
        }
        decision
    }

    /// Human-readable summary for experiment logs.
    pub fn summary(&self) -> String {
        format!(
            "mix profile_k={} eff_k={} full={} reduced={} cover={} holds={} bw_mult={:.3}",
            self.config.target_k,
            self.config.effective_target_k(),
            self.telemetry.flushes_full,
            self.telemetry.flushes_reduced,
            self.telemetry.flushes_cover,
            self.telemetry.holds,
            self.telemetry.bandwidth_multiplier()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_threshold_flushes_at_k() {
        let cfg = AdaptiveMixConfig {
            target_k: 10,
            min_batch_size: 2,
            max_wait_ms: 50,
            reduced_fraction_num: 1,
            reduced_fraction_den: 5,
            cover_when_underfilled: true,
            adaptive_rate_factor_bps: 0,
        };
        assert_eq!(cfg.decide(10, 1), AdaptiveMixDecision::FullThreshold);
        assert_eq!(cfg.decide(9, 1), AdaptiveMixDecision::Hold);
    }

    #[test]
    fn reduced_threshold_on_timeout() {
        let cfg = AdaptiveMixConfig {
            target_k: 100,
            min_batch_size: 5,
            max_wait_ms: 50,
            reduced_fraction_num: 1,
            reduced_fraction_den: 10,
            cover_when_underfilled: true,
            adaptive_rate_factor_bps: 0,
        };
        // reduced_threshold = max(10, 5) = 10
        assert_eq!(cfg.reduced_threshold(), 10);
        assert_eq!(cfg.decide(12, 50), AdaptiveMixDecision::ReducedThreshold);
        assert_eq!(cfg.decide(3, 50), AdaptiveMixDecision::CoverTrafficBackfill);
    }

    #[test]
    fn empty_batch_holds_before_timeout() {
        let cfg = AdaptiveMixConfig::default();
        assert_eq!(cfg.decide(0, 0), AdaptiveMixDecision::EmergencyHold);
    }

    #[test]
    fn adaptive_rate_scales_k_down() {
        let mut cfg = MixProfile::Normal.config();
        cfg.adaptive_rate_factor_bps = 100_000; // 100 packets/sec
        // expected over 50ms = 100 * 0.05 = 5 → clamp to min_batch_size 16
        assert_eq!(cfg.effective_target_k(), 16);
        cfg.adaptive_rate_factor_bps = 10_000_000; // 10k pps
        assert_eq!(cfg.effective_target_k(), 256);
    }

    #[test]
    fn mixer_state_machine_fills_and_flushes() {
        let mut mixer = AdaptiveMixer::new(AdaptiveMixConfig {
            target_k: 4,
            min_batch_size: 2,
            max_wait_ms: 30,
            reduced_fraction_num: 1,
            reduced_fraction_den: 2,
            cover_when_underfilled: true,
            adaptive_rate_factor_bps: 0,
        });
        assert_eq!(mixer.push_packet(), AdaptiveMixDecision::Hold);
        assert_eq!(mixer.push_packet(), AdaptiveMixDecision::Hold);
        assert_eq!(mixer.push_packet(), AdaptiveMixDecision::Hold);
        assert_eq!(mixer.push_packet(), AdaptiveMixDecision::FullThreshold);
        assert_eq!(mixer.batch_size, 0);
        assert_eq!(mixer.telemetry.flushes_full, 1);
        assert_eq!(mixer.telemetry.total_real_packets_flushed, 4);
    }

    #[test]
    fn mixer_timeout_emits_cover() {
        let mut mixer = AdaptiveMixer::new(AdaptiveMixConfig {
            target_k: 20,
            min_batch_size: 5,
            max_wait_ms: 10,
            reduced_fraction_num: 1,
            reduced_fraction_den: 4,
            cover_when_underfilled: true,
            adaptive_rate_factor_bps: 0,
        });
        mixer.push_packet();
        let d = mixer.tick(10);
        assert_eq!(d, AdaptiveMixDecision::CoverTrafficBackfill);
        assert!(mixer.telemetry.total_cover_packets_emitted > 0);
        assert!(mixer.telemetry.bandwidth_multiplier() > 1.0);
    }

    #[test]
    fn profiles_order_by_anonymity() {
        let fast = MixProfile::Fast.config();
        let normal = MixProfile::Normal.config();
        let high = MixProfile::HighAnonymity.config();
        assert!(fast.target_k < normal.target_k);
        assert!(normal.target_k < high.target_k);
        assert!(fast.max_wait_ms <= normal.max_wait_ms);
        assert!(normal.max_wait_ms <= high.max_wait_ms);
    }
}
