//! Empirical anonymity / traffic-analysis metrics.
//!
//! These statistics do **not** prove anonymity. They give reproducible numbers
//! for experiment sweeps: Shannon entropy, histogram KL divergence, a simple
//! mutual-information estimate between ingress and egress timing ranks, latency
//! percentiles, and bandwidth multipliers.

use crate::mix_policy::{AdaptiveMixDecision, AdaptiveMixer, MixProfile};
use crate::traffic_analysis::{PacketObservation, TrafficShapeReport, analyze_observations};

/// Shannon entropy of a discrete distribution, in bits.
pub fn shannon_entropy(counts: &[u64]) -> f64 {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    let mut h = 0.0;
    for &c in counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total_f;
        h -= p * p.log2();
    }
    h
}

/// KL divergence KL(P || Q) for aligned histograms. Empty bins in Q use epsilon.
pub fn kl_divergence(p_counts: &[u64], q_counts: &[u64]) -> f64 {
    assert_eq!(p_counts.len(), q_counts.len());
    let p_total: u64 = p_counts.iter().sum();
    let q_total: u64 = q_counts.iter().sum();
    if p_total == 0 || q_total == 0 {
        return 0.0;
    }
    let p_total_f = p_total as f64;
    let q_total_f = q_total as f64;
    let eps = 1e-12;
    let mut kl = 0.0;
    for (&pc, &qc) in p_counts.iter().zip(q_counts.iter()) {
        let p = (pc as f64 / p_total_f).max(eps);
        let q = (qc as f64 / q_total_f).max(eps);
        if pc > 0 {
            kl += p * (p / q).ln();
        }
    }
    // convert nats → bits
    kl / core::f64::consts::LN_2
}

/// Histogram of inter-arrival times into fixed-width bins.
pub fn interval_histogram(
    observations: &[PacketObservation],
    bin_width_us: u64,
    bins: usize,
) -> Vec<u64> {
    let mut hist = vec![0u64; bins.max(1)];
    if bin_width_us == 0 {
        return hist;
    }
    for w in observations.windows(2) {
        let dt = w[1].timestamp_micros.saturating_sub(w[0].timestamp_micros);
        let idx = ((dt / bin_width_us) as usize).min(bins - 1);
        hist[idx] = hist[idx].saturating_add(1);
    }
    hist
}

/// Histogram of packet lengths.
pub fn length_histogram(
    observations: &[PacketObservation],
    max_len: usize,
    bins: usize,
) -> Vec<u64> {
    let mut hist = vec![0u64; bins.max(1)];
    let max_len = max_len.max(1);
    for o in observations {
        let idx = (o.length_bytes.saturating_mul(bins) / (max_len + 1)).min(bins - 1);
        hist[idx] = hist[idx].saturating_add(1);
    }
    hist
}

/// Pair of ingress/egress timestamps for the same logical packet id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowTimingPair {
    pub packet_id: u64,
    pub ingress_us: u64,
    pub egress_us: u64,
}

/// Naive mutual information between quantized ingress and egress times (bits).
///
/// Both timestamps are quantized into `bins` equal-width bins over the observed
/// range, then MI is computed from the joint histogram. This is a coarse
/// GPA-style correlator suitable for relative comparisons across mix policies.
pub fn mutual_information_timing(pairs: &[FlowTimingPair], bins: usize) -> f64 {
    if pairs.len() < 2 || bins < 2 {
        return 0.0;
    }
    let bins = bins.min(64);
    let ing_min = pairs.iter().map(|p| p.ingress_us).min().unwrap();
    let ing_max = pairs.iter().map(|p| p.ingress_us).max().unwrap();
    let egr_min = pairs.iter().map(|p| p.egress_us).min().unwrap();
    let egr_max = pairs.iter().map(|p| p.egress_us).max().unwrap();
    let ing_span = (ing_max - ing_min).max(1);
    let egr_span = (egr_max - egr_min).max(1);

    let mut joint = vec![0u64; bins * bins];
    let mut ing_m = vec![0u64; bins];
    let mut egr_m = vec![0u64; bins];
    for p in pairs {
        let ib =
            (((p.ingress_us - ing_min) as u128 * bins as u128) / (ing_span as u128 + 1)) as usize;
        let eb =
            (((p.egress_us - egr_min) as u128 * bins as u128) / (egr_span as u128 + 1)) as usize;
        let ib = ib.min(bins - 1);
        let eb = eb.min(bins - 1);
        joint[ib * bins + eb] = joint[ib * bins + eb].saturating_add(1);
        ing_m[ib] = ing_m[ib].saturating_add(1);
        egr_m[eb] = egr_m[eb].saturating_add(1);
    }
    let n = pairs.len() as f64;
    let mut mi = 0.0;
    let eps = 1e-15;
    for i in 0..bins {
        for j in 0..bins {
            let c = joint[i * bins + j] as f64;
            if c <= 0.0 {
                continue;
            }
            let pxy = c / n;
            let px = (ing_m[i] as f64 / n).max(eps);
            let py = (egr_m[j] as f64 / n).max(eps);
            mi += pxy * (pxy / (px * py)).ln();
        }
    }
    mi / core::f64::consts::LN_2
}

/// Latency sample in microseconds (egress - ingress).
pub fn latencies_us(pairs: &[FlowTimingPair]) -> Vec<u64> {
    pairs
        .iter()
        .map(|p| p.egress_us.saturating_sub(p.ingress_us))
        .collect()
}

/// Percentile of a sorted-or-unsorted sample set (nearest-rank).
pub fn percentile(mut samples: Vec<u64>, pct: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    let pct = pct.clamp(0.0, 100.0);
    let idx = ((pct / 100.0) * (samples.len() as f64 - 1.0)).round() as usize;
    samples[idx.min(samples.len() - 1)]
}

#[derive(Debug, Clone, PartialEq)]
pub struct LatencyCdf {
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub mean_us: f64,
}

pub fn latency_cdf(pairs: &[FlowTimingPair]) -> LatencyCdf {
    let samples = latencies_us(pairs);
    if samples.is_empty() {
        return LatencyCdf {
            p50_us: 0,
            p95_us: 0,
            p99_us: 0,
            max_us: 0,
            mean_us: 0.0,
        };
    }
    let mean = samples.iter().sum::<u64>() as f64 / samples.len() as f64;
    let max = *samples.iter().max().unwrap();
    LatencyCdf {
        p50_us: percentile(samples.clone(), 50.0),
        p95_us: percentile(samples.clone(), 95.0),
        p99_us: percentile(samples, 99.0),
        max_us: max,
        mean_us: mean,
    }
}

/// Bandwidth multiplier = total_bytes_sent / payload_bytes.
pub fn bandwidth_multiplier(total_bytes_sent: u64, payload_bytes: u64) -> f64 {
    if payload_bytes == 0 {
        return 1.0;
    }
    total_bytes_sent as f64 / payload_bytes as f64
}

/// Aggregate experiment report for one mix configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct MixExperimentReport {
    pub profile: &'static str,
    pub target_k: usize,
    pub max_wait_ms: u64,
    pub packets: usize,
    pub ingress_rate_pps: f64,
    pub mi_bits: f64,
    pub egress_entropy_bits: f64,
    pub interval_kl_vs_constant: f64,
    pub latency: LatencyCdf,
    pub bandwidth_mult: f64,
    pub flushes_full: u64,
    pub flushes_reduced: u64,
    pub flushes_cover: u64,
    pub shape: TrafficShapeReport,
}

/// Simulate a simple single-hop mix: packets arrive at constant or bursty rate,
/// mixer applies adaptive policy, egress is emitted on flush (with cover).
///
/// Returns timing pairs for real packets and the mix experiment report.
pub fn simulate_adaptive_mix(
    profile: MixProfile,
    real_packets: usize,
    inter_arrival_ms: u64,
    packet_len: usize,
    cover_len: usize,
) -> (
    Vec<FlowTimingPair>,
    MixExperimentReport,
    Vec<PacketObservation>,
) {
    let cfg = profile.config();
    let mut mixer = AdaptiveMixer::new(cfg);
    let mut pairs = Vec::with_capacity(real_packets);
    let mut egress: Vec<PacketObservation> = Vec::new();
    let mut pending: Vec<(u64, u64)> = Vec::new(); // (packet_id, ingress_us)
    let mut now_ms: u64 = 0;
    let mut next_id: u64 = 0;
    let mut real_sent = 0usize;
    let mut total_bytes = 0u64;
    let payload_bytes = (real_packets * packet_len) as u64;

    // Drive simulation until all real packets have egressed.
    let mut safety = 0;
    while real_sent < real_packets || !pending.is_empty() {
        safety += 1;
        if safety > real_packets * 1000 + 10_000 {
            break;
        }

        // Arrive one real packet on schedule while we still have some.
        if real_sent < real_packets {
            let ingress_us = now_ms.saturating_mul(1000);
            pending.push((next_id, ingress_us));
            next_id += 1;
            real_sent += 1;
            let decision = mixer.push_packet();
            apply_flush(
                decision,
                &mixer,
                &mut pending,
                &mut pairs,
                &mut egress,
                &mut total_bytes,
                now_ms,
                packet_len,
                cover_len,
            );
        }

        // Time advances by inter-arrival between packets; when no more arrivals,
        // advance by 1ms ticks to hit max_wait.
        let step = if real_sent < real_packets {
            inter_arrival_ms.max(1)
        } else {
            1
        };
        now_ms = now_ms.saturating_add(step);
        let decision = mixer.tick(step);
        apply_flush(
            decision,
            &mixer,
            &mut pending,
            &mut pairs,
            &mut egress,
            &mut total_bytes,
            now_ms,
            packet_len,
            cover_len,
        );
    }

    let shape = analyze_observations(&egress);
    let mi = mutual_information_timing(&pairs, 16);
    let hist = interval_histogram(&egress, 1000, 32);
    let constant = {
        // Ideal constant-rate histogram: all mass in the first non-zero mean bin.
        let mut c = vec![0u64; 32];
        if !egress.is_empty() {
            c[0] = egress.len().saturating_sub(1) as u64;
        }
        c
    };
    let kl = kl_divergence(&hist, &constant);
    let ent = shannon_entropy(&hist);
    let lat = latency_cdf(&pairs);
    let name = match profile {
        MixProfile::Fast => "fast",
        MixProfile::Normal => "normal",
        MixProfile::HighAnonymity => "high_anonymity",
    };
    let rate = if inter_arrival_ms == 0 {
        f64::INFINITY
    } else {
        1000.0 / inter_arrival_ms as f64
    };
    let report = MixExperimentReport {
        profile: name,
        target_k: cfg.target_k,
        max_wait_ms: cfg.max_wait_ms,
        packets: real_packets,
        ingress_rate_pps: rate,
        mi_bits: mi,
        egress_entropy_bits: ent,
        interval_kl_vs_constant: kl,
        latency: lat,
        bandwidth_mult: bandwidth_multiplier(total_bytes, payload_bytes),
        flushes_full: mixer.telemetry.flushes_full,
        flushes_reduced: mixer.telemetry.flushes_reduced,
        flushes_cover: mixer.telemetry.flushes_cover,
        shape,
    };
    (pairs, report, egress)
}

#[allow(clippy::too_many_arguments)]
fn apply_flush(
    decision: AdaptiveMixDecision,
    mixer: &AdaptiveMixer,
    pending: &mut Vec<(u64, u64)>,
    pairs: &mut Vec<FlowTimingPair>,
    egress: &mut Vec<PacketObservation>,
    total_bytes: &mut u64,
    now_ms: u64,
    packet_len: usize,
    cover_len: usize,
) {
    let egress_us = now_ms.saturating_mul(1000);
    match decision {
        AdaptiveMixDecision::FullThreshold | AdaptiveMixDecision::ReducedThreshold => {
            // Flush all pending real packets at this tick (batch atomicity).
            let batch = std::mem::take(pending);
            for (id, ing) in batch {
                pairs.push(FlowTimingPair {
                    packet_id: id,
                    ingress_us: ing,
                    egress_us,
                });
                egress.push(PacketObservation {
                    timestamp_micros: egress_us,
                    length_bytes: packet_len,
                });
                *total_bytes = total_bytes.saturating_add(packet_len as u64);
            }
        }
        AdaptiveMixDecision::CoverTrafficBackfill => {
            let real_n = pending.len();
            let batch = std::mem::take(pending);
            for (id, ing) in batch {
                pairs.push(FlowTimingPair {
                    packet_id: id,
                    ingress_us: ing,
                    egress_us,
                });
                egress.push(PacketObservation {
                    timestamp_micros: egress_us,
                    length_bytes: packet_len,
                });
                *total_bytes = total_bytes.saturating_add(packet_len as u64);
            }
            // Prefer telemetry's last cover count (recorded before mixer reset).
            let cover_n = if mixer.telemetry.total_cover_packets_emitted > 0
                && mixer.telemetry.flushes_cover > 0
            {
                // Approximate per-flush cover from running totals is awkward; use config.
                mixer.config.cover_cells_needed(real_n).max(1)
            } else {
                mixer.config.cover_cells_needed(real_n).max(1)
            };
            for _ in 0..cover_n {
                egress.push(PacketObservation {
                    timestamp_micros: egress_us,
                    length_bytes: cover_len,
                });
                *total_bytes = total_bytes.saturating_add(cover_len as u64);
            }
        }
        AdaptiveMixDecision::Hold | AdaptiveMixDecision::EmergencyHold => {}
    }
}

/// Sweep K / rate surface for the three profiles; returns CSV text.
pub fn sweep_mix_k_latency_csv(packets: usize, inter_arrival_ms_values: &[u64]) -> String {
    let mut out = String::from(
        "profile,target_k,max_wait_ms,inter_arrival_ms,ingress_pps,packets,mi_bits,egress_entropy,kl_vs_const,p50_us,p95_us,p99_us,bw_mult,flushes_full,flushes_reduced,flushes_cover\n",
    );
    for profile in [
        MixProfile::Fast,
        MixProfile::Normal,
        MixProfile::HighAnonymity,
    ] {
        for &ia in inter_arrival_ms_values {
            let (_pairs, report, _egr) = simulate_adaptive_mix(profile, packets, ia, 1228, 1228);
            out.push_str(&format!(
                "{},{},{},{},{:.4},{},{:.6},{:.6},{:.6},{},{},{},{:.4},{},{},{}\n",
                report.profile,
                report.target_k,
                report.max_wait_ms,
                ia,
                report.ingress_rate_pps,
                report.packets,
                report.mi_bits,
                report.egress_entropy_bits,
                report.interval_kl_vs_constant,
                report.latency.p50_us,
                report.latency.p95_us,
                report.latency.p99_us,
                report.bandwidth_mult,
                report.flushes_full,
                report.flushes_reduced,
                report.flushes_cover,
            ));
        }
    }
    out
}

/// Compare RS(16,10) overhead (fixed 1.6x) vs fountain progressive recovery.
#[derive(Debug, Clone, PartialEq)]
pub struct FecCompareRow {
    pub codec: &'static str,
    pub payload_len: usize,
    pub symbols_sent: usize,
    pub symbols_needed: usize,
    pub overhead_ratio: f64,
}

pub fn compare_fec_overhead(payload: &[u8], k: usize, max_repair: usize) -> Vec<FecCompareRow> {
    use crate::fountain::progressive_recovery_count;
    use crate::gf28::ReedSolomon16_10;

    let mut rows = Vec::new();
    // Fixed RS 16/10: always send 16 shards for 10 data shards.
    let rs = ReedSolomon16_10::new();
    let symbol_len = payload.len().div_ceil(10).max(1);
    let mut data_shards = Vec::new();
    for i in 0..10 {
        let start = i * symbol_len;
        let mut shard = vec![0u8; symbol_len];
        if start < payload.len() {
            let end = (start + symbol_len).min(payload.len());
            shard[..end - start].copy_from_slice(&payload[start..end]);
        }
        data_shards.push(shard);
    }
    let refs: Vec<&[u8]> = data_shards.iter().map(Vec::as_slice).collect();
    if let Ok(encoded) = rs.encode(&refs) {
        rows.push(FecCompareRow {
            codec: "reed_solomon_16_10",
            payload_len: payload.len(),
            symbols_sent: encoded.len(),
            symbols_needed: 10,
            overhead_ratio: encoded.len() as f64 / 10.0,
        });
    }

    if let Ok(needed) = progressive_recovery_count(payload, k, max_repair) {
        rows.push(FecCompareRow {
            codec: "fountain_xor_prototype",
            payload_len: payload.len(),
            symbols_sent: k + max_repair,
            symbols_needed: needed,
            overhead_ratio: needed as f64 / k as f64,
        });
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_uniform_is_high() {
        let counts = vec![10, 10, 10, 10];
        let h = shannon_entropy(&counts);
        assert!((h - 2.0).abs() < 1e-9);
    }

    #[test]
    fn kl_identical_is_zero() {
        let p = vec![5, 5, 5, 5];
        assert!(kl_divergence(&p, &p).abs() < 1e-9);
    }

    #[test]
    fn mi_identical_times_is_high() {
        let pairs: Vec<_> = (0..64)
            .map(|i| FlowTimingPair {
                packet_id: i,
                ingress_us: i * 1000,
                egress_us: i * 1000 + 50, // nearly order-preserving
            })
            .collect();
        let mi = mutual_information_timing(&pairs, 16);
        assert!(
            mi > 1.0,
            "expected high MI for order-preserving relay, got {mi}"
        );
    }

    #[test]
    fn percentile_basic() {
        let s = vec![10, 20, 30, 40, 50];
        assert_eq!(percentile(s.clone(), 0.0), 10);
        assert_eq!(percentile(s.clone(), 100.0), 50);
        assert_eq!(percentile(s, 50.0), 30);
    }

    #[test]
    fn simulate_fast_profile_finishes() {
        let (pairs, report, egress) = simulate_adaptive_mix(MixProfile::Fast, 32, 5, 1228, 1228);
        assert_eq!(pairs.len(), 32);
        assert!(!egress.is_empty());
        assert!(
            report.latency.p50_us > 0
                || report.flushes_full + report.flushes_reduced + report.flushes_cover > 0
        );
        assert!(report.bandwidth_mult >= 1.0);
    }

    #[test]
    fn sweep_csv_has_header_and_rows() {
        let csv = sweep_mix_k_latency_csv(16, &[1, 5]);
        assert!(csv.starts_with("profile,"));
        let lines: Vec<_> = csv.lines().collect();
        // 3 profiles * 2 rates + header
        assert_eq!(lines.len(), 1 + 3 * 2);
    }

    #[test]
    fn fec_compare_includes_both_codecs() {
        let payload = vec![1u8; 100];
        let rows = compare_fec_overhead(&payload, 8, 8);
        assert!(rows.iter().any(|r| r.codec.contains("reed_solomon")));
        assert!(rows.iter().any(|r| r.codec.contains("fountain")));
    }
}
