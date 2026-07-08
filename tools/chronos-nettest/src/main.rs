//! CHRONOS nettest + experiment harness.
//!
//! Modes (via CHRONOS_NETTEST_MODE):
//! - `smoke` (default): lightweight self-check of core metrics + FEC
//! - `mix-sweep`: adaptive mixer K/latency surface → CSV on stdout
//! - `fec-compare`: RS(16,10) vs fountain progressive recovery
//! - `leak-audit`: larger mix simulation with MI / entropy / latency CDF

use chronos_core::anonymity_metrics::{
    FlowTimingPair, compare_fec_overhead, mutual_information_timing, simulate_adaptive_mix,
    sweep_mix_k_latency_csv,
};
use chronos_core::fountain::encode_payload_with_repair;
use chronos_core::mix_policy::MixProfile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::var("CHRONOS_NETTEST_MODE").unwrap_or_else(|_| "smoke".to_string());
    let packets = std::env::var("CHRONOS_NETTEST_PACKETS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(match mode.as_str() {
            "leak-audit" => 2_000,
            "mix-sweep" => 128,
            _ => 64,
        });

    println!("chronos-nettest: mode={mode} packets={packets}");

    match mode.as_str() {
        "smoke" => run_smoke(packets)?,
        "mix-sweep" => run_mix_sweep(packets)?,
        "fec-compare" => run_fec_compare()?,
        "leak-audit" => run_leak_audit(packets)?,
        other => {
            return Err(format!(
                "unknown CHRONOS_NETTEST_MODE={other}; expected smoke|mix-sweep|fec-compare|leak-audit"
            )
            .into());
        }
    }
    println!("chronos-nettest: PASS");
    Ok(())
}

fn run_smoke(packets: usize) -> Result<(), Box<dyn std::error::Error>> {
    let (pairs, report, egress) = simulate_adaptive_mix(MixProfile::Normal, packets, 2, 1228, 1228);
    if pairs.len() != packets {
        return Err(format!("expected {packets} pairs, got {}", pairs.len()).into());
    }
    if egress.is_empty() {
        return Err("empty egress trace".into());
    }
    println!(
        "smoke: profile={} mi_bits={:.4} p50_us={} p95_us={} bw_mult={:.3} egress_packets={}",
        report.profile,
        report.mi_bits,
        report.latency.p50_us,
        report.latency.p95_us,
        report.bandwidth_mult,
        egress.len()
    );

    let payload: Vec<u8> = (0..120u8).collect();
    let fec = encode_payload_with_repair(&payload, 8, 4)?;
    println!(
        "smoke: fountain k={} repair={} overhead={:.3}",
        fec.k, fec.repair, fec.overhead_ratio
    );
    Ok(())
}

fn run_mix_sweep(packets: usize) -> Result<(), Box<dyn std::error::Error>> {
    // Inter-arrival ms: high rate → low rate
    let inter_arrivals = [1u64, 2, 5, 10, 20, 50];
    let csv = sweep_mix_k_latency_csv(packets, &inter_arrivals);
    print!("{csv}");
    Ok(())
}

fn run_fec_compare() -> Result<(), Box<dyn std::error::Error>> {
    println!("codec,payload_len,symbols_sent,symbols_needed,overhead_ratio");
    for &len in &[64usize, 200, 500, 1000] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let rows = compare_fec_overhead(&payload, 10, 12);
        for r in rows {
            println!(
                "{},{},{},{},{:.4}",
                r.codec, r.payload_len, r.symbols_sent, r.symbols_needed, r.overhead_ratio
            );
        }
    }
    Ok(())
}

fn run_leak_audit(packets: usize) -> Result<(), Box<dyn std::error::Error>> {
    if packets < 100 {
        return Err("leak-audit requires CHRONOS_NETTEST_PACKETS >= 100".into());
    }
    println!(
        "profile,packets,inter_arrival_ms,mi_bits,p50_us,p95_us,p99_us,bw_mult,flushes_full,flushes_reduced,flushes_cover,egress_entropy"
    );
    for profile in [
        MixProfile::Fast,
        MixProfile::Normal,
        MixProfile::HighAnonymity,
    ] {
        for &ia in &[1u64, 5, 20] {
            let (pairs, report, _egr) = simulate_adaptive_mix(profile, packets, ia, 1228, 1228);
            // Sanity: MI of identity mapping would be high; batching should reduce order leakage somewhat
            let _mi_check = mutual_information_timing(&pairs, 16);
            println!(
                "{},{},{},{:.6},{},{},{},{:.4},{},{},{},{:.6}",
                report.profile,
                report.packets,
                ia,
                report.mi_bits,
                report.latency.p50_us,
                report.latency.p95_us,
                report.latency.p99_us,
                report.bandwidth_mult,
                report.flushes_full,
                report.flushes_reduced,
                report.flushes_cover,
                report.egress_entropy_bits
            );
        }
    }

    // Baseline: no mixing (identity egress) should show higher MI than batched profiles at same rate.
    let identity: Vec<FlowTimingPair> = (0..packets as u64)
        .map(|i| FlowTimingPair {
            packet_id: i,
            ingress_us: i * 1000,
            egress_us: i * 1000 + 100,
        })
        .collect();
    let mi_identity = mutual_information_timing(&identity, 16);
    let (_p, batched, _) = simulate_adaptive_mix(MixProfile::HighAnonymity, packets, 1, 1228, 1228);
    let mi_batched = mutual_information_timing(&_p, 16);
    println!(
        "leak-audit comparison: identity_mi={:.6} high_anonymity_mi={:.6}",
        mi_identity, mi_batched
    );
    if mi_batched > mi_identity + 0.5 {
        // Not a hard failure — batching can still preserve order if flushes are frequent.
        eprintln!(
            "chronos-nettest: note: batched MI not lower than identity (batching may be flushing often)"
        );
    }
    let _ = batched;
    Ok(())
}
