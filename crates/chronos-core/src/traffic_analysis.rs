//! Traffic-analysis measurement harness primitives.
//!
//! These helpers do not claim anonymity. They provide deterministic measurements
//! that let tests and simulations compare packet length uniformity and timing
//! regularity for paced/cover-traffic plans.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketObservation {
    pub timestamp_micros: u64,
    pub length_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrafficShapeReport {
    pub packet_count: usize,
    pub unique_lengths: usize,
    pub mean_interval_micros: f64,
    pub max_interval_jitter_micros: u64,
    pub constant_length: bool,
    pub constant_interval: bool,
}

pub fn analyze_observations(observations: &[PacketObservation]) -> TrafficShapeReport {
    let packet_count = observations.len();
    let mut lengths: Vec<usize> = observations.iter().map(|o| o.length_bytes).collect();
    lengths.sort_unstable();
    lengths.dedup();

    let intervals: Vec<u64> = observations
        .windows(2)
        .map(|w| w[1].timestamp_micros.saturating_sub(w[0].timestamp_micros))
        .collect();
    let mean_interval_micros = if intervals.is_empty() {
        0.0
    } else {
        intervals.iter().sum::<u64>() as f64 / intervals.len() as f64
    };
    let max_interval_jitter_micros = if intervals.is_empty() {
        0
    } else {
        let min = intervals.iter().min().copied().unwrap_or(0);
        let max = intervals.iter().max().copied().unwrap_or(0);
        max - min
    };

    TrafficShapeReport {
        packet_count,
        unique_lengths: lengths.len(),
        mean_interval_micros,
        max_interval_jitter_micros,
        constant_length: lengths.len() <= 1,
        constant_interval: max_interval_jitter_micros == 0,
    }
}

pub fn synthesize_constant_rate_trace(
    packet_count: usize,
    interval_micros: u64,
    length_bytes: usize,
) -> Vec<PacketObservation> {
    (0..packet_count)
        .map(|idx| PacketObservation {
            timestamp_micros: idx as u64 * interval_micros,
            length_bytes,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_harness_accepts_constant_rate_constant_length_trace() {
        let trace = synthesize_constant_rate_trace(8, 5000, 1228);
        let report = analyze_observations(&trace);
        assert_eq!(report.packet_count, 8);
        assert_eq!(report.unique_lengths, 1);
        assert!(report.constant_length);
        assert!(report.constant_interval);
        assert_eq!(report.max_interval_jitter_micros, 0);
    }

    #[test]
    fn traffic_harness_detects_length_and_timing_variation() {
        let trace = vec![
            PacketObservation {
                timestamp_micros: 0,
                length_bytes: 1000,
            },
            PacketObservation {
                timestamp_micros: 5000,
                length_bytes: 1228,
            },
            PacketObservation {
                timestamp_micros: 12_000,
                length_bytes: 1228,
            },
        ];
        let report = analyze_observations(&trace);
        assert!(!report.constant_length);
        assert!(!report.constant_interval);
        assert_eq!(report.unique_lengths, 2);
        assert_eq!(report.max_interval_jitter_micros, 2000);
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrafficClassifierScore {
    pub timing_leak_score: f64,
    pub length_leak_score: f64,
    pub combined_score: f64,
}

pub fn heuristic_classifier_score(report: TrafficShapeReport) -> TrafficClassifierScore {
    let timing = if report.constant_interval {
        0.0
    } else {
        (report.max_interval_jitter_micros as f64 / 10_000.0).min(1.0)
    };
    let length = if report.constant_length {
        0.0
    } else {
        ((report.unique_lengths.saturating_sub(1)) as f64 / 8.0).min(1.0)
    };
    TrafficClassifierScore {
        timing_leak_score: timing,
        length_leak_score: length,
        combined_score: ((timing + length) / 2.0).min(1.0),
    }
}

#[cfg(test)]
mod classifier_tests {
    use super::*;
    #[test]
    fn heuristic_scores_shaped_trace_lower_than_unshaped() {
        let shaped = heuristic_classifier_score(analyze_observations(
            &synthesize_constant_rate_trace(5, 1000, 1228),
        ));
        let unshaped = heuristic_classifier_score(analyze_observations(&[
            PacketObservation {
                timestamp_micros: 0,
                length_bytes: 900,
            },
            PacketObservation {
                timestamp_micros: 1000,
                length_bytes: 1228,
            },
            PacketObservation {
                timestamp_micros: 9000,
                length_bytes: 777,
            },
        ]));
        assert!(shaped.combined_score < unshaped.combined_score);
    }
}

pub fn observations_to_csv(observations: &[PacketObservation]) -> String {
    let mut out = String::from("timestamp_micros,length_bytes\n");
    for obs in observations {
        out.push_str(&format!("{},{}\n", obs.timestamp_micros, obs.length_bytes));
    }
    out
}

pub fn observations_from_csv(csv: &str) -> Result<Vec<PacketObservation>, String> {
    let mut out = Vec::new();
    for (line_no, line) in csv.lines().enumerate() {
        if line_no == 0 && line.trim() == "timestamp_micros,length_bytes" {
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let (ts, len) = line
            .split_once(',')
            .ok_or_else(|| format!("invalid csv line {line_no}"))?;
        out.push(PacketObservation {
            timestamp_micros: ts.parse::<u64>().map_err(|e| e.to_string())?,
            length_bytes: len.parse::<usize>().map_err(|e| e.to_string())?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod csv_tests {
    use super::*;
    #[test]
    fn traffic_observations_round_trip_csv() {
        let trace = synthesize_constant_rate_trace(3, 10, 1228);
        let csv = observations_to_csv(&trace);
        assert_eq!(observations_from_csv(&csv).unwrap(), trace);
    }
}
