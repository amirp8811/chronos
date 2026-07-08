//! Lightweight fountain / sliding-window FEC prototype.
//!
//! This is **not** a full RaptorQ implementation. It provides a deterministic
//! rateless-style encoder/decoder over GF(2) XOR combinations so experiments can
//! compare progressive recovery latency and overhead against fixed Reed-Solomon
//! (16,10) without pulling a heavyweight codec dependency.
//!
//! Design notes:
//! - Source block is split into `k` symbols of equal length.
//! - Degree-1 systematic symbols are emitted first (indices 0..k-1).
//! - Repair symbols are XOR of a deterministic degree-d subset selected by
//!   a linear congruential seed from the ESI (encoding symbol id).
//! - Decoder peels degree-1 equations (belief-propagation style) until recovery
//!   or stall. For small k this is sufficient for lab comparisons.

#[cfg(not(feature = "std"))]
use alloc::format;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// One encoded fountain symbol (systematic or repair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FountainSymbol {
    /// Encoding symbol identifier. 0..k-1 are systematic.
    pub esi: u32,
    pub data: Vec<u8>,
}

/// Configuration for a fountain source block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FountainConfig {
    pub k: usize,
    pub symbol_len: usize,
}

impl FountainConfig {
    pub fn new(k: usize, symbol_len: usize) -> Result<Self, String> {
        if k == 0 || k > 256 {
            return Err(format!("k out of supported range 1..=256, got {k}"));
        }
        if symbol_len == 0 || symbol_len > 4096 {
            return Err(format!(
                "symbol_len out of supported range 1..=4096, got {symbol_len}"
            ));
        }
        Ok(Self { k, symbol_len })
    }
}

/// Deterministic LCG for repair neighbor selection.
#[inline]
fn lcg(seed: u32) -> u32 {
    seed.wrapping_mul(1664525).wrapping_add(1013904223)
}

/// Degree distribution: mostly degree 2-4 with occasional higher degree.
fn degree_for_esi(esi: u32, k: usize) -> usize {
    if (esi as usize) < k {
        return 1;
    }
    let r = lcg(esi ^ 0xA5A5_5A5A) % 100;
    if r < 50 {
        2.min(k)
    } else if r < 80 {
        3.min(k)
    } else if r < 95 {
        4.min(k)
    } else {
        (k / 2).clamp(2, k)
    }
}

/// Neighbor indices for a given ESI.
fn neighbors(esi: u32, k: usize) -> Vec<usize> {
    if (esi as usize) < k {
        return vec![esi as usize];
    }
    let d = degree_for_esi(esi, k);
    let mut out = Vec::with_capacity(d);
    let mut state = lcg(esi.wrapping_add(1));
    while out.len() < d {
        state = lcg(state);
        let idx = (state as usize) % k;
        if !out.contains(&idx) {
            out.push(idx);
        }
    }
    out.sort_unstable();
    out
}

/// Encode `k` source symbols into systematic + `repair_count` repair symbols.
pub fn fountain_encode(
    source_symbols: &[Vec<u8>],
    repair_count: usize,
) -> Result<Vec<FountainSymbol>, String> {
    if source_symbols.is_empty() {
        return Err("need at least one source symbol".into());
    }
    let k = source_symbols.len();
    let symbol_len = source_symbols[0].len();
    for (i, s) in source_symbols.iter().enumerate() {
        if s.len() != symbol_len {
            return Err(format!(
                "symbol {i} length {} != expected {symbol_len}",
                s.len()
            ));
        }
    }
    let _cfg = FountainConfig::new(k, symbol_len)?;

    let mut out = Vec::with_capacity(k + repair_count);
    // Systematic
    for (i, sym) in source_symbols.iter().enumerate() {
        out.push(FountainSymbol {
            esi: i as u32,
            data: sym.clone(),
        });
    }
    // Repair
    for r in 0..repair_count {
        let esi = (k + r) as u32;
        let neigh = neighbors(esi, k);
        let mut data = vec![0u8; symbol_len];
        for &idx in &neigh {
            for (b, &src) in data.iter_mut().zip(source_symbols[idx].iter()) {
                *b ^= src;
            }
        }
        out.push(FountainSymbol { esi, data });
    }
    Ok(out)
}

/// Split a contiguous payload into `k` equal-length symbols (zero-padded).
pub fn split_payload(payload: &[u8], k: usize) -> Result<Vec<Vec<u8>>, String> {
    if k == 0 {
        return Err("k must be > 0".into());
    }
    let symbol_len = payload.len().div_ceil(k).max(1);
    let mut symbols = Vec::with_capacity(k);
    for i in 0..k {
        let start = i * symbol_len;
        let mut sym = vec![0u8; symbol_len];
        if start < payload.len() {
            let end = (start + symbol_len).min(payload.len());
            let take = end - start;
            sym[..take].copy_from_slice(&payload[start..end]);
        }
        symbols.push(sym);
    }
    Ok(symbols)
}

/// Join k symbols back into a payload of `total_len` bytes.
pub fn join_payload(symbols: &[Vec<u8>], total_len: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(total_len);
    for s in symbols {
        out.extend_from_slice(s);
    }
    if out.len() < total_len {
        return Err(format!(
            "joined length {} < expected {total_len}",
            out.len()
        ));
    }
    out.truncate(total_len);
    Ok(out)
}

/// Belief-propagation style fountain decoder for small k.
#[derive(Debug, Clone)]
pub struct FountainDecoder {
    k: usize,
    symbol_len: usize,
    recovered: Vec<Option<Vec<u8>>>,
    /// Pending equations: (neighbor indices still unresolved, xor-accumulated data)
    equations: Vec<(Vec<usize>, Vec<u8>)>,
}

impl FountainDecoder {
    pub fn new(k: usize, symbol_len: usize) -> Result<Self, String> {
        let _ = FountainConfig::new(k, symbol_len)?;
        Ok(Self {
            k,
            symbol_len,
            recovered: vec![None; k],
            equations: Vec::new(),
        })
    }

    pub fn recovered_count(&self) -> usize {
        self.recovered.iter().filter(|s| s.is_some()).count()
    }

    pub fn is_complete(&self) -> bool {
        self.recovered_count() == self.k
    }

    pub fn take_recovered(self) -> Result<Vec<Vec<u8>>, String> {
        if !self.is_complete() {
            return Err(format!(
                "incomplete: {}/{} symbols",
                self.recovered_count(),
                self.k
            ));
        }
        Ok(self
            .recovered
            .into_iter()
            .map(|s| s.expect("complete"))
            .collect())
    }

    /// Ingest one encoded symbol; returns true if newly completed.
    pub fn ingest(&mut self, symbol: &FountainSymbol) -> Result<bool, String> {
        if symbol.data.len() != self.symbol_len {
            return Err(format!(
                "symbol length {} != {}",
                symbol.data.len(),
                self.symbol_len
            ));
        }
        let mut neigh = neighbors(symbol.esi, self.k);
        let mut data = symbol.data.clone();

        // Reduce by already-recovered neighbors
        let mut still = Vec::new();
        for idx in neigh.drain(..) {
            if let Some(ref known) = self.recovered[idx] {
                for (b, &k) in data.iter_mut().zip(known.iter()) {
                    *b ^= k;
                }
            } else {
                still.push(idx);
            }
        }

        if still.is_empty() {
            // Redundant / check equation; ignore
            return Ok(self.is_complete());
        }
        if still.len() == 1 {
            self.recover(still[0], data)?;
        } else {
            self.equations.push((still, data));
        }
        self.peel()?;
        Ok(self.is_complete())
    }

    fn recover(&mut self, idx: usize, data: Vec<u8>) -> Result<(), String> {
        if idx >= self.k {
            return Err(format!("index {idx} out of range"));
        }
        if let Some(ref existing) = self.recovered[idx] {
            if existing != &data {
                return Err(format!("conflict recovering symbol {idx}"));
            }
            return Ok(());
        }
        self.recovered[idx] = Some(data);
        Ok(())
    }

    fn peel(&mut self) -> Result<(), String> {
        let mut progress = true;
        while progress {
            progress = false;
            let mut i = 0;
            while i < self.equations.len() {
                let (neigh, data) = &self.equations[i];
                let mut still = Vec::new();
                let mut reduced = data.clone();
                for &idx in neigh {
                    if let Some(ref known) = self.recovered[idx] {
                        for (b, &k) in reduced.iter_mut().zip(known.iter()) {
                            *b ^= k;
                        }
                    } else {
                        still.push(idx);
                    }
                }
                if still.is_empty() {
                    self.equations.swap_remove(i);
                    progress = true;
                    continue;
                }
                if still.len() == 1 {
                    let idx = still[0];
                    self.equations.swap_remove(i);
                    self.recover(idx, reduced)?;
                    progress = true;
                    continue;
                }
                self.equations[i] = (still, reduced);
                i += 1;
            }
        }
        Ok(())
    }
}

/// Encode a payload with systematic + repair symbols and report overhead.
#[derive(Debug, Clone, PartialEq)]
pub struct FountainEncodeReport {
    pub k: usize,
    pub systematic: usize,
    pub repair: usize,
    pub total_symbols: usize,
    pub symbol_len: usize,
    pub overhead_ratio: f64,
    pub symbols: Vec<FountainSymbol>,
}

pub fn encode_payload_with_repair(
    payload: &[u8],
    k: usize,
    repair_count: usize,
) -> Result<FountainEncodeReport, String> {
    let source = split_payload(payload, k)?;
    let symbol_len = source[0].len();
    let symbols = fountain_encode(&source, repair_count)?;
    let total = symbols.len();
    Ok(FountainEncodeReport {
        k,
        systematic: k,
        repair: repair_count,
        total_symbols: total,
        symbol_len,
        overhead_ratio: total as f64 / k as f64,
        symbols,
    })
}

/// Try to decode from a subset of symbols; returns recovered payload length bytes.
pub fn try_decode_payload(
    symbols: &[FountainSymbol],
    k: usize,
    symbol_len: usize,
    total_len: usize,
) -> Result<Vec<u8>, String> {
    let mut dec = FountainDecoder::new(k, symbol_len)?;
    for s in symbols {
        if dec.ingest(s)? {
            break;
        }
    }
    let recovered = dec.take_recovered()?;
    join_payload(&recovered, total_len)
}

/// Minimum repair symbols (beyond systematic) needed under a random loss pattern.
/// `loss_mask[i] == true` means symbol i from a systematic+repair stream is lost.
pub fn progressive_recovery_count(
    payload: &[u8],
    k: usize,
    max_repair: usize,
) -> Result<usize, String> {
    let report = encode_payload_with_repair(payload, k, max_repair)?;
    let mut dec = FountainDecoder::new(k, report.symbol_len)?;
    for (received, s) in report.symbols.iter().enumerate() {
        if dec.ingest(s)? {
            return Ok(received + 1);
        }
    }
    Err(format!(
        "failed to recover with {} symbols",
        report.symbols.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systematic_round_trip() {
        let payload = b"hello chronos fountain fec prototype!!".to_vec();
        let k = 8;
        let report = encode_payload_with_repair(&payload, k, 4).unwrap();
        assert_eq!(report.systematic, k);
        assert_eq!(report.total_symbols, k + 4);
        // Decode using only systematic symbols
        let recovered =
            try_decode_payload(&report.symbols[..k], k, report.symbol_len, payload.len()).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn recovers_with_loss_using_repair() {
        let payload: Vec<u8> = (0..200u8).collect();
        let k = 10;
        let report = encode_payload_with_repair(&payload, k, 12).unwrap();
        // Drop 3 systematic symbols; feed remaining systematic + repairs
        let mut subset = Vec::new();
        for s in &report.symbols {
            if s.esi == 1 || s.esi == 4 || s.esi == 7 {
                continue; // lost
            }
            subset.push(s.clone());
        }
        let recovered = try_decode_payload(&subset, k, report.symbol_len, payload.len()).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn progressive_count_at_least_k() {
        let payload = vec![7u8; 64];
        let n = progressive_recovery_count(&payload, 8, 16).unwrap();
        assert!(n >= 8);
        assert!(n <= 8 + 16);
    }

    #[test]
    fn overhead_ratio_matches() {
        let report = encode_payload_with_repair(b"abc", 4, 2).unwrap();
        assert!((report.overhead_ratio - 1.5).abs() < 1e-9);
    }
}
