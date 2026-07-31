//! Deliberately non-production onion-header simulation.
//!
//! This module exists only for deterministic demonstrations of four-hop header
//! mutation. It uses SHA-256-derived XOR and a truncated SHA-256 checksum. It
//! provides neither authenticated per-hop routing nor an anonymity guarantee and
//! must not be used for network traffic. Real relay code uses `route_layer`.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub const SIMULATION_ONION_PAYLOAD_BYTES: usize = 944;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulationOnionError {
    PayloadTooLarge { got: usize, max: usize },
    InvalidHopIndex { got: usize, max: usize },
}

/// Cell-shaped data used only by the optional simulation feature.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationOnionCell {
    pub mutated_session_tag: [u8; 16],
    pub monotonic_seq_iv: [u8; 12],
    pub simulated_header: [u8; 212],
    pub shard_payload_or_noise: [u8; SIMULATION_ONION_PAYLOAD_BYTES],
    pub integrity_check: [u8; 16],
}

impl SimulationOnionCell {
    /// Creates a simulation cell without truncating the payload.
    pub fn new(tag: [u8; 16], seq: u64, payload: &[u8]) -> Result<Self, SimulationOnionError> {
        if payload.len() > SIMULATION_ONION_PAYLOAD_BYTES {
            return Err(SimulationOnionError::PayloadTooLarge {
                got: payload.len(),
                max: SIMULATION_ONION_PAYLOAD_BYTES,
            });
        }
        let mut seq_iv = [0u8; 12];
        seq_iv[4..].copy_from_slice(&seq.to_be_bytes());
        let mut shard_payload_or_noise = [0u8; SIMULATION_ONION_PAYLOAD_BYTES];
        shard_payload_or_noise[..payload.len()].copy_from_slice(payload);
        Ok(Self {
            mutated_session_tag: tag,
            monotonic_seq_iv: seq_iv,
            simulated_header: [0u8; 212],
            shard_payload_or_noise,
            integrity_check: [0u8; 16],
        })
    }
}

/// Four-hop header-mutation simulator. It is intentionally unavailable from the
/// default public API.
pub struct SphinxSimulationProcessor {
    pub hop_secrets: [Vec<u8>; 4],
}

impl SphinxSimulationProcessor {
    pub fn new(hop_secrets: [Vec<u8>; 4]) -> Self {
        Self { hop_secrets }
    }

    pub fn encapsulate(
        &self,
        initial_tag: [u8; 16],
        seq: u64,
        payload: &[u8],
    ) -> Result<SimulationOnionCell, SimulationOnionError> {
        let mut cell = SimulationOnionCell::new(initial_tag, seq, payload)?;
        let mut instruction_block = [0u8; 212];
        for hop in (0usize..4).rev() {
            let secret = &self.hop_secrets[hop];
            let mut hasher = Sha256::new();
            hasher.update(secret);
            hasher.update(b"chronos-simulation-header-layer");
            hasher.update((hop as u32).to_be_bytes());
            let keystream = hasher.finalize();
            for (index, byte) in instruction_block.iter_mut().enumerate() {
                *byte ^= keystream[index % keystream.len()];
            }
        }
        cell.simulated_header = instruction_block;

        let mut hasher = Sha256::new();
        hasher.update(cell.mutated_session_tag);
        hasher.update(cell.monotonic_seq_iv);
        hasher.update(cell.simulated_header);
        hasher.update(cell.shard_payload_or_noise);
        cell.integrity_check
            .copy_from_slice(&hasher.finalize()[..16]);
        Ok(cell)
    }

    pub fn decapsulate_hop(
        &self,
        hop_index: usize,
        cell: &mut SimulationOnionCell,
    ) -> Result<([u8; 16], u32), SimulationOnionError> {
        if hop_index >= 4 {
            return Err(SimulationOnionError::InvalidHopIndex {
                got: hop_index,
                max: 3,
            });
        }
        let secret = &self.hop_secrets[hop_index];
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(cell.mutated_session_tag);
        hasher.update(cell.monotonic_seq_iv);
        let next_tag_hash = hasher.finalize();
        let mut next_tag = [0u8; 16];
        next_tag.copy_from_slice(&next_tag_hash[..16]);

        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(b"chronos-simulation-header-layer");
        hasher.update((hop_index as u32).to_be_bytes());
        let keystream = hasher.finalize();
        for (index, byte) in cell.simulated_header.iter_mut().enumerate() {
            *byte ^= keystream[index % keystream.len()];
        }
        let output_port =
            u32::from_be_bytes(cell.simulated_header[0..4].try_into().expect("fixed"));
        cell.mutated_session_tag = next_tag;
        Ok((next_tag, output_port))
    }
}

impl core::fmt::Display for SimulationOnionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversize_simulation_payload_is_rejected_without_truncation() {
        let payload = vec![7u8; SIMULATION_ONION_PAYLOAD_BYTES + 1];
        assert_eq!(
            SimulationOnionCell::new([0; 16], 0, &payload),
            Err(SimulationOnionError::PayloadTooLarge {
                got: SIMULATION_ONION_PAYLOAD_BYTES + 1,
                max: SIMULATION_ONION_PAYLOAD_BYTES,
            })
        );
    }

    #[test]
    fn exact_simulation_payload_limit_is_preserved() {
        let payload = vec![9u8; SIMULATION_ONION_PAYLOAD_BYTES];
        let cell = SimulationOnionCell::new([1; 16], 7, &payload).expect("exact maximum");
        assert_eq!(cell.shard_payload_or_noise, payload.as_slice());
    }
}
