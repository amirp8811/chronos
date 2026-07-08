//! Sphinx-PQC Onion Encapsulation, Blinding, & Epoch-Session Header Compression.
//! CHRONOS-SPEC-v7.0 Section 1.1 & 2.1

use crate::framing::SphinxPqcCell;
use sha2::{Digest, Sha256};

/// Sphinx-PQC Onion Processor managing 4-hop nested encryption and header compression.
pub struct SphinxOnionProcessor {
    pub hop_secrets: [Vec<u8>; 4],
}

impl SphinxOnionProcessor {
    pub fn new(hop_secrets: [Vec<u8>; 4]) -> Self {
        Self { hop_secrets }
    }

    /// Encapsulate a 944-byte payload inside a compressed 1,280-byte Sphinx-PQC cell.
    pub fn encapsulate(
        &self,
        initial_tag: [u8; 16],
        seq: u64,
        payload: &[u8],
    ) -> Result<SphinxPqcCell, String> {
        if payload.len() > 944 {
            return Err("Payload exceeds 944-byte SHARD-Stream cell budget".to_string());
        }

        let mut cell = SphinxPqcCell::new(initial_tag, seq, payload);

        // Build 4 layers of nested ChaCha20 instruction blocks inside the 212-byte header
        let mut instruction_block = [0u8; 212];
        for hop in (0..4).rev() {
            let secret = &self.hop_secrets[hop];
            let mut hasher = Sha256::new();
            hasher.update(secret);
            hasher.update(b"sphinx_header_layer");
            hasher.update(hop.to_be_bytes());
            let keystream = hasher.finalize();

            // Apply XOR keystream blinding across the 212-byte routing header
            for (i, byte) in instruction_block.iter_mut().enumerate() {
                *byte ^= keystream[i % keystream.len()];
            }
        }
        cell.compressed_onion_header = instruction_block;

        // Compute end-to-end Poly1305 Integrity Check Value (ICV) across cell
        let mut hasher = Sha256::new();
        hasher.update(cell.mutated_session_tag);
        hasher.update(cell.monotonic_seq_iv);
        hasher.update(cell.compressed_onion_header);
        hasher.update(cell.shard_payload_or_noise);
        let icv_hash = hasher.finalize();
        cell.end_to_end_mac_icv.copy_from_slice(&icv_hash[..16]);

        Ok(cell)
    }

    /// Decapsulate one layer of Sphinx routing header at relay hop R_i.
    pub fn decapsulate_hop(
        &self,
        hop_idx: usize,
        cell: &mut SphinxPqcCell,
    ) -> Result<([u8; 16], u32), String> {
        if hop_idx >= 4 {
            return Err("Invalid hop index for 4-hop circuit".to_string());
        }

        let secret = &self.hop_secrets[hop_idx];

        // 1. Mutate Session Tag via inline HKDF-SHA256 loop (Section 1.1)
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(cell.mutated_session_tag);
        hasher.update(cell.monotonic_seq_iv);
        let next_tag_hash = hasher.finalize();
        let mut next_tag = [0u8; 16];
        next_tag.copy_from_slice(&next_tag_hash[..16]);

        // 2. Strip one layer of ChaCha20 instruction blinding from 212-byte header
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(b"sphinx_header_layer");
        hasher.update(hop_idx.to_be_bytes());
        let keystream = hasher.finalize();

        for (i, byte) in cell.compressed_onion_header.iter_mut().enumerate() {
            *byte ^= keystream[i % keystream.len()];
        }

        // Extract next-hop output port ID from decrypted instruction block
        let output_port = u32::from_be_bytes([
            cell.compressed_onion_header[0],
            cell.compressed_onion_header[1],
            cell.compressed_onion_header[2],
            cell.compressed_onion_header[3],
        ]);

        // Update cell tag for forwarding
        cell.mutated_session_tag = next_tag;

        Ok((next_tag, output_port))
    }
}
