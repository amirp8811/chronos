//! Revised Wire-Level Frame Budget (1,280 Bytes) & 4 KB Hugepage UMEM Descriptor.
//! CHRONOS-SPEC-v7.0 Section 2.1 & 5.1

use std::sync::atomic::{AtomicU8, Ordering};

pub const WIRE_DATAGRAM_SIZE: usize = 1280;
pub const APP_CELL_PAYLOAD_SIZE: usize = 1200;
pub const SIMD_SCRATCHPAD_SIZE: usize = 2808;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SphinxPqcCell {
    pub mutated_session_tag: [u8; 16],
    pub monotonic_seq_iv: [u8; 12],
    pub compressed_onion_header: [u8; 212],
    pub shard_payload_or_noise: [u8; 944],
    pub end_to_end_mac_icv: [u8; 16],
}

impl SphinxPqcCell {
    pub fn new(tag: [u8; 16], seq: u64, payload: &[u8]) -> Self {
        let mut seq_iv = [0u8; 12];
        let seq_bytes = seq.to_be_bytes();
        seq_iv[4..12].copy_from_slice(&seq_bytes);

        let mut shard = [0u8; 944];
        let len = payload.len().min(944);
        shard[..len].copy_from_slice(&payload[..len]);

        Self {
            mutated_session_tag: tag,
            monotonic_seq_iv: seq_iv,
            compressed_onion_header: [0u8; 212],
            shard_payload_or_noise: shard,
            end_to_end_mac_icv: [0u8; 16],
        }
    }
}

/// 4 KB Hugepage-Aligned UMEM Descriptor with Atomic CQE Lifecycle Tracker.
#[repr(C, align(4096))]
pub struct UmemFrameDescriptor {
    pub wire_datagram: [u8; WIRE_DATAGRAM_SIZE],
    pub simd_scratchpad: [u8; SIMD_SCRATCHPAD_SIZE],
    // Atomic ref-counter at offset 4088: 0=Free/Fill Ring, 1=RX Harvest/SIMD Math, 2=Egress DMA in progress
    pub lifecycle_state: AtomicU8,
    pub _padding: [u8; 7],
}

impl UmemFrameDescriptor {
    pub fn new() -> Self {
        Self {
            wire_datagram: [0u8; WIRE_DATAGRAM_SIZE],
            simd_scratchpad: [0u8; SIMD_SCRATCHPAD_SIZE],
            lifecycle_state: AtomicU8::new(0),
            _padding: [0u8; 7],
        }
    }

    #[inline(always)]
    pub fn submit_to_egress_iouring(&mut self) {
        self.lifecycle_state.store(2, Ordering::Release);
    }

    #[inline(always)]
    pub fn on_iouring_cqe_received(&mut self) {
        self.lifecycle_state.store(0, Ordering::Release);
    }

    #[inline(always)]
    pub fn is_safe_for_fill_ring(&self) -> bool {
        self.lifecycle_state.load(Ordering::Acquire) == 0
    }
}

impl Default for UmemFrameDescriptor {
    fn default() -> Self {
        Self::new()
    }
}
