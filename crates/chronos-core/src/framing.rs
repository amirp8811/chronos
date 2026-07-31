//! Fixed wire-budget constants and a prototype UMEM descriptor.
//!
//! The descriptor models memory layout only. It is not a native networking
//! driver, and it is kept separate from protocol cryptography.

use core::sync::atomic::{AtomicU8, Ordering};

pub const WIRE_DATAGRAM_SIZE: usize = 1280;
pub const APP_CELL_PAYLOAD_SIZE: usize = 1200;
pub const SIMD_SCRATCHPAD_SIZE: usize = 2808;

/// 4 KB hugepage-aligned UMEM descriptor with an atomic lifecycle tracker.
#[repr(C, align(4096))]
pub struct UmemFrameDescriptor {
    pub wire_datagram: [u8; WIRE_DATAGRAM_SIZE],
    pub simd_scratchpad: [u8; SIMD_SCRATCHPAD_SIZE],
    /// 0 = free/fill ring, 1 = receive processing, 2 = egress in progress.
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
