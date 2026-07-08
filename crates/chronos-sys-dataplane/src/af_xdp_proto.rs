//! AF_XDP data-plane prototype boundary.
//!
//! Atomic ring cursors are isolated here so all future AF_XDP fill/RX/TX/CQ
//! pointer manipulation goes through a single hardware-boundary wrapper with
//! explicit compiler fences.

use crate::{choose_data_plane, DataPlaneMode};
use std::sync::atomic::{compiler_fence, AtomicU32, Ordering};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AfXdpPlan {
    pub enabled: bool,
    pub umem_frames: usize,
    pub frame_size: usize,
}

#[derive(Debug)]
pub struct AfXdpRingCursor {
    producer: AtomicU32,
    consumer: AtomicU32,
    mask: u32,
}

impl AfXdpRingCursor {
    pub fn new(ring_entries: u32) -> Self {
        let entries = ring_entries.max(2).next_power_of_two();
        Self {
            producer: AtomicU32::new(0),
            consumer: AtomicU32::new(0),
            mask: entries - 1,
        }
    }

    pub fn reserve_producer_slot(&self) -> u32 {
        compiler_fence(Ordering::SeqCst);
        let slot = self.producer.fetch_add(1, Ordering::AcqRel) & self.mask;
        compiler_fence(Ordering::SeqCst);
        slot
    }

    pub fn publish_consumer_completion(&self, completed: u32) {
        compiler_fence(Ordering::SeqCst);
        self.consumer.store(completed, Ordering::Release);
        compiler_fence(Ordering::SeqCst);
    }

    pub fn producer(&self) -> u32 {
        self.producer.load(Ordering::Acquire)
    }

    pub fn consumer(&self) -> u32 {
        self.consumer.load(Ordering::Acquire)
    }
}

pub fn plan_af_xdp(interface: &str, preferred_engine: &str, umem_mb: usize) -> AfXdpPlan {
    let probe = choose_data_plane(interface, preferred_engine);
    let frame_size = 4096;
    let bytes = umem_mb.max(1) * 1024 * 1024;
    AfXdpPlan {
        enabled: probe.mode == DataPlaneMode::AfXdpPrototype,
        umem_frames: bytes / frame_size,
        frame_size,
    }
}
