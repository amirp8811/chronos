//! io_uring data-plane prototype boundary.
//!
//! Submission/completion queue atomics are isolated here so SQ/CQ updates cannot
//! be open-coded throughout daemon logic.

use crate::{choose_data_plane, DataPlaneMode};
use std::sync::atomic::{compiler_fence, AtomicU32, Ordering};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoUringPlan {
    pub enabled: bool,
    pub registered_buffers: usize,
    pub sqpoll: bool,
}

#[derive(Debug)]
pub struct IoUringQueueCursor {
    sq_tail: AtomicU32,
    cq_head: AtomicU32,
}

impl IoUringQueueCursor {
    pub fn new() -> Self {
        Self {
            sq_tail: AtomicU32::new(0),
            cq_head: AtomicU32::new(0),
        }
    }

    pub fn publish_submission_tail(&self, tail: u32) {
        compiler_fence(Ordering::SeqCst);
        self.sq_tail.store(tail, Ordering::Release);
        compiler_fence(Ordering::SeqCst);
    }

    pub fn observe_submission_tail(&self) -> u32 {
        compiler_fence(Ordering::SeqCst);
        self.sq_tail.load(Ordering::Acquire)
    }

    pub fn advance_completion_head(&self, head: u32) {
        compiler_fence(Ordering::SeqCst);
        self.cq_head.store(head, Ordering::Release);
        compiler_fence(Ordering::SeqCst);
    }

    pub fn observe_completion_head(&self) -> u32 {
        compiler_fence(Ordering::SeqCst);
        self.cq_head.load(Ordering::Acquire)
    }
}

pub fn plan_io_uring(interface: &str, preferred_engine: &str, buffers: usize) -> IoUringPlan {
    let probe = choose_data_plane(interface, preferred_engine);
    IoUringPlan {
        enabled: probe.mode == DataPlaneMode::IoUringPrototype,
        registered_buffers: if buffers == 0 { 1 } else { buffers },
        sqpoll: probe.mode == DataPlaneMode::IoUringPrototype,
    }
}

impl Default for IoUringQueueCursor {
    fn default() -> Self {
        Self::new()
    }
}
