//! Dataplane ring-state model used by loom tests and future AF_XDP/io_uring HALs.
//!
//! This module deliberately models ownership transitions instead of packet bytes:
//! Free -> RxOwned -> TxOwned -> Free. The real HAL should preserve this state
//! machine around UMEM descriptors and completion entries.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorState {
    Free = 0,
    RxOwned = 1,
    TxOwned = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorTransitionError {
    WrongState {
        expected: DescriptorState,
        actual: DescriptorState,
    },
}

#[cfg(not(test))]
mod atomics {
    pub use std::sync::atomic::{AtomicU8, Ordering};
}

#[cfg(test)]
mod atomics {
    pub use loom::sync::atomic::{AtomicU8, Ordering};
}

use atomics::{AtomicU8, Ordering};

pub struct DescriptorLifecycle {
    state: AtomicU8,
}

impl DescriptorLifecycle {
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(DescriptorState::Free as u8),
        }
    }

    pub fn state(&self) -> DescriptorState {
        decode(self.state.load(Ordering::Acquire))
    }

    pub fn claim_for_rx(&self) -> Result<(), DescriptorTransitionError> {
        self.transition(DescriptorState::Free, DescriptorState::RxOwned)
    }

    pub fn submit_for_tx(&self) -> Result<(), DescriptorTransitionError> {
        self.transition(DescriptorState::RxOwned, DescriptorState::TxOwned)
    }

    pub fn complete_tx(&self) -> Result<(), DescriptorTransitionError> {
        self.transition(DescriptorState::TxOwned, DescriptorState::Free)
    }

    fn transition(
        &self,
        expected: DescriptorState,
        next: DescriptorState,
    ) -> Result<(), DescriptorTransitionError> {
        self.state
            .compare_exchange(
                expected as u8,
                next as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|actual| DescriptorTransitionError::WrongState {
                expected,
                actual: decode(actual),
            })
    }
}

impl Default for DescriptorLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

fn decode(v: u8) -> DescriptorState {
    match v {
        1 => DescriptorState::RxOwned,
        2 => DescriptorState::TxOwned,
        _ => DescriptorState::Free,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    // Note: in a real loom test we'd use loom::thread, but for standard tests Arc is fine.
    
    #[test]
    fn descriptor_cannot_be_double_claimed() {
        let d = DescriptorLifecycle::new();
        assert_eq!(d.claim_for_rx(), Ok(()));
        assert!(d.claim_for_rx().is_err());
    }
}
