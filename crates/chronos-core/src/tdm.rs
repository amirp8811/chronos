//! Deterministic time-slot planning model.
//!
//! This module returns a model of data and optional cover slots for tests and
//! experiments. It does not sleep, perform I/O, or create constant-rate network
//! egress on its own.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdmCellKind {
    Data,
    Cover,
}

/// Upper bound for one in-memory planning call. Larger epochs must be planned
/// in chunks by the caller rather than allocating an unbounded vector.
pub const TDM_MAX_EPOCH_SLOTS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdmPlanError {
    TooManySlots { got: u64, max: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdmSlot {
    pub slot_index: u64,
    pub send_after: Duration,
    pub kind: TdmCellKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdmScheduler {
    slot_width: Duration,
    cover_when_idle: bool,
}

impl TdmScheduler {
    pub fn new(slot_width: Duration, cover_when_idle: bool) -> Self {
        Self {
            slot_width,
            cover_when_idle,
        }
    }

    pub fn plan_epoch(
        &self,
        epoch_slots: u64,
        data_cells: u64,
    ) -> Result<Vec<TdmSlot>, TdmPlanError> {
        if epoch_slots > TDM_MAX_EPOCH_SLOTS {
            return Err(TdmPlanError::TooManySlots {
                got: epoch_slots,
                max: TDM_MAX_EPOCH_SLOTS,
            });
        }
        let mut slots = Vec::with_capacity(epoch_slots as usize);
        for slot_index in 0..epoch_slots {
            let kind = if slot_index < data_cells {
                TdmCellKind::Data
            } else if self.cover_when_idle {
                TdmCellKind::Cover
            } else {
                continue;
            };
            slots.push(TdmSlot {
                slot_index,
                send_after: self.slot_width.saturating_mul(slot_index as u32),
                kind,
            });
        }
        Ok(slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tdm_scheduler_fills_idle_slots_with_cover() {
        let s = TdmScheduler::new(Duration::from_millis(5), true);
        let plan = s.plan_epoch(4, 2).expect("plan");
        assert_eq!(plan.len(), 4);
        assert_eq!(plan[0].kind, TdmCellKind::Data);
        assert_eq!(plan[1].kind, TdmCellKind::Data);
        assert_eq!(plan[2].kind, TdmCellKind::Cover);
        assert_eq!(plan[3].send_after, Duration::from_millis(15));
    }

    #[test]
    fn tdm_scheduler_rejects_unbounded_epoch_allocations() {
        let scheduler = TdmScheduler::new(Duration::from_millis(1), false);
        assert_eq!(
            scheduler.plan_epoch(TDM_MAX_EPOCH_SLOTS + 1, 0),
            Err(TdmPlanError::TooManySlots {
                got: TDM_MAX_EPOCH_SLOTS + 1,
                max: TDM_MAX_EPOCH_SLOTS,
            })
        );
    }

    #[test]
    fn tdm_scheduler_can_skip_cover_when_disabled() {
        let s = TdmScheduler::new(Duration::from_millis(1), false);
        let plan = s.plan_epoch(8, 3).expect("plan");
        assert_eq!(plan.len(), 3);
        assert!(plan.iter().all(|slot| slot.kind == TdmCellKind::Data));
    }
}
