//! Constant-rate/TDM pacing primitives.
//!
//! This is a deterministic scheduler used by tests and relay prototypes. It does
//! not sleep or perform I/O; callers use the returned plan to pace real sends.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdmCellKind {
    Data,
    Cover,
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

    pub fn plan_epoch(&self, epoch_slots: u64, data_cells: u64) -> Vec<TdmSlot> {
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
        slots
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tdm_scheduler_fills_idle_slots_with_cover() {
        let s = TdmScheduler::new(Duration::from_millis(5), true);
        let plan = s.plan_epoch(4, 2);
        assert_eq!(plan.len(), 4);
        assert_eq!(plan[0].kind, TdmCellKind::Data);
        assert_eq!(plan[1].kind, TdmCellKind::Data);
        assert_eq!(plan[2].kind, TdmCellKind::Cover);
        assert_eq!(plan[3].send_after, Duration::from_millis(15));
    }

    #[test]
    fn tdm_scheduler_can_skip_cover_when_disabled() {
        let s = TdmScheduler::new(Duration::from_millis(1), false);
        let plan = s.plan_epoch(8, 3);
        assert_eq!(plan.len(), 3);
        assert!(plan.iter().all(|slot| slot.kind == TdmCellKind::Data));
    }
}
