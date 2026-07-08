//! io_uring data-plane prototype boundary.

use crate::dataplane_probe::{DataPlaneMode, choose_data_plane};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoUringPlan {
    pub enabled: bool,
    pub registered_buffers: usize,
    pub sqpoll: bool,
}

pub fn plan_io_uring(interface: &str, preferred_engine: &str, buffers: usize) -> IoUringPlan {
    let probe = choose_data_plane(interface, preferred_engine);
    IoUringPlan {
        enabled: probe.mode == DataPlaneMode::IoUringPrototype,
        registered_buffers: if buffers == 0 { 1 } else { buffers },
        sqpoll: probe.mode == DataPlaneMode::IoUringPrototype,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn io_uring_plan_enables_for_preference() {
        let p = plan_io_uring("lo", "io_uring_sqpoll", 64);
        assert!(p.enabled);
        assert!(p.sqpoll);
        assert_eq!(p.registered_buffers, 64);
    }
}
