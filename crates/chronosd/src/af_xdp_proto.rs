//! AF_XDP data-plane prototype boundary.

use crate::dataplane_probe::{DataPlaneMode, choose_data_plane};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AfXdpPlan {
    pub enabled: bool,
    pub umem_frames: usize,
    pub frame_size: usize,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn af_xdp_plan_enables_for_eth_interface() {
        let p = plan_af_xdp("eth0", "af_xdp_zero_copy", 64);
        assert!(p.enabled);
        assert_eq!(p.frame_size, 4096);
        assert!(p.umem_frames > 0);
    }
}
