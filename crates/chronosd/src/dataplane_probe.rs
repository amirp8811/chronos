//! Data-plane capability probing primitives.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPlaneMode {
    TokioUdp,
    IoUringPrototype,
    AfXdpPrototype,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPlaneProbeResult {
    pub mode: DataPlaneMode,
    pub reason: String,
}

pub fn choose_data_plane(interface: &str, preferred: &str) -> DataPlaneProbeResult {
    match preferred {
        "af_xdp_zero_copy" if interface.starts_with("eth") || interface.contains("mlx") => {
            DataPlaneProbeResult {
                mode: DataPlaneMode::AfXdpPrototype,
                reason: "preferred AF_XDP-capable interface pattern".to_string(),
            }
        }
        "io_uring_sqpoll" => DataPlaneProbeResult {
            mode: DataPlaneMode::IoUringPrototype,
            reason: "preferred io_uring SQPOLL prototype".to_string(),
        },
        _ => DataPlaneProbeResult {
            mode: DataPlaneMode::TokioUdp,
            reason: "safe Tokio UDP fallback".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chooses_safe_fallback_for_unknown_interface() {
        assert_eq!(
            choose_data_plane("lo", "af_xdp_zero_copy").mode,
            DataPlaneMode::TokioUdp
        );
    }
    #[test]
    fn chooses_af_xdp_prototype_for_eth_preference() {
        assert_eq!(
            choose_data_plane("eth0", "af_xdp_zero_copy").mode,
            DataPlaneMode::AfXdpPrototype
        );
    }
}
