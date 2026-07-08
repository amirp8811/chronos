pub mod ring_model;
pub mod af_xdp_proto;
pub mod io_uring_proto;

pub use ring_model::*;
pub use af_xdp_proto::*;
pub use io_uring_proto::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPlaneMode {
    StandardUdp,
    AfXdpPrototype,
    IoUringPrototype,
}

pub struct DataPlaneProbe {
    pub mode: DataPlaneMode,
}

pub fn choose_data_plane(_interface: &str, preferred: &str) -> DataPlaneProbe {
    match preferred {
        "af_xdp" | "af_xdp_zero_copy" => DataPlaneProbe { mode: DataPlaneMode::AfXdpPrototype },
        "io_uring" | "io_uring_sqpoll" => DataPlaneProbe { mode: DataPlaneMode::IoUringPrototype },
        _ => DataPlaneProbe { mode: DataPlaneMode::StandardUdp },
    }
}
pub mod timestamping;
pub mod umem;
