use std::os::unix::io::AsRawFd;

pub fn enable_hardware_timestamping<S: AsRawFd>(socket: &S) -> std::io::Result<()> {
    // This is a platform-specific syscall wrapper for SO_TIMESTAMPING.
    // In production, this targets the NIC driver's hardware clock.
    #[cfg(target_os = "linux")]
    {
        use libc::{setsockopt, SOL_SOCKET, SO_TIMESTAMPING};
        // SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE etc.
        let flags: i32 = 0x01 | 0x02 | 0x04;
        let fd = socket.as_raw_fd();
        let res = unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_TIMESTAMPING,
                &flags as *const _ as *const _,
                std::mem::size_of::<i32>() as u32,
            )
        };
        if res == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
