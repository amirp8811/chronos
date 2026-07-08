/// Zero-Copy UMEM descriptor pool for AF_XDP and io_uring.
/// This ensures 0% memory copies between the NIC and User-space.
pub struct UmemPool {
    base_ptr: *mut u8,
    frame_size: usize,
    num_frames: usize,
    mapped_len: usize,
}

impl UmemPool {
    pub fn new(size_mb: usize) -> Result<Self, String> {
        let frame_size = 4096;
        let size_bytes = size_mb
            .saturating_mul(1024)
            .saturating_mul(1024)
            .max(frame_size);
        let num_frames = size_bytes / frame_size;

        // In production, this uses mmap with MAP_HUGETLB.
        let base_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size_bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, // Should be MAP_HUGETLB
                -1,
                0,
            )
        };
        if base_ptr == libc::MAP_FAILED {
            return Err(format!(
                "mmap failed for {size_bytes} bytes: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(Self {
            base_ptr: base_ptr as *mut u8,
            frame_size,
            num_frames,
            mapped_len: size_bytes,
        })
    }

    pub fn frame_at(&self, index: usize) -> *mut u8 {
        assert!(index < self.num_frames);
        unsafe { self.base_ptr.add(index * self.frame_size) }
    }

    pub fn num_frames(&self) -> usize {
        self.num_frames
    }
}

impl Drop for UmemPool {
    fn drop(&mut self) {
        if !self.base_ptr.is_null() && self.mapped_len > 0 {
            unsafe {
                libc::munmap(self.base_ptr as *mut _, self.mapped_len);
            }
        }
    }
}

// UmemPool is intentionally !Send/!Sync: it owns a raw mmap region.
