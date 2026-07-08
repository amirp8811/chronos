use std::fs;
use std::path::Path;

pub struct CacheResctrl {
    group_name: String,
}

impl CacheResctrl {
    pub fn new(name: &str) -> Self {
        Self {
            group_name: name.to_string(),
        }
    }

    pub fn lock_l3_cache(&self, mask: &str) -> std::io::Result<()> {
        let base_path = Path::new("/sys/fs/resctrl");
        if !base_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "resctrl fs not mounted",
            ));
        }

        let group_path = base_path.join(&self.group_name);
        if !group_path.exists() {
            fs::create_dir(&group_path)?;
        }

        // Write the bitmask for L3 cache ways
        fs::write(group_path.join("schemata"), format!("L3:0={mask}"))?;

        // To assign a process: fs::write(group_path.join("tasks"), pid.to_string())?;
        Ok(())
    }
}

/// Compatibility wrapper used by `chronosd` main for optional CAT isolation.
pub struct L3CacheLocker {
    slice_mb: f64,
    inner: CacheResctrl,
}

impl L3CacheLocker {
    pub fn new(slice_mb: f64) -> Self {
        Self {
            slice_mb,
            inner: CacheResctrl::new("chronosd"),
        }
    }

    pub fn lock_to_current_thread(&self) -> Result<(), String> {
        // Map slice size to a coarse hex mask for documentation/demo only.
        let ways = ((self.slice_mb / 2.0).ceil() as u32).clamp(1, 16);
        let mask = format!("{:x}", (1u32 << ways) - 1);
        self.inner.lock_l3_cache(&mask).map_err(|e| e.to_string())
    }
}
