use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PowValidator {
    current_window_epoch: u64,
    spent_nonces: HashSet<(SocketAddr, u32)>,
    window_ms: u64,
}

impl PowValidator {
    pub fn new(window_ms: u64) -> Self {
        Self {
            current_window_epoch: 0,
            spent_nonces: HashSet::new(),
            window_ms,
        }
    }

    pub fn validate(&mut self, source: SocketAddr, nonce: u32, timestamp_ms: u64) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        
        // Step 1: Enforce strict temporal horizon (e.g., 30s drift)
        if (now as i64 - timestamp_ms as i64).abs() > self.window_ms as i64 {
            return false;
        }

        // Step 2: Clear historical state if we cross an epoch boundary
        let epoch = now / self.window_ms;
        if epoch > self.current_window_epoch {
            self.spent_nonces.clear();
            self.current_window_epoch = epoch;
        }

        // Step 3: Check and commit nonce
        // insert returns false if the item was already present
        self.spent_nonces.insert((source, nonce))
    }
}
