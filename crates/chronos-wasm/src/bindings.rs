use std::panic;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn chronos_init() {
    // Keep panic hook local; console_error_panic_hook is optional in browsers.
    panic::set_hook(Box::new(|_| {
        // Swallow panics at the FFI boundary; callers use return codes.
    }));
}

/// Safe wrapper used by wasm-bindgen and native tests.
pub fn chronos_process_packet_slice(data: &[u8]) -> i32 {
    panic::catch_unwind(|| {
        if data.is_empty() {
            return -2;
        }
        // In a real implementation, we'd parse the packet here.
        0 // Success
    })
    .unwrap_or(-1)
}

#[wasm_bindgen]
pub fn process_packet_wasm(data: &[u8]) -> i32 {
    chronos_process_packet_slice(data)
}

#[wasm_bindgen]
pub fn chronos_wasm_version() -> String {
    "7.0.0".to_string()
}

#[wasm_bindgen]
pub fn chronos_plan_tdm_slots(slots: u32, data_cells: u32, cover_when_idle: bool) -> u32 {
    use chronos_core::tdm::TdmScheduler;
    use std::time::Duration;
    let s = TdmScheduler::new(Duration::from_millis(1), cover_when_idle);
    s.plan_epoch(slots as u64, data_cells as u64).len() as u32
}

#[wasm_bindgen]
pub fn chronos_secure_cell_self_test(message: &str) -> bool {
    use chronos_core::secure_cell::SecureShardCell;
    let key = [7u8; 32];
    let tag = [1u8; 16];
    match SecureShardCell::encrypt(&key, tag, 1, 0, message.as_bytes()) {
        Ok(cell) => cell
            .decrypt(&key)
            .map(|p| p == message.as_bytes())
            .unwrap_or(false),
        Err(_) => false,
    }
}
