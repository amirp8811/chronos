//! Minimal wasm-bindgen boundary for the browser package.
//!
//! These exports are intentionally small and deterministic so the web UI can
//! start calling real Rust/WASM functions before the browser transport is fully
//! implemented.

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn chronos_wasm_version() -> String {
    "CHRONOS-WASM v7.0 prototype bindings".to_string()
}

#[wasm_bindgen]
pub fn chronos_plan_tdm_slots(slots: u32, data_cells: u32, cover_when_idle: bool) -> String {
    let scheduler =
        chronos_core::TdmScheduler::new(std::time::Duration::from_millis(1), cover_when_idle);
    let plan = scheduler.plan_epoch(slots as u64, data_cells as u64);
    let data = plan
        .iter()
        .filter(|s| s.kind == chronos_core::TdmCellKind::Data)
        .count();
    let cover = plan
        .iter()
        .filter(|s| s.kind == chronos_core::TdmCellKind::Cover)
        .count();
    format!("slots={} data={} cover={}", plan.len(), data, cover)
}

#[wasm_bindgen]
pub fn chronos_secure_cell_self_test(message: &str) -> bool {
    let key = match chronos_core::derive_link_key(&[0x42u8; 32], &[0x24u8; 16]) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let cell =
        match chronos_core::SecureShardCell::encrypt(&key, [0x24; 16], 1, 0, message.as_bytes()) {
            Ok(cell) => cell,
            Err(_) => return false,
        };
    cell.decrypt(&key)
        .map(|plain| plain == message.as_bytes())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wasm_bindings_return_real_values() {
        assert!(chronos_wasm_version().contains("CHRONOS-WASM"));
        assert_eq!(chronos_plan_tdm_slots(4, 2, true), "slots=4 data=2 cover=2");
        assert!(chronos_secure_cell_self_test("hello wasm"));
    }
}
