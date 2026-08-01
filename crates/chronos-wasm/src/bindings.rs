use std::panic;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn chronos_init() {
    // Keep panic handling inside the FFI boundary; exported functions return
    // explicit status values instead of unwinding into a host runtime.
    panic::set_hook(Box::new(|_| {}));
}

/// Validates a real CRP7 relay packet without performing network I/O.
pub fn chronos_validate_relay_packet_slice(data: &[u8]) -> i32 {
    panic::catch_unwind(|| match chronos_core::RelayPacket::decode(data) {
        Ok(_) => 0,
        Err(_) => -2,
    })
    .unwrap_or(-1)
}

#[wasm_bindgen]
pub fn validate_relay_packet_wasm(data: &[u8]) -> i32 {
    chronos_validate_relay_packet_slice(data)
}

#[wasm_bindgen]
pub fn chronos_wasm_version() -> String {
    "7.0.0".to_string()
}

/// Returns the number of slots in a locally computed scheduling model.
#[wasm_bindgen]
pub fn chronos_plan_simulated_slots(slots: u32, data_cells: u32, cover_when_idle: bool) -> u32 {
    use chronos_core::tdm::TdmScheduler;
    use std::time::Duration;
    TdmScheduler::new(Duration::from_millis(1), cover_when_idle)
        .plan_epoch(u64::from(slots), u64::from(data_cells))
        .len() as u32
}

/// Runs a local authenticated-cell roundtrip self-test.
#[wasm_bindgen]
pub fn chronos_secure_cell_self_test(message: &str) -> bool {
    use chronos_core::secure_cell::SecureCellSender;
    let key = [7u8; 32];
    let route_tag = [1u8; 16];
    let mut sender = SecureCellSender::new(key, route_tag);
    match sender.seal(0, message.as_bytes()) {
        Ok(cell) => cell
            .decrypt(&key)
            .map(|plaintext| plaintext == message.as_bytes())
            .unwrap_or(false),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_packet_validation_uses_real_decoder() {
        assert_eq!(chronos_validate_relay_packet_slice(b"not a packet"), -2);
    }
}
