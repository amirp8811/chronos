#![no_main]
#![deny(unsafe_code)]

use chronos_core::{APP_CELL_PAYLOAD_SIZE, SecureShardCell};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Normalize arbitrary fuzzer input into the fixed-width wire representation
    // so every execution reaches the real secure-cell parser.
    let mut cell_bytes = [0u8; APP_CELL_PAYLOAD_SIZE];
    let copy_len = data.len().min(APP_CELL_PAYLOAD_SIZE);
    cell_bytes[..copy_len].copy_from_slice(&data[..copy_len]);
    let _ = SecureShardCell::from_app_cell_bytes(&cell_bytes);
});
