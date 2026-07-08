#![no_main]

use chronos_wasm::stego_ws::SteganographicWebSocketEngine;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let engine = SteganographicWebSocketEngine::new();
    let _ = engine.parse_stego_ws_frame(data);
});
