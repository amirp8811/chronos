#![no_main]
#![deny(unsafe_code)]

use chronos_wasm::WebSocketBinaryFrameParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parser = WebSocketBinaryFrameParser::default();
    let _ = parser.parse_binary_frame(data);
});
