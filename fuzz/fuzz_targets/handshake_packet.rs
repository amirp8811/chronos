#![no_main]
#![deny(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = chronos_core::HandshakePacket::decode(data);
});
