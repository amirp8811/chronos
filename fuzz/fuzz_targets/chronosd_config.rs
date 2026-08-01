#![no_main]
#![deny(unsafe_code)]

use chronosd::config::parse_chronosd_config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_chronosd_config(text);
    }
});
