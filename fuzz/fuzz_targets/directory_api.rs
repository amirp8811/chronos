#![no_main]
#![deny(unsafe_code)]

use chronos_dir::api::{DirectoryApiConfig, handle_command};
use chronos_dir::store::DirectoryStore;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let mut store = DirectoryStore::new();
        let config = DirectoryApiConfig::default();
        let _ = handle_command(&mut store, line, &config, 1_700_000_000);
    }
});
