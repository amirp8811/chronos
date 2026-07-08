#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { if data.len() == chronos_core::APP_CELL_PAYLOAD_SIZE { let mut b=[0u8; chronos_core::APP_CELL_PAYLOAD_SIZE]; b.copy_from_slice(data); let _=chronos_core::SecureShardCell::from_app_cell_bytes(&b); } });
