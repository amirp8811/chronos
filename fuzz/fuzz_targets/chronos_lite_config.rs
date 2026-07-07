#![no_main]
use libfuzzer_sys::fuzz_target;
mod cfg { include!("../../crates/chronos-lite/src/config.rs"); }
fuzz_target!(|data: &[u8]| { if let Ok(s)=std::str::from_utf8(data){ let _=cfg::parse_chronos_lite_config(s); } });
