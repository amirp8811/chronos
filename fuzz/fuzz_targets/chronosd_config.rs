#![no_main]
use libfuzzer_sys::fuzz_target;
mod cfg { include!("../../crates/chronosd/src/config.rs"); }
fuzz_target!(|data: &[u8]| { if let Ok(s)=std::str::from_utf8(data){ let _=cfg::parse_chronosd_config(s); } });
