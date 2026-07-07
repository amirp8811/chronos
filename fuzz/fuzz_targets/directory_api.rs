#![no_main]
use libfuzzer_sys::fuzz_target;
mod store { include!("../../crates/chronos-dir/src/store.rs"); }
mod api { include!("../../crates/chronos-dir/src/api.rs"); }
fuzz_target!(|data: &[u8]| { if let Ok(s)=std::str::from_utf8(data){ let mut st=store::DirectoryStore::new(); let _=api::handle_command(&mut st, s); } });
