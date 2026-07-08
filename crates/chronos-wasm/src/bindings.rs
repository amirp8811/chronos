use wasm_bindgen::prelude::*;
use std::panic;

#[wasm_bindgen]
pub fn chronos_init() {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
}

#[no_mangle]
pub extern "C" fn chronos_process_packet(ptr: *mut u8, len: usize) -> i32 {
    panic::catch_unwind(|| {
        if ptr.is_null() || len == 0 {
            return -2;
        }
        // In a real implementation, we'd parse the packet here.
        0 // Success
    })
    .unwrap_or_else(|_| {
        // Log locally if possible, then return error code
        -1 // Panic caught
    })
}

#[wasm_bindgen]
pub fn process_packet_wasm(data: &[u8]) -> i32 {
    chronos_process_packet(data.as_ptr() as *mut u8, data.len())
}
