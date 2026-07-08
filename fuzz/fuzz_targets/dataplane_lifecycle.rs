#![no_main]

use chronos_sys_dataplane::DescriptorLifecycle;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|ops: &[u8]| {
    let d = DescriptorLifecycle::new();
    for op in ops {
        match op % 3 {
            0 => {
                let _ = d.claim_for_rx();
            }
            1 => {
                let _ = d.submit_for_tx();
            }
            _ => {
                let _ = d.complete_tx();
            }
        }
    }
});
