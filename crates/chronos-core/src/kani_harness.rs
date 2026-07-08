#[cfg(kani)]
mod verification {
    use crate::sphinx::*;

    #[kani::proof]
    fn prove_sphinx_header_unwrapping_is_safe() {
        // Symbolic input for header
        let header: [u8; SPHINX_HEADER_SIZE] = kani::any();
        let key: [u8; 32] = kani::any();

        // Ensure no panics occur during unwrapping logic
        let _ = unwrap_header_layer(&header, &key);
    }
}
