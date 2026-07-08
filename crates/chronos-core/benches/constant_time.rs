//! Placeholder constant-time variance bench.
//!
//! Full criterion harness is optional; this binary still builds under
//! `cargo test --workspace` / clippy all-targets.

fn main() {
    // Intentionally minimal: real timing benches need dedicated hardware quiet time.
    let _ = (0u64..10_000u64).fold(0u64, |a, b| a.wrapping_add(b));
}
