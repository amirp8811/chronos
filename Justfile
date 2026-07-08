# CHRONOS Developer Automation

# Build the documentation book
docs:
    mdbook build book

# Run the full security validation suite
validate:
    bash scripts/validation_pass.sh

# Run the simulation nettest
test-net:
    cargo run -p chronos-nettest

# Run Kani verification (requires kani installed)
verify:
    cargo kani --package chronos-core

# Run fuzzers for 1 minute each
fuzz-all:
    cargo +nightly fuzz run relay_packet -- -max_total_time=60
    cargo +nightly fuzz run stego_ws_frame -- -max_total_time=60
