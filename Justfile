# CHRONOS Developer Automation

# Run the full security validation suite
validate:
    bash scripts/validation_pass.sh

# Run the simulation nettest (smoke)
test-net:
    cargo run -p chronos-nettest

# Adaptive mix K/latency sweep (CSV)
mix-sweep:
    CHRONOS_NETTEST_MODE=mix-sweep cargo run -p chronos-nettest

# FEC RS vs fountain comparison
fec-compare:
    CHRONOS_NETTEST_MODE=fec-compare cargo run -p chronos-nettest

# Larger leak-audit style metrics run
leak-audit:
    CHRONOS_NETTEST_MODE=leak-audit CHRONOS_NETTEST_PACKETS=2000 cargo run -p chronos-nettest

# Bundle mix + FEC + leak experiments into artifacts/
experiments:
    bash scripts/run_mix_experiments.sh

# Run Kani verification (requires kani installed)
verify:
    cargo kani --package chronos-core

# Run fuzzers for 1 minute each
fuzz-all:
    cargo +nightly fuzz run relay_packet -- -max_total_time=60
    cargo +nightly fuzz run stego_ws_frame -- -max_total_time=60
