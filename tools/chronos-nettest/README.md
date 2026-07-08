# chronos-nettest

Local experiment harness for CHRONOS mix policy, FEC comparison, and traffic-analysis metrics.

## Modes

Set `CHRONOS_NETTEST_MODE`:

| Mode | Purpose |
| --- | --- |
| `smoke` (default) | Quick adaptive-mix + fountain self-check |
| `mix-sweep` | CSV sweep of profile × inter-arrival rate (MI, latency CDF, bandwidth) |
| `fec-compare` | Reed-Solomon (16,10) vs fountain progressive recovery overhead |
| `leak-audit` | Larger mix simulation with MI / entropy / latency percentiles |

Optional: `CHRONOS_NETTEST_PACKETS` (default depends on mode).

## Examples

```bash
# Smoke
cargo run -p chronos-nettest

# K / latency surface
CHRONOS_NETTEST_MODE=mix-sweep CHRONOS_NETTEST_PACKETS=128 cargo run -p chronos-nettest

# FEC overhead comparison
CHRONOS_NETTEST_MODE=fec-compare cargo run -p chronos-nettest

# Leak-oriented audit
CHRONOS_NETTEST_MODE=leak-audit CHRONOS_NETTEST_PACKETS=2000 cargo run -p chronos-nettest
```

Metrics are defined in `chronos_core::anonymity_metrics` and do **not** claim production anonymity; they are for relative, reproducible experiments.
