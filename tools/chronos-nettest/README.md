# chronos-nettest

Local experiment harness for CHRONOS codec and mixing-policy models. Its output
is useful for repeatable engineering experiments; it is not a network benchmark
or an anonymity proof.

## Modes

Set `CHRONOS_NETTEST_MODE`:

| Mode | Purpose |
| --- | --- |
| `smoke` | Small codec and adaptive-policy self-check. |
| `mix-sweep` | Local profile and inter-arrival sweep producing timing and latency data. |
| `fec-compare` | Local recovery-overhead experiment for repository codecs. |
| `leak-audit` | Larger simulated timing, entropy, and latency experiment. |

`CHRONOS_NETTEST_PACKETS` optionally selects the simulated packet count.

```bash
cargo run -p chronos-nettest
CHRONOS_NETTEST_MODE=mix-sweep CHRONOS_NETTEST_PACKETS=128 cargo run -p chronos-nettest
CHRONOS_NETTEST_MODE=leak-audit CHRONOS_NETTEST_PACKETS=2000 cargo run -p chronos-nettest
```

Results apply to the selected in-process model and inputs only. They do not
measure a deployed relay network or establish a privacy property.
