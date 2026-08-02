# chronos-nettest

Local experiment harness for CHRONOS protocol primitives and relay scenarios.
Reports are generated from local code execution; they are not network benchmarks
or anonymity proofs.

## Signed-directory UDP scenarios

Each scenario accepts `--out <path>` to write a JSON report. When `--out` is
omitted, it writes the report to standard output.

### Three-hop local delivery

Creates three signed relay records, retrieves and pins each relay identity,
derives one CHS7 route secret per relay, starts three localhost UDP relays,
builds an authenticated three-hop route, and verifies byte-for-byte receiver
delivery.

Handshake messages are executed in-process for this local harness; route packet
forwarding still uses real localhost UDP relays.

```bash
cargo run -p chronos-nettest -- --scenario three-hop-local --messages 10 --out reports/three-hop-local.json
```

### Replay rejection

Sends one valid route through a localhost relay, then resends the identical
inner route. The report confirms replay rejection and absence of a second
delivery.

```bash
cargo run -p chronos-nettest -- --scenario replay-negative --out reports/replay-negative.json
```

### Directory validation negatives

Exercises the directory command path and verifies default rejection of unsigned,
bad-signature, zero-key-material, and expired relay records.

```bash
cargo run -p chronos-nettest -- --scenario directory-negative --out reports/directory-negative.json
```

`--messages N` sends N authenticated route packets through the same persistent
three-hop circuit. The report includes mean, minimum, p50, p95, p99, and maximum
measured local delivery latency across those messages. It also reports delivery
ratio and actual per-relay processing counters. The three CHS7 handshakes and
their derived route secrets are established once per scenario run.

## Legacy local models

The existing local codec and mix-policy experiments remain available through
`CHRONOS_NETTEST_MODE`:

| Mode | Purpose |
| --- | --- |
| `smoke` | Codec and adaptive-policy self-check. |
| `mix-sweep` | Local profile and inter-arrival sweep. |
| `fec-compare` | Recovery-overhead experiment for repository codecs. |
| `leak-audit` | Simulated timing, entropy, and latency experiment. |

```bash
cargo run -p chronos-nettest
CHRONOS_NETTEST_MODE=mix-sweep CHRONOS_NETTEST_PACKETS=128 cargo run -p chronos-nettest
```

All scenarios are local prototype experiments. They do not establish production
anonymity or deploy a relay network.
