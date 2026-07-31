# CHRONOS

[![CI](https://github.com/amirp8811/chronos/actions/workflows/ci.yml/badge.svg)](https://github.com/amirp8811/chronos/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**CHRONOS** is an experimental Rust codebase for studying authenticated relay
packets, hybrid route setup, erasure-coded cells, and traffic-shaping policies.
It is developed as a self-contained prototype with explicit security boundaries.

> ## Prototype warning
> **CHRONOS is not a production anonymity system.** It has not received a
> security audit, a deployment review, or a real-network anonymity evaluation.
> Do not use it to protect people, sensitive communications, or operational
> identities.

## Implementation status

| Area | Status | What that means today |
| --- | --- | --- |
| Authenticated secure cells | Implemented and unit-tested | Fixed-size ChaCha20-Poly1305 cells, replay-window receiver, and stateful sender sequence allocation are exercised in tests. |
| Route layers | Implemented and unit-tested | Per-hop authenticated wrapping, identifier blinding, and bounded replay handling are implemented for local relay tests. The bounded cache trades replay retention for memory limits. |
| Hybrid handshake | Implemented and unit-tested | ML-KEM-768 and X25519 route-secret setup is bound to a pinned, stable relay identity. Deployment key distribution remains out of scope. |
| Proof-of-work admission | Prototype | Address-bound, time-windowed challenges and replay tracking are implemented for the UDP prototype. Operational rate limits and abuse monitoring are not. |
| Directory API | Local prototype | Signed relay-record ingestion is implemented. The TCP line protocol is not a public directory service or consensus system. |
| Erasure coding and mix policy | Prototype models | The codecs and scheduling policy are tested in-process. They are not evidence of network-level anonymity. |
| Send delay | Implemented as a relay option | It delays actual sends only. It does **not** emit cover traffic or provide constant-rate egress. |
| Dataplane, mobile, browser, and directory consensus | Planned or simulated | These areas contain interfaces, experiments, or presentation scaffolds; they are not operational products. |
| Optional onion-header simulation | Simulation only | It is feature-gated and deliberately excluded from the default public API. It is not a production cryptographic construction. |

## Build and validate

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo check -p chronos-core --no-default-features
python3 scripts/static_audit.py
```

For the local experiment harness:

```bash
cargo run -p chronos-nettest
```

## Repository structure

| Path | Purpose |
| --- | --- |
| `crates/chronos-core` | Protocol primitives. Its default build is `std`; a deliberately smaller, audited subset builds without `std`. |
| `crates/chronosd` | Experimental UDP relay daemon. |
| `crates/chronos-dir` | Local authenticated directory-record prototype. |
| `crates/chronos-sys-dataplane` | Hardware-abstraction boundary; the sole crate permitted to contain `unsafe` code. |
| `crates/chronos-lite`, `crates/chronos-wasm` | Client-side experiments and bindings. |
| `apps/` | Clearly labelled interface demonstrations and future client scaffolds. |
| `docs/` | Architecture, protocol, and status notes. |
| `scripts/` | Validation and experiment tooling. |

## Documentation

- [Architecture and status](docs/ARCHITECTURE.md)
- [Implemented protocol notes](docs/PROTOCOLS.md)
- [Security boundaries and validation](SECURITY.md)
- [Repository rules](RULES.md)
- [Contributing](CONTRIBUTING.md)

## License

CHRONOS is licensed under the [Apache License 2.0](LICENSE).
