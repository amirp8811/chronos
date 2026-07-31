# CHRONOS

[![CI](https://github.com/amirp8811/chronos/actions/workflows/ci.yml/badge.svg)](https://github.com/amirp8811/chronos/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust MSRV](https://img.shields.io/badge/rust-1.97.1%2B-orange.svg)](https://www.rust-lang.org/)

**CHRONOS** is a Rust implementation of a low-latency, multipath anonymous
communication network. It combines synchronous (TDM) packet mixing, multipath
erasure coding, and an isolated `no_std` cryptographic core to provide strong
anonymity with interactive latencies.

> **Status:** Hardened reference prototype. Core cryptographic and routing
> logic is implemented and tested. The kernel-bypass dataplane, multi-peer relay
> service, and directory consensus are currently simulated and have not yet been
> validated on real hardware. CHRONOS is not yet a production anonymity system.

## Features

- **Synchronous TDM mixing** — constant-rate packet flushing to decouple
  ingress/egress timing from content.
- **Multipath erasure coding** — (16,10) Reed–Solomon sharding to remove
  head-of-line blocking.
- **Post-quantum handshakes** — ML-KEM-768 + X25519 hybrid key exchange.
- **Isolated `no_std` core** — cryptographic primitives in a `no_std` crate,
  with `unsafe` confined to the dataplane HAL.
- **Adaptive mix policy** — selectable anonymity/latency profiles with
  cover-traffic backfill.

## Quick Start

### Build & test

```bash
cargo build --workspace
cargo test --workspace
python3 scripts/static_audit.py
```

### Local simulation

Run a local 2-hop relay-chain simulation:

```bash
cargo run -p chronos-nettest
```

## Repository structure

| Path | Purpose |
| --- | --- |
| `crates/chronos-core` | `no_std` cryptographic engine. |
| `crates/chronos-sys-dataplane` | Isolated HAL for kernel-bypass networking. |
| `crates/chronosd` | Relay daemon. |
| `crates/chronos-dir` | Directory and consensus. |
| `crates/chronos-lite` | Residential/ARM client runtime. |
| `crates/chronos-wasm` | Browser runtime with FFI panic barriers. |
| `docs/` | Architecture and protocol reference. |
| `scripts/` | Build, audit, and experiment tooling. |

## Documentation

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — design, wire formats, and implementation status.
- [PROTOCOLS.md](docs/PROTOCOLS.md) — wire-format and protocol identifiers.
- [SECURITY.md](SECURITY.md) — threat model, anonymity parameters, and validation gates.
- [CONTRIBUTING.md](CONTRIBUTING.md) — governance and how to help.
- [RULES.md](RULES.md) — repository conventions and honesty policy.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community standards.

## License

CHRONOS is licensed under the [Apache License 2.0](LICENSE).
