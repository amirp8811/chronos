# CHRONOS: Low-Latency, Multipath Anonymous Communication Fabric

[![CI](https://github.com/amirp8811/chronos/actions/workflows/ci.yml/badge.svg)](https://github.com/amirp8811/chronos/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust MSRV](https://img.shields.io/badge/rust-1.97.1%2B-orange.svg)](https://www.rust-lang.org/)
[![Wiki](https://img.shields.io/badge/docs-wiki-8A2BE2.svg)](https://github.com/amirp8811/chronos/wiki)

CHRONOS is a pure-software anonymous communication fabric aimed at the **anonymity–latency–bandwidth frontier** (strong anonymity, low latency, low *incremental* bandwidth). It uses synchronous TDM pacing, multipath erasure coding, and an explicit **escape architecture** (prepaid isochronous slots + precomputed shuffle + PIR) so strong interactive modes are engineerable without denying classical impossibility results for free-silence mixnets.

See **[docs/HOW_TO_BEAT_THE_TRILEMMA.md](docs/HOW_TO_BEAT_THE_TRILEMMA.md)** for the constructive design and **[docs/TRILEMMA_SOLUTION_PLAN.md](docs/TRILEMMA_SOLUTION_PLAN.md)** for measurement gates (S1–S10).

---

## 🛠 Project Status: Hardened Reference Prototype

This repository is currently a **hardened reference prototype**. While core cryptographic and routing logic is implemented and validated, production deployment at macroscopic scale requires physical hardware staging and site-specific NIC drivers.

**Current Capabilities**:
- **Post-Quantum Resilience**: ML-KEM-768 + X25519 hybrid handshakes.
- **High-Throughput Dataplane**: `io_uring` and `AF_XDP` abstractions for 10Gbps+ line-rate targets.
- **Synchronous Mixing**: TDM-based packet flushing to defeat Global Passive Adversaries (GPA).
- **Hardened Isolation**: Strictly decoupled `no_std` cryptographic core and isolated hardware HAL.

**Maturity:** Cryptographic primitives, protocol wire formats, fuzzing, and the local
`chronos-nettest` simulation are implemented and tested. The kernel-bypass dataplane
(`AF_XDP` / `io_uring`), the multi-peer relay service, and directory consensus are
currently *simulated / prototype* — not yet staged on real hardware. **Do not rely on
CHRONOS for real-world anonymity yet.** Open work is tracked in GitHub Issues and
`docs/FULL_TODO.md`; see `RULES.md` for how we keep the project honest and consistent.

---

## 🚀 Quick Start

### Build & Test
```bash
# Build the workspace
cargo build --workspace

# Run security-hardened validation suite
cargo test --workspace

# Run static audit (Enforces #![deny(unsafe_code)] outside HAL)
python3 scripts/static_audit.py
```

### Local Simulation
Run a local 2-hop relay chain simulation:
```bash
cargo run -p chronos-nettest
```

---

## 🏗 Repository Structure

- `crates/chronos-core`: The `no_std` cryptographic engine.
- `crates/chronos-sys-dataplane`: The isolated HAL for kernel-bypass networking.
- `crates/chronosd`: High-performance relay daemon.
- `crates/chronos-dir`: Decentralized directory and consensus.
- `crates/chronos-lite`: Residential/ARM client runtime.
- `crates/chronos-wasm`: Browser runtime with FFI panic barriers.
- `docs/`: Trilemma strategy and escape architecture.

---

## 📚 Documentation

- [docs/HOW_TO_BEAT_THE_TRILEMMA.md](docs/HOW_TO_BEAT_THE_TRILEMMA.md) — **How CHRONOS beats the trilemma** (X1 slot / X2 org pod / X3 open stream).
- [docs/TRILEMMA_SOLUTION_PLAN.md](docs/TRILEMMA_SOLUTION_PLAN.md) — Success criteria, pillars, experiment plan.
- [docs/README.md](docs/README.md) — Documentation index.
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — Design, wire formats, implementation status.
- [SECURITY.md](SECURITY.md) — Threat notes, anonymity parameters, validation gates.
- [CONTRIBUTING.md](CONTRIBUTING.md) — Governance and how to help.

---

## ⚖️ License
CHRONOS is licensed under the **Apache License 2.0**.
