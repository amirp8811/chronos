# CHRONOS: Low-Latency, Multipath Anonymous Communication Fabric

CHRONOS is a world-class, pure-software anonymous communication fabric engineered to overcome the **Anonymity Trilemma** (Strong Anonymity, Low Latency, and Low Bandwidth Overhead). It operates as a synchronous, Time-Division Multiplexed (TDM) and constant-rate paced multipath erasure network.

---

## 🛠 Project Status: Hardened Reference Prototype

This repository is currently a **hardened reference prototype**. While core cryptographic and routing logic is implemented and validated, production deployment at macroscopic scale requires physical hardware staging and site-specific NIC drivers.

**Current Capabilities**:
- **Post-Quantum Resilience**: ML-KEM-768 + X25519 hybrid handshakes.
- **High-Throughput Dataplane**: `io_uring` and `AF_XDP` abstractions for 10Gbps+ line-rate targets.
- **Synchronous Mixing**: TDM-based packet flushing to defeat Global Passive Adversaries (GPA).
- **Hardened Isolation**: Strictly decoupled `no_std` cryptographic core and isolated hardware HAL.

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

---

## 📚 Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Deep dive into design, wire formats, and implementation status.
- [SECURITY.md](SECURITY.md) - Threat model, anonymity parameters, and validation architecture.
- [CONTRIBUTING.md](CONTRIBUTING.md) - Governance, Code of Conduct, and how to help.

---

## ⚖️ License
CHRONOS is licensed under the **Apache License 2.0**.
