# CHRONOS Architecture & Implementation Roadmap

This document provides a deep dive into the technical design and the path to production for CHRONOS v7.0.

---

## 1. Architectural Vision
CHRONOS solves the Anonymity Trilemma by moving away from asynchronous TCP circuits. It utilizes:
- **Zero-Copy Data-Plane**: Sub-millisecond packet processing via `AF_XDP` and `io_uring`.
- **Multipath Erasure Coding**: (16,10) Reed-Solomon sharding to eliminate Head-of-Line (HoL) blocking.
- **Synchronous TDM Mixing**: Constant-rate packet flushing to decouple ingress/egress timing.

---

## 2. Protocol Specifications

### **CHR7 (Secure Cell)**
Fixed 1,280-byte envelope.
- `CHR7` Magic | Version | Flags | Payload Len | Route Tag | IV | Ciphertext (944B) | MAC (16B).

### **CHS7 (Handshake)**
Hybrid PQC Key Exchange combining **ML-KEM-768** and **X25519**. Includes memory-bounded PoW for Anti-DoS.

### **CRP7 (Relay Packet)**
Multi-type wire format: `Hello`, `Shard`, `Ack`, `Error`, `Route`, `Data`.

### **RTE7 (Route Layer)**
Onion-wrapped commands with per-hop ChaCha20-Poly1305 and packet-id blinding.

---

## 3. Implementation Status Matrix

| Feature | Status | Note |
| :--- | :--- | :--- |
| **Sphinx Routing** | **[Implemented]** | Post-Quantum hybrid (ML-KEM/X25519). |
| **Erasure Coding** | **[Implemented]** | (16,10) GF(2^8) Reed-Solomon. |
| **Dataplane HAL** | **[Implemented]** | Isolated crate with Acquire/Release fences. |
| **no_std Core** | **[Partial]** | `std` gated; needs clock trait migration. |
| **AF_XDP/io_uring**| **[Partial]** | Abstractions ready; needs native-driver validation. |
| **PIR Storage** | **[Prototype]** | Threshold DPF-PIR oblivious dead-drop. |
| **BFT Consensus** | **[Prototype]** | Regional BLS Quorum logic. |

---

## 4. Production Roadmap

### Tier 1: Logic & Hardening (Completed)
- [x] Sphinx & Galois Math.
- [x] Hardened FFI Panic Barriers.
- [x] Memory-Bounded PoW (Sliding-window epoch).

### Tier 2: Performance & Audit (In Progress)
- [x] Isolated HAL for kernel-bypass I/O.
- [x] High-sample statistical leak auditing.
- [ ] Formal Verification of Sphinx header unwrapping.

### Tier 3: Global Deployment (Planned)
- [ ] Native `AF_XDP` driver-mode integration.
- [ ] Hardware-accelerated SIMD bitonic sorting.
- [ ] Regional BLS Quorum Mesh deployment.
