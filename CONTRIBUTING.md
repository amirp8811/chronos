# Contributing to CHRONOS

We welcome contributions from systems engineers, cryptographers, protocol researchers, and developers who share our commitment to overcoming the Das et al. (2018) Anonymity Trilemma.

## Engineering & Architectural Rigor
1. Memory Safety & High-Performance Execution: All core data-plane routing, cryptography, and framing primitives must be written in Rust (2024 Edition). Never allocate heap memory (Box, Vec, String) on hot routing paths?utilize pre-mapped 4 KB hugepage descriptors and zero-copy io_uring direct buffers.
2. Preservation of the Anonymity Trilemma: Any contribution that introduces variable bandwidth bursts (O(N) dummy broadcasts) or asynchronous event-driven timing leaks without constant-rate cover noise will be rejected.
3. Post-Quantum Cryptography Compliance: All new cryptographic protocols must align with NIST Post-Quantum Cryptography standards (ML-KEM-768 + X25519 hybrid ECDH + ChaCha20-Poly1305).
