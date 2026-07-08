# CHRONOS Security, Anonymity & Validation

This document outlines the security invariants, anonymity parameters, and the 4-gate validation architecture.

---

## 1. Security Invariants
1. **Timing Indistinguishability**: Synchronous mixing and constant-rate pacing decouple timing.
2. **Memory Isolation**: Physical separation of the cryptographic core and the unsafe HAL.
3. **Panic Safety**: All WASM/Mobile entry points are protected by `catch_unwind` barriers.

---

## 2. Anonymity Parameters (v7.0)
- **Mixing Threshold (K)**: 25,000 packets.
- **Max Batch Latency**: 50ms (Adaptive flushing via `mix_policy`).
- **Differential Privacy**: Epsilon ($\epsilon$) targeted at 0.1 per epoch with Laplace noise.

---

## 3. Validation Architecture (The 4 Gates)

### Gate 1: Logic & Correctness
- Functional Tests: `cargo test`
- Logic Fuzzing: `cargo fuzz run relay_packet`

### Gate 2: Lifecycle & Concurrency
- `loom` tests for ring atomics in the HAL.
- `cargo fuzz run dataplane_lifecycle`.

### Gate 3: Virtualized Topology
- Namespace/veth simulation with bursty impairment via `setup_virtual_topology.sh`.

### Gate 4: Macroscopic Leak Auditing
- Statistical analysis of 100,000+ packet traces.
- Metrics: **Mutual Information (MI)**, **KL Divergence**, and **Egress Entropy**.

---

## 4. Warrant Canary
CHRONOS maintainers have received:
1. **NO** secret subpoenas.
2. **NO** National Security Letters (NSLs).
3. **NO** forced backdoor installations.

*Last Updated: 2026-07-08*

---

## 5. Responsible Disclosure
Vulnerabilities should be reported privately to `amirp8811@gmail.com`.

---

## 6. Measurable Experiment Hooks (Prototype)

The following are **engineering metrics**, not anonymity proofs. They live in
`chronos_core::anonymity_metrics` and are exercised by `chronos-nettest`:

| Metric | Meaning | How to run |
| --- | --- | --- |
| Mutual information (timing) | Coarse GPA correlator between ingress/egress timestamps | `CHRONOS_NETTEST_MODE=leak-audit` |
| Egress interval entropy | Diversity of inter-departure times | mix-sweep / leak-audit |
| KL vs constant-rate | Distance of egress timing from ideal constant pacing | mix-sweep |
| Latency CDF (p50/p95/p99) | End-to-end hold time under adaptive mix profiles | mix-sweep |
| Bandwidth multiplier | `(real + cover) / real` bytes or packets | mix-sweep / smoke |

### Adversary scopes currently modeled in software

1. **Local passive observer** on a single hop: sees arrival/departure times and lengths.
2. **Simulated mix batching**: adaptive K / max-wait / cover backfill (`MixProfile::{Fast,Normal,HighAnonymity}`).
3. **Not yet modeled**: multi-hop GPA with colluding relays, active confirmation attacks, or directory query leakage.

Reproducible sweeps:

```bash
bash scripts/run_mix_experiments.sh
```

---

## 7. Trilemma strategy documents

- Escape architecture (all-three product design): [`docs/HOW_TO_BEAT_THE_TRILEMMA.md`](docs/HOW_TO_BEAT_THE_TRILEMMA.md)
- Measurement plan and S1–S10 gates: [`docs/TRILEMMA_SOLUTION_PLAN.md`](docs/TRILEMMA_SOLUTION_PLAN.md)

