# CHRONOS Architecture and Status

CHRONOS separates protocol experiments from operational claims. A module being
present in this repository does not mean it is ready for deployment. The status
labels below are the authoritative description of current maturity.

> **Deployment boundary:** CHRONOS is a research prototype, not a production
> anonymity service. Its code and tests do not establish a real-world anonymity
> guarantee.

## Implemented protocol path

The local test path is composed of the following components:

1. **CHS7 handshake** — a server hello carries X25519 and ML-KEM-768 public
   material signed by a stable Ed25519 relay identity. Clients must compare that
   identity with an expected identity before creating a key share.
2. **RTE7 route layer** — a sender wraps a payload once for each hop using
   ChaCha20-Poly1305. Each relay authenticates its layer before recording replay
   state, then either forwards a blinded packet identifier or emits a local
   payload.
3. **CRP7 relay envelope** — the UDP prototype carries route, data, shard,
   acknowledgement, and error packets in a compact local envelope.
4. **CHR7 secure cell** — fixed-size application cells authenticate metadata and
   padded payloads. `SecureCellSender` owns monotonically increasing sequence
   values for one key and route-tag domain.
5. **SHARD-Stream codec** — a single in-memory block can be split into ten data
   and six recovery shards. This is a codec, not a multipath transport service.

## Explicitly bounded behaviour

### Route replay cache

Route replay entries are added only after successful authentication. The cache
is bounded by count and time-to-live. When full, it evicts the oldest entry;
that is a memory-safety trade-off, not a permanent replay guarantee. A relay
operator must size and partition this cache for the traffic and trust boundary
of a future deployment.

### Proof-of-work admission

The experimental UDP relay can issue stateless challenges bound to relay ID,
client address, difficulty, time window, and a configured server secret. A
challenge uses the current window; verification also accepts one prior window
to tolerate ordinary delay. The daemon refuses to enable this feature unless a
non-zero 32-byte secret is supplied through its configured environment variable.
The implementation does not yet provide operational abuse detection or a
production admission policy.

### Send delay

`chronosd` can delay each actual outbound send. This option is accurately named
`send_delay_ms`: it does not run an independent slot scheduler, send cover
cells, or maintain constant-rate egress. It must not be interpreted as timing
indistinguishability.

## Status by subsystem

| Subsystem | Status | Boundary |
| --- | --- | --- |
| Secure cells, replay windows, route layers | Implemented and tested | Local protocol primitives only; no external audit. |
| Stable-identity handshake | Implemented and tested | Expected relay identities must be obtained by a deployment-specific trusted mechanism. |
| Signed directory records | Implemented local API | The line protocol is local-only; consensus, authorization policy, and durable operational administration are not implemented. |
| `chronos-core` no-`std` subset | Implemented and checked | Only allocation-friendly cryptographic/math modules are compiled without `std`; runtime services remain `std`-only. |
| Erasure codec and adaptive mixing policy | Prototype | In-process algorithms and measurements, not network protection claims. |
| Dataplane abstraction | Prototype interface | It is not a validated high-performance networking path. |
| Client applications | Planned scaffolds | No supported mobile or browser client exists. |
| Optional onion-header simulation | Simulation | It demonstrates header mutation only and is feature-gated; it is not part of the default API. |

## Optional simulation feature

The `simulation` feature contains `SphinxSimulationProcessor` and
`SimulationOnionCell`. It is intentionally named and gated as a simulation. It
uses a simple SHA-256-derived XOR header mutation and checksum for deterministic
demonstrations. It has no authenticated per-hop security property and must not
be used for traffic.

## Validation posture

The repository CI checks formatting, warnings, workspace tests with the locked
dependency graph, the no-`std` core build, and local static policy checks.
Fuzzing and external cryptographic review are valuable next steps, but neither
has been completed as a release gate.
