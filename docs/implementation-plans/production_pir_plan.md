# Production-grade PIR implementation plan

## Goal

Replace the current educational two-server XOR point-function prototype with a production-grade private information retrieval system with clearly stated privacy assumptions, consistency guarantees, and reproducible tests.

## Current state

Implemented today:

- DPF snapshot persistence in `chronos-lite`.
- `DpfQueryRequest` / `DpfQueryResponse` scaffolding.
- Two-server XOR point-function share prototype.
- Two-server PIR-style evaluation with snapshot-root mismatch rejection.

Not implemented:

- A reviewed DPF/PIR construction.
- Formal privacy proof or model.
- Multi-server threat model beyond local tests.
- Efficient large-database query evaluation.
- Persistent production storage engine.
- Network protocol for PIR query fanout.

## Recommended architecture

Use a staged approach:

1. Define a threat model.
2. Implement a reviewed computational DPF construction or adopt an audited crate.
3. Build a multi-server query protocol around it.
4. Add consistency proofs.
5. Add performance optimizations.
6. Add formal-ish documentation and external review.

## Stage 1 — Threat model and protocol document

Create `docs/protocols/pir.md`.

Specify:

- Number of servers: 2, 3, or 4+.
- Privacy threshold: e.g. private against any one non-colluding server.
- Failure threshold: how many unavailable servers can be tolerated.
- Malicious vs honest-but-curious model.
- What metadata is hidden:
  - bucket index,
  - query content,
  - response size,
  - timing?
- What metadata is not hidden yet.
- Snapshot consistency assumptions.
- Replay behavior.

Validation gate:

- Review document checked into repo.
- Tests refer to threat model labels in test names.

## Stage 2 — Choose cryptographic construction

Options:

### Option A: audited dependency

Preferred if a suitable Rust crate exists.

Requirements:

- Maintained crate.
- Clear security claims.
- Constant-time where relevant.
- License compatible with Apache-2.0.
- Test vectors or paper references.

### Option B: implement from paper

Only if no dependency is suitable.

Requirements:

- Paper citation.
- Step-by-step construction notes.
- Test vectors.
- External review before production claims.

Validation gate:

- `docs/protocols/pir.md` names the construction.
- `cargo deny`/license check if dependency added.
- Known-answer tests added.

## Stage 3 — Core PIR API

Add a new core crate or module, ideally:

```text
crates/chronos-pir
```

Public API sketch:

```rust
pub struct PirParams {
    pub bucket_count: usize,
    pub bucket_size: usize,
    pub server_count: usize,
    pub privacy_threshold: usize,
}

pub struct PirClientQuerySet { ... }
pub struct PirServerQuery { ... }
pub struct PirServerResponse { ... }

pub trait PirClient {
    fn generate_queries(index: u64, params: &PirParams) -> Result<PirClientQuerySet, PirError>;
    fn combine_responses(responses: &[PirServerResponse]) -> Result<Vec<u8>, PirError>;
}

pub trait PirServer {
    fn evaluate(query: &PirServerQuery, snapshot: &Snapshot) -> Result<PirServerResponse, PirError>;
}
```

Validation gate:

- Unit tests for query generation.
- Unit tests for response combining.
- Invalid parameter tests.

## Stage 4 — Snapshot consistency

Current snapshot roots are simple strings. Improve this.

Implement:

- Canonical snapshot serialization.
- Hash root with SHA-256 or BLAKE3.
- Per-bucket hashing.
- Optional Merkle proof for returned bucket.

Validation gate:

- Same snapshot produces same root across servers.
- Different bucket data changes root.
- Mixed-root response combining is rejected.

## Stage 5 — Network protocol

Extend `chronos-lite` storage relay with a PIR query endpoint.

Possible local protocol:

```text
CRP7 Data packet payload = PIR_QUERY_V1 bytes
PIR_RESPONSE_V1 bytes returned as CRP7 Data
```

Or use TCP for prototype:

```text
PIRQUERY <base64 query>
```

Validation gate:

- Local two-server integration test.
- Query one logical index from two separate relay instances.
- Combine responses client-side.

## Stage 6 — Malicious-server handling

Add:

- response authentication,
- snapshot root confirmation,
- optional Merkle proofs,
- server identity binding,
- replay protection.

Validation gate:

- Tampered response rejected.
- Wrong snapshot rejected.
- Duplicate/replayed response rejected if protocol requires freshness.

## Stage 7 — Performance

Add benchmarks:

```text
cargo bench -p chronos-pir
```

Measure:

- query generation time,
- server evaluation time,
- response size,
- combine time,
- memory usage.

Validation gate:

- Benchmarks committed.
- Performance targets documented.

## Stage 8 — Security review checklist

Before calling it production-grade:

- Threat model reviewed.
- Construction reviewed against paper/spec.
- Known-answer tests present.
- Fuzz tests present.
- Dependency audit complete.
- Side-channel considerations documented.
- External cryptographic review planned or completed.

## Definition of done

Minimum production-grade criteria:

- Real DPF/PIR construction implemented or audited dependency used.
- Threat model explicitly documented.
- Snapshot consistency cryptographically enforced.
- Networked multi-server integration tests pass.
- Malicious/tampered response tests pass.
- Benchmarks exist.
- Fuzz tests exist.
- Documentation clearly states privacy assumptions.
