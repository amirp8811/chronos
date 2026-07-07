# CHRONOS full TODO list

This is the master TODO list for moving CHRONOS from the current validated local prototype toward a production-ready anonymous communication system.

Status legend:

- `[done]` implemented and validated in this repo
- `[partial]` some implementation exists, but not production complete
- `[todo]` not implemented yet
- `[external]` requires external review, hardware, browser/mobile platform, or deployment environment

Last updated: 2026-07-07

---

## 0. Current baseline

### Implemented baseline

- [done] Rust workspace builds and tests.
- [done] Strict clippy passes with `-D warnings`.
- [done] `cargo fmt --check` passes.
- [done] Static audit script exists and passes hard checks.
- [done] 105 normal workspace tests pass.
- [done] Chutney-like `chronos-nettest` harness compiles and can be run manually.
- [done] `IMPLEMENTATION_STATUS.md` documents implemented work.
- [done] `IMPLEMENTATION_PLAN.md` tracks phases and cross-phase additions.
- [done] `PROTOCOLS.md` documents current protocol notes.
- [done] `docs/spec/CHRONOS-CRYPTO-SPEC.md` exists.
- [done] `docs/threat-model.md` exists.
- [done] `docs/SECURITY_VALIDATION_PLAN.md` exists.

---

# 1. Documentation, claims, and project governance

## 1.1 README and public claims

- [partial] Add implementation-reality warning to README.
- [todo] Rewrite README to clearly separate:
  - implemented today,
  - prototype features,
  - simulations,
  - target-spec claims,
  - unsafe/not audited warnings.
- [todo] Remove or heavily qualify “production-grade” language until external audits are complete.
- [todo] Add a clear “Security status” badge/section.
- [todo] Add “Do not use for real anonymity yet” warning near install commands.
- [todo] Document exact audited commit once audits occur.
- [todo] Add a changelog.
- [todo] Add release/versioning policy.

## 1.2 Protocol documentation

- [done] Add `PROTOCOLS.md`.
- [done] Add CHR7 secure cell notes.
- [done] Add shard stream notes.
- [done] Add CHS7 handshake notes.
- [done] Add CRP7 relay packet notes.
- [done] Add RTE7 route layer notes.
- [partial] Add `docs/spec/CHRONOS-CRYPTO-SPEC.md`.
- [todo] Expand protocol docs into RFC-style specs:
  - [todo] `docs/spec/CHR7-secure-cell.md`
  - [todo] `docs/spec/CHS7-handshake.md`
  - [todo] `docs/spec/CRP7-relay-packet.md`
  - [todo] `docs/spec/RTE7-route-layer.md`
  - [todo] `docs/spec/SHARD-stream.md`
  - [todo] `docs/spec/DPF-PIR.md`
  - [todo] `docs/spec/directory-consensus.md`
- [todo] Add byte-level diagrams for all wire formats.
- [todo] Add state machine diagrams.
- [todo] Add packet examples for every packet type.

## 1.3 Threat model and limitations

- [done] Add `docs/threat-model.md`.
- [todo] Expand threat model with:
  - [todo] local passive adversary,
  - [todo] malicious relay,
  - [todo] directory adversary,
  - [todo] global passive adversary,
  - [todo] active network adversary,
  - [todo] mobile platform adversary,
  - [todo] browser platform adversary,
  - [todo] storage relay adversary.
- [todo] Add claim matrix:
  - claim,
  - implemented evidence,
  - tests,
  - limitations,
  - external review status.
- [todo] Document non-goals.
- [todo] Document known weaknesses.

## 1.4 Audit preparation

- [todo] Create `audit/` directory.
- [todo] Create `audit/scope.md`.
- [todo] Create `audit/known-limitations.md`.
- [todo] Create `audit/questions-for-reviewers.md`.
- [todo] Create `audit/build-and-test.md`.
- [todo] Create audit-ready architecture diagrams.
- [todo] Create audit-ready dependency list.
- [todo] Create audit-ready commit hash and tag.
- [external] Commission independent cryptographic review.
- [external] Commission independent Rust implementation audit.
- [external] Publish audit reports and fix findings.

---

# 2. Build, CI, validation, and release engineering

## 2.1 Validation scripts

- [done] Add `scripts/static_audit.py`.
- [done] Add `scripts/validation_pass.sh`.
- [done] Validate three consecutive passes manually.
- [todo] Make validation script robust without cache workaround hacks.
- [todo] Add CI workflow for validation script.
- [todo] Add CI matrix for Linux/macOS/Windows where possible.
- [todo] Add CI job for `cargo test --workspace`.
- [todo] Add CI job for `cargo clippy --workspace --all-targets -- -D warnings`.
- [todo] Add CI job for `cargo fmt --check`.
- [todo] Add CI job for docs link check.

## 2.2 Fuzzing

- [done] Add cargo-fuzz scaffolding.
- [done] Add fuzz target for `RelayPacket`.
- [done] Add fuzz target for `LayeredRoutePacket`.
- [done] Add fuzz target for `HandshakePacket`.
- [done] Add fuzz target for `SecureShardCell`.
- [done] Add fuzz target for `chronosd` config parser.
- [done] Add fuzz target for `chronos-lite` config parser.
- [done] Add fuzz target for directory API command parser.
- [todo] Run every fuzz target for at least 5 minutes locally and fix crashes.
- [todo] Run every fuzz target for at least 1 hour before audit.
- [todo] Add fuzz corpus seeds from test vectors.
- [todo] Add CI/nightly fuzzing.
- [todo] Add crash artifact retention.
- [todo] Add fuzz target for DPF query parser.
- [todo] Add fuzz target for DPF snapshot loader.
- [todo] Add fuzz target for directory store loader.
- [todo] Add fuzz target for route table parser.

## 2.3 Test vectors

- [done] Add `docs/test-vectors/crp7_data_packet_v1.json`.
- [done] Add Rust test for CRP7 data vector.
- [todo] Add CHR7 secure cell deterministic test vector.
- [todo] Add CHS7 server hello vector.
- [todo] Add CHS7 client key share vector.
- [todo] Add CHS7 key confirmation vector.
- [todo] Add RTE7 one-hop vector.
- [todo] Add RTE7 multi-hop vector.
- [todo] Add DPF query vector.
- [todo] Add directory record vector.
- [todo] Add vector verification test suite.

## 2.4 Benchmarks

- [todo] Add benchmark harness.
- [todo] Benchmark secure cell encrypt/decrypt.
- [todo] Benchmark 16-of-10 erasure encode/decode.
- [todo] Benchmark CHS7 handshake generation/acceptance.
- [todo] Benchmark RTE7 wrap/peel.
- [todo] Benchmark CRP7 decode/encode.
- [todo] Benchmark DPF snapshot query evaluation.
- [todo] Benchmark chronosd UDP relay throughput.
- [todo] Benchmark 2-hop and 3-hop local relay latency.
- [todo] Benchmark memory usage.
- [todo] Add benchmark results to docs.

## 2.5 Release engineering

- [todo] Define versioning policy.
- [todo] Add signed release process.
- [todo] Add checksums for release artifacts.
- [todo] Add reproducible build notes.
- [todo] Add SBOM generation.
- [todo] Add dependency audit tooling.
- [todo] Add `cargo deny` or equivalent.
- [todo] Add license policy.

---

# 3. Cryptography and protocol security

## 3.1 Secure cell / CHR7

- [done] Implement fixed 1,200-byte secure cell.
- [done] Implement HKDF-SHA256 link-key derivation.
- [done] Implement ChaCha20-Poly1305 encryption.
- [done] Authenticate header/AAD.
- [done] Reject tampering.
- [done] Add replay receiver helper.
- [todo] Add zeroization for ephemeral AEAD keys.
- [todo] Add deterministic secure-cell test vectors.
- [todo] Fuzz secure-cell parser continuously.
- [todo] Review nonce uniqueness policy.
- [todo] Review max payload and padding leakage.

## 3.2 CHS7 handshake

- [done] Implement CHS7 packet format.
- [done] Implement ServerHello.
- [done] Implement ClientKeyShare.
- [done] Implement ServerKeyConfirm.
- [done] Implement Error packet type.
- [done] Implement PowChallenge/PowSolution packet types.
- [done] Implement transcript hash.
- [done] Implement suite/version downgrade rejection.
- [done] Implement ML-KEM-768 + X25519 route secret derivation.
- [done] Implement key confirmation.
- [done] Wire live CHS7 into `chronosd`.
- [done] Wire live PoW into CHS7 in `chronosd`.
- [todo] Add handshake transcript test vectors.
- [todo] Add invalid ML-KEM ciphertext tests.
- [todo] Add handshake replay tests.
- [todo] Add session resumption policy or explicit non-support.
- [todo] Add key rotation/rekey handshake.
- [todo] Add zeroization for derived route secrets.
- [external] Protocol audit of CHS7.

## 3.3 RTE7 route layer

- [done] Implement layered route packets.
- [done] Implement per-hop AEAD.
- [done] Implement packet-ID blinding.
- [done] Implement typed route commands.
- [done] Implement Drop command.
- [done] Implement DeliverLocal command.
- [done] Implement Forward command.
- [done] Implement Reply command.
- [done] Implement single-use reply block.
- [done] Implement route replay cache.
- [done] Implement TTL/capacity bounded replay cache.
- [done] Integrate live route peeling in `chronosd`.
- [todo] Add formal Sphinx comparison document.
- [todo] Add route-layer test vectors.
- [todo] Add fixed-width production route header.
- [todo] Add route-depth hiding policy.
- [todo] Add route padding policy.
- [external] Protocol audit of RTE7.

## 3.4 Key management

- [done] Implement node key generation.
- [done] Persist X25519 key.
- [done] Persist ML-KEM-768 seed.
- [done] Use key store in `chronosd`.
- [todo] Use key store in `chronos-lite` runtime.
- [todo] Add key rotation.
- [todo] Add key expiry.
- [todo] Add key backup/restore docs.
- [todo] Add secure deletion notes.
- [todo] Add zeroize to key material where possible.
- [todo] Add permission validation, not only write mode.

## 3.5 Directory signatures

- [done] Add Ed25519 signed relay record prototype.
- [done] Add signed record tamper tests.
- [partial] Add quorum-backed directory commit prototype.
- [todo] Replace local validator keys with persistent validator identities.
- [todo] Add validator key rotation.
- [todo] Add signed directory record wire format.
- [todo] Add validator trust root.
- [todo] Add threshold/quorum policy config.
- [external] Review directory signature/consensus model.

---

# 4. Relay runtime and networking

## 4.1 CRP7 relay packet

- [done] Implement CRP7 packet format.
- [done] Implement Shard packet.
- [done] Implement Route packet.
- [done] Implement Data packet.
- [done] Implement Ack packet.
- [done] Implement Error packet.
- [done] Implement typed `RelayErrorCode`.
- [done] Add parser tests.
- [done] Add fuzz target.
- [todo] Add more test vectors.
- [todo] Add reserved-bit policy.

## 4.2 `chronosd` UDP relay

- [done] Implement Tokio UDP relay.
- [done] Implement static route table.
- [done] Implement ACKs.
- [done] Implement typed errors.
- [done] Implement route peeling.
- [done] Implement live CHS7 handshake.
- [done] Implement live PoW admission.
- [done] Implement session enforcement mode.
- [done] Implement outbound bounded queue.
- [done] Implement queue-full error.
- [done] Implement TDM send pacing.
- [done] Implement Prometheus-compatible metrics endpoint.
- [done] Implement route table persistence helpers.
- [todo] Integrate `SessionManager` directly into `ChronosUdpRelay` instead of parallel session fields.
- [todo] Add session expiry loop.
- [todo] Add graceful shutdown.
- [todo] Add peer health tracking.
- [todo] Add retry policy.
- [todo] Add packet expiry in queues.
- [todo] Add per-peer queue limits.
- [todo] Add per-stream queue limits.
- [todo] Add integration tests for packet loss/reordering.
- [todo] Add metrics for every error type.

## 4.3 Chutney-like nettest

- [done] Add `tools/chronos-nettest`.
- [done] Spawn local `chronosd` relays.
- [done] Test sender -> relay1 -> relay2 -> receiver.
- [done] Verify ACK.
- [done] Collect CSV packet trace.
- [todo] Add 3-hop route-peeling nettest.
- [todo] Add CHS7 handshake nettest.
- [todo] Add PoW nettest.
- [todo] Add directory-assisted route discovery nettest.
- [todo] Add failure-mode nettests.
- [todo] Add nettest CI job.

---

# 5. Directory service

## 5.1 Local store

- [done] Implement `DirectoryStore`.
- [done] Implement upsert/get/prune.
- [done] Implement store persistence.
- [done] Implement TCP API with UPSERT/GET/PRUNE.
- [todo] Add LIST command.
- [todo] Add signed UPSERT command.
- [todo] Add record versioning.
- [todo] Add conflict resolution.
- [todo] Add persistent DB compaction.

## 5.2 Quorum/consensus prototype

- [done] Implement Ed25519 validator votes.
- [done] Implement quorum certificate prototype.
- [done] Commit record only after threshold votes.
- [done] Reject tampered votes.
- [todo] Add validator networking.
- [todo] Add proposal messages.
- [todo] Add vote messages.
- [todo] Add view numbers.
- [todo] Add leader election.
- [todo] Add view change.
- [todo] Add persistent consensus log.
- [todo] Add epoch transitions.
- [todo] Add `.chr` records.
- [todo] Add BLS aggregation or justify Ed25519 quorum design.
- [external] Full BFT/consensus review.

---

# 6. DPF/PIR and storage

## 6.1 Current DPF/PIR prototype

- [done] Implement DPF snapshot persistence.
- [done] Implement DPF query request encoding.
- [done] Implement DPF query response.
- [done] Implement two-server XOR point-function share prototype.
- [done] Implement two-server PIR evaluation.
- [done] Reject snapshot-root mismatch.
- [todo] Add networked PIR endpoint.
- [todo] Add signed storage snapshots.
- [todo] Add malicious response detection beyond root mismatch.
- [todo] Add storage compaction.
- [todo] Add bucket size policy.
- [todo] Add privacy threat model for current prototype.
- [external] Choose/review production PIR construction.

## 6.2 Production PIR

- [todo] Define PIR threat model.
- [todo] Select audited DPF/PIR construction.
- [todo] Implement or integrate chosen construction.
- [todo] Add known-answer tests.
- [todo] Add formal-ish security argument.
- [todo] Add external cryptographic review.
- [todo] Add large database benchmarks.

---

# 7. Browser and web UI

## 7.1 WASM

- [done] Add wasm-bindgen crate type.
- [done] Export WASM version.
- [done] Export TDM planner self-test.
- [done] Export secure cell self-test.
- [todo] Export CHS7 packet helpers.
- [todo] Export CRP7 packet helpers.
- [todo] Export RTE7 route helpers.
- [todo] Export shard-stream encode/decode helpers.
- [todo] Add wasm-pack build instructions.
- [todo] Add wasm CI build.

## 7.2 Web UI

- [done] Add WASM loader fallback panel.
- [partial] Static dashboard exists.
- [todo] Add WebSocket client module.
- [todo] Add WebSocket gateway or direct WebSocket relay.
- [todo] Add connect/disconnect controls.
- [todo] Add CHS7 handshake from browser.
- [todo] Add send CRP7 packet UI.
- [todo] Add ACK/error display.
- [todo] Add Playwright tests.
- [todo] Add WebTransport feature detection.
- [todo] Add WebTransport server/gateway.

---

# 8. Mobile clients

## 8.1 iOS

- [partial] Add iOS README scaffold.
- [todo] Create Swift package or Xcode project.
- [todo] Add Keychain storage wrapper.
- [todo] Add WebSocket transport wrapper.
- [todo] Add CHS7 handshake flow.
- [todo] Add CRP7 packet send/receive.
- [todo] Add basic UI.
- [todo] Add simulator tests.

## 8.2 Android

- [partial] Add Android README scaffold.
- [todo] Create Gradle/Kotlin project.
- [todo] Add Android Keystore wrapper.
- [todo] Add WebSocket transport wrapper.
- [todo] Add CHS7 handshake flow.
- [todo] Add CRP7 packet send/receive.
- [todo] Add basic UI.
- [todo] Add emulator tests.

## 8.3 Shared mobile core

- [todo] Decide FFI strategy.
- [todo] Evaluate UniFFI.
- [todo] Create mobile core crate if needed.
- [todo] Generate Swift/Kotlin bindings.

---

# 9. Data plane and hardware

## 9.1 Tokio UDP

- [done] Implement live Tokio UDP relay.
- [done] Add queue/backpressure.
- [done] Add pacing.
- [done] Add metrics.

## 9.2 io_uring

- [partial] Add io_uring planning boundary.
- [todo] Add feature-gated `io-uring` dependency.
- [todo] Define data-plane trait.
- [todo] Implement UDP recv/send with io_uring.
- [todo] Add registered buffers.
- [todo] Add SQPOLL support.
- [todo] Add Linux-only tests.
- [todo] Add metrics.

## 9.3 AF_XDP

- [partial] Add AF_XDP planning boundary.
- [todo] Choose AF_XDP crate or libbpf strategy.
- [todo] Add feature gate.
- [todo] Implement UMEM allocation.
- [todo] Implement fill/RX/TX/completion rings.
- [todo] Implement XDP program attach/detach.
- [todo] Integrate with relay handler.
- [todo] Add hardware test docs.

## 9.4 NIC RSS / Toeplitz

- [partial] Build ethtool argument vector.
- [todo] Add dry-run controller trait.
- [todo] Add command execution backend.
- [todo] Add privilege checks.
- [todo] Add interface capability checks.
- [todo] Add netlink backend.
- [todo] Add rollback/verification.
- [todo] Add hardware test docs.

---

# 10. Anonymity and traffic analysis

## 10.1 TDM and cover traffic

- [done] Add deterministic TDM scheduler.
- [done] Add live send pacing.
- [todo] Add cover packet generation in live relay.
- [todo] Add cover traffic config.
- [todo] Add cover traffic metrics.
- [todo] Add active vs idle indistinguishability tests.

## 10.2 Trace collection

- [done] Add nettest trace CSV output.
- [done] Add CSV import/export.
- [done] Add basic traffic shape analyzer.
- [done] Add heuristic classifier score.
- [todo] Add multi-run trace collection.
- [todo] Add route correlation metric.
- [todo] Add packet count leakage metric.
- [todo] Add burstiness metric.
- [todo] Add synthetic dataset generator.
- [todo] Add classifier baseline beyond heuristic.
- [external] Run realistic traffic-analysis experiments.

---

# 11. Security validation and audits

## 11.1 Internal validation

- [done] Add validation plan.
- [done] Add crypto spec draft.
- [done] Add threat model draft.
- [done] Add static audit script.
- [done] Run validation pass three times.
- [todo] Reduce static audit warnings in non-test code.
- [todo] Add CI for validation pass.
- [todo] Add cargo-fuzz CI/nightly.

## 11.2 External review

- [todo] Prepare audit package.
- [todo] Select cryptographic reviewers.
- [todo] Select Rust implementation auditors.
- [external] Conduct cryptographic review.
- [external] Conduct implementation audit.
- [todo] Fix findings.
- [todo] Publish audit report and response.

---

# 12. Production operations

## 12.1 Deployment

- [todo] Add systemd service file.
- [todo] Add Dockerfile for dev only.
- [todo] Add package build instructions.
- [todo] Add secure bootstrap instructions.
- [todo] Remove or replace `curl | bash` style install in docs.

## 12.2 Runtime safety

- [todo] Add graceful shutdown.
- [todo] Add config validation before binding sockets.
- [todo] Add runtime health endpoint.
- [todo] Add log redaction policy.
- [todo] Add key permission checks.
- [todo] Add resource limits.

## 12.3 Observability

- [done] Add Prometheus text renderer.
- [done] Add metrics TCP endpoint.
- [todo] Add more counters.
- [todo] Add histograms.
- [todo] Add structured logs.
- [todo] Add OpenTelemetry support.

---

# 13. Final production readiness gates

Do not mark production ready until all are complete:

- [todo] External cryptographic review complete.
- [todo] External implementation audit complete.
- [todo] All critical/high findings fixed.
- [todo] Continuous fuzzing in place.
- [todo] Threat model reviewed.
- [todo] README claims aligned with evidence.
- [todo] Browser client tested.
- [todo] Multi-node nettest in CI.
- [todo] Deployment hardening complete.
- [todo] Security policy and vulnerability reporting process published.
