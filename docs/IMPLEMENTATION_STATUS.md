# CHRONOS implementation status

This workspace is a reference prototype being aligned with the CHRONOS v7.0 specification. It is not yet a production anonymous communication network.

## Changes made in this workspace

- Imported/cloned `amirp8811/chronos` into `/home/user/chronos`.
- Updated all crate manifests from Rust 2021 to Rust 2024 edition to match the project README/spec language.
- Removed unused dependencies from crate manifests (`serde`, `serde_json`, `thiserror`, unused `sha2`, unused `chronos-core`).
- Replaced the `rand` use in `chronosd::toeplitz_rss` with a std-only simulation salt generator, avoiding an extra dependency.
- Narrowed Tokio feature flags per binary instead of enabling `tokio/full`.
- Reworked the Reed-Solomon `(16,10)` generator matrix in `chronos-core` to be systematic:
  - rows `0..10` are identity rows, so the first ten encoded shards are the original data shards;
  - rows `10..16` are Cauchy parity rows over GF(2^8), suitable for 10-of-16 reconstruction.
- Added unit tests for systematic encoding and mixed data/parity recovery.
- Added a README implementation-status warning so the documentation no longer implies the current code is production-ready.

## Still not spec-complete

The codebase now has real, validated building blocks for fixed-size AEAD cells, replay checks, 16-of-10 encrypted erasure blocks, an X25519 link-key boundary, CRP7 relay packets, a stateful local UDP relay handler, and `chronos-lite` config loading. It is still **not** a production CHRONOS v7.0 network. Remaining gaps are tracked below by area.

### Cryptography and route privacy

| Area | Current state | Spec-level gap |
| --- | --- | --- |
| Link key agreement | X25519 implemented in `handshake.rs`; ML-KEM-768 + X25519 route-secret setup implemented in `hybrid_route.rs`. | Bind the hybrid transcript into full session/circuit setup, add serialization/test vectors, and enforce downgrade protection. |
| AEAD cell encryption | ChaCha20-Poly1305 + HKDF implemented in `secure_cell.rs`. | Integrate with the final route/circuit protocol and key schedule. |
| Sphinx/onion routing | `route_layer.rs` now provides AEAD-protected layered route packets, per-hop packet-ID blinding, typed route commands, route replay state, and single-use reply blocks; old `sphinx.rs` has been removed from the core crate. | This is a concrete Sphinx-like route layer, but it is not a formal academic Sphinx proof. Remaining work: external review, fixed-width production route headers, interop vectors, and full circuit/session binding. |
| Forward secrecy / key lifecycle | Basic ratchet prototype exists. | Bind ratchet state to real handshakes, relay sessions, zeroization, and rekey tests. |
| PQC claims | ML-KEM-768 + X25519 route-secret setup is implemented and tested, and those secrets drive the route layer. | Add serialized handshake transcripts, downgrade protection, failure policy, interop vectors, and multi-peer session integration. |

### Relay and transport

| Area | Current state | Spec-level gap |
| --- | --- | --- |
| Local UDP relay | CRP7 relay packets, stateful replay handler, ACKs, route-packet forwarding, and localhost tests exist. | Build a real multi-peer relay service with routing tables, peer identity, backpressure, metrics, and persistent configuration. |
| AF_XDP / io_uring | `chronosd` still simulates engine selection. | Implement actual AF_XDP sockets, UMEM registration, RX/TX rings, and `io_uring` fallback. |
| NIC RSS / Toeplitz | `toeplitz_rss.rs` still simulates salt changes. | Implement netlink/libbpf/ethtool control and queue-rate telemetry. |
| resctrl / cache isolation | Writes to resctrl paths if present, but remains minimal. | Add feature detection, cleanup, thread pinning, and validation tests. |
| Constant-rate/TDM scheduling | Not implemented. | Add pacing queues, padding/cover policy, timing tests, and load benchmarks. |

### Browser/WASM/mobile

| Area | Current state | Spec-level gap |
| --- | --- | --- |
| `chronos-wasm` | Still mostly simulation/logging. | Add `wasm-bindgen`/JS bindings, WebTransport, WebSocket fallback, Web Worker PoW, SharedArrayBuffer setup, and browser integration tests. |
| `apps/chronos-web` | Static demo dashboard. | Wire to the real WASM runtime and relay protocol. |
| Mobile power/stealth | Simulation only. | Implement platform-specific networking/power behavior or mark claims as aspirational. |

### Storage and directory

| Area | Current state | Spec-level gap |
| --- | --- | --- |
| DPF/PIR storage | Local storage simulation only. | Implement real DPF key generation, multi-server PIR queries, consistency proofs, persistence, and privacy tests. |
| Directory consensus | `chronos-dir` still simulates consensus. | Implement validator networking, HotStuff-style state machine replication, BLS12-381 signatures, persistent logs, and `.chr` records. |
| Domain/relay peering | Documentation only. | Define actual registration, identity, proof, and enforcement protocols. |

### Configuration, operations, and validation

| Area | Current state | Spec-level gap |
| --- | --- | --- |
| Config loading | `chronos-lite` now loads a std-only subset of its config. | Wire `chronosd` and `chronos-dir` configs; consider full TOML parsing if config complexity grows. |
| Bootstrap/install | Scripts remain mostly dev-oriented. | Add signed releases, checksums, service files, least-privilege setup, and safe key generation. |
| Testing | `cargo fmt`, `check`, `test`, and strict `clippy` pass; 109 tests currently pass. | Add fuzzing, property tests, multi-node integration tests, benchmarks, and adversarial traffic-analysis tests. |
| Documentation honesty | This file is current, README has an implementation warning. | Continue splitting target spec vs implemented behavior so claims stay accurate. |

## Verification note

Cargo/Rust was installed in the working session for validation. Current validation commands are listed in the tranche notes below and all pass.

## Dependency minimisation

To reduce attack surface, the workspace now keeps only dependencies used by source code:

- `chronos-core`: `sha2`, `hkdf`, `chacha20poly1305`, and `x25519-dalek` for hashing, AEAD/HKDF cells, and the X25519 link-key boundary.
- `chronosd`: `chronos-core`, `tokio` with minimal `macros`, `rt-multi-thread`, `time` features, and `log`.
- `chronos-lite`: `chronos-core`, `tokio` with only `io-util`, `macros`, `net`, `rt-multi-thread`, `sync`, `time`, and `log`.
- `chronos-dir`: `tokio` with minimal `macros`, `rt-multi-thread`, `time`, and `log`.
- `chronos-wasm`: `log` only.

Removed direct dependencies: `serde`, `serde_json`, `thiserror`, `rand`, unused `sha2`, and unused `chronos-core` crate links. Later, `hkdf`, `chacha20poly1305`, and `x25519-dalek` were intentionally added to replace placeholder packet crypto with real AEAD/HKDF and X25519 primitives. `chronos-core` was reintroduced to `chronos-lite` once the local relay path started consuming real core packet/codec types.

Validation completed after dependency minimisation:

```bash
cargo check --workspace
cargo test --workspace
```

Both commands completed successfully.

## Implementation tranche 1: authenticated cell primitive

Started replacing the placeholder packet crypto path with a production-oriented primitive in `chronos-core/src/secure_cell.rs`:

- Added a versioned fixed-size 1,200-byte SHARD cell envelope.
- Added HKDF-SHA256 link-key derivation boundary.
- Added ChaCha20-Poly1305 authenticated encryption over a padded 944-byte payload region.
- Authenticates route tag, flags, payload length, and sequence IV as AEAD AAD.
- Added parser/serializer for exact app-cell bytes.
- Added tamper-detection and round-trip tests.

This is not the full Sphinx-PQC route layer yet; it is the first real AEAD packet building block that future Sphinx/relay code can consume.

## Implementation tranche 2: receive-side replay validation and stricter CI checks

Added receive-side replay protection around the authenticated cell primitive:

- Added `SecureShardCell::sequence()` for extracting the monotonic sequence from the AEAD nonce.
- Added deterministic `ReplayWindow` supporting out-of-order delivery inside a bounded window while rejecting duplicates and stale packets.
- Added `SecureCellReceiver`, which authenticates/decrypts first and advances replay state only for valid cells.
- Added tests for out-of-order acceptance, duplicate rejection, stale rejection, and authenticated replay rejection.

Validation after this tranche now includes multiple passes:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass.

Additional hygiene fixes made while enabling strict validation:

- Formatted the Rust workspace with `cargo fmt`.
- Fixed clippy findings across touched and pre-existing code paths.
- Removed remaining dead-code warnings in `chronosd` by logging selected data-plane descriptor summaries and batch-window settings.

## Implementation tranche 3: encrypted erasure-block codec

Connected the new AEAD cell primitive to the GF(2^8) erasure codec in `chronos-core/src/shard_stream.rs`:

- Added `SecureShardBlockCodec` for single-block message encoding/decoding.
- Splits a plaintext message into 10 data symbols, creates 6 Cauchy parity symbols, and encrypts each shard as a `SecureShardCell`.
- Adds authenticated per-shard metadata: block ID, original length, symbol length, shard index, and codec parameters.
- Decode path authenticates cells, skips tampered cells, enforces duplicate/stale replay checks through `SecureCellReceiver`, validates block metadata consistency, and reconstructs from 10 valid shards.
- Added tests for 10-of-16 recovery, tampered-cell skipping, insufficient shard failure, and oversized message rejection.

Validation after tranche 3:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass.

## Implementation tranche 4: localhost UDP secure-shard integration

Added a first network-facing integration test in `chronos-lite/src/secure_udp.rs`:

- Reintroduced `chronos-core` as a real dependency of `chronos-lite` because it now consumes the secure shard codec.
- Encodes a plaintext message into encrypted 16-of-10 shard cells.
- Sends 10 exact 1,200-byte app-cell datagrams over localhost UDP.
- Parses received datagrams back into `SecureShardCell` values.
- Reconstructs and verifies the original message from the UDP-delivered shards.

This is not the final relay network protocol, but it validates the first real local transport path for authenticated erasure shards.

Validation after tranche 4:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass.

## Implementation tranche 5: secure UDP relay forwarding path

Extended the localhost UDP work into a simple relay-forwarding path:

- Added reusable `parse_secure_app_datagram` helper for exact 1,200-byte encrypted app-cell UDP payloads; serialization uses `SecureShardCell::to_app_cell_bytes()`.
- Updated the `chronos-lite` UDP listener to recognize and log secure CHRONOS app-cell envelopes by sequence and payload length.
- Added an integration test for sender -> relay -> receiver forwarding of encrypted shard cells. The relay parses fixed cell envelopes and forwards opaque encrypted cells without decrypting them.
- Added wrong-length datagram rejection tests.

This is still a localhost stepping stone, not the full production relay protocol, but it introduces the first validated relay forwarding behavior for secure erasure shards.

Validation after tranche 5:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass.

## Implementation tranche 6: X25519 link handshake boundary

Added `chronos-core/src/handshake.rs` as the first real key-agreement primitive:

- Implements the X25519 half of the target hybrid ML-KEM-768 + X25519 handshake.
- Adds typed node public/secret wrappers and `LinkSharedSecret`.
- Feeds X25519 shared secrets into the existing HKDF/AEAD cell-key derivation.
- Adds tests proving both peers derive the same link secret, can encrypt/decrypt a secure cell, and route tags domain-separate derived cell keys.

This still does not implement ML-KEM-768; that remains the next cryptographic gap.

Validation after tranche 6:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass.

## Implementation tranche 7: explicit relay packet envelope

Added `chronos-core/src/relay_packet.rs` and wired it into the localhost relay test path:

- Defines a compact versioned `CRP7` relay packet header with packet type, flags, stream ID, sequence, and bounded payload.
- Adds packet types for `Hello`, `Shard`, `Ack`, and `Error`.
- Wraps a 1,200-byte `SecureShardCell` into a 1,228-byte relay shard packet, staying within the IPv6 minimum-MTU UDP payload limit of 1,232 bytes for this non-QUIC local transport.
- Adds strict parser validation for magic, version, packet type, reserved bytes, declared payload length, maximum payload, and shard-cell integrity.
- Updates the sender -> relay -> receiver test to forward relay packets rather than raw app cells.

Validation after tranche 7:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass.

## Implementation tranche 8: stateful relay packet handler

Added `chronos-core/src/relay_handler.rs` to turn the relay packet envelope into a stateful forwarding decision layer:

- Adds `RelayPacketHandler` with per-stream replay windows.
- Validates that shard packets contain intact `SecureShardCell` envelopes without decrypting them.
- Rejects duplicate/stale relay sequences per stream.
- Returns a forwarding decision plus an ACK packet for valid shard packets.
- Rejects unsupported packet types (`Hello`, `Ack`, `Error`) in the shard forwarding path.
- Added ACK/Error constructors to `RelayPacket`.
- Added tests for valid forwarding, ACK generation, duplicate rejection, per-stream sequence isolation, and unsupported packet rejection.

Validation after tranche 8:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass.

## Implementation tranche 9: chronos-lite relay path uses stateful handler

Wired the stateful relay handler into the localhost UDP relay test path:

- `chronos-lite::secure_udp` now exposes `process_secure_relay_datagram`, which parses CRP7 relay packets and runs them through `RelayPacketHandler`.
- The sender -> relay -> receiver test now validates ACK generation back to the sender for each forwarded shard.
- The relay forwarding helper now rejects duplicate relay sequences through the core handler instead of just parse/forwarding packets.
- Added a duplicate sequence processing test at the UDP datagram boundary.

Validation after tranche 9:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass.

## Implementation tranche 10: std-only chronos-lite config loader

Added real configuration loading for `chronos-lite` without adding a general TOML dependency:

- Added `chronos-lite/src/config.rs`, a small std-only parser for the simple TOML subset used by `configs/chronos-lite.toml`.
- Parses node identity, role, jurisdiction, data-plane interface/engine flags, DPF storage settings, and TURN reflector endpoint arrays.
- `chronos-lite` now loads `CHRONOS_LITE_CONFIG` or defaults to `configs/chronos-lite.toml`, falling back to safe local defaults if loading fails.
- Startup logs now reflect config values instead of hard-coded node/role/engine strings.
- Added parser tests for the bundled subset, invalid booleans, and defaults for missing values.

Validation after tranche 10:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass.

## Implementation tranche 11: authenticated layered route packet prototype

Added `chronos-core/src/route_layer.rs` as the first concrete replacement path for the old SHA-256/XOR `sphinx.rs` simulation:

- Adds a versioned `RTE7` layered route packet format.
- Wraps payloads in one ChaCha20-Poly1305 authenticated layer per hop.
- Derives per-hop AEAD keys with HKDF-SHA256 from typed hop secrets, packet ID, and hop index.
- Authenticates route commands (`next_stream_id`, flags), layer headers, inner lengths, and ciphertext.
- Supports ordered per-hop peeling into either the next route packet or terminal payload.
- Adds tests for ordered multi-hop peeling, tamper detection, wrong-hop-secret rejection, and out-of-order hop rejection.

This is still not full Sphinx-PQC: no ML-KEM route setup, no SURB support, and no formal Sphinx blinding. It is, however, a real AEAD-protected layered route primitive that can replace more of the placeholder `sphinx.rs` path.

Validation after tranche 11:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass.

## Implementation tranche 12: hybrid ML-KEM-768 + X25519 route-secret setup

Added `chronos-core/src/hybrid_route.rs` to provide the first real PQ/classical hybrid route setup boundary:

- Adds ML-KEM-768 keypair generation using the RustCrypto `ml-kem` crate.
- Encapsulates an ML-KEM shared secret to a route-hop receiver.
- Combines the ML-KEM shared secret with an X25519 shared secret using HKDF-SHA256 and route context.
- Produces a `RouteHopSecret` compatible with the authenticated layered route packet prototype.
- Adds tests proving sender/receiver derive the same hybrid route secret, the secret can drive route-layer encryption/decryption, and route contexts domain-separate derived secrets.

This implements the first ML-KEM route setup primitive, but full Sphinx-PQC still needs formal blinding, SURBs, replay state integration, and full relay-path integration.

Validation after tranche 12:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass.

## Implementation tranche 13: complete route-layer replacement path

Finished the requested route-layer replacement work at the code/prototype level:

- **Formal Sphinx-style blinding path:** added per-hop packet-ID blinding using HKDF-SHA256 over the current packet ID, hop index, and hop secret. Each peeled hop receives a different blinded `packet_id`, so downstream relay identifiers are unlinkable at the packet-envelope level in this implementation. This is a concrete Sphinx-like blinding mechanism, not a published formal proof.
- **SURB/reply blocks:** added `SingleUseReplyBlock`, which seals a reply payload into a pre-defined reverse route and enforces one-time use.
- **Route replay state:** added `RouteReplayCache` and `RouteLayerProcessor`; duplicate `(packet_id, hop_index)` route packets are rejected.
- **Production route-command semantics:** replaced raw final-hop flag usage with typed command semantics: `Forward`, `DeliverLocal`, `Drop`, and `Reply`, plus constructors on `RouteCommand`.
- **Relay forwarding integration:** added `RelayPacketType::Route`, `RelayPacket::route`, `RelayPacket::route_packet`, stateful route replay enforcement in `RelayPacketHandler`, and localhost UDP route-packet forwarding tests.
- **Old `sphinx.rs` removal:** removed the old SHA-256/XOR `sphinx.rs` module from `chronos-core` and deleted the file. `route_layer.rs` is now the core route-layer replacement path.

Tests added/updated cover blinded multi-hop peeling, route packet serialization, route replay rejection, single-use reply block enforcement, drop command enforcement, relay route packet round-trips, relay handler route forwarding, duplicate route packet rejection, and localhost UDP route forwarding.

Validation after tranche 13:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests at tranche 13; tranche 14 raises the total to 49 passing tests.

## Implementation tranche 14: chronosd async UDP relay service

Started Phase 1 of `IMPLEMENTATION_PLAN.md` by adding a real Tokio UDP relay loop to `chronosd`:

- Added `chronosd/src/udp_relay.rs`.
- Added `ChronosUdpRelay`, which binds a UDP socket, decodes CRP7 relay packets, runs them through `RelayPacketHandler`, forwards validated shard/route packets, and ACKs the sender.
- Added `StaticRouteTable`, mapping stream IDs to destination socket addresses.
- Added static route parsing for `CHRONOSD_STATIC_ROUTES` entries like `77=127.0.0.1:9001,88=127.0.0.1:9002`.
- Wired runtime activation through `CHRONOSD_UDP_RELAY_BIND`; if set, `chronosd` starts the UDP relay service instead of the simulation loop.
- Added NO_ROUTE error packet behavior when a stream has no static destination.
- Added integration tests for sender -> chronosd UDP relay -> receiver using both encrypted shard packets and route packets, including ACK validation.
- Updated `IMPLEMENTATION_PLAN.md` to mark the first Phase 1 relay tasks as done/partial.

Validation after tranche 14:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests at tranche 14; tranche 15 raises the total to 51 passing tests.

## Implementation tranche 15: Phase 1 relay hardening tests

Continued Phase 1 by hardening the `chronosd` UDP relay behavior:

- Added a NO_ROUTE test proving the relay returns a CRP7 `Error` packet with payload `NO_ROUTE` when no static route exists.
- Added a two-hop local relay test: sender -> relay1 -> relay2 -> receiver, with ACK validation.
- Updated `IMPLEMENTATION_PLAN.md` to mark Phase 1 ACK/error handling as done and note two-hop relay coverage.

Validation after tranche 15:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 16: Phase 2 key generation and persistence

Started Phase 2 of `IMPLEMENTATION_PLAN.md` by adding runtime node key management:

- Added `chronos-core/src/key_store.rs`.
- Added `NodeKeyMaterial`, containing an X25519 node secret and ML-KEM-768 route keypair.
- Added OS-CSPRNG X25519 key generation via `getrandom`.
- Added ML-KEM-768 decapsulation seed persistence and reload support.
- Added `MlKem768RouteKeypair::from_seed_bytes` and `to_seed_bytes` for deterministic reload.
- Added `X25519NodeSecret::to_bytes` for persistence.
- Added `save_to_dir`, `load_from_dir`, and `load_or_generate`.
- Secret key files are written with owner-only `0600` permissions on Unix platforms.
- Added tests for key save/load round-trip, loaded-key hybrid route setup, and wrong-length key rejection.
- Updated `IMPLEMENTATION_PLAN.md` to mark Phase 2 key generation and persistence as done.

Validation after tranche 16:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 17: Phase 2 handshake packet flow and transcript protection

Completed the remaining Phase 2 handshake items:

- Added `chronos-core/src/handshake_protocol.rs`.
- Added CHS7 handshake packets for `ServerHello`, `ClientKeyShare`, `ServerKeyConfirm`, and `Error`.
- `ServerHello` carries X25519 public key bytes and ML-KEM-768 encapsulation public key bytes.
- `ClientKeyShare` carries client X25519 public key bytes and ML-KEM-768 ciphertext bytes.
- Added transcript hashing over the encoded server hello and client key share.
- Added suite/version binding and explicit suite validation to prevent downgrade acceptance.
- Added HKDF-SHA256 key-confirmation tags derived from the hybrid route secret and transcript hash.
- Added client verification of server key confirmation.
- Added deterministic/failure tests covering successful handshakes, packet round-trips, bad magic, downgraded suite rejection, bad confirmation rejection, and wrong packet type rejection.
- Updated `IMPLEMENTATION_PLAN.md` to mark Phase 2 complete.

Validation after tranche 17:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 18: Phase 3 live route peeling in chronosd

Started Phase 3 by wiring route processing into the live `chronosd` UDP relay runtime:

- `ChronosUdpRelay` now supports per-stream route-hop secrets.
- Added `CHRONOSD_ROUTE_SECRETS` parsing for entries like `10=<64 hex chars>`.
- Route packets can now be peeled in the relay runtime instead of only forwarded opaquely.
- `RouteCommand::forward` creates a new CRP7 route packet for the next stream.
- `RouteCommand::deliver_local` emits a CRP7 `Data` packet with terminal payload.
- `RouteCommand::reply` emits a CRP7 `Data` packet to the reply stream.
- `RouteCommand::drop` returns a CRP7 `Error` packet with payload `DROP`.
- Added `RelayPacketType::Data` and `RelayPacket::data`.
- Added a local three-relay test: sender -> relay1(peel) -> relay2(peel) -> relay3(peel) -> receiver, proving hop-by-hop route processing and terminal delivery.
- Updated `IMPLEMENTATION_PLAN.md` Phase 3: mapping, peeling, command execution, and 3-hop tests are done; replay-cache expiry remains partial.

Validation after tranche 18:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 19: Phase 3 bounded route replay cache completion

Finished the remaining Phase 3 replay-cache item:

- `RouteReplayCache` now has configurable max-entry and TTL bounds.
- Expired entries are pruned before replay checks.
- Oldest entries are evicted when capacity is exceeded.
- Added `RouteLayerProcessor::with_replay_limits` for runtime/test configuration.
- Added tests for TTL expiry and capacity eviction.
- Updated `IMPLEMENTATION_PLAN.md` to mark Phase 3 replay-cache expiry/bounds as done.

Validation after tranche 19:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 20: chronosd config and runtime key wiring

Implemented more of the outstanding project checklist:

- Added `chronosd/src/config.rs`, a std-only config loader for the `configs/chronosd.toml` subset.
- Added `[runtime]` settings to `configs/chronosd.toml` for key directory, UDP bind address, static routes, route secrets, and replay cache limits.
- `chronosd` now loads `CHRONOSD_CONFIG` or defaults to `configs/chronosd.toml`.
- `chronosd` now load-or-generates node key material at startup via `NodeKeyMaterial`.
- `chronosd` now uses config values for interface, cache slice size, Toeplitz threshold, UDP relay bind, static routes, route secrets, and route replay bounds.
- Added route-secret spec parsing from config as well as environment variables.
- Added config parser tests for valid config and invalid booleans.

Validation after tranche 20:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 21: live CHS7 handshake installation in chronosd

Implemented the remaining live-handshake integration for the local prototype:

- `ChronosUdpRelay` can now enable a CHS7 handshake server from `NodeKeyMaterial`.
- Empty CHS7 `ServerHello` packets act as local prototype hello requests; the relay replies with its real server hello containing X25519 and ML-KEM-768 public keys.
- CHS7 `ClientKeyShare` packets are accepted by the relay, verified through the core handshake protocol, and confirmed with `ServerKeyConfirm`.
- The derived hybrid route secret is installed into the live relay route-secret table under an allocated local stream ID.
- Added a live integration test proving: client requests server hello -> client sends key share -> client verifies server confirmation -> client sends a route packet using the derived secret -> relay peels it and delivers terminal CRP7 `Data` to a receiver.
- Updated `IMPLEMENTATION_PLAN.md` to mark live CHS7 handshake installation as done for the local prototype.

Validation after tranche 21:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 22: typed relay errors and basic observability counters

Implemented more of the remaining relay hardening checklist:

- Added `RelayErrorCode` with typed binary error codes for malformed packet, replay, no session, unknown stream, expired route, unauthorized, queue full, unsupported version, no route, drop, and internal error.
- Added `RelayPacket::error_code` and `RelayPacket::decode_error_code` so CRP7 errors no longer need string payloads.
- Updated `chronosd` NO_ROUTE and DROP paths to emit typed binary CRP7 error packets.
- Added `UdpRelayMetrics` counters for packets received, forwarded packets, ACKs, errors, NO_ROUTE errors, route packets peeled, and delivered data packets.
- Added metrics assertions to the UDP relay test path.

Validation after tranche 22:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 23: fuzz targets, PoW boundary, TDM scheduler, directory store, queue primitive, and protocol docs

Implemented additional items from the remaining checklist:

- Added real `cargo-fuzz`/libFuzzer target scaffolding under `fuzz/` for `RelayPacket`, `HandshakePacket`, `LayeredRoutePacket`, and `SecureShardCell` parsers.
- Added `chronos-core/src/pow_admission.rs`, a PoW admission challenge/verification boundary with deterministic tests.
- Added `chronos-core/src/tdm.rs`, a deterministic constant-rate/TDM scheduling primitive with cover-cell planning tests.
- Added `chronosd/src/queue.rs`, a bounded relay queue/backpressure primitive returning typed `RelayErrorCode::QueueFull` on overflow.
- Added `chronos-dir/src/store.rs`, a prototype local relay-record directory store with expiry/pruning tests.
- Added `PROTOCOLS.md`, documenting the implemented secure cell, shard stream, CHS7 handshake, CRP7 relay packet, and RTE7 route-layer formats.
- Added typed relay error code tests and UDP relay metrics tests in earlier work; this tranche keeps them validated.

Validation after tranche 23:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current workspace test count: 109 passing tests. Fuzz targets are present but not run by the standard test command; run them with `cargo fuzz run <target>` from the `fuzz/` package.

## Implementation tranche 24: live PoW admission in CHS7 handshake

Wired the PoW admission boundary into the live `chronosd` CHS7 handshake path:

- Extended CHS7 with `PowChallenge` and `PowSolution` packet types.
- Added `HandshakePacket::pow_challenge`, `decode_pow_challenge`, and `pow_solution` helpers.
- `ChronosUdpRelay` can now enable PoW admission with a `PowChallenge`.
- When PoW is enabled, an empty `ServerHello` request returns a `PowChallenge` first.
- The client must return a valid `PowSolution` before receiving the real server hello.
- `ClientKeyShare` is rejected unless the peer has satisfied PoW when PoW is enabled.
- `chronosd` config/runtime can enable PoW via existing security config fields.
- Added live test proving challenge -> solution -> server hello -> key share -> confirmation.

Validation after tranche 24:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 25: live relay outbound queue/backpressure integration

Integrated the bounded relay queue into the live `chronosd` UDP relay path:

- `ChronosUdpRelay` now owns a `BoundedRelayQueue` for outbound packets.
- Forwarded packets and ACKs are enqueued before send, then flushed in order.
- Queue capacity is configurable through `runtime.outbound_queue_max` in `configs/chronosd.toml`.
- Queue overflow now returns a typed CRP7 `RelayErrorCode::QueueFull` error packet to the sender.
- Added queue-full metrics via `UdpRelayMetrics::queue_full_errors`.
- Added a live relay test proving outbound queue saturation returns a typed QueueFull error.

Validation after tranche 25:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 26: Prometheus metrics endpoint

Added a minimal Prometheus-compatible metrics endpoint for `chronosd`:

- Added `chronosd/src/metrics.rs`.
- Added `render_prometheus` for `UdpRelayMetrics` counters.
- Added `serve_metrics`, a small Tokio TCP HTTP responder serving Prometheus text format.
- Added `runtime.metrics_bind` support in `configs/chronosd.toml` and `chronosd` config parsing.
- `chronosd` can now spawn a metrics endpoint alongside the UDP relay when `metrics_bind` is configured.
- Added renderer tests for the Prometheus output.

Validation after tranche 26:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count remains 76 passing tests.

## Implementation tranche 27: local networked directory API

Implemented the next logical component after relay metrics: a prototype networked directory API.

- Added `chronos-dir/src/api.rs`.
- Added a tiny line-oriented TCP API for local prototype use:
  - `UPSERT <node_id> <addr> <expires_unix>`
  - `GET <node_id> <now_unix>`
  - `PRUNE <now_unix>`
- Wired `chronos-dir` to run the API when `CHRONOS_DIR_API_BIND` is set.
- Kept the existing consensus simulation path as the default when the API bind variable is not set.
- Added tests for upsert, lookup, expiry, and prune behavior through the API command handler.

Validation after tranche 27:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 28: DPF snapshot persistence and query protocol

Implemented the next storage-focused step for `chronos-lite`:

- Extended `chronos-lite/src/dpf_store.rs` with `DpfQueryRequest` and `DpfQueryResponse` types.
- Added binary query request encoding/decoding with `CHDQP001` magic.
- Added snapshot persistence to `.chrds` files with `CHDPF001` magic.
- Added snapshot reload support that restores active epoch snapshots and advances `current_epoch` safely.
- Wired `chronos-lite` self-test to exercise encoded DPF query requests and query responses.
- Added optional `CHRONOS_LITE_DPF_DIR` load/persist behavior for local snapshot persistence.
- Added tests for query request round-trip and snapshot persist/reload/query.

Validation after tranche 28:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 29: live TDM send pacing

Integrated the TDM/pacing primitive into the live `chronosd` UDP relay send path:

- Added `runtime.tdm_slot_ms` to `configs/chronosd.toml` and the `chronosd` config parser.
- `ChronosUdpRelay` now supports `enable_tdm_pacing(Duration)`.
- The live UDP send path sleeps for the configured slot width before each outbound send when pacing is enabled.
- Added a test proving a forwarded packet plus ACK consume two paced send slots.

Validation after tranche 29:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 30: traffic-analysis harness primitives

Implemented a deterministic traffic-analysis measurement harness in `chronos-core`:

- Added `chronos-core/src/traffic_analysis.rs`.
- Added `PacketObservation` and `TrafficShapeReport`.
- Added `analyze_observations` to measure packet-count, unique packet lengths, mean interval, maximum interval jitter, constant-length status, and constant-interval status.
- Added `synthesize_constant_rate_trace` to produce controlled constant-rate traces for tests and future simulations.
- Added tests proving constant-rate/constant-length traces pass and variable length/timing traces are detected.

Validation after tranche 30:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 31: WASM bindings, data-plane/NIC prototypes, and app scaffolding

Implemented several remaining prototype/scaffolding items:

- Added `chronos-wasm/src/bindings.rs` with wasm-bindgen exports:
  - `chronos_wasm_version`
  - `chronos_plan_tdm_slots`
  - `chronos_secure_cell_self_test`
- Updated `chronos-wasm` to build as `cdylib`/`rlib` and depend on `wasm-bindgen` plus `chronos-core`.
- Added `chronosd/src/dataplane_probe.rs`, a deterministic data-plane selection probe for Tokio UDP, io_uring prototype, and AF_XDP prototype modes.
- Added `chronosd/src/nic_control.rs`, which validates/builds ethtool Toeplitz RSS hkey argument vectors without executing privileged operations.
- Wired data-plane probe logging into `chronosd` startup and Toeplitz hkey argument construction into the RSS salt shuffler simulation boundary.
- Added web integration notes in `apps/chronos-web/README.md` for the new WASM exports.
- Added mobile scaffolding notes in `apps/chronos-mobile/ios/README.md` and `apps/chronos-mobile/android/README.md`.

Validation after tranche 31:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 32: directory persistence, config fuzz targets, and web UI loader

Implemented several additional logical next steps:

- Added directory-store persistence (`save_to_file`/`load_from_file`) and wired optional `CHRONOS_DIR_DB` loading/saving into the local directory API path.
- Added cargo-fuzz targets for `chronosd` config parsing, `chronos-lite` config parsing, and directory API command parsing.
- Added a non-invasive WASM loader panel to `apps/chronos-web/index.html` that attempts to load `./pkg/chronos_wasm.js` and call the real wasm-bindgen exports, falling back gracefully when the bundle is not built.

Validation after tranche 32:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 33: signed records, DPF point shares, session manager, and README reality note

Implemented another set of remaining prototype boundaries:

- Added `chronos-core/src/session.rs`, a session/circuit lifecycle manager with open, touch, close, rekey, idle expiry, and tests.
- Added two-server XOR point-function share generation to `chronos-lite` DPF storage as a concrete privacy-oriented DPF primitive for local tests.
- Added signed/authenticated relay record scaffolding in `chronos-dir/src/signed_record.rs` using a keyed SHA-256 MAC boundary for local validator authorization tests. This is not yet public-key validator signing.
- Added a README "Current implementation reality" note to reduce target-spec overclaiming.
- Added mobile and web scaffolding in previous tranches and kept them validated.

Validation after tranche 33:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 34: session enforcement, Ed25519 records, route persistence, and traffic CSV

Implemented additional remaining items from the feasible list:

- Added live relay session enforcement mode: route packets can be rejected with typed `NoSession` errors unless their stream was installed by a CHS7 session.
- Added `StaticRouteTable` save/load helpers and tests for route table persistence.
- Replaced the directory signed-record scaffold with Ed25519 signatures using `ed25519-dalek`.
- Added traffic observation CSV export/import helpers and round-trip tests.
- Added tests proving session enforcement rejects unauthorized route packets.

Validation after tranche 34:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current test count: 105 passing tests.

## Implementation tranche 35: consensus prototype, multi-server PIR, io_uring/AF_XDP planning, and additional hardening

Implemented another group of high-difficulty prototype boundaries:

- Added `chronos-dir/src/consensus_store.rs`: Ed25519 validator votes, quorum certificates, threshold commit into `DirectoryStore`, and tests for quorum commit, insufficient quorum, and tampered-record rejection.
- Added multi-server PIR evaluation in `chronos-lite/src/dpf_store.rs`, combining two DPF point-function shares against two independently evaluated storage engines and rejecting snapshot-root mismatches.
- Added `chronosd/src/io_uring_proto.rs` and `chronosd/src/af_xdp_proto.rs` as explicit data-plane planning boundaries for io_uring and AF_XDP modes, with tests.
- Added route/session enforcement, Ed25519 signed records, static route persistence, traffic CSV import/export, and session lifecycle work in previous tranches and kept them validated.
- Added README implementation-reality language to reduce target-spec overclaiming.

Validation after tranche 35:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All four validation commands pass. Current workspace test count: 109 passing tests.

## Implementation tranche 36: Chutney-like nettest harness

Added a local multi-process smoke-test harness:

- Added `tools/chronos-nettest` as a workspace binary.
- The harness spawns two local `chronosd` relay processes with static routes.
- It sends one encrypted CRP7 shard packet through sender -> relay1 -> relay2 -> receiver.
- It verifies receiver delivery and sender ACK behavior.
- It can be run manually with `cargo run -p chronos-nettest`.

This harness is not run by the standard unit-test suite because it spawns nested `cargo run -p chronosd` processes, but it compiles in workspace checks.

## Implementation tranche 37: advanced implementation plans for remaining production-only items

Added detailed implementation plans for the remaining hard production areas:

- `docs/implementation-plans/production_pir_plan.md`
- `docs/implementation-plans/io_uring_plan.md`
- `docs/implementation-plans/af_xdp_plan.md`
- `docs/implementation-plans/nic_rss_netlink_plan.md`
- `docs/implementation-plans/browser_runtime_plan.md`
- `docs/implementation-plans/mobile_plan.md`

These plans separate what can be implemented in the repo from what requires hardware, browsers, mobile SDKs, external review, or privileged environments.

## Implementation tranche 38: internal security validation plan, threat model, crypto spec, test vector, and trace collection

Implemented the internal validation program requested for cryptographic and anonymity/privacy readiness:

- Added `docs/SECURITY_VALIDATION_PLAN.md` covering cryptographic review, protocol review, implementation audit, fuzzing plan, side-channel review scope, and threat-model validation.
- Added `docs/spec/CHRONOS-CRYPTO-SPEC.md` documenting the implemented CHR7 secure cell, CHS7 handshake, hybrid route secret derivation, RTE7 route layer, CRP7 relay packet, and key storage behavior.
- Added `docs/threat-model.md` distinguishing supported claims from unsupported/target-spec anonymity claims.
- Added `docs/test-vectors/crp7_data_packet_v1.json` plus a Rust test that verifies the documented CRP7 data-packet vector.
- Extended `tools/chronos-nettest` to collect packet observations, write CSV traces under `target/chronos-traces/`, and print a traffic-shape report.
- Added `scripts/static_audit.py` and `scripts/validation_pass.sh` for repeatable internal validation.
- Ran the validation pass three consecutive times cleanly. The static audit reports review warnings for unwrap/expect usage, largely in tests, but no hard failures for `unsafe`, `todo!`, `unimplemented!`, or `dbg!`.

Validation command run three times:

```bash
bash scripts/validation_pass.sh
```

Each pass runs:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 scripts/static_audit.py
```

All three passes completed successfully. Current normal workspace test count: 109 passing tests.

## Implementation tranche 39: pre-audit critical finding remediations

Addressed the internal pre-audit findings supplied for CHS7/CHR7/RTE7/PoW:

- **PFS remediation:** live `chronosd` CHS7 now generates per-session ephemeral X25519 and ML-KEM-768 key material for server hellos and stores pending ephemeral handshakes per source. Static node keys are no longer the live session ECDH/KEM secrets in the relay handshake path.
- **Constant-time confirmation:** CHS7 key confirmation now checks exact tag length and uses `subtle::ConstantTimeEq` instead of short-circuiting vector equality.
- **CHR7 reserved-byte authentication:** secure-cell reserved bytes are included in AEAD AAD; reserved-byte mutation now fails authentication instead of creating unauthenticated trailing space.
- **Route packet constant-size relay invariant:** CRP7 route packets now pad route payloads to the fixed relay payload size, and route decoding trims by the internal RTE7 declared length.
- **PoW token hardening:** CHS7 PoW challenges now carry a source-bound token; live relay verification reconstructs the token from the sender address and server secret before accepting a solution.
- **Strict handshake lengths:** CHS7 server hello and client key share parsers now require exact ML-KEM/X25519 payload sizes and reject trailing garbage.

Validation after tranche 39:

```bash
bash scripts/validation_pass.sh
```

The pass runs formatting, workspace check, workspace tests, strict clippy, and static audit. It completed successfully. Current normal workspace test count: 109 passing tests.
