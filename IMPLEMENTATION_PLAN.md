# CHRONOS implementation plan

This plan tracks the remaining work needed to move the repository from validated primitives and localhost tests toward a usable multi-node prototype and, later, a production-quality CHRONOS implementation.

## Validation policy

Every implementation tranche must pass:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Phase 1 — Local multi-node relay prototype

1. [done] Add a real async UDP relay loop to `chronosd` using the existing `RelayPacketHandler`.
2. [done] Add static route-table support for stream ID to socket address forwarding.
3. [done] Add integration tests for sender -> chronosd relay -> receiver using both shard and route packets, plus a two-hop relay test.
4. [done] Add ACK and error response behavior for forwarded and rejected packets. ACKs and NO_ROUTE error packets are implemented and tested.
5. [done] Add config/env wiring for local relay bind address and static routes. `CHRONOSD_UDP_RELAY_BIND`, `CHRONOSD_STATIC_ROUTES`, and `configs/chronosd.toml` runtime settings are implemented.

## Phase 2 — Runtime key management and handshake

1. [done] Add node key generation for X25519 and ML-KEM-768.
2. [done] Persist node keys with safe file permissions.
3. [done] Define handshake packets: server hello, client key share, key confirmation, and error.
4. [done] Bind ML-KEM + X25519 into a transcript hash with suite/version downgrade protection.
5. [done] Add deterministic handshake tests and failure tests for malformed packets, downgrade attempts, wrong packet types, and bad confirmations.

## Phase 3 — Route processing in live relay runtime

1. [done] Map route packets to hop/session secrets.
2. [done] Peel one route layer in the relay runtime.
3. [done] Execute typed route commands: forward, deliver local, drop, reply.
4. [done] Maintain route replay caches with expiry and size bounds.
5. [done] Add local 3-hop tests that prove hop-by-hop packet-ID blinding and delivery.

## Phase 4 — Robust protocol validation

1. [partial] Fuzz `SecureShardCell`, `RelayPacket`, `LayeredRoutePacket`, and CHS7 handshake packets. Config parser fuzz targets remain.
2. Add property tests for any-10-of-16 erasure recovery.
3. Add packet loss/reorder/duplicate tests.
4. Add benchmarks for AEAD, erasure coding, route peeling, and UDP relay throughput.

## Phase 5 — Production service hardening

1. Replace dev env routing with full config-file routing.
2. Add structured logging and metrics.
3. Add graceful shutdown and queue/backpressure limits.
4. Add service files, signed releases, and safer bootstrap.
5. Add persistence for keys, peer state, directory state, and storage state.

## Phase 6 — Larger spec components

1. Implement real DPF/PIR storage.
2. Implement directory consensus and `.chr` records.
3. Implement browser/WASM runtime and web UI integration.
4. Implement `chronosd` io_uring and later AF_XDP data planes.
5. Implement traffic shaping, constant-rate/TDM scheduling, and adversarial traffic-analysis tests.


## Cross-phase completed additions

- [done] Chutney-like local multi-process nettest harness in `tools/chronos-nettest`.
- [partial] io_uring and AF_XDP planning boundaries exist; actual kernel I/O remains.
- [partial] two-server PIR evaluation across storage engines exists; production cryptographic PIR remains.
- [partial] Ed25519 quorum-backed directory commit prototype exists; full HotStuff/BFT remains.
- [done] traffic-analysis CSV import/export helpers exist.
- [done] static route table persistence helpers and tests exist.
- [done] Ed25519 signed directory relay records replace the earlier keyed-MAC scaffold.
- [done] live relay session enforcement mode rejects route packets without CHS7-installed sessions.
- [partial] signed peer-record authorization scaffold exists with keyed MAC; public-key validator signatures remain.
- [partial] two-server XOR point-function DPF primitive exists; production PIR remains.
- [partial] session/circuit lifecycle manager exists in core; full live relay session policy remains.
- [done] directory-store persistence with optional `CHRONOS_DIR_DB` load/save.
- [done] config parser fuzz targets for chronosd, chronos-lite, and directory API command parsing.
- [partial] web UI attempts to load real WASM exports and falls back to demo mode.
- [partial] web and mobile app scaffolding docs exist; full UI/native clients remain.
- [partial] NIC RSS Toeplitz ethtool argument construction exists; privileged netlink/ethtool execution remains.
- [partial] data-plane probe prototypes exist for Tokio UDP/io_uring/AF_XDP; actual io_uring/AF_XDP I/O remains.
- [partial] WASM bindings exist for version, TDM planning, and secure-cell self-test; browser transport bindings remain.
- [partial] deterministic traffic-analysis harness exists for length/timing regularity; adversarial classifier tests remain.
- [partial] DPF snapshot persistence and query request encoding exist; true multi-server DPF/PIR privacy remains.
- [done] cargo-fuzz target scaffolding for core parsers.
- [done] PoW admission boundary exists and live CHS7 handshake enforcement is wired for the local prototype.
- [done] TDM scheduler primitive exists and live `chronosd` UDP send pacing is wired.
- [partial] local directory store and a local TCP directory API exist; consensus-backed/network-authenticated directory remains.
- [done] bounded queue primitive exists and live relay outbound queue/backpressure integration is wired.
- [done] protocol format notes added in `PROTOCOLS.md`.
- [done] typed CRP7 relay error codes for NO_ROUTE/DROP and full error-code enum.
- [done] relay observability counters and a Prometheus-compatible metrics endpoint exist in `chronosd`.
- [done] `chronosd` config loader for the existing `configs/chronosd.toml` subset.
- [done] `chronosd` runtime key loading/generation through `NodeKeyMaterial`.
- [done] bounded route replay cache expiry and size eviction.
- [done] live route peeling in `chronosd` with static/session-like route-hop secrets.
- [done] CHS7 handshake exists in core and live UDP relay handshake installation is wired for the local prototype.
- [partial] parser hardening is covered by deterministic malformed-input tests and cargo-fuzz/libFuzzer targets for core packet parsers; config parser fuzz targets remain.
- [not started] PoW admission integration into live handshake/relay.
- [not started] WASM bindings.


## Recently completed follow-up work

- [done] Live CHS7 handshake in `chronosd` installs route-hop secrets into the UDP relay session table.
- [done] Three-hop route-peeling relay test covers live route command execution through `chronosd`.
- [done] `chronosd` config file support and runtime key loading/generation.
