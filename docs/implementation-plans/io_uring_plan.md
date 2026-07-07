# Real kernel io_uring I/O implementation plan

## Goal

Replace or supplement Tokio UDP relay I/O with a real Linux `io_uring` data path while preserving the existing CRP7 packet semantics and relay handler logic.

## Current state

Implemented today:

- Tokio UDP relay in `chronosd`.
- `io_uring_proto.rs` planning boundary.
- Data-plane selection logic.

Not implemented:

- Actual `io_uring` rings.
- Registered buffers.
- SQPOLL setup.
- Completion queue processing.
- Integration with relay packet parser/handler.

## Stage 1 — Choose crate and feature flag

Recommended crates:

- `io-uring` for lower-level direct ring control.
- `tokio-uring` for async integration but heavier runtime changes.

Recommendation:

Use `io-uring` first for a dedicated Linux-only module.

Add feature:

```toml
[features]
io-uring-dataplane = ["dep:io-uring"]
```

Add module:

```text
crates/chronosd/src/io_uring_dataplane.rs
```

Validation gate:

- Workspace builds without feature on all platforms.
- Linux feature build compiles in CI/container.

## Stage 2 — Define data-plane trait

Add a trait independent of implementation:

```rust
pub trait DatagramDataPlane {
    fn local_addr(&self) -> Result<SocketAddr, DataPlaneError>;
    fn recv_batch(&mut self, out: &mut [ReceivedDatagram]) -> Result<usize, DataPlaneError>;
    fn send_batch(&mut self, datagrams: &[OutboundDatagram]) -> Result<usize, DataPlaneError>;
}
```

Types:

```rust
pub struct ReceivedDatagram {
    pub source: SocketAddr,
    pub len: usize,
    pub buffer_index: usize,
}

pub struct OutboundDatagram {
    pub destination: SocketAddr,
    pub bytes: Vec<u8>,
}
```

Validation gate:

- Tokio UDP implementation adapted to trait.
- Existing relay tests still pass.

## Stage 3 — Basic io_uring UDP socket

Implement:

- UDP socket creation.
- Nonblocking FD registration.
- `recvmsg` submission.
- `sendmsg` submission.
- CQE handling.

Start without registered buffers.

Validation gate:

- Local echo test using io_uring module.
- No relay integration yet.

## Stage 4 — Registered buffers

Implement:

- fixed-size receive buffers, likely `RELAY_PACKET_MAX_BYTES`.
- buffer registration.
- buffer pool lifecycle.
- safe ownership model.

Validation gate:

- Buffer reuse tests.
- No double-use of in-flight buffers.

## Stage 5 — Relay integration

Wire into `ChronosUdpRelay` behind config:

```toml
preferred_engine = "io_uring_sqpoll"
```

The relay should not care whether datagrams come from Tokio or io_uring.

Validation gate:

- Existing relay integration tests pass with Tokio.
- New Linux-only io_uring relay test passes when feature enabled.

## Stage 6 — SQPOLL

Add:

- `IORING_SETUP_SQPOLL` configuration.
- capability checks.
- fallback to non-SQPOLL if unavailable.
- clear logs and metrics.

Validation gate:

- test/capability probe does not require root unless SQPOLL is explicitly requested.

## Stage 7 — Metrics

Expose:

- submissions,
- completions,
- CQE errors,
- buffer exhaustion,
- send failures,
- recv failures.

Validation gate:

- Prometheus rendering includes io_uring counters.

## Risks

- Linux-only.
- Kernel-version-specific behavior.
- Unsafe lifecycle bugs if buffers are mishandled.
- SQPOLL permissions/capability issues.

## Definition of done

- Feature-gated io_uring module compiles.
- Local UDP relay can run on io_uring path.
- Registered buffers implemented.
- Fallback behavior documented.
- Metrics and tests exist.
