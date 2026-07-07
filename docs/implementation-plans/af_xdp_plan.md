# Real AF_XDP UMEM/ring I/O implementation plan

## Goal

Implement a real AF_XDP data path for `chronosd` on supported Linux hosts while preserving CRP7 packet semantics.

## Current state

Implemented today:

- `af_xdp_proto.rs` planning boundary.
- UMEM sizing calculation.
- Interface preference detection.

Not implemented:

- AF_XDP socket creation.
- UMEM allocation/registration.
- fill/completion/RX/TX rings.
- XDP program loading/attachment.
- packet forwarding through rings.

## Stage 1 — Decide dependency strategy

Options:

1. Use `libbpf-rs` + AF_XDP bindings.
2. Use a dedicated AF_XDP crate if maintained.
3. Write minimal FFI bindings.

Recommendation:

Start with `libbpf-rs` or a maintained AF_XDP crate. Avoid custom FFI unless necessary.

Validation gate:

- Feature-gated compile on Linux.
- Non-Linux builds unaffected.

## Stage 2 — Feature gate and capability probe

Add feature:

```toml
[features]
af-xdp-dataplane = [...]
```

Probe:

- kernel supports XDP,
- interface exists,
- driver mode vs generic mode,
- required capabilities present.

Validation gate:

- Probe returns structured unsupported errors.
- No privileged action unless explicitly requested.

## Stage 3 — UMEM design

Define:

- frame size: 4096 initially,
- frame count based on config,
- headroom and payload offsets,
- safe descriptor state.

Reuse current `UmemFrameDescriptor` ideas where possible.

Validation gate:

- UMEM allocation tests where feature/hardware available.
- Layout assertions.

## Stage 4 — Ring lifecycle

Implement:

- fill ring population,
- RX ring polling,
- TX ring submission,
- completion ring reclaim,
- backpressure if TX unavailable.

Validation gate:

- ring accounting test under mocked ring if possible.
- hardware integration test gated/ignored by default.

## Stage 5 — XDP program attachment

Implement:

- attach XDP program to redirect packets into AF_XDP socket,
- detach on shutdown,
- cleanup on error.

Validation gate:

- dry-run attach plan test.
- manual hardware test instructions.

## Stage 6 — Relay integration

Implement `DatagramDataPlane` for AF_XDP.

Validation gate:

- CRP7 relay handler receives datagrams from AF_XDP buffers.
- Packet parser errors do not leak buffers.

## Stage 7 — Safety and cleanup

Must handle:

- Ctrl-C shutdown,
- interface disappearance,
- ring exhaustion,
- malformed packet drops,
- XDP detach cleanup.

Validation gate:

- cleanup tests for simulated failure paths.

## Risks

- Hardware-specific.
- Privileged.
- Unsafe memory management.
- Kernel and NIC driver variations.

## Definition of done

- Feature-gated AF_XDP path compiles.
- Capability probe implemented.
- UMEM/rings operational on supported host.
- Relay can forward packets through AF_XDP path.
- Cleanup and metrics implemented.
- Manual hardware test documented.
