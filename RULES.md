# CHRONOS Repository Rules

These conventions keep CHRONOS self-contained, internally consistent, and
honest about its maturity.

## Documentation

- Define CHRONOS terms in this repository before relying on them. Do not assume
  outside terminology or systems are familiar to the reader.
- Do not publish competitive scorecards or comparison tables.
- Do not make absolute or unverifiable privacy, security, performance, or
  deployment claims. A claim must point to a test, benchmark, or clearly marked
  design target.
- State maturity precisely: implemented and tested, prototype, simulation,
  planned, or unsupported. Top-level documents must match `README.md`.
- Do not leave placeholder links, external dependency references, or unnamed
  future repositories in user-facing documentation.

## Naming and public API

- Crate and binary names use hyphens. Rust modules use `snake_case`; public
  types use `PascalCase`.
- Protocol identifiers are defined once in `docs/PROTOCOLS.md`.
- `route_layer` is the supported route packet path. The optional onion-header
  demonstration is feature-gated as a simulation and must never be described as
  production cryptography.
- Public AEAD construction APIs must guide callers toward stateful nonce or
  sequence allocation. Explicit nonce/identifier APIs need a documented reason
  and a test-vector or externally managed allocator use case.

## Module and dependency boundaries

- `chronos-core` is the source of truth for protocol primitives. Its no-`std`
  claim applies only to modules built by `--no-default-features`.
- `chronos-sys-dataplane` is the only crate allowed to contain `unsafe` code.
  Other crate roots declare `#![deny(unsafe_code)]`.
- New dependencies need a one-line justification in the pull request.
- No glob re-exports at a crate root; enumerate public APIs explicitly.

## Required validation

Run before requesting review:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo check -p chronos-core --no-default-features
python3 scripts/static_audit.py
```

## Change process

- Every change is reviewed through a pull request with passing CI.
- Do not remove tests to hide failures. Add focused regression tests for
  correctness or security fixes when practical.
- Keep commits focused and describe breaking API changes in the pull request.
- Do not commit build artifacts or credentials.
