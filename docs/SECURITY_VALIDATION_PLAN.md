# CHRONOS security validation plan

This document defines the repeatable validation process for the current CHRONOS prototype. It is **not** a substitute for an independent third-party cryptographic audit, but it provides a structured internal review workflow.

## Scope

Validated areas:

- core packet parsing and serialization,
- AEAD secure cells,
- route layer,
- CHS7 handshake,
- relay packet handling,
- DPF/PIR prototype code,
- directory prototype code,
- `chronosd` relay runtime,
- `chronos-lite` local storage/UDP code,
- WASM binding surface,
- nettest harness.

## Review categories

### 1. Cryptographic review

Checklist:

- no placeholder crypto exported as production,
- AEAD used for confidentiality/integrity,
- route secrets derived from ML-KEM-768 + X25519 where claimed,
- transcript binding exists for CHS7,
- downgrade checks exist,
- key confirmation exists,
- replay protection exists.

### 2. Protocol review

Checklist:

- magic/version fields checked,
- packet lengths checked,
- unsupported packet types rejected,
- route commands typed,
- replay/duplicate handling present,
- error packets typed where used.

### 3. Implementation audit

Checklist:

- no `unsafe`,
- no `todo!`, `unimplemented!`, or `dbg!`,
- no unexpected `panic!` in non-test code,
- no `unwrap`/`expect` in non-test code unless justified,
- strict clippy passes,
- tests pass.

### 4. Fuzzing plan

Current fuzz target scaffolds:

- `relay_packet`,
- `route_packet`,
- `handshake_packet`,
- `secure_cell`,
- `chronosd_config`,
- `chronos_lite_config`,
- `directory_api`.

Run examples:

```bash
cd fuzz
cargo fuzz run relay_packet
cargo fuzz run route_packet
cargo fuzz run handshake_packet
cargo fuzz run secure_cell
```

Continuous fuzzing still requires CI infrastructure.

### 5. Side-channel review

Current internal scope:

- check for obvious variable-time secret-dependent branching in newly added code,
- document that full side-channel review remains external work.

### 6. Threat-model validation

Current internal scope:

- document implemented protections and remaining gaps,
- keep README/status honest,
- avoid production anonymity claims until independently evaluated.

## Pass/fail policy

A validation pass must run:

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 scripts/static_audit.py
```

A release candidate requires three consecutive clean passes.
