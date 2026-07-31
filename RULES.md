# CHRONOS — Repository Rules

Conventions every change must follow. These exist so the repo stays
self-contained, internally consistent, and honest about its maturity.

## 1. Documentation wording
- **Define our terms independently.** Every CHRONOS-specific term (TDM,
  SHARD-Stream, CRP7/CHS7/RTE7, DPF-PIR, escape architecture) is defined
  in-repo the first time it appears. Do **not** assume the reader knows Tor,
  mixnets, Sphinx, Loopix, Nym, HORNET, or any external system.
- **No competitive scorecards.** Do not publish "X vs CHRONOS" comparison
  tables. Prior art may be named in a neutral "Prior Art" note, but never
  rated against CHRONOS.
- **No absolute or unverifiable claims.** Ban "100% DoS Immunity",
  "unassailable", "Flawless", "eradicates", "0% tag linkability",
  "10/10 feasibility". Every claim traces to a test vector, benchmark, or a
  clearly-labelled *design target*.
- **State maturity honestly.** Top-level docs state the real status
  (prototype / reference / production) using the same wording as
  `docs/IMPLEMENTATION_STATUS.md`.
- **No dangling references.** Never link or name a repo/package that does not
  exist yet. Fill the link or remove it.

## 2. Naming
- Crate/binary names use hyphens: `chronos-core`, `chronos-dir`,
  `chronos-lite`, `chronos-wasm`, `chronos-sys-dataplane`, `chronos-relay`
  (the relay daemon; historically `chronosd`).
- Protocol identifiers (CRP7, CHS7, RTE7, DPF) are self-defined in
  `docs/PROTOCOLS.md` and listed there in one place.
- Files/modules are `snake_case`; public types are `PascalCase`.

## 3. Module & dependency boundaries
- `chronos-core` is the only `no_std` crate and the single source of truth
  for crypto + protocol primitives.
- `chronos-sys-dataplane` is the only crate allowed `unsafe` (kernel-bypass).
  Everything else talks to it through a safe interface.
- Minimize external dependencies. No new dependency without a one-line
  justification in the PR.
- One routing layer is canonical (`route_layer` orchestrates; `sphinx`
  defines the wire header). Don't expose both as the public path.

## 4. Code style (enforced by CI, not memory)
- `rustfmt.toml` is authoritative; run `cargo fmt` before committing.
- `#![deny(warnings)]` in CI via clippy (`-D warnings`).
- `#![deny(unsafe_code)]` outside the HAL crate; `scripts/static_audit.py`
  verifies this in CI.
- No glob `pub use *::*` re-exports at a crate root — enumerate the public
  API explicitly.

## 5. Process
- Every change goes through a PR; CI (fmt + clippy + test + static audit) must
  be green.
- Tracking lives in **GitHub Issues**, not in `FULL_TODO.md`. The TODO file is
  a release checklist, not a backlog.
- Commits follow `area: short summary` (e.g. `chronos-relay: fix replay window
  under clock skew`).
- Build artifacts (tarballs, `.VSCodeCounter/`) are never committed; release
  binaries are published as GitHub Release assets.
