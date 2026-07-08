#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi
rm -rf "$HOME"/.cargo/registry/src/index.crates.io-*/rustversion-1.0.23 "$HOME"/.cargo/registry/cache/index.crates.io-*/rustversion-1.0.23.crate 2>/dev/null || true
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 scripts/static_audit.py
