#!/usr/bin/env bash
# Reproducible CHRONOS mix / FEC experiment runner.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

OUT_DIR="${CHRONOS_EXPERIMENT_OUT:-artifacts/experiments}"
mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

echo "==> mix-sweep"
CHRONOS_NETTEST_MODE=mix-sweep CHRONOS_NETTEST_PACKETS="${CHRONOS_NETTEST_PACKETS:-128}" \
  cargo run -q -p chronos-nettest | tee "$OUT_DIR/mix_sweep_${STAMP}.csv"

echo "==> fec-compare"
CHRONOS_NETTEST_MODE=fec-compare \
  cargo run -q -p chronos-nettest | tee "$OUT_DIR/fec_compare_${STAMP}.csv"

echo "==> leak-audit"
CHRONOS_NETTEST_MODE=leak-audit CHRONOS_NETTEST_PACKETS="${CHRONOS_LEAK_PACKETS:-1000}" \
  cargo run -q -p chronos-nettest | tee "$OUT_DIR/leak_audit_${STAMP}.txt"

echo "Wrote experiment artifacts under $OUT_DIR"
