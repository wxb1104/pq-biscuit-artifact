#!/usr/bin/env bash
# Shared setup for reproducing the PQ-Biscuit experiments.
# Sourced by the numbered scripts; not meant to be run directly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"          # .../experiments
ROOT="$(cd "$EXP_DIR/.." && pwd)"                # artifact root
IMPL="$ROOT/impl/pqbiscuit"
PQDIR="$EXP_DIR/pqbench"
DATA="$EXP_DIR/data"
FIG="$EXP_DIR/figures"

AVX2_TARGET="$ROOT/.target/avx2"
PORTABLE_TARGET="$ROOT/.target/portable"
PQ_TARGET="$ROOT/.target/pqbench"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$AVX2_TARGET}"

# Load cargo if it is installed under $HOME (no-op otherwise).
# shellcheck disable=SC1091
source "$HOME/.cargo/env" 2>/dev/null || true

mkdir -p "$DATA" "$FIG"

# Pin measurements to one physical core on Linux (taskset). On macOS taskset is
# absent and the empty PIN leaves execution unpinned.
PIN_CORE="${PIN_CORE:-2}"
if command -v taskset >/dev/null 2>&1; then
  PIN="taskset -c $PIN_CORE"
else
  PIN=""
fi

# runbin <binary-name> [args...] -- the harness binaries write to the relative
# path ../../experiments/data, so they must be launched from the impl crate dir.
runbin() {
  local bin="$1"; shift || true
  ( cd "$IMPL" && ${PIN:-} "$CARGO_TARGET_DIR/release/$bin" "$@" )
}

echo "[common] artifact root : $ROOT"
echo "[common] data dir      : $DATA"
echo "[common] target dir    : $CARGO_TARGET_DIR"
echo "[common] core pinning  : ${PIN:-none}"
