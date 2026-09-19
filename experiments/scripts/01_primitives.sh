#!/usr/bin/env bash
# Step 1 - standalone primitive benchmark (real PQClean kernels via pqcrypto-rs).
# Emits data/algostats.csv: public/secret/signature sizes and keygen/sign/verify
# median + p95 for Ed25519 and the nine NIST parameter sets.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$HERE/common.sh"

cd "$PQDIR"
CARGO_TARGET_DIR="$PQ_TARGET" cargo run --release -- "$DATA"
echo "[01] wrote $DATA/algostats.csv"
