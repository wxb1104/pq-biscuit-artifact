#!/usr/bin/env bash
# Step 2 - end-to-end token measurements with the DEFAULT AVX2 PQClean kernels.
# Produces all e55_*, e56_*_avx2 and e6_* raw CSVs used by the paper:
#   e55_bench         -> e55_token_size.csv, e55_latency.csv
#   e55_hybrid_bench  -> e55_hybrid_size.csv, e55_hybrid_latency.csv
#   e55_mixed         -> e55_mixed.csv
#   e6_fidelity       -> e6_fidelity.csv   (exits non-zero if any check FAILs)
#   e6_pregen         -> e6_pregen.csv
#   e6_profiles       -> e6_profiles_size.csv, e6_profiles_verify.csv
#   e56_formal avx2   -> e56_latency_avx2.csv, e56_size_avx2.csv, e56_fnlen_avx2.csv
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$HERE/common.sh"
export CARGO_TARGET_DIR="$AVX2_TARGET"

cd "$IMPL"
cargo build --release \
  --bin e55_bench --bin e55_hybrid_bench --bin e55_mixed \
  --bin e6_fidelity --bin e6_pregen --bin e6_profiles --bin e56_formal

runbin e55_bench
runbin e55_hybrid_bench
runbin e55_mixed
runbin e6_fidelity
runbin e6_pregen
runbin e6_profiles
runbin e56_formal avx2
echo "[02] AVX2 measurements complete"
