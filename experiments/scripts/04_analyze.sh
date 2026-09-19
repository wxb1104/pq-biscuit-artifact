#!/usr/bin/env bash
# Step 4 - analysis, curve fitting and paper figures.
# Reads the raw CSVs in data/ and writes derived CSV/JSON summaries and the
# figures to figures/. Requires Python 3 with pandas, numpy and matplotlib.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$HERE/common.sh"

python3 - <<'PY'
import importlib, sys
missing = [m for m in ("pandas", "numpy", "matplotlib") if importlib.util.find_spec(m) is None]
if missing:
    sys.exit("Missing Python packages: " + ", ".join(missing) +
             "\nInstall with:  python3 -m pip install pandas numpy matplotlib")
print("[04] python dependencies OK")
PY

cd "$EXP_DIR"
python3 calibrate_e55.py        # fig9 size_vs_n, fig10 full_latency (+capacity_e55.csv)
python3 analyze_mixed_e55.py    # fig11 mixed_chains      (+e55_mixed_summary.json)
python3 analyze_hybrid_e55.py   # fig12 hybrid_size, fig13 hybrid_latency
python3 analyze_formal_e56.py   # fig14 verify_avx2_portable, fig15 sign_phases, fig16 fnlen
python3 analyze_e6.py           # fig17 fidelity, fig18 pregen, fig19 profiles
echo "[04] analysis complete; figures in $FIG"
ls -1 "$FIG"
