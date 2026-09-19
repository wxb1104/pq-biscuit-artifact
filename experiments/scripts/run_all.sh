#!/usr/bin/env bash
# End-to-end reproduction: primitives -> AVX2 measurement -> portable
# measurement -> analysis/figures. Run from any working directory.
#
#   bash scripts/run_all.sh
#
# Wall-clock timings are hardware dependent; serialized sizes and pass/fail
# outcomes are not. On Linux the harnesses are pinned to one core (PIN_CORE,
# default 2); on macOS pinning is skipped.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$HERE/01_primitives.sh"
bash "$HERE/02_measure_avx2.sh"
bash "$HERE/03_measure_portable.sh"
bash "$HERE/04_analyze.sh"
echo "ALL_STEPS_DONE"
