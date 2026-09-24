#!/usr/bin/env bash
# Reset network result CSVs to header-only before a clean full run.
# The token manifest is NOT touched.
set -u
DATA=/mnt/e/pqc+zhengshu/biscuit-pq/experiments/data
cd "$DATA" || exit 1
for f in net_latency net_throughput net_segments_meas net_footprint net_calibrate; do
  if [ -f "$f.csv" ]; then
    head -n 1 "$f.csv" > "$f.csv.tmp" && mv "$f.csv.tmp" "$f.csv"
    echo "cleared $f.csv -> $(wc -l "$f.csv" | awk '{print $1}') lines (header only)"
  else
    echo "absent: $f.csv"
  fi
done
echo "manifest: $(wc -l net_tokens_manifest.csv 2>/dev/null | awk '{print $1" lines"}') (kept)"
