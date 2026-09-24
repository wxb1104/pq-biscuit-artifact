#!/usr/bin/env bash
# Quick tau=0 sanity check: steady-state per-request server verification time
# vs end-to-end latency, to cross-check the E55/E56 micro-benchmarks.
# Run as root; assumes netbed_up already done (starts server if needed).
set -euo pipefail
PROOT=/mnt/e/pqc+zhengshu/biscuit-pq
CRATE=$PROOT/impl/pqbiscuit
NB=$PROOT/experiments/netbed
DATA=$PROOT/experiments/data
TOK=$NB/tokens; KEY=$NB/rootkeys
BIN=$CRATE/target/release
IP_S=10.99.0.1; PORT=8080

if ! ip netns list 2>/dev/null | grep -q nbS; then
  echo "== testbed missing, bringing up =="
  bash <(tr -d '\r' < "$NB/netbed_up.sh")
fi
if [ ! -f "$TOK/ed25519_n20.tok" ]; then
  ( cd "$CRATE" && "$BIN/netbed_gen" )
fi
bash <(tr -d '\r' < "$NB/netbed_set.sh") 0 0 unlim

if ! pgrep -f 'target/release/netbed_server' >/dev/null; then
  ip netns exec nbS taskset -c 10 "$BIN/netbed_server" \
    --addr "$IP_S:$PORT" --keys "$KEY" >/tmp/nbsrv.log 2>&1 &
  echo $! >/tmp/nbsrv.pid
  for i in $(seq 1 100); do
    ip netns exec nbC bash -c "exec 3<>/dev/tcp/$IP_S/$PORT" 2>/dev/null && break
    sleep 0.2
  done
fi

rm -f "$DATA/net_quick0.csv"
for prof in ed25519 fndsa512 slhdsa128f; do
  ip netns exec nbC taskset -c 6 "$BIN/netbed_client" latency \
    --server "$IP_S:$PORT" --tokens "$TOK" --profile "$prof" --n 20 \
    --mode ka --samples 1000 --rtt 0 --loss 0 --out "$DATA/net_quick0.csv"
done

python3 - "$DATA/net_quick0.csv" <<'PY'
import sys, pandas as pd
df = pd.read_csv(sys.argv[1])
df = df[df.status==200]
for prof,g in df.groupby('profile'):
    tv=g.verify_ns/1e3; tt=g.total_ns/1e3
    print(f"{prof:12s} n=20 ka tau=0  "
          f"t_v P50={tv.median():8.1f}us  P95={tv.quantile(.95):8.1f}us | "
          f"total P50={tt.median():8.1f}us  P95={tt.quantile(.95):8.1f}us | "
          f"rho={tv.median()/tt.median():.3f}")
PY
