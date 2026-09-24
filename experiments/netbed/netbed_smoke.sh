#!/usr/bin/env bash
# End-to-end smoke test: up -> generate tokens -> set RTT 20ms -> server ->
# a few ka and new requests (incl. a large FN-DSA-512 n=20 token).
# Run as root. Does NOT tear the testbed down (use netbed_down.sh).
set -euo pipefail

PROOT=/mnt/e/pqc+zhengshu/biscuit-pq
CRATE=$PROOT/impl/pqbiscuit
NB=$PROOT/experiments/netbed
DATA=$PROOT/experiments/data
TOK=$NB/tokens
KEY=$NB/rootkeys
BIN=$CRATE/target/release
IP_S=10.99.0.1
PORT=8080

echo "== up =="
bash <(tr -d '\r' < "$NB/netbed_up.sh")

echo "== offline token generation (cwd=$CRATE) =="
( cd "$CRATE" && "$BIN/netbed_gen" ) 2>&1 | tee /tmp/netgen.log

echo "== set rtt=20ms loss=0 =="
bash <(tr -d '\r' < "$NB/netbed_set.sh") 20 0 unlim

echo "== start server in nbS (core 2) =="
pkill -f 'target/release/netbed_server' 2>/dev/null || true
ip netns exec nbS taskset -c 2 "$BIN/netbed_server" \
    --addr "$IP_S:$PORT" --keys "$KEY" >/tmp/nbsrv.log 2>&1 &
echo $! >/tmp/nbsrv.pid

echo "== wait for listen =="
ok=0
for i in $(seq 1 100); do
  if ip netns exec nbC bash -c "exec 3<>/dev/tcp/$IP_S/$PORT" 2>/dev/null; then ok=1; break; fi
  sleep 0.2
done
[ "$ok" = 1 ] || { echo "server did not come up"; cat /tmp/nbsrv.log; exit 1; }
echo "server up"

echo "== ka x5 ed25519 n1 =="
ip netns exec nbC taskset -c 6 "$BIN/netbed_client" latency \
  --server "$IP_S:$PORT" --tokens "$TOK" --profile ed25519 --n 1 \
  --mode ka --samples 5 --rtt 20 --loss 0 --out "$DATA/net_smoke.csv"

echo "== ka x3 fndsa512 n20 (large token) =="
ip netns exec nbC taskset -c 6 "$BIN/netbed_client" latency \
  --server "$IP_S:$PORT" --tokens "$TOK" --profile fndsa512 --n 20 \
  --mode ka --samples 3 --rtt 20 --loss 0 --out "$DATA/net_smoke.csv"

echo "== new x3 fndsa512 n20 =="
ip netns exec nbC taskset -c 6 "$BIN/netbed_client" latency \
  --server "$IP_S:$PORT" --tokens "$TOK" --profile fndsa512 --n 20 \
  --mode new --samples 3 --rtt 20 --loss 0 --out "$DATA/net_smoke.csv"

echo "== manifest (head) =="
head -6 "$NB/net_tokens_manifest.csv"
echo "..."
echo "== smoke rows =="
cat "$DATA/net_smoke.csv"
echo "== server log =="
cat /tmp/nbsrv.log
echo "SMOKE OK (testbed left up; pid $(cat /tmp/nbsrv.pid))"
