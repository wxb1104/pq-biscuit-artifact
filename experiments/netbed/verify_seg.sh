#!/usr/bin/env bash
# Verify E-N5 segment counting after disabling veth offloads.
set -uo pipefail
PROOT=/mnt/e/pqc+zhengshu/biscuit-pq
NB=$PROOT/experiments/netbed
CRATE=$PROOT/impl/pqbiscuit; BIN=$CRATE/target/release
TOK=$NB/tokens; KEY=$NB/rootkeys
IP_S=10.99.0.1; IP_C=10.99.0.2; PORT=8080
cleanup(){ ip netns exec nbS pkill -f netbed_server 2>/dev/null || true
  bash <(tr -d '\r' < "$NB/netbed_down.sh") || true; }
trap cleanup EXIT
bash <(tr -d '\r' < "$NB/netbed_up.sh")
ip netns exec nbS taskset -c 10 "$BIN/netbed_server" --addr "$IP_S:$PORT" --keys "$KEY" >/tmp/v_srv.log 2>&1 &
for i in $(seq 1 50); do ip netns exec nbC bash -c "exec 3<>/dev/tcp/$IP_S/$PORT" 2>/dev/null && break; sleep 0.2; done
echo "server up"
for spec in "ed25519 20 3" "slhdsa128f 20 345"; do
  set -- $spec; prof=$1; n=$2; expected=$3
  bash <(tr -d '\r' < "$NB/netbed_set.sh") 1 0 unlim >/dev/null
  rm -f /tmp/vseg.pcap
  ip netns exec nbS timeout 4 tcpdump -i vS -nn -w /tmp/vseg.pcap "host $IP_C and tcp port $PORT" >/dev/null 2>&1 &
  tp=$!; sleep 0.6
  ip netns exec nbC taskset -c 6 "$BIN/netbed_client" latency --server "$IP_S:$PORT" \
    --tokens "$TOK" --profile "$prof" --n "$n" --mode new --samples 1 --nowarm true \
    --rtt 1 --loss 0 --out /tmp/vlat.csv >/dev/null 2>&1 || true
  wait "$tp" 2>/dev/null || true
  up=$(ip netns exec nbS tcpdump -nn -r /tmp/vseg.pcap "src host $IP_C" 2>/dev/null | grep -c 'length [1-9][0-9]*' || true)
  echo "$prof n=$n: measured up=${up:-0} expected=$expected"
done
