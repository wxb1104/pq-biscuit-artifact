#!/usr/bin/env bash
# Apply a network condition to the testbed.
# usage: bash netbed_set.sh [rtt_ms] [loss_pct] [rate]
#   rtt_ms : target round-trip time in ms (delay split symmetrically, default 0)
#   loss_pct: independent Bernoulli loss on the CLIENT veth egress only (default 0)
#   rate   : "unlim" or a tc rate, e.g. 1mbit / 46kbit (default unlim)
# Must run as root.
set -euo pipefail

NS_S=nbS; NS_C=nbC; VS=vS; VC=vC
RTT="${1:-0}"
LOSS="${2:-0}"
RATE="${3:-unlim}"

HALF="$(awk -v r="$RTT" 'BEGIN{ printf "%.3f", r/2.0 }')"

set_qdisc () {
  local ns="$1" dev="$2" loss="$3"
  ip netns exec "$ns" tc qdisc del dev "$dev" root 2>/dev/null || true
  if [ "$RATE" != "unlim" ]; then
    # Shaper first (root), then delay/loss as its child. Placing netem at the
    # root with its large default queue (limit 1000) lets a sustained large-token
    # burst buffer-bloat (cwnd inflates) and then hit the small tbf tail-drop
    # buffer, causing retransmission storms. Shaping first pins cwnd to the rate
    # and the child netem only has to hold a BDP-sized number of in-flight packets.
    ip netns exec "$ns" tc qdisc add dev "$dev" root handle 1: \
        tbf rate "$RATE" burst 32768 latency 2000ms
    ip netns exec "$ns" tc qdisc add dev "$dev" parent 1:1 handle 2: \
        netem delay "${HALF}ms" loss "${loss}%" limit 30
  else
    ip netns exec "$ns" tc qdisc add dev "$dev" root handle 1: \
        netem delay "${HALF}ms" loss "${loss}%"
  fi
}

# server side: symmetric delay, no loss
set_qdisc "$NS_S" "$VS" "0"
# client side egress: symmetric delay + the single loss point
set_qdisc "$NS_C" "$VC" "$LOSS"

echo "[netbed_set] rtt=${RTT}ms (half=${HALF}ms x2), loss=${LOSS}% (client egress), rate=$RATE"
