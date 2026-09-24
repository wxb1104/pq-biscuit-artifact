#!/usr/bin/env bash
# Bring up the two-namespace veth testbed with baseline (pass-through) qdiscs.
# Must run as root inside WSL2:  sudo bash netbed_up.sh
set -euo pipefail

NS_S=nbS
NS_C=nbC
VS=vS
VC=vC
IP_S=10.99.0.1
IP_C=10.99.0.2

# load netem / tbf / mirror modules if built as modules
modprobe sch_netem 2>/dev/null || true
modprobe sch_tbf    2>/dev/null || true
modprobe act_mirred 2>/dev/null || true

# clean any leftovers
ip netns del "$NS_S" 2>/dev/null || true
ip netns del "$NS_C" 2>/dev/null || true

ip netns add "$NS_S"
ip netns add "$NS_C"
ip link add "$VS" type veth peer name "$VC"
ip link set "$VS" netns "$NS_S"
ip link set "$VC" netns "$NS_C"

ip -n "$NS_S" link set lo up
ip -n "$NS_C" link set lo up
ip -n "$NS_S" addr add "${IP_S}/24" dev "$VS"
ip -n "$NS_C" addr add "${IP_C}/24" dev "$VC"
ip -n "$NS_S" link set "$VS" mtu 1500 up
ip -n "$NS_C" link set "$VC" mtu 1500 up

# Disable all segmentation/aggregation/checksum offloads so that tcpdump on the
# veth sees real MSS-sized IP segments (otherwise veth GSO/GRO/TSO coalesces many
# segments into super-packets and E-N5 under-counts). Best-effort on veth.
if command -v ethtool >/dev/null 2>&1; then
  ip netns exec "$NS_S" ethtool -K "$VS" rx off tx off sg off tso off gso off gro off lro off 2>/dev/null || true
  ip netns exec "$NS_C" ethtool -K "$VC" rx off tx off sg off tso off gso off gro off lro off 2>/dev/null || true
else
  echo "[netbed_up] ethtool not installed; E-N5 may under-count segments"
fi

# baseline pass-through netem qdiscs (netbed_set replaces these per condition)
ip netns exec "$NS_S" tc qdisc add dev "$VS" root handle 1: netem
ip netns exec "$NS_C" tc qdisc add dev "$VC" root handle 1: netem

echo "[netbed_up] $NS_S=$IP_S ($VS)  <--veth-->  $NS_C=$IP_C ($VC)"
ip netns exec "$NS_S" ip -brief addr show "$VS"
ip netns exec "$NS_C" ip -brief addr show "$VC"
