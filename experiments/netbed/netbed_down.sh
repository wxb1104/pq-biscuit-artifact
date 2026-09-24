#!/usr/bin/env bash
# Tear down the testbed namespaces (veth pairs are removed with them).
# Kills any lingering netbed server first. Must run as root.
set -euo pipefail
pkill -f 'target/release/netbed_server' 2>/dev/null || true
ip netns del nbS 2>/dev/null || true
ip netns del nbC 2>/dev/null || true
echo "[netbed_down] namespaces removed"
