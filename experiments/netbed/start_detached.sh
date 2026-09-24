#!/usr/bin/env bash
# Launch one stage DETACHED from the invoking wsl.exe process group (setsid),
# so a front-end quota gate that kills the wsl process group cannot stop it.
# Usage:  start_detached.sh en1
set -u
NB=/mnt/e/pqc+zhengshu/biscuit-pq/experiments/netbed
STAGE="${1:-en1}"
RUNLOG="$NB/run_${STAGE}.log"
PIDF="$NB/run_all.pid"

# Make sure no stale testbed/process from an earlier aborted run lingers.
tr -d '\r' < "$NB/cleanup_netbed.sh" | bash >/dev/null 2>&1 || true

tr -d '\r' < "$NB/netbed_run_all.sh" > /tmp/netbed_run_all.clean.sh
setsid bash -c "STAGE='$STAGE' RUN_LOG='$RUNLOG' bash /tmp/netbed_run_all.clean.sh" \
   </dev/null >/dev/null 2>&1 &
echo $! > "$PIDF"
sleep 3
echo "detached STAGE=$STAGE pid=$(cat "$PIDF") log=$RUNLOG"
