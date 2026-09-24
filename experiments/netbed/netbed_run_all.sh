#!/usr/bin/env bash
# Full E-N network matrix for Post-Quantum Biscuit.
#
# Single root WSL session: brings up the testbed, ensures offline tokens,
# starts the verifier, calibrates every network condition with ping, runs
# E-N1..E-N6, then tears the testbed down. Safe to re-run per stage:
#   STAGE=all|rest|en1|en2|en3|en4|en5|en6   (rest = en2..en6; default all)
#   QUICK=1                              (tiny matrix to validate plumbing)
#
# Run:  wsl -u root bash -lc "tr -d '\r' < netbed_run_all.sh | STAGE=all bash"
set -uo pipefail

# Paths derive from this script's location (it lives at experiments/netbed), so
# the matrix runs unchanged wherever the repository is cloned.
NB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROOT="$(cd "$NB/../.." && pwd)"
CRATE=$PROOT/impl/pqbiscuit
DATA="${DATA_OVERRIDE:-$PROOT/experiments/data}"
TOK=$NB/tokens; KEY=$NB/rootkeys
BIN=$CRATE/target/release
IP_S=10.99.0.1; IP_C=10.99.0.2; PORT=8080
STAGE="${STAGE:-all}"
QUICK="${QUICK:-0}"
RUN_LOG="${RUN_LOG:-$NB/run_all.log}"

mkdir -p "$DATA"
exec > >(tee "$RUN_LOG") 2>&1
echo "=== netbed_run_all STAGE=$STAGE QUICK=$QUICK $(date) ==="

# ---- matrices (full vs QUICK) ----
if [ "$QUICK" = "1" ]; then
  P_ALL="ed25519 fndsa512 mix-mldsa87-fndsa512"
  NS_ALL="1 20"; RTTS="0 20"
  LOSS_PROFS="ed25519 fndsa512"; LOSS_NS="1 20"; LOSSES="0 5"
  TP_PROFS="ed25519 fndsa512"; TP_NS="20"; TP_RTTS="0"; CONCS="1"; REPS="1"; DUR=3
  NB_PROFS="ed25519 fndsa512"; NB_NS="20"; S1=3; S46=3
else
  P_ALL="ed25519 mldsa44 mldsa65 mldsa87 fndsa512 fndsa1024 slhdsa128s slhdsa128f slhdsa256s slhdsa256f hyb-ed-mldsa44 hyb-ed-fndsa512 mix-mldsa87-fndsa512 mix-slh256s-fndsa512 mix-mldsa87-mldsa44"
  NS_ALL="1 5 10 20"; RTTS="0 1 5 20 50 100 200"
  LOSS_PROFS="ed25519 fndsa512 mldsa87 slhdsa128f hyb-ed-fndsa512 mix-mldsa87-fndsa512"
  LOSS_NS="1 10 20"; LOSSES="0 1 3 5"
  TP_PROFS="ed25519 mldsa44 mldsa87 fndsa512 fndsa1024 slhdsa128f hyb-ed-fndsa512 mix-mldsa87-fndsa512"
  TP_NS="1 20"; TP_RTTS="0 1 20"; CONCS="1 2 4 8 16 32"; REPS="1 2 3"; DUR=15
  NB_PROFS="ed25519 fndsa512 mldsa87 slhdsa128f hyb-ed-fndsa512 mix-mldsa87-fndsa512"
  NB_NS="10 20"; S1=30; S46=20
fi

ka_samples () { # rtt
  if [ "$QUICK" = "1" ]; then echo 50; elif [ "$1" -ge 100 ]; then echo 400; else echo 1000; fi
}
new_samples () {
  if [ "$QUICK" = "1" ]; then echo 20; elif [ "$1" -ge 100 ]; then echo 200; else echo 400; fi
}

# ---- testbed lifecycle ----
bash <(tr -d '\r' < "$NB/netbed_up.sh")
if [ ! -f "$TOK/ed25519_n20.tok" ]; then
  ( cd "$CRATE" && "$BIN/netbed_gen" )
fi

start_server () { # core-spec, client-core-spec exported as C_CORE
  pkill -f 'target/release/netbed_server' 2>/dev/null || true; sleep 0.3
  ip netns exec nbS taskset -c "$1" "$BIN/netbed_server" \
    --addr "$IP_S:$PORT" --keys "$KEY" >/tmp/nbsrv.log 2>&1 &
  echo $! >/tmp/nbsrv.pid
  for i in $(seq 1 100); do
    ip netns exec nbC bash -c "exec 3<>/dev/tcp/$IP_S/$PORT" 2>/dev/null && { echo "server up (cores $1)"; return; }
    sleep 0.2
  done
  echo "server failed"; cat /tmp/nbsrv.log; exit 1
}
stop_server () { pkill -f 'target/release/netbed_server' 2>/dev/null || true; sleep 0.3; }
cleanup () { stop_server; bash <(tr -d '\r' < "$NB/netbed_down.sh") || true; }
trap cleanup EXIT

setcond () { bash <(tr -d '\r' < "$NB/netbed_set.sh") "$@" >/dev/null; }

# Always re-applies the qdisc (no cross-stage caching) and calibrates with ping.
calib () { # stage rtt loss rate
  local stage="$1"; local rtt="$2"; local loss="$3"; local rate="$4"
  setcond "$rtt" "$loss" "$rate"; sleep 0.4
  local f="$DATA/net_calibrate.csv"
  [ -f "$f" ] || echo "stage,rtt_ms,loss_pct,rate,ping_n,ping_min,ping_avg,ping_max,ping_loss_pct" > "$f"
  local pn=20; local pi="-i 0.05"
  if awk "BEGIN{exit !($loss>0)}"; then pn=100; pi="-i 0.02"; fi
  local out q mn av mx pl
  out="$(ip netns exec nbC ping -q -c "$pn" $pi -W 1 "$IP_S" 2>&1)"
  q="$(printf '%s' "$out" | grep -oE '[0-9.]+/[0-9.]+/[0-9.]+/[0-9.]+' | tail -1)"
  mn="$(cut -d/ -f1 <<<"$q")"; av="$(cut -d/ -f2 <<<"$q")"; mx="$(cut -d/ -f3 <<<"$q")"
  pl="$(printf '%s' "$out" | grep -oE '[0-9]+% packet loss' | tail -1 | cut -d% -f1)"; pl="${pl:-0}"
  echo "$stage,$rtt,$loss,$rate,$pn,${mn:-NA},${av:-NA},${mx:-NA},$pl" >> "$f"
  echo "  [calib] $stage rtt=$rtt loss=$loss rate=$rate -> avg=${av:-NA}ms loss=${pl}% (n=$pn)"
}

clean_stage_lat () { # stage: drop prior rows for this stage in net_latency.csv (keep header)
  local f="$DATA/net_latency.csv"
  [ -f "$f" ] && awk -F, -v e="$1" 'NR==1||$1!=e' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}
clean_stage_cal () { # stage: drop prior calibration rows for this stage
  local f="$DATA/net_calibrate.csv"
  [ -f "$f" ] && awk -F, -v e="$1" 'NR==1||$1!=e' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

# ---- unit-level resume helpers (columns: 1 exp,3 profile,6 n,7 mode,8 rtt) ----
LAT_HEADER='exp,family,profile,root,att,n,mode,rtt_ms,loss_pct,rate,seq,total_ns,verify_ns,status'
ensure_lat_header () {
  local f="$DATA/net_latency.csv"; mkdir -p "$DATA"
  [ -f "$f" ] || echo "$LAT_HEADER" > "$f"
}
# count rows of one latency unit; optional loss(%)/rate keys for E-N2/E-N4
unit_count () { # exp prof n mode rtt [loss] [rate]
  local f="$DATA/net_latency.csv"; [ -f "$f" ] || { echo 0; return; }
  awk -F, -v e="$1" -v p="$2" -v nn="$3" -v mm="$4" -v rr="$5" \
      -v lc="${6:-}" -v rc="${7:-}" \
    'NR>1&&$1==e&&$3==p&&$6==nn&&$7==mm&&$8==rr&&(lc==""||$9==lc)&&(rc==""||$10==rc){c++}
     END{print c+0}' "$f"
}
# drop all rows of one latency unit (keep the header and every other unit)
unit_purge () { # exp prof n mode rtt [loss] [rate]
  local f="$DATA/net_latency.csv"; [ -f "$f" ] || return 0
  awk -F, -v e="$1" -v p="$2" -v nn="$3" -v mm="$4" -v rr="$5" \
      -v lc="${6:-}" -v rc="${7:-}" \
    'NR==1||!($1==e&&$3==p&&$6==nn&&$7==mm&&$8==rr&&(lc==""||$9==lc)&&(rc==""||$10==rc))' \
    "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

cli_lat () { # prof n mode samples rtt loss rate exp clientcores [nowarm]
  local nw=""
  [ "${10:-}" = "nowarm" ] && nw="--nowarm true"
  ip netns exec nbC taskset -c "$9" "$BIN/netbed_client" latency \
    --server "$IP_S:$PORT" --tokens "$TOK" --profile "$1" --n "$2" --mode "$3" \
    --samples "$4" --rtt "$5" --loss "$6" --rate "$7" --exp "$8" $nw \
    --out "$DATA/net_latency.csv" || echo "  WARN latency $1 n$2 $3 rtt$5 loss$6 $7"
}

# throughput unit already measured? key: profile,n,rtt,conc,rep (cols 1,3,4,5,6)
tp_exists () { # prof n rtt conc rep
  local f="$DATA/net_throughput.csv"; [ -f "$f" ] || { echo 0; return; }
  awk -F, -v p="$1" -v nn="$2" -v rr="$3" -v cc="$4" -v rp="$5" \
    'NR>1&&$1==p&&$3==nn&&$4==rr&&$5==cc&&$6==rp{n++} END{print n+0}' "$f"
}
# segmentation unit already measured? key: profile,n (cols 1,2)
seg_exists () { # prof n
  local f="$DATA/net_segments_meas.csv"; [ -f "$f" ] || { echo 0; return; }
  awk -F, -v p="$1" -v nn="$2" 'NR>1&&$1==p&&$2==nn{n++} END{print n+0}' "$f"
}

# ================= E-N1: latency vs RTT (unit-level resume) =================
run_en1 () {
  echo "### E-N1 latency vs RTT (unit-level resume)"
  ensure_lat_header; clean_stage_cal en1; start_server 10
  for prof in $P_ALL; do for n in $NS_ALL; do for rtt in $RTTS; do
    wka=$(ka_samples "$rtt"); wnew=$(new_samples "$rtt")
    cka=$(unit_count en1 "$prof" "$n" ka "$rtt")
    cnew=$(unit_count en1 "$prof" "$n" new "$rtt")
    if [ "$cka" -eq "$wka" ] && [ "$cnew" -eq "$wnew" ]; then
      echo "en1[$prof n=$n RTT=$rtt] complete (ka=$cka new=$cnew), skip"
      continue
    fi
    calib en1 "$rtt" 0 unlim
    if [ "$cka" -ne "$wka" ]; then
      if [ "$cka" -gt 0 ]; then unit_purge en1 "$prof" "$n" ka "$rtt"; echo "  purged partial ka $cka/$wka"; fi
      cli_lat "$prof" "$n" ka "$wka" "$rtt" 0 unlim en1 6
    fi
    if [ "$cnew" -ne "$wnew" ]; then
      if [ "$cnew" -gt 0 ]; then unit_purge en1 "$prof" "$n" new "$rtt"; echo "  purged partial new $cnew/$wnew"; fi
      cli_lat "$prof" "$n" new "$wnew" "$rtt" 0 unlim en1 6
    fi
  done; done; done
}

# ================= E-N2: latency vs loss (unit-level resume) =================
run_en2 () {
  echo "### E-N2 latency vs loss (rtt=20, unit-level resume)"
  ensure_lat_header; clean_stage_cal en2; start_server 10
  local ks ns
  if [ "$QUICK" = "1" ]; then ks=30; ns=15; else ks=1000; ns=400; fi
  for prof in $LOSS_PROFS; do for n in $LOSS_NS; do for loss in $LOSSES; do
    local cka cnew
    cka=$(unit_count en2 "$prof" "$n" ka 20 "$loss")
    cnew=$(unit_count en2 "$prof" "$n" new 20 "$loss")
    if [ "$cka" -eq "$ks" ] && [ "$cnew" -eq "$ns" ]; then
      echo "en2[$prof n=$n loss=$loss] complete (ka=$cka new=$cnew), skip"; continue
    fi
    calib en2 20 "$loss" unlim
    if [ "$cka" -ne "$ks" ]; then
      [ "$cka" -gt 0 ] && { unit_purge en2 "$prof" "$n" ka 20 "$loss"; echo "  purged partial ka $cka/$ks"; }
      cli_lat "$prof" "$n" ka "$ks" 20 "$loss" unlim en2 6
    fi
    if [ "$cnew" -ne "$ns" ]; then
      [ "$cnew" -gt 0 ] && { unit_purge en2 "$prof" "$n" new 20 "$loss"; echo "  purged partial new $cnew/$ns"; }
      cli_lat "$prof" "$n" new "$ns" 20 "$loss" unlim en2 6
    fi
  done; done; done
}

# ================= E-N3: throughput (unit-level resume) =================
run_en3 () {
  echo "### E-N3 throughput (unit-level resume)"; clean_stage_cal en3; start_server 2-5
  local f="$DATA/net_throughput.csv"
  [ -f "$f" ] || echo "profile,family,n,rtt_ms,conc,rep,duration_s,completed,failed,rps,p50_ns,p95_ns,p99_ns,verify_mean_ns" > "$f"
  for prof in $TP_PROFS; do for n in $TP_NS; do for rtt in $TP_RTTS; do
    calib en3 "$rtt" 0 unlim
    for conc in $CONCS; do for rep in $REPS; do
      if [ "$(tp_exists "$prof" "$n" "$rtt" "$conc" "$rep")" -ge 1 ]; then
        echo "en3[$prof n=$n rtt=$rtt c=$conc rep=$rep] complete, skip"; continue
      fi
      ip netns exec nbC taskset -c 6-9 "$BIN/netbed_client" throughput \
        --server "$IP_S:$PORT" --tokens "$TOK" --profile "$prof" --n "$n" \
        --conc "$conc" --duration "$DUR" --rep "$rep" --rtt "$rtt" --out "$f" \
        || echo "  WARN throughput $prof n$n c$conc rtt$r rep$rep"
    done; done
  done; done; done
}

# ================= E-N4: constrained bandwidth (unit-level resume) =================
run_en4 () {
  echo "### E-N4 constrained bandwidth (rtt=50, unit-level resume)"
  ensure_lat_header; clean_stage_cal en4; start_server 10
  for prof in $NB_PROFS; do for n in $NB_NS; do for rate in 1mbit 46kbit; do
    local s=$S1; [ "$rate" = "46kbit" ] && s=$S46
    local c; c=$(unit_count en4 "$prof" "$n" ka 50 "" "$rate")
    if [ "$c" -eq "$s" ]; then
      echo "en4[$prof n=$n rate=$rate] complete ($c), skip"; continue
    fi
    calib en4 50 0 "$rate"; setcond 50 0 "$rate"
    [ "$c" -gt 0 ] && { unit_purge en4 "$prof" "$n" ka 50 "" "$rate"; echo "  purged partial ka $c/$s"; }
    # --nowarm: over a narrow link the default 30 warm-up transfers would each
    # re-send the whole (multi-hundred-KB) token; transfer time is deterministic
    # (size/rate), so warm-up only doubles the stage without adding information.
    cli_lat "$prof" "$n" ka "$s" 50 0 "$rate" en4 6 nowarm
  done; done; done
  setcond 0 0 unlim
}

# ================= E-N5: wire segmentation (tcpdump) =================
run_en5 () {
  echo "### E-N5 wire segmentation"; start_server 10
  command -v tcpdump >/dev/null || { echo "tcpdump missing; skipping"; return 0; }
  setcond 1 0 unlim; sleep 0.3
  local f="$DATA/net_segments_meas.csv"
  [ -f "$f" ] || echo "profile,n,meas_up,meas_dn" > "$f"
  for prof in $P_ALL; do for n in $NS_ALL; do
    if [ "$(seg_exists "$prof" "$n")" -ge 1 ]; then
      echo "en5[$prof n=$n] complete, skip"; continue
    fi
    rm -f /tmp/seg.pcap
    ip netns exec nbS timeout 4 tcpdump -i vS -nn -w /tmp/seg.pcap \
        "host $IP_C and tcp port $PORT" >/dev/null 2>&1 &
    local tpid=$!
    sleep 0.6
    ip netns exec nbC taskset -c 6 "$BIN/netbed_client" latency \
      --server "$IP_S:$PORT" --tokens "$TOK" --profile "$prof" --n "$n" \
      --mode new --samples 1 --nowarm true --rtt 1 --loss 0 \
      --out /tmp/seg_lat.csv >/dev/null 2>&1 || true
    wait "$tpid" 2>/dev/null || true
    local up dn
    up=$(ip netns exec nbS tcpdump -nn -r /tmp/seg.pcap "src host $IP_C" 2>/dev/null | grep -c 'length [1-9][0-9]*' || true)
    dn=$(ip netns exec nbS tcpdump -nn -r /tmp/seg.pcap "src host $IP_S" 2>/dev/null | grep -c 'length [1-9][0-9]*' || true)
    echo "$prof,$n,${up:-0},${dn:-0}" >> "$f"
    echo "  [seg] $prof n$n up=${up:-0} dn=${dn:-0}"
  done; done
}

# ================= E-N6: footprint =================
run_en6 () {
  echo "### E-N6 footprint"; start_server 2-5
  local raw strip f="$DATA/net_footprint.csv"
  raw=$(stat -c%s "$BIN/netbed_server")
  cp "$BIN/netbed_server" /tmp/nbs_strip && strip /tmp/nbs_strip 2>/dev/null || cp "$BIN/netbed_server" /tmp/nbs_strip
  strip=$(stat -c%s /tmp/nbs_strip)
  echo "backend,binary_b,stripped_b,rss_kb" > "$f"
  setcond 0 0 unlim
  for prof in ed25519 fndsa512 slhdsa128f; do
    stop_server; sleep 0.2
    ip netns exec nbS taskset -c 2-5 "$BIN/netbed_server" \
      --addr "$IP_S:$PORT" --keys "$KEY" >/tmp/nbsrv.log 2>&1 &
    local spid=$!
    for i in $(seq 1 100); do ip netns exec nbC bash -c "exec 3<>/dev/tcp/$IP_S/$PORT" 2>/dev/null && break; sleep 0.2; done
    ip netns exec nbC taskset -c 6-9 "$BIN/netbed_client" throughput \
      --server "$IP_S:$PORT" --tokens "$TOK" --profile "$prof" --n 20 \
      --conc 8 --duration 12 --rep 1 --rtt 0 --out /tmp/foot_tp.csv >/dev/null 2>&1 || true
    sleep 1
    local rss; rss=$(awk '/VmHWM/{print $2}' "/proc/$spid/status" 2>/dev/null)
    echo "$prof,$raw,$strip,${rss:-NA}" >> "$f"
    echo "  [foot] $prof rss=${rss:-NA}KB binary=$raw stripped=$strip"
    kill "$spid" 2>/dev/null || true; sleep 0.3
  done
}

case "$STAGE" in
  en1) run_en1;; en2) run_en2;; en3) run_en3;; en4) run_en4;;
  en5) run_en5;; en6) run_en6;;
  rest) run_en2; run_en3; run_en4; run_en5; run_en6;;
  all) run_en1; run_en2; run_en3; run_en4; run_en5; run_en6;;
  *) echo "unknown STAGE $STAGE"; exit 2;;
esac
echo "=== netbed_run_all STAGE=$STAGE DONE $(date) ==="
