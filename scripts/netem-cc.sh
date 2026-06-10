#!/usr/bin/env bash
# netem-cc.sh — congestion-control / loss-recovery A/B harness. Run ON the
# loadgen VM (it shapes that host's NIC), pointed at a deployed waitless.
#
# Methodology: IFB-ingress netem adds delay + loss to the *server→client
# data* path (not the client's egress), so the SERVER's congestion
# controller + loss recovery is what's under test — the right lens for
# CUBIC-vs-Reno and Tail-Loss-Probe A/Bs (docs/tcp-backlog L1/L4).
#
# Usage:  bash netem-cc.sh <mode> <server-ip> [arm-label]
#   trials  N single-object transfers per profile + median/min/max + stall
#           count — the median rejects the bimodal tail-loss-RTO outliers and
#           exposes the steady-state (CC-curve-bound) throughput. [default use]
#   ab      sustained 20 MB keep-alive download per profile, per-run MB/s.
#   diag    single transfers + server /obs recovery counters — classifies a
#           real RTO-dominated collapse from a measurement artifact.
# Env: DEV (NIC, default ens3), N (trials, 15), REPEATS (ab, 6),
#      N_URLS (ab keep-alive count, 20).
# Tears netem down on exit so a crashed run never leaves the NIC throttled.
set -u
MODE="${1:?mode: trials|ab|diag}"
SRV="${2:?server ip}"
ARM="${3:-arm}"
DEV="${DEV:-ens3}"
N="${N:-15}"
REPEATS="${REPEATS:-6}"
N_URLS="${N_URLS:-20}"

# ── Shared netem plumbing — the one source of truth for the shaping setup ──
netem_down() {
  sudo tc qdisc del dev "$DEV" ingress 2>/dev/null
  sudo tc qdisc del dev ifb0 root 2>/dev/null
}
trap netem_down EXIT

# Loss on the server→client DATA path: redirect this NIC's ingress to an IFB
# device and run netem there (an egress qdisc on ifb0 shapes the redirected
# ingress). $1=delay $2=loss.
netem_up() {
  sudo modprobe ifb act_mirred cls_u32 sch_ingress sch_netem 2>/dev/null
  sudo ip link add ifb0 type ifb 2>/dev/null || true
  sudo ip link set ifb0 up
  netem_down
  sudo tc qdisc add dev "$DEV" handle ffff: ingress
  sudo tc filter add dev "$DEV" parent ffff: protocol ip u32 match u32 0 0 \
       action mirred egress redirect dev ifb0
  sudo tc qdisc add dev ifb0 root netem delay "$1" loss "$2"
}

# Download `$1` (a path) once over its own connection; print bytes/sec.
speed() { curl -sk --http1.1 -o /dev/null -w '%{speed_download}' "https://$SRV/$1"; }

# ── mode: trials — median-over-N, robust to the tail-loss-RTO outliers ──────
mode_trials() {
  run_profile() { # delay loss obj
    netem_up "$1" "$2"
    local times=() i t
    for i in $(seq "$N"); do
      t=$(speed "$3")
      times+=("$t")
      printf "  [%s] %s %s %s #%d: %.3f MB/s\n" "$ARM" "$1" "$2" "$3" "$i" \
        "$(awk -v x="$t" 'BEGIN{print x/1e6}')"
    done
    netem_down
    printf '%s\n' "${times[@]}" | sort -n | awk -v arm="$ARM" -v d="$1" -v l="$2" -v o="$3" '
      {v[NR]=$1/1e6} END{
        med=(NR%2)?v[(NR+1)/2]:(v[NR/2]+v[NR/2+1])/2; s=0; for(i=1;i<=NR;i++) if(v[i]<0.2) s++;
        printf "  >> [%s] %s %s %s  MEDIAN=%.3f MB/s  min=%.3f max=%.3f  stalls(<0.2)=%d/%d\n",
               arm, d, l, o, med, v[1], v[NR], s, NR }'
  }
  echo "== arm=$ARM mode=trials N=$N =="
  netem_down
  run_profile 25ms 1% static-1m
  run_profile 50ms 1% static-1m
  echo "== done $ARM =="
}

# ── mode: ab — sustained keep-alive download per loss profile ───────────────
mode_ab() {
  local ARGS="" _
  for _ in $(seq "$N_URLS"); do ARGS="$ARGS -o /dev/null https://$SRV/static-1m"; done
  run() {
    local t0 t1
    t0=$(date +%s.%N)
    curl -sk --http1.1 $ARGS >/dev/null 2>&1
    t1=$(date +%s.%N)
    awk -v a="$t0" -v b="$t1" -v n="$N_URLS" 'BEGIN{printf "%.2f", n/(b-a)}'
  }
  matrix() { # delay loss
    netem_up "$1" "$2"
    local probe
    probe=$(run)
    echo "  [$ARM] netem $1 $2 (qdisc: $(sudo tc -s qdisc show dev ifb0 | head -1 | tr -s ' '))"
    awk -v p="$probe" 'BEGIN{ if (p+0 > 300) print "  !! WARNING netem not effective ("p" MB/s) — INVALID" }'
    local i v
    for i in $(seq "$REPEATS"); do
      v=$(run)
      printf "  [%s] %s %s run %d: %s MB/s\n" "$ARM" "$1" "$2" "$i" "$v"
    done
    netem_down
  }
  echo "== arm=$ARM mode=ab urls=$N_URLS repeats=$REPEATS =="
  netem_down
  echo "## CLEAN"
  local i
  for i in $(seq 4); do printf "  [%s] clean run %d: %s MB/s\n" "$ARM" "$i" "$(run)"; done
  echo "## 25ms 1%"; matrix 25ms 1%
  echo "## 50ms 1%"; matrix 50ms 1%
  echo "## 50ms 2%"; matrix 50ms 2%
  echo "== done $ARM =="
}

# ── mode: diag — classify the collapse (single transfers + /obs counters) ───
mode_diag() {
  tcpdiag() {
    curl -sk --max-time 5 "https://$SRV/obs" | tr ',' '\n' \
      | grep -iE "retrans|rtx|rto|dup_ack|sack|tlp|pmtu|timeout" | head -20
  }
  one() { curl -sk --http1.1 -o /dev/null -w "  $1: %{speed_download} B/s  time=%{time_total}s\n" "https://$SRV/$1"; }
  echo "== mode=diag single-request transfers =="
  netem_down
  echo "## CLEAN single /static-1m x3"
  local i
  for i in 1 2 3; do one static-1m; done
  netem_up 25ms 1%
  echo "## 25ms 1%: /static-256k x3 (fewer losses)"
  for i in 1 2 3; do one static-256k; done
  echo "## 25ms 1%: /static-1m x3 (with server tcp counters)"
  echo "  -- BEFORE --"; tcpdiag
  for i in 1 2 3; do one static-1m; done
  echo "  -- AFTER --"; tcpdiag
  netem_down
  echo "== done =="
}

case "$MODE" in
  trials) mode_trials ;;
  ab) mode_ab ;;
  diag) mode_diag ;;
  *) echo "unknown mode '$MODE' (trials|ab|diag)" >&2; exit 2 ;;
esac
