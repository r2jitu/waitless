#!/usr/bin/env bash
# netem-cc-ab.sh — congestion-control A/B harness, run ON the loadgen VM.
#
# Adds delay + loss to the *server→client data* path (IFB-ingress netem so
# the SERVER's congestion controller is the thing under test), then measures
# a sustained 20 MB keep-alive download of /static-1m. Prints per-run MB/s.
#
# Usage:  bash netem-cc-ab.sh <server-ip> [arm-label]
# Tears netem down on exit so a crashed run never leaves the NIC throttled.
set -u
SRV="${1:?server ip}"; ARM="${2:-arm}"; DEV="${DEV:-ens3}"
N_URLS="${N_URLS:-20}"; REPEATS="${REPEATS:-6}"

ARGS=""; for _ in $(seq "$N_URLS"); do ARGS="$ARGS -o /dev/null https://$SRV/static-1m"; done

netem_down() {
  sudo tc qdisc del dev "$DEV" ingress 2>/dev/null
  sudo tc qdisc del dev ifb0 root 2>/dev/null
}
trap netem_down EXIT

netem_up() { # $1=delay $2=loss
  sudo modprobe ifb act_mirred cls_u32 sch_ingress sch_netem 2>/dev/null
  sudo ip link add ifb0 type ifb 2>/dev/null || true
  sudo ip link set ifb0 up
  netem_down
  sudo tc qdisc add dev "$DEV" handle ffff: ingress
  sudo tc filter add dev "$DEV" parent ffff: protocol ip u32 match u32 0 0 \
       action mirred egress redirect dev ifb0
  sudo tc qdisc add dev ifb0 root netem delay "$1" loss "$2"
}

one_run() { # prints MB/s
  local t0 t1; t0=$(date +%s.%N)
  curl -sk --http1.1 $ARGS >/dev/null 2>&1
  t1=$(date +%s.%N)
  awk -v a="$t0" -v b="$t1" -v n="$N_URLS" 'BEGIN{printf "%.2f", n/(b-a)}'
}

matrix() { # $1=delay $2=loss
  netem_up "$1" "$2"
  # Sanity: a 50 ms path MUST be far below the ~650 MB/s LAN line; if it
  # isn't, netem didn't take and the numbers are meaningless.
  local probe; probe=$(one_run)
  echo "  [$ARM] netem $1 $2  (verify qdisc: $(sudo tc -s qdisc show dev ifb0 | head -1 | tr -s ' '))"
  awk -v p="$probe" 'BEGIN{ if (p+0 > 300) print "  !! WARNING netem not effective (" p " MB/s) — INVALID"; }'
  local i v
  for i in $(seq "$REPEATS"); do v=$(one_run); printf "  [%s] %s %s run %d: %s MB/s\n" "$ARM" "$1" "$2" "$i" "$v"; done
  netem_down
}

echo "== arm=$ARM server=$SRV dev=$DEV urls=$N_URLS repeats=$REPEATS =="
netem_down
echo "## CLEAN (no netem)"
for i in $(seq 4); do printf "  [%s] clean run %d: %s MB/s\n" "$ARM" "$i" "$(one_run)"; done
echo "## 25ms 1%"; matrix 25ms 1%
echo "## 50ms 1%"; matrix 50ms 1%
echo "## 50ms 2%"; matrix 50ms 2%
echo "== done arm=$ARM =="
