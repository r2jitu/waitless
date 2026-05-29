#!/usr/bin/env bash
# twolg.sh — saturate a fast server from TWO GCE loadgens at once.
#
# A single c3-highcpu-8 wrk host tops out near ~800K rps plain /
# ~580K TLS, which is below what a bare-metal waitless server can
# sustain — so a one-loadgen run measures the loadgen, not the
# server. This drives wrk from two loadgen VMs in parallel against
# the same server and sums their throughput (the server's real
# delivered rps), reporting per-repeat sum + median over N repeats.
#
# Usage: twolg.sh SERVER_IP LABEL [PROTO=https] [DURATION=30] [REPEATS=3] [CONNS=8000]
# Env:   LG1, LG2 (loadgen instance names), ZONE.
set -u
SERVER_IP="${1:?server ip}"; LABEL="${2:?label}"
PROTO="${3:-https}"; DUR="${4:-30}"; REPEATS="${5:-3}"; CONNS="${6:-8000}"
LG1="${LG1:-kvm-vm}"; LG2="${LG2:-waitless-peer-nginx}"; ZONE="${ZONE:-us-west1-c}"
URL="${PROTO}://${SERVER_IP}/health"

run_one() { # $1=loadgen $2=outfile
  timeout 90 gcloud compute ssh "$1" --zone="$ZONE" --command \
    "wrk -t8 -c${CONNS} -d${DUR}s --latency $URL 2>&1" >"$2" 2>/dev/null
}
rps()  { grep 'Requests/sec' "$1" | awk '{print $2}'; }
p50()  { awk '/Latency Distribution/{f=1} f&&/50%/{print $2; exit}' "$1"; }
p99()  { awk '/Latency Distribution/{f=1} f&&/99%/{print $2; exit}' "$1"; }

echo "## $LABEL  ($PROTO, ${DUR}s, 2x wrk -t8 -c${CONNS}, ${REPEATS} repeats)"
sums=()
for i in $(seq 1 "$REPEATS"); do
  run_one "$LG1" "/tmp/lg1.txt" & run_one "$LG2" "/tmp/lg2.txt" & wait
  r1=$(rps /tmp/lg1.txt); r2=$(rps /tmp/lg2.txt)
  sum=$(awk "BEGIN{printf \"%.0f\", ${r1:-0}+${r2:-0}}")
  sums+=("$sum")
  printf "  run %d: %s rps  (lg1=%s p50=%s p99=%s | lg2=%s p50=%s p99=%s)\n" \
    "$i" "$sum" "${r1:-?}" "$(p50 /tmp/lg1.txt)" "$(p99 /tmp/lg1.txt)" \
    "${r2:-?}" "$(p50 /tmp/lg2.txt)" "$(p99 /tmp/lg2.txt)"
done
med=$(printf '%s\n' "${sums[@]}" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
echo "  median sum: $med rps"
