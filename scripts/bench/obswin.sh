#!/usr/bin/env bash
# obswin.sh — capture a per-request /obs cy/req decomposition for a server
# under sustained 2-loadgen load, the right way:
#
#   start load on BOTH loadgens  →  warm up  →  snapshot /obs (PRE)  →
#   steady measurement window    →  snapshot /obs (POST)  →  profile_obs.py
#
# This is the companion to twolg.sh (which reports throughput). Together
# they give the before/after picture for a perf A/B. Crucially the /obs
# snapshots are taken WHILE load runs, and profile_obs.py is called with
# its real signature (LABEL PRE.json POST.json) so the decomposition lines
# up with the measured window rather than a cold or post-drain snapshot.
#
# Usage: obswin.sh SERVER_IP LABEL [PROTO=https] [WARMUP=10] [WINDOW=20] [CONNS=8000]
# Env:   LG1, LG2 (loadgen instance names), ZONE.
set -u
SERVER_IP="${1:?server ip}"; LABEL="${2:?label}"
PROTO="${3:-https}"; WARMUP="${4:-10}"; WINDOW="${5:-20}"; CONNS="${6:-8000}"
LG1="${LG1:-kvm-vm}"; LG2="${LG2:-waitless-peer-nginx}"; ZONE="${ZONE:-us-west1-c}"
URL="${PROTO}://${SERVER_IP}/health"
DUR=$((WARMUP + WINDOW + 6))   # load outlasts the whole snapshot window

scriptdir="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$scriptdir/../.." && pwd)"

snap() { # $1 = outfile
  curl -fsS --max-time 8 "http://${SERVER_IP}/obs" -o "$1" 2>/dev/null \
    || curl -fsSk --max-time 8 "https://${SERVER_IP}/obs" -o "$1" 2>/dev/null
}

echo "## $LABEL  (/obs window: warmup=${WARMUP}s, measure=${WINDOW}s, 2x wrk -c${CONNS})"

# Kick sustained load on both loadgens (background; they outlast the window).
for lg in "$LG1" "$LG2"; do
  timeout $((DUR + 30)) gcloud compute ssh "$lg" --zone="$ZONE" --command \
    "wrk -t8 -c${CONNS} -d${DUR}s $URL >/dev/null 2>&1" >/dev/null 2>&1 &
done

sleep "$WARMUP"
if ! snap "/tmp/${LABEL}.pre.json"; then
  echo "  ERROR: PRE /obs snapshot failed" >&2; wait; return 1 2>/dev/null || exit 1
fi
sleep "$WINDOW"
if ! snap "/tmp/${LABEL}.post.json"; then
  echo "  ERROR: POST /obs snapshot failed" >&2; wait; return 1 2>/dev/null || exit 1
fi
wait  # let the wrk ssh sessions finish

python3 "${repo}/scripts/profile_obs.py" "$LABEL" \
  "/tmp/${LABEL}.pre.json" "/tmp/${LABEL}.post.json"
