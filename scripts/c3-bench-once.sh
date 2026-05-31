#!/usr/bin/env bash
# scripts/c3-bench-once.sh — run wrk from kvm-vm against the deployed
# waitless-webserver (GCE c3 + gVNIC) at one conn count, snapshot /obs
# pre + post, print the rps line and the same /obs delta block the
# kvm-iterate script prints. Lets us compare cliff behavior on the
# production-shape datapath against the kvm-iterate (virtio-net) runs.
#
# Usage:
#   ./c3-bench-once.sh --conns 10000 --duration 8
#   ./c3-bench-once.sh --conns 14000 --duration 10 --workload health-tls
#
# Requires `waitless-webserver` and `kvm-vm` to be RUNNING in
# us-west1-c. Does not start or stop them.

set -euo pipefail

CONNS=10000
DURATION=8
WORKLOAD="health-tls"
THREADS=4
KVM="${GCP_KVM_VM_NAME:-kvm-vm}"
UNI="${WAITLESS_GCE_NAME:-waitless-webserver}"
ZONE="${WAITLESS_GCE_ZONE:-us-west1-c}"

while [ $# -gt 0 ]; do
    case "$1" in
    --conns) shift; CONNS="$1" ;;
    --duration) shift; DURATION="$1" ;;
    --workload) shift; WORKLOAD="$1" ;;
    --threads) shift; THREADS="$1" ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
    shift
done

UNI_IP="$(gcloud compute instances describe "$UNI" --zone="$ZONE" \
    --format='value(networkInterfaces[0].networkIP)')"

case "$WORKLOAD" in
health)         URL="http://$UNI_IP/health" ;;
health-tls)     URL="https://$UNI_IP/health" ;;
static64k)      URL="http://$UNI_IP/static-64k" ;;
static64k-tls)  URL="https://$UNI_IP/static-64k" ;;
static256k-tls) URL="https://$UNI_IP/static-256k" ;;
static1m-tls)   URL="https://$UNI_IP/static-1m" ;;
*) echo "unknown workload: $WORKLOAD" >&2; exit 1 ;;
esac

echo "==> Running bench from $KVM against $UNI ($UNI_IP), $WORKLOAD, conns=$CONNS, duration=${DURATION}s" >&2

# `OBS_DELTA_PY` interpolates the shared /obs-delta script into the
# REMOTE heredoc below — keeps the body in one place
# (`scripts/bench/obs_delta.py`) instead of duplicating it across
# `c3-bench-once.sh` and `kvm-iterate.sh`.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OBS_DELTA_PY="$(cat "$SCRIPT_DIR/bench/obs_delta.py")"

gcloud compute ssh "$KVM" --zone="$ZONE" --command="bash -s" <<REMOTE
set -euo pipefail
ulimit -Sn 1048576 2>/dev/null || true

# Snapshot /obs pre.
curl -sk --max-time 5 "https://$UNI_IP/obs" > /tmp/obs-pre.json 2>/dev/null \
    || echo '{}' > /tmp/obs-pre.json

# Drive wrk.
echo "==> wrk -t$THREADS -c$CONNS -d${DURATION}s --latency $URL" >&2
wrk -t$THREADS -c$CONNS -d${DURATION}s --latency --timeout 10s "$URL" 2>&1 | \
    grep -E 'Requests/sec|^[[:space:]]+(50|99)%|Socket errors|Latency'

# Snapshot /obs post.
curl -sk --max-time 15 "https://$UNI_IP/obs" > /tmp/obs-post.json 2>/dev/null \
    || echo '{}' > /tmp/obs-post.json

# Delta block — body in scripts/bench/obs_delta.py, interpolated
# via \$OBS_DELTA_PY (the outer REMOTE heredoc expands it; the
# inner 'PY' heredoc passes it to python as stdin).
echo "" >&2
echo "==> /obs deltas (post - pre):" >&2
python3 - /tmp/obs-pre.json /tmp/obs-post.json <<'PY'
$OBS_DELTA_PY
PY
REMOTE
