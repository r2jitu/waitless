#!/usr/bin/env bash
# scripts/bench/gce-h2-bench.sh — drive the `loadgen http --proto
# h1|h2|h3` workload from kvm-vm against the deployed
# waitless-webserver, and print per-request work + (for h2) per-phase
# CPU from /obs deltas (`h2_profile.py`).
#
# The h2/h3 analog of `c3-bench-once.sh` (which is wrk / HTTP-1.1 only).
# Use it to get the throughput TRUTH + CPU profile that HVF can't give
# (see `feedback_gce_first_iteration`): HVF is proxy-bound and reports
# false parity; this measures the real gVNIC datapath.
#
# Requires `waitless-webserver` + `kvm-vm` RUNNING in us-west1-c, with
# the loadgen already built on kvm-vm. Run `gcp-deploy-bench.sh
# --keep-running ...` first (it deploys the unikernel + syncs/builds the
# loadgen). This script does NOT start or stop the VMs.
#
# Usage:
#   ./gce-h2-bench.sh --proto h2 --conns 25 --streams 16
#   ./gce-h2-bench.sh --proto h1 --conns 300 --endpoint /health --duration 8
#   ./gce-h2-bench.sh --proto h2 --endpoint /static-64k --conns 8 --streams 4
#   for p in h1 h2 h3; do ./gce-h2-bench.sh --proto $p; done   # A/B sweep

set -euo pipefail

PROTO=h2
CONNS=25
STREAMS=16
DURATION=6
WARMUP=1
ENDPOINT=/health
KVM="${GCP_KVM_VM_NAME:-kvm-vm}"
UNI="${WAITLESS_GCE_NAME:-waitless-webserver}"
ZONE="${WAITLESS_GCE_ZONE:-us-west1-c}"

while [ $# -gt 0 ]; do
    case "$1" in
    --proto) shift; PROTO="$1" ;;
    --conns) shift; CONNS="$1" ;;
    --streams) shift; STREAMS="$1" ;;
    --duration) shift; DURATION="$1" ;;
    --warmup) shift; WARMUP="$1" ;;
    --endpoint) shift; ENDPOINT="$1" ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# *//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
    shift
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# READ the assigned internal IP — never hardcode (it changes on every
# redeploy; a stale IP silently benches the wrong/old VM).
UNI_IP="$(gcloud compute instances describe "$UNI" --zone="$ZONE" \
    --format='value(networkInterfaces[0].networkIP)')"
[ -n "$UNI_IP" ] || { echo "Error: couldn't read $UNI internal IP" >&2; exit 1; }

echo "==> $PROTO $ENDPOINT  c$CONNS s$STREAMS ${DURATION}s  vs $UNI ($UNI_IP)" >&2

# Ship the profiler to kvm-vm and run it there (it owns the loadgen
# binary + the low-RTT path to the unikernel).
gcloud compute scp "$SCRIPT_DIR/h2_profile.py" "$KVM:/tmp/h2_profile.py" \
    --zone="$ZONE" >/dev/null
gcloud compute ssh "$KVM" --zone="$ZONE" --command="\
    ulimit -Sn 1048576 2>/dev/null || true; \
    python3 /tmp/h2_profile.py $UNI_IP --proto $PROTO --port 443 \
        --endpoint $ENDPOINT --conns $CONNS --streams $STREAMS \
        --duration $DURATION --warmup $WARMUP"
