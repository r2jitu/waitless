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
health)        URL="http://$UNI_IP/health" ;;
health-tls)    URL="https://$UNI_IP/health" ;;
static64k)     URL="http://$UNI_IP/static-64k" ;;
static64k-tls) URL="https://$UNI_IP/static-64k" ;;
*) echo "unknown workload: $WORKLOAD" >&2; exit 1 ;;
esac

echo "==> Running bench from $KVM against $UNI ($UNI_IP), $WORKLOAD, conns=$CONNS, duration=${DURATION}s" >&2

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

# Same delta block as kvm-iterate.
echo "" >&2
echo "==> /obs deltas (post - pre):" >&2
python3 - <<'PY'
import json
pre = json.load(open('/tmp/obs-pre.json'))
post = json.load(open('/tmp/obs-post.json'))
def delta_block(name, keys=None):
    p, q = pre.get(name, {}), post.get(name, {})
    print(f"  [{name}]")
    for k in (keys or sorted(set(p.keys()) | set(q.keys()))):
        v1, v2 = p.get(k, 0), q.get(k, 0)
        if isinstance(v2, (int, float)) and isinstance(v1, (int, float)):
            d = v2 - v1
            if d != 0:
                print(f"    {k:35s} {v1:>12} -> {v2:>12}  Δ={d:+d}")
        elif isinstance(v2, list) and v2 != v1:
            print(f"    {k:35s} {v1} -> {v2}")
delta_block('runtime')
delta_block('tcp')
delta_block('http')
delta_block('nic', ['rx_frames', 'tx_packets', 'num_queue_pairs', 'rx_max_min_ratio_x100'])
tp, tq = pre.get('tls', {}), post.get('tls', {})
db = tq.get('encrypt_bytes',0) - tp.get('encrypt_bytes',0)
dc = tq.get('encrypt_cycles',0) - tp.get('encrypt_cycles',0)
if db > 0:
    print(f"  [tls] encrypt {db} B, {dc} cy, {dc/db:.2f} cy/B")
el_p, el_q = pre.get('event_loop',{}), post.get('event_loop',{})
def ed(f): return [b-a for a,b in zip(el_p.get(f,[]), el_q.get(f,[]))]
busy, idle = ed('core_busy_cycles'), ed('core_idle_cycles')
loops, poll, svc, rt = ed('core_loops'), ed('core_poll_work'), ed('core_service_work'), ed('core_runtime_work')
for i in range(len(busy)):
    tot = busy[i] + idle[i]
    ip = 100*idle[i]/tot if tot>0 else 0
    rpl = rt[i] / max(loops[i],1)
    print(f"  c{i}: loops={loops[i]:>9} poll={poll[i]:>7} svc={svc[i]:>7} rt={rt[i]:>7} idle={ip:5.1f}% rt/loop={rpl:.4f}")
PY
REMOTE
