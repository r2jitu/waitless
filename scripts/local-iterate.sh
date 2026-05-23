#!/usr/bin/env bash
# scripts/local-iterate.sh — Fast local edit-build-bench loop on HVF.
#
# Targets the perf-bottleneck investigation on the bench/pareto-rig
# branch: each cycle builds the unikernel, launches it under Apple
# HVF, drives load via wrk against the forwarded ports, snapshots
# /obs, kills the VM, and prints a summary.
#
# Typical cycle: ~30s end-to-end (most of that is the wrk run).
# vs. GCE deploy + probe: ~3-5 minutes. ~10x iteration speedup for
# code that doesn't depend on the gve NIC driver path.
#
# What HVF CAN'T reproduce vs GCE:
#   - gve NIC-driver bottlenecks (HVF uses userspace TCP proxy)
#   - Real network packet RST/retransmit dynamics under loss
#
# What HVF CAN reproduce:
#   - async runtime overhead at scale
#   - TCP slot pool contention
#   - per-conn allocation churn
#   - HTTP / TLS hot-path costs
#
# Usage:
#   ./local-iterate.sh                          # default: 1000 conns, 10s
#   ./local-iterate.sh --conns 4000             # custom conn count
#   ./local-iterate.sh --conns 500 --duration 20 --workload health-tls
#
# Workloads:
#   health      - HTTP /health
#   health-tls  - HTTPS /health
#   static64k   - HTTP /static-64k
#   static64k-tls - HTTPS /static-64k

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

CONNS=1000
DURATION=10
WARMUP=2
WORKLOAD="health-tls"
THREADS=4
VCPUS=4
RAM_MB=512

while [ $# -gt 0 ]; do
    case "$1" in
    --conns) shift; CONNS="$1" ;;
    --duration) shift; DURATION="$1" ;;
    --warmup) shift; WARMUP="$1" ;;
    --workload) shift; WORKLOAD="$1" ;;
    --threads) shift; THREADS="$1" ;;
    --cpus) shift; VCPUS="$1" ;;
    --ram) shift; RAM_MB="$1" ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# *//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
    shift
done

# wrk needs higher fd limits for high-conn tests on macOS. Bumping
# now; harmless on lower-conn runs.
ulimit -n 16384 2>/dev/null || true

# Map workload to URL.
case "$WORKLOAD" in
health)        URL="http://127.0.0.1:8080/health" ;;
health-tls)    URL="https://127.0.0.1:8443/health" ;;
static64k)     URL="http://127.0.0.1:8080/static-64k" ;;
static64k-tls) URL="https://127.0.0.1:8443/static-64k" ;;
*) echo "unknown workload: $WORKLOAD" >&2; exit 1 ;;
esac

# Build the HVF launcher target (incremental — fast after first build).
echo "==> Building //apps/webserver:webserver_hvf..." >&2
bazel build //apps/webserver:webserver_hvf >/dev/null 2>&1

# Launch HVF in background. The launcher already wires the port
# forwards from BUILD.bazel (tcp:8080→80, tcp:8443→443, udp:8443→443).
echo "==> Starting HVF VM (vcpus=$VCPUS, ram=${RAM_MB}MB)..." >&2
bazel run //apps/webserver:webserver_hvf -- \
    "--cpus=$VCPUS" "--ram=$RAM_MB" \
    >/tmp/webserver-hvf.log 2>&1 &
VM_PID=$!
trap '{
    # Kill the launcher subprocess; HVF runner exits when its
    # parent goes away. Pipe to /dev/null to swallow shutdown noise.
    kill $VM_PID 2>/dev/null || true
    wait 2>/dev/null || true
}' EXIT

# Wait for /health to respond.
echo -n "==> Waiting for boot... " >&2
for i in $(seq 1 60); do
    if curl -fsSk --max-time 1 http://127.0.0.1:8080/health >/dev/null 2>&1; then
        echo "ready (${i}s)" >&2
        break
    fi
    sleep 1
done
if ! curl -fsSk --max-time 2 http://127.0.0.1:8080/health >/dev/null 2>&1; then
    echo "FAILED — last serial:" >&2
    tail -20 /tmp/webserver-hvf.log
    exit 1
fi

# Snapshot /obs before load.
curl -sk http://127.0.0.1:8080/obs > /tmp/obs-pre.json

# Run wrk.
echo "==> wrk -t$THREADS -c$CONNS -d${DURATION}s --latency $URL" >&2
WRK_OUT=$(wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" \
    --latency --timeout 10s "$URL" 2>&1 || true)
echo "$WRK_OUT" | grep -E 'Requests/sec|Latency|Socket errors|^\s+[59]9|^\s+50%' >&2

# Snapshot /obs after load.
curl -sk http://127.0.0.1:8080/obs > /tmp/obs-post.json

# Print /obs deltas for the most interesting blocks.
echo "" >&2
echo "==> /obs deltas (post - pre):" >&2
python3 - <<EOF
import json
pre = json.load(open('/tmp/obs-pre.json'))
post = json.load(open('/tmp/obs-post.json'))

def delta_block(name, keys=None):
    p, q = pre.get(name, {}), post.get(name, {})
    print(f"  [{name}]")
    for k in (keys or sorted(set(p.keys()) | set(q.keys()))):
        v1 = p.get(k, 0)
        v2 = q.get(k, 0)
        if isinstance(v2, (int, float)) and isinstance(v1, (int, float)):
            d = v2 - v1
            if d != 0:
                print(f"    {k:35s} {v1:>12} -> {v2:>12}  Δ={d:+d}")
        elif isinstance(v2, list) and v2 != v1:
            print(f"    {k:35s} {v1} -> {v2}")

delta_block('runtime')
delta_block('tcp')
delta_block('http')
delta_block('nic', ['rx_frames', 'tx_packets', 'num_queue_pairs'])
print("  [tls cy/B]")
tls_p = pre.get('tls', {})
tls_q = post.get('tls', {})
db = tls_q.get('encrypt_bytes', 0) - tls_p.get('encrypt_bytes', 0)
dc = tls_q.get('encrypt_cycles', 0) - tls_p.get('encrypt_cycles', 0)
if db > 0:
    print(f"    encrypt: {db:>12} B, {dc:>14} cy, {dc/db:.2f} cy/B")
print("  [event_loop deltas]")
el_p = pre.get('event_loop', {})
el_q = post.get('event_loop', {})
def el_deltas(field):
    p = el_p.get(field, [])
    q = el_q.get(field, [])
    return [b - a for a, b in zip(p, q)]
busy = el_deltas('core_busy_cycles')
idle = el_deltas('core_idle_cycles')
loops = el_deltas('core_loops')
poll = el_deltas('core_poll_work')
svc = el_deltas('core_service_work')
rt = el_deltas('core_runtime_work')
ie = el_deltas('core_idle_enters')
for i in range(len(busy)):
    tot = busy[i] + idle[i]
    idle_pct = 100.0 * idle[i] / tot if tot > 0 else 0
    rt_per_loop = rt[i] / max(loops[i], 1)
    print(f"    c{i}: loops={loops[i]:>9} poll={poll[i]:>7} svc={svc[i]:>7} rt={rt[i]:>7} idle_ent={ie[i]:>5} idle={idle_pct:5.1f}% rt/loop={rt_per_loop:.4f}")
EOF
