#!/usr/bin/env bash
# pareto-bench.sh — drive a concurrency sweep against one or more
# peer VMs (waitless / nginx / tokio-hyper) from the kvm-vm loadgen,
# emit JSONL the Pareto chart script consumes.
#
# What it does, end-to-end:
#   1. Brings up the kvm-vm (loadgen) and ensures sysctls + wrk are
#      installed.
#   2. For each requested peer + workload + concurrency level, runs
#      wrk for $DURATION seconds against the peer's internal IP.
#   3. Emits one JSON line per (peer, workload, concurrency) cell to
#      stdout — the chart-generation step parses these directly. Also
#      mirrors a human-readable summary to stderr.
#
# Usage:
#   ./pareto-bench.sh --peer nginx --target 10.138.0.43
#   ./pareto-bench.sh --peer waitless --target 10.138.0.42 \
#       --workload health,static64k \
#       --conns 100,1000,4000,16000,32000 \
#       --duration 30
#
#   # Multiple peers in one run: invoke once per peer; the JSONL is
#   # additive (append > out.jsonl).
#
# Outputs:
#   stdout: one JSON object per line:
#     {"peer":"nginx","machine":"c3-highcpu-8","workload":"health-tls",
#      "conns":16000,"threads":4,"rps":234567,"p50_us":68,
#      "p99_us":210,"duration_s":30}
#   stderr: progress + per-cell summary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

PEER=""
TARGET=""
MACHINE=""
WORKLOADS="health,health-tls,static64k-tls"
CONNS="100,1000,4000,16000,32000"
DURATION=30
WARMUP=5

KVM_NAME="${GCP_KVM_VM_NAME:-kvm-vm}"
KVM_ZONE="${GCP_KVM_VM_ZONE:-us-west1-c}"

while [ $# -gt 0 ]; do
    case "$1" in
    --peer)
        shift
        PEER="$1"
        ;;
    --target)
        shift
        TARGET="$1"
        ;;
    --machine)
        shift
        MACHINE="$1"
        ;;
    --workload | --workloads)
        shift
        WORKLOADS="$1"
        ;;
    --conns)
        shift
        CONNS="$1"
        ;;
    --duration)
        shift
        DURATION="$1"
        ;;
    --warmup)
        shift
        WARMUP="$1"
        ;;
    -h | --help)
        sed -n '2,28p' "$0" | sed 's/^# *//'
        exit 0
        ;;
    *)
        echo "unknown arg: $1" >&2
        exit 1
        ;;
    esac
    shift
done

[ -n "$PEER" ] || { echo "error: --peer required (waitless|nginx|tokio-hyper)" >&2; exit 1; }
[ -n "$TARGET" ] || { echo "error: --target IP required" >&2; exit 1; }

# Auto-detect machine if not provided. Looks up the peer's actual GCE
# machine type so the JSONL row is self-describing without needing the
# caller to pass it manually.
if [ -z "$MACHINE" ]; then
    # Map peer name to the GCE instance name peer-deploy.sh creates.
    case "$PEER" in
    nginx) inst="waitless-peer-nginx" ;;
    tokio-hyper) inst="waitless-peer-tokio" ;;
    waitless) inst="${WAITLESS_GCE_NAME:-waitless-webserver}" ;;
    *) inst="" ;;
    esac
    if [ -n "$inst" ]; then
        MACHINE="$(gcloud compute instances describe "$inst" \
            --zone="$KVM_ZONE" --format='value(machineType.basename())' 2>/dev/null || echo unknown)"
    else
        MACHINE="unknown"
    fi
fi

PROJECT="${WAITLESS_GCE_PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"

# ── Ensure kvm-vm is up and has wrk + tuned sysctls ───────────
echo "==> Ensuring $KVM_NAME is running..." >&2
status="$(gcloud compute instances describe "$KVM_NAME" --zone="$KVM_ZONE" \
    --project="$PROJECT" --format='value(status)' 2>/dev/null || echo MISSING)"
case "$status" in
RUNNING) ;;
TERMINATED | STOPPED)
    gcloud compute instances start "$KVM_NAME" --zone="$KVM_ZONE" --project="$PROJECT" >/dev/null
    for _ in $(seq 1 30); do
        if gcloud compute ssh "$KVM_NAME" --zone="$KVM_ZONE" --project="$PROJECT" \
            --command='true' >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done
    ;;
MISSING)
    echo "error: $KVM_NAME does not exist" >&2
    exit 1
    ;;
esac

ssh_kvm() {
    gcloud compute ssh "$KVM_NAME" --zone="$KVM_ZONE" \
        --project="$PROJECT" --command="$1"
}

# Install wrk + tune loadgen sysctls. Idempotent.
echo "==> Tuning loadgen sysctls + installing wrk..." >&2
ssh_kvm "
command -v wrk >/dev/null 2>&1 || sudo apt-get install -y -qq wrk >/dev/null
sudo sysctl -w net.ipv4.tcp_tw_reuse=1 net.ipv4.ip_local_port_range='1024 65535' \
    net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535 \
    fs.file-max=2097152 >/dev/null
ulimit -n 1048576
" >/dev/null

# ── Map workload name to URL path + scheme ────────────────────
workload_url() {
    case "$1" in
    health)        echo "http://$TARGET/health" ;;
    health-tls)    echo "https://$TARGET/health" ;;
    static64k)     echo "http://$TARGET/static-64k" ;;
    static64k-tls) echo "https://$TARGET/static-64k" ;;
    *)             echo "" ;;
    esac
}

# wrk thread count: one thread per ~10K conns, capped at host vCPUs.
# kvm-vm is c3-highcpu-8, so cap at 8.
threads_for_conns() {
    local conns=$1
    local n=$(( conns / 10000 ))
    [ $n -lt 1 ] && n=1
    [ $n -gt 8 ] && n=8
    echo $n
}

# Parse wrk output: pull Requests/sec, Latency p50/p99, Transfer/sec.
# wrk's default output is human-readable; we grep specific lines.
# Latency suffix can be us/ms/s — normalize to microseconds for the JSON.
parse_wrk() {
    local out="$1"
    # Requests/sec line:  "Requests/sec:    234567.89"
    local rps p50 p99
    rps=$(echo "$out" | awk '/Requests\/sec:/ {print $2}')
    [ -z "$rps" ] && rps="0"
    # Latency Distribution lines:
    #   "    50%   68.00us"
    #   "    99%  210.00us"
    p50=$(echo "$out" | awk '/^[[:space:]]+50%/ {print $2}')
    p99=$(echo "$out" | awk '/^[[:space:]]+99%/ {print $2}')
    p50_us=$(to_us "$p50")
    p99_us=$(to_us "$p99")
    echo "$rps $p50_us $p99_us"
}

# Convert a wrk latency value like "68.00us" / "210.45ms" / "1.20s"
# to integer microseconds.
to_us() {
    local v="$1"
    [ -z "$v" ] && { echo 0; return; }
    local num unit
    num=$(echo "$v" | sed -E 's/([0-9.]+).*/\1/')
    unit=$(echo "$v" | sed -E 's/[0-9.]+(.*)/\1/')
    case "$unit" in
    us) printf '%.0f\n' "$num" ;;
    ms) printf '%.0f\n' "$(echo "$num * 1000" | bc -l)" ;;
    s)  printf '%.0f\n' "$(echo "$num * 1000000" | bc -l)" ;;
    *)  echo 0 ;;
    esac
}

# ── Sweep ─────────────────────────────────────────────────────
echo "" >&2
echo "==> Pareto sweep: peer=$PEER target=$TARGET machine=$MACHINE" >&2
echo "    workloads: $WORKLOADS" >&2
echo "    conns:     $CONNS" >&2
echo "    duration:  ${DURATION}s (+${WARMUP}s warmup)" >&2
echo "" >&2

IFS=',' read -ra WL_LIST <<<"$WORKLOADS"
IFS=',' read -ra CONN_LIST <<<"$CONNS"

for wl in "${WL_LIST[@]}"; do
    url="$(workload_url "$wl")"
    [ -z "$url" ] && { echo "skip: unknown workload '$wl'" >&2; continue; }
    for conns in "${CONN_LIST[@]}"; do
        threads=${PARETO_THREADS:-$(threads_for_conns "$conns")}
        echo -n "  [$wl c=$conns t=$threads] " >&2

        # Warm up: discard a $WARMUP-second run. Then the measurement.
        # `wrk --latency` enables percentile histograms.
        ssh_kvm "wrk -t $threads -c $conns -d ${WARMUP}s --timeout 10s $url >/dev/null 2>&1 || true" >/dev/null
        out=$(ssh_kvm "wrk -t $threads -c $conns -d ${DURATION}s --latency --timeout 10s $url 2>&1 || true")

        read -r rps p50_us p99_us <<<"$(parse_wrk "$out")"

        # Tolerate wrk producing 0 (e.g., conn exhaustion) — still
        # emit the row so the chart sees the data point.
        echo "rps=$rps p50=${p50_us}us p99=${p99_us}us" >&2

        printf '{"peer":"%s","machine":"%s","target":"%s","workload":"%s","conns":%d,"threads":%d,"rps":%s,"p50_us":%s,"p99_us":%s,"duration_s":%d}\n' \
            "$PEER" "$MACHINE" "$TARGET" "$wl" "$conns" "$threads" "$rps" "$p50_us" "$p99_us" "$DURATION"
    done
done

echo "" >&2
echo "==> Sweep done." >&2
