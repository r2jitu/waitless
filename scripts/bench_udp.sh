#!/usr/bin/env bash
# scripts/bench_udp.sh — UDP echo benchmark: measures multi-core scaling.
#
# Sends UDP packets from multiple source ports to exercise flow-hash
# distribution across cores. Measures packets/sec and latency.
#
# Usage:
#   ./scripts/bench_udp.sh                    # default: 1 and 4 cores
#   UNIKERNEL_CPUS=8 ./scripts/bench_udp.sh   # custom core count

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/helpers.sh"

DURATION="${BENCH_DURATION:-5}"
SENDERS="${BENCH_UDP_SENDERS:-8}"     # number of parallel sender threads
BASE_PORT=25400

cleanup() {
    [[ -n "${VM_PID:-}" ]] && kill -TERM "$VM_PID" 2>/dev/null
    wait "$VM_PID" 2>/dev/null || true
    [[ -n "${VM_LOG:-}" ]] && rm -f "$VM_LOG"
}
trap cleanup EXIT

# Python script that sends/receives UDP from multiple source ports in parallel
udp_bench_py() {
    local port=$1 duration=$2 senders=$3
    python3 -c "
import socket, time, threading, sys

PORT = $port
DURATION = $duration
SENDERS = $senders

sent = [0] * SENDERS
received = [0] * SENDERS
latencies = [[] for _ in range(SENDERS)]

def sender(idx):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    # Bind to a unique source port so flow hash distributes across cores
    s.bind(('', 0))
    msg = f'bench{idx}'.encode()
    end = time.monotonic() + DURATION
    while time.monotonic() < end:
        t0 = time.monotonic()
        s.sendto(msg, ('127.0.0.1', PORT))
        sent[idx] += 1
        try:
            data, _ = s.recvfrom(64)
            t1 = time.monotonic()
            received[idx] += 1
            latencies[idx].append(t1 - t0)
        except socket.timeout:
            pass
    s.close()

threads = []
for i in range(SENDERS):
    t = threading.Thread(target=sender, args=(i,))
    t.start()
    threads.append(t)
for t in threads:
    t.join()

total_sent = sum(sent)
total_recv = sum(received)
all_lat = sorted(sum(latencies, []))
if all_lat:
    p50 = all_lat[len(all_lat)//2]
    p99 = all_lat[int(len(all_lat)*0.99)]
else:
    p50 = p99 = 0

rps = total_recv / DURATION
print(f'{rps:.1f} pkt/s  p50={p50*1e6:.0f}us  p99={p99*1e6:.0f}us  (sent={total_sent} recv={total_recv})')
" 2>&1
}

run_bench() {
    local label=$1 cpus=$2 port=$3

    local elf="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
    detect_qemu "$elf"
    command -v "$QEMU_BIN" &>/dev/null || { echo "SKIP: $QEMU_BIN not found"; return; }

    export UNIKERNEL_CPUS=$cpus
    start_qemu "$port" "" "${QEMU_MACHINE[@]}" -kernel "$KERNEL_ARG"

    # Wait for server (HTTP ready implies UDP echo is also ready)
    if ! wait_http "$port" 30 "$VM_PID"; then
        echo "  $label: server didn't start"
        kill -TERM "$VM_PID" 2>/dev/null; wait "$VM_PID" 2>/dev/null || true; VM_PID=""
        return
    fi

    local udp_port=$((port + 1))
    printf "  %-35s " "$label"
    udp_bench_py "$udp_port" "$DURATION" "$SENDERS"

    kill -TERM "$VM_PID" 2>/dev/null; wait "$VM_PID" 2>/dev/null || true; VM_PID=""
    sleep 1
}

# Build
echo "==> Building..."
cd "$PROJECT_ROOT"

HOST_ARCH="$(uname -m)"
if [[ "$HOST_ARCH" == "arm64" ]] || [[ "$HOST_ARCH" == "aarch64" ]]; then
    bazel build --config=aarch64-qemu //apps/webserver:webserver.img 2>&1 | tail -1
else
    bazel build --config=x86_64-qemu //apps/webserver:webserver.elf 2>&1 | tail -1
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  UDP Echo Benchmark  (${SENDERS} senders × ${DURATION}s)"
echo "═══════════════════════════════════════════════════════════════════"

run_bench "1-core" 1 "$BASE_PORT"
run_bench "2-core (MTTCG)" 2 "$((BASE_PORT + 10))"
run_bench "4-core (MTTCG)" 4 "$((BASE_PORT + 20))"

echo "═══════════════════════════════════════════════════════════════════"
