#!/usr/bin/env bash
# scripts/bench.sh — HTTP server benchmark
#
# Measures and compares throughput and latency for three configurations:
#   1. Unikernel       — our bare-metal HTTP server running in QEMU (TCG)
#   2. Linux + nginx   — nginx:alpine in Docker (Linux VM, hardware-accelerated
#                        on Apple Silicon via Apple Virtualization.framework)
#   3. macOS + nginx   — nginx running natively on the host, no virtualization
#
# Prerequisites (all installable via Homebrew):
#   brew install wrk nginx
#   Docker Desktop (for the Linux VM comparison)
#
# Usage:
#   ./scripts/bench.sh                        # defaults below
#   BENCH_CONNS=200 BENCH_DURATION=60 ./scripts/bench.sh
#
# Important: the unikernel's HTTP server has MAX_ACTIVE=64 simultaneous
# connections.  Keep BENCH_CONNS ≤ 63 to avoid excess connections being
# dropped by the server.  The default (50) is safe.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HOST_ARCH="$(uname -m)"   # arm64 or x86_64

# ── Benchmark parameters (override via environment) ──────────────────────────
BENCH_PORT="${BENCH_PORT:-18080}"     # separate from the dev port (8080)
THREADS="${BENCH_THREADS:-4}"
CONNS="${BENCH_CONNS:-50}"            # ≤ 63 for unikernel (MAX_ACTIVE=64)
WARMUP="${BENCH_WARMUP:-5}"           # seconds
DURATION="${BENCH_DURATION:-30}"      # seconds
ENDPOINT="/health"
BENCH_URL="http://localhost:${BENCH_PORT}${ENDPOINT}"

# ── State ────────────────────────────────────────────────────────────────────
QEMU_PID=""
DOCKER_CID=""
NGINX_RUNNING=false
HAVE_DOCKER=false
HAVE_NGINX=false

declare -a LABELS RPS_ARR P50_ARR P99_ARR

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
    [ -n "$QEMU_PID" ]          && kill -TERM "$QEMU_PID" 2>/dev/null; QEMU_PID=""
    [ -n "$DOCKER_CID" ]        && docker stop "$DOCKER_CID" >/dev/null 2>&1; DOCKER_CID=""
    [ "$NGINX_RUNNING" = true ] && nginx -c /tmp/nginx-native-bench.conf -s stop 2>/dev/null; NGINX_RUNNING=false
}
trap cleanup EXIT INT TERM

# ── Helpers ───────────────────────────────────────────────────────────────────
die() { echo "ERROR: $*" >&2; exit 1; }

wait_ready() {
    local port=$1 max=${2:-60} elapsed=0
    printf "  Waiting for server on port %s... " "$port"
    while ! curl -sf "http://localhost:${port}${ENDPOINT}" >/dev/null 2>&1; do
        if [ $elapsed -ge $max ]; then
            echo "TIMEOUT after ${max}s"
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo "ready (${elapsed}s)"
}

# Run a wrk benchmark and store results into the named shell variables.
# Usage: run_wrk label rps_var p50_var p99_var
run_wrk() {
    local label=$1 rps_var=$2 p50_var=$3 p99_var=$4

    printf "  Warmup  (%ds)... " "$WARMUP"
    wrk -t"$THREADS" -c"$CONNS" -d"${WARMUP}s" "$BENCH_URL" >/dev/null 2>&1 || true
    echo "done"

    printf "  Measure (%ds)... " "$DURATION"
    local out
    out=$(wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --latency "$BENCH_URL" 2>&1)
    echo "done"

    # Parse wrk's output
    local rps p50 p99
    rps=$(echo "$out" | awk '/Requests\/sec:/{print $2}')
    p50=$(echo "$out" | awk '/^\s+50%/{print $2}')
    p99=$(echo "$out" | awk '/^\s+99%/{print $2}')

    printf -v "$rps_var" '%s' "${rps:-N/A}"
    printf -v "$p50_var" '%s' "${p50:-N/A}"
    printf -v "$p99_var" '%s' "${p99:-N/A}"
}

# ── Prerequisite check ────────────────────────────────────────────────────────
check_prereqs() {
    echo "==> Checking prerequisites..."
    command -v wrk >/dev/null 2>&1 || die "wrk not found.  Install: brew install wrk"

    if [ "$HOST_ARCH" = "arm64" ]; then
        command -v qemu-system-aarch64 >/dev/null 2>&1 \
            || die "qemu-system-aarch64 not found.  Install: brew install qemu"
    else
        command -v qemu-system-x86_64 >/dev/null 2>&1 \
            || die "qemu-system-x86_64 not found.  Install: brew install qemu"
    fi
    echo "  wrk:    $(wrk --version 2>&1 | head -1)"

    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        HAVE_DOCKER=true
        echo "  docker: $(docker version --format '{{.Client.Version}}' 2>/dev/null || echo 'available')"
    else
        HAVE_DOCKER=false
        echo "  docker: not available  (Docker benchmark will be skipped)"
    fi

    if command -v nginx >/dev/null 2>&1; then
        HAVE_NGINX=true
        echo "  nginx:  $(nginx -v 2>&1 | head -1)"
    else
        HAVE_NGINX=false
        echo "  nginx:  not found  (native macOS benchmark will be skipped)"
        echo "          Install: brew install nginx"
    fi

    # Check port is free
    if lsof -i ":${BENCH_PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
        die "Port ${BENCH_PORT} is already in use.  Set BENCH_PORT=<other port>."
    fi
    echo ""
}

# ── Benchmark 1: Unikernel in QEMU ───────────────────────────────────────────
bench_unikernel() {
    echo "==> [1/3] Unikernel — bare-metal in QEMU (TCG software emulation)"

    echo "  Building unikernel ELF..."
    cd "$PROJECT_ROOT"
    bazel build //apps/webserver:webserver.elf 2>&1 | \
        grep -E '(INFO|ERROR|WARNING|Target)' | tail -3 || true
    local elf="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
    [ -f "$elf" ] || die "ELF not found: $elf"

    local log="/tmp/unikernel-bench.log"
    rm -f "$log"

    # Start QEMU in the background.
    # We use -chardev file so serial output goes to a log file without
    # needing a terminal; stdin is /dev/null.  We kill QEMU with SIGTERM
    # after the benchmark (no graceful VM shutdown needed here).
    local qemu_cmd
    if [ "$HOST_ARCH" = "arm64" ]; then
        qemu-system-aarch64 \
            -machine virt \
            -kernel "$elf" \
            -m 128 -smp 1 -cpu max \
            -display none -monitor none \
            -chardev "file,id=s0,path=${log}" -serial chardev:s0 \
            -no-reboot \
            -device virtio-net-pci,netdev=net0 \
            -netdev "user,id=net0,hostfwd=tcp::${BENCH_PORT}-:80" \
            </dev/null >/dev/null 2>&1 &
    else
        qemu-system-x86_64 \
            -kernel "$elf" \
            -m 128 -smp 1 -cpu qemu64 \
            -display none -monitor none \
            -chardev "file,id=s0,path=${log}" -serial chardev:s0 \
            -no-reboot \
            -device virtio-net-pci,netdev=net0 \
            -netdev "user,id=net0,hostfwd=tcp::${BENCH_PORT}-:80" \
            </dev/null >/dev/null 2>&1 &
    fi
    QEMU_PID=$!

    if ! wait_ready "$BENCH_PORT" 90; then
        echo "  Boot log (last 30 lines):"
        tail -30 "$log" 2>/dev/null || echo "  (no log)"
        kill -TERM "$QEMU_PID" 2>/dev/null; QEMU_PID=""
        echo "  Skipping unikernel benchmark."
        return 0
    fi

    local rps p50 p99
    run_wrk "unikernel" rps p50 p99

    kill -TERM "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""

    LABELS+=("Unikernel (QEMU TCG)")
    RPS_ARR+=("$rps")
    P50_ARR+=("$p50")
    P99_ARR+=("$p99")
    echo ""
}

# ── Benchmark 2: nginx in Docker (Linux VM) ───────────────────────────────────
bench_docker_nginx() {
    echo "==> [2/3] nginx in Docker  (Linux VM + nginx)"

    # Custom nginx config: match unikernel's Connection: close behaviour and
    # serve the same /health endpoint.
    cat > /tmp/nginx-bench-docker.conf << 'NGINXEOF'
events {}
http {
    keepalive_timeout 0;
    server {
        listen 80;
        location /health {
            default_type application/json;
            return 200 '{"status":"ok","runtime":"nginx","version":"docker"}';
        }
        location / { return 200 "OK\n"; }
    }
}
NGINXEOF

    local cid
    cid=$(docker run --rm -d \
        -p "${BENCH_PORT}:80" \
        -v /tmp/nginx-bench-docker.conf:/etc/nginx/nginx.conf:ro \
        nginx:alpine 2>/dev/null) \
        || { echo "  docker run failed — skipping"; echo ""; return 0; }
    DOCKER_CID="$cid"

    if ! wait_ready "$BENCH_PORT" 30; then
        docker stop "$cid" >/dev/null 2>&1 || true; DOCKER_CID=""
        echo "  Skipping Docker benchmark."; echo ""; return 0
    fi

    local rps p50 p99
    run_wrk "docker_nginx" rps p50 p99

    docker stop "$cid" >/dev/null 2>&1; DOCKER_CID=""

    LABELS+=("nginx/Linux (Docker VM)")
    RPS_ARR+=("$rps")
    P50_ARR+=("$p50")
    P99_ARR+=("$p99")
    echo ""
}

# ── Benchmark 3: native nginx on macOS ───────────────────────────────────────
bench_native_nginx() {
    echo "==> [3/3] nginx on macOS  (native, no virtualization)"

    local cfg="/tmp/nginx-native-bench.conf"
    local pid_file="/tmp/nginx-native-bench.pid"

    # Write config with keepalive_timeout=0 to match the unikernel.
    cat > "$cfg" << NGINXEOF
worker_processes 1;
pid ${pid_file};
error_log /dev/null;
events { worker_connections 1024; }
http {
    keepalive_timeout 0;
    server {
        listen ${BENCH_PORT};
        location /health {
            default_type application/json;
            return 200 '{"status":"ok","runtime":"nginx","version":"native-macos"}';
        }
        location / { return 200 "OK\n"; }
    }
}
NGINXEOF

    nginx -c "$cfg" || { echo "  nginx failed to start — skipping"; echo ""; return 0; }
    NGINX_RUNNING=true

    if ! wait_ready "$BENCH_PORT" 10; then
        nginx -c "$cfg" -s stop 2>/dev/null || true; NGINX_RUNNING=false
        echo "  Skipping native benchmark."; echo ""; return 0
    fi

    local rps p50 p99
    run_wrk "native_nginx" rps p50 p99

    nginx -c "$cfg" -s stop 2>/dev/null || true; NGINX_RUNNING=false

    LABELS+=("nginx (native macOS)")
    RPS_ARR+=("$rps")
    P50_ARR+=("$p50")
    P99_ARR+=("$p99")
    echo ""
}

# ── Results table ─────────────────────────────────────────────────────────────
print_results() {
    if [ ${#LABELS[@]} -eq 0 ]; then
        echo "No benchmark results to display."
        return
    fi

    echo "══════════════════════════════════════════════════════════════════════"
    echo "  Results"
    printf "  %s threads · %s connections · %ss · %s\n" \
        "$THREADS" "$CONNS" "$DURATION" "$ENDPOINT"
    echo "══════════════════════════════════════════════════════════════════════"
    printf "  %-30s  %12s  %8s  %8s\n" "Server" "Req/sec" "p50" "p99"
    echo "──────────────────────────────────────────────────────────────────────"
    for i in "${!LABELS[@]}"; do
        printf "  %-30s  %12s  %8s  %8s\n" \
            "${LABELS[$i]}" "${RPS_ARR[$i]}" "${P50_ARR[$i]}" "${P99_ARR[$i]}"
    done
    echo "══════════════════════════════════════════════════════════════════════"
    cat << 'NOTES'

  Interpretation
  ──────────────
  Unikernel (QEMU TCG): the unikernel runs under QEMU's software CPU emulator
    (TCG), not native hardware.  Every instruction is translated in software,
    which dominates the latency numbers.  The comparison is most meaningful
    between unikernel-in-QEMU and the Docker VM (both go through a VM layer),
    where the delta reflects OS + HTTP stack overhead rather than just TCG cost.

  Docker on Apple Silicon: uses Apple Virtualization.framework (hardware VM),
    NOT QEMU TCG.  Substantially faster than TCG for the same workload.

  Native nginx: no virtualization at all — shows the macOS scheduler and
    nginx's event loop at full speed.

  All three servers are configured with Connection: close (keepalive_timeout=0)
    to put each on equal footing with the unikernel's HTTP/1.0-style responses.

  To run with different parameters:
    BENCH_CONNS=10 BENCH_DURATION=60 ./scripts/bench.sh

NOTES
}

# ── Entry point ───────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  HTTP Server Benchmark"
echo "  Unikernel (QEMU) · Linux/nginx (Docker) · native nginx (macOS)"
echo "══════════════════════════════════════════════════════════════════════"
echo ""

check_prereqs
bench_unikernel

if [ "$HAVE_DOCKER" = true ]; then
    bench_docker_nginx
else
    echo "==> [2/3] nginx in Docker — skipped (Docker not available)"
    echo ""
fi

if [ "$HAVE_NGINX" = true ]; then
    bench_native_nginx
else
    echo "==> [3/3] nginx on macOS — skipped (nginx not installed)"
    echo "  Install: brew install nginx"
    echo ""
fi

print_results
