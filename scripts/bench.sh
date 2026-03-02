#!/usr/bin/env bash
# scripts/bench.sh — HTTP server benchmark
#
# Measures and compares throughput and latency for three configurations,
# all running the SAME minimal poll()-based HTTP server (bench_server.c):
#
#   1. Unikernel       — our bare-metal HTTP server running in QEMU (TCG)
#   2. Linux (Docker)  — bench_server compiled for Linux, running in Docker
#                        (Apple Virtualization.framework on Apple Silicon)
#   3. macOS (native)  — bench_server compiled natively on the host, no VM
#
# Using the same server code in all three scenarios isolates OS and
# virtualization overhead rather than differences between HTTP servers.
#
# Prerequisites (all installable via Homebrew / standard tools):
#   brew install wrk
#   Docker Desktop (for the Linux VM comparison)
#   Xcode Command Line Tools / any cc (for the native macOS build)
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
SERVER_PID=""
HAVE_DOCKER=false
HAVE_CC=false

declare -a LABELS RPS_ARR P50_ARR P99_ARR

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
    [ -n "$QEMU_PID" ]   && kill -TERM "$QEMU_PID"   2>/dev/null; QEMU_PID=""
    [ -n "$DOCKER_CID" ] && docker stop "$DOCKER_CID" >/dev/null 2>&1; DOCKER_CID=""
    [ -n "$SERVER_PID" ] && kill -TERM "$SERVER_PID"  2>/dev/null; SERVER_PID=""
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
    out=$(wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --latency "$BENCH_URL" 2>&1) || true
    echo "done"

    # Parse wrk's output.
    # Use _-prefixed names to avoid colliding with the caller's local variables
    # of the same name (which would cause printf -v to set the wrong scope).
    local _rps _p50 _p99
    _rps=$(echo "$out" | awk '/Requests\/sec:/{print $2}')
    _p50=$(echo "$out" | awk '/[[:space:]]50%/{print $2}')
    _p99=$(echo "$out" | awk '/[[:space:]]99%/{print $2}')

    printf -v "$rps_var" '%s' "${_rps:-N/A}"
    printf -v "$p50_var" '%s' "${_p50:-N/A}"
    printf -v "$p99_var" '%s' "${_p99:-N/A}"
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

    if command -v cc >/dev/null 2>&1; then
        HAVE_CC=true
        echo "  cc:     $(cc --version 2>&1 | head -1)"
    else
        HAVE_CC=false
        echo "  cc:     not found  (native macOS benchmark will be skipped)"
        echo "          Install: xcode-select --install"
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
    # -chardev file routes serial output to a log without needing a terminal.
    if [ "$HOST_ARCH" = "arm64" ]; then
        # virtio-net-device (MMIO) is simpler than virtio-net-pci and avoids
        # the PCIe ECAM bus scan in the kernel.
        # Note: HVF is not used — QEMU on ARM64 aborts on ISV=0 exits from
        # UART/GIC MMIO accesses, which is a separate limitation from PCIe ECAM.
        qemu-system-aarch64 \
            -machine virt \
            -kernel "$elf" \
            -m 128 -smp 1 -cpu max \
            -display none -monitor none \
            -chardev "file,id=s0,path=${log}" -serial chardev:s0 \
            -no-reboot \
            -device virtio-net-device,netdev=net0 \
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

# ── Benchmark 2: bench_server in Docker (Linux VM) ────────────────────────────
bench_docker_server() {
    echo "==> [2/3] bench_server in Docker  (Linux VM + same server code)"

    echo "  Building Docker image (bench_server for Linux)..."
    docker build -q \
        -f "$PROJECT_ROOT/bench/Dockerfile" \
        -t bench_server_linux \
        "$PROJECT_ROOT" >/dev/null 2>&1 \
        || { echo "  docker build failed — skipping"; echo ""; return 0; }

    local cid
    cid=$(docker run --rm -d \
        -p "${BENCH_PORT}:80" \
        bench_server_linux 2>/dev/null) \
        || { echo "  docker run failed — skipping"; echo ""; return 0; }
    DOCKER_CID="$cid"

    if ! wait_ready "$BENCH_PORT" 30; then
        docker stop "$cid" >/dev/null 2>&1 || true; DOCKER_CID=""
        echo "  Skipping Docker benchmark."; echo ""; return 0
    fi

    local rps p50 p99
    run_wrk "docker_server" rps p50 p99

    docker stop "$cid" >/dev/null 2>&1; DOCKER_CID=""

    LABELS+=("bench_server/Linux (Docker VM)")
    RPS_ARR+=("$rps")
    P50_ARR+=("$p50")
    P99_ARR+=("$p99")
    echo ""
}

# ── Benchmark 3: bench_server native on macOS ─────────────────────────────────
bench_native_server() {
    echo "==> [3/3] bench_server on macOS  (native, no virtualization)"

    local bin="/tmp/bench_server_macos"
    echo "  Compiling bench_server for macOS..."
    cc -O2 -DRUNTIME='"macos"' \
        -o "$bin" \
        "$PROJECT_ROOT/bench/bench_server.c" 2>&1 \
        || { echo "  Compile failed — skipping"; echo ""; return 0; }

    "$bin" "$BENCH_PORT" >/dev/null 2>&1 &
    SERVER_PID=$!

    if ! wait_ready "$BENCH_PORT" 10; then
        kill -TERM "$SERVER_PID" 2>/dev/null; SERVER_PID=""
        echo "  Skipping native benchmark."; echo ""; return 0
    fi

    local rps p50 p99
    run_wrk "native_server" rps p50 p99

    kill -TERM "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""

    LABELS+=("bench_server (native macOS)")
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
    printf "  %-35s  %12s  %8s  %8s\n" "Server" "Req/sec" "p50" "p99"
    echo "──────────────────────────────────────────────────────────────────────"
    for i in "${!LABELS[@]}"; do
        printf "  %-35s  %12s  %8s  %8s\n" \
            "${LABELS[$i]}" "${RPS_ARR[$i]}" "${P50_ARR[$i]}" "${P99_ARR[$i]}"
    done
    echo "══════════════════════════════════════════════════════════════════════"
    cat << 'NOTES'

  Interpretation
  ──────────────
  All three scenarios run the same poll()-based HTTP server (bench_server.c)
    so the benchmark isolates OS and virtualization overhead rather than
    differences between HTTP server implementations.  Each server uses
    Connection: close (no keep-alive) after every response, matching the
    unikernel's HTTP/1.0-style behaviour.

  Unikernel (QEMU TCG): every instruction is translated in software by QEMU's
    TCG emulator.  Network packets also traverse virtio-net emulation.  Both
    TCG cost and virtio overhead are included in the latency numbers.

  bench_server/Linux (Docker): on Apple Silicon, Docker uses Apple
    Virtualization.framework (hardware-accelerated VM), NOT QEMU TCG.
    Network still goes through a virtual interface, but the guest CPU runs
    at near-native speed.  This scenario shows Linux kernel + network stack
    overhead on top of the hardware VM.

  bench_server (native macOS): no virtualization — just the macOS TCP stack
    and the poll() event loop at full speed.  This is the practical ceiling
    for single-threaded connection throughput on this machine.

  To run with different parameters:
    BENCH_CONNS=10 BENCH_DURATION=60 ./scripts/bench.sh

NOTES
}

# ── Entry point ───────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  HTTP Server Benchmark  (same server code, three environments)"
echo "  Unikernel (QEMU) · Linux/bench_server (Docker) · macOS (native)"
echo "══════════════════════════════════════════════════════════════════════"
echo ""

check_prereqs
bench_unikernel

if [ "$HAVE_DOCKER" = true ]; then
    bench_docker_server
else
    echo "==> [2/3] bench_server in Docker — skipped (Docker not available)"
    echo ""
fi

if [ "$HAVE_CC" = true ]; then
    bench_native_server
else
    echo "==> [3/3] bench_server on macOS — skipped (cc not found)"
    echo "  Install: xcode-select --install"
    echo ""
fi

print_results
