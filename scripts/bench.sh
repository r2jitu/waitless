#!/usr/bin/env bash
# scripts/bench.sh — HTTP server benchmark
#
# Measures and compares throughput and latency for the same webserver
# application across up to four environments:
#
#   1. Unikernel (VZ)   — macOS arm64 only: hardware-accelerated via VZ.framework
#   2. Unikernel (QEMU) — software TCG emulation (all platforms)
#   3. Linux (Docker)   — webserver compiled for Linux, running in Docker
#                         (Apple Virtualization.framework on Apple Silicon)
#   4. macOS native     — webserver_native binary, POSIX TCP, no VM
#
# The same application code (apps/webserver/main.cc + net/http.cc) runs in
# all four environments — only the TCP backend and OS differ.
#
# Prerequisites (all installable via Homebrew / standard tools):
#   brew install wrk
#   Docker Desktop (for the Linux VM comparison)
#
# Usage:
#   ./scripts/bench.sh                        # defaults below
#   BENCH_CONNS=10 BENCH_DURATION=60 ./scripts/bench.sh
#
# Note: the unikernel HTTP server supports up to MAX_ACTIVE=64 simultaneous
# connections.  Keep BENCH_CONNS ≤ 63.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/helpers.sh"

HOST_OS="$(uname -s)"     # Darwin or Linux
HOST_ARCH="$(uname -m)"   # arm64/aarch64 or x86_64

# ── Benchmark parameters (override via environment) ──────────────────────────
BENCH_PORT="${BENCH_PORT:-18080}"     # separate from the dev port (8080)
THREADS="${BENCH_THREADS:-1}"
CONNS="${BENCH_CONNS:-1}"             # Start with 1; unikernel serialises on single-thread TCP
DURATION="${BENCH_DURATION:-5}"       # seconds
# NOTE: No separate warmup run — the unikernel has no JIT/caches to warm.
# A separate warmup wrk causes the server to crash when wrk tears down
# all connections at the same time (bridge state bug). The first few seconds
# of the measurement inherently serve as warmup.
ENDPOINT="/health"

# Each benchmark gets its own port so there is zero chance of port conflicts
# between server transitions (no sleep or timing dependency needed).
PORT_VZ="${BENCH_PORT}"
PORT_QEMU="$((BENCH_PORT + 1))"
PORT_DOCKER="$((BENCH_PORT + 2))"
PORT_NATIVE="$((BENCH_PORT + 3))"
PORT_X86="$((BENCH_PORT + 4))"

# ── State ────────────────────────────────────────────────────────────────────
QEMU_PID=""
DOCKER_CID=""
SERVER_PID=""
HAVE_DOCKER=false
ORIG_MSL=""   # saved net.inet.tcp.msl before we reduce it
declare -a LABELS RPS_ARR P50_ARR P99_ARR

# ── TCP TIME_WAIT reduction (macOS only, requires sudo) ───────────────────────
# Reducing MSL 15000→500ms makes TIME_WAIT = 1s instead of 30s, which keeps
# the ephemeral port pool from exhausting between benchmarks.
reduce_time_wait() {
    [ "$HOST_OS" != "Darwin" ] && return
    ORIG_MSL=$(sysctl -n net.inet.tcp.msl 2>/dev/null || true)
    if sudo -n sysctl -w net.inet.tcp.msl=500 >/dev/null 2>&1; then
        echo "  Reduced net.inet.tcp.msl: ${ORIG_MSL}ms → 500ms (TIME_WAIT: 30s → 1s)"
    else
        echo "  note: sudo not available — will wait for TIME_WAIT to drain between benchmarks"
        ORIG_MSL=""
    fi
}
restore_time_wait() {
    [ -n "$ORIG_MSL" ] || return 0
    sudo -n sysctl -w net.inet.tcp.msl="$ORIG_MSL" >/dev/null 2>&1 || true
    ORIG_MSL=""
}

# Wait for loopback TIME_WAIT connections to drain before starting the next
# benchmark.  With Connection: close, each HTTP request leaves a source port
# in TIME_WAIT for 2*MSL (~30s on macOS default).  A high-throughput benchmark
# can exhaust the 16384-port loopback pool; the next benchmark then can't
# open new TCP connections from the host.
#
# Strategy: poll netstat every second until the loopback TIME_WAIT count drops
# below a safe threshold, with a hard cap of 2*MSL+5 seconds.
wait_port_pool() {
    [ "$HOST_OS" = "Darwin" ] || return
    # If MSL was already reduced to 500ms, TIME_WAIT = 1s — no need to wait long
    local msl
    msl=$(sysctl -n net.inet.tcp.msl 2>/dev/null || echo "15000")
    local tw_max=$(( (msl * 2 / 1000) + 5 ))  # hard timeout in seconds
    local threshold=1000  # consider pool "free" once fewer than 1000 TIME_WAIT
    local start=$SECONDS
    local first_wait=true

    while true; do
        local tw
        tw=$(netstat -an 2>/dev/null | awk '/127\.0\.0\.1.*TIME_WAIT/ || /::1.*TIME_WAIT/{c++} END{print c+0}')
        [ "$tw" -le "$threshold" ] && break
        if [ $(( SECONDS - start )) -ge $tw_max ]; then
            $first_wait && echo ""
            printf "  (TIME_WAIT drain timeout after %ds, proceeding with %d ports)\n" \
                "$tw_max" "$tw"
            return
        fi
        if $first_wait; then
            printf "  Waiting for %d TIME_WAIT ports to expire (max %ds)..." "$tw" "$tw_max"
            first_wait=false
        fi
        sleep 1
    done
    $first_wait || echo " done ($((SECONDS - start))s)"
}

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
    [ -n "$QEMU_PID" ]   && kill -TERM "$QEMU_PID"   2>/dev/null; QEMU_PID=""
    [ -n "$DOCKER_CID" ] && docker stop "$DOCKER_CID" >/dev/null 2>&1; DOCKER_CID=""
    [ -n "$SERVER_PID" ] && kill -TERM "$SERVER_PID"  2>/dev/null; SERVER_PID=""
    restore_time_wait
}
trap cleanup EXIT INT TERM

# ── Helpers ───────────────────────────────────────────────────────────────────
die() { echo "ERROR: $*" >&2; exit 1; }

wait_ready() {
    local port=$1 max=${2:-60} pid=${3:-""} host=${4:-"127.0.0.1"}
    local elapsed=0
    printf "  Waiting for server on %s:%s... " "$host" "$port"
    while ! curl -sf --max-time 3 "http://${host}:${port}${ENDPOINT}" >/dev/null 2>&1; do
        if [ $elapsed -ge $max ]; then
            echo "TIMEOUT after ${max}s"
            return 1
        fi
        # Detect if the background process has already crashed so we don't
        # spend the full timeout waiting for a server that will never arrive.
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "CRASHED (process exited unexpectedly)"
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo "ready (${elapsed}s)"
}

record_result() {
    LABELS+=("$1"); RPS_ARR+=("$2"); P50_ARR+=("$3"); P99_ARR+=("$4")
    printf "  → %s req/s  p50=%s  p99=%s\n" "$2" "$3" "$4"
}

# Run a wrk benchmark and store results into the named shell variables.
# Usage: run_wrk label rps_var p50_var p99_var url
run_wrk() {
    local label=$1 rps_var=$2 p50_var=$3 p99_var=$4 url=$5

    printf "  Measure (%ds)... " "$DURATION"
    local out
    out=$(wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --latency "$url" 2>&1) || true
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

    if [ "$HOST_OS" = "Darwin" ] && [ "$HOST_ARCH" = "arm64" ]; then
        : # run-vz is built via Bazel (bazel build //scripts:run_vz)
    elif [ "$HOST_ARCH" = "arm64" ] || [ "$HOST_ARCH" = "aarch64" ]; then
        command -v qemu-system-aarch64 >/dev/null 2>&1 \
            || die "qemu-system-aarch64 not found.  Install: brew install qemu  OR  sudo apt install qemu-system-arm"
    else
        command -v qemu-system-x86_64 >/dev/null 2>&1 \
            || die "qemu-system-x86_64 not found.  Install: brew install qemu  OR  sudo apt install qemu-system-x86"
    fi
    echo "  wrk:    $(wrk --version 2>&1 | head -1)"

    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        HAVE_DOCKER=true
        echo "  docker: $(docker version --format '{{.Client.Version}}' 2>/dev/null || echo 'available')"
    else
        HAVE_DOCKER=false
        echo "  docker: not available  (Docker benchmark will be skipped)"
    fi

    # Check all benchmark ports are free
    for _p in "$PORT_VZ" "$PORT_QEMU" "$PORT_X86" "$PORT_DOCKER" "$PORT_NATIVE"; do
        if lsof -i ":${_p}" -sTCP:LISTEN >/dev/null 2>&1; then
            die "Port ${_p} is already in use.  Set BENCH_PORT=<other base port>."
        fi
    done

    reduce_time_wait
    echo ""
}

# ── Benchmark: Unikernel (VZ or QEMU) ─────────────────────────────────────────
bench_unikernel() {
    local step=$1 port=$2
    local url="http://127.0.0.1:${port}${ENDPOINT}"
    wait_port_pool
    local label runner
    if [ "${UNIKERNEL_RUNNER:-}" = "qemu" ]; then
        label="Unikernel (QEMU TCG)"
        runner="qemu"
    elif [ "$HOST_OS" = "Darwin" ] && [ "$HOST_ARCH" = "arm64" ]; then
        label="Unikernel (VZ.framework)"
        runner="vz"
    else
        label="Unikernel (QEMU TCG)"
        runner="qemu"
    fi
    echo "==> [${step}/${TOTAL}] $label"

    echo "  Building unikernel image..."
    cd "$PROJECT_ROOT"
    # ELF is always produced — it is an intermediate product of the .img genrule.
    local elf="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
    local img="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.img"
    local build_config target artifact_path
    if [ "$runner" = "vz" ]; then
        build_config="aarch64-vz"; target="webserver.img"; artifact_path="$img"
    elif [ "$HOST_ARCH" = "arm64" ] || [ "$HOST_ARCH" = "aarch64" ]; then
        build_config="aarch64-qemu"; target="webserver.img"; artifact_path="$img"
    else
        build_config="x86_64-qemu"; target="webserver.elf"; artifact_path="$elf"
    fi
    bazel build "--config=$build_config" "//apps/webserver:$target" 2>&1 | \
        grep -E '(INFO|ERROR|WARNING|Target)' | tail -3 || true
    [ -f "$artifact_path" ] || die "$target not found: $artifact_path"

    local log="/tmp/unikernel-bench.log"
    rm -f "$log"

    if [ "$runner" = "vz" ]; then
        # ── macOS arm64: use VZ.framework via run-vz ─────────────────────────
        # run-vz accepts a pre-built raw binary image (.img).
        # Run with stdin from /dev/null (no terminal) and stdout to the log.
        # isatty() returns 0 so enableRawInput() is a no-op.  The serial
        # console writes to stdout → log; stderr (VZ banner) goes to log too.
        local RUN_VZ="$PROJECT_ROOT/bazel-bin/scripts/run-vz"
        # Always build via Bazel — fast no-op if run-vz.swift hasn't changed.
        (cd "$PROJECT_ROOT" && bazel build //scripts:run_vz 2>&1 | grep -E '(INFO|ERROR|WARNING|Target)' | tail -3) || true
        UNIKERNEL_MEMORY=128 "$RUN_VZ" "$img" "$port" \
            </dev/null >"$log" 2>&1 &
        QEMU_PID=$!

    else
        # ── QEMU path ────────────────────────────────────────────────────────
        detect_qemu "$elf"
        start_qemu "$port" "$log" "${QEMU_MACHINE[@]}" -kernel "$KERNEL_ARG"
        QEMU_PID=$VM_PID
    fi

    local timeout=60
    [ "$runner" = "vz" ] && timeout=30  # VZ boots much faster than TCG

    # For VZ with NAT networking, try to discover the VM's IP from the
    # serial log.  If DHCP succeeds, the kernel prints "dhcp: configured IP x.x.x.x".
    # Limit this search to 10s — if DHCP fails, the VM still works via
    # localhost port forwarding (the run-vz bridge handles TCP proxy).
    local wait_host="127.0.0.1"
    local wait_port="$port"
    if [ "$runner" = "vz" ]; then
        local vm_ip=""
        for (( _w=0; _w<10; _w++ )); do
            if ! kill -0 "$QEMU_PID" 2>/dev/null; then break; fi
            vm_ip=$(grep -o 'dhcp: configured IP [0-9.]*' "$log" 2>/dev/null \
                    | head -1 | awk '{print $NF}') || true
            [ -n "$vm_ip" ] && break
            sleep 1
        done
        if [ -n "$vm_ip" ]; then
            case "$vm_ip" in
                10.0.2.*) ;; # legacy bridge — use localhost:PORT
                *)
                    wait_host="$vm_ip"
                    wait_port="80"
                    url="http://${vm_ip}:80${ENDPOINT}"
                    echo "  VM IP: $vm_ip (NAT networking — direct connection)"
                    ;;
            esac
        fi
    fi

    if ! wait_ready "$wait_port" "$timeout" "$QEMU_PID" "$wait_host"; then
        echo "  Boot log (last 30 lines):"
        tail -30 "$log" 2>/dev/null || echo "  (no log)"
        kill -TERM "$QEMU_PID" 2>/dev/null; QEMU_PID=""
        echo "  Skipping unikernel benchmark."
        return 0
    fi

    local rps p50 p99
    run_wrk "unikernel" rps p50 p99 "$url"

    kill -TERM "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""

    record_result "$label" "$rps" "$p50" "$p99"
    echo ""
}

# ── Benchmark: Unikernel (QEMU x86-64 cross-emulation) ────────────────────────
bench_unikernel_x86() {
    local step=$1
    local url="http://127.0.0.1:${PORT_X86}${ENDPOINT}"
    wait_port_pool
    echo "==> [${step}/${TOTAL}] Unikernel (QEMU x86-64 TCG)"

    if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
        echo "  qemu-system-x86_64 not found — skipping"
        echo ""
        return 0
    fi

    echo "  Building x86-64 unikernel ELF..."
    cd "$PROJECT_ROOT"
    bazel build --platforms=//bazel/platforms:x86_64_unikernel \
        //apps/webserver:webserver.elf 2>&1 | \
        grep -E '(INFO|ERROR|WARNING|Target)' | tail -3 || true
    local elf="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
    [ -f "$elf" ] || { echo "  ELF not found — skipping"; echo ""; return 0; }

    local log="/tmp/unikernel-x86-bench.log"
    rm -f "$log"

    detect_qemu "$elf"
    start_qemu "$PORT_X86" "$log" "${QEMU_MACHINE[@]}" -kernel "$KERNEL_ARG"
    QEMU_PID=$VM_PID

    if ! wait_ready "$PORT_X86" 120 "$QEMU_PID"; then
        echo "  Boot log (last 30 lines):"
        tail -30 "$log" 2>/dev/null || echo "  (no log)"
        kill -TERM "$QEMU_PID" 2>/dev/null; QEMU_PID=""
        echo "  Skipping x86-64 benchmark."
        echo ""
        return 0
    fi

    local rps p50 p99
    run_wrk "unikernel_x86" rps p50 p99 "$url"

    kill -TERM "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null || true
    QEMU_PID=""

    record_result "Unikernel (QEMU x86-64 TCG)" "$rps" "$p50" "$p99"
    echo ""
}

# ── Benchmark: webserver in Docker (Linux VM) ─────────────────────────────────
bench_docker_server() {
    local url="http://127.0.0.1:${PORT_DOCKER}${ENDPOINT}"
    wait_port_pool
    echo "==> [${STEP_DOCKER}/${TOTAL}] webserver in Docker  (same app code, Linux VM)"

    echo "  Building Docker image (webserver for Linux)..."
    docker build -q \
        -f "$PROJECT_ROOT/bench/Dockerfile" \
        -t webserver_linux \
        "$PROJECT_ROOT" >/dev/null 2>&1 \
        || { echo "  docker build failed — skipping"; echo ""; return 0; }

    local cid
    cid=$(docker run --rm -d \
        -p "${PORT_DOCKER}:80" \
        webserver_linux 2>/dev/null) \
        || { echo "  docker run failed — skipping"; echo ""; return 0; }
    DOCKER_CID="$cid"

    if ! wait_ready "$PORT_DOCKER" 30; then
        docker stop "$cid" >/dev/null 2>&1 || true; DOCKER_CID=""
        echo "  Skipping Docker benchmark."; echo ""; return 0
    fi

    local rps p50 p99
    run_wrk "docker_server" rps p50 p99 "$url"

    docker stop "$cid" >/dev/null 2>&1; DOCKER_CID=""

    record_result "webserver/Linux (Docker VM)" "$rps" "$p50" "$p99"
    echo ""
}

# ── Benchmark: webserver_native (same app code, POSIX TCP, no VM) ─────────────
bench_native_server() {
    local url="http://127.0.0.1:${PORT_NATIVE}${ENDPOINT}"
    wait_port_pool
    echo "==> [${STEP_NATIVE}/${TOTAL}] webserver_native  (same app code, POSIX TCP, no VM)"

    echo "  Building webserver_native..."
    cd "$PROJECT_ROOT"
    bazel build --config=aarch64-macos //apps/webserver:webserver_native 2>&1 | \
        grep -E '(INFO|ERROR|WARNING|Target)' | tail -3 || true

    local bin="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver_native"
    if [ ! -f "$bin" ]; then
        echo "  Binary not found — skipping"; echo ""; return 0
    fi

    PORT="$PORT_NATIVE" "$bin" >/dev/null 2>&1 &
    SERVER_PID=$!

    if ! wait_ready "$PORT_NATIVE" 10 "$SERVER_PID"; then
        kill -TERM "$SERVER_PID" 2>/dev/null; SERVER_PID=""
        echo "  Skipping webserver_native benchmark."; echo ""; return 0
    fi

    local rps p50 p99
    run_wrk "webserver_native" rps p50 p99 "$url"

    kill -TERM "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""

    record_result "webserver_native (POSIX, no VM)" "$rps" "$p50" "$p99"
    echo ""
}

print_results() {
    [ ${#LABELS[@]} -eq 0 ] && { echo "No benchmark results to display."; return; }
    echo "══════════════════════════════════════════════════════════════════════"
    printf "  Results  (%s threads · %s connections · %ss · %s)\n" \
        "$THREADS" "$CONNS" "$DURATION" "$ENDPOINT"
    echo "══════════════════════════════════════════════════════════════════════"
    printf "  %-35s  %12s  %8s  %8s\n" "Server" "Req/sec" "p50" "p99"
    echo "──────────────────────────────────────────────────────────────────────"
    for i in "${!LABELS[@]}"; do
        printf "  %-35s  %12s  %8s  %8s\n" \
            "${LABELS[$i]}" "${RPS_ARR[$i]}" "${P50_ARR[$i]}" "${P99_ARR[$i]}"
    done
    echo "══════════════════════════════════════════════════════════════════════"
    echo "  To run with different parameters:"
    echo "    BENCH_CONNS=10 BENCH_DURATION=60 ./scripts/bench.sh"
    echo "══════════════════════════════════════════════════════════════════════"
}

# ── Entry point ───────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  HTTP Server Benchmark  (same app code, four environments)"
echo "  Unikernel VZ · Unikernel QEMU · Linux/Docker · macOS native"
echo "══════════════════════════════════════════════════════════════════════"
echo ""

check_prereqs

# On macOS arm64, run both VZ (hardware-accelerated) and QEMU (TCG).
# On other platforms, only one unikernel runner is available.
# x86-64 cross-emulation benchmark runs if qemu-system-x86_64 is installed.
HAS_QEMU_X86=false
command -v qemu-system-x86_64 >/dev/null 2>&1 && HAS_QEMU_X86=true

NEXT_STEP=1
STEP_UNIKERNEL_VZ=""
STEP_UNIKERNEL_QEMU=""
STEP_UNIKERNEL_X86=""

if [ "$HOST_OS" = "Darwin" ] && [ "$HOST_ARCH" = "arm64" ] && [ "${UNIKERNEL_RUNNER:-}" != "qemu" ]; then
    STEP_UNIKERNEL_VZ=$NEXT_STEP; NEXT_STEP=$((NEXT_STEP + 1))
fi
STEP_UNIKERNEL_QEMU=$NEXT_STEP; NEXT_STEP=$((NEXT_STEP + 1))
if [ "$HAS_QEMU_X86" = true ] && [ "$HOST_ARCH" != "x86_64" ]; then
    STEP_UNIKERNEL_X86=$NEXT_STEP; NEXT_STEP=$((NEXT_STEP + 1))
fi
STEP_DOCKER=$NEXT_STEP; NEXT_STEP=$((NEXT_STEP + 1))
STEP_NATIVE=$NEXT_STEP; NEXT_STEP=$((NEXT_STEP + 1))
TOTAL=$((NEXT_STEP - 1))

# Run VZ benchmark (macOS arm64 only)
if [ -n "$STEP_UNIKERNEL_VZ" ]; then
    bench_unikernel "$STEP_UNIKERNEL_VZ" "$PORT_VZ"
fi

# Run aarch64 QEMU benchmark (always on arm64; overrides default on macOS arm64)
UNIKERNEL_RUNNER=qemu bench_unikernel "$STEP_UNIKERNEL_QEMU" "$PORT_QEMU"

# Run x86-64 QEMU benchmark (cross-architecture emulation)
if [ -n "$STEP_UNIKERNEL_X86" ]; then
    bench_unikernel_x86 "$STEP_UNIKERNEL_X86"
fi

if [ "$HAVE_DOCKER" = true ]; then
    bench_docker_server
else
    echo "==> [${STEP_DOCKER}/${TOTAL}] webserver in Docker — skipped (Docker not available)"
    echo ""
fi

bench_native_server

print_results
