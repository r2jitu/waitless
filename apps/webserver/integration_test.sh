#!/usr/bin/env bash
# apps/webserver/integration_test.sh
#
# Integration test: boot the webserver in QEMU, verify HTTP endpoints respond
# correctly, then shut QEMU down.
#
# Run:
#   bazel test //apps/webserver:integration_test              # x86_64
#   bazel test --config=aarch64 //apps/webserver:integration_test  # aarch64
#
# Requirements:  qemu-system-{x86_64,aarch64}  (brew install qemu)
# If the right QEMU binary is missing the test is skipped (exit 0).

set -euo pipefail

FAILURES=0
QEMU_PID=""
QEMU_LOG=""

# ---- Cleanup on exit --------------------------------------------------------
cleanup() {
    if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    [[ -n "$QEMU_LOG" ]] && rm -f "$QEMU_LOG" || true
}
trap cleanup EXIT

# ---- Locate the webserver binary --------------------------------------------
# Bazel sets RUNFILES_DIR when running via "bazel test".
RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
ELF="${RUNFILES}/_main/apps/webserver/webserver.elf"
IMG="${RUNFILES}/_main/apps/webserver/webserver.img"

if [[ ! -f "$ELF" ]]; then
    echo "ERROR: webserver.elf not found at $ELF" >&2
    exit 1
fi

# ---- Detect ELF architecture ------------------------------------------------
ELF_INFO="$(file "$ELF" 2>/dev/null || echo "")"

if echo "$ELF_INFO" | grep -q "ARM aarch64"; then
    QEMU_BIN="qemu-system-aarch64"
    QEMU_MACHINE_ARGS=(-machine virt -cpu max)
    VIRTIO_NET_DEV="virtio-net-device"
    # ARM64 QEMU -kernel expects a raw binary with ARM64 Image header, not ELF.
    KERNEL="$IMG"
    if [[ ! -f "$KERNEL" ]]; then
        echo "ERROR: webserver.img not found at $IMG" >&2
        exit 1
    fi
elif echo "$ELF_INFO" | grep -q "x86-64"; then
    QEMU_BIN="qemu-system-x86_64"
    QEMU_MACHINE_ARGS=(-cpu qemu64)
    VIRTIO_NET_DEV="virtio-net-pci"
    KERNEL="$ELF"
else
    echo "ERROR: could not detect ELF architecture from: $ELF_INFO" >&2
    exit 1
fi

if ! command -v "$QEMU_BIN" &>/dev/null; then
    echo "SKIP: $QEMU_BIN not found — install with: brew install qemu"
    exit 0  # skip, not fail
fi

# ---- Pick a port (use TEST_PORT env if set, otherwise default) --------------
PORT="${TEST_PORT:-18099}"

# ---- Launch QEMU in the background ------------------------------------------
QEMU_LOG="$(mktemp /tmp/unikernel_test_XXXXXX.log)"

echo "==> Booting webserver in $QEMU_BIN (kernel: $(basename "$KERNEL"))..."
echo "    Port: localhost:${PORT} → VM:80"

"$QEMU_BIN" \
    "${QEMU_MACHINE_ARGS[@]}" \
    -kernel "$KERNEL" \
    -m 128 \
    -smp 1 \
    -nographic \
    -serial "file:${QEMU_LOG}" \
    -no-reboot \
    -device "${VIRTIO_NET_DEV}",netdev=net0 \
    -netdev "user,id=net0,hostfwd=tcp::${PORT}-:80" \
    &>/dev/null &

QEMU_PID=$!

# ---- Wait for HTTP server to be ready (poll up to 60s) ----------------------
echo "==> Waiting for HTTP server to become ready..."
READY=0
for i in $(seq 1 60); do
    if curl -sf --max-time 1 "http://localhost:${PORT}/" &>/dev/null; then
        READY=1
        echo "    Ready after ${i}s"
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "ERROR: QEMU exited unexpectedly" >&2
        echo "--- serial output ---" >&2
        cat "$QEMU_LOG" >&2
        exit 1
    fi
    sleep 1
done

if [[ $READY -eq 0 ]]; then
    echo "ERROR: server did not become ready within 60s" >&2
    echo "--- serial output ---" >&2
    cat "$QEMU_LOG" >&2
    exit 1
fi

# ---- HTTP test helper -------------------------------------------------------
check_http() {
    local desc="$1"
    local url="$2"
    local expected_status="$3"
    local expected_body_substr="${4:-}"

    local response body status
    response="$(curl -s -w $'\n''%{http_code}' --max-time 5 "$url" 2>&1 || true)"
    body="$(echo "$response" | sed '$d')"
    status="$(echo "$response" | tail -n 1)"

    local ok=1
    [[ "$status" != "$expected_status" ]] && ok=0
    if [[ -n "$expected_body_substr" ]] && ! echo "$body" | grep -q "$expected_body_substr"; then
        ok=0
    fi

    if [[ $ok -eq 1 ]]; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc"
        echo "  URL:              $url"
        echo "  Expected status:  $expected_status"
        echo "  Got status:       $status"
        [[ -n "$expected_body_substr" ]] && \
            echo "  Expected body contains: '$expected_body_substr'"
        echo "  Got body:         $body"
        FAILURES=$((FAILURES + 1))
    fi
}

# ---- Run integration tests --------------------------------------------------
echo ""
echo "==> Running HTTP tests..."

check_http "GET /       → 200"               "http://localhost:${PORT}/"       "200" ""
check_http "GET /health → 200 with content"  "http://localhost:${PORT}/health" "200" ""
check_http "GET /notfound → 404 Not Found"   "http://localhost:${PORT}/xyz"    "404" "Not Found"

# POST with body (webserver should respond, even if method not routed)
check_http "POST / → valid HTTP response"    "http://localhost:${PORT}/" "200" ""

# ---- Summary ----------------------------------------------------------------
echo ""
if [[ $FAILURES -eq 0 ]]; then
    echo "ALL INTEGRATION TESTS PASSED"
    exit 0
else
    echo "$FAILURES INTEGRATION TEST(S) FAILED"
    echo ""
    echo "--- serial output (last 40 lines) ---"
    tail -40 "$QEMU_LOG"
    exit 1
fi
