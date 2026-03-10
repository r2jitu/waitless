#!/usr/bin/env bash
# apps/webserver/test_qemu.sh — Boot webserver via QEMU (-kernel), verify HTTP.
# Auto-detects x86_64 or aarch64 from the ELF. Skips if QEMU is not installed.
#
#   bazel test //apps/webserver:test_qemu
#   bazel test --config=x86_64 //apps/webserver:test_qemu

set -euo pipefail

FAILURES=0
VM_PID=""
VM_LOG=""

cleanup() {
    if [[ -n "$VM_PID" ]] && kill -0 "$VM_PID" 2>/dev/null; then
        kill "$VM_PID" 2>/dev/null || true
        wait "$VM_PID" 2>/dev/null || true
    fi
    [[ -n "$VM_LOG" ]] && rm -f "$VM_LOG" || true
}
trap cleanup EXIT

# ---- Locate binaries --------------------------------------------------------
RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
ELF="${RUNFILES}/_main/apps/webserver/webserver.elf"
IMG="${RUNFILES}/_main/apps/webserver/webserver.img"

[[ -f "$ELF" ]] || { echo "ERROR: webserver.elf not found at $ELF" >&2; exit 1; }

# ---- Detect architecture from ELF ------------------------------------------
ELF_INFO="$(file "$ELF" 2>/dev/null || echo "")"

if echo "$ELF_INFO" | grep -q "ARM aarch64"; then
    QEMU_BIN="qemu-system-aarch64"
    QEMU_ARGS=(-machine virt -cpu max -kernel "$IMG")
    VIRTIO_NET_DEV="virtio-net-device"
    [[ -f "$IMG" ]] || { echo "ERROR: webserver.img not found at $IMG" >&2; exit 1; }
elif echo "$ELF_INFO" | grep -q "x86-64"; then
    QEMU_BIN="qemu-system-x86_64"
    QEMU_ARGS=(-cpu qemu64 -kernel "$ELF")
    VIRTIO_NET_DEV="virtio-net-pci"
else
    echo "ERROR: unknown ELF architecture: $ELF_INFO" >&2; exit 1
fi

command -v "$QEMU_BIN" &>/dev/null || { echo "SKIP: $QEMU_BIN not found"; exit 0; }

# ---- Boot -------------------------------------------------------------------
PORT="${TEST_PORT:-18099}"
VM_LOG="$(mktemp /tmp/unikernel_qemu_test_XXXXXX.log)"

echo "==> Booting webserver in $QEMU_BIN (port $PORT)..."
"$QEMU_BIN" \
    "${QEMU_ARGS[@]}" \
    -m 128 -smp 1 -nographic \
    -serial "file:${VM_LOG}" \
    -no-reboot \
    -device "${VIRTIO_NET_DEV}",netdev=net0 \
    -netdev "user,id=net0,hostfwd=tcp::${PORT}-:80" \
    &>/dev/null &
VM_PID=$!

# ---- Wait for HTTP ---------------------------------------------------------
READY=0
for i in $(seq 1 60); do
    if curl -sf --max-time 1 "http://localhost:${PORT}/" &>/dev/null; then
        READY=1; echo "    Ready after ${i}s"; break
    fi
    kill -0 "$VM_PID" 2>/dev/null || { echo "ERROR: VM exited" >&2; cat "$VM_LOG" >&2; exit 1; }
    sleep 1
done
[[ $READY -eq 1 ]] || { echo "ERROR: not ready after 60s" >&2; cat "$VM_LOG" >&2; exit 1; }

# ---- HTTP tests -------------------------------------------------------------
check_http() {
    local desc="$1" url="$2" want_status="$3" want_body="${4:-}"
    local resp body status ok=1
    resp="$(curl -s -w $'\n%{http_code}' --max-time 5 "$url" 2>&1 || true)"
    body="$(echo "$resp" | sed '$d')"; status="$(echo "$resp" | tail -n1)"
    [[ "$status" == "$want_status" ]] || ok=0
    [[ -z "$want_body" ]] || echo "$body" | grep -q "$want_body" || ok=0
    if [[ $ok -eq 1 ]]; then echo "PASS: $desc"
    else echo "FAIL: $desc (status=$status)"; FAILURES=$((FAILURES+1)); fi
}

echo ""; echo "==> Running HTTP tests (QEMU)..."
check_http "GET /"        "http://localhost:${PORT}/"       "200"
check_http "GET /health"  "http://localhost:${PORT}/health" "200"
check_http "GET /notfound" "http://localhost:${PORT}/xyz"   "404" "Not Found"

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL QEMU TESTS PASSED"; exit 0; }
echo "$FAILURES QEMU TEST(S) FAILED"; tail -40 "$VM_LOG"; exit 1
