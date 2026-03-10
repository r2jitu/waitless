#!/usr/bin/env bash
# apps/webserver/test_limine.sh — Boot webserver from Limine ISO via QEMU, verify HTTP.
# Tests the full bootloader path: Limine BIOS → kernel ELF entry.
# x86_64 only — skips on aarch64 (needs UEFI firmware).
#
#   bazel test --config=x86_64 //apps/webserver:test_limine

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
ISO="${RUNFILES}/_main/apps/webserver/webserver.iso"
ELF="${RUNFILES}/_main/apps/webserver/webserver.elf"

[[ -f "$ISO" ]] || { echo "ERROR: webserver_limine.iso not found at $ISO" >&2; exit 1; }

# ---- Architecture check (x86 only) -----------------------------------------
ELF_INFO="$(file "$ELF" 2>/dev/null || echo "")"
if echo "$ELF_INFO" | grep -q "ARM aarch64"; then
    echo "SKIP: Limine ISO boot requires UEFI firmware on aarch64 (not available)"
    exit 0
fi

QEMU_BIN="qemu-system-x86_64"
command -v "$QEMU_BIN" &>/dev/null || { echo "SKIP: $QEMU_BIN not found"; exit 0; }

# ---- Boot from ISO ----------------------------------------------------------
PORT="${TEST_PORT:-18097}"
VM_LOG="$(mktemp /tmp/unikernel_limine_test_XXXXXX.log)"

echo "==> Booting webserver from Limine ISO in $QEMU_BIN (port $PORT)..."
"$QEMU_BIN" \
    -cpu qemu64 \
    -cdrom "$ISO" \
    -m 128 -smp 1 -nographic \
    -serial "file:${VM_LOG}" \
    -no-reboot \
    -device virtio-net-pci,netdev=net0 \
    -netdev "user,id=net0,hostfwd=tcp::${PORT}-:80" \
    &>/dev/null &
VM_PID=$!

# ---- Wait for HTTP ---------------------------------------------------------
READY=0
for i in $(seq 1 90); do
    if curl -sf --max-time 1 "http://localhost:${PORT}/" &>/dev/null; then
        READY=1; echo "    Ready after ${i}s"; break
    fi
    kill -0 "$VM_PID" 2>/dev/null || { echo "ERROR: VM exited" >&2; cat "$VM_LOG" >&2; exit 1; }
    sleep 1
done
[[ $READY -eq 1 ]] || { echo "ERROR: not ready after 90s" >&2; cat "$VM_LOG" >&2; exit 1; }

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

echo ""; echo "==> Running HTTP tests (Limine ISO)..."
check_http "GET /"        "http://localhost:${PORT}/"       "200"
check_http "GET /health"  "http://localhost:${PORT}/health" "200"
check_http "GET /notfound" "http://localhost:${PORT}/xyz"   "404" "Not Found"

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL LIMINE TESTS PASSED"; exit 0; }
echo "$FAILURES LIMINE TEST(S) FAILED"; tail -40 "$VM_LOG"; exit 1
