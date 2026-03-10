#!/usr/bin/env bash
# apps/webserver/test_iso.sh — Boot webserver from Limine ISO via QEMU, verify HTTP.
# Tests the full bootloader path: Limine BIOS → kernel ELF entry.
# x86_64 only — skips on aarch64 (needs UEFI firmware).
#
#   bazel test --config=x86_64 //apps/webserver:test_iso

set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

FAILURES=0
trap cleanup_vm EXIT

ISO="${RUNFILES}/_main/apps/webserver/webserver.iso"
ELF="${RUNFILES}/_main/apps/webserver/webserver.limine.elf"

[[ -f "$ISO" ]] || { echo "ERROR: webserver.iso not found at $ISO" >&2; exit 1; }

ELF_INFO="$(file "$ELF" 2>/dev/null || echo "")"
if echo "$ELF_INFO" | grep -q "ARM aarch64"; then
    echo "SKIP: Limine ISO boot requires UEFI firmware on aarch64 (not available)"
    exit 0
fi

QEMU_BIN="qemu-system-x86_64"
VIRTIO_DEV="virtio-net-pci"
command -v "$QEMU_BIN" &>/dev/null || { echo "SKIP: $QEMU_BIN not found"; exit 0; }

PORT="${TEST_PORT:-18097}"
echo "==> Booting webserver from Limine ISO in $QEMU_BIN (port $PORT)..."
start_qemu "$PORT" "" -cpu qemu64 -cdrom "$ISO"

if ! wait_http "$PORT" 90 "$VM_PID"; then
    echo "ERROR: not ready after 90s" >&2; cat "$VM_LOG" >&2; exit 1
fi

echo ""; echo "==> Running HTTP tests (Limine ISO)..."
check_http "GET /"         "http://localhost:${PORT}/"       "200"             || FAILURES=$((FAILURES+1))
check_http "GET /health"   "http://localhost:${PORT}/health" "200"             || FAILURES=$((FAILURES+1))
check_http "GET /notfound" "http://localhost:${PORT}/xyz"    "404" "Not Found" || FAILURES=$((FAILURES+1))

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL ISO TESTS PASSED"; exit 0; }
echo "$FAILURES ISO TEST(S) FAILED"; tail -40 "$VM_LOG"; exit 1
