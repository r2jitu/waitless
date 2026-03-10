#!/usr/bin/env bash
# apps/webserver/test_qemu.sh — Boot webserver via QEMU (-kernel), verify HTTP.
# Auto-detects x86_64 or aarch64 from the ELF. Skips if QEMU is not installed.
#
#   bazel test //apps/webserver:test_qemu
#   bazel test --config=x86_64 //apps/webserver:test_qemu

set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

FAILURES=0
trap cleanup_vm EXIT

ELF="${RUNFILES}/_main/apps/webserver/webserver.elf"
[[ -f "$ELF" ]] || { echo "ERROR: webserver.elf not found at $ELF" >&2; exit 1; }

detect_qemu "$ELF"
command -v "$QEMU_BIN" &>/dev/null || { echo "SKIP: $QEMU_BIN not found"; exit 0; }

PORT="${TEST_PORT:-18099}"
echo "==> Booting webserver in $QEMU_BIN (port $PORT)..."
start_qemu "$PORT" "${QEMU_MACHINE[@]}" -kernel "$KERNEL_ARG"

if ! wait_http "$PORT" 60 "$VM_PID"; then
    echo "ERROR: not ready after 60s" >&2; cat "$VM_LOG" >&2; exit 1
fi

echo ""; echo "==> Running HTTP tests (QEMU)..."
check_http "GET /"         "http://localhost:${PORT}/"       "200"             || FAILURES=$((FAILURES+1))
check_http "GET /health"   "http://localhost:${PORT}/health" "200"             || FAILURES=$((FAILURES+1))
check_http "GET /notfound" "http://localhost:${PORT}/xyz"    "404" "Not Found" || FAILURES=$((FAILURES+1))

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL QEMU TESTS PASSED"; exit 0; }
echo "$FAILURES QEMU TEST(S) FAILED"; tail -40 "$VM_LOG"; exit 1
