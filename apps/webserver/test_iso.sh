#!/usr/bin/env bash
# apps/webserver/test_iso.sh — Boot webserver from the Limine ISO via QEMU
# and verify the HTTP, HTTPS, and UDP paths end-to-end. Tests the full
# bootloader path: Limine BIOS → kernel ELF entry. x86_64 only; skips on
# aarch64 (needs UEFI firmware).
#
#   bazel test --config=x86_64-iso //apps/webserver:test
#
# Port layout matches test_qemu.sh (see scripts/helpers.sh::_qemu_net_args):
#   TCP PORT     -> guest :80   (HTTP)
#   TCP PORT+1   -> guest :443  (HTTPS)
#   UDP PORT+2   -> guest :7    (echo)

set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

FAILURES=0
trap cleanup_vm EXIT

ISO="${RUNFILES}/_main/apps/webserver/webserver.iso"
ELF="${RUNFILES}/_main/apps/webserver/webserver.limine.elf"
DEV_CERT="${RUNFILES}/_main/apps/webserver/dev_certs/dev_cert.pem"
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
VM_HOST="127.0.0.1"
TLS_PORT=$((PORT + 1))
UDP_PORT=$((PORT + 2))

echo "==> Booting webserver from Limine ISO (HTTP :$PORT  HTTPS :$TLS_PORT  UDP :$UDP_PORT)..."
start_qemu "$PORT" "" -cpu max -cdrom "$ISO"

if ! wait_http "$PORT" 15 "$VM_PID"; then
    echo "ERROR: HTTP not ready after 15s" >&2; cat "$VM_LOG" >&2; exit 1
fi

echo ""; echo "==> HTTP tests..."
check_http "GET /"         "http://localhost:${PORT}/"       "200"             || FAILURES=$((FAILURES+1))
check_http "GET /health"   "http://localhost:${PORT}/health" "200"             || FAILURES=$((FAILURES+1))
check_http "GET /notfound" "http://localhost:${PORT}/xyz"    "404" "Not Found" || FAILURES=$((FAILURES+1))

echo ""; echo "==> HTTPS tests..."
if [[ ! -f "$DEV_CERT" ]]; then
    echo "  SKIP: dev_cert.pem missing from runfiles"
elif ! find_openssl; then
    echo "  SKIP: no TLS-1.3-capable openssl found"
else
    VM_PORT="$TLS_PORT"
    check_https "GET /"         "/"       "200"                 || FAILURES=$((FAILURES+1))
    check_https "GET /health"   "/health" "200"  "status"       || FAILURES=$((FAILURES+1))
    check_https "GET /notfound" "/xyz"    "404" "Not Found"     || FAILURES=$((FAILURES+1))
fi

echo ""; echo "==> UDP echo test..."
REPLY=$(python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b'hello', ('127.0.0.1', $UDP_PORT))
try:
    data, _ = s.recvfrom(1024)
    sys.stdout.write(data.decode())
except socket.timeout:
    pass
s.close()
" 2>/dev/null || true)
if [[ "$REPLY" == "hello" ]]; then
    echo "  PASS: UDP echo on port $UDP_PORT"
else
    echo "  FAIL: UDP echo — expected 'hello', got '${REPLY:-<empty>}'"
    FAILURES=$((FAILURES+1))
fi

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL ISO TESTS PASSED"; exit 0; }
echo "$FAILURES ISO TEST(S) FAILED"; tail -40 "$VM_LOG"; exit 1
