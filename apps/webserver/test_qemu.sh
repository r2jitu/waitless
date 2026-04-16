#!/usr/bin/env bash
# apps/webserver/test_qemu.sh — Boot webserver via QEMU (-kernel), verify the
# HTTP, HTTPS, and UDP paths end-to-end. Auto-detects x86_64 or aarch64 from
# the ELF. Skips if QEMU is not installed.
#
#   bazel test --config=aarch64-qemu //apps/webserver:test
#   bazel test --config=x86_64-qemu  //apps/webserver:test
#
# Port layout (canonical; see scripts/helpers.sh::_qemu_net_args):
#   TCP PORT     -> guest :80   (HTTP)
#   TCP PORT+1   -> guest :443  (HTTPS)
#   UDP PORT+2   -> guest :7    (echo)

set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

FAILURES=0
trap cleanup_vm EXIT

ELF="${RUNFILES}/_main/apps/webserver/webserver.elf"
DEV_CERT="${RUNFILES}/_main/apps/webserver/dev_certs/dev_cert.pem"
[[ -f "$ELF" ]] || { echo "ERROR: webserver.elf not found at $ELF" >&2; exit 1; }

detect_qemu "$ELF"
command -v "$QEMU_BIN" &>/dev/null || { echo "SKIP: $QEMU_BIN not found"; exit 0; }

PORT="${TEST_PORT:-18099}"
VM_HOST="127.0.0.1"
TLS_PORT=$((PORT + 1))
UDP_PORT=$((PORT + 2))

echo "==> Booting webserver in $QEMU_BIN (HTTP :$PORT  HTTPS :$TLS_PORT  UDP :$UDP_PORT)..."
start_qemu "$PORT" "" "${QEMU_MACHINE[@]}" -kernel "$KERNEL_ARG"

if ! wait_http "$PORT" 10 "$VM_PID"; then
    echo "ERROR: HTTP not ready after 10s" >&2; cat "$VM_LOG" >&2; exit 1
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
[[ $FAILURES -eq 0 ]] && { echo "ALL QEMU TESTS PASSED"; exit 0; }
echo "$FAILURES QEMU TEST(S) FAILED"; tail -40 "$VM_LOG"; exit 1
