#!/usr/bin/env bash
# apps/webserver/test.sh — Boot webserver via the :webserver launcher and
# verify HTTP + HTTPS + UDP end-to-end.
#
# Runner-agnostic: instead of picking HVF / QEMU / ISO / native launch
# logic per config, this test lists :webserver in its `data` and invokes
# it as a subprocess. Whatever the active config's launcher does, the
# test just waits for the three service ports to come up and probes them.
# One test script covers every runner.
#
#   bazel test --config=hvf           //apps/webserver:test
#   bazel test --config=aarch64-qemu  //apps/webserver:test
#   bazel test --config=x86_64-iso    //apps/webserver:test
#   bazel test                        //apps/webserver:test   (native)
#
# Port layout:
#   TCP TEST_PORT     → HTTP   (default 18080)
#   TCP TEST_TLS_PORT → HTTPS  (default 18443)
#   UDP TEST_UDP_PORT → echo   (default 18007)

set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

LAUNCHER="${RUNFILES}/_main/apps/webserver/webserver"
DEV_CERT="${RUNFILES}/_main/apps/webserver/dev_certs/dev_cert.pem"
[[ -x "$LAUNCHER" ]] || { echo "ERROR: webserver launcher not found at $LAUNCHER" >&2; exit 1; }

PORT="${TEST_PORT:-18080}"
TLS_PORT="${TEST_TLS_PORT:-18443}"
UDP_PORT="${TEST_UDP_PORT:-18007}"

FAILURES=0
VM_LOG="$(mktemp /tmp/webserver_test_XXXXXX.log)"
VM_PID=""
cleanup() {
    if [[ -n "$VM_PID" ]] && kill -0 "$VM_PID" 2>/dev/null; then
        kill -TERM "$VM_PID" 2>/dev/null || true
        # Give the guest a moment to PSCI/ACPI off cleanly, then force.
        for _ in 1 2 3 4; do
            kill -0 "$VM_PID" 2>/dev/null || break
            sleep 0.5
        done
        kill -KILL "$VM_PID" 2>/dev/null || true
        wait "$VM_PID" 2>/dev/null || true
    fi
    # Also mop up any child VM/runner processes the launcher spawned.
    pkill -P "$VM_PID" 2>/dev/null || true
    pkill -f 'run-hvf|qemu-system' 2>/dev/null || true
    rm -f "$VM_LOG"
}
trap cleanup EXIT

echo "==> Launching :webserver  (HTTP :$PORT  HTTPS :$TLS_PORT  UDP :$UDP_PORT)..."
env UNIKERNEL_PORT="$PORT" UNIKERNEL_TLS_PORT="$TLS_PORT" UNIKERNEL_UDP_PORT="$UDP_PORT" \
    "$LAUNCHER" >"$VM_LOG" 2>&1 &
VM_PID=$!

if ! wait_http "$PORT" 20 "$VM_PID"; then
    echo "ERROR: HTTP not ready after 20s" >&2
    cat "$VM_LOG" >&2
    exit 1
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
    VM_HOST="127.0.0.1" VM_PORT="$TLS_PORT" \
        check_https "GET /"         "/"       "200"                 || FAILURES=$((FAILURES+1))
    VM_HOST="127.0.0.1" VM_PORT="$TLS_PORT" \
        check_https "GET /health"   "/health" "200"  "status"       || FAILURES=$((FAILURES+1))
    VM_HOST="127.0.0.1" VM_PORT="$TLS_PORT" \
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
if [[ $FAILURES -eq 0 ]]; then
    echo "ALL WEBSERVER TESTS PASSED"
    exit 0
fi
echo "$FAILURES WEBSERVER TEST(S) FAILED"
tail -40 "$VM_LOG"
exit 1
