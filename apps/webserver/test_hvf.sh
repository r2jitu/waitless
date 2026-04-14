#!/usr/bin/env bash
# apps/webserver/test_hvf.sh — Boot webserver via HVF runner, verify HTTP.
# macOS arm64 only; skips on other platforms.
#
#   bazel test //apps/webserver:test
#
# The HVF runner uses a userspace TCP/UDP proxy (no vmnet, no root).
# Default forwards: -p tcp:8080:80 -p udp:18080:7. The test points wrk
# at localhost:8080.

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]] || [[ "$(uname -m)" != "arm64" ]]; then
    echo "SKIP: HVF runner only works on macOS arm64"
    exit 0
fi

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

FAILURES=0
trap cleanup_vm EXIT

IMG="${RUNFILES}/_main/apps/webserver/webserver.img"
HVF_BIN="${RUNFILES}/_main/tools/hvf-runner/run-hvf"
[[ -f "$IMG" ]] || { echo "ERROR: webserver.img not found at $IMG" >&2; exit 1; }
[[ -x "$HVF_BIN" ]] || { echo "ERROR: run-hvf not found at $HVF_BIN" >&2; exit 1; }

VM_LOG="$(mktemp /tmp/unikernel_hvf_test_XXXXXX.log)"

# Userspace proxy: guest HTTP on :80 is forwarded to localhost:8080.
VM_HOST="127.0.0.1"
VM_PORT="8080"

echo "==> Booting webserver via HVF runner..."
"$HVF_BIN" "$IMG" -p "tcp:${VM_PORT}:80" >"$VM_LOG" 2>&1 &
VM_PID=$!

if ! wait_http "$VM_PORT" 30 "$VM_PID" "$VM_HOST"; then
    echo "ERROR: not ready after 30s" >&2; cat "$VM_LOG" >&2; exit 1
fi

echo ""; echo "==> Running HTTP tests (HVF)..."
check_http "GET /"         "http://${VM_HOST}:${VM_PORT}/"       "200"             || FAILURES=$((FAILURES+1))
check_http "GET /health"   "http://${VM_HOST}:${VM_PORT}/health" "200"             || FAILURES=$((FAILURES+1))
check_http "GET /notfound" "http://${VM_HOST}:${VM_PORT}/xyz"    "404" "Not Found" || FAILURES=$((FAILURES+1))

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL HVF TESTS PASSED"; exit 0; }
echo "$FAILURES HVF TEST(S) FAILED"; tail -40 "$VM_LOG"; exit 1
