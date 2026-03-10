#!/usr/bin/env bash
# apps/webserver/test_vz.sh — Boot webserver via VZ.framework, verify HTTP.
# macOS arm64 only — skips on other platforms.
#
#   bazel test //apps/webserver:test_vz

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]] || [[ "$(uname -m)" != "arm64" ]]; then
    echo "SKIP: VZ.framework only runs on macOS arm64"
    exit 0
fi

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

FAILURES=0
trap cleanup_vm EXIT

IMG="${RUNFILES}/_main/apps/webserver/webserver.img"
VZ_BIN="${RUNFILES}/_main/scripts/run-vz"

[[ -f "$IMG" ]]    || { echo "ERROR: webserver.img not found at $IMG" >&2; exit 1; }
[[ -f "$VZ_BIN" ]] || { echo "SKIP: run-vz binary not found"; exit 0; }

PORT="${TEST_PORT:-18098}"
VM_LOG="$(mktemp /tmp/unikernel_vz_test_XXXXXX.log)"

echo "==> Booting webserver via VZ.framework (port $PORT)..."
"$VZ_BIN" "$IMG" "$PORT" >"$VM_LOG" 2>&1 &
VM_PID=$!

if ! wait_http "$PORT" 30 "$VM_PID"; then
    echo "ERROR: not ready after 30s" >&2; cat "$VM_LOG" >&2; exit 1
fi

echo ""; echo "==> Running HTTP tests (VZ)..."
check_http "GET /"         "http://localhost:${PORT}/"       "200"             || FAILURES=$((FAILURES+1))
check_http "GET /health"   "http://localhost:${PORT}/health" "200"             || FAILURES=$((FAILURES+1))
check_http "GET /notfound" "http://localhost:${PORT}/xyz"    "404" "Not Found" || FAILURES=$((FAILURES+1))

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL VZ TESTS PASSED"; exit 0; }
echo "$FAILURES VZ TEST(S) FAILED"; tail -40 "$VM_LOG"; exit 1
