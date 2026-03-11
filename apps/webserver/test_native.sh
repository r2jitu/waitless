#!/usr/bin/env bash
# apps/webserver/test_native.sh — Boot webserver_native (POSIX), verify HTTP.
# Runs the native binary directly — no VM required.
#
#   bazel test //apps/webserver:test
#   bazel test --config=aarch64-macos //apps/webserver:test

set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
EXE="${RUNFILES}/_main/apps/webserver/webserver_native"

[[ -f "$EXE" ]] || { echo "ERROR: webserver_native not found at $EXE" >&2; exit 1; }

PORT="${TEST_PORT:-18096}"
FAILURES=0

PORT="$PORT" "$EXE" >/dev/null 2>&1 &
SERVER_PID=$!
trap "kill -TERM $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null || true" EXIT

echo "==> Waiting for webserver_native on port $PORT..."
for i in $(seq 1 20); do
    curl -sf --max-time 2 "http://localhost:${PORT}/health" >/dev/null 2>&1 && break
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: server process exited unexpectedly" >&2; exit 1
    fi
    sleep 0.5
done
curl -sf --max-time 2 "http://localhost:${PORT}/health" >/dev/null 2>&1 \
    || { echo "ERROR: server not ready after 10s" >&2; exit 1; }

check_http() {
    local label=$1 url=$2 expected_status=$3 expected_body=${4:-}
    local status body
    body=$(curl -sf --max-time 5 -w "\n%{http_code}" "$url" 2>/dev/null) || true
    status="${body##*$'\n'}"
    body="${body%$'\n'*}"
    if [[ "$status" != "$expected_status" ]]; then
        echo "FAIL $label: expected HTTP $expected_status, got $status"
        FAILURES=$((FAILURES+1))
        return
    fi
    if [[ -n "$expected_body" && "$body" != *"$expected_body"* ]]; then
        echo "FAIL $label: body missing '$expected_body'"
        FAILURES=$((FAILURES+1))
        return
    fi
    echo "PASS $label"
}

echo ""; echo "==> Running HTTP tests (native)..."
check_http "GET /"         "http://localhost:${PORT}/"       "200"
check_http "GET /health"   "http://localhost:${PORT}/health" "200"
check_http "GET /notfound" "http://localhost:${PORT}/xyz"    "404"

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL NATIVE TESTS PASSED"; exit 0; }
echo "$FAILURES NATIVE TEST(S) FAILED"; exit 1
