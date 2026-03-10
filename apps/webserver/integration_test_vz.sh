#!/usr/bin/env bash
# apps/webserver/integration_test_vz.sh
#
# Integration test: boot the webserver via VZ.framework, verify HTTP endpoints.
# macOS arm64 only — skips on other platforms.
#
# Run:
#   bazel test //apps/webserver:integration_test_vz

set -euo pipefail

FAILURES=0
VZ_PID=""
VZ_LOG=""

# ---- Cleanup on exit --------------------------------------------------------
cleanup() {
    if [[ -n "$VZ_PID" ]] && kill -0 "$VZ_PID" 2>/dev/null; then
        kill "$VZ_PID" 2>/dev/null || true
        wait "$VZ_PID" 2>/dev/null || true
    fi
    [[ -n "$VZ_LOG" ]] && rm -f "$VZ_LOG" || true
}
trap cleanup EXIT

# ---- Platform check ----------------------------------------------------------
if [[ "$(uname -s)" != "Darwin" ]] || [[ "$(uname -m)" != "arm64" ]]; then
    echo "SKIP: VZ.framework test only runs on macOS arm64"
    exit 0
fi

# ---- Locate binaries ---------------------------------------------------------
RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
IMG="${RUNFILES}/_main/apps/webserver/webserver.img"
VZ_BIN="${RUNFILES}/_main/scripts/run-vz"

if [[ ! -f "$IMG" ]]; then
    echo "ERROR: webserver.img not found at $IMG" >&2
    exit 1
fi

if [[ ! -f "$VZ_BIN" ]]; then
    echo "SKIP: run-vz binary not found (VZ.framework not available)"
    exit 0
fi

# ---- Pick a port -------------------------------------------------------------
PORT="${TEST_PORT:-18098}"

# ---- Launch VZ in the background ---------------------------------------------
VZ_LOG="$(mktemp /tmp/unikernel_vz_test_XXXXXX.log)"

echo "==> Booting webserver via VZ.framework..."
echo "    Port: localhost:${PORT} → VM:80"

"$VZ_BIN" "$IMG" "$PORT" >"$VZ_LOG" 2>&1 &
VZ_PID=$!

# ---- Wait for HTTP server to be ready (poll up to 30s) -----------------------
echo "==> Waiting for HTTP server to become ready..."
READY=0
for i in $(seq 1 30); do
    if curl -sf --max-time 1 "http://localhost:${PORT}/" &>/dev/null; then
        READY=1
        echo "    Ready after ${i}s"
        break
    fi
    if ! kill -0 "$VZ_PID" 2>/dev/null; then
        echo "ERROR: VZ runner exited unexpectedly" >&2
        echo "--- output ---" >&2
        cat "$VZ_LOG" >&2
        exit 1
    fi
    sleep 1
done

if [[ $READY -eq 0 ]]; then
    echo "ERROR: server did not become ready within 30s" >&2
    echo "--- output ---" >&2
    cat "$VZ_LOG" >&2
    exit 1
fi

# ---- HTTP test helper -------------------------------------------------------
check_http() {
    local desc="$1"
    local url="$2"
    local expected_status="$3"
    local expected_body_substr="${4:-}"

    local response body status
    response="$(curl -s -w $'\n''%{http_code}' --max-time 5 "$url" 2>&1 || true)"
    body="$(echo "$response" | sed '$d')"
    status="$(echo "$response" | tail -n 1)"

    local ok=1
    [[ "$status" != "$expected_status" ]] && ok=0
    if [[ -n "$expected_body_substr" ]] && ! echo "$body" | grep -q "$expected_body_substr"; then
        ok=0
    fi

    if [[ $ok -eq 1 ]]; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc"
        echo "  URL:              $url"
        echo "  Expected status:  $expected_status"
        echo "  Got status:       $status"
        [[ -n "$expected_body_substr" ]] && \
            echo "  Expected body contains: '$expected_body_substr'"
        echo "  Got body:         $body"
        FAILURES=$((FAILURES + 1))
    fi
}

# ---- Run integration tests --------------------------------------------------
echo ""
echo "==> Running HTTP tests (VZ.framework)..."

check_http "GET /       → 200"               "http://localhost:${PORT}/"       "200" ""
check_http "GET /health → 200 with content"  "http://localhost:${PORT}/health" "200" ""
check_http "GET /notfound → 404 Not Found"   "http://localhost:${PORT}/xyz"    "404" "Not Found"
check_http "POST / → valid HTTP response"    "http://localhost:${PORT}/"       "200" ""

# ---- Summary ----------------------------------------------------------------
echo ""
if [[ $FAILURES -eq 0 ]]; then
    echo "ALL VZ INTEGRATION TESTS PASSED"
    exit 0
else
    echo "$FAILURES VZ INTEGRATION TEST(S) FAILED"
    echo ""
    echo "--- VZ output (last 40 lines) ---"
    tail -40 "$VZ_LOG"
    exit 1
fi
