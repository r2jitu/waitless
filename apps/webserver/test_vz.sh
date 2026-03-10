#!/usr/bin/env bash
# apps/webserver/test_vz.sh — Boot webserver via VZ.framework, verify HTTP.
# macOS arm64 only — skips on other platforms.
#
#   bazel test //apps/webserver:test_vz

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

# ---- Platform check ---------------------------------------------------------
if [[ "$(uname -s)" != "Darwin" ]] || [[ "$(uname -m)" != "arm64" ]]; then
    echo "SKIP: VZ.framework only runs on macOS arm64"
    exit 0
fi

# ---- Locate binaries --------------------------------------------------------
RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
IMG="${RUNFILES}/_main/apps/webserver/webserver.img"
VZ_BIN="${RUNFILES}/_main/scripts/run-vz"

[[ -f "$IMG" ]]    || { echo "ERROR: webserver.img not found at $IMG" >&2; exit 1; }
[[ -f "$VZ_BIN" ]] || { echo "SKIP: run-vz binary not found"; exit 0; }

# ---- Boot -------------------------------------------------------------------
PORT="${TEST_PORT:-18098}"
VM_LOG="$(mktemp /tmp/unikernel_vz_test_XXXXXX.log)"

echo "==> Booting webserver via VZ.framework (port $PORT)..."
"$VZ_BIN" "$IMG" "$PORT" >"$VM_LOG" 2>&1 &
VM_PID=$!

# ---- Wait for HTTP ---------------------------------------------------------
READY=0
for i in $(seq 1 30); do
    if curl -sf --max-time 1 "http://localhost:${PORT}/" &>/dev/null; then
        READY=1; echo "    Ready after ${i}s"; break
    fi
    kill -0 "$VM_PID" 2>/dev/null || { echo "ERROR: VM exited" >&2; cat "$VM_LOG" >&2; exit 1; }
    sleep 1
done
[[ $READY -eq 1 ]] || { echo "ERROR: not ready after 30s" >&2; cat "$VM_LOG" >&2; exit 1; }

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

echo ""; echo "==> Running HTTP tests (VZ)..."
check_http "GET /"        "http://localhost:${PORT}/"       "200"
check_http "GET /health"  "http://localhost:${PORT}/health" "200"
check_http "GET /notfound" "http://localhost:${PORT}/xyz"   "404" "Not Found"

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL VZ TESTS PASSED"; exit 0; }
echo "$FAILURES VZ TEST(S) FAILED"; tail -40 "$VM_LOG"; exit 1
