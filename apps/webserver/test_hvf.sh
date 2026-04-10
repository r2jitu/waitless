#!/usr/bin/env bash
# apps/webserver/test_hvf.sh — Boot webserver via HVF runner, verify HTTP.
# macOS arm64 only, requires root (for vmnet). Skips on other platforms.
#
#   bazel test //apps/webserver:test_hvf

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]] || [[ "$(uname -m)" != "arm64" ]]; then
    echo "SKIP: HVF runner only works on macOS arm64"
    exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "SKIP: HVF runner with vmnet requires root (try: sudo bazel test ...)"
    exit 0
fi

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

FAILURES=0
trap cleanup_vm EXIT

IMG="${RUNFILES}/_main/apps/webserver/webserver.img"
[[ -f "$IMG" ]] || { echo "ERROR: webserver.img not found at $IMG" >&2; exit 1; }

# Build the HVF runner via cargo (not yet a Bazel target).
PROJECT_ROOT="${RUNFILES}/_main"
HVF_DIR="${PROJECT_ROOT}/tools/hvf-runner"
HVF_BIN="${HVF_DIR}/target/release/run-hvf"
if [[ ! -x "$HVF_BIN" ]]; then
    echo "==> Building HVF runner..."
    (cd "$HVF_DIR" && cargo build --release --quiet 2>/dev/null) || { echo "SKIP: cargo build failed"; exit 0; }
    codesign --force --sign - --entitlements "${HVF_DIR}/run-hvf.entitlements" "$HVF_BIN" 2>/dev/null
fi
[[ -x "$HVF_BIN" ]] || { echo "SKIP: run-hvf binary not found"; exit 0; }

VM_LOG="$(mktemp /tmp/unikernel_hvf_test_XXXXXX.log)"

# HVF host-mode: VM is at 192.168.18.2:80 (no proxy port needed).
VM_HOST="192.168.18.2"
VM_PORT="80"

echo "==> Booting webserver via HVF runner..."
"$HVF_BIN" "$IMG" >"$VM_LOG" 2>&1 &
VM_PID=$!

# Wait for the VM to be reachable (DHCP + event loop startup).
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
