#!/usr/bin/env bash
# apps/webserver/test_hvf.sh — Boot webserver via HVF runner, verify HTTPS.
# macOS arm64 only; skips on other platforms.
#
#   bazel test //apps/webserver:test
#
# The HVF runner uses a userspace TCP/UDP proxy (no vmnet, no root).
# The webserver is HTTPS-only (TLS 1.3 + Ed25519 dev cert); we use
# Homebrew's openssl s_client to drive the handshake because macOS
# LibreSSL 3.3.6 doesn't support Ed25519 cert verification.
#
# Default forward: -p tcp:8443:80. The test points openssl at localhost:8443.

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]] || [[ "$(uname -m)" != "arm64" ]]; then
    echo "SKIP: HVF runner only works on macOS arm64"
    exit 0
fi

# Find a Homebrew openssl (brew installs 3.x which does support Ed25519).
# Fall back to /usr/bin/openssl only if it's OpenSSL 3.x (not LibreSSL).
OPENSSL=""
for candidate in /opt/homebrew/bin/openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/bin/openssl openssl; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" version 2>&1)
        if [[ "$ver" == OpenSSL\ 3.* ]]; then
            OPENSSL="$candidate"
            break
        fi
    fi
done
if [[ -z "$OPENSSL" ]]; then
    echo "SKIP: OpenSSL 3.x not found (LibreSSL doesn't support our Ed25519 dev cert)"
    exit 0
fi
echo "==> Using $($OPENSSL version)"

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"

FAILURES=0

IMG="${RUNFILES}/_main/apps/webserver/webserver.img"
HVF_BIN="${RUNFILES}/_main/tools/hvf-runner/run-hvf"
DEV_CERT="${RUNFILES}/_main/apps/webserver/dev_certs/dev_cert.pem"
[[ -f "$IMG" ]] || { echo "ERROR: webserver.img not found at $IMG" >&2; exit 1; }
[[ -x "$HVF_BIN" ]] || { echo "ERROR: run-hvf not found at $HVF_BIN" >&2; exit 1; }
[[ -f "$DEV_CERT" ]] || { echo "ERROR: dev_cert.pem not found at $DEV_CERT" >&2; exit 1; }

VM_LOG="$(mktemp /tmp/unikernel_hvf_test_XXXXXX.log)"
cleanup() {
    if [[ -n "${VM_PID:-}" ]] && kill -0 "$VM_PID" 2>/dev/null; then
        kill "$VM_PID" 2>/dev/null || true
        wait "$VM_PID" 2>/dev/null || true
    fi
    rm -f "$VM_LOG"
}
trap cleanup EXIT

VM_HOST="127.0.0.1"
VM_PORT="8443"

echo "==> Booting webserver via HVF runner (HTTPS on :${VM_PORT})..."
"$HVF_BIN" "$IMG" -p "tcp:${VM_PORT}:80" >"$VM_LOG" 2>&1 &
VM_PID=$!

# Poll the TLS handshake until it succeeds (up to 30s).
# openssl s_client returns 0 if it can connect and complete the handshake.
echo "==> Waiting for TLS handshake to succeed..."
ready=0
for _ in $(seq 1 30); do
    if echo "" | "$OPENSSL" s_client -connect "${VM_HOST}:${VM_PORT}" -tls1_3 \
            -CAfile "$DEV_CERT" -servername unikernel.local -quiet \
            2>/dev/null | grep -q "HTTP\|--END-OF-BUFFER--" 2>/dev/null; then
        ready=1; break
    fi
    # Simpler check: openssl exit-code after a handshake-only run.
    if echo "" | "$OPENSSL" s_client -connect "${VM_HOST}:${VM_PORT}" -tls1_3 \
            -CAfile "$DEV_CERT" -servername unikernel.local -quiet \
            </dev/null 2>&1 | grep -q "Cipher is TLS_CHACHA20_POLY1305_SHA256"; then
        ready=1; break
    fi
    sleep 1
done
if [[ $ready -eq 0 ]]; then
    echo "ERROR: TLS server not ready after 30s" >&2
    cat "$VM_LOG" >&2
    exit 1
fi

# Helper: issue one HTTPS request and check the status + body.
check_https() {
    local name="$1" path="$2" expect_status="$3" expect_body="${4:-}"
    local response
    response=$(printf 'GET %s HTTP/1.1\r\nHost: unikernel.local\r\nConnection: close\r\n\r\n' "$path" | \
        "$OPENSSL" s_client -connect "${VM_HOST}:${VM_PORT}" -tls1_3 \
            -CAfile "$DEV_CERT" -servername unikernel.local -quiet 2>/dev/null)
    local status_line
    status_line=$(echo "$response" | head -1 | tr -d '\r')
    if [[ "$status_line" == "HTTP/1.1 $expect_status"* ]]; then
        if [[ -n "$expect_body" ]] && ! echo "$response" | grep -q "$expect_body"; then
            echo "  FAIL: $name — missing '$expect_body' in body"
            return 1
        fi
        echo "  PASS: $name"
        return 0
    fi
    echo "  FAIL: $name — got '$status_line', expected HTTP/1.1 $expect_status"
    return 1
}

echo ""; echo "==> Running HTTPS tests (HVF)..."
check_https "GET /"         "/"       "200"             || FAILURES=$((FAILURES+1))
check_https "GET /health"   "/health" "200"  "status"   || FAILURES=$((FAILURES+1))
check_https "GET /notfound" "/xyz"    "404"  "Not Found"|| FAILURES=$((FAILURES+1))

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL HVF TLS TESTS PASSED"; exit 0; }
echo "$FAILURES HVF TLS TEST(S) FAILED"; tail -40 "$VM_LOG"; exit 1
