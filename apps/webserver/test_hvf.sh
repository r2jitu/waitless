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

# Bounded command runner. macOS lacks GNU `timeout`; use perl (always
# present) to fork+exec the child under an alarm and escalate TERM→KILL
# if it runs long. Exit 124 on timeout, otherwise the child's exit code.
run_timeout() {
    perl -e '
        my $t = shift;
        my $pid = fork // die "fork: $!";
        if ($pid == 0) { exec { $ARGV[0] } @ARGV or exit 127; }
        local $SIG{ALRM} = sub {
            kill TERM => $pid;
            select undef, undef, undef, 0.5;
            kill KILL => $pid;
        };
        alarm $t;
        waitpid $pid, 0;
        alarm 0;
        exit(($? & 127) ? 124 : ($? >> 8));
    ' "$@"
}

# Issue one HTTPS request (bounded). Prints the response, exits 124 if
# openssl hangs (e.g. the hvf-runner TCP relay is up but the guest hasn't
# bound port 80 yet, so bytes go into a void and no response flows back).
https_get() {
    local path="$1" timeout_s="${2:-5}"
    printf 'GET %s HTTP/1.1\r\nHost: unikernel.local\r\nConnection: close\r\n\r\n' "$path" | \
        run_timeout "$timeout_s" "$OPENSSL" s_client -connect "${VM_HOST}:${VM_PORT}" -tls1_3 \
            -CAfile "$DEV_CERT" -servername unikernel.local -quiet 2>/dev/null
}

# Poll readiness with real HTTP GETs (up to 30s).  The old probe piped
# `echo ""` into openssl and grepped the output, but the server (correctly)
# waits for a complete request line and openssl therefore never exits —
# wedging the first loop iteration before `sleep 1` is reached.
echo "==> Waiting for HTTPS server to come up..."
ready=0
for _ in $(seq 1 30); do
    status_line=$(https_get /health 3 | head -1 | tr -d '\r' || true)
    if [[ "$status_line" == HTTP/1.1\ 200* ]]; then
        ready=1; break
    fi
    sleep 1
done
if [[ $ready -eq 0 ]]; then
    echo "ERROR: HTTPS server not ready after 30s" >&2
    cat "$VM_LOG" >&2
    exit 1
fi

# Helper: issue one HTTPS request and check the status + body.
check_https() {
    local name="$1" path="$2" expect_status="$3" expect_body="${4:-}"
    local response
    response=$(https_get "$path" 10)
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
