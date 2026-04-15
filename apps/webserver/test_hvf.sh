#!/usr/bin/env bash
# apps/webserver/test_hvf.sh — Boot webserver via HVF runner, verify HTTPS.
# macOS arm64 only; skips on other platforms.
#
#   bazel test --config=hvf //apps/webserver:test
#
# The HVF runner uses a userspace TCP/UDP proxy (no vmnet, no root).
# The webserver is HTTPS-only (TLS 1.3 + Ed25519 dev cert); the shared
# helpers drive the handshake through Homebrew's openssl s_client
# because macOS LibreSSL doesn't support Ed25519 cert verification.
#
# Default forward: -p tcp:8443:80. The test points openssl at localhost:8443.

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]] || [[ "$(uname -m)" != "arm64" ]]; then
    echo "SKIP: HVF runner only works on macOS arm64"
    exit 0
fi

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

if ! find_openssl_3x; then
    echo "SKIP: OpenSSL 3.x not found (LibreSSL doesn't support our Ed25519 dev cert)"
    exit 0
fi
echo "==> Using $($OPENSSL version)"

IMG="${RUNFILES}/_main/apps/webserver/webserver.img"
HVF_BIN="${RUNFILES}/_main/tools/hvf-runner/run-hvf"
DEV_CERT="${RUNFILES}/_main/apps/webserver/dev_certs/dev_cert.pem"
[[ -f "$IMG" ]] || { echo "ERROR: webserver.img not found at $IMG" >&2; exit 1; }
[[ -x "$HVF_BIN" ]] || { echo "ERROR: run-hvf not found at $HVF_BIN" >&2; exit 1; }
[[ -f "$DEV_CERT" ]] || { echo "ERROR: dev_cert.pem not found at $DEV_CERT" >&2; exit 1; }

FAILURES=0
VM_LOG="$(mktemp -t unikernel_hvf_test_XXXXXXXX)"
trap cleanup_vm EXIT

VM_HOST="127.0.0.1"
VM_PORT="8443"

echo "==> Booting webserver via HVF runner (HTTPS on :${VM_PORT})..."
"$HVF_BIN" "$IMG" -p "tcp:${VM_PORT}:80" >"$VM_LOG" 2>&1 &
VM_PID=$!

if ! wait_https /health 30 "$VM_PID"; then
    echo "ERROR: HTTPS server not ready after 30s" >&2
    cat "$VM_LOG" >&2
    exit 1
fi

echo ""; echo "==> Running HTTPS tests (HVF)..."
check_https "GET /"         "/"       "200"             || FAILURES=$((FAILURES+1))
check_https "GET /health"   "/health" "200"  "status"   || FAILURES=$((FAILURES+1))
check_https "GET /notfound" "/xyz"    "404"  "Not Found"|| FAILURES=$((FAILURES+1))

# Burst: rapid sequential HTTPS connects. Regression guard for two bugs
# squashed together in commits 52e3a62 (hvf-runner CLOSE_WAIT fd-leak on
# host-side FIN) and 03bf02f (tls_server advance() didn't loop, stranding
# app_data records that arrived in the same TCP segment as
# ClientChangeCipherSpec+Finished). Pre-fix: ~20% of requests in a tight
# loop came back empty, so 3 sequential checks rolled a ~49% chance of
# passing. 30 sequential checks roll ≪1% — effectively deterministic.
echo ""
burst_https "Burst test (HVF)" /health 30 || FAILURES=$((FAILURES+1))

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL HVF TLS TESTS PASSED"; exit 0; }
echo "$FAILURES HVF TLS TEST(S) FAILED"; tail -40 "$VM_LOG"; exit 1
