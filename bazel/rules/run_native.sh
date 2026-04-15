#!/usr/bin/env bash
# bazel/rules/run_native.sh — Run the native POSIX binary (no VM).
#
#   bazel run //apps/webserver
#   bazel run --config=aarch64-macos //apps/webserver
#
# Env: UNIKERNEL_PORT     — plain HTTP port (default 8080)
#      UNIKERNEL_TLS_PORT — HTTPS port      (default 8443)
set -euo pipefail

[[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]] && { echo "error: use 'bazel run'" >&2; exit 1; }
WS="$BUILD_WORKSPACE_DIRECTORY"

PORT="${UNIKERNEL_PORT:-8080}"
TLS_PORT="${UNIKERNEL_TLS_PORT:-8443}"

echo "==> http://localhost:${PORT}/"
echo "==> https://localhost:${TLS_PORT}/  (self-signed dev cert — use curl -k)"

exec env PORT="$PORT" TLS_PORT="$TLS_PORT" \
    "$WS/bazel-bin/${UNIKERNEL_NATIVE_RELPATH}"
