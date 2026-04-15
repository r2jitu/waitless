#!/usr/bin/env bash
# bazel/rules/run_hvf.sh — Run unikernel via HVF (macOS arm64, Apple Hypervisor.framework)
#
#   bazel run --config=hvf //apps/webserver:run
#
# Env: UNIKERNEL_PORT     — plain HTTP host port (default 8080, → guest:80)
#      UNIKERNEL_TLS_PORT — HTTPS host port      (default 8443, → guest:443)
#      UNIKERNEL_MEMORY   — guest RAM in MB      (default 128)
#      UNIKERNEL_CPUS     — guest vCPU count     (default 1)
set -euo pipefail

[[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]] && { echo "error: use 'bazel run'" >&2; exit 1; }
WS="$BUILD_WORKSPACE_DIRECTORY"

PORT="${UNIKERNEL_PORT:-8080}"
TLS_PORT="${UNIKERNEL_TLS_PORT:-8443}"
UDP_PORT=$((PORT + 10000))

echo "==> http://localhost:${PORT}/"
echo "==> https://localhost:${TLS_PORT}/  (self-signed dev cert — use curl -k)"

exec "$WS/bazel-bin/${UNIKERNEL_HVF_RELPATH}" \
    "$WS/bazel-bin/${UNIKERNEL_IMG_RELPATH}" \
    "--ram=${UNIKERNEL_MEMORY:-128}" \
    "--cpus=${UNIKERNEL_CPUS:-1}" \
    -p "tcp:${PORT}:80" \
    -p "tcp:${TLS_PORT}:443" \
    -p "udp:${UDP_PORT}:7"
