#!/usr/bin/env bash
# bazel/rules/run_hvf.sh — Run unikernel via HVF (macOS arm64, Apple Hypervisor.framework)
#
#   bazel run --config=hvf //apps/webserver:run
#
# Env: UNIKERNEL_PORT (default 8080), UNIKERNEL_MEMORY (default 128),
#      UNIKERNEL_CPUS (default 1)
set -euo pipefail

[[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]] && { echo "error: use 'bazel run'" >&2; exit 1; }
WS="$BUILD_WORKSPACE_DIRECTORY"

PORT="${UNIKERNEL_PORT:-8080}"
UDP_PORT=$((PORT + 10000))

exec "$WS/bazel-bin/${UNIKERNEL_HVF_RELPATH}" \
    "$WS/bazel-bin/${UNIKERNEL_IMG_RELPATH}" \
    "--ram=${UNIKERNEL_MEMORY:-128}" \
    "--cpus=${UNIKERNEL_CPUS:-1}" \
    -p "tcp:${PORT}:80" \
    -p "udp:${UDP_PORT}:7"
