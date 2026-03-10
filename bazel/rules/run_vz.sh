#!/usr/bin/env bash
# bazel/rules/run_vz.sh — Run unikernel via VZ.framework (macOS arm64)
#
#   bazel run //apps/webserver:run_vz
#
# Env: UNIKERNEL_PORT (default 8080), UNIKERNEL_MEMORY (default 128)
set -euo pipefail

[[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]] && { echo "error: use 'bazel run'" >&2; exit 1; }
WS="$BUILD_WORKSPACE_DIRECTORY"

exec "$WS/bazel-bin/${UNIKERNEL_VZ_RELPATH}" \
    "$WS/bazel-bin/${UNIKERNEL_IMG_RELPATH}" \
    "${UNIKERNEL_PORT:-8080}"
