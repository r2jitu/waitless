#!/usr/bin/env bash
# bazel/rules/run_native.sh — Run the native POSIX binary (no VM).
#
#   bazel run //apps/webserver
#   bazel run --config=aarch64-macos //apps/webserver
#
# Env: UNIKERNEL_PORT (passed through to binary via PORT env var)
set -euo pipefail

[[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]] && { echo "error: use 'bazel run'" >&2; exit 1; }
WS="$BUILD_WORKSPACE_DIRECTORY"

exec env PORT="${UNIKERNEL_PORT:-8080}" \
    "$WS/bazel-bin/${UNIKERNEL_NATIVE_RELPATH}"
