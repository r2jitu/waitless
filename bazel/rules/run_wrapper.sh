#!/usr/bin/env bash
# bazel/rules/run_wrapper.sh — launcher for "bazel run //apps/<name>:run"
#
# Bazel 6+ sets BUILD_WORKSPACE_DIRECTORY to the workspace root when a target
# is run via "bazel run".  We use that to locate the pre-built files (which
# Bazel guaranteed to have built before running this script) and hand off to
# the runner in scripts/run-local.sh.
#
# On macOS arm64, the pre-built .img (raw ARM64 binary) is passed directly so
# run-local.sh → run-vz can boot it without any runtime ELF conversion.
# On all other platforms, the ELF is passed and QEMU handles it directly.
#
# Env vars set by unikernel.bzl:
#   UNIKERNEL_ELF_RELPATH — workspace-relative path of the ELF
#   UNIKERNEL_IMG_RELPATH — workspace-relative path of the raw binary image

set -euo pipefail

if [[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then
    echo "error: this script must be invoked via 'bazel run', not directly." >&2
    exit 1
fi

WORKSPACE="$BUILD_WORKSPACE_DIRECTORY"
HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

ELF="${WORKSPACE}/bazel-bin/${UNIKERNEL_ELF_RELPATH}"
IMG="${WORKSPACE}/bazel-bin/${UNIKERNEL_IMG_RELPATH:-}"

if [[ ! -f "$ELF" ]]; then
    echo "error: ELF not found: $ELF" >&2
    echo "       Run 'bazel build ${UNIKERNEL_ELF_RELPATH}' first." >&2
    exit 1
fi

# On macOS arm64, use the Bazel-built VZ.framework runner directly.
# run-vz accepts only raw binaries (not ELFs), and Bazel built both the
# .img and run-vz binary as part of this target's dependencies.
VZ_BIN="${WORKSPACE}/bazel-bin/${UNIKERNEL_VZ_RELPATH:-}"
if [[ "$HOST_OS" = "Darwin" && "$HOST_ARCH" = "arm64" && -n "$VZ_BIN" && -x "$VZ_BIN" && -f "$IMG" ]]; then
    exec "$VZ_BIN" "$IMG" "${UNIKERNEL_PORT:-8080}"
fi

exec "${WORKSPACE}/scripts/run-local.sh" "$ELF"
