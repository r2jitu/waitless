#!/usr/bin/env bash
# bazel/rules/run_wrapper.sh — launcher for "bazel run //apps/<name>:run"
#
# On macOS arm64, uses the Bazel-built VZ.framework runner (hardware-accelerated).
# On all other platforms, auto-detects arch from ELF and falls back to QEMU.
#
# Env vars set by unikernel.bzl:
#   UNIKERNEL_ELF_RELPATH — workspace-relative path of the ELF
#   UNIKERNEL_IMG_RELPATH — workspace-relative path of the raw binary image
#   UNIKERNEL_VZ_RELPATH  — workspace-relative path of the run-vz binary

set -euo pipefail

if [[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then
    echo "error: this script must be invoked via 'bazel run', not directly." >&2
    exit 1
fi

WORKSPACE="$BUILD_WORKSPACE_DIRECTORY"

source "$WORKSPACE/scripts/helpers.sh"

ELF="${WORKSPACE}/bazel-bin/${UNIKERNEL_ELF_RELPATH}"
IMG="${WORKSPACE}/bazel-bin/${UNIKERNEL_IMG_RELPATH:-}"

if [[ ! -f "$ELF" ]]; then
    echo "error: ELF not found: $ELF" >&2
    echo "       Run 'bazel build ${UNIKERNEL_ELF_RELPATH}' first." >&2
    exit 1
fi

# macOS arm64: use the Bazel-built VZ.framework runner (hardware-accelerated).
VZ_BIN="${WORKSPACE}/bazel-bin/${UNIKERNEL_VZ_RELPATH:-}"
if [[ "$(uname -s)" = "Darwin" && "$(uname -m)" = "arm64" && -n "$VZ_BIN" && -x "$VZ_BIN" && -f "$IMG" ]]; then
    exec "$VZ_BIN" "$IMG" "${UNIKERNEL_PORT:-8080}"
fi

# All other platforms: auto-detect arch from ELF and run via QEMU.
detect_qemu "$ELF"
run_qemu "${UNIKERNEL_PORT:-8080}" "${UNIKERNEL_MEMORY:-128}" \
    "${QEMU_MACHINE[@]}" -kernel "$KERNEL_ARG"
