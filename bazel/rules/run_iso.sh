#!/usr/bin/env bash
# bazel/rules/run_iso.sh — Run unikernel from Limine ISO via QEMU (x86_64)
#
#   bazel run --config=x86_64 //apps/webserver:run_iso
#
# Env: UNIKERNEL_PORT (default 8080), UNIKERNEL_MEMORY (default 128)
set -euo pipefail

[[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]] && { echo "error: use 'bazel run'" >&2; exit 1; }
WS="$BUILD_WORKSPACE_DIRECTORY"

source "$WS/scripts/helpers.sh"

QEMU_BIN="qemu-system-x86_64"
VIRTIO_DEV="virtio-net-pci"

run_qemu "${UNIKERNEL_PORT:-8080}" "${UNIKERNEL_MEMORY:-128}" \
    -cpu qemu64 -cdrom "$WS/bazel-bin/${UNIKERNEL_ISO_RELPATH}"
