#!/usr/bin/env bash
# bazel/rules/run_iso.sh — Run unikernel from Limine ISO via QEMU (x86_64)
#
#   bazel run --config=x86_64 //apps/webserver:run_iso
#
# Env: UNIKERNEL_PORT   — base host port (default 8080):
#                         http://localhost:$PORT/
#                         https://localhost:$((PORT+1))/
#                         udp  ::$((PORT+2))  -> guest :7
#      UNIKERNEL_MEMORY — guest RAM in MB     (default 128)
set -euo pipefail

[[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]] && { echo "error: use 'bazel run'" >&2; exit 1; }
WS="$BUILD_WORKSPACE_DIRECTORY"

source "$WS/scripts/helpers.sh"

QEMU_BIN="qemu-system-x86_64"
VIRTIO_DEV="virtio-net-pci"

PORT="${UNIKERNEL_PORT:-8080}"

echo "==> http://localhost:${PORT}/"
echo "==> https://localhost:$((PORT+1))/  (self-signed dev cert — use curl -k)"
echo "==> udp  ::$((PORT+2)) → guest :7"

run_qemu "$PORT" "${UNIKERNEL_MEMORY:-128}" \
    -cpu max -cdrom "$WS/bazel-bin/${UNIKERNEL_ISO_RELPATH}"
