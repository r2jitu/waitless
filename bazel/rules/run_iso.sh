#!/usr/bin/env bash
# bazel/rules/run_iso.sh — Run unikernel from Limine ISO via QEMU (x86_64)
#
#   bazel run --config=x86_64 //apps/webserver:run_iso
#
# Env: UNIKERNEL_PORT     — plain HTTP host port (default 8080, → guest:80)
#      UNIKERNEL_TLS_PORT — HTTPS host port      (default 8443, → guest:443)
#      UNIKERNEL_MEMORY   — guest RAM in MB      (default 128)
set -euo pipefail

[[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]] && { echo "error: use 'bazel run'" >&2; exit 1; }
WS="$BUILD_WORKSPACE_DIRECTORY"

source "$WS/scripts/helpers.sh"

QEMU_BIN="qemu-system-x86_64"
VIRTIO_DEV="virtio-net-pci"

PORT="${UNIKERNEL_PORT:-8080}"
TLS_PORT="${UNIKERNEL_TLS_PORT:-8443}"

echo "==> http://localhost:${PORT}/"
echo "==> https://localhost:${TLS_PORT}/  (self-signed dev cert — use curl -k)"

run_qemu "$PORT" "$TLS_PORT" "${UNIKERNEL_MEMORY:-128}" \
    -cpu qemu64 -cdrom "$WS/bazel-bin/${UNIKERNEL_ISO_RELPATH}"
