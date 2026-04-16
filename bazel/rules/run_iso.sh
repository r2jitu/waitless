#!/usr/bin/env bash
# bazel/rules/run_iso.sh — Run unikernel from Limine ISO via QEMU (x86_64).
#
# Runs from two contexts without caring which:
#   1. `bazel run --config=x86_64-iso //apps/webserver:webserver`
#   2. sh_test subprocess via :webserver in data.
#
# Env:
#   UNIKERNEL_PORT     — host HTTP port   (default 8080) → guest :80
#   UNIKERNEL_TLS_PORT — host HTTPS port  (default 8443) → guest :443
#   UNIKERNEL_UDP_PORT — host UDP port    (default 8007) → guest :7
#   UNIKERNEL_MEMORY   — guest RAM in MB  (default 128)
set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
SELF_NAME="$(basename "$0")"
ISO="${SELF_DIR}/${SELF_NAME}.iso"
[[ -f "$ISO" ]] || { echo "ERROR: .iso not found at $ISO" >&2; exit 1; }

ROOT="$(cd "$SELF_DIR/../.." && pwd)"
source "$ROOT/scripts/helpers.sh"

QEMU_BIN="qemu-system-x86_64"
VIRTIO_DEV="virtio-net-pci"

PORT="${UNIKERNEL_PORT:-8080}"
TLS_PORT="${UNIKERNEL_TLS_PORT:-8443}"
UDP_PORT="${UNIKERNEL_UDP_PORT:-8007}"

echo "==> http://localhost:${PORT}/"
echo "==> https://localhost:${TLS_PORT}/  (self-signed dev cert — use curl -k)"
echo "==> udp  ::${UDP_PORT} → guest :7"

run_qemu "$PORT" "$TLS_PORT" "$UDP_PORT" "${UNIKERNEL_MEMORY:-128}" \
    -cpu max -cdrom "$ISO"
