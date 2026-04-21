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
# Variant wrappers (from `unikernel_variants`) symlink this script
# at `<app>_<variant>`; artefacts stay named after the base target.
for _suffix in _hvf _iso _qemu_aarch64 _qemu_x86_64; do
    SELF_NAME="${SELF_NAME%$_suffix}"
done
ISO="${SELF_DIR}/${SELF_NAME}.iso"
[[ -f "$ISO" ]] || { echo "ERROR: .iso not found at $ISO" >&2; exit 1; }

# Walk upward from $SELF_DIR until we hit the helpers.sh marker —
# survives arbitrary target nesting depth.
ROOT="$SELF_DIR"
while [[ "$ROOT" != "/" ]] && [[ ! -f "$ROOT/scripts/helpers.sh" ]]; do
    ROOT="$(dirname "$ROOT")"
done
[[ -f "$ROOT/scripts/helpers.sh" ]] || { echo "ERROR: scripts/helpers.sh not found (searched upward from $SELF_DIR)" >&2; exit 1; }
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
