#!/usr/bin/env bash
# bazel/rules/run_iso.sh — Run unikernel from Limine ISO via QEMU (x86_64)
#
#   bazel run --config=x86_64 //apps/webserver:run_iso
#
# Env: UNIKERNEL_PORT (default 8080), UNIKERNEL_MEMORY (default 128)
set -euo pipefail

[[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]] && { echo "error: use 'bazel run'" >&2; exit 1; }
WS="$BUILD_WORKSPACE_DIRECTORY"

ISO="$WS/bazel-bin/${UNIKERNEL_ISO_RELPATH}"
PORT="${UNIKERNEL_PORT:-8080}"
MEMORY="${UNIKERNEL_MEMORY:-128}"

exec qemu-system-x86_64 \
    -cpu qemu64 -cdrom "$ISO" \
    -m "$MEMORY" -smp 1 \
    -display none -monitor none \
    -chardev stdio,id=s0,signal=off -serial chardev:s0 \
    -no-reboot \
    -device virtio-net-pci,netdev=net0 \
    -netdev "user,id=net0,hostfwd=tcp::${PORT}-:80"
