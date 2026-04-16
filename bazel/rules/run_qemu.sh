#!/usr/bin/env bash
# bazel/rules/run_qemu.sh — Run unikernel via QEMU (auto-detects arch from ELF)
#
#   bazel run //apps/webserver:run_qemu
#   bazel run --config=x86_64 //apps/webserver:run_qemu
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

ELF="$WS/bazel-bin/${UNIKERNEL_ELF_RELPATH}"
detect_qemu "$ELF"

PORT="${UNIKERNEL_PORT:-8080}"

echo "==> http://localhost:${PORT}/"
echo "==> https://localhost:$((PORT+1))/  (self-signed dev cert — use curl -k)"
echo "==> udp  ::$((PORT+2)) → guest :7"

run_qemu "$PORT" "${UNIKERNEL_MEMORY:-128}" \
    "${QEMU_MACHINE[@]}" -kernel "$KERNEL_ARG"
