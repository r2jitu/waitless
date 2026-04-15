#!/usr/bin/env bash
# bazel/rules/run_qemu.sh — Run unikernel via QEMU (auto-detects arch from ELF)
#
#   bazel run //apps/webserver:run_qemu
#   bazel run --config=x86_64 //apps/webserver:run_qemu
#
# Env: UNIKERNEL_PORT     — plain HTTP host port (default 8080, → guest:80)
#      UNIKERNEL_TLS_PORT — HTTPS host port      (default 8443, → guest:443)
#      UNIKERNEL_MEMORY   — guest RAM in MB      (default 128)
set -euo pipefail

[[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]] && { echo "error: use 'bazel run'" >&2; exit 1; }
WS="$BUILD_WORKSPACE_DIRECTORY"

source "$WS/scripts/helpers.sh"

ELF="$WS/bazel-bin/${UNIKERNEL_ELF_RELPATH}"
detect_qemu "$ELF"

PORT="${UNIKERNEL_PORT:-8080}"
TLS_PORT="${UNIKERNEL_TLS_PORT:-8443}"

echo "==> http://localhost:${PORT}/"
echo "==> https://localhost:${TLS_PORT}/  (self-signed dev cert — use curl -k)"

run_qemu "$PORT" "$TLS_PORT" "${UNIKERNEL_MEMORY:-128}" \
    "${QEMU_MACHINE[@]}" -kernel "$KERNEL_ARG"
