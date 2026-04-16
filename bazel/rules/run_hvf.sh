#!/usr/bin/env bash
# bazel/rules/run_hvf.sh — Run unikernel via the HVF runner (macOS arm64).
#
# Runs from two contexts without caring which:
#   1. `bazel run --config=hvf //apps/webserver:webserver`
#   2. sh_test subprocess via :webserver in data.
#
# This script sits next to `<app>.img` in the runfiles tree, so the image
# is resolved via $0's sibling. The run-hvf binary is always at
# `tools/hvf-runner/run-hvf`, found via the runfiles root.
#
# Env:
#   UNIKERNEL_PORT     — host HTTP port   (default 8080) → guest :80
#   UNIKERNEL_TLS_PORT — host HTTPS port  (default 8443) → guest :443
#   UNIKERNEL_UDP_PORT — host UDP port    (default 8007) → guest :7
#   UNIKERNEL_MEMORY   — guest RAM in MB  (default 128)
#   UNIKERNEL_CPUS     — guest vCPU count (default 1)
set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
SELF_NAME="$(basename "$0")"
IMG="${SELF_DIR}/${SELF_NAME}.img"
[[ -f "$IMG" ]] || { echo "ERROR: .img not found at $IMG" >&2; exit 1; }

# Walk upward from $SELF_DIR until we find the workspace/runfiles root
# (identified by `scripts/helpers.sh`, a data dep of every
# unikernel_binary). Survives targets at arbitrary nesting depth.
ROOT="$SELF_DIR"
while [[ "$ROOT" != "/" ]] && [[ ! -f "$ROOT/tools/hvf-runner/run-hvf" ]]; do
    ROOT="$(dirname "$ROOT")"
done
HVF="$ROOT/tools/hvf-runner/run-hvf"
[[ -x "$HVF" ]] || { echo "ERROR: run-hvf not found (searched upward from $SELF_DIR)" >&2; exit 1; }

PORT="${UNIKERNEL_PORT:-8080}"
TLS_PORT="${UNIKERNEL_TLS_PORT:-8443}"
UDP_PORT="${UNIKERNEL_UDP_PORT:-8007}"

echo "==> http://localhost:${PORT}/"
echo "==> https://localhost:${TLS_PORT}/  (self-signed dev cert — use curl -k)"
echo "==> udp  ::${UDP_PORT} → guest :7"

exec "$HVF" "$IMG" \
    "--ram=${UNIKERNEL_MEMORY:-128}" \
    "--cpus=${UNIKERNEL_CPUS:-1}" \
    -p "tcp:${PORT}:80" \
    -p "tcp:${TLS_PORT}:443" \
    -p "udp:${UDP_PORT}:7"
