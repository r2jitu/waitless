#!/usr/bin/env bash
# bazel/rules/run_qemu.sh — Run unikernel via QEMU (auto-detects arch from ELF)
#
#   bazel run //apps/webserver:run_qemu
#   bazel run --config=x86_64 //apps/webserver:run_qemu
#
# Env: UNIKERNEL_PORT (default 8080), UNIKERNEL_MEMORY (default 128)
set -euo pipefail

[[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]] && { echo "error: use 'bazel run'" >&2; exit 1; }
WS="$BUILD_WORKSPACE_DIRECTORY"

ELF="$WS/bazel-bin/${UNIKERNEL_ELF_RELPATH}"
IMG="$WS/bazel-bin/${UNIKERNEL_IMG_RELPATH:-}"
MEMORY="${UNIKERNEL_MEMORY:-128}"
PORT="${UNIKERNEL_PORT:-8080}"

QEMU_COMMON=(
    -m "$MEMORY" -smp 1
    -display none -monitor none
    -chardev stdio,id=s0,signal=off -serial chardev:s0
    -no-reboot
)

ELF_INFO="$(file "$ELF" 2>/dev/null || echo "")"

if echo "$ELF_INFO" | grep -q "ARM aarch64"; then
    [[ -f "$IMG" ]] || { echo "error: .img not found: $IMG" >&2; exit 1; }
    exec qemu-system-aarch64 \
        -machine virt -cpu max -kernel "$IMG" \
        "${QEMU_COMMON[@]}" \
        -device virtio-net-device,netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp::${PORT}-:80"
else
    # HVF/KVM only work when host arch matches guest arch
    ACCEL=()
    if [[ "$(uname -m)" = "x86_64" ]]; then
        if [[ "$(uname -s)" = "Darwin" ]] && sysctl -n kern.hv_support 2>/dev/null | grep -q '^1$'; then
            ACCEL=(-accel hvf)
        elif [[ "$(uname -s)" = "Linux" ]] && [[ -r /dev/kvm ]]; then
            ACCEL=(-accel kvm)
        fi
    fi
    exec qemu-system-x86_64 \
        -cpu qemu64 -kernel "$ELF" \
        "${QEMU_COMMON[@]}" \
        -device virtio-net-pci,netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp::${PORT}-:80" \
        ${ACCEL[@]+"${ACCEL[@]}"}
fi
