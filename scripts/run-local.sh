#!/usr/bin/env bash
# run-local.sh — Run a unikernel image locally
#
# Prerequisites:
#   macOS arm64:  Xcode / swiftc (ships with Xcode Command Line Tools)
#   macOS x86_64: brew install qemu
#   Linux:        apt install qemu-system-arm qemu-system-x86  (or equivalent)
#
# Usage:
#   ./scripts/run-local.sh [path-to-kernel]
#
# The kernel path may be a raw binary (.img) or ELF (.elf).
# If no path is given, builds and runs the webserver example.
# Runner is selected automatically:
#   • macOS arm64  → HVF runner (Apple Hypervisor.framework, in-tree Rust)
#   • macOS x86_64 → QEMU with HVF if available
#   • Linux        → QEMU with KVM if /dev/kvm is accessible
#
# Environment variables:
#   UNIKERNEL_RUNNER=qemu  Force QEMU even on macOS arm64 (TCG, no HW accel)
#   UNIKERNEL_PORT=8080    Base host port:
#                            http://localhost:$PORT/
#                            https://localhost:$((PORT+1))/
#                            udp  ::$((PORT+2)) → guest :7
#   UNIKERNEL_MEMORY=128   VM memory in MB
#   UNIKERNEL_CPUS=1       Number of vCPUs
#
# QEMU invocation goes through scripts/helpers.sh::run_qemu, the exact
# same helper that sh_test targets use via start_qemu — so test and
# interactive launches stay in lockstep by construction.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/helpers.sh"

HOST_OS="$(uname -s)"     # Darwin or Linux
HOST_ARCH="$(uname -m)"   # arm64/aarch64 or x86_64

MEMORY="${UNIKERNEL_MEMORY:-128}"
export UNIKERNEL_CPUS="${UNIKERNEL_CPUS:-1}"   # read by _qemu_net_args
HOST_PORT="${UNIKERNEL_PORT:-8080}"

KERNEL="${1:-}"

# ── Build if no kernel provided ───────────────────────────────────────────────
if [ -z "$KERNEL" ]; then
    echo "==> Building webserver for ${HOST_ARCH}..."
    cd "$PROJECT_ROOT"

    if [ "$HOST_ARCH" = "arm64" ] || [ "$HOST_ARCH" = "aarch64" ]; then
        # aarch64: build raw .img (HVF runner and QEMU -kernel both need it;
        # the PIE ELF doesn't relocate cleanly under -kernel).
        bazel build //apps/webserver:webserver.img
        KERNEL="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.img"
    else
        bazel build //apps/webserver:webserver.elf
        KERNEL="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
    fi

    echo "==> Built: $KERNEL"
fi

[[ -f "$KERNEL" ]] || { echo "Error: kernel not found: $KERNEL"; exit 1; }

echo "==> Starting unikernel (OS=${HOST_OS} arch=${HOST_ARCH})"
echo "    Memory: ${MEMORY}MB  CPUs: ${UNIKERNEL_CPUS}"
echo "    HTTP  http://localhost:${HOST_PORT}/         → guest :80"
echo "    HTTPS https://localhost:$((HOST_PORT+1))/    → guest :443  (curl -k)"
echo "    UDP   localhost:$((HOST_PORT+2))             → guest :7"
echo "    Serial console below.  Press Ctrl-C to exit."
echo ""

# ── macOS arm64 → HVF runner (hardware-accelerated, default) ─────────────────
RUNNER="${UNIKERNEL_RUNNER:-hvf}"
if [ "$HOST_OS" = "Darwin" ] && [ "$HOST_ARCH" = "arm64" ] && [ "$RUNNER" = "hvf" ]; then
    RUN_HVF="$PROJECT_ROOT/bazel-bin/tools/hvf-runner/run-hvf"
    (cd "$PROJECT_ROOT" && bazel build //tools/hvf-runner:run_hvf 2>/dev/null)

    IMG="$KERNEL"
    if [[ "$KERNEL" == *.elf ]]; then
        IMG="${KERNEL%.elf}.img"
        [[ -f "$IMG" ]] || { echo "Error: run-hvf needs raw .img at $IMG"; exit 1; }
    fi
    [[ -x "$RUN_HVF" ]] || { echo "Error: run-hvf missing: bazel build //tools/hvf-runner:run_hvf"; exit 1; }

    exec "$RUN_HVF" "$IMG" \
        "--ram=${MEMORY}" "--cpus=${UNIKERNEL_CPUS}" \
        -p "tcp:${HOST_PORT}:80" \
        -p "tcp:$((HOST_PORT+1)):443" \
        -p "udp:$((HOST_PORT+2)):7"
fi

# ── QEMU path (Linux any arch, macOS x86_64, macOS arm64 with RUNNER=qemu) ──
detect_qemu "$KERNEL"

ACCEL=()
if [ "$HOST_OS" = "Linux" ] && [ -r /dev/kvm ]; then
    ACCEL=(-accel kvm)
    echo "    KVM acceleration enabled."
elif [ "$HOST_OS" = "Darwin" ] && [ "$HOST_ARCH" = "arm64" ]; then
    # Apple Hypervisor.framework on arm64 doesn't guarantee ISV=1 in
    # ESR_EL2 for MMIO exits, so QEMU+HVF asserts on the first virtio
    # MMIO access. TCG only.
    ACCEL=(-accel tcg,thread=multi)
elif [ "$HOST_OS" = "Darwin" ] && [ "$HOST_ARCH" = "x86_64" ] && \
     sysctl -n kern.hv_support 2>/dev/null | grep -q '^1$'; then
    ACCEL=(-accel hvf)
fi

# QEMU_MACHINE was populated by detect_qemu; covers -machine virt on
# aarch64 and -cpu (max/host) per accel. For the ISO/Limine path a
# caller passes -cdrom; this script always uses -kernel.
if [[ "$HOST_ARCH" = "arm64" || "$HOST_ARCH" = "aarch64" ]] && [[ "$KERNEL" == *.elf ]]; then
    IMG="${KERNEL%.elf}.img"
    [[ -f "$IMG" ]] || { echo "Error: QEMU -kernel on aarch64 needs raw .img at $IMG"; exit 1; }
    KERNEL_ARG="$IMG"
fi

run_qemu "$HOST_PORT" "$MEMORY" "${QEMU_MACHINE[@]}" "${ACCEL[@]}" -kernel "$KERNEL_ARG"
