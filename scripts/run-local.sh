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
#   UNIKERNEL_PORT=8080    Host port forwarded to VM port 80
#   UNIKERNEL_MEMORY=128   VM memory in MB
#   UNIKERNEL_CPUS=1       Number of vCPUs
#
# Port 8080 on localhost is forwarded to port 80 in the VM.
# Access the web server at: http://localhost:8080/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HOST_OS="$(uname -s)"     # Darwin or Linux
HOST_ARCH="$(uname -m)"   # arm64/aarch64 or x86_64

# Memory allocation (MB), vCPU count, host port
MEMORY="${UNIKERNEL_MEMORY:-128}"
CPUS="${UNIKERNEL_CPUS:-1}"
HOST_PORT="${UNIKERNEL_PORT:-8080}"

KERNEL="${1:-}"

# ── Build if no kernel provided ───────────────────────────────────────────────
if [ -z "$KERNEL" ]; then
    echo "==> Building webserver for ${HOST_ARCH}..."
    cd "$PROJECT_ROOT"

    if [ "$HOST_OS" = "Darwin" ] && [ "$HOST_ARCH" = "arm64" ]; then
        # macOS arm64: build raw binary image for the HVF runner.
        # .bazelrc.local sets --platforms=aarch64_unikernel by default.
        bazel build //apps/webserver:webserver.img
        KERNEL="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.img"
    elif [ "$HOST_ARCH" = "arm64" ] || [ "$HOST_ARCH" = "aarch64" ]; then
        # Linux arm64: build raw binary for QEMU -kernel (PIE ELF loads wrong).
        bazel build //apps/webserver:webserver.img
        KERNEL="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.img"
    else
        bazel build //apps/webserver:webserver.elf
        KERNEL="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
    fi

    echo "==> Built: $KERNEL"
fi

if [ ! -f "$KERNEL" ]; then
    echo "Error: kernel not found: $KERNEL"
    exit 1
fi

# ── macOS arm64 → HVF runner (hardware-accelerated) ──────────────────────────
# UNIKERNEL_RUNNER: hvf (default) or qemu.
RUNNER="${UNIKERNEL_RUNNER:-hvf}"
if [ "$HOST_OS" = "Darwin" ] && [ "$HOST_ARCH" = "arm64" ] && [ "$RUNNER" = "hvf" ]; then
    RUN_HVF="$PROJECT_ROOT/tools/hvf-runner/target/release/run-hvf"

    # Build via cargo + codesign.
    (cd "$PROJECT_ROOT/tools/hvf-runner" && cargo build --release --quiet 2>/dev/null && \
     codesign --force --sign - --entitlements run-hvf.entitlements target/release/run-hvf 2>/dev/null)

    IMG="$KERNEL"
    if [[ "$KERNEL" == *.elf ]]; then
        IMG="${KERNEL%.elf}.img"
        if [ ! -f "$IMG" ]; then
            echo "Error: run-hvf requires a raw binary image, not an ELF."
            echo "       Expected: $IMG"
            exit 1
        fi
    fi

    if [ ! -x "$RUN_HVF" ]; then
        echo "Error: HVF runner not found at $RUN_HVF"
        echo "       Build it: cd tools/hvf-runner && cargo build --release"
        exit 1
    fi
    UDP_HOST_PORT=$((HOST_PORT + 10000))
    exec "$RUN_HVF" "$IMG" \
        "--ram=${MEMORY}" "--cpus=${CPUS}" \
        -p "tcp:${HOST_PORT}:80" \
        -p "udp:${UDP_HOST_PORT}:7"
fi

# ── Common QEMU output flags ──────────────────────────────────────────────────
# -display none                 : no graphical window
# -monitor none                 : no QEMU monitor
# -chardev stdio,id=s0,signal=off : serial on stdio; "signal=off" (the QEMU
#                                   default) disables ISIG so Ctrl-C is passed
#                                   to the VM as byte 0x03 instead of generating
#                                   SIGINT.  The kernel detects 0x03 in the
#                                   serial RX FIFO, stops the server, and calls
#                                   PSCI/ACPI power-off so QEMU exits cleanly.
# -serial chardev:s0            : attach serial port to the chardev above
# -no-reboot                    : exit instead of rebooting on RESET

echo "==> Starting QEMU (OS=${HOST_OS} arch=${HOST_ARCH})"
echo "    Memory: ${MEMORY}MB  CPUs: ${CPUS}"
echo "    Network: http://localhost:${HOST_PORT}/ -> VM port 80"
echo "    Serial console below.  Press Ctrl-C to exit."
echo ""

QEMU_OUTPUT=(
    -display none
    -monitor none
    -chardev stdio,id=s0,signal=off
    -serial chardev:s0
    -no-reboot
)

# ── macOS arm64 + QEMU (UNIKERNEL_RUNNER=qemu) ───────────────────────────────
if [ "$HOST_OS" = "Darwin" ] && [ "$HOST_ARCH" = "arm64" ]; then
    if ! command -v qemu-system-aarch64 &>/dev/null; then
        echo "Error: qemu-system-aarch64 not found. Install with: brew install qemu"
        exit 1
    fi

    # QEMU needs .img (raw binary), not .elf.
    IMG="$KERNEL"
    if [[ "$KERNEL" == *.elf ]]; then
        IMG="${KERNEL%.elf}.img"
        if [ ! -f "$IMG" ]; then
            echo "Error: QEMU -kernel needs a raw binary image for aarch64."
            echo "       Expected: $IMG"
            echo "       Build it: bazel build //apps/webserver:webserver.img"
            exit 1
        fi
    fi

    # Must use TCG — Apple Hypervisor.framework doesn't guarantee ISV=1 in
    # ESR_EL2 for MMIO exits, causing QEMU to assert in hvf_handle_exception.
    exec qemu-system-aarch64 \
        -machine virt \
        -accel tcg \
        -kernel "$IMG" \
        -m "${MEMORY}" \
        -smp "${CPUS}" \
        -cpu max \
        "${QEMU_OUTPUT[@]}" \
        -device virtio-net-device,netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp::${HOST_PORT}-:80"
fi

# ── Linux → QEMU with KVM auto-detect ────────────────────────────────────────
if [ "$HOST_OS" = "Linux" ]; then
    KVM_FLAGS=()
    if [ -r /dev/kvm ]; then
        KVM_FLAGS=(-accel kvm)
        echo "    KVM acceleration enabled."
    fi

    if [ "$HOST_ARCH" = "aarch64" ] || [ "$HOST_ARCH" = "arm64" ]; then
        if ! command -v qemu-system-aarch64 &>/dev/null; then
            echo "Error: qemu-system-aarch64 not found."
            echo "Install with: sudo apt install qemu-system-arm"
            exit 1
        fi
        IMG="$KERNEL"
        if [[ "$KERNEL" == *.elf ]]; then
            IMG="${KERNEL%.elf}.img"
            if [ ! -f "$IMG" ]; then
                echo "Error: QEMU -kernel needs a raw binary image for aarch64."
                echo "       Expected: $IMG"
                echo "       Build it: bazel build //apps/webserver:webserver.img"
                exit 1
            fi
        fi

        exec qemu-system-aarch64 \
            -machine virt \
            -kernel "$IMG" \
            -m "${MEMORY}" \
            -smp "${CPUS}" \
            "${QEMU_OUTPUT[@]}" \
            -device virtio-net-device,netdev=net0 \
            -netdev "user,id=net0,hostfwd=tcp::${HOST_PORT}-:80" \
            -cpu max \
            "${KVM_FLAGS[@]}"
    else
        if ! command -v qemu-system-x86_64 &>/dev/null; then
            echo "Error: qemu-system-x86_64 not found."
            echo "Install with: sudo apt install qemu-system-x86"
            exit 1
        fi
        exec qemu-system-x86_64 \
            -kernel "$KERNEL" \
            -m "${MEMORY}" \
            -smp "${CPUS}" \
            -cpu qemu64 \
            "${QEMU_OUTPUT[@]}" \
            -device virtio-net-pci,netdev=net0 \
            -netdev "user,id=net0,hostfwd=tcp::${HOST_PORT}-:80" \
            "${KVM_FLAGS[@]}"
    fi
fi

# ── macOS x86_64 → QEMU with HVF ─────────────────────────────────────────────
if ! command -v qemu-system-x86_64 &>/dev/null; then
    echo "Error: qemu-system-x86_64 not found. Install with: brew install qemu"
    exit 1
fi

QEMU_X86=(
    qemu-system-x86_64
    -kernel "$KERNEL"
    -m "${MEMORY}"
    -smp "${CPUS}"
    -cpu qemu64
    "${QEMU_OUTPUT[@]}"
    -device virtio-net-pci,netdev=net0
    -netdev "user,id=net0,hostfwd=tcp::${HOST_PORT}-:80"
)

if sysctl -n kern.hv_support 2>/dev/null | grep -q '^1$'; then
    exec "${QEMU_X86[@]}" -accel hvf
else
    exec "${QEMU_X86[@]}"
fi
