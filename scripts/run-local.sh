#!/usr/bin/env bash
# run-local.sh — Run a unikernel image locally with QEMU on macOS
#
# Prerequisites:
#   brew install qemu
#
# Usage:
#   ./scripts/run-local.sh [path-to-elf]
#
# If no path is given, builds and runs the webserver example.
# Architecture is detected automatically:
#   • Apple Silicon (arm64) → qemu-system-aarch64 with TCG (HVF unavailable; see below)
#   • Intel Mac  (x86_64)  → qemu-system-x86_64  with HVF if available
#
# The VM gets a virtio-net NIC with user-mode networking.
# Port 8080 on localhost is forwarded to port 80 in the VM.
#
# Access the web server at: http://localhost:8080/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HOST_ARCH="$(uname -m)"   # arm64 or x86_64

# Memory allocation (MB), vCPU count, host port
MEMORY="${UNIKERNEL_MEMORY:-128}"
CPUS="${UNIKERNEL_CPUS:-1}"
HOST_PORT="${UNIKERNEL_PORT:-8080}"

ELF="${1:-}"

# ── Build if no ELF provided ─────────────────────────────────────────────────
if [ -z "$ELF" ]; then
    echo "==> Building webserver for ${HOST_ARCH}..."
    cd "$PROJECT_ROOT"

    if [ "$HOST_ARCH" = "arm64" ]; then
        bazel build --config=aarch64 //apps/webserver:webserver.elf
        ELF="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
    else
        bazel build //apps/webserver:webserver.elf
        ELF="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
    fi

    echo "==> Built: $ELF"
fi

if [ ! -f "$ELF" ]; then
    echo "Error: ELF not found: $ELF"
    exit 1
fi

echo "==> Starting QEMU (arch=${HOST_ARCH})"
echo "    Memory: ${MEMORY}MB  CPUs: ${CPUS}"
echo "    Network: http://localhost:${HOST_PORT}/ -> VM port 80"
echo "    Serial console below.  Press Ctrl-C to exit."
echo ""

# ── Common QEMU output flags ──────────────────────────────────────────────────
# We use exec so QEMU is Bazel's direct child process.  That way Ctrl-C from
# the terminal reaches Bazel, which kills QEMU (its direct child) cleanly.
# If we left a shell in between, Bazel would kill the shell and QEMU would be
# orphaned and keep running.
#
# -display none                 : no graphical window
# -monitor none                 : no QEMU monitor
# -chardev stdio,id=s0,signal=off : serial on stdio; "signal=off" (the QEMU
#                                   default) disables ISIG so Ctrl-C is passed
#                                   to the VM as byte 0x03 instead of generating
#                                   SIGINT.  The kernel detects 0x03 in the
#                                   serial RX FIFO, stops the server, and calls
#                                   PSCI/ACPI power-off so QEMU exits cleanly.
#                                   ("signal=on" would send SIGINT to QEMU.)
# -serial chardev:s0            : attach serial port to the chardev above

QEMU_OUTPUT=(
    -display none
    -monitor none
    -chardev stdio,id=s0,signal=off
    -serial chardev:s0
    -no-reboot
)

# ── ARM64 (Apple Silicon) ────────────────────────────────────────────────────
if [ "$HOST_ARCH" = "arm64" ]; then
    if ! command -v qemu-system-aarch64 &>/dev/null; then
        echo "Error: qemu-system-aarch64 not found. Install with: brew install qemu"
        exit 1
    fi

    # HVF is not used on aarch64: Apple's Hypervisor.framework does not guarantee
    # ISV=1 in ESR_EL2 for device MMIO exits, so QEMU cannot decode or emulate
    # those accesses.  This affects every device the unikernel touches (GIC,
    # PCIe ECAM, virtio BARs).  TCG emulates all MMIO correctly.
    exec qemu-system-aarch64 \
        -machine virt \
        -kernel "$ELF" \
        -m "${MEMORY}" \
        -smp "${CPUS}" \
        "${QEMU_OUTPUT[@]}" \
        -device virtio-net-pci,netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp::${HOST_PORT}-:80" \
        -cpu max

# ── x86_64 (Intel Mac) ───────────────────────────────────────────────────────
else
    if ! command -v qemu-system-x86_64 &>/dev/null; then
        echo "Error: qemu-system-x86_64 not found. Install with: brew install qemu"
        exit 1
    fi

    QEMU_X86=(
        qemu-system-x86_64
        -kernel "$ELF"
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
fi
