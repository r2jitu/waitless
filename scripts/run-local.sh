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
#   • Apple Silicon (arm64) → qemu-system-aarch64 with HVF acceleration
#   • Intel Mac  (x86_64)  → qemu-system-x86_64  with HVF or software
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
echo "    Serial console below.  Press Ctrl-A X to exit."
echo ""

# ── ARM64 (Apple Silicon) ────────────────────────────────────────────────────
if [ "$HOST_ARCH" = "arm64" ]; then
    if ! command -v qemu-system-aarch64 &>/dev/null; then
        echo "Error: qemu-system-aarch64 not found. Install with: brew install qemu"
        exit 1
    fi

    QEMU_NET=(
        -device virtio-net-pci,netdev=net0
        -netdev "user,id=net0,hostfwd=tcp::${HOST_PORT}-:80"
    )
    QEMU_BASE=(
        qemu-system-aarch64
        -machine virt
        -kernel "$ELF"
        -m "${MEMORY}"
        -smp "${CPUS}"
        -nographic
        -serial mon:stdio
        -no-reboot
        "${QEMU_NET[@]}"
    )

    # Use HVF (native hypervisor) if available, otherwise fall back to software TCG.
    # We detect HVF via sysctl rather than using "exec hvf || exec tcg" — the
    # latter is broken because exec replaces the shell process, so if QEMU fails
    # at HVF runtime the fallback is unreachable.
    if sysctl -n kern.hv_support 2>/dev/null | grep -q '^1$'; then
        exec "${QEMU_BASE[@]}" -cpu host -accel hvf
    else
        exec "${QEMU_BASE[@]}" -cpu cortex-a57
    fi

# ── x86_64 (Intel Mac) ───────────────────────────────────────────────────────
else
    if ! command -v qemu-system-x86_64 &>/dev/null; then
        echo "Error: qemu-system-x86_64 not found. Install with: brew install qemu"
        exit 1
    fi

    QEMU_COMMON=(
        qemu-system-x86_64
        -kernel "$ELF"
        -m "${MEMORY}"
        -smp "${CPUS}"
        -cpu qemu64
        -nographic
        -serial mon:stdio
        -no-reboot
        -device virtio-net-pci,netdev=net0
        -netdev "user,id=net0,hostfwd=tcp::${HOST_PORT}-:80"
    )

    if sysctl -n kern.hv_support 2>/dev/null | grep -q '^1$'; then
        exec "${QEMU_COMMON[@]}" -accel hvf
    else
        exec "${QEMU_COMMON[@]}"
    fi
fi
