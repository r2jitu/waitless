#!/usr/bin/env bash
# scripts/helpers.sh — QEMU launch helpers for the interactive `bazel run`
# path (bazel/rules/run_qemu.sh + run_iso.sh). Source this file; do not
# execute it directly:
#
#   source "$ROOT/scripts/helpers.sh"    (from a launcher script)
#
# Integration tests are Python now (apps/*/test.py) and use
# scripts/test_helpers.py. This file has no test-side responsibilities
# left — just the two functions needed to launch QEMU interactively.

# ── QEMU configuration ──────────────────────────────────────────────────────
# Detect QEMU binary, machine args, and virtio device type from an ELF.
#
# Usage: detect_qemu "$ELF" "$IMG"
# Sets:  QEMU_BIN  QEMU_MACHINE  VIRTIO_DEV  KERNEL_ARG
#
# Caller supplies both the ELF and the corresponding raw binary
# (.img). aarch64 QEMU loads the .img, x86_64 QEMU loads the .elf;
# the detector only decides between the two. The old behaviour
# derived .img from the .elf path by suffix substitution, which
# coupled the layout to the runner script's sibling-file convention
# — giving callers explicit control removes that coupling.
detect_qemu() {
    local elf="$1"
    local img="$2"
    local info
    info="$(file "$elf" 2>/dev/null || echo "")"

    if echo "$info" | grep -q "ARM aarch64"; then
        QEMU_BIN="qemu-system-aarch64"
        QEMU_MACHINE=(-machine virt -cpu max)
        VIRTIO_DEV="virtio-net-device"
        KERNEL_ARG="$img"
        [[ -f "$KERNEL_ARG" ]] || {
            echo "error: .img not found: $KERNEL_ARG" >&2
            return 1
        }
    else
        QEMU_BIN="qemu-system-x86_64"
        VIRTIO_DEV="virtio-net-pci"
        KERNEL_ARG="$elf"
        # Machine type: q35 (PCIe + ACPI MCFG) instead of QEMU's
        # legacy i440fx default. MCFG is what the kernel walks at
        # `pci::init` time to discover the ECAM base — without it
        # x86 falls back to 0xCF8/0xCFC port-I/O config space, which
        # is 2 vmexits per dword instead of 1 MMIO touch.
        #
        # CPU model choice:
        #
        #   - Accelerated (KVM/HVF):  -cpu host  pass-through so the
        #     guest sees the real host's feature set. On any modern
        #     GCP / Apple Silicon x86 host that includes AVX/AVX2,
        #     which our p256 + chacha20poly1305 builds rely on.
        #
        #   - TCG emulation:  -cpu max  enables every feature TCG
        #     can simulate, including AVX. `-cpu qemu64` (the QEMU
        #     default) is pre-AVX and makes the compiled crypto
        #     crates crash with #UD the first time they emit a
        #     VMOVDQU — we learned this the hard way when TLS init
        #     started doing a d*G scalar mult at boot time.
        #
        # HVF on Apple Silicon arm64 never accelerates x86 guests,
        # so that branch only ever activates on an x86_64 macOS host
        # (which in practice doesn't exist anymore — every current
        # Mac is aarch64).
        if [[ "$(uname -m)" = "x86_64" ]]; then
            if [[ "$(uname -s)" = "Darwin" ]] && sysctl -n kern.hv_support 2>/dev/null | grep -q '^1$'; then
                QEMU_MACHINE=(-machine q35 -cpu host -accel hvf)
            elif [[ "$(uname -s)" = "Linux" ]] && [[ -r /dev/kvm ]]; then
                QEMU_MACHINE=(-machine q35 -cpu host -accel kvm)
            else
                QEMU_MACHINE=(-machine q35 -cpu max)
            fi
        else
            QEMU_MACHINE=(-machine q35 -cpu max)
        fi
    fi
}

# ── Shared QEMU arg builder ──────────────────────────────────────────────────
#
# Exec QEMU interactively (for `bazel run //path:name`).
#
# Usage: run_qemu MEMORY CPUS HOSTFWD [EXTRA_QEMU_ARGS...]
#   HOSTFWD is a comma-joined list of QEMU `hostfwd=…` forwards,
#   e.g. `hostfwd=tcp::8080-:80,hostfwd=udp::8007-:7`. Built by the
#   per-variant launcher template from each app's `port_forwards`
#   attr on `unikernel_binary`. Empty string = no port forwarding.
# Prereq: QEMU_BIN and VIRTIO_DEV must be set (via detect_qemu).
run_qemu() {
    local memory="$1" cpus="$2" hostfwd="$3"
    shift 3

    local dev_extra=""
    local netdev_extra=""
    # VirtIO multi-queue is PCI-only (MMIO's `virtio-net-device`
    # doesn't support the `mq=on,vectors=…,queues=…` trio) AND
    # requires at least one hostfwd — QEMU's user-mode netdev
    # rejects `queues=N` when there are no port forwards to spray
    # across the queues ("Invalid parameter 'queues'"). Apps with
    # `port_forwards = []` (e.g. the headless SMP tests) get a
    # single-queue netdev even when booting multi-core.
    if [[ "$cpus" -gt 1 ]] && [[ "$VIRTIO_DEV" == *"-pci"* ]] && [[ -n "$hostfwd" ]]; then
        local vectors=$((2 * cpus + 2))
        dev_extra=",mq=on,vectors=$vectors,queues=$cpus"
        netdev_extra=",queues=$cpus"
    fi

    local netdev="user,id=net0"
    if [[ -n "$hostfwd" ]]; then
        netdev+=",${hostfwd}"
    fi
    netdev+="${netdev_extra}"

    exec "$QEMU_BIN" \
        "$@" \
        -m "$memory" -smp "$cpus" \
        -display none -monitor none \
        -chardev stdio,id=s0,signal=off -serial chardev:s0 \
        -no-reboot \
        -device "${VIRTIO_DEV}${dev_extra},netdev=net0" \
        -netdev "$netdev"
}
