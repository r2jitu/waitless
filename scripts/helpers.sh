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
        [[ -f "$KERNEL_ARG" ]] || { echo "error: .img not found: $KERNEL_ARG" >&2; return 1; }
    else
        QEMU_BIN="qemu-system-x86_64"
        VIRTIO_DEV="virtio-net-pci"
        KERNEL_ARG="$elf"
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
                QEMU_MACHINE=(-cpu host -accel hvf)
            elif [[ "$(uname -s)" = "Linux" ]] && [[ -r /dev/kvm ]]; then
                QEMU_MACHINE=(-cpu host -accel kvm)
            else
                QEMU_MACHINE=(-cpu max)
            fi
        else
            QEMU_MACHINE=(-cpu max)
        fi
    fi
}

# ── Shared QEMU arg builder ──────────────────────────────────────────────────
# Canonical port-forward layout: three independent ports so user-facing
# defaults stay conventional (80 / 443 / 7):
#
#   host:HTTP_PORT  -> guest :80   (plain HTTP)
#   host:TLS_PORT   -> guest :443  (HTTPS)
#   host:UDP_PORT   -> guest :7    (UDP echo)
#
# `_qemu_net_args HTTP_PORT TLS_PORT UDP_PORT CPUS` prints the
# `-device … -netdev …` pair.
_qemu_net_args() {
    local http_port="$1" tls_port="$2" udp_port="$3" cpus="$4"
    local dev_extra=""
    # Enable VirtIO multi-queue for PCI devices with multiple vCPUs.
    # MMIO devices (virtio-net-device) don't support mq parameter.
    if [[ "$cpus" -gt 1 ]] && [[ "$VIRTIO_DEV" == *"-pci"* ]]; then
        local vectors=$(( 2 * cpus + 2 ))
        dev_extra=",mq=on,vectors=$vectors,queues=$cpus"
    fi
    local netdev_extra=""
    # user-mode netdev supports queues= only alongside PCI multi-queue.
    if [[ "$cpus" -gt 1 ]] && [[ "$VIRTIO_DEV" == *"-pci"* ]]; then
        netdev_extra=",queues=$cpus"
    fi
    local forwards="hostfwd=tcp::${http_port}-:80"
    forwards+=",hostfwd=tcp::${tls_port}-:443"
    forwards+=",hostfwd=udp::${udp_port}-:7"
    printf '%s\n' \
        "-device" "${VIRTIO_DEV}${dev_extra},netdev=net0" \
        "-netdev" "user,id=net0,${forwards}${netdev_extra}"
}

# Exec QEMU interactively (for `bazel run //path:name`).
#
# Usage: run_qemu HTTP_PORT TLS_PORT UDP_PORT MEMORY [EXTRA_QEMU_ARGS...]
# Prereq: QEMU_BIN and VIRTIO_DEV must be set (via detect_qemu or manually).
run_qemu() {
    local http_port="$1" tls_port="$2" udp_port="$3" memory="$4"
    shift 4
    local cpus="${UNIKERNEL_CPUS:-1}"
    local net_args=()
    while IFS= read -r line; do net_args+=("$line"); done \
        < <(_qemu_net_args "$http_port" "$tls_port" "$udp_port" "$cpus")
    exec "$QEMU_BIN" \
        "$@" \
        -m "$memory" -smp "$cpus" \
        -display none -monitor none \
        -chardev stdio,id=s0,signal=off -serial chardev:s0 \
        -no-reboot \
        "${net_args[@]}"
}
