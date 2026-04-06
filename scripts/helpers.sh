#!/usr/bin/env bash
# scripts/helpers.sh — Shared helpers for run, test, and bench scripts.
#
# Source this file; do not execute it directly.
#   source "$(dirname "$0")/helpers.sh"                     (from scripts/)
#   source "$BUILD_WORKSPACE_DIRECTORY/scripts/helpers.sh"  (from bazel run)
#   source "${RUNFILES}/_main/scripts/helpers.sh"           (from bazel test)

# ── QEMU configuration ──────────────────────────────────────────────────────
# Detect QEMU binary, machine args, and virtio device type from an ELF.
#
# Usage: detect_qemu "$ELF"
# Sets:  QEMU_BIN  QEMU_MACHINE  VIRTIO_DEV  KERNEL_ARG
detect_qemu() {
    local elf="$1"
    local info
    info="$(file "$elf" 2>/dev/null || echo "")"

    if echo "$info" | grep -q "ARM aarch64"; then
        QEMU_BIN="qemu-system-aarch64"
        QEMU_MACHINE=(-machine virt -cpu max)
        VIRTIO_DEV="virtio-net-device"
        # aarch64 QEMU needs raw .img, not ELF
        KERNEL_ARG="${elf%.elf}.img"
        [[ -f "$KERNEL_ARG" ]] || { echo "error: .img not found: $KERNEL_ARG" >&2; return 1; }
    else
        QEMU_BIN="qemu-system-x86_64"
        QEMU_MACHINE=(-cpu qemu64)
        VIRTIO_DEV="virtio-net-pci"
        KERNEL_ARG="$elf"
        # HVF/KVM only when host arch matches guest
        if [[ "$(uname -m)" = "x86_64" ]]; then
            if [[ "$(uname -s)" = "Darwin" ]] && sysctl -n kern.hv_support 2>/dev/null | grep -q '^1$'; then
                QEMU_MACHINE+=(-accel hvf)
            elif [[ "$(uname -s)" = "Linux" ]] && [[ -r /dev/kvm ]]; then
                QEMU_MACHINE+=(-accel kvm)
            fi
        fi
    fi
}

# ── VM lifecycle ─────────────────────────────────────────────────────────────
# Kill background VM and remove log file.
# Usage: trap cleanup_vm EXIT
cleanup_vm() {
    if [[ -n "${VM_PID:-}" ]] && kill -0 "$VM_PID" 2>/dev/null; then
        kill "$VM_PID" 2>/dev/null || true
        wait "$VM_PID" 2>/dev/null || true
    fi
    [[ -n "${VM_LOG:-}" ]] && rm -f "$VM_LOG" || true
}

# Start QEMU in background.
# Usage: start_qemu PORT [LOG] [EXTRA_QEMU_ARGS...]
#   LOG: log file path; omit or pass "" to create a tempfile (sets VM_LOG).
# Prereq: QEMU_BIN and VIRTIO_DEV must be set (via detect_qemu or manually).
# Sets: VM_PID; sets VM_LOG if LOG is empty.
start_qemu() {
    local port="$1" log="${2:-}"; shift 2
    if [[ -z "$log" ]]; then
        VM_LOG="$(mktemp /tmp/unikernel_test_XXXXXXXX)"
        log="$VM_LOG"
    fi
    local cpus="${UNIKERNEL_CPUS:-1}"
    local accel_args=""
    # Use multi-threaded TCG when running multiple vCPUs so each gets its own host thread.
    if [[ "$cpus" -gt 1 ]]; then
        accel_args="-accel tcg,thread=multi"
    fi
    "$QEMU_BIN" \
        "$@" \
        ${accel_args} \
        -m 128 -smp "$cpus" -nographic \
        -serial "file:${log}" \
        -no-reboot \
        -device "${VIRTIO_DEV}",netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp::${port}-:80,hostfwd=udp::$((port+1))-:7" \
        &>/dev/null &
    VM_PID=$!
}

# Exec QEMU interactively (for `bazel run` targets).
# Usage: run_qemu PORT MEMORY [EXTRA_QEMU_ARGS...]
# Prereq: QEMU_BIN and VIRTIO_DEV must be set (via detect_qemu or manually).
run_qemu() {
    local port="$1" memory="$2"; shift 2
    exec "$QEMU_BIN" \
        "$@" \
        -m "$memory" -smp 1 \
        -display none -monitor none \
        -chardev stdio,id=s0,signal=off -serial chardev:s0 \
        -no-reboot \
        -device "${VIRTIO_DEV}",netdev=net0 \
        -netdev "user,id=net0,hostfwd=tcp::${port}-:80"
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────
# Wait for an HTTP endpoint to respond.
# Usage: wait_http PORT [TIMEOUT] [PID] [HOST] [ENDPOINT]
wait_http() {
    local port=$1 timeout=${2:-60} pid=${3:-""} host=${4:-"127.0.0.1"} endpoint=${5:-"/"}
    local elapsed=0
    while ! curl -sf --max-time 3 "http://${host}:${port}${endpoint}" >/dev/null 2>&1; do
        if [[ $elapsed -ge $timeout ]]; then return 1; fi
        if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then return 1; fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 0
}

# Test an HTTP endpoint.  Returns 0 on pass, 1 on fail.
# Usage: check_http DESC URL WANT_STATUS [WANT_BODY]
check_http() {
    local desc="$1" url="$2" want_status="$3" want_body="${4:-}"
    local resp body status ok=1
    resp="$(curl -s -w $'\n%{http_code}' --max-time 5 "$url" 2>&1 || true)"
    body="$(echo "$resp" | sed '$d')"
    status="$(echo "$resp" | tail -n1)"
    [[ "$status" == "$want_status" ]] || ok=0
    [[ -z "$want_body" ]] || echo "$body" | grep -q "$want_body" || ok=0
    if [[ $ok -eq 1 ]]; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc (status=$status)"
        return 1
    fi
}
