#!/usr/bin/env bash
# apps/test_tls/test_tls.sh — Boot the TLS primitives test app, verify PASS.
#
# Drives //net:tls_crypto + //net:tls through a full-stack smoke test
# (AEAD roundtrip + tamper, X25519, HKDF-Expand-Label, key schedule
# cascade, traffic-key record roundtrip) inside a real unikernel boot,
# not a host unit test. Passes if the serial log contains
# "TLS TESTS: ALL PASSED" and no "FAIL".

set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"

HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

VM_LOG="$(mktemp /tmp/unikernel_tls_test_XXXXXX.log)"
cleanup() {
    if [[ -n "${VM_PID:-}" ]] && kill -0 "$VM_PID" 2>/dev/null; then
        kill "$VM_PID" 2>/dev/null || true
        wait "$VM_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

if [[ "$HOST_OS" = "Darwin" ]] && [[ "$HOST_ARCH" = "arm64" ]]; then
    # HVF runner path (macOS arm64).
    IMG="${RUNFILES}/_main/apps/test_tls/test_tls.img"
    HVF="${RUNFILES}/_main/tools/hvf-runner/run-hvf"
    [[ -f "$IMG" ]] || { echo "ERROR: test_tls.img not found at $IMG" >&2; exit 1; }
    [[ -x "$HVF" ]] || { echo "ERROR: run-hvf not found at $HVF" >&2; exit 1; }

    echo "==> Booting test_tls via HVF runner..."
    "$HVF" "$IMG" --ram=128 --cpus=1 > "$VM_LOG" 2>&1 &
    VM_PID=$!
else
    # QEMU path — only in --config=aarch64-qemu / x86_64-qemu test
    # invocations.
    source "${RUNFILES}/_main/scripts/helpers.sh"
    trap cleanup_vm EXIT
    ELF="${RUNFILES}/_main/apps/test_tls/test_tls.elf"
    [[ -f "$ELF" ]] || { echo "ERROR: test_tls.elf not found at $ELF" >&2; exit 1; }
    detect_qemu "$ELF"
    command -v "$QEMU_BIN" &>/dev/null || { echo "SKIP: $QEMU_BIN not found"; exit 0; }

    PORT="${TEST_PORT:-18299}"
    echo "==> Booting test_tls in $QEMU_BIN..."
    # test_tls runs its crypto checks over serial; the network forwards are unused.
    start_qemu "$PORT" "$((PORT+1))" "$((PORT+2))" "" "${QEMU_MACHINE[@]}" -kernel "$KERNEL_ARG"
fi

# Wait up to 20 s for "TLS TESTS:" line (either PASS or FAIL).
for i in $(seq 1 40); do
    if grep -q "TLS TESTS:" "$VM_LOG" 2>/dev/null; then
        break
    fi
    sleep 0.5
done

# Kill the VM if still running.
if [[ -n "${VM_PID:-}" ]] && kill -0 "$VM_PID" 2>/dev/null; then
    kill "$VM_PID" 2>/dev/null || true
    wait "$VM_PID" 2>/dev/null || true
fi

echo ""
echo "==> Serial output:"
cat "$VM_LOG"
echo ""

FAILURES=0
if grep -q "TLS TESTS: ALL PASSED" "$VM_LOG"; then
    echo "PASS: all TLS primitive tests passed"
else
    echo "FAIL: TLS primitive tests did not all pass"
    FAILURES=$((FAILURES+1))
fi

if grep -q "\[tls\] FAIL" "$VM_LOG"; then
    echo "FAIL: at least one TLS subtest reported failure"
    FAILURES=$((FAILURES+1))
fi

[[ $FAILURES -eq 0 ]] && exit 0
exit 1
