#!/usr/bin/env bash
# apps/test_percpu/test_percpu.sh — Verify per-core state independence.
#
#   bazel test --config=aarch64-qemu //apps/test_percpu:test
#   bazel test --config=x86_64-qemu //apps/test_percpu:test

set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

trap cleanup_vm EXIT

ELF="${RUNFILES}/_main/apps/test_percpu/test_percpu.elf"
[[ -f "$ELF" ]] || { echo "ERROR: test_percpu.elf not found at $ELF" >&2; exit 1; }

detect_qemu "$ELF"
command -v "$QEMU_BIN" &>/dev/null || { echo "SKIP: $QEMU_BIN not found"; exit 0; }

EXPECTED_CPUS=4
export UNIKERNEL_CPUS=$EXPECTED_CPUS

PORT="${TEST_PORT:-18299}"
echo "==> Booting test_percpu with $EXPECTED_CPUS cores in $QEMU_BIN..."
# test_percpu doesn't exercise networking; give start_qemu placeholder ports.
start_qemu "$PORT" "$((PORT+1))" "$((PORT+2))" "" "${QEMU_MACHINE[@]}" -kernel "$KERNEL_ARG"

# Wait for the app to finish
for i in $(seq 1 30); do
    if ! kill -0 "$VM_PID" 2>/dev/null; then break; fi
    if grep -q "Per-core state test complete" "$VM_LOG" 2>/dev/null; then break; fi
    sleep 0.5
done
kill "$VM_PID" 2>/dev/null || true
wait "$VM_PID" 2>/dev/null || true

echo ""
echo "==> Serial output:"
cat "$VM_LOG"
echo ""

echo "==> Checking per-core state..."
FAILURES=0

# All 4 cores should come online
if grep -q "${EXPECTED_CPUS}/${EXPECTED_CPUS} cores online" "$VM_LOG"; then
    echo "  PASS: ${EXPECTED_CPUS}/${EXPECTED_CPUS} cores online"
else
    echo "  FAIL: expected '${EXPECTED_CPUS}/${EXPECTED_CPUS} cores online'"
    FAILURES=$((FAILURES+1))
fi

# Core 0 should verify its own state
if grep -q "Core 0: inbox OK" "$VM_LOG"; then
    echo "  PASS: core 0 per-core state"
else
    echo "  FAIL: core 0 per-core state"
    FAILURES=$((FAILURES+1))
fi

# Each AP should verify its own state
for cpu in $(seq 1 $((EXPECTED_CPUS-1))); do
    if grep -q "Core ${cpu}: inbox OK" "$VM_LOG"; then
        echo "  PASS: core ${cpu} per-core state"
    else
        echo "  FAIL: core ${cpu} per-core state not verified"
        FAILURES=$((FAILURES+1))
    fi
done

# Core 0 should verify TX staging from all APs
if grep -q "verified TX staging from all APs" "$VM_LOG"; then
    echo "  PASS: cross-core TX staging verified"
else
    echo "  FAIL: TX staging verification"
    FAILURES=$((FAILURES+1))
fi

# App should complete
if grep -q "Per-core state test complete" "$VM_LOG"; then
    echo "  PASS: test completed"
else
    echo "  FAIL: test did not complete"
    FAILURES=$((FAILURES+1))
fi

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL PER-CORE STATE TESTS PASSED"; exit 0; }
echo "$FAILURES PER-CORE STATE TEST(S) FAILED"; exit 1
