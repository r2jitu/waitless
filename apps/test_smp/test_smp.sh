#!/usr/bin/env bash
# apps/test_smp/test_smp.sh — Boot with 4 cores, verify all come online.
#
#   bazel test --config=aarch64-qemu //apps/test_smp:test

set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${BASH_SOURCE[0]%.sh}.runfiles}"
source "${RUNFILES}/_main/scripts/helpers.sh"

trap cleanup_vm EXIT

ELF="${RUNFILES}/_main/apps/test_smp/test_smp.elf"
[[ -f "$ELF" ]] || { echo "ERROR: test_smp.elf not found at $ELF" >&2; exit 1; }

detect_qemu "$ELF"
command -v "$QEMU_BIN" &>/dev/null || { echo "SKIP: $QEMU_BIN not found"; exit 0; }

EXPECTED_CPUS=4
export UNIKERNEL_CPUS=$EXPECTED_CPUS

PORT="${TEST_PORT:-18199}"
echo "==> Booting test_smp with $EXPECTED_CPUS cores in $QEMU_BIN..."
start_qemu "$PORT" "" "${QEMU_MACHINE[@]}" -kernel "$KERNEL_ARG"

# Wait for the app to finish (it prints "SMP test complete" then shuts down)
for i in $(seq 1 30); do
    if ! kill -0 "$VM_PID" 2>/dev/null; then
        break
    fi
    sleep 0.5
done
# Kill if still running
kill "$VM_PID" 2>/dev/null || true
wait "$VM_PID" 2>/dev/null || true

echo ""
echo "==> Serial output:"
cat "$VM_LOG"
echo ""

# Check for SMP boot success
echo "==> Checking SMP boot..."
FAILURES=0

if grep -q "${EXPECTED_CPUS}/${EXPECTED_CPUS} cores online" "$VM_LOG"; then
    echo "  PASS: ${EXPECTED_CPUS}/${EXPECTED_CPUS} cores online"
else
    echo "  FAIL: expected '${EXPECTED_CPUS}/${EXPECTED_CPUS} cores online' in serial output"
    FAILURES=$((FAILURES+1))
fi

# Verify each core printed "online"
for cpu in $(seq 1 $((EXPECTED_CPUS-1))); do
    if grep -q "core ${cpu} online" "$VM_LOG"; then
        echo "  PASS: core ${cpu} online"
    else
        echo "  FAIL: core ${cpu} did not come online"
        FAILURES=$((FAILURES+1))
    fi
done

if grep -q "SMP test complete" "$VM_LOG"; then
    echo "  PASS: app reached main and shut down"
else
    echo "  FAIL: app did not reach main"
    FAILURES=$((FAILURES+1))
fi

echo ""
[[ $FAILURES -eq 0 ]] && { echo "ALL SMP TESTS PASSED"; exit 0; }
echo "$FAILURES SMP TEST(S) FAILED"; exit 1
