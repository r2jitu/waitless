#!/usr/bin/env bash
# check-configs.sh — Assert every --config= mode still analyzes cleanly.
#
# Runs `bazel build --nobuild` (load + analyze, no action execution) for
# the four runners we ship against both //apps/webserver:run and
# //apps/webserver:test. Catches regressions in unikernel.bzl's runner
# select(), genrule exec-cfg wiring (see tools/hvf-runner/BUILD.bazel
# commit 53f3fd7), and platform_compatible_with constraint drift — none
# of which are caught by a normal `bazel build` on the default config.
#
# Usage:
#   scripts/check-configs.sh              # all configs
#   scripts/check-configs.sh hvf qemu     # subset
#
# Exit codes:
#   0  all requested configs analyzed successfully
#   1  at least one config failed (details printed to stderr)
#
# Host-gated configs:
#   hvf  — requires macOS arm64 (skipped elsewhere, not a failure)
#
# This is an analysis-only check (~1s per config cold, ms warm), so it's
# fast enough to run locally before pushing and cheap enough for CI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

ALL_CONFIGS=(hvf qemu iso native)
CONFIGS=("${@:-${ALL_CONFIGS[@]}}")

TARGETS=(
    //apps/webserver:run
    //apps/webserver:test
)

HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

# Returns 0 if the given config can be analyzed on this host, 1 if it
# must be skipped. Only hvf is host-gated today (macOS arm64 only).
host_supports() {
    case "$1" in
        hvf)
            [[ "$HOST_OS" == "Darwin" && "$HOST_ARCH" == "arm64" ]]
            ;;
        *)
            return 0
            ;;
    esac
}

FAIL=0
SKIP=0
PASS=0

for cfg in "${CONFIGS[@]}"; do
    if ! host_supports "$cfg"; then
        printf "%-8s SKIP (not supported on %s %s)\n" "$cfg" "$HOST_OS" "$HOST_ARCH"
        SKIP=$((SKIP + 1))
        continue
    fi

    printf "%-8s " "$cfg"
    log="$(mktemp -t check-configs-XXXXXXXX)"
    if bazel build --nobuild --config="$cfg" "${TARGETS[@]}" >"$log" 2>&1; then
        printf "PASS\n"
        PASS=$((PASS + 1))
        rm -f "$log"
    else
        printf "FAIL\n"
        sed 's/^/    /' "$log" >&2
        FAIL=$((FAIL + 1))
        rm -f "$log"
    fi
done

echo
printf "=== %d passed, %d failed, %d skipped ===\n" "$PASS" "$FAIL" "$SKIP"
[[ $FAIL -eq 0 ]]
