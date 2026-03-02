#!/usr/bin/env bash
# bazel/rules/run_wrapper.sh — launcher for "bazel run //apps/<name>:run"
#
# Bazel 6+ sets BUILD_WORKSPACE_DIRECTORY to the workspace root when a target
# is run via "bazel run".  We use that to locate the pre-built ELF (which
# Bazel guaranteed to have built before running this script) and hand off to
# the QEMU launcher in scripts/run-local.sh.
#
# The env var UNIKERNEL_ELF_RELPATH is set by the sh_binary() rule in
# unikernel.bzl to the workspace-relative path of the ELF, e.g.
#   apps/webserver/webserver.elf
#
# Usage:
#   bazel run //apps/webserver:run              # x86_64
#   bazel run --config=aarch64 //apps/webserver:run  # aarch64

set -euo pipefail

if [[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then
    echo "error: this script must be invoked via 'bazel run', not directly." >&2
    exit 1
fi

WORKSPACE="$BUILD_WORKSPACE_DIRECTORY"
ELF="${WORKSPACE}/bazel-bin/${UNIKERNEL_ELF_RELPATH}"

if [[ ! -f "$ELF" ]]; then
    echo "error: ELF not found: $ELF" >&2
    echo "       Run 'bazel build ${UNIKERNEL_ELF_RELPATH}' first." >&2
    exit 1
fi

exec "${WORKSPACE}/scripts/run-local.sh" "$ELF"
