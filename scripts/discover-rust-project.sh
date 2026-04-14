#!/usr/bin/env bash
# scripts/discover-rust-project.sh — rust-analyzer discoverConfig hook.
#
# rust-analyzer (in VS Code, JetBrains, etc.) calls this script with
# its `discoverConfig` machinery whenever it needs fresh Bazel project
# metadata: the script invokes the rules_rust `discover_bazel_rust_project`
# tool and the JSON output is read directly by the IDE — no
# `rust-project.json` written to the source tree, no manual regeneration
# step.
#
# Invocation contract is defined by rust-analyzer:
#   https://rust-analyzer.github.io/manual.html#discover-config
#
# Why a separate `--output_base`:
#   The IDE bazel invocations use a different output_base from the
#   CLI builds. This stops them fighting for the build lock on the
#   default output_base whenever the IDE happens to recompute project
#   metadata while the user is also running a bazel command from the
#   shell. Bazel's content-addressed download cache is shared, so the
#   only extra disk cost is the action graph + execroot for the
#   rust-analyzer-specific actions.

set -euo pipefail

WS="${BUILD_WORKSPACE_DIRECTORY:-$(cd "$(dirname "$0")/.." && pwd)}"

exec bazel \
    "--output_base=${HOME}/.cache/bazel-rust-analyzer-$(basename "$WS")" \
    run --ui_event_filters=-info,-stdout,-stderr --noshow_progress \
    //:discover_rust_project -- "$@"
