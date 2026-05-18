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
OUTPUT_BASE="${HOME}/.cache/bazel-rust-analyzer-$(basename "$WS")"
LOCKDIR="${OUTPUT_BASE}.discover.lock.d"

mkdir -p "$(dirname "$OUTPUT_BASE")"

# Serialize concurrent invocations. rust-analyzer fires this script
# multiple times in rapid succession (~8 in the same ms on project
# open); without a mutex they race on bazel's own output-base lock
# and bazel's "Another command holds the output base lock"
# contention message lands on stdout, breaking r-a's JSON parser.
# macOS has no `flock(1)`, so use an atomic `mkdir` spin-wait.
while ! mkdir "$LOCKDIR" 2>/dev/null; do sleep 0.05; done
trap 'rmdir "$LOCKDIR" 2>/dev/null || true' EXIT

# Ignore "$@": r-a passes a buildfile path per invocation, and
# `discover_bazel_rust_project` errors out with "Aquery returned
# an empty result" for BUILDs that have no rust targets (e.g. the
# root BUILD.bazel, any C++-only package). Full-project discovery
# with no arg is the one mode that works reliably.
#
# stderr → stdout + filter to JSON lines only: strips bazel's
# status/warning chatter and any late lock messages so only
# well-formed {"kind":"progress"|"finished"} payloads reach r-a.
#
# Two platforms in play:
#   - Outer `bazel run` builds `//:discover_rust_project`, a host
#     Rust binary (anyhow/clap/…). It can't build under a unikernel
#     target platform (`target_compatible_with = @platforms//:
#     incompatible` on those crates) — analysis would fail with
#     INCOMPATIBLE_TARGET_REQUESTED and the script would emit no
#     JSON, leaving r-a stuck waiting. So we pin the outer build to
#     the matching-arch host platform.
#   - Inner bazel calls the tool spawns (`bazel info`, aquery) are
#     what rust-project.json is generated from; their target
#     platform controls which `#[cfg(target_os = "none")]` blocks
#     rust-analyzer sees as active. We forward
#     `--bazel_arg=--platforms=...` to pin those to the unikernel
#     target platform so the bare-metal code paths light up.
#
# The inner `//...` wildcard under unikernel relies on two bazel
# rules marking their targets incompatible with `os:none`:
#   - `rust_proc_macro` in `//bazel/rules:rust.bzl` (otherwise
#     `//uni/macros` resolves to the `*-unknown-none` rust toolchain
#     and can't build a proc-macro).
#   - `unikernel_app_test` py_test variants in `//bazel/rules:variants.bzl`
#     (no default_test_toolchain is registered for bare-metal).
# Both carry a `select({os_none: [@platforms//:incompatible], ...})`
# so wildcard expansion silently skips them in the unikernel config;
# normal consumers (proc_macro_deps with cfg=exec, `bazel test` on
# the host platform) are unaffected.
case "$(uname -sm)" in
"Darwin arm64") HOST_PLATFORM="//bazel/platforms:aarch64_macos" ;;
"Linux x86_64") HOST_PLATFORM="//bazel/platforms:x86_64_linux" ;;
*)
    echo "unsupported host $(uname -sm)" >&2
    exit 1
    ;;
esac
case "$(uname -m)" in
arm64 | aarch64) TARGET_PLATFORM="//bazel/platforms:aarch64_unikernel" ;;
x86_64) TARGET_PLATFORM="//bazel/platforms:x86_64_unikernel" ;;
esac

bazel \
    "--output_base=${OUTPUT_BASE}" \
    run --ui_event_filters=-info,-stdout,-stderr --noshow_progress \
    --platforms="${HOST_PLATFORM}" \
    //:discover_rust_project \
    -- --bazel_arg=--platforms="${TARGET_PLATFORM}" \
    2>&1 | awk '/^\{/'
