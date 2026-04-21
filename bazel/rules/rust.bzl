"""Shared Rust build configuration for unikernel crates.

Common rustc_flags (panic=abort, opt-level=2) are set globally in .bazelrc
via --@rules_rust//:extra_rustc_flags. This file provides the per-target
symbolic flag lists.
"""

# ARM64 unikernel targets need PIC for position-independent ELF
# (boot.S applies relocations at runtime). x86_64 and native don't.
UNIKERNEL_RUSTC_FLAGS = select({
    "//bazel/platforms:aarch64": ["-C", "relocation-model=pic"],
    "//conditions:default": [],
})

# Host-native `rust_test` targets need `-Cpanic=unwind` so the libtest
# harness can catch assertion panics. Every rust_test in the repo
# sets this via `rustc_flags = HOST_TEST_RUSTC_FLAGS`.
#
# Why it can't move to `.bazelrc`:
#
#   * A global `build --extra_rustc_flag=-Cpanic=unwind` would apply
#     to every crate, including our `#![no_std]` libraries. Rustc
#     rejects the combination ("unwinding panics are not supported
#     without std") and the bare-metal build fails.
#
#   * A `test --extra_rustc_flag=-Cpanic=unwind` override applies
#     to every rustc invocation that `bazel test` triggers, which
#     includes the unikernel binaries pulled in as `data` by
#     integration tests (e.g. `//apps/webserver:test` → `:webserver`
#     unikernel ELF). Same no_std breakage.
#
#   * rules_rust doesn't ship a per-target transition that would
#     rebuild only a `rust_test`'s own rustc invocation with unwind
#     (Cargo auto-does this — see the Cargo book's profiles page
#     under "Test profile" — but Bazel's equivalent is not there).
#
# For the dep-chain variant of this problem — a `rust_test` with
# `crate = ":foo"` rebuilding `foo` with panic=unwind but linking
# against a library dep compiled panic=abort — the pattern is to
# declare a sibling `rust_library` of the dep with the same
# `crate_name` but `rustc_flags = HOST_TEST_RUSTC_FLAGS`. See
# `//util:atomic_fn` / `:atomic_fn_unwind` and the `//net:protocol_test`
# that depends on the unwind variant. Multi-target-per-source is
# ugly but contained — we'd need a full Bazel transition to drop
# it, which is substantial Starlark outside the init-redesign
# plan's scope.
HOST_TEST_RUSTC_FLAGS = ["-Cpanic=unwind"]
