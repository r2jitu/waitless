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
# Why we can't move this to `.bazelrc`:
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
#   * `#![cfg_attr(not(test), no_std)]` lets an individual crate
#     flip to std when built as its own test, but when a rust_test
#     on crate A links rlib B built as no_std + panic=abort, the
#     linker still rejects the combination. Workaround: inline
#     cfg(test) shim of the dep's type (see `net/protocol.rs`).
#
# Every OSS Bazel/rust_no_std project lands on the same per-target
# flag pattern. Landing a custom Bazel transition to rebuild test
# deps with panic=unwind is possible but substantial Starlark work
# and outside the scope of the init-redesign plan. Revisit if/when
# the shim count grows beyond a single site.
HOST_TEST_RUSTC_FLAGS = ["-Cpanic=unwind"]
