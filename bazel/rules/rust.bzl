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

# Panic strategy is handled in `.bazelrc`:
#
#   * Global: `-Cpanic=abort` — every rlib in this repo is
#     `#![cfg_attr(not(test), no_std)]` (or bare `#![no_std]`), and
#     rustc rejects `panic=unwind` on a no_std crate.
#
#   * `test` verb appends `-Cpanic=unwind` so rust_test targets
#     get the unwinding libtest harness. Test source files flip
#     to std under `--test` cfg via `cfg_attr(not(test), no_std)`,
#     so the unwind strategy is legal there.
#
#   * Integration tests tagged `integration` are filtered out of
#     the default `bazel test` set. Users run them with
#     `--config=hvf` / `=iso` / `=qemu`, which re-assert
#     `-Cpanic=abort` so the unikernel binary rebuilds cleanly.
#
#   * The one residual awkwardness: a `rust_test` that
#     `crate = ":foo"` (or that `srcs =` foo's source directly)
#     pulls `:foo`'s dep rlibs. Those deps don't get `--test`, so
#     their `#![cfg_attr(not(test), no_std)]` stays active and
#     rustc refuses panic=unwind on no_std. Fix: the
#     `//bazel/rules:tests_need_std` bool_flag flips to True under
#     the `test` verb, and affected crates (currently just
#     `//util/atomic_fn`) `select()` on the matching config_setting
#     to inject `crate_features = ["std"]`, flipping themselves to
#     std + unwind for the duration of the test build. Transitions
#     (e.g. `integration_data`) that re-enter the production sub-
#     graph reset the flag to False.
