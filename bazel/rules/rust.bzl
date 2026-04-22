"""Shared Rust build configuration for unikernel crates.

Common rustc_flags (panic=abort, opt-level=2) are set globally in .bazelrc
via --@rules_rust//:extra_rustc_flags. This file provides the per-target
symbolic flag lists.
"""

load("@rules_rust//rust:defs.bzl", _rust_proc_macro = "rust_proc_macro", _rust_test = "rust_test")

# ARM64 unikernel targets need PIC for position-independent ELF
# (boot.S applies relocations at runtime). x86_64 and native don't.
UNIKERNEL_RUSTC_FLAGS = select({
    "//bazel/platforms:aarch64": ["-C", "relocation-model=pic"],
    "//conditions:default": [],
})

# `bazel build ...` would otherwise try to compile every rust_test
# under the global `-Cpanic=abort`, which rustc rejects for test
# binaries ("building tests with panic=abort is not supported without
# `-Zpanic_abort_tests`"). Only the `test` verb flips
# `//bazel/rules:tests_need_std=True` (and adds `-Cpanic=unwind`), so
# gate rust_test compatibility on that flag — wildcard builds skip
# these targets, `bazel test ...` still picks them up.
def rust_test(**kwargs):
    if "target_compatible_with" in kwargs:
        fail("rust_test: unikernel wrapper owns target_compatible_with")
    kwargs["target_compatible_with"] = select({
        "//bazel/rules:tests_need_std_on": [],
        "//conditions:default": ["@platforms//:incompatible"],
    })
    _rust_test(**kwargs)

# Proc-macros are dylibs loaded into rustc, so a panic in the macro
# unwinds into the compiler. rustc warns ("building proc macro crate
# with `panic=abort` may crash the compiler...") on every proc-macro
# target under the global `-Cpanic=abort`. Pin `-Cpanic=unwind` via
# the target's own `rustc_flags` — those are appended AFTER
# `extra_rustc_flags`, so the unwind flag is last-wins.
def rust_proc_macro(rustc_flags = [], **kwargs):
    _rust_proc_macro(rustc_flags = rustc_flags + ["-Cpanic=unwind"], **kwargs)

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
#   * Integration tests are per-variant (`:test_hvf`, `:test_iso`,
#     `:test_qemu_<arch>`) and depend on the matching unikernel
#     variant target. The variant rule in
#     `//bazel/rules:variants.bzl` applies a Bazel transition that
#     re-asserts `-Cpanic=abort` on the unikernel sub-graph, so the
#     test-verb unwind override never reaches the no_std rlibs.
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
#     std + unwind for the duration of the test build. Variant
#     transitions re-enter the production sub-graph with the flag
#     reset to False.
