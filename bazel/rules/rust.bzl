"""Shared Rust build configuration for unikernel crates.

Common rustc_flags (panic=abort, opt-level=2) are set globally in .bazelrc
via --@rules_rust//:extra_rustc_flags. `-Cpanic=abort` and aarch64 PIC
are threaded through unikernel binaries via Bazel transitions in
`//bazel/rules:{unikernel,variants}.bzl` — see those files.
"""

load(
    "@rules_rust//rust:defs.bzl",
    _rust_doc_test = "rust_doc_test",
    _rust_proc_macro = "rust_proc_macro",
    _rust_test = "rust_test",
)

# Labels used as `select()` keys / `target_compatible_with` values from
# inside these wrapper macros must be `Label()` objects, not bare `//…`
# strings: a bare string resolves against the BUILD file calling the
# wrapper (an external app's repo), not `@waitless`. `Label()` evaluated
# here binds to this `.bzl` file's repo and stays fixed regardless of
# caller. (`//conditions:default` is a pseudo-label — left as a string.)
_TESTS_NEED_STD_ON = Label("//bazel/rules:tests_need_std_on")
_OS_NONE = Label("//bazel/platforms:os_none")
_INCOMPATIBLE = Label("@platforms//:incompatible")

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
        _TESTS_NEED_STD_ON: [],
        "//conditions:default": [_INCOMPATIBLE],
    })
    _rust_test(**kwargs)

# `rust_doc_test` compiles (and runs) the crate's `///` doc examples,
# including `compile_fail` blocks — the only way to assert "this must
# not compile" without a `trybuild`-style dep. Doc-test binaries are
# `std` + libtest, so they hit the same `-Cpanic=abort` rejection as
# `rust_test`; gate them on the same `tests_need_std` flag.
def rust_doc_test(**kwargs):
    if "target_compatible_with" in kwargs:
        fail("rust_doc_test: unikernel wrapper owns target_compatible_with")
    kwargs["target_compatible_with"] = select({
        _TESTS_NEED_STD_ON: [],
        "//conditions:default": [_INCOMPATIBLE],
    })
    _rust_doc_test(**kwargs)

# Proc-macros are dylibs loaded into rustc, so a panic in the macro
# unwinds into the compiler. rustc warns ("building proc macro crate
# with `panic=abort` may crash the compiler...") on every proc-macro
# target under the global `-Cpanic=abort`. Pin `-Cpanic=unwind` via
# the target's own `rustc_flags` — those are appended AFTER
# `extra_rustc_flags`, so the unwind flag is last-wins.
#
# `target_compatible_with` gates direct enumeration under a unikernel
# target platform (`os:none`): the registered rust toolchain there
# targets `*-unknown-none`, which can't build proc-macros (`warning:
# dropping unsupported crate type proc-macro` → `can't find crate for
# std`). Normal consumers reach proc-macros through `proc_macro_deps`,
# whose cfg="exec" transition switches back to the host platform
# before toolchain resolution, so THAT path still builds fine. The
# incompat marker only suppresses wildcard expansion (`bazel build
# //...`) from trying to compile the proc-macro in the top-level
# unikernel config — which is what the rust-analyzer discover aspect
# does under `--platforms=*_unikernel`.
def rust_proc_macro(rustc_flags = [], target_compatible_with = [], **kwargs):
    _rust_proc_macro(
        rustc_flags = rustc_flags + ["-Cpanic=unwind"],
        target_compatible_with = target_compatible_with + select({
            _OS_NONE: [_INCOMPATIBLE],
            "//conditions:default": [],
        }),
        **kwargs
    )

# Panic strategy is handled in `.bazelrc`:
#
#   * Global: `-Cpanic=abort` — the production target is a
#     unikernel with no unwinding runtime.
#
#   * `test` verb appends `-Cpanic=unwind` so rust_test targets
#     get the unwinding libtest harness. A `rust_test` crate flips
#     to std under `--test` via `#![cfg_attr(not(test), no_std)]`,
#     so the unwind strategy is legal there. Its dependency rlibs
#     don't get `--test` and stay no_std — but a no_std rlib links
#     fine into the unwinding test binary, so no per-dep std-flip
#     is needed.
#
#   * Integration tests are per-variant (`:test_hvf`, `:test_iso`,
#     `:test_qemu_<arch>`) and depend on the matching unikernel
#     variant target. The variant rule in
#     `//bazel/rules:variants.bzl` applies a Bazel transition that
#     re-asserts `-Cpanic=abort` on the unikernel sub-graph, so the
#     test-verb unwind override never reaches the unikernel rlibs.
