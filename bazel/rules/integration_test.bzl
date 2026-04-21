"""Integration-test helpers.

`integration_data(src)` wraps a target that an integration test consumes
as `data = [...]`, applying a one-hop Bazel transition that resets
`-Cpanic=abort` regardless of the outer build's configuration.

Why: under `bazel test` the outer config carries `-Cpanic=unwind`
(set by `.bazelrc`'s `test --extra_rustc_flag` so rust_test's libtest
harness can unwind). Any binary that needs to stay panic=abort (e.g.,
every target in this repo that links `#![no_std]` rlibs) must override
that flag back. Without this wrapper we'd do it the hacky way — tag
integration tests so `bazel test //...` skips them, then require the
user to pass `--config=hvf` so a second `.bazelrc` override re-asserts
abort. With the wrapper the test's data-dep sub-graph carries its own
configuration, the outer config is untouched, and `bazel test //...`
just works.

Usage:

    load("//bazel/rules:integration_test.bzl", "integration_data")

    unikernel_binary(name = "webserver", ...)

    integration_data(name = "webserver_for_test", src = ":webserver")

    py_test(name = "test", ..., data = [":webserver_for_test"])

The transition only flips the panic flag — it does NOT change the
platform, so the `--config=hvf` / `=iso` / `=qemu` / default-native
platform selection still drives which unikernel runner boots. That
keeps the existing runner-per-config ergonomics intact.
"""

def _abort_panic_impl(_settings, _attr):
    return {
        # `@rules_rust//:extra_rustc_flag` is a repeatable string_list
        # flag. Transitions on list-typed flags REPLACE the list for
        # the transitioned sub-graph, so this single-element value
        # shadows any `test`-verb `-Cpanic=unwind` appended upstream.
        # Rustc still sees `-Cpanic=abort` from the global
        # `extra_rustc_flags` too, but with identical orderings the
        # last wins and that stays abort.
        "@rules_rust//:extra_rustc_flag": ["-Cpanic=abort"],
    }

_abort_panic_transition = transition(
    implementation = _abort_panic_impl,
    inputs = [],
    outputs = ["@rules_rust//:extra_rustc_flag"],
)

def _integration_data_impl(ctx):
    src = ctx.attr.src[0]  # cfg=transition makes `src` a 1-element list
    default_info = src[DefaultInfo]
    # Pass through the src's files + runfiles. Consumers (py_test's
    # `data = [...]`) see the wrapped target's artifacts at the src's
    # native runfile paths (e.g. `apps/webserver/webserver` for a
    # wrapped `:webserver` launcher), NOT under the wrapper's name —
    # tests that hardcode the src path keep working.
    return [
        DefaultInfo(
            files = default_info.files,
            runfiles = default_info.default_runfiles,
        ),
    ]

integration_data = rule(
    implementation = _integration_data_impl,
    attrs = {
        "src": attr.label(
            cfg = _abort_panic_transition,
            mandatory = True,
            doc = "The target to build under panic=abort.",
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
