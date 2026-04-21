"""Per-runner variant targets for unikernel apps.

For each `unikernel_binary(name, app)` — declared via the sibling
`unikernel_variants(name, app)` macro — this file produces one
runnable `:<name>_<variant>` target per supported runner.

Each variant wraps the shared `:<name>` sh_binary launcher under a
Bazel transition that pins the matching target platform + runner
selection + `-Cpanic=abort` for the variant's dep sub-graph. `bazel
run //apps/webserver:webserver_hvf` is a drop-in for
`bazel run --config=hvf //apps/webserver:webserver`, but because the
transition is a per-target attribute (not a whole-build flag) the
analysis cache is preserved across variants — `bazel test //...`
can cover the full runner matrix in one invocation without
invalidating the other runners' artifacts.

Variants produced:
  * `:<name>_hvf`          — aarch64 unikernel + native HVF runner.
  * `:<name>_iso`          — x86_64 unikernel + Limine ISO in QEMU.
  * `:<name>_qemu_aarch64` — aarch64 unikernel + QEMU TCG.
  * `:<name>_qemu_x86_64`  — x86_64 unikernel + QEMU TCG.

(Native builds already have a dedicated `:<name>_native` produced
by `unikernel_binary` — a rust_binary, not a launcher — so they
need no wrapping.)

The old `:<name>` launcher stays as-is for now — variants are
additive so existing `bazel run --config=hvf //...` workflows keep
working during the migration.
"""

# Transitions that flip the sub-graph into each variant's config.
# Outputs:
#   * `//command_line_option:platforms` — target platform (unikernel
#                                         arch variant; native omitted).
#   * `//bazel/rules:uni_runner`        — `hvf` / `iso` / `qemu` / `native`
#                                         string_flag driving the
#                                         unikernel_binary launcher's
#                                         select()s on runner.
#   * `@rules_rust//:extra_rustc_flag`  — `-Cpanic=abort` so under the
#                                         `test` verb (which sets
#                                         panic=unwind globally) the
#                                         unikernel rlibs still compile.
#   * `//bazel/rules:tests_need_std`    — False so `atomic_fn`'s feature-
#                                         gated no_std stays on.
#
# One transition per variant (Starlark doesn't allow closure-generated
# transitions at load time), factored via `_make_variant_transition`.

def _make_variant_transition(platform, uni_runner):
    def _impl(_settings, _attr):
        out = {
            "//bazel/rules:uni_runner": uni_runner,
            "@rules_rust//:extra_rustc_flag": ["-Cpanic=abort"],
            "//bazel/rules:tests_need_std": False,
        }
        if platform:
            out["//command_line_option:platforms"] = platform
        return out

    outputs = [
        "//bazel/rules:uni_runner",
        "@rules_rust//:extra_rustc_flag",
        "//bazel/rules:tests_need_std",
    ]
    if platform:
        outputs.append("//command_line_option:platforms")

    return transition(
        implementation = _impl,
        inputs = [],
        outputs = outputs,
    )

_hvf_transition = _make_variant_transition(
    platform = "//bazel/platforms:aarch64_unikernel",
    uni_runner = "hvf",
)

_iso_transition = _make_variant_transition(
    platform = "//bazel/platforms:x86_64_unikernel",
    uni_runner = "iso",
)

_qemu_aarch64_transition = _make_variant_transition(
    platform = "//bazel/platforms:aarch64_unikernel",
    uni_runner = "qemu",
)

_qemu_x86_64_transition = _make_variant_transition(
    platform = "//bazel/platforms:x86_64_unikernel",
    uni_runner = "qemu",
)


# Wrapper rule: exposes the transitioned `src` as a new executable
# target with this rule's name. A symlink in the rule's output
# directory gives Bazel an executable to hand to `bazel run`, and
# the src's runfiles (the .img / .elf / .iso + helpers.sh) are
# preserved — so the runner script (sitting next to the symlink in
# the runfiles tree) finds its sibling artefacts via $0's directory,
# exactly as it does today under `--config=<runner>`.
#
# One rule per variant because Starlark transitions are attr-cfg, not
# parameterised at rule-build time.
def _variant_impl(ctx):
    src = ctx.attr.src[0]  # `cfg = transition` makes `src` a 1-list
    src_exe = src[DefaultInfo].files_to_run.executable

    # Symlink the transitioned src's executable to a file named after
    # this rule. `basename $0` in the runner script will be e.g.
    # `webserver_hvf`; the script strips the `_<variant>` suffix to
    # locate sibling artefacts (which keep the original `<name>.img`
    # naming from the underlying unikernel_binary).
    out = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(output = out, target_file = src_exe, is_executable = True)

    return [DefaultInfo(
        executable = out,
        runfiles = src[DefaultInfo].default_runfiles,
    )]

def _make_variant_rule(variant_transition):
    return rule(
        implementation = _variant_impl,
        executable = True,
        attrs = {
            "src": attr.label(
                cfg = variant_transition,
                executable = True,
                mandatory = True,
                doc = "The base unikernel sh_binary launcher to wrap.",
            ),
            "_allowlist_function_transition": attr.label(
                default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
            ),
        },
    )

_hvf_variant = _make_variant_rule(_hvf_transition)
_iso_variant = _make_variant_rule(_iso_transition)
_qemu_aarch64_variant = _make_variant_rule(_qemu_aarch64_transition)
_qemu_x86_64_variant = _make_variant_rule(_qemu_x86_64_transition)

def unikernel_variants(src, visibility = None):
    """Generate `:<src>_<variant>` runnable targets for every runner.

    Each variant's transition re-builds `src`'s sub-graph under the
    matching platform + runner, so all variants share declaration
    but land in independent configurations. Variant names are
    derived from `src`'s target name — e.g. `src = ":webserver"`
    yields `:webserver_hvf`, `:webserver_iso`, etc.

    Unconventionally no `name` argument: the macro generates
    multiple targets with distinct derived names, so a `name` would
    either shadow the underlying target (tripping buildifier's
    duplicated-name check) or force the caller to repeat `src`.

    Args:
      src: unified launcher target (the `:<name>` produced by
        `unikernel_binary`).
      visibility: Bazel visibility for the generated variants.
    """
    base = src.rsplit(":", 1)[-1] if ":" in src else src.rsplit("/", 1)[-1]
    _hvf_variant(name = base + "_hvf", src = src, visibility = visibility)
    _iso_variant(name = base + "_iso", src = src, visibility = visibility)
    _qemu_aarch64_variant(name = base + "_qemu_aarch64", src = src, visibility = visibility)
    _qemu_x86_64_variant(name = base + "_qemu_x86_64", src = src, visibility = visibility)
