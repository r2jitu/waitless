"""Per-runner variant targets for unikernel apps.

For each `unikernel_binary(name, app)` declaration, this file
produces one runnable `:<name>_<variant>` target per supported
runner, plus a sibling `unikernel_app_test(name, app_base, test_rule,
...)` macro that fans a test target out across the same variant
list. Adding a new variant is a single edit to `_VARIANT_SPECS`
below; every app + app-test picks it up automatically.

Each variant rule transitions its target-side deps (ELF / IMG / ISO)
into the matching platform + `uni_runner` + `-Cpanic=abort` sub-
configuration, symlinks them into the rule's own output directory
under filenames that encode the variant name, and template-expands
a per-variant launcher script with those filenames baked in. Net
effect:

  * Every runfile the launcher touches lives in its own directory —
    no upward-walk, no suffix-stripping, no `basename $0` parsing.
  * Switching runners keeps the analysis cache warm — `bazel build
    :webserver_hvf :webserver_iso` resolves both in one go.
  * `bazel test //...` covers the full runner matrix without
    `--config=` flag gymnastics. HVF variants carry
    `target_compatible_with = [@platforms//os:macos]` so they
    auto-skip on Linux; every other variant runs anywhere QEMU is
    available.

Variants produced (names & platform compat defined in _VARIANT_SPECS):
  * `:<name>_hvf`          — aarch64 unikernel + native HVF runner.
  * `:<name>_iso_x86_64`   — x86_64 unikernel + Limine ISO (cloud boot).
  * `:<name>_iso_aarch64`  — aarch64 unikernel + Limine ISO (ARM cloud).
  * `:<name>_qemu_aarch64` — aarch64 unikernel + QEMU TCG.
  * `:<name>_qemu_x86_64`  — x86_64 unikernel + QEMU TCG.

(Native is already covered by `unikernel_binary`'s `:<name>_native`
rust_binary — a direct host executable, no launcher script required.)
"""

# ── Transitions ────────────────────────────────────────────────────────────
#
# Each transition flips the same four keys:
#
#   * `//command_line_option:platforms` — target platform.
#   * `//bazel/rules:uni_runner`        — string_flag driving runner
#                                         config_settings.
#   * `@rules_rust//:extra_rustc_flag`  — `-Cpanic=abort` (overrides
#                                         the `test`-verb unwind).
#   * `//bazel/rules:tests_need_std`    — False so atomic_fn stays
#                                         no_std inside the sub-graph.
#
# Starlark requires `transition()` at .bzl load time, so we build the
# four concrete objects here via the shared helper and reference them
# from _VARIANT_SPECS below.

def _make_variant_transition(platform, uni_runner):
    outputs = [
        "//bazel/rules:uni_runner",
        "@rules_rust//:extra_rustc_flag",
        "//bazel/rules:tests_need_std",
    ]
    if platform != None:
        outputs.append("//command_line_option:platforms")

    def _impl(_settings, _attr):
        out = {
            "//bazel/rules:uni_runner": uni_runner,
            "@rules_rust//:extra_rustc_flag": ["-Cpanic=abort"],
            "//bazel/rules:tests_need_std": False,
        }
        if platform != None:
            out["//command_line_option:platforms"] = platform
        return out

    return transition(implementation = _impl, inputs = [], outputs = outputs)

_hvf_transition = _make_variant_transition(
    platform = "//bazel/platforms:aarch64_unikernel",
    uni_runner = "hvf",
)
_iso_x86_64_transition = _make_variant_transition(
    platform = "//bazel/platforms:x86_64_unikernel",
    uni_runner = "iso",
)
_iso_aarch64_transition = _make_variant_transition(
    platform = "//bazel/platforms:aarch64_unikernel",
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


# ── Variant rule helpers ───────────────────────────────────────────────────

def _symlink_into_outdir(ctx, src_file, out_name):
    """Declare an output named `out_name` and symlink `src_file` to it."""
    out = ctx.actions.declare_file(out_name)
    ctx.actions.symlink(output = out, target_file = src_file)
    return out

def _expand_launcher(ctx, substitutions):
    """Expand the rule's `_template` attr to a named-after-target executable."""
    out = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = out,
        substitutions = substitutions,
        is_executable = True,
    )
    return out

def _relpath_from_launcher_to(ctx, target_file):
    """Return `$SELF_DIR`-relative path from launcher to `target_file`.

    The launcher is declared at `<package>/<name>` in runfiles; its
    runtime `$SELF_DIR` is the package directory. To reach a file at
    `target_file.short_path`, we walk up `package_depth` levels to
    the runfiles root and then down via `short_path`. Lets us
    reference shared runfiles (e.g. `//scripts:helpers.sh`) without
    symlinking a per-variant copy next to the launcher.
    """
    package_depth = ctx.label.package.count("/") + 1 if ctx.label.package else 0
    return ("../" * package_depth) + target_file.short_path

# ── Port-forward launcher-string builders ────────────────────────────────
#
# `port_fwd()` in unikernel.bzl returns a `struct(proto, guest, host)`.
# These helpers turn a list of such structs into the finished launcher
# argument string for each runner (HVF `-p` flags / QEMU `hostfwd=…`
# entries). Rule attrs can't hold structs, so we format up-front at
# macro time and pass the single resulting string through a `string`
# attr — no encode / parse pair on the rule-impl side.
#
# Env-var override name is derived as `UNIKERNEL_<PROTO>_<GUEST>`
# (e.g. `UNIKERNEL_TCP_80`). Same convention is honored by the
# native binary (`uni::native`), so users override the host port
# the same way regardless of runner. Bash-style default expansion
# — `${…:-<host>}` — falls back to the BUILD-declared default.

def _port_fwd_env_var(pf):
    """Derive the runtime override env-var name for a port_fwd() struct."""
    return "UNIKERNEL_{}_{}".format(pf.proto.upper(), pf.guest)

def _build_hvf_port_flags(port_forwards):
    """Build HVF runner `-p proto:host:guest` arg string."""
    parts = []
    for f in port_forwards:
        parts.append('-p "{proto}:${{{env}:-{host}}}:{guest}"'.format(
            proto = f.proto,
            env = _port_fwd_env_var(f),
            host = f.host,
            guest = f.guest,
        ))
    return " ".join(parts)

def _build_qemu_hostfwd(port_forwards):
    """Build QEMU `user,…,hostfwd=…,hostfwd=…` forward string."""
    parts = []
    for f in port_forwards:
        # helpers.sh's run_qemu passes this into
        # `-netdev user,…,<hostfwd>` where bash re-evaluates
        # `${VAR:-default}` in context.
        parts.append("hostfwd={proto}::${{{env}:-{host}}}-:{guest}".format(
            proto = f.proto,
            env = _port_fwd_env_var(f),
            host = f.host,
            guest = f.guest,
        ))
    return ",".join(parts)

def _hvf_port_forward_kwargs(port_forwards):
    return {"hvf_port_flags": _build_hvf_port_flags(port_forwards)}

def _qemu_port_forward_kwargs(port_forwards):
    return {"qemu_hostfwd": _build_qemu_hostfwd(port_forwards)}

# Per-variant rule implementations. Each takes exactly the attrs its
# runner script consumes, symlinks them into co-located files, and
# returns a launcher that references them by fixed `%TOKEN%` names.
#
# Note on `ctx.attr.X` vs `ctx.attr.X[0]`: attrs declared with
# `cfg = <some_transition>` resolve to a *list* (one Target per
# output config — even when, as here, the transition is single-
# valued), so they need the `[0]` dereference. Attrs without `cfg`
# resolve to a plain Target. Mixing both in the same impl is a
# paper-cut but idiomatic for Bazel.

def _hvf_impl(ctx):
    img = _symlink_into_outdir(
        ctx,
        ctx.attr.img[0][DefaultInfo].files.to_list()[0],
        ctx.label.name + ".img",
    )
    # `hvf_runner` is a host-cfg label (no [0], no transition); consume
    # it from its natural runfiles path via a launcher-relative path,
    # same pattern used for `helpers.sh` in the iso / qemu variants.
    runner = ctx.attr.hvf_runner[DefaultInfo].files.to_list()[0]
    launcher = _expand_launcher(ctx, {
        "%IMG%": img.basename,
        "%RUNNER%": _relpath_from_launcher_to(ctx, runner),
        "%PORT_FLAGS%": ctx.attr.hvf_port_flags,
        "%DEFAULT_RAM%": str(ctx.attr.default_ram_mb),
        "%DEFAULT_CPUS%": str(ctx.attr.default_cpus),
    })
    return [DefaultInfo(
        executable = launcher,
        runfiles = ctx.runfiles(files = [launcher, img, runner]),
    )]

def _iso_impl(ctx):
    iso = _symlink_into_outdir(
        ctx,
        ctx.attr.iso[0][DefaultInfo].files.to_list()[0],
        ctx.label.name + ".iso",
    )
    launcher = _expand_launcher(ctx, {
        "%ISO%": iso.basename,
        "%HELPERS%": _relpath_from_launcher_to(ctx, ctx.file.helpers),
        "%HOSTFWD%": ctx.attr.qemu_hostfwd,
        "%DEFAULT_RAM%": str(ctx.attr.default_ram_mb),
        "%DEFAULT_CPUS%": str(ctx.attr.default_cpus),
        "%QEMU_BIN%": ctx.attr._qemu_bin,
        "%VIRTIO_DEV%": ctx.attr._virtio_dev,
        "%QEMU_MACHINE%": ctx.attr._qemu_machine,
    })
    return [DefaultInfo(
        executable = launcher,
        runfiles = ctx.runfiles(files = [launcher, iso, ctx.file.helpers]),
    )]

def _qemu_impl(ctx):
    # Both .elf and .img ship together: x86_64 QEMU reads the ELF
    # directly via `-kernel`, aarch64 QEMU needs the raw .img (the
    # ELF is PIE and QEMU can't load it). The launcher passes both
    # explicitly to `detect_qemu` in helpers.sh, so we just
    # symlink each under a co-located name and substitute both
    # tokens — no implicit path derivation.
    elf = _symlink_into_outdir(
        ctx,
        ctx.attr.elf[0][DefaultInfo].files.to_list()[0],
        ctx.label.name + ".elf",
    )
    img = _symlink_into_outdir(
        ctx,
        ctx.attr.img[0][DefaultInfo].files.to_list()[0],
        ctx.label.name + ".img",
    )
    launcher = _expand_launcher(ctx, {
        "%ELF%": elf.basename,
        "%IMG%": img.basename,
        "%HELPERS%": _relpath_from_launcher_to(ctx, ctx.file.helpers),
        "%HOSTFWD%": ctx.attr.qemu_hostfwd,
        "%DEFAULT_RAM%": str(ctx.attr.default_ram_mb),
        "%DEFAULT_CPUS%": str(ctx.attr.default_cpus),
    })
    return [DefaultInfo(
        executable = launcher,
        runfiles = ctx.runfiles(files = [launcher, elf, img, ctx.file.helpers]),
    )]

_ALLOWLIST_ATTR = {
    "_allowlist_function_transition": attr.label(
        default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
    ),
}

# `_HELPERS_ATTR` is shared by every variant rule whose launcher sources
# //scripts:helpers.sh (iso + qemu_*). HVF doesn't — its launcher just
# `exec`s the HVF runner directly.
_HELPERS_ATTR = {
    "helpers": attr.label(
        default = "//scripts:helpers.sh",
        allow_single_file = True,
    ),
}

# Every variant rule takes `default_ram_mb` and `default_cpus` — the
# impl substitutes them into its launcher template. Runtime
# `UNIKERNEL_MEMORY` / `UNIKERNEL_CPUS` env-vars still override
# per-invocation; these set the defaults that kick in when no env
# override is present. Port-forward config is injected per-variant
# via `hvf_port_flags` / `qemu_hostfwd` (pre-formatted launcher
# strings built in the macro).
_VM_CONFIG_ATTRS = {
    "default_ram_mb": attr.int(
        default = 128,
        doc = "Default guest RAM in MB (overridable via UNIKERNEL_MEMORY).",
    ),
    "default_cpus": attr.int(
        default = 1,
        doc = "Default vCPU count (overridable via UNIKERNEL_CPUS).",
    ),
}

def _build_variant_rule(impl, template, extra_attrs):
    """Build a variant rule with the common plumbing baked in.

    All variant rules share: executable=True, the function_transition
    allowlist, and a `_template` attr. They differ in their impl,
    their launcher template, and which label attrs they expose
    (what goes through the transition, what's host-cfg, what's a
    shared helper, …).

    Args:
      impl: Starlark impl function for the rule.
      template: launcher template label (e.g. run_hvf.sh.tmpl).
      extra_attrs: dict of variant-specific attr.* declarations.
    """
    return rule(
        implementation = impl,
        executable = True,
        attrs = dict(
            _ALLOWLIST_ATTR,
            _template = attr.label(default = template, allow_single_file = True),
            **extra_attrs
        ),
    )

_hvf_variant = _build_variant_rule(
    impl = _hvf_impl,
    template = "//bazel/rules:run_hvf.sh.tmpl",
    extra_attrs = dict(_VM_CONFIG_ATTRS, **{
        "img": attr.label(
            cfg = _hvf_transition,
            mandatory = True,
            allow_single_file = True,
            doc = "The <name>.img of the underlying unikernel_binary (transitioned).",
        ),
        "hvf_runner": attr.label(
            mandatory = True,
            doc = "Host-platform HVF runner binary (built in outer config).",
        ),
        "hvf_port_flags": attr.string(
            doc = "Pre-formatted `-p` flags; built by `_build_hvf_port_flags`.",
        ),
    }),
)

# ISO runs its guest under QEMU but boots via Limine rather than
# `-kernel`, so the template can't rely on `detect_qemu` (which
# sniffs an ELF to pick the right qemu-system-*). Each per-arch
# ISO rule bakes in the QEMU binary + machine args via
# `_qemu_bin` / `_virtio_dev` / `_qemu_machine` string attrs
# that the impl substitutes into the launcher template.
def _make_iso_variant(variant_transition, qemu_bin, virtio_dev, qemu_machine):
    return _build_variant_rule(
        impl = _iso_impl,
        template = "//bazel/rules:run_iso.sh.tmpl",
        extra_attrs = dict(
            dict(_HELPERS_ATTR, **_VM_CONFIG_ATTRS),
            **{
                "iso": attr.label(
                    cfg = variant_transition,
                    mandatory = True,
                    allow_single_file = True,
                    doc = "The <name>.iso of the underlying unikernel_binary (transitioned).",
                ),
                "qemu_hostfwd": attr.string(
                    doc = "Pre-formatted QEMU `hostfwd=…` string; built by `_build_qemu_hostfwd`.",
                ),
                "_qemu_bin": attr.string(default = qemu_bin),
                "_virtio_dev": attr.string(default = virtio_dev),
                "_qemu_machine": attr.string(default = qemu_machine),
            }
        ),
    )

_iso_x86_64_variant = _make_iso_variant(
    _iso_x86_64_transition,
    qemu_bin = "qemu-system-x86_64",
    virtio_dev = "virtio-net-pci",
    qemu_machine = "",  # x86_64 QEMU defaults are fine without `-machine`.
)
_iso_aarch64_variant = _make_iso_variant(
    _iso_aarch64_transition,
    qemu_bin = "qemu-system-aarch64",
    virtio_dev = "virtio-net-pci",
    qemu_machine = "-machine virt",
)

def _make_qemu_variant(variant_transition):
    return _build_variant_rule(
        impl = _qemu_impl,
        template = "//bazel/rules:run_qemu.sh.tmpl",
        extra_attrs = dict(
            dict(_HELPERS_ATTR, **_VM_CONFIG_ATTRS),
            **{
                "elf": attr.label(
                    cfg = variant_transition,
                    mandatory = True,
                    doc = "The <name>.elf of the underlying unikernel_binary (transitioned).",
                ),
                "img": attr.label(
                    cfg = variant_transition,
                    mandatory = True,
                    allow_single_file = True,
                    doc = "The <name>.img of the underlying unikernel_binary (transitioned).",
                ),
                "qemu_hostfwd": attr.string(
                    doc = "Pre-formatted QEMU `hostfwd=…` string; built by `_build_qemu_hostfwd`.",
                ),
            }
        ),
    )

_qemu_aarch64_variant = _make_qemu_variant(_qemu_aarch64_transition)
_qemu_x86_64_variant = _make_qemu_variant(_qemu_x86_64_transition)

# ── Variant specs — single source of truth ───────────────────────────────
#
# Each spec wires a suffix ("hvf", "iso", "qemu_<arch>") to:
#   * `rule_fn`           — the Starlark rule function that
#                           instantiates the variant target.
#   * `src_attrs`         — attrs to fill from the app's package
#                           (e.g. `{"img": ".img"}` → `:<base>.img`).
#   * `host_attrs`        — attrs that are plain host labels, not
#                           derived from `base` (e.g. the hvf_runner).
#   * `host_compat`       — the `target_compatible_with` the variant
#                           executable carries. `bazel test //...`
#                           auto-skips variants the current host
#                           doesn't satisfy (hvf → macOS only;
#                           qemu_* and iso run anywhere with QEMU).
#   * `in_default_test_set` — whether `unikernel_app_test` includes
#                             this variant when the caller doesn't
#                             pass an explicit `variants = [...]`.

_VARIANT_SPECS = [
    struct(
        suffix = "hvf",
        rule_fn = _hvf_variant,
        src_attrs = {"img": ".img"},
        host_attrs = {"hvf_runner": "//tools/hvf-runner:run_hvf"},
        port_forward_kwargs = _hvf_port_forward_kwargs,
        host_compat = ["@platforms//os:macos"],  # Hypervisor.framework.
        extra_test_tags = [],
        in_default_test_set = True,
    ),
    # ISO variants exist for both arches because the primary use
    # case is cloud deployment (GCE custom images, AWS Graviton /
    # ARM bare-metal), not local dev. Both carry the `iso` umbrella
    # tag so `--test_tag_filters=iso` runs both archs. Excluded from
    # the default test set: the guest CODE exercised is identical to
    # the QEMU variants (same app binary) — the Limine boot path is
    # already validated by the `.iso` genrule itself succeeding.
    # Apps that want runtime ISO-boot coverage opt in via
    # `variants = [..., "iso_x86_64", "iso_aarch64"]`.
    struct(
        suffix = "iso_x86_64",
        rule_fn = _iso_x86_64_variant,
        src_attrs = {"iso": ".iso"},
        host_attrs = {},
        port_forward_kwargs = _qemu_port_forward_kwargs,
        host_compat = [],
        extra_test_tags = ["iso"],
        in_default_test_set = False,
    ),
    struct(
        suffix = "iso_aarch64",
        rule_fn = _iso_aarch64_variant,
        src_attrs = {"iso": ".iso"},
        host_attrs = {},
        port_forward_kwargs = _qemu_port_forward_kwargs,
        host_compat = [],
        extra_test_tags = ["iso"],
        in_default_test_set = False,
    ),
    struct(
        suffix = "qemu_aarch64",
        rule_fn = _qemu_aarch64_variant,
        src_attrs = {"elf": ".elf", "img": ".img"},
        host_attrs = {},
        port_forward_kwargs = _qemu_port_forward_kwargs,
        host_compat = [],
        # `qemu` is an umbrella tag so `--test_tag_filters=qemu`
        # picks up both architectures in one shot.
        extra_test_tags = ["qemu"],
        in_default_test_set = True,
    ),
    struct(
        suffix = "qemu_x86_64",
        rule_fn = _qemu_x86_64_variant,
        src_attrs = {"elf": ".elf", "img": ".img"},
        host_attrs = {},
        port_forward_kwargs = _qemu_port_forward_kwargs,
        host_compat = [],
        extra_test_tags = ["qemu"],
        in_default_test_set = True,
    ),
    struct(
        # Native: `:<name>_native` is a plain rust_binary declared
        # by `unikernel_binary` itself (native_main.rs links libstd,
        # so no transition or wrapper is required for the `bazel
        # test` verb's panic=unwind to work). `rule_fn = None`
        # signals `unikernel_variants` to skip target creation; the
        # spec entry is still present so `unikernel_app_test` fans
        # out across native too — fast, no VM boot.
        suffix = "native",
        rule_fn = None,
        src_attrs = {},
        host_attrs = {},
        port_forward_kwargs = None,
        host_compat = ["//bazel/platforms:native"],
        extra_test_tags = [],
        in_default_test_set = True,
    ),
]

_SUFFIX_TO_SPEC = {spec.suffix: spec for spec in _VARIANT_SPECS}
_ALL_VARIANT_SUFFIXES = tuple([v.suffix for v in _VARIANT_SPECS])
_DEFAULT_TEST_VARIANT_SUFFIXES = tuple([
    v.suffix for v in _VARIANT_SPECS if v.in_default_test_set
])

def _instantiate_variant(spec, name, base, vm_config, visibility):
    """Invoke `spec.rule_fn` with attrs derived from `spec` + `base`.

    `rule_fn = None` means the target is produced elsewhere — native's
    `:<base>_native` is declared directly by `unikernel_binary` — so
    this helper is a no-op for that spec.
    """
    if spec.rule_fn == None:
        return
    kwargs = {}
    for attr_name, suffix in spec.src_attrs.items():
        kwargs[attr_name] = ":" + base + suffix
    for attr_name, label in spec.host_attrs.items():
        kwargs[attr_name] = label
    # Per-runner port-forward attr (e.g. HVF's `hvf_port_flags` vs
    # QEMU/ISO's `qemu_hostfwd`) — spec picks the builder.
    kwargs.update(spec.port_forward_kwargs(vm_config.port_forwards))
    spec.rule_fn(
        name = name,
        default_ram_mb = vm_config.ram_mb,
        default_cpus = vm_config.cpus,
        target_compatible_with = spec.host_compat,
        visibility = visibility,
        **kwargs
    )

# ── Public macros ─────────────────────────────────────────────────────────

# buildifier: disable=unnamed-macro
def unikernel_variants(
        name,
        port_forwards,
        ram_mb,
        cpus,
        visibility = None):
    """Generate `:<name>_<variant>` runnable targets for every runner in _VARIANT_SPECS.

    Called from `unikernel_binary` after the artefact targets are
    declared (`:<name>.img` / `:<name>.elf` / `:<name>.iso` must
    exist in the same package). Every config arg is required —
    `unikernel_binary` handles defaults (`port_fwd()` entries,
    `ram_mb=128`, `cpus=1`) so this internal macro stays explicit.

    `name` is a prefix for the generated targets, not a target of
    its own — the underlying unikernel_binary intentionally does
    not expose a unified `:<name>` launcher.

    Args:
      name: target-name prefix (matches the enclosing unikernel_binary).
      port_forwards: per-app forwarding config (entries built via
        `port_fwd()` in unikernel.bzl).
      ram_mb: default guest RAM in MB (overridable via UNIKERNEL_MEMORY).
      cpus: default vCPU count (overridable via UNIKERNEL_CPUS).
      visibility: Bazel visibility for the generated variants.
    """
    vm_config = struct(
        port_forwards = port_forwards,
        ram_mb = ram_mb,
        cpus = cpus,
    )
    for spec in _VARIANT_SPECS:
        _instantiate_variant(
            spec,
            name + "_" + spec.suffix,
            name,
            vm_config,
            visibility,
        )

def unikernel_app_test(name, app_base, test_rule, extra_data = None, variants = None, **kwargs):
    """Generate `:<name>_<variant>` test targets for every requested runner.

    For each variant produced by `unikernel_variants(name = app_base)`,
    instantiate `test_rule` with the variant target added as a data
    dep and `LAUNCHER_NAME` set in the test env so the test script
    can resolve the variant's co-located runfiles.

    The macro is `test_rule`-agnostic so callers are free to use
    py_test today and (say) a custom rule tomorrow — every current
    app happens to use py_test but nothing here assumes it.

    Each generated test target is tagged with its variant suffix
    (`hvf`, `qemu_aarch64`, …) so users can filter the matrix via
    `bazel test --test_tag_filters=hvf //...` (all HVF tests) or
    `--test_tag_filters=qemu_aarch64 //...` (only aarch64 QEMU).

    Args:
      name: base name for the test targets (`:<name>_<variant>`).
      app_base: name passed to the app's `unikernel_binary` —
        the variant targets it generated are `:<app_base>_<variant>`.
      test_rule: test-rule function to instantiate (e.g. py_test,
        sh_test). Caller loads + passes it in directly.
      extra_data: additional data files the test needs besides the
        variant target (e.g. dev certs).
      variants: subset of variant suffixes to fan out across; omit
        for the default set (every variant except `iso`, since ISO
        tests the same guest code as QEMU with a different boot
        sequence). Tests that want ISO coverage or narrower cuts
        pass an explicit list.
      **kwargs: forwarded to every test_rule call (`srcs`, `deps`,
        `tags`, `timeout`, …). `target_compatible_with` is reserved
        — the macro sets it from the variant spec, so passing it in
        `kwargs` is an error.
    """
    if "target_compatible_with" in kwargs:
        fail("unikernel_app_test: `target_compatible_with` is set per-variant " +
             "from `host_compat` in variants.bzl; drop it from your call.")

    # Pull `srcs` and common tags out of kwargs. Each variant gets
    # its own copy of the source file (see below), so we consume
    # `srcs` here and supply per-variant lists inside the loop.
    srcs = kwargs.pop("srcs", None)
    if not srcs or len(srcs) != 1:
        fail("unikernel_app_test: `srcs` must be a single-element list " +
             "(the test entry-point script).")
    src_file = srcs[0]
    caller_tags = list(kwargs.pop("tags", []))

    selected = variants if variants != None else _DEFAULT_TEST_VARIANT_SUFFIXES
    for suffix in selected:
        if suffix not in _SUFFIX_TO_SPEC:
            fail("unikernel_app_test: unknown variant '{}' (known: {})".format(
                suffix,
                ", ".join(_ALL_VARIANT_SUFFIXES),
            ))
        spec = _SUFFIX_TO_SPEC[suffix]
        launcher_name = app_base + "_" + suffix
        # Per-variant source copy. py_test registers a `PyCompile`
        # action keyed on its srcs, and multiple py_test targets
        # sharing the same source file collide on the resulting
        # `__pycache__/<stem>.cpython-*.pyc` output. Giving every
        # variant its own file (same content, unique name) sidesteps
        # the collision — trivially works for any test_rule that
        # accepts `srcs`, and is a no-op for rules that don't run a
        # compile step on their sources.
        variant_src = name + "_" + suffix + "_src.py"
        native.genrule(
            name = name + "_" + suffix + "_src",
            srcs = [src_file],
            outs = [variant_src],
            cmd = "cp $< $@",
        )
        # Tags: caller-supplied + the variant's own suffix + any
        # umbrella tags from the spec (e.g. "qemu" for both qemu
        # archs). Lets `--test_tag_filters=hvf` / `=qemu` /
        # `=qemu_aarch64` all work.
        variant_tags = caller_tags + [suffix] + list(spec.extra_test_tags)
        test_rule(
            name = name + "_" + suffix,
            srcs = [variant_src],
            main = variant_src,
            data = [":" + launcher_name] + (extra_data or []),
            env = {"LAUNCHER_NAME": launcher_name},
            target_compatible_with = spec.host_compat,
            tags = variant_tags,
            **kwargs
        )
