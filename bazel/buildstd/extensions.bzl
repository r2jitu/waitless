"""Hard-float x86_64 bare-metal Rust sysroot + toolchain.

The stock `x86_64-unknown-none` target is soft-float (its spec carries
`rustc-abi: softfloat`). The TLS/QUIC crypto crates need SSE/AES register
classes, which forced a per-crate `-Ctarget-feature=-soft-float,+sse,+sse2`
override -- an ABI-changing toggle that rust-lang/rust#116344 is turning
into a hard error. See the long comment in MODULE.bazel.

This extension builds `core`, `compiler_builtins` and `alloc` from pinned
`rust-src` against `//bazel/toolchain:x86_64-waitless-none.json` -- a
hard-float spec (SSE2 ABI, no `rustc-abi: softfloat`) -- and emits a
`rust_toolchain`, so the *entire* x86_64 unikernel (kernel and crypto
alike) compiles with one consistent hard-float ABI and no
`-Ctarget-feature` ABI toggle anywhere.

The std crates use nightly `#![feature]`s, so they are built with
`RUSTC_BOOTSTRAP=1` against the pinned *stable* rustc -- the toolchain
channel stays stable; only these three fetch-time compiles opt in.

`rustc` is taken from `@rust_host_tools` (the rules_rust host download), so
the generated toolchain is correct for whatever host fetched the repo --
aarch64-macos dev boxes and x86_64-linux GCE/CI alike.
"""

# The custom target's name. rustc derives a JSON target's triple identity
# from the spec filename; with the rules_rust `target_json` patch the spec
# is written as `<rust_toolchain name>.json`, so this string is, verbatim,
# the rustc target triple, the `rust_toolchain` target name, and the stem
# of the committed `//bazel/toolchain:<triple>.json` spec. Rename in all
# three places together if rebranding the ABI.
_TARGET_TRIPLE = "x86_64-waitless-none"

# Pinned to the rules_rust toolchain version (`rust.toolchain(versions=...)`
# in MODULE.bazel). Bump both together; rustc rejects a mismatched `core`.
_RUST_SRC_VERSION = "1.93.1"
_RUST_SRC_SHA256 = "7ade6b2ef03a3b7a614d54df6637a97d18144690bd49daab63bd4b22e0e6bac0"

# cfgs that `cargo build -Zbuild-std` feeds `compiler_builtins` 0.1.160 on
# x86_64: the `default` Cargo feature set plus what its build script emits.
# We drive rustc directly, so they are replicated here. `--check-cfg` flags
# are intentionally omitted -- `--cap-lints allow` already silences the
# `unexpected_cfgs` lint they would otherwise gate.
_COMPILER_BUILTINS_CFGS = [
    'feature="compiler-builtins"',
    'feature="default"',
    'feature="rustc-dep-of-std"',
    'feature="unstable-intrinsics"',
    'feature="mem"',
    'feature="mem-unaligned"',
    "f16_enabled",
    "f128_enabled",
    "intrinsics_enabled",
    "arch_enabled",
]

# Flags shared by all three std crates. `--emit=link` -> `lib<name>.rlib`
# (no hash suffix), which `rust_stdlib_filegroup` partitions by basename.
#
# Bitcode is left embedded (rustc's default — no `-Cembed-bitcode=no`).
# The unikernel image can be built with LTO (`--//bazel/rules:lto`, off
# by default — see //bazel/rules:waitless.bzl and :variants.bzl); when
# it is, the final binary's LTO reaches `core` / `compiler_builtins` /
# `alloc` as crate deps, and without a `.llvmbc` section in these rlibs
# rustc aborts the link with "failed to get bitcode from object file
# for LTO (Can't find section .llvmbc)". This sysroot is built once by
# a repo rule that can't see the build flag, so bitcode is embedded
# unconditionally — harmless for non-LTO builds (a metadata section,
# not part of any loaded segment).
_COMMON_RUSTC_FLAGS = [
    "--crate-type",
    "lib",
    "--emit=link",
    "--edition",
    "2024",
    "-Cpanic=abort",
    "-Copt-level=3",
    "-Cdebug-assertions=off",
    "-Cstrip=debuginfo",
    "-Zforce-unstable-if-unmarked",
    "--cap-lints",
    "allow",
]

def _host(rctx):
    """(cpu, os, triple) of the host fetching this repo."""
    arch = rctx.os.arch.lower()
    if arch in ("amd64", "x86_64", "x64"):
        cpu = "x86_64"
    elif arch in ("aarch64", "arm64"):
        cpu = "aarch64"
    else:
        fail("hardfloat_sysroot: unsupported host CPU: " + arch)
    name = rctx.os.name.lower()
    if name.startswith("mac") or name == "darwin" or "os x" in name:
        return struct(cpu = cpu, os = "macos", triple = cpu + "-apple-darwin")
    if name.startswith("linux"):
        return struct(cpu = cpu, os = "linux", triple = cpu + "-unknown-linux-gnu")
    fail("hardfloat_sysroot: unsupported host OS: " + name)

def _build_crate(rctx, rustc, spec, crate, root, extra):
    """Compile one std crate into sysroot/lib<crate>.rlib."""
    res = rctx.execute(
        [rustc, "--crate-name", crate, root, "--out-dir", "sysroot"] +
        extra + _COMMON_RUSTC_FLAGS + ["--target", spec],
        environment = {"RUSTC_BOOTSTRAP": "1"},
        quiet = False,
    )
    if res.return_code != 0:
        fail("hardfloat_sysroot: compiling `{}` failed:\n{}\n{}".format(
            crate,
            res.stdout,
            res.stderr,
        ))

def _hardfloat_sysroot_impl(rctx):
    host = _host(rctx)

    # rust-src: the std crate sources, pinned to the toolchain version.
    rctx.download_and_extract(
        url = "https://static.rust-lang.org/dist/rust-src-{}.tar.xz".format(_RUST_SRC_VERSION),
        sha256 = _RUST_SRC_SHA256,
        stripPrefix = "rust-src-{}".format(_RUST_SRC_VERSION),
        output = "src",
    )

    # The hard-float target spec -- single source of truth, committed in-repo.
    # Kept under spec/ so it does not collide with the `<triple>.json` file
    # the rust_toolchain rule declares as an action output at repo root.
    #
    # rustc fingerprints a JSON target's *content* and folds the hash into
    # the crate-compat triple, so the spec the std crates are built against
    # must be byte-identical to the one rules_rust feeds the kernel build.
    # rules_rust re-emits it via `json.encode_indent(.., indent=4)`; mirror
    # that exactly here rather than writing the raw (2-space) committed file.
    target_json = rctx.read(rctx.attr.target_json)
    spec = "spec/{}.json".format(_TARGET_TRIPLE)
    rctx.file(spec, json.encode_indent(json.decode(target_json), indent = "    "))

    # rustc from the rules_rust host (== exec) toolchain download.
    host_tools = rctx.path(rctx.attr._host_tools_anchor).dirname
    rustc = "{}/bin/rustc".format(host_tools)
    if not rctx.path(rustc).exists:
        fail("hardfloat_sysroot: rustc not found at " + rustc)

    lib = "src/rust-src/lib/rustlib/src/rust/library"
    cb_cfgs = []
    for c in _COMPILER_BUILTINS_CFGS:
        cb_cfgs += ["--cfg", c]

    # core (#![no_core], no deps) -> compiler_builtins (needs core) ->
    # alloc (needs core + compiler_builtins).
    _build_crate(rctx, rustc, spec, "core", lib + "/core/src/lib.rs", [])
    _build_crate(
        rctx,
        rustc,
        spec,
        "compiler_builtins",
        lib + "/compiler-builtins/compiler-builtins/src/lib.rs",
        cb_cfgs + ["--extern", "core=sysroot/libcore.rlib"],
    )
    _build_crate(
        rctx,
        rustc,
        spec,
        "alloc",
        lib + "/alloc/src/lib.rs",
        [
            "-Zunstable-options",
            "--extern",
            "core=sysroot/libcore.rlib",
            "--extern",
            "compiler_builtins=sysroot/libcompiler_builtins.rlib",
        ],
    )

    rctx.file("BUILD.bazel", _BUILD_TEMPLATE
        .replace("%{triple}", _TARGET_TRIPLE)
        .replace("%{exec_triple}", host.triple)
        .replace("%{exec_cpu}", host.cpu)
        .replace("%{exec_os}", host.os)
        .replace("%{target_json}", target_json))

_BUILD_TEMPLATE = """\
# @generated by //bazel/buildstd:extensions.bzl -- do not edit.
# Hard-float x86_64 bare-metal Rust sysroot + toolchain (rust-lang/rust#116344).
load("@rules_rust//rust:toolchain.bzl", "rust_stdlib_filegroup", "rust_toolchain")

package(default_visibility = ["//visibility:public"])

# core / compiler_builtins / alloc, compiled from pinned rust-src against the
# hard-float %{triple}.json spec.
rust_stdlib_filegroup(
    name = "rust_std",
    srcs = glob(["sysroot/*.rlib"]),
)

# The rust_toolchain target name is, verbatim, the rustc target triple: the
# patched rules_rust writes the spec to `<name>.json` and rustc derives the
# triple from that filename.
rust_toolchain(
    name = "%{triple}",
    rust_std = ":rust_std",
    rustc = "@rust_host_tools//:rustc",
    rustc_lib = "@rust_host_tools//:rustc_lib",
    rust_doc = "@rust_host_tools//:rustdoc",
    linker = "@rust_host_tools//:rust-lld",
    linker_type = "direct",
    cargo = "@rust_host_tools//:cargo",
    rustfmt = "@rust_host_tools//:rustfmt_bin",
    clippy_driver = "@rust_host_tools//:clippy_driver_bin",
    cargo_clippy = "@rust_host_tools//:cargo_clippy_bin",
    llvm_cov = "@rust_host_tools//:llvm_cov_bin",
    llvm_profdata = "@rust_host_tools//:llvm_profdata_bin",
    llvm_lib = "@rust_host_tools//:llvm_lib",
    allocator_library = None,
    global_allocator_library = None,
    binary_ext = "",
    staticlib_ext = ".a",
    dylib_ext = ".so",
    stdlib_linkflags = [],
    default_edition = "2024",
    exec_triple = "%{exec_triple}",
    target_json = \"\"\"%{target_json}\"\"\",
    extra_rustc_flags = [],
    extra_exec_rustc_flags = [],
)

toolchain(
    name = "toolchain",
    exec_compatible_with = [
        "@platforms//cpu:%{exec_cpu}",
        "@platforms//os:%{exec_os}",
    ],
    target_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:none",
    ],
    toolchain = ":%{triple}",
    toolchain_type = "@rules_rust//rust:toolchain",
)
"""

_hardfloat_sysroot = repository_rule(
    implementation = _hardfloat_sysroot_impl,
    attrs = {
        "target_json": attr.label(
            allow_single_file = True,
            mandatory = True,
            doc = "Custom hard-float target-spec JSON.",
        ),
        "_host_tools_anchor": attr.label(
            default = "@rust_host_tools//:BUILD.bazel",
            doc = "Anchor to locate the rules_rust host rustc download.",
        ),
    },
    configure = True,
    doc = "Builds a hard-float x86_64 bare-metal sysroot and rust_toolchain.",
)

def _hardfloat_impl(module_ctx):
    target_json = None
    for mod in module_ctx.modules:
        for tc in mod.tags.toolchain:
            target_json = tc.target_json
    _hardfloat_sysroot(name = "hardfloat_x86_64_none", target_json = target_json)

hardfloat = module_extension(
    implementation = _hardfloat_impl,
    tag_classes = {
        "toolchain": tag_class(attrs = {
            "target_json": attr.label(allow_single_file = True, mandatory = True),
        }),
    },
    doc = "Hard-float x86_64 bare-metal sysroot + rust_toolchain.",
)
