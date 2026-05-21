# Consuming Waitless as a Bazel library

The `apps/` in this repo are examples. The intended way to build a real
Waitless app is a **separate repository** that depends on this one as a
Bazel module and calls the `unikernel_binary` rule. This page covers the
boilerplate every external app must supply itself.

## Why an external app needs boilerplate

`unikernel_binary` and the `rust_*` wrappers in
[`bazel/rules/`](../bazel/rules) are repo-hygienic — every label they
emit internally is a `Label()` object bound to `@waitless`, so an app
calling them resolves `//crates/boot:entry`, `//crates/waitless`, the linker
scripts, etc. against Waitless's repo, not its own. No mirror `alias()`
packages required.

But some Bazel mechanisms are read **only from the root module** — the
module you actually invoke `bazel` in. Waitless can't provide those for
you; the consuming app must re-declare them. Everything below is exactly
that set.

## What the app's `MODULE.bazel` must declare

```python
module(name = "myapp", version = "0.0.0")

# 1. Depend on waitless + point Bazel at the checkout. Any override
#    works (git_override, archive_override); local_path_override is the
#    simplest for a sibling checkout.
bazel_dep(name = "waitless", version = "0.1.0")
local_path_override(
    module_name = "waitless",
    path = "../waitless",
)

# 2. Depend on rules_rust at the SAME version Waitless uses.
bazel_dep(name = "rules_rust", version = "0.69.0")

# 3. Re-declare the rules_rust patch override. `single_version_override`
#    (and the patch files it names) is honored ONLY from the root
#    module — Waitless's copy is ignored when it is a dependency.
#    Copy both patches out of Waitless's `bazel/patches/` into your own
#    repo and reference your local copies:
#      - rules_rust_aarch64_none.patch       (adds aarch64-unknown-none)
#      - rules_rust_target_json_name.patch   (clean custom-target name)
single_version_override(
    module_name = "rules_rust",
    patch_strip = 1,
    patches = [
        "//bazel/patches:rules_rust_aarch64_none.patch",
        "//bazel/patches:rules_rust_target_json_name.patch",
    ],
)

# 4. Re-declare the `rust` toolchain extension tags. The `rust`
#    extension reads `rust.toolchain(...)` tags ONLY from the root
#    module, so Waitless's declaration does not reach your build.
#    Match Waitless's MODULE.bazel exactly: same edition, same
#    `versions`, same `extra_target_triples`.
rust = use_extension("@rules_rust//rust:extensions.bzl", "rust")
rust.toolchain(
    edition = "2024",
    extra_target_triples = [
        "aarch64-unknown-none",
        "x86_64-unknown-linux-musl",
    ],
    versions = ["1.93.1"],
)
use_repo(rust, "rust_toolchains")
```

If Waitless ever bumps `rules_rust`, its patch set, the Rust toolchain
version, the edition, or `extra_target_triples`, every consuming app must
update its `MODULE.bazel` to match.

## What the app does NOT repeat

`register_toolchains` / `register_execution_platforms` calls and the
`crate` (crate_universe) and `hardfloat` (x86_64 hard-float sysroot)
module extensions **accumulate across the whole module graph**. Waitless
declares them, and an app depending on Waitless inherits them — so an
app must *not* re-declare:

- the `register_toolchains(...)` lines (CC toolchains, the hard-float
  toolchain, `@rust_toolchains//:all`),
- `register_execution_platforms(...)`,
- the `crate.from_cargo(...)` / `crate.annotation*` block,
- the `hardfloat.toolchain(...)` block.

Re-declaring those would double-register or conflict. The split is
simply: **toolchain *tags* and *overrides* = root-only, re-declare them;
*registrations* and *extensions* = graph-wide, inherit them.**

## The app's `BUILD.bazel`

Once `MODULE.bazel` is set up, the `BUILD.bazel` is short — load the
rule and call it. See [`apps/hello/BUILD.bazel`](../apps/hello/BUILD.bazel)
for the minimal example:

```python
load("@rules_rust//rust:defs.bzl", "rust_library")
load("@waitless//bazel/rules:unikernel.bzl", "port_fwd", "unikernel_binary")

rust_library(
    name = "app",
    srcs = ["src/main.rs"],
    crate_root = "src/main.rs",
    deps = [
        "@waitless//crates/proto/http",
        "@waitless//crates/waitless",
    ],
)

unikernel_binary(
    name = "myapp",
    app = ":app",
    drivers = ["@waitless//crates/drivers/virtio-net"],
    port_forwards = [port_fwd("tcp", guest = 80, host = 8080)],
)
```

In-tree apps write `//crates/waitless` because they *are* in Waitless's repo;
external apps write `@waitless//crates/waitless` so the label resolves to the
dependency. `unikernel_binary` then produces the usual variant targets
(`:myapp_hvf`, `:myapp_iso_x86_64`, `:myapp_qemu_aarch64`, …), runnable
with plain `bazel run` / `bazel test`.
