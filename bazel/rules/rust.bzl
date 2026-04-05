"""Shared Rust build configuration for unikernel crates.

Common rustc_flags (panic=abort, opt-level=2) are set globally in .bazelrc
via --@rules_rust//:extra_rustc_flags. This file provides the per-platform
flags that require select().
"""

# ARM64 unikernel targets need PIC for position-independent ELF
# (boot.S applies relocations at runtime). x86_64 and native don't.
UNIKERNEL_RUSTC_FLAGS = select({
    "//bazel/platforms:aarch64": ["-C", "relocation-model=pic"],
    "//conditions:default": [],
})
