"""Shared Rust build configuration for unikernel crates.

Common rustc_flags (panic=abort, opt-level=2) are set globally in .bazelrc
via --@rules_rust//:extra_rustc_flags. This file provides the per-platform
flags that require select().
"""

# ARM64 unikernel targets need PIC for position-independent ELF
# (boot.S applies relocations at runtime). x86_64 and native don't.
#
# VZ-compat mode (--config=aarch64-vz): VZ.framework does not virtualize
# the exclusive monitor — both LDXR/STXR and LSE CAS/LDADD fault with DFSC
# 0x35 (unsupported exclusive/atomic access).  LDAR/STLR (load-acquire /
# store-release) work fine.  The vz_compat cfg gate replaces all CAS/RMW
# with load+store pairs; SPSC rings (LDAR/STLR only) are used for inbox
# distribution, which works correctly across vCPU threads.
UNIKERNEL_RUSTC_FLAGS = select({
    "//bazel/platforms:aarch64": ["-C", "relocation-model=pic"],
    "//conditions:default": [],
}) + select({
    "//bazel/platforms:runner_vz": ["--cfg", "vz_compat"],
    "//conditions:default": [],
})
