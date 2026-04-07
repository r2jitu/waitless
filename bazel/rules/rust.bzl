"""Shared Rust build configuration for unikernel crates.

Common rustc_flags (panic=abort, opt-level=2) are set globally in .bazelrc
via --@rules_rust//:extra_rustc_flags. This file provides the per-platform
flags that require select().
"""

# ARM64 unikernel targets need PIC for position-independent ELF
# (boot.S applies relocations at runtime). x86_64 and native don't.
#
# VZ-compat mode (--config=aarch64-vz) disables Tier 2 packet
# distribution because VZ.framework has inbox visibility issues
# across vCPU threads. Networking runs single-core; compute (service
# callbacks) still runs on all cores.
UNIKERNEL_RUSTC_FLAGS = select({
    "//bazel/platforms:aarch64": ["-C", "relocation-model=pic"],
    "//conditions:default": [],
}) + select({
    "//bazel/platforms:runner_vz": ["--cfg", "vz_compat"],
    "//conditions:default": [],
})
