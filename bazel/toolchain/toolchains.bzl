"""Helper to register CC toolchains with minimal boilerplate."""

load(":cc_toolchain_config.bzl", "cc_toolchain_config")
load("@rules_cc//cc/toolchains:cc_toolchain.bzl", "cc_toolchain")

def register_cc_toolchain(name, arch, cpu, os):
    """Register a CC toolchain for a (cpu, os) pair."""
    cc_toolchain_config(name = name + "_config", target_arch = arch)
    cc_toolchain(
        name = name + "_impl",
        toolchain_config = ":" + name + "_config",
        all_files = ":all_files",
        ar_files = ":all_files",
        as_files = ":all_files",
        compiler_files = ":all_files",
        dwp_files = ":empty",
        linker_files = ":all_files",
        objcopy_files = ":empty",
        strip_files = ":empty",
    )
    native.toolchain(
        name = name,
        exec_compatible_with = ["@platforms//os:macos"],
        target_compatible_with = ["@platforms//cpu:" + cpu, "@platforms//os:" + os],
        toolchain = ":" + name + "_impl",
        toolchain_type = "@rules_cc//cc:toolchain_type",
    )
