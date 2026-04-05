"""Minimal CC toolchain for rules_rust linker resolution.

No C/C++ code is compiled. This toolchain exists because rules_rust
requires a registered CC toolchain to find the linker for each platform.
"""

load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load(
    "@rules_cc//cc:cc_toolchain_config_lib.bzl",
    "feature",
    "flag_group",
    "flag_set",
    "tool_path",
)

def _impl(ctx):
    is_macos = ctx.attr.target_os == "macos"
    gcc_tool = "wrapper/clang.sh" if is_macos else "wrapper/lld.sh"
    link_flags = ["-lc++"] if is_macos else ["-nostdlib"]

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        features = [
            feature(
                name = "default_link_flags",
                enabled = True,
                flag_sets = [flag_set(
                    actions = [
                        ACTION_NAMES.cpp_link_executable,
                        ACTION_NAMES.cpp_link_dynamic_library,
                        ACTION_NAMES.cpp_link_nodeps_dynamic_library,
                    ],
                    flag_groups = [flag_group(flags = link_flags)],
                )],
            ),
            feature(name = "supports_pic", enabled = ctx.attr.pic),
        ],
        toolchain_identifier = ctx.attr.name,
        host_system_name = "local",
        target_system_name = ctx.attr.target_system,
        target_cpu = ctx.attr.target_cpu,
        target_libc = ctx.attr.target_libc,
        compiler = "clang",
        abi_version = "unknown",
        abi_libc_version = "unknown",
        tool_paths = [
            tool_path(name = "gcc",     path = gcc_tool),
            tool_path(name = "ld",      path = gcc_tool),
            tool_path(name = "ar",      path = "/usr/bin/false"),
            tool_path(name = "cpp",     path = "/usr/bin/false"),
            tool_path(name = "gcov",    path = "/usr/bin/false"),
            tool_path(name = "nm",      path = "/usr/bin/false"),
            tool_path(name = "objdump", path = "/usr/bin/false"),
            tool_path(name = "strip",   path = "/usr/bin/false"),
        ],
    )

cc_toolchain_config = rule(
    implementation = _impl,
    attrs = {
        "target_cpu":    attr.string(mandatory = True),
        "target_os":     attr.string(mandatory = True),
        "target_system": attr.string(mandatory = True),
        "target_libc":   attr.string(default = "none"),
        "pic":           attr.bool(default = False),
    },
    provides = [CcToolchainConfigInfo],
)
