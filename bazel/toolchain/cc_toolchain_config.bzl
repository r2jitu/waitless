"""Minimal CC toolchain for rules_rust linker resolution.

No C/C++ code is compiled — this toolchain exists solely because
rules_rust requires a registered CC toolchain to find the linker.
The clang_wrapper.sh detects when rustc invokes it as a linker
(-flavor gnu) and dispatches to ld.lld directly.
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

_LINK_ACTIONS = [
    ACTION_NAMES.cpp_link_executable,
    ACTION_NAMES.cpp_link_dynamic_library,
    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
]

def _impl(ctx):
    arch = ctx.attr.target_arch

    if arch == "aarch64_macos":
        tool_paths = [
            tool_path(name = "gcc",     path = "wrapper/clang_wrapper.sh"),
            tool_path(name = "ld",      path = "/usr/bin/ld"),
            tool_path(name = "ar",      path = "/usr/bin/libtool"),
            tool_path(name = "cpp",     path = "/usr/bin/false"),
            tool_path(name = "gcov",    path = "/usr/bin/false"),
            tool_path(name = "nm",      path = "/usr/bin/nm"),
            tool_path(name = "objdump", path = "/usr/bin/false"),
            tool_path(name = "strip",   path = "/usr/bin/strip"),
        ]
        link_flags = ["-lc++"]
        toolchain_id = "aarch64-macos-toolchain"
        target_system = "aarch64-apple-darwin"
        target_cpu = "aarch64"
        target_libc = "macosx"
    else:
        tool_paths = [
            tool_path(name = "gcc",     path = "wrapper/clang_wrapper.sh"),
            tool_path(name = "ld",      path = "wrapper/clang_wrapper.sh"),
            tool_path(name = "ar",      path = "/usr/bin/false"),
            tool_path(name = "cpp",     path = "/usr/bin/false"),
            tool_path(name = "gcov",    path = "/usr/bin/false"),
            tool_path(name = "nm",      path = "/usr/bin/false"),
            tool_path(name = "objdump", path = "/usr/bin/false"),
            tool_path(name = "strip",   path = "/usr/bin/false"),
        ]
        link_flags = ["-nostdlib"]
        if arch == "aarch64":
            toolchain_id = "unikernel-aarch64-toolchain"
            target_system = "aarch64-linux-musl"
            target_cpu = "aarch64"
        else:
            toolchain_id = "unikernel-x86_64-toolchain"
            target_system = "x86_64-linux-musl"
            target_cpu = "x86_64"
        target_libc = "none"

    link_feature = feature(
        name = "default_link_flags",
        enabled = True,
        flag_sets = [flag_set(
            actions = _LINK_ACTIONS,
            flag_groups = [flag_group(flags = link_flags)],
        )],
    )

    pic_feature = feature(name = "supports_pic", enabled = (arch == "aarch64"))

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        features = [link_feature, pic_feature],
        toolchain_identifier = toolchain_id,
        host_system_name = "aarch64-apple-darwin",
        target_system_name = target_system,
        target_cpu = target_cpu,
        target_libc = target_libc,
        compiler = "clang",
        abi_version = "unknown",
        abi_libc_version = "unknown",
        tool_paths = tool_paths,
        cxx_builtin_include_directories = [
            "/opt/homebrew/Cellar/llvm/22.1.0/lib/clang/22/include",
        ] + ([
            "/opt/homebrew/Cellar/llvm/22.1.0/include/c++/v1",
            "/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk/usr/include",
            "/Library/Developer/CommandLineTools/usr/include",
        ] if arch == "aarch64_macos" else []),
    )

cc_toolchain_config = rule(
    implementation = _impl,
    attrs = {
        "target_arch": attr.string(
            default = "x86_64",
            values = ["x86_64", "aarch64", "aarch64_macos"],
        ),
    },
    provides = [CcToolchainConfigInfo],
)
