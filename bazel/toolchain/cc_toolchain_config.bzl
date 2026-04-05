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

# Target configurations: (toolchain_id, target_system, target_cpu, target_libc)
_TARGETS = {
    "x86_64":      ("unikernel-x86_64", "x86_64-linux-musl",    "x86_64",  "none"),
    "aarch64":     ("unikernel-aarch64", "aarch64-linux-musl",   "aarch64", "none"),
    "x86_64_linux":("x86_64-linux",      "x86_64-unknown-linux-musl", "x86_64", "musl"),
    "aarch64_macos":("aarch64-macos",    "aarch64-apple-darwin", "aarch64", "macosx"),
}

def _impl(ctx):
    arch = ctx.attr.target_arch
    toolchain_id, target_system, target_cpu, target_libc = _TARGETS[arch]

    if arch == "aarch64_macos":
        # macOS native: use system clang
        gcc_tool = "wrapper/clang_wrapper.sh"
        link_flags = ["-lc++"]
    else:
        # Bare-metal + Linux: use Rust's ld.lld
        gcc_tool = "wrapper/lld.sh"
        link_flags = ["-nostdlib"]

    tool_paths = [
        tool_path(name = "gcc",     path = gcc_tool),
        tool_path(name = "ld",      path = gcc_tool),
        tool_path(name = "ar",      path = "/usr/bin/false"),
        tool_path(name = "cpp",     path = "/usr/bin/false"),
        tool_path(name = "gcov",    path = "/usr/bin/false"),
        tool_path(name = "nm",      path = "/usr/bin/false"),
        tool_path(name = "objdump", path = "/usr/bin/false"),
        tool_path(name = "strip",   path = "/usr/bin/false"),
    ]

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
            feature(name = "supports_pic", enabled = (arch == "aarch64")),
        ],
        toolchain_identifier = toolchain_id,
        host_system_name = "local",
        target_system_name = target_system,
        target_cpu = target_cpu,
        target_libc = target_libc,
        compiler = "clang",
        abi_version = "unknown",
        abi_libc_version = "unknown",
        tool_paths = tool_paths,
    )

cc_toolchain_config = rule(
    implementation = _impl,
    attrs = {
        "target_arch": attr.string(
            values = ["x86_64", "aarch64", "aarch64_macos", "x86_64_linux"],
        ),
    },
    provides = [CcToolchainConfigInfo],
)
