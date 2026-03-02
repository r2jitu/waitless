"""Custom Clang toolchain configuration for x86_64 bare-metal unikernel."""

load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load(
    "@rules_cc//cc:cc_toolchain_config_lib.bzl",
    "feature",
    "flag_group",
    "flag_set",
    "tool_path",
)

# All C/C++ compile actions
_ALL_COMPILE_ACTIONS = [
    ACTION_NAMES.c_compile,
    ACTION_NAMES.cpp_compile,
    ACTION_NAMES.assemble,
    ACTION_NAMES.preprocess_assemble,
    ACTION_NAMES.cpp_header_parsing,
    ACTION_NAMES.cpp_module_compile,
    ACTION_NAMES.cpp_module_codegen,
]

# All link actions
_ALL_LINK_ACTIONS = [
    ACTION_NAMES.cpp_link_executable,
    ACTION_NAMES.cpp_link_dynamic_library,
    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
]

def _impl(ctx):
    arch = ctx.attr.target_arch

    tool_paths = [
        tool_path(name = "gcc",     path = "wrapper/clang_wrapper.sh"),
        tool_path(name = "ld",      path = "wrapper/ld_wrapper.sh"),
        tool_path(name = "ar",      path = "wrapper/ar_wrapper.sh"),
        tool_path(name = "cpp",     path = "/usr/bin/false"),
        tool_path(name = "gcov",    path = "/usr/bin/false"),
        tool_path(name = "nm",      path = "/usr/bin/false"),
        tool_path(name = "objdump", path = "/usr/bin/false"),
        tool_path(name = "strip",   path = "/usr/bin/false"),
    ]

    if arch == "aarch64":
        # Use linux-musl triple so Homebrew clang drives LLD for ELF output.
        # (-ffreestanding + -nostdlib ensures no Linux headers/libs are used.)
        arch_compile_flags = [
            "--target=aarch64-linux-musl",
            "-ffreestanding",
            "-nostdlib",
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-stack-protector",
            # Disable FP/NEON register usage by the compiler.
            # This is the standard approach for kernel code (same as Linux
            # CONFIG_KERNEL_MODE_NEON).  Without this, the compiler emits
            # 128-bit NEON stores (stur q0) to zero-initialise adjacent struct
            # fields; those stores require 16-byte alignment that kernel structs
            # do not guarantee → alignment fault (ESR DFSC=0x21).
            # -mgeneral-regs-only implies -fno-vectorize/-fno-slp-vectorize.
            "-mgeneral-regs-only",
            # Require all loads/stores to use naturally-aligned addresses.
            # Without this, the compiler may combine adjacent small-field writes
            # into a single unaligned 64-bit STUR (e.g. stur xzr, [x0, #0x2])
            # which faults on QEMU cortex-a57 even with SCTLR_EL1.A=0.
            "-mstrict-align",
            "-Wall",
            "-O2",
            "-g",
            "-D__UNIKERNEL__=1",
            "-D__aarch64__=1",
        ]
        linker_script = "bazel/toolchain/unikernel_arm64.ld"
        toolchain_id  = "unikernel-aarch64-toolchain"
        target_system = "aarch64-linux-musl"
        target_cpu    = "aarch64"
    else:
        arch_compile_flags = [
            "--target=x86_64-linux-musl",
            "-ffreestanding",
            "-nostdlib",
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-stack-protector",
            "-mno-red-zone",
            "-mcmodel=kernel",
            "-Wall",
            "-O2",
            "-g",
            "-D__UNIKERNEL__=1",
        ]
        linker_script = "bazel/toolchain/unikernel.ld"
        toolchain_id  = "unikernel-x86_64-toolchain"
        target_system = "x86_64-linux-musl"
        target_cpu    = "x86_64"

    default_compile_flags_feature = feature(
        name = "default_compile_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = _ALL_COMPILE_ACTIONS,
                flag_groups = [flag_group(flags = arch_compile_flags)],
            ),
        ],
    )

    default_link_flags_feature = feature(
        name = "default_link_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = _ALL_LINK_ACTIONS,
                flag_groups = [
                    flag_group(
                        flags = [
                            # --target must be present at link time too so
                            # clang drives ld.lld (ELF) not ld64.lld (MachO).
                            "--target=" + target_system,
                            "-fuse-ld=lld",
                            "-nostdlib",
                            "-static",
                            "-Wl,-z,max-page-size=0x1000",
                            "-Wl,-T," + linker_script,
                        ],
                    ),
                ],
            ),
        ],
    )

    supports_pic_feature = feature(name = "supports_pic", enabled = False)

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        features = [
            default_compile_flags_feature,
            default_link_flags_feature,
            supports_pic_feature,
        ],
        toolchain_identifier = toolchain_id,
        host_system_name = "aarch64-apple-darwin",
        target_system_name = target_system,
        target_cpu = target_cpu,
        target_libc = "none",
        compiler = "clang",
        abi_version = "unknown",
        abi_libc_version = "unknown",
        tool_paths = tool_paths,
        # Homebrew LLVM's clang resource dir contains stdint.h, stddef.h, etc.
        # Declaring it here lets Bazel's sandbox hermetic check accept them.
        cxx_builtin_include_directories = [
            "/opt/homebrew/Cellar/llvm/22.1.0/lib/clang/22/include",
        ],
    )

cc_toolchain_config = rule(
    implementation = _impl,
    attrs = {
        "target_arch": attr.string(
            default = "x86_64",
            values = ["x86_64", "aarch64"],
        ),
    },
    provides = [CcToolchainConfigInfo],
)
