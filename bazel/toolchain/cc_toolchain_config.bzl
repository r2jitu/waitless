"""Custom Clang toolchain configuration for x86_64 bare-metal unikernel."""

load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
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

    if arch == "aarch64_macos":
        # Native macOS: use system libtool (macOS archive format: libtool -static)
        # and Apple ld via the clang driver (no ELF linker wrapper needed).
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
    else:
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
            # PIE: generate position-independent code so the kernel can be
            # loaded at any physical address (QEMU: 0x40000000, VZ: 0x00000000).
            # boot.S processes .rela.dyn at startup to fix absolute pointers.
            # LLD resolves all GOT entries at link time; no dynamic linker needed.
            "-fPIC",
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
            "-Wextra",
            "-Werror",
            "-Wshadow",
            "-Wno-unused-parameter",  # kernel callbacks must match fixed signatures
            "-O2",
            "-g",
            "-D__UNIKERNEL__=1",
            "-D__aarch64__=1",
        ]
        linker_script = "bazel/toolchain/unikernel_arm64.ld"
        toolchain_id  = "unikernel-aarch64-toolchain"
        target_system = "aarch64-linux-musl"
        target_cpu    = "aarch64"
    elif arch == "aarch64_macos":
        # Native macOS arm64 binary — host toolchain, no bare-metal restrictions.
        arch_compile_flags = [
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wshadow",
            "-Wno-unused-parameter",
            "-O2",
            "-g",
        ]
        linker_script = None
        toolchain_id  = "aarch64-macos-toolchain"
        target_system = "aarch64-apple-darwin"
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
            "-Wextra",
            "-Werror",
            "-Wshadow",
            "-Wno-unused-parameter",  # kernel callbacks must match fixed signatures
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

    if arch == "aarch64_macos":
        # Native macOS: clang driver defaults to Apple ld + system SDK.
        # No special linker flags needed — just link the C++ runtime.
        link_flag_list = ["-lc++"]
    else:
        link_flag_list = [
            # --target must be present at link time too so
            # clang drives ld.lld (ELF) not ld64.lld (MachO).
            "--target=" + target_system,
            "-fuse-ld=lld",
            "-nostdlib",
        ] + (["-pie", "-Wl,-z,notext"] if arch == "aarch64" else ["-static"]) + [
            "-Wl,-z,norelro",
            "-Wl,--allow-multiple-definition",
            "-Wl,-z,max-page-size=0x1000",
            "-Wl,-T," + linker_script,
        ]

    default_link_flags_feature = feature(
        name = "default_link_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = _ALL_LINK_ACTIONS,
                flag_groups = [flag_group(flags = link_flag_list)],
            ),
        ],
    )

    # aarch64 unikernel uses -fPIC/--pie for position-independent kernel.
    # aarch64_macos (native) uses default PIC (position-dependent MachO is fine).
    # x86_64 uses -mcmodel=kernel (large PIE model) so PIC is not needed there.
    supports_pic_feature = feature(name = "supports_pic", enabled = (arch == "aarch64"))

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
        target_libc = "macosx" if arch == "aarch64_macos" else "none",
        compiler = "clang",
        abi_version = "unknown",
        abi_libc_version = "unknown",
        tool_paths = tool_paths,
        # Homebrew LLVM's clang resource dir contains stdint.h, stddef.h, etc.
        # Declaring it here lets Bazel's sandbox hermetic check accept them.
        # For native macOS also include the CommandLineTools SDK headers.
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
