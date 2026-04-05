"""Build rules for unikernel images.

Provides unikernel_binary() which links a Rust application library into
bootable kernel images using rustc + rust-lld (no C++ toolchain for linking).
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")
load("//bazel/rules:rust.bzl", "UNIKERNEL_RUSTC_FLAGS")

# Linker flags shared by all unikernel binaries.
_LINK_FLAGS = [
    "-C", "link-arg=--gc-sections",
    "-C", "link-arg=--allow-multiple-definition",
    "-C", "link-arg=-zmax-page-size=0x1000",
    "-C", "link-arg=-znorelro",
    "-C", "link-arg=-nostdlib",
    "-C", "link-arg=--strip-debug",
]

_LINK_FLAGS_ARCH = select({
    "//bazel/platforms:aarch64": ["-C", "link-arg=-pie", "-C", "link-arg=-znotext"],
    "//conditions:default": ["-C", "link-arg=-static", "-C", "link-arg=--no-pie"],
})

def unikernel_binary(name, app, visibility = None):
    """Build a unikernel from a Rust application library.

    The application is a rust_library that exports:
        #[unsafe(no_mangle)] pub extern "C" fn uni_main() -> i32

    Targets produced:
      - <name>.elf        : Bare-metal ELF kernel binary
      - <name>.limine.elf : Higher-half ELF for Limine boot
      - <name>.img        : Raw binary (for QEMU -kernel / VZ)
      - <name>.iso        : Limine-bootable ISO
      - <name>_native     : Native POSIX binary (no VM)
      - <name>_run        : Launch with runner selected by --config

    Args:
        name: Base name for all output targets.
        app: A rust_library target (e.g. ":app").
        visibility: Bazel visibility specification.
    """

    # Common deps for unikernel binaries (Rust static libs + linker scripts).
    _unikernel_deps = [
        app,
        "//kernel:entry_rs",
        "//kernel:limine_rs",
        "//kernel:libc_rs",
    ]

    # ---- Unikernel ELF ----
    # rust_binary links via rustc → rust-lld. Assembly is included via
    # global_asm!(include_str!(...)) in the Rust crates — no cc_library needed.
    rust_binary(
        name = name + ".elf",
        crate_name = name + "_elf",
        srcs = ["//bazel/rules:unikernel_main.rs"],
        deps = _unikernel_deps,
        linker_script = select({
            "//bazel/platforms:aarch64": "//bazel/toolchain:unikernel_arm64.ld",
            "//conditions:default": "//bazel/toolchain:unikernel.ld",
        }),
        rustc_flags = UNIKERNEL_RUSTC_FLAGS + _LINK_FLAGS + _LINK_FLAGS_ARCH,
        visibility = visibility,
    )

    # Flat binary for ARM64 bootloaders (VZ.framework, QEMU -kernel).
    native.genrule(
        name = name + ".img",
        srcs = [":" + name + ".elf"],
        outs = [name + ".img"],
        cmd = """
            OC=""
            for p in /opt/homebrew/opt/llvm/bin/llvm-objcopy \
                     /usr/local/bin/llvm-objcopy \
                     /usr/bin/llvm-objcopy \
                     llvm-objcopy; do
                if command -v "$$p" >/dev/null 2>&1 || [ -x "$$p" ]; then
                    OC=$$p; break
                fi
            done
            if [ -z "$$OC" ]; then
                echo "ERROR: llvm-objcopy not found. Install: brew install llvm" >&2
                exit 1
            fi
            $$OC -O binary $(location :{name_elf}) $@
        """.format(name_elf = name + ".elf"),
        visibility = visibility,
    )

    # ---- Native POSIX binary ----
    rust_binary(
        name = name + "_native",
        srcs = ["//bazel/rules:native_main.rs"],
        deps = [app, "//uni"],
        rustc_flags = select({
            "@platforms//os:macos": ["-C", "link-arg=-lSystem"],
            "//conditions:default": ["-C", "link-arg=-lc", "-C", "link-arg=-lpthread"],
        }),
        target_compatible_with = ["//bazel/platforms:native"],
        visibility = visibility,
    )

    # ---- Unified run target ----
    sh_binary(
        name = name + "_run",
        srcs = select({
            "//bazel/platforms:runner_vz":   ["//bazel/rules:run_vz.sh"],
            "//bazel/platforms:runner_qemu": ["//bazel/rules:run_qemu.sh"],
            "//bazel/platforms:runner_iso":  ["//bazel/rules:run_iso.sh"],
            "//conditions:default":          ["//bazel/rules:run_native.sh"],
        }),
        data = select({
            "//bazel/platforms:runner_vz": [
                ":" + name + ".img",
                "//scripts:run_vz",
            ],
            "//bazel/platforms:runner_qemu": [
                ":" + name + ".elf",
                ":" + name + ".img",
            ],
            "//bazel/platforms:runner_iso": [
                ":" + name + ".iso",
            ],
            "//conditions:default": [
                ":" + name + "_native",
            ],
        }),
        env = select({
            "//bazel/platforms:runner_vz": {
                "UNIKERNEL_IMG_RELPATH": native.package_name() + "/" + name + ".img",
                "UNIKERNEL_VZ_RELPATH":  "scripts/run-vz",
            },
            "//bazel/platforms:runner_qemu": {
                "UNIKERNEL_ELF_RELPATH": native.package_name() + "/" + name + ".elf",
                "UNIKERNEL_IMG_RELPATH": native.package_name() + "/" + name + ".img",
            },
            "//bazel/platforms:runner_iso": {
                "UNIKERNEL_ISO_RELPATH": native.package_name() + "/" + name + ".iso",
            },
            "//conditions:default": {
                "UNIKERNEL_NATIVE_RELPATH": native.package_name() + "/" + name + "_native",
            },
        }),
        visibility = visibility,
    )

    # ---- Higher-half ELF for Limine boot ----
    # Uses both the base linker script (via linker_script attr) and the
    # supplemental Limine script (via -C link-arg=-T).
    rust_binary(
        name = name + ".limine.elf",
        crate_name = name + "_limine_elf",
        srcs = ["//bazel/rules:unikernel_main.rs"],
        deps = _unikernel_deps,
        data = ["//bazel/toolchain:unikernel_limine.ld"],
        linker_script = "//bazel/toolchain:unikernel.ld",
        rustc_flags = UNIKERNEL_RUSTC_FLAGS + _LINK_FLAGS + _LINK_FLAGS_ARCH + [
            "-C", "link-arg=-T", "-C", "link-arg=bazel/toolchain/unikernel_limine.ld",
        ],
        visibility = visibility,
    )

    # ---- Limine-bootable ISO ----
    native.genrule(
        name = name + ".iso",
        srcs = select({
            "//bazel/platforms:aarch64": [
                ":" + name + ".elf",
                "//boot:limine.conf",
            ],
            "//conditions:default": [
                ":" + name + ".limine.elf",
                "//boot:limine.conf",
            ],
        }),
        outs = [name + ".iso"],
        cmd = select({
            "//bazel/platforms:aarch64": """
                $(location //scripts:make_limine_iso) \
                    $(location :{name_elf}) $@ \
                    --arch aarch64 --conf $(location //boot:limine.conf)
            """.format(name_elf = name + ".elf"),
            "//conditions:default": """
                $(location //scripts:make_limine_iso) \
                    $(location :{name_limine_elf}) $@ \
                    --arch x86_64 --conf $(location //boot:limine.conf)
            """.format(name_limine_elf = name + ".limine.elf"),
        }),
        tools = ["//scripts:make_limine_iso"],
        local = True,
        visibility = visibility,
    )
