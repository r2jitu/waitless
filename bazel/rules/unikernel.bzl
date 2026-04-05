"""Build rules for unikernel images.

Provides unikernel_binary() which packages a Rust application library
into bootable kernel images using rustc + rust-lld.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")
load("//bazel/rules:rust.bzl", "UNIKERNEL_RUSTC_FLAGS")

# Bare-metal linker flags (passed to rust-lld via -C link-arg).
_LINK_FLAGS = [
    "-C", "linker-flavor=ld.lld",
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
    """Package a Rust application into bootable unikernel images.

    The application is a rust_library with a #[uni::main] entry point.

    Targets produced:
      - <name>.elf        : Bare-metal ELF (QEMU direct boot, VZ)
      - <name>.img        : Raw binary (ARM64 VZ.framework / QEMU -kernel)
      - <name>.limine.elf : Higher-half ELF (Limine bootloader)
      - <name>.iso        : Limine-bootable ISO (BIOS + UEFI)
      - <name>_native     : Native POSIX binary (host OS, no VM)
      - <name>_run        : Unified launcher (runner selected by --config)

    Args:
        name: Base name for all output targets.
        app: A rust_library target with a #[uni::main] entry point.
        visibility: Bazel visibility specification.
    """

    _unikernel_deps = [app, "//kernel:entry", "//kernel:limine", "//kernel:libc"]
    _unikernel_flags = UNIKERNEL_RUSTC_FLAGS + _LINK_FLAGS + _LINK_FLAGS_ARCH

    # ── Unikernel ELF ────────────────────────────────────────────────────
    rust_binary(
        name = name + ".elf",
        crate_name = name + "_elf",
        srcs = ["//bazel/rules:unikernel_main.rs"],
        deps = _unikernel_deps,
        linker_script = select({
            "//bazel/platforms:aarch64": "//bazel/toolchain:unikernel_arm64.ld",
            "//conditions:default": "//bazel/toolchain:unikernel.ld",
        }),
        rustc_flags = _unikernel_flags,
        visibility = visibility,
    )

    # ── Raw binary (ELF → flat image for ARM64 bootloaders) ──────────────
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
                echo "ERROR: llvm-objcopy not found" >&2; exit 1
            fi
            $$OC -O binary $(location :{name_elf}) $@
        """.format(name_elf = name + ".elf"),
        visibility = visibility,
    )

    # ── Limine higher-half ELF (x86_64 Limine boot) ─────────────────────
    rust_binary(
        name = name + ".limine.elf",
        crate_name = name + "_limine_elf",
        srcs = ["//bazel/rules:unikernel_main.rs"],
        deps = _unikernel_deps,
        data = ["//bazel/toolchain:unikernel_limine.ld"],
        linker_script = "//bazel/toolchain:unikernel.ld",
        rustc_flags = _unikernel_flags + [
            "-C", "link-arg=-T", "-C", "link-arg=bazel/toolchain/unikernel_limine.ld",
        ],
        visibility = visibility,
    )

    # ── Limine ISO (BIOS + UEFI hybrid) ─────────────────────────────────
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

    # ── Native POSIX binary ──────────────────────────────────────────────
    rust_binary(
        name = name + "_native",
        srcs = ["//bazel/rules:native_main.rs"],
        deps = [app, "//uni"],
        rustc_flags = select({
            "@platforms//os:macos": ["-C", "link-arg=-lSystem"],
            # Linux musl: static binary, no external sysroot needed.
            # Rust ships a self-contained musl libc + crt.
            "//conditions:default": [
                "-C", "linker-flavor=ld.lld",
                "-C", "target-feature=+crt-static",
                "-C", "link-arg=-lc",
            ],
        }),
        target_compatible_with = ["//bazel/platforms:native"],
        visibility = visibility,
    )

    # ── Unified launcher ─────────────────────────────────────────────────
    sh_binary(
        name = name + "_run",
        srcs = select({
            "//bazel/platforms:runner_vz":   ["//bazel/rules:run_vz.sh"],
            "//bazel/platforms:runner_qemu": ["//bazel/rules:run_qemu.sh"],
            "//bazel/platforms:runner_iso":  ["//bazel/rules:run_iso.sh"],
            "//conditions:default":          ["//bazel/rules:run_native.sh"],
        }),
        data = select({
            "//bazel/platforms:runner_vz":   [":" + name + ".img", "//scripts:run_vz"],
            "//bazel/platforms:runner_qemu": [":" + name + ".elf", ":" + name + ".img"],
            "//bazel/platforms:runner_iso":  [":" + name + ".iso"],
            "//conditions:default":          [":" + name + "_native"],
        }),
        env = select({
            "//bazel/platforms:runner_vz": {
                "UNIKERNEL_IMG_RELPATH": native.package_name() + "/" + name + ".img",
                "UNIKERNEL_VZ_RELPATH": "scripts/run-vz",
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
