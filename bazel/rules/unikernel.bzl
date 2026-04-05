"""Build rules for unikernel images.

Provides unikernel_binary() which links a Rust application library into
bootable kernel images for local testing (QEMU, VZ) and cloud deployment.
"""

load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")

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
        app: A rust_library target (e.g. ":webserver").
        visibility: Bazel visibility specification.
    """

    # ---- Unikernel ELF ----
    # The app's rust_library provides CcInfo (a .a with the uni_main symbol).
    # cc_binary links it with the kernel entry + boot assembly.
    cc_binary(
        name = name + ".elf",
        srcs = [],
        deps = [app, "//kernel:entry"],
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
    # Thin wrapper provides #[panic_handler]; app + uni linked as deps.
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
    cc_binary(
        name = name + ".limine.elf",
        srcs = [],
        deps = [app, "//kernel:entry"],
        linkopts = ["-Wl,-T,bazel/toolchain/unikernel_limine.ld"],
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
