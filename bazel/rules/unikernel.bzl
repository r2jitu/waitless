"""Build rules for unikernel images.

Provides unikernel_binary() which compiles a bare-metal ELF kernel and
produces bootable images for local testing (QEMU, VZ) and cloud deployment
(Limine ISO/disk).
"""

load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")

def unikernel_binary(name, srcs, deps = [], copts = [], visibility = None):
    """Build a unikernel ELF binary from application sources.

    Targets produced:
      - <name>.elf        : Bare-metal ELF kernel binary (identity-mapped)
      - <name>.limine.elf : Higher-half ELF for Limine boot
      - <name>.img        : Raw binary (objcopy, for QEMU -kernel / VZ)
      - <name>_run        : Launch with auto-detected runner (QEMU or VZ)
      - <name>_run_vz     : Launch with VZ.framework (macOS arm64)
      - <name>_run_qemu   : Launch with QEMU (auto-detects arch)
      - <name>_run_iso    : Launch Limine ISO with QEMU (x86_64)
      - <name>.iso        : Limine-bootable ISO (BIOS+UEFI, for cloud/QEMU)

    Args:
        name: Base name for all output targets.
        srcs: Application source files (typically main.cc).
        deps: Additional dependencies beyond the kernel runtime.
        copts: Additional compiler flags.
        visibility: Bazel visibility specification.
    """
    cc_binary(
        name = name + ".elf",
        srcs = srcs,
        deps = deps + [
            "//kernel:entry",
            "//kernel:boot",
            "//kernel:core",
            "//kernel:arch_init",
            "//drivers:virtio_net",
            "//net",
        ],
        copts = copts,
        linkopts = [],
        visibility = visibility,
    )

    # Flat binary image for ARM64 bootloaders (VZ.framework, QEMU -kernel).
    # Converts ELF → raw binary via llvm-objcopy at build time so the
    # runtime tools (run-vz, run-local.sh) don't need to do it themselves.
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

    # "bazel run //apps/<name>:run" — auto-detects runner:
    #   macOS arm64  → VZ.framework (hardware-accelerated via run-vz)
    #   everything else → QEMU (via detect_qemu in helpers.sh)
    sh_binary(
        name = name + "_run",
        srcs = ["//bazel/rules:run_wrapper.sh"],
        data = [":" + name + ".elf"] + select({
            # macOS arm64: include VZ runner + raw image (more specific than :aarch64).
            "//bazel/platforms:macos_arm64": [
                ":" + name + ".img",
                "//scripts:run_vz",
            ],
            # Other arm64 (Linux): raw image for QEMU -kernel (PIE ELF loads wrong).
            "//bazel/platforms:aarch64": [
                ":" + name + ".img",
            ],
            "//conditions:default": [],
        }),
        env = {
            "UNIKERNEL_ELF_RELPATH": native.package_name() + "/" + name + ".elf",
            "UNIKERNEL_IMG_RELPATH": native.package_name() + "/" + name + ".img",
            "UNIKERNEL_VZ_RELPATH": "scripts/run-vz",
        },
        visibility = visibility,
    )

    # "bazel run //apps/<name>:run_vz" — VZ.framework (macOS arm64 only)
    sh_binary(
        name = name + "_run_vz",
        srcs = ["//bazel/rules:run_vz.sh"],
        data = [
            ":" + name + ".img",
            "//scripts:run_vz",
        ],
        env = {
            "UNIKERNEL_IMG_RELPATH": native.package_name() + "/" + name + ".img",
            "UNIKERNEL_VZ_RELPATH": "scripts/run-vz",
        },
        target_compatible_with = [
            "@platforms//cpu:aarch64",
            "//bazel/platforms:host_macos",
        ],
        visibility = visibility,
    )

    # "bazel run //apps/<name>:run_qemu" — QEMU (auto-detects arch from ELF)
    sh_binary(
        name = name + "_run_qemu",
        srcs = ["//bazel/rules:run_qemu.sh"],
        data = [":" + name + ".elf"] + select({
            "//bazel/platforms:aarch64": [":" + name + ".img"],
            "//conditions:default": [],
        }),
        env = {
            "UNIKERNEL_ELF_RELPATH": native.package_name() + "/" + name + ".elf",
            "UNIKERNEL_IMG_RELPATH": native.package_name() + "/" + name + ".img",
        },
        visibility = visibility,
    )

    # "bazel run //apps/<name>:run_iso" — Limine ISO via QEMU (x86_64)
    sh_binary(
        name = name + "_run_iso",
        srcs = ["//bazel/rules:run_iso.sh"],
        data = select({
            "//bazel/platforms:aarch64": [
                ":" + name + ".elf",
                ":" + name + ".iso",
            ],
            "//conditions:default": [
                ":" + name + ".limine.elf",
                ":" + name + ".iso",
            ],
        }),
        env = {
            "UNIKERNEL_ISO_RELPATH": native.package_name() + "/" + name + ".iso",
        },
        visibility = visibility,
    )

    # Higher-half ELF for Limine boot.
    # Limine revision 3 requires kernel virtual addresses >= 0xFFFF800000000000.
    # This target re-links the same sources with a supplemental linker script
    # that overrides __kernel_base to place the kernel in the top-2GB region.
    # Excludes //kernel:boot (boot.S) because its 32-bit entry code uses
    # R_X86_64_32 relocations that can't reach higher-half addresses.
    # Limine enters at limine_entry() directly — boot.S is not needed.
    cc_binary(
        name = name + ".limine.elf",
        srcs = srcs,
        deps = deps + [
            "//kernel:entry",
            "//kernel:core",
            "//kernel:arch_init",
            "//drivers:virtio_net",
            "//net",
        ],
        copts = copts,
        linkopts = ["-Wl,-T,bazel/toolchain/unikernel_limine.ld"],
        visibility = visibility,
    )

    # Limine-bootable ISO (BIOS+UEFI hybrid).
    # Uses the higher-half ELF on x86_64 (required by Limine revision 3)
    # and the normal ELF on aarch64.
    # Prerequisites: xorriso (brew install xorriso), git.
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
        local = True,  # Needs network (first run) and host tools
        visibility = visibility,
    )
