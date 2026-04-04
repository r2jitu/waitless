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
      - <name>.iso        : Limine-bootable ISO (BIOS+UEFI, for cloud/QEMU)
      - <name>_native     : Native POSIX binary (same app code, host OS TCP)
      - <name>_run        : Launch with runner selected by --config:
                              (default)           → native POSIX binary
                              --config=vz         → VZ.framework (macOS arm64)
                              --config=qemu       → QEMU (host arch)
                              --config=aarch64-vz  → explicit
                              --config=x86_64-qemu, --config=x86_64-iso, …
                              --config=native      → native (host arch, from .bazelrc.local)
                              --config=aarch64-macos, --config=x86_64-linux → explicit

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
            "//net:stack",
                        "//uni:ffi",
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

    # Native POSIX binary — same application code, host OS TCP backend.
    # Only built when the platform has the runtime:native constraint
    # (aarch64_macos or x86_64_linux); excluded from unikernel
    # platforms (os:none) where the bare-metal toolchain would be selected.
    cc_binary(
        name = name + "_native",
        srcs = srcs,
        deps = deps + [
            "//uni:native",
            "//uni:native_entry",
        ],
        copts = copts,
        target_compatible_with = ["//bazel/platforms:native"],
        visibility = visibility,
    )

    # Unified run target — runner selected by --define=uni_runner=<value>.
    # Default (no define): native POSIX binary.
    # --config=vz/qemu/iso (or --config=<arch>-<runner>) set the define.
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
                # Include both .elf and .img: run_qemu.sh uses .elf for x86_64
                # and .img for aarch64 (both are needed to avoid nested select).
                ":" + name + ".elf",
                ":" + name + ".img",
            ],
            "//bazel/platforms:runner_iso": [
                # .iso already embeds the kernel; only the ISO path is needed.
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
            "//net:stack",
                        "//uni:ffi",
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
