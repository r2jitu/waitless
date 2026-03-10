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
      - <name>.elf        : Bare-metal ELF kernel binary
      - <name>.img        : Raw binary (objcopy, for QEMU -kernel / VZ)
      - <name>_run        : Launch with QEMU or VZ.framework
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

    # "bazel run //apps/<name>:run" — builds the ELF (and IMG on aarch64) then
    # launches the appropriate runner.  On macOS arm64, run_wrapper.sh passes
    # the pre-built .img to run-local.sh → run-vz (no runtime ELF conversion).
    sh_binary(
        name = name + "_run",
        srcs = ["//bazel/rules:run_wrapper.sh"],
        data = [":" + name + ".elf"] + select({
            "//bazel/platforms:aarch64": [
                ":" + name + ".img",
                "//scripts:run_vz",
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

    # Limine-bootable ISO (BIOS+UEFI hybrid).
    # Works on both x86_64 and aarch64. Uses scripts/make-limine-iso.sh
    # which fetches Limine binaries on first run.
    # Prerequisites: xorriso (brew install xorriso), git.
    native.genrule(
        name = name + ".iso",
        srcs = [
            ":" + name + ".elf",
            "//boot:limine.conf",
        ],
        outs = [name + ".iso"],
        cmd = select({
            "//bazel/platforms:aarch64": """
                $(location //scripts:make_limine_iso) \
                    $(location :{name_elf}) $@ \
                    --arch aarch64 --conf $(location //boot:limine.conf)
            """.format(name_elf = name + ".elf"),
            "//conditions:default": """
                $(location //scripts:make_limine_iso) \
                    $(location :{name_elf}) $@ \
                    --arch x86_64 --conf $(location //boot:limine.conf)
            """.format(name_elf = name + ".elf"),
        }),
        tools = ["//scripts:make_limine_iso"],
        local = True,  # Needs network (first run) and host tools
        visibility = visibility,
    )
