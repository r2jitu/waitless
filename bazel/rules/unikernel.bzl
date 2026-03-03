"""Build rules for unikernel images.

Provides unikernel_binary() which compiles a bare-metal ELF kernel and
optionally produces a bootable ISO and raw disk image for QEMU or cloud
deployment.
"""

load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")

def unikernel_binary(name, srcs, deps = [], copts = [], visibility = None):
    """Build a unikernel ELF binary from application sources.

    This macro produces three targets:
      - <name>.elf  : The bare-metal ELF kernel binary (cc_binary)
      - <name>_iso  : A GRUB multiboot2 bootable ISO (genrule)
      - <name>_raw  : A raw disk image for cloud deployment (genrule)

    The ELF binary automatically links against the kernel runtime (boot,
    core, arch_init), drivers (virtio_net), and the network stack.

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
            "//bazel/platforms:aarch64": [":" + name + ".img"],
            "//conditions:default": [],
        }),
        env = {
            "UNIKERNEL_ELF_RELPATH": native.package_name() + "/" + name + ".elf",
            "UNIKERNEL_IMG_RELPATH": native.package_name() + "/" + name + ".img",
        },
        visibility = visibility,
    )

    # Create a bootable ISO for QEMU/cloud using GRUB multiboot2.
    # Falls back to copying the raw ELF if grub-mkrescue is not available.
    native.genrule(
        name = name + "_iso",
        srcs = [":" + name + ".elf"],
        outs = [name + ".iso"],
        cmd = """
            mkdir -p $(@D)/iso/boot/grub
            cp $(location :{name_elf}) $(@D)/iso/boot/kernel.elf
            echo 'set timeout=0' > $(@D)/iso/boot/grub/grub.cfg
            echo 'set default=0' >> $(@D)/iso/boot/grub/grub.cfg
            echo 'menuentry "unikernel" {{' >> $(@D)/iso/boot/grub/grub.cfg
            echo '  multiboot2 /boot/kernel.elf' >> $(@D)/iso/boot/grub/grub.cfg
            echo '}}' >> $(@D)/iso/boot/grub/grub.cfg
            grub-mkrescue -o $@ $(@D)/iso 2>/dev/null || cp $(location :{name_elf}) $@
        """.format(name_elf = name + ".elf"),
        visibility = visibility,
    )

    # Create a raw disk image for cloud deployment.
    # This embeds the ELF at the start of a 64MB image.
    # Production cloud scripts should handle proper partitioning and
    # bootloader installation.
    native.genrule(
        name = name + "_raw",
        srcs = [":" + name + ".elf"],
        outs = [name + ".raw"],
        cmd = """
            dd if=/dev/zero of=$@ bs=1M count=64 2>/dev/null
            dd if=$(location :{name_elf}) of=$@ conv=notrunc 2>/dev/null
        """.format(name_elf = name + ".elf"),
        visibility = visibility,
    )
