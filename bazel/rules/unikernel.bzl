"""Build rules for unikernel images.

Provides unikernel_binary() which packages a Rust application library
into bootable kernel images using rustc + rust-lld.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")
load("//bazel/rules:rust.bzl", "UNIKERNEL_RUSTC_FLAGS")
load("//bazel/rules:variants.bzl", "unikernel_variants")

# Bare-metal linker flags (passed to rust-lld via -C link-arg).
_LINK_FLAGS = [
    "-C",
    "linker-flavor=ld.lld",
    "-C",
    "link-arg=--gc-sections",
    "-C",
    "link-arg=--allow-multiple-definition",
    "-C",
    "link-arg=-zmax-page-size=0x1000",
    "-C",
    "link-arg=-znorelro",
    "-C",
    "link-arg=-nostdlib",
    "-C",
    "link-arg=--strip-debug",
]

_LINK_FLAGS_ARCH = select({
    "//bazel/platforms:aarch64": ["-C", "link-arg=-pie", "-C", "link-arg=-znotext"],
    "//conditions:default": ["-C", "link-arg=-static", "-C", "link-arg=--no-pie"],
})

def unikernel_binary(name, app, visibility = None):
    """Package a Rust application into bootable unikernel images.

    The application is a rust_library with a #[uni::boot] entry point.

    Targets produced:
      - <name>            : Unified launcher — `bazel run //path:name` picks
                            the runner from the active platform config
                            (hvf / qemu / iso / native).
      - <name>.elf        : Bare-metal ELF (QEMU direct boot)
      - <name>.img        : Raw binary (HVF runner / QEMU -kernel on aarch64)
      - <name>.limine.elf : Higher-half ELF (Limine bootloader)
      - <name>.iso        : Limine-bootable ISO (BIOS + UEFI)
      - <name>_native     : Native POSIX binary (host OS, no VM)

    Args:
        name: Base name for all output targets.
        app: A rust_library target with a #[uni::boot] entry point.
        visibility: Bazel visibility specification.
    """

    # Common deps for both .elf paths. boot_asm (x86_64 multiboot/PVH stub)
    # is added per-target below since it's incompatible with higher-half
    # linking and only needed for the QEMU direct-boot ELF.
    _common_deps = [app, "//boot:entry", "//boot:limine", "//boot:libc"]
    _unikernel_flags = UNIKERNEL_RUSTC_FLAGS + _LINK_FLAGS + _LINK_FLAGS_ARCH

    # ── Unikernel ELF ────────────────────────────────────────────────────
    rust_binary(
        name = name + ".elf",
        crate_name = name + "_elf",
        srcs = ["//bazel/rules:unikernel_main.rs"],
        deps = _common_deps + select({
            "//bazel/platforms:x86_64": ["//boot:boot_asm"],
            "//conditions:default": [],
        }),
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
    #
    # Uses a standalone linker script (unikernel_limine.ld) that places
    # the kernel at 0xFFFFFFFF80100000. Excludes //boot:boot_asm because
    # boot.S has 32-bit absolute relocations that can't reach higher-half;
    # Limine enters at limine_entry() directly so the multiboot stub
    # isn't needed. The runner_iso config also adds `-Ccode-model=kernel`
    # globally so all Rust crates emit R_X86_64_32S (signed) relocations
    # that fit the top-2GB region.
    rust_binary(
        name = name + ".limine.elf",
        crate_name = name + "_limine_elf",
        srcs = ["//bazel/rules:unikernel_main.rs"],
        deps = _common_deps,
        linker_script = "//bazel/toolchain:unikernel_limine.ld",
        rustc_flags = _unikernel_flags,
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
                "-C",
                "linker-flavor=ld.lld",
                "-C",
                "target-feature=+crt-static",
                "-C",
                "link-arg=-lc",
            ],
        }),
        target_compatible_with = ["//bazel/platforms:native"],
        visibility = visibility,
    )

    # ── Unified launcher — the rule's top-level target is itself runnable ───
    # The run_*.sh scripts find the app's artefacts via $0-relative paths
    # (they sit next to <name>.elf / <name>.img / <name>.iso / <name>_native
    # in the runfiles tree), so no env={} substitutions are needed. That
    # lets :webserver be spawned both via `bazel run` and as a subprocess
    # from an sh_test that lists :webserver in its `data` — the sh_binary
    # `env` block is only applied in `bazel run` context and would
    # therefore be useless for the subprocess path.
    sh_binary(
        name = name,
        srcs = select({
            "//bazel/platforms:runner_hvf": ["//bazel/rules:run_hvf.sh"],
            "//bazel/platforms:runner_qemu": ["//bazel/rules:run_qemu.sh"],
            "//bazel/platforms:runner_iso": ["//bazel/rules:run_iso.sh"],
            "//conditions:default": ["//bazel/rules:run_native.sh"],
        }),
        data = ["//scripts:helpers.sh"] + select({
            "//bazel/platforms:runner_hvf": [":" + name + ".img", "//tools/hvf-runner:run_hvf"],
            "//bazel/platforms:runner_qemu": [":" + name + ".elf", ":" + name + ".img"],
            "//bazel/platforms:runner_iso": [":" + name + ".iso"],
            "//conditions:default": [":" + name + "_native"],
        }),
        visibility = visibility,
    )

    # ── Per-runner variants — `:<name>_hvf` / `_iso` / `_qemu_<arch>` ────
    # Each variant wraps the unified launcher above under a Bazel
    # transition that pins the matching platform + runner selection +
    # `-Cpanic=abort`. `bazel run :<name>_hvf` is a drop-in for
    # `bazel run --config=hvf :<name>` — but without invalidating the
    # other variants' analysis cache when switching runners, and
    # `bazel test //...` can cover the full runner matrix in one shot.
    unikernel_variants(src = ":" + name, visibility = visibility)
