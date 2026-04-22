"""Build rules for unikernel images.

Provides unikernel_binary() which packages a Rust application library
into bootable kernel images using rustc + rust-lld.
"""

load("@bazel_skylib//rules:write_file.bzl", "write_file")
load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//bazel/rules:rust.bzl", "UNIKERNEL_RUSTC_FLAGS")
load("//bazel/rules:variants.bzl", "unikernel_variants")

# ── Public launch-config helpers ─────────────────────────────────────────
#
# `port_fwd` lives here alongside `unikernel_binary` (not in
# `variants.bzl`) so apps only pull one `.bzl` for the rule + its
# attr-construction helpers. Lists of these go into
# `unikernel_binary(port_forwards = [...])`.

def port_fwd(proto, guest, host):
    """Build a validated port-forward entry for the `port_forwards` attr.

    Returns a struct with the three fields, validated up front so
    errors surface at macro-call time rather than deep inside rule
    analysis. The struct is carried through the `unikernel_binary`
    → `unikernel_variants` macro chain and serialised into a
    `string_list` attr only at the rule boundary (callers never
    see the encoding).

    Example:
        port_fwd("tcp", guest = 80, host = 8080)

    Semantics:
      * `guest` is fixed — baked into the variant launcher; matches
        the port the app listens on inside the guest.
      * `host` is the default external port the launcher exposes.
      * At runtime, `UNIKERNEL_<PROTO>_<GUEST>` (e.g.
        `UNIKERNEL_TCP_80`) overrides the host port; otherwise
        `host` is used. Same convention is honored by the native
        binary (`:<name>_native`), so users override ports the
        same way regardless of runner.

    Args:
      proto: `"tcp"` or `"udp"`.
      guest: guest-side port the app listens on (fixed).
      host: default external host port.

    Returns:
      A `struct(proto, guest, host)` ready to be dropped into a
      `port_forwards = [...]` list.
    """
    if proto not in ("tcp", "udp"):
        fail("port_fwd: proto must be 'tcp' or 'udp', got '{}'".format(proto))
    if type(host) != "int" or host <= 0 or host > 65535:
        fail("port_fwd: host must be a TCP/UDP port (1–65535), got '{}'".format(host))
    if type(guest) != "int" or guest <= 0 or guest > 65535:
        fail("port_fwd: guest must be a TCP/UDP port (1–65535), got '{}'".format(guest))
    return struct(proto = proto, guest = guest, host = host)

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

def _label_crate_name(label):
    """Derive the Rust crate name from a Bazel label string.

    Mirrors rules_rust's default `crate_name` derivation: take the
    label's target name (explicit `:foo` or implicit trailing path
    component) and replace non-identifier characters with `_`.

    Label forms accepted:
      `//uni-driver-virtio-net`                     → `uni_driver_virtio_net`
      `//uni-driver-virtio-net:uni-driver-virtio-net` → `uni_driver_virtio_net`
      `:foo-bar`                                    → `foo_bar`
    """
    if ":" in label:
        target = label.split(":")[-1]
    else:
        target = label.rsplit("/", 1)[-1]
    return target.replace("-", "_")

def unikernel_binary(
        name,
        app,
        drivers = [],
        port_forwards = [],
        ram_mb = 128,
        cpus = 1,
        visibility = None):
    """Package a Rust application into bootable unikernel images.

    The application is a rust_library with a #[uni::boot] entry point.

    Artifact targets produced:
      - <name>.elf        : Bare-metal ELF (QEMU direct boot)
      - <name>.img        : Raw binary (HVF runner / QEMU -kernel on aarch64)
      - <name>.limine.elf : Higher-half ELF (Limine bootloader)
      - <name>.iso        : Limine-bootable ISO (BIOS + UEFI)

    Runnable targets:
      - <name>_native       : Native POSIX binary (host OS, no VM,
                              declared here directly).
      - <name>_hvf          : aarch64 unikernel + HVF runner.
      - <name>_iso_x86_64   : x86_64 unikernel + Limine ISO (cloud boot).
      - <name>_iso_aarch64  : aarch64 unikernel + Limine ISO (ARM cloud).
      - <name>_qemu_aarch64 : aarch64 unikernel + QEMU TCG.
      - <name>_qemu_x86_64  : x86_64 unikernel + QEMU TCG.

    The VM variants are generated via `unikernel_variants`; native
    is a plain rust_binary because `native_main.rs` links libstd
    (so `bazel test`'s `-Cpanic=unwind` works without a Bazel
    transition resetting it).

    Args:
        name: Base name for all output targets.
        app: A rust_library target with a #[uni::boot] entry point.
        drivers: list of NIC driver crate labels (e.g.
          `//uni-driver-virtio-net`). Each is `extern crate`d at the
          unikernel binary's crate root so its
          `register_ethernet_driver!` entry survives rlib DCE. Not
          used by the `_native` binary — native networking flows
          through POSIX sockets. Crate names follow rules_rust's
          auto-derivation: label target (or trailing path component)
          with `-` replaced by `_`.
        port_forwards: list of entries built via `port_fwd()`. Each
          entry baked into the variant launchers as a `host_port →
          guest_port` forward, with `UNIKERNEL_*`-style env vars
          overriding the host port at run time. Defaults to `[]`
          (no forwards) so non-interactive test apps stay clean;
          server apps opt in with `port_forwards =
          HTTP_HTTPS_UDP_FORWARDS` (or their own list).
        ram_mb: default guest RAM in MB, overridable at run time
          via `UNIKERNEL_MEMORY`.
        cpus: default vCPU count, overridable at run time via
          `UNIKERNEL_CPUS`.
        visibility: Bazel visibility specification.
    """

    # Unikernel artefact targets (.elf, .img, .limine.elf, .iso)
    # are marked `target_compatible_with = ["@platforms//os:none"]`
    # — they only make sense under a bare-metal target platform, so
    # `bazel build //...` on a host platform skips them cleanly
    # rather than failing to compile no_std code / emit unikernel-
    # specific link sections. Variant transitions
    # (//bazel/rules:variants.bzl) flip the platform to aarch64 /
    # x86_64 `_unikernel` (both `os:none`), so the variant dep-chain
    # (`:<name>_hvf` → `:<name>.img` → `:<name>.elf`) builds fine.
    _unikernel_only = ["@platforms//os:none"]

    # Common deps for both .elf paths. boot_asm (x86_64 multiboot/PVH stub)
    # is added per-target below since it's incompatible with higher-half
    # linking and only needed for the QEMU direct-boot ELF.
    _common_deps = [app, "//boot:entry", "//boot:limine", "//boot:libc"] + drivers
    _unikernel_flags = UNIKERNEL_RUSTC_FLAGS + _LINK_FLAGS + _LINK_FLAGS_ARCH

    # ── Generated unikernel_main.rs ──────────────────────────────────────
    #
    # Each NIC driver crate registers itself via
    # `register_ethernet_driver!`, which emits a `#[used]` static into
    # the `.uni_drivers_ethernet` linker section. Without a path-level
    # reference from the binary crate, rustc does rlib-level DCE and
    # the whole rlib (and thus the section entry) gets dropped. So we
    # generate a per-binary main.rs that `extern crate`s each driver
    # at the binary crate root — rustc honours `extern crate` in a
    # binary crate as a link-forcing reference.
    #
    # We can't put the `extern crate` inside a sub-rlib (e.g. a shim
    # library): rustc's rlib DCE kicks in one level up — if nothing in
    # the binary reaches items in the shim's rlib, the shim is dropped
    # and its `extern crate` declarations go with it.
    main_src_rule = name + "_main_src"
    main_rs = name + "_unikernel_main.rs"
    main_content = [
        "// Generated by unikernel_binary(). Do not edit — edit the macro instead.",
        "#![no_std]",
        "#![no_main]",
        "",
        "extern crate app;",
    ]
    for d in drivers:
        main_content.append("extern crate " + _label_crate_name(d) + ";")
    main_content += [
        "",
        "// entry_rs provides the real panic handler (serial output + shutdown).",
        "// This one exists only to satisfy the compiler for the binary crate root.",
        "// --allow-multiple-definition at link time resolves the duplicate.",
        "#[panic_handler]",
        "fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }",
        "",
        "#[unsafe(no_mangle)]",
        "pub extern \"C\" fn rust_eh_personality() {}",
        "",
    ]
    write_file(
        name = main_src_rule,
        out = main_rs,
        content = main_content,
        target_compatible_with = _unikernel_only,
    )

    # ── Unikernel ELF ────────────────────────────────────────────────────
    rust_binary(
        name = name + ".elf",
        crate_name = name + "_elf",
        srcs = [":" + main_src_rule],
        crate_root = main_rs,
        deps = _common_deps + select({
            "//bazel/platforms:x86_64": ["//boot:boot_asm"],
            "//conditions:default": [],
        }),
        linker_script = select({
            "//bazel/platforms:aarch64": "//bazel/toolchain:unikernel_arm64.ld",
            "//conditions:default": "//bazel/toolchain:unikernel.ld",
        }),
        rustc_flags = _unikernel_flags,
        target_compatible_with = _unikernel_only,
        visibility = visibility,
    )

    # ── Raw binary (ELF → flat image for ARM64 bootloaders) ──────────────
    # Rule name is `<name>_img_gen` (not `<name>.img`) so Bazel doesn't
    # warn that the rule name collides with its single output file.
    # External references use the file label `:<name>.img`, which still
    # resolves to this rule's output.
    native.genrule(
        name = name + "_img_gen",
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
        target_compatible_with = _unikernel_only,
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
        srcs = [":" + main_src_rule],
        crate_root = main_rs,
        deps = _common_deps,
        linker_script = "//bazel/toolchain:unikernel_limine.ld",
        rustc_flags = _unikernel_flags,
        target_compatible_with = _unikernel_only,
        visibility = visibility,
    )

    # ── Limine ISO (BIOS + UEFI hybrid) ─────────────────────────────────
    # Rule name is `<name>_iso_gen` (not `<name>.iso`) so Bazel doesn't
    # warn that the rule name collides with its single output file.
    # External references use the file label `:<name>.iso`.
    native.genrule(
        name = name + "_iso_gen",
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
        target_compatible_with = _unikernel_only,
        visibility = visibility,
    )

    # ── Native POSIX binary ──────────────────────────────────────────────
    #
    # Directly runnable as `:<name>_native` — no variant wrapper,
    # no transition. `native_main.rs` is a std binary (libstd
    # provides panic handler / allocator / eh_personality); the
    # dep-chain rlibs (uni, uni-net, net/*, app) stay `#![no_std]`
    # but compile cleanly under any panic strategy because rlibs
    # don't own a panic handler.
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

    # ── Per-runner variants — `:<name>_hvf` / `_iso` / `_qemu_<arch>` ────
    # Each variant is a runnable target that transitions its sub-graph
    # into the matching platform + runner + `-Cpanic=abort` config, so
    # `bazel run :<name>_hvf` boots the HVF variant, `bazel run
    # :<name>_iso_x86_64` boots the Limine ISO, etc. — no `--config=`
    # flag, analysis cache preserved across variants. The VM-shape
    # config (port forwards, RAM, CPUs) passes through to each
    # variant's launcher template.
    unikernel_variants(
        name = name,
        port_forwards = port_forwards,
        ram_mb = ram_mb,
        cpus = cpus,
        visibility = visibility,
    )
