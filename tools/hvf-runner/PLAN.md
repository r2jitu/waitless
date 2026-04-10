# HVF Runner — Implementation Plan

A native Apple Hypervisor.framework runner for the unikernel, intended to
replace VZ.framework as the local hardware-accelerated dev path on Apple
Silicon. **Status: Phase 0 complete. Phase 1+ paused; resume via this
document.**

The motivation, design rationale, and decision history are in the
conversation log that produced this crate. This file is the entry point
for *resuming* the work — what state we're in, what's blocking, and what
to do next.

---

## Why this crate exists

The local-dev story for ARM64 on Apple Silicon today is:

- **`scripts/run-vz.swift` (VZ.framework)** — works, hardware-accelerated,
  but uses VZ's idiosyncratic device model (virtio-pci with auto-BAR,
  INTx-only delivery, async config-write timing quirks). Not cloud-faithful.
- **QEMU + TCG** — slow software emulation; correct but not what you want
  for the inner dev loop.
- **QEMU + HVF** — broken: QEMU 10.x asserts `(isv)` on the first guest
  MMIO trap because mainline QEMU has no manual instruction decoder for
  EL1 stage-2 aborts. Won't be fixed upstream.

The HVF runner aims to be a small, focused tool that:

- Talks to `Hypervisor.framework` directly (no QEMU dependency).
- Boots **the same `webserver.img`** that runs in production cloud, with
  zero kernel changes.
- Emulates only the device set the kernel actually needs: PL011 UART and
  one virtio-mmio net device. Uses HVF's native vGIC for everything else.
- Reuses the existing `NetBridge` from `tools/run-vz/run-vz.swift` (or
  whichever path it lives in by the time you read this).
- Provides a cloud-faithful device model — same memory layout the QEMU
  `virt` machine and Firecracker present.

---

## Current state (Phase 0 complete)

What exists in this crate today:

```
tools/hvf-runner/
├── Cargo.toml              # Standalone crate, libc only, panic=abort, LTO release
├── build.rs                # Links Hypervisor.framework + assembles smoke stubs
├── run-hvf.entitlements    # com.apple.security.hypervisor (required for hv_vm_create)
├── PLAN.md                 # this file
├── src/
│   ├── lib.rs              # Re-exports (currently just `hvf`)
│   ├── hvf.rs              # FFI bindings + minimal helpers (~300 LoC)
│   └── main.rs             # Stub binary — prints "not yet implemented"
└── examples/
    ├── stubs.s             # Hand-assembled aarch64 guest stubs for the smoke test
    └── smoke.rs            # Phase 0 smoke harness — verifies HVF capabilities
```

The Phase 0 smoke test (`cargo build --release --example smoke`, codesign,
run) verifies three load-bearing assumptions and currently passes all three:

1. **Memory ops on guest RAM work**: plain `LDR/STR` and `STLR/LDAR` 
   succeed on `hv_vm_allocate`'d guest memory.
2. **Instruction-fetch via host mapping works**: when a guest stage-2
   data abort happens, the runner can read the faulting instruction word
   by dereferencing `host_ram + (PC - guest_ram_base)`.
3. **Native vGIC works**: `hv_gic_create()` succeeds on macOS 15+,
   `hv_gic_set_distributor_reg` round-trips, `hv_gic_set_spi(intid, true)`
   returns success.

The smoke test also exposes a `SMOKE_EXPERIMENT=mmu_self` mode that
exercises real `LDXR/STXR` and `CASALB` instructions from inside a guest
that sets up its own MMU. **This passes only after the boot.S MAIR layout
fix** (commit before this one). See the "Critical finding" section below.

---

## Critical finding — read this before writing any runner code

During Phase 0 we hit a wall: every attempt to execute `LDXR/STXR` or
`LSE CASAL` in a guest faulted with `ESR_EL1=0x96000035`, EC=0x25,
DFSC=0x35 ("Unsupported Exclusive or Atomic access"). The fault was
reproducible across every memory allocation strategy:
`hv_vm_allocate`, `mmap MAP_PRIVATE`, `mmap MAP_SHARED`, `mmap MAP_JIT`.
It was reproducible across guest-side and host-side MMU setup. It was
reproducible across `hv_vm_config_set_ipa_granule(4KB)` and `EL2`-enable
attempts. It looked like a fundamental M2 HVF limitation.

**The actual cause was the kernel's MAIR layout.** Apple Silicon HVF
on M2 inspects the descriptor's `AttrIdx` and only enables the guest
exclusive monitor when it points at the "standard" MAIR slot used by
Linux/OVMF/U-Boot (Write-Back at AttrIdx 3). Our boot.S used WB at
AttrIdx 1 — semantically identical per the ARMv8 spec, but HVF rejects
it. The fix is the previous commit, which changes `MAIR_EL1` to
`0xFFBB4400` and L1 descriptors to `0x70d`.

**Implication for future work**: any kernel image this runner boots
must be built with the post-MAIR-fix boot.S. The runner itself doesn't
need to do anything special with MAIR — the guest sets it up — but if
you're ever booting a custom test kernel that bypasses our boot.S, you
need to mirror the OVMF MAIR layout or atomics will fault.

The full investigation that led to this finding (libkrun, OVMF, krunkit
ground-truth tests, the four ruled-out sub-experiments) is in the
conversation log that produced this PLAN.md. If you need to re-verify
the M2 limitation, the smoke harness's `mmu_self` experiment is the
fastest reproducer.

---

## How to resume work

### Build and run the smoke test

```sh
cd tools/hvf-runner
cargo build --release --example smoke
codesign --force --sign - \
    --entitlements run-hvf.entitlements \
    target/release/examples/smoke
./target/release/examples/smoke
```

Expected output:

```
OK: memory ops (plain LDR/STR + STLR/LDAR)
OK: instruction-fetch (guest stub bytes visible via host mapping)
OK: native vGIC (hv_gic_create + distributor reg round-trip + hv_gic_set_spi)

--- exclusive-monitor experiments (informational, not failure-gating) ---
(info) hv_vm_create config = default
(info) allocated guest RAM via SMOKE_MEM=alloc
OK: guest-side MMU + atomics (counter=100, CASALB byte=42)
```

The smoke harness ships with two knobs (`SMOKE_EXPERIMENT`, `SMOKE_MEM`)
documented in the source.

### Build the (currently stub) runner binary

```sh
cargo build --release
codesign --force --sign - \
    --entitlements run-hvf.entitlements \
    target/release/run-hvf
./target/release/run-hvf  # prints "not yet implemented" today
```

The crate is dual-build: it works under plain `cargo` (above) and is
intended to also work under Bazel via a `BUILD.bazel` (not yet written
— see Phase 1 below).

---

## Phased plan (where the work picks up)

### Phase 1 — Boot to "hello kernel" with PL011 only (~2 days)

Goal: boot the existing `webserver.img` far enough to see the full boot
banner including `[INIT] Virtio-net driver (Rust)...`. With native vGIC
the kernel's GIC init works automatically. Only PL011 needs MMIO
emulation in this phase.

**New files** (or modules within `src/`):

| File | Approx LoC | Purpose |
|---|---|---|
| `src/vm.rs` | ~350 | VM + vCPU lifecycle, run loop, exception dispatch |
| `src/decoder.rs` | ~100 | aarch64 load/store decoder (4 forms + fallback panic) |
| `src/fdt.rs` | ~250 | Device Tree Blob generator (hand-rolled) |
| `src/pl011.rs` | ~100 | PL011 UART emulation |
| `src/terminal.rs` | ~60 | termios raw-mode helpers |
| `src/main.rs` | ~150 | Replace stub with real CLI entry point |

**Key implementation notes** (lessons from Phase 0):

- **HVF starts vCPUs with `CPSR=0x0` (EL0t).** You must explicitly set
  `CPSR=0x3c5` (EL1h, all DAIF masked) before the first `hv_vcpu_run`
  or you'll get an instruction abort from EL0 before any guest code
  runs. See `examples/smoke.rs::SmokeVm::new` for the exact sequence.

- **HVF starts vCPUs with `MPIDR_EL1=0`.** The vGIC requires bit 31
  to be set ("RES1"). Write `0x80000000` via
  `hv_vcpu_set_sys_reg(MpidrEl1, ...)` before running. This must
  happen before `hv_gic_get_redistributor_base` works.

- **Native vGIC must be created before vCPUs.** Order:
  1. `hv_vm_create`
  2. `hv_gic_config_create` + `hv_gic_config_set_distributor_base` +
     `hv_gic_config_set_redistributor_base`
  3. `hv_gic_create(cfg)`
  4. `hv_vcpu_create`
  5. `hv_gic_get_redistributor_base(vcpu, &out)` — this is where you
     find the redist IPA to put in the FDT.

- **Stage-2 fault PC is in `HV_REG_PC`, not `ELR_EL1`.** HVF takes
  the exception at EL2 (itself), not EL1, so `ELR_EL1`/`FAR_EL1`/
  `ESR_EL1` stay stale. The faulting VA/IPA are in the exit struct's
  `.exception.virtual_address` / `.physical_address`.

- **Decoder needs to handle only ~4 instruction forms.** The kernel
  uses `core::ptr::read_volatile`/`write_volatile` for all device
  access; LLVM with `-mgeneral-regs-only` only emits these:
  - `ldr Wt, [Xn{,#imm12}]` — `0xffc00000 / 0xb9400000`
  - `str Wt, [Xn{,#imm12}]` — `0xffc00000 / 0xb9000000`
  - `ldrb Wt, [Xn{,#imm12}]` — `0xffc00000 / 0x39400000`
  - `strb Wt, [Xn{,#imm12}]` — `0xffc00000 / 0x39000000`
  
  Decoder fallback should hex-dump unknown encodings and panic with
  the instruction word, so adding cases is fix-forward.

- **macOS version gate**: refuse to run on macOS < 15 (`hv_gic_create`
  was added in 15.0). The smoke test currently doesn't gate this
  because it's a pre-existing concern; the main runner should.

- **VTimer exit handling**: when `hv_vcpu_run` returns
  `HV_EXIT_REASON_VTIMER_ACTIVATED`, the VTimer is auto-masked. The
  runner needs to make the VTimer interrupt pending in the vGIC and
  wait for the guest to deactivate it before clearing the mask via
  `hv_vcpu_set_vtimer_mask(false)`. See `<Hypervisor/hv_vcpu.h>`
  comments on `hv_vcpu_set_vtimer_mask` for the protocol. The
  unikernel kernel uses `cntv_ctl_el0` for idle wakeups
  ([kernel/aarch64/exceptions.rs:enable_timer_wakeup](../../kernel/aarch64/exceptions.rs)),
  so this matters.

**Verification**: build, codesign, run with `webserver.img` as argv[1].
Kernel boots, prints banner, reaches `[INIT] Virtio-net driver (Rust)...
virtio_net: virtio-mmio net device found`. DHCP will hang because
queue notifications aren't handled yet — that's the boundary between
Phase 1 and Phase 2.

### Phase 2 — virtio-mmio + NetBridge (~3 days, the meat)

Goal: kernel completes boot, DHCP succeeds, HTTP server listens, `curl
http://localhost:18080/` returns the homepage byte-identical to QEMU+TCG.

| New file | Approx LoC | Purpose |
|---|---|---|
| `src/virtio.rs` | ~450 | virtio-mmio register file + virtio-net backend |
| `src/net_bridge.rs` | ~550 | Rust port of the Swift `NetBridge` (zero-copy, kqueue) |

**Layout decisions to mirror krunkit / Firecracker**:
- virtio-net at IPA `0xa000000` with INTID 35 (SPI 3)
- 64-deep queues, version-1 only
- One TX queue, one RX queue (no multiqueue for Phase 2)
- Negotiate `VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC` only

**Interrupt delivery**: with native vGIC, the RX thread calls
`hv_gic_set_spi(35, true)` whenever it injects a frame. The kernel's
existing `arch::idle()` path WFIs and is woken automatically by the
vGIC — no polling hack needed.

**NetBridge port**: currently the Swift implementation lives in
`scripts/run-vz.swift` lines 159-562 (or wherever it ends up after
the `tools/run-vz/` move planned in the parent task list). The port
is line-by-line, with these Rust improvements:
- `Box<[u8; 65536]>` TX/RX buffers, allocated once, reused forever
- `libc::kevent` directly for the event loop (no `tokio`/`mio` dep)
- Connection table as `HashMap<u16, ProxyConn>`
- All packet construction via `&mut [u8]` slices, no `Vec` allocation

**Verification**: `curl -sS -m 5 http://localhost:18080/` returns
HTTP 200 with the kernel homepage; diff against the QEMU+TCG output
should be empty.

### Phase 3 — Performance tuning (~1 day)

Goals:
- ≥500 req/s minimum (matches QEMU+TCG floor)
- ≥1500 req/s stretch (beats VZ)

Likely tuning levers (in priority order):
1. Coalesce SPI signals — don't call `hv_gic_set_spi(35)` per RX frame;
   batch with a 1 ms timer or kick only when the kernel has acked the
   previous interrupt.
2. Split `virtio_net` mutex into per-direction state (TX is vCPU-only;
   RX is bridge-thread-only) so the only cross-thread state is
   `interrupt_status`, which can be `AtomicU32`.
3. Pin the vCPU thread to a P-core via `pthread_set_qos_class_self_np
   (QOS_CLASS_USER_INTERACTIVE, 0)`.
4. `#[inline]` aggressively on the gpa→host translation and packet
   builders.

### Phase 4 — Bazel integration + dispatch (~half a day)

- `tools/hvf-runner/BUILD.bazel`: `rust_binary` target + a `genrule`
  that codesigns the output with `run-hvf.entitlements`. Pattern
  matches the existing run-vz integration in `scripts/BUILD.bazel`.
- `bazel/platforms/BUILD.bazel`: add `runner_hvf` `config_setting`
  parallel to `runner_vz`.
- `bazel/rules/unikernel.bzl`: extend the `_run` macro's `select()`
  to recognize `runner_hvf` and select `//tools/hvf-runner:run_hvf`.
- `bazel/rules/run_hvf.sh`: one-liner wrapper, mirrors `run_vz.sh`.
- `apps/webserver/BUILD.bazel`: add `test_hvf.sh` (copy of
  `test_vz.sh`, swap binary path) and a new `select()` arm.
- `scripts/run-local.sh`: add HVF dispatch branch on `Darwin/arm64`,
  before the existing VZ branch, gated on `UNIKERNEL_RUNNER=hvf` (or
  whichever default the project picks).

The crate is designed to be extracted into its own repo later via
`git subtree split tools/hvf-runner`. Avoid Bazel-only deps in the
crate sources themselves so plain `cargo build --release` continues
to work standalone.

---

## Reference index — files in this repo that the runner depends on

Read-only references the runner needs to be aware of:

- [boot/aarch64/boot.S](../../boot/aarch64/boot.S) — Linux ARM64 Image
  header, kernel entry contract (`x0=DTB`), MAIR layout the runner's
  memory model assumes.
- [kernel/aarch64/fdt.rs](../../kernel/aarch64/fdt.rs) — what the
  kernel parses out of the FDT. Authoritative for the FDT generator.
- [kernel/aarch64/exceptions.rs](../../kernel/aarch64/exceptions.rs) —
  GIC init code. Native vGIC means the runner doesn't emulate any of
  these registers, but the kernel's code path has to complete
  correctly under HVF's vGIC.
- [kernel/serial.rs](../../kernel/serial.rs) — PL011 register layout
  the kernel uses.
- [drivers/virtio.rs](../../drivers/virtio.rs) — virtio-mmio register
  offsets. Authoritative for the device emulator.
- [drivers/virtio_net.rs](../../drivers/virtio_net.rs) — virtio-net
  init sequence; tells you which feature bits to offer.
- `tools/run-vz/run-vz.swift` (or `scripts/run-vz.swift`, depending
  on whether the move has happened) — `NetBridge` source to port to
  Rust.
- `<Hypervisor/hv.h>` and friends in the macOS SDK — the FFI surface
  is documented in `src/hvf.rs`.

Verify the smoke test still passes before adding any new code in
Phase 1, so you have a known-good baseline.
