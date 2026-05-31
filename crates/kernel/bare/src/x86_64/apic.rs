// kernel/x86_64/apic.rs — Local APIC initialization for x86_64.
//
// Detects and configures the Local APIC for each CPU core.
// Replaces the legacy 8259 PIC for interrupt delivery on SMP systems.

use crate::mm;
use crate::mmio::{self, ReadWrite};

// ── Local APIC register layout ───────────────────────────────────────────────
//
// Each LAPIC register is a u32 at a 16-byte stride. We wrap each one in
// `ApicReg<u32>` (a `ReadWrite<u32>` + 12 bytes of padding) so the struct
// layout matches the Intel SDM exactly. Compile-time `offset_of!` asserts
// validate every named offset.

#[repr(C)]
struct ApicReg<T: Copy> {
    val: ReadWrite<T>,
    _pad: [u32; 3],
}

impl<T: Copy> ApicReg<T> {
    #[inline(always)]
    fn read(&self) -> T {
        self.val.read()
    }
    #[inline(always)]
    fn write(&self, v: T) {
        self.val.write(v);
    }
}

#[repr(C)]
struct ApicRegs {
    _r0: [ApicReg<u32>; 2],  // 0x000..0x020
    id: ApicReg<u32>,        // 0x020
    version: ApicReg<u32>,   // 0x030
    _r1: [ApicReg<u32>; 4],  // 0x040..0x080
    tpr: ApicReg<u32>,       // 0x080
    _r2: [ApicReg<u32>; 2],  // 0x090..0x0B0
    eoi: ApicReg<u32>,       // 0x0B0
    _r3: [ApicReg<u32>; 3],  // 0x0C0..0x0F0
    svr: ApicReg<u32>,       // 0x0F0
    _r4: [ApicReg<u32>; 32], // 0x100..0x300
    icr_lo: ApicReg<u32>,    // 0x300
    icr_hi: ApicReg<u32>,    // 0x310
    lvt_timer: ApicReg<u32>, // 0x320
    _r5: [ApicReg<u32>; 2],  // 0x330..0x350
    lvt_lint0: ApicReg<u32>, // 0x350
    lvt_lint1: ApicReg<u32>, // 0x360
    lvt_error: ApicReg<u32>, // 0x370
    initial_count: ApicReg<u32>, // 0x380
    current_count: ApicReg<u32>, // 0x390
    _r6: [ApicReg<u32>; 4],  // 0x3A0..0x3E0
    divide_config: ApicReg<u32>, // 0x3E0
}

// Compile-time layout assertions — every named register lands at the
// Intel SDM-documented offset.
const _: () = assert!(core::mem::offset_of!(ApicRegs, id) == 0x020);
const _: () = assert!(core::mem::offset_of!(ApicRegs, version) == 0x030);
const _: () = assert!(core::mem::offset_of!(ApicRegs, tpr) == 0x080);
const _: () = assert!(core::mem::offset_of!(ApicRegs, eoi) == 0x0B0);
const _: () = assert!(core::mem::offset_of!(ApicRegs, svr) == 0x0F0);
const _: () = assert!(core::mem::offset_of!(ApicRegs, icr_lo) == 0x300);
const _: () = assert!(core::mem::offset_of!(ApicRegs, icr_hi) == 0x310);
const _: () = assert!(core::mem::offset_of!(ApicRegs, lvt_timer) == 0x320);
const _: () = assert!(core::mem::offset_of!(ApicRegs, lvt_lint0) == 0x350);
const _: () = assert!(core::mem::offset_of!(ApicRegs, lvt_lint1) == 0x360);
const _: () = assert!(core::mem::offset_of!(ApicRegs, lvt_error) == 0x370);
const _: () = assert!(core::mem::offset_of!(ApicRegs, initial_count) == 0x380);
const _: () = assert!(core::mem::offset_of!(ApicRegs, current_count) == 0x390);
const _: () = assert!(core::mem::offset_of!(ApicRegs, divide_config) == 0x3E0);

/// Spurious interrupt vector (must be 0xXF per Intel spec).
const SPURIOUS_VECTOR: u32 = 0xFF;

/// MSR for APIC base address.
const IA32_APIC_BASE_MSR: u32 = 0x1B;

/// Virtual address of the Local APIC MMIO page. Set once on the BSP via
/// `init()` before any AP starts; read by every core for MMIO access.
static APIC_BASE: crate::once::InitOnce<u64> = crate::once::InitOnce::new();

#[inline(always)]
fn lapic() -> &'static ApicRegs {
    // SAFETY: APIC_BASE is published exactly once during init(); readers
    // see the post-Acquire address. The struct layout matches the Intel
    // SDM (verified by const offset_of! asserts above).
    unsafe { mmio::at::<ApicRegs>(*APIC_BASE.get()) }
}

/// Read an MSR.
///
/// # Safety
///
/// `msr` must name a readable model-specific register on this CPU.
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Write an MSR.
///
/// # Safety
///
/// `msr` must name a writable model-specific register on this CPU and
/// `val` must be a legal value for it.
unsafe fn wrmsr(msr: u32, val: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") val as u32,
            in("edx") (val >> 32) as u32,
            options(nomem, nostack),
        );
    }
}

/// Get the current CPU's APIC ID.
pub fn apic_id() -> u32 {
    lapic().id.read() >> 24
}

/// Send End-Of-Interrupt to the Local APIC.
pub fn eoi() {
    lapic().eoi.write(0);
}

// ── LAPIC timer (TSC-deadline one-shot, for bounded idle) ──────────────────
//
// We use TSC-deadline mode (LVT timer mode 0b10): arming is a single MSR
// write of an absolute TSC value, which fires once when the TSC reaches it
// and then auto-disarms. No bus-frequency calibration (the classic
// initial-count timer would need it); we reuse the TSC rate the kernel
// already calibrates (`crate::time::cycles_per_us`). The event-loop idle
// path arms a short deadline before `hlt` so an idle core sleeps for a
// bounded interval and then re-polls, instead of busy-spinning — the
// dominant idle-CPU cost on shared GCE shapes (e2-small). See
// reference_idle_cpu_spin.

/// IA32_TSC_DEADLINE MSR. Writing a nonzero absolute TSC value arms the
/// LAPIC timer to fire once when `rdtsc()` reaches it; writing 0 disarms.
const IA32_TSC_DEADLINE_MSR: u32 = 0x6E0;
/// IDT vector for the LAPIC timer interrupt. Above the virtio/gve MSI-X
/// range (0x60..) and below the spurious vector (0xFF).
pub const TIMER_VECTOR: u8 = 0xF0;
/// LVT timer mode field (bits 18:17): 0b10 = TSC-deadline.
const LVT_TIMER_TSC_DEADLINE: u32 = 0b10 << 17;

/// Whether the LAPIC timer is usable for bounded idle (TSC-deadline or
/// the calibrated classic one-shot). Set once during `timer_init()`;
/// read by `arm_timer_cycles`. When false the idle path falls back to
/// its prior behaviour (no bounded-sleep timer).
static TIMER_AVAILABLE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Calibrated LAPIC-timer ticks per microsecond, for the *classic*
/// (initial-count) one-shot path. `0` means "TSC-deadline mode" (no
/// classic count needed) — the two modes are distinguished by this.
/// GCE e2-small's KVM does NOT expose TSC-deadline (CPUID.01H:ECX[24]
/// clear), so the classic path is what actually runs there.
static APIC_TICKS_PER_US: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// Classic timer LVT mode: one-shot (bits 18:17 = 0b00), so writing
/// `initial_count` arms a single fire.
const LVT_TIMER_ONESHOT: u32 = 0;
/// `divide_config` value for divide-by-1 (bits [3,1,0] = 0b1011).
const DIVIDE_BY_1: u32 = 0b1011;

/// True once the LAPIC timer is usable for bounded idle.
#[inline]
pub fn timer_available() -> bool {
    TIMER_AVAILABLE.load(core::sync::atomic::Ordering::Relaxed)
}

/// Configure this core's LAPIC timer LVT (TSC-deadline if CPUID
/// advertises it, else a TSC-calibrated classic one-shot), pointed at
/// [`TIMER_VECTOR`] and unmasked (disarmed until `arm_timer_cycles`).
/// Idempotent; safe to call per-core. Records availability from CPUID.
fn timer_init() {
    let l = lapic();
    let tsc_deadline = unsafe { core::arch::x86_64::__cpuid(1).ecx } & (1 << 24) != 0;
    if tsc_deadline {
        // Disarm before switching mode (Intel SDM: write 0 to the
        // deadline MSR when changing timer mode).
        unsafe { wrmsr(IA32_TSC_DEADLINE_MSR, 0) };
        l.lvt_timer
            .write(LVT_TIMER_TSC_DEADLINE | TIMER_VECTOR as u32);
        APIC_TICKS_PER_US.store(0, core::sync::atomic::Ordering::Relaxed); // 0 = TSC-deadline
        TIMER_AVAILABLE.store(true, core::sync::atomic::Ordering::Relaxed);
        return;
    }

    // Classic one-shot LAPIC timer (the path that actually runs on
    // GCE shapes without TSC-deadline). Calibrate the timer's tick
    // rate against the already-calibrated TSC (boot order:
    // `cycles_per_us` runs before `apic::init`), then leave the LVT in
    // one-shot mode, unmasked, disarmed (count 0). Per-core, but the
    // rate is identical across cores so a later writer just overwrites
    // the same value.
    let per_us = crate::time::cycles_per_us();
    if per_us == 0 {
        l.lvt_timer.write(0x10000); // can't calibrate → stay masked
        return;
    }
    l.divide_config.write(DIVIDE_BY_1);
    l.lvt_timer.write(0x10000); // masked during calibration
    l.initial_count.write(u32::MAX);
    let t0 = crate::time::now_cycles();
    let cal_cycles = per_us.saturating_mul(2000); // 2 ms calibration
    while crate::time::now_cycles().wrapping_sub(t0) < cal_cycles {
        core::hint::spin_loop();
    }
    let elapsed_apic = u32::MAX - l.current_count.read();
    l.initial_count.write(0); // stop counting
    let apic_per_us = ((elapsed_apic as u64) / 2000).max(1);
    APIC_TICKS_PER_US.store(apic_per_us, core::sync::atomic::Ordering::Relaxed);
    // One-shot mode, unmasked, pointed at the timer vector. Disarmed
    // (count already 0) until `arm_timer_cycles` writes initial_count.
    l.lvt_timer.write(LVT_TIMER_ONESHOT | TIMER_VECTOR as u32);
    TIMER_AVAILABLE.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// Arm the LAPIC timer to fire once `cycles` TSC ticks from now
/// (TSC-deadline). No-op if TSC-deadline isn't available. The fire
/// auto-disarms the timer; the [`TIMER_VECTOR`] ISR just sends EOI.
#[inline]
pub fn arm_timer_cycles(cycles: u64) {
    if !timer_available() {
        return;
    }
    let apic_per_us = APIC_TICKS_PER_US.load(core::sync::atomic::Ordering::Relaxed);
    if apic_per_us == 0 {
        // TSC-deadline mode.
        let deadline = crate::time::now_cycles().wrapping_add(cycles.max(1));
        unsafe { wrmsr(IA32_TSC_DEADLINE_MSR, deadline) };
    } else {
        // Classic mode: convert the requested TSC-cycle interval to
        // APIC ticks and arm the one-shot by writing initial_count.
        let per_us_tsc = crate::time::cycles_per_us();
        let us = if per_us_tsc > 0 { cycles / per_us_tsc } else { 0 };
        let count = us
            .saturating_mul(apic_per_us)
            .clamp(1, u32::MAX as u64) as u32;
        lapic().initial_count.write(count);
    }
}

/// Disarm the LAPIC timer (clear any pending deadline).
#[inline]
pub fn disarm_timer() {
    if !timer_available() {
        return;
    }
    if APIC_TICKS_PER_US.load(core::sync::atomic::Ordering::Relaxed) == 0 {
        unsafe { wrmsr(IA32_TSC_DEADLINE_MSR, 0) }; // TSC-deadline
    } else {
        lapic().initial_count.write(0); // classic one-shot
    }
}

/// ISR for the LAPIC timer vector — the deadline already auto-disarmed,
/// so just acknowledge. Its only job is to wake the core from `hlt`.
unsafe extern "C" fn timer_isr(_frame: *mut super::idt::InterruptFrame) {
    eoi();
}

/// Initialize the Local APIC on the current core (BSP or AP).
///
/// # Safety
///
/// Must run on the BSP exactly once, before any AP starts and before
/// any other core reads `APIC_BASE`. Reprograms LAPIC MMIO registers.
pub unsafe fn init() {
    unsafe {
        // Read APIC base from MSR
        let msr_val = rdmsr(IA32_APIC_BASE_MSR);
        let phys_base = msr_val & 0xFFFF_F000; // bits 12-35

        // Map APIC MMIO page via HHDM and publish for all cores.
        APIC_BASE.init(mm::phys_to_virt(phys_base) as u64);
    }

    let l = lapic();

    // Enable APIC in virtual wire mode: PIC interrupts route through
    // LINT0 of the BSP's Local APIC. This lets PIC device IRQs work
    // while the APIC is active (needed for INIT-SIPI-SIPI).
    l.svr.write(0x100 | SPURIOUS_VECTOR);
    l.tpr.write(0);

    // LINT0 = ExtINT (PIC passthrough), edge-triggered, unmasked
    l.lvt_lint0.write(0x00000700); // delivery mode 111 = ExtINT
    // LINT1 = NMI, edge-triggered, unmasked
    l.lvt_lint1.write(0x00000400); // delivery mode 100 = NMI
    // Timer = one-shot for bounded idle (sets the LVT + records
    // availability). Disarmed until `arm_timer_cycles`, so no interrupt
    // fires until the idle path arms it. Register the ISR first; the
    // IDT is already loaded by this point in boot.
    super::idt::register_handler(TIMER_VECTOR, timer_isr);
    timer_init();

    // Silent on success — the boot banner's `platform:` and `cpu:`
    // lines already cover the diagnostic surface. Keep `id` / `ver`
    // available for future debugging if a hypervisor turns up that
    // reports surprising values.
    let _ = (l.id.read() >> 24, l.version.read() & 0xFF);
}

/// Initialize the Local APIC on a secondary core (AP).
/// The BSP has already disabled PIC and mapped the APIC base.
///
/// # Safety
///
/// Must run on an AP after the BSP's `init()` has published
/// `APIC_BASE`. Reprograms this core's LAPIC MMIO registers.
pub unsafe fn init_ap() {
    unsafe {
        // Read APIC base from MSR (same physical address as BSP)
        let msr_val = rdmsr(IA32_APIC_BASE_MSR);
        // Ensure global enable bit is set
        wrmsr(IA32_APIC_BASE_MSR, msr_val | (1 << 11));
    }

    // The BSP has already published APIC_BASE; APs use the same mapping.
    let l = lapic();
    l.svr.write(0x100 | SPURIOUS_VECTOR);
    l.tpr.write(0);
    // Per-core LVT config for the bounded-idle timer (ISR already
    // registered in the shared IDT by the BSP's `init`).
    timer_init();
}

/// Send an IPI (Inter-Processor Interrupt) to a specific APIC ID.
///
/// # Safety
///
/// The LAPIC must be initialized (`init`/`init_ap` has run on this
/// core). `vector` must be a legal interrupt vector and
/// `target_apic_id` an existing core; a delivered IPI runs an ISR on
/// the target.
pub unsafe fn send_ipi(target_apic_id: u32, vector: u8) {
    let l = lapic();
    // Set destination in ICR high
    l.icr_hi.write(target_apic_id << 24);
    // Send: fixed delivery, physical mode, assert, edge-triggered
    l.icr_lo.write(vector as u32);
}

/// Wait for any pending IPI to finish dispatching. ICR_LO bit 12
/// ("Delivery Status") is set while an IPI is in flight and clears
/// once the LAPIC has accepted it. Spins on that bit instead of a
/// fixed 100K iteration loop — the wait is typically <100 cycles on
/// KVM, vs ~1 ms for the fixed spin.
#[inline]
fn wait_ipi_idle(l: &ApicRegs) {
    while (l.icr_lo.read() & (1 << 12)) != 0 {
        core::hint::spin_loop();
    }
}

/// Send INIT IPI to a target core.
///
/// # Safety
///
/// The LAPIC must be initialized. `target_apic_id` must name a real
/// AP; INIT resets that core's execution state.
pub unsafe fn send_init(target_apic_id: u32) {
    let l = lapic();
    l.icr_hi.write(target_apic_id << 24);
    // INIT: delivery mode 101, level assert, edge
    l.icr_lo.write(0x00004500);
    wait_ipi_idle(l);
    // Deassert
    l.icr_hi.write(target_apic_id << 24);
    l.icr_lo.write(0x00008500);
    wait_ipi_idle(l);
}

/// Send Startup IPI (SIPI) to a target core.
/// `vector` is the page number (4KB-aligned) where the AP trampoline lives.
/// e.g., if trampoline is at 0x8000, vector = 0x08.
///
/// # Safety
///
/// The LAPIC must be initialized. `vector` must point at a valid AP
/// trampoline page and `target_apic_id` must name a real AP that has
/// already received INIT; SIPI starts code execution on that core.
pub unsafe fn send_sipi(target_apic_id: u32, vector: u8) {
    let l = lapic();
    l.icr_hi.write(target_apic_id << 24);
    // SIPI: delivery mode 110, vector = page number
    l.icr_lo.write(0x00004600 | vector as u32);
    wait_ipi_idle(l);
}

/// Broadcast INIT to all cores except self.
///
/// # Safety
///
/// The LAPIC must be initialized. INIT resets every other core's
/// execution state, so callers must own the AP-boot sequence.
pub unsafe fn send_init_broadcast() {
    let l = lapic();
    l.icr_hi.write(0);
    // INIT (101), all excluding self (11 in bits 19:18)
    l.icr_lo.write(0x000C4500);
    wait_ipi_idle(l);
}

/// Broadcast SIPI to all cores except self.
///
/// # Safety
///
/// The LAPIC must be initialized. `vector` must point at a valid AP
/// trampoline page; SIPI starts code execution on every other core.
pub unsafe fn send_sipi_broadcast(vector: u8) {
    let l = lapic();
    l.icr_hi.write(0);
    // SIPI (110), all excluding self (11 in bits 19:18)
    l.icr_lo.write(0x000C4600 | vector as u32);
    wait_ipi_idle(l);
}
