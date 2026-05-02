// kernel/time.rs — Hardware timing utilities.

/// Read the monotonic hardware cycle counter — TSC on x86_64,
/// CNTVCT_EL0 on aarch64. Used for micro-benchmarking hot paths
/// (e.g. per-stage TLS handshake profiling). Cheap: a single
/// instruction on both architectures.
#[inline(always)]
pub fn now_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let v: u64;
        core::arch::asm!(
            "mrs {0}, cntvct_el0",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
        v
    }
}

/// Hardware cycle-counter frequency in ticks per microsecond.
///
/// aarch64: reads CNTFRQ_EL0 directly (architectural virtual
/// counter frequency, typically 24 MHz on Apple Silicon).
/// x86_64: reuses the PIT-calibrated TSC rate from `udelay`.
#[cfg(target_arch = "aarch64")]
pub fn cycles_per_us() -> u64 {
    let freq: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, cntfrq_el0",
            out(reg) freq,
            options(nomem, nostack, preserves_flags),
        );
    }
    (freq / 1_000_000).max(1)
}

#[cfg(target_arch = "x86_64")]
pub fn cycles_per_us() -> u64 {
    // Force calibration via a zero-length udelay if not yet done.
    udelay(0);
    X86_TSC_PER_US.load(core::sync::atomic::Ordering::Relaxed).max(1)
}

#[cfg(target_arch = "x86_64")]
static X86_TSC_PER_US: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

// ── Boot-phase timing ──────────────────────────────────────────────────────
//
// `mark_boot_start` is called once at the top of `kernel_boot` (after
// `serial::init`), capturing the cycle counter. `since_boot_us` /
// `log_phase` then report elapsed time for any milestone the boot path
// wants to surface — kernel-init phases, the user `init()` entry, and
// the final "ready to serve" line.
//
// On aarch64 the cycle counter is always live (CNTVCT_EL0). On x86 it's
// the TSC, calibrated lazily via `cycles_per_us()` — but the start
// timestamp is still valid because we capture raw cycles and only
// convert to µs when reporting.

static BOOT_START_CYCLES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Capture the boot-start cycle count. Idempotent: only the first call
/// wins (so an accidental second call from an AP can't reset the
/// origin). Must be called from the BSP at the earliest convenient
/// point after `serial::init` so the elapsed-since-boot numbers cover
/// every later phase.
pub fn mark_boot_start() {
    let _ = BOOT_START_CYCLES.compare_exchange(
        0,
        now_cycles(),
        core::sync::atomic::Ordering::Release,
        core::sync::atomic::Ordering::Relaxed,
    );
}

/// Microseconds since `mark_boot_start`. Returns 0 if `mark_boot_start`
/// hasn't been called yet (rather than panicking) so a misordered call
/// surfaces as obviously-wrong "0 ms" output instead of a fault.
pub fn since_boot_us() -> u64 {
    let start = BOOT_START_CYCLES.load(core::sync::atomic::Ordering::Acquire);
    if start == 0 {
        return 0;
    }
    let elapsed = now_cycles().wrapping_sub(start);
    elapsed / cycles_per_us()
}

/// Print `[TIME] LABEL: N ms` (since boot) on the serial console.
/// Cheap: one cycle counter read, one TSC-rate read (cached after the
/// first x86 PIT calibration), and a few `serial::puts`. Not on a hot
/// path — call at phase boundaries only.
pub fn log_phase(label: &[u8]) {
    let ms = since_boot_us() / 1000;
    crate::serial::puts(b"[TIME] ");
    crate::serial::puts(label);
    crate::serial::puts(b": ");
    let mut buf = [0u8; 20];
    let mut len = 0;
    let mut v = ms;
    if v == 0 {
        buf[0] = b'0';
        len = 1;
    } else {
        while v > 0 {
            buf[len] = b'0' + (v % 10) as u8;
            v /= 10;
            len += 1;
        }
    }
    let mut out = [0u8; 20];
    for i in 0..len {
        out[i] = buf[len - 1 - i];
    }
    crate::serial::puts(&out[..len]);
    crate::serial::puts(b" ms\n");
}

/// Busy-wait for approximately `us` microseconds.
#[cfg(target_arch = "x86_64")]
pub fn udelay(us: u32) {
    // Calibration cache lives in the module-level `X86_TSC_PER_US`
    // atomic so `cycles_per_us()` can share the same result.
    // Multiple cores may call udelay() concurrently and the first
    // call calibrates; the calibration result is a constant property
    // of the host so a benign double-calibrate is harmless.
    let mut tsc_per_us = X86_TSC_PER_US.load(core::sync::atomic::Ordering::Relaxed);
    if tsc_per_us == 0 {
        unsafe {
            const PIT_COUNT: u16 = 11932; // ~10ms
            let gate = x86_inb(0x61);
            x86_outb(0x61, (gate & 0xFD) | 0x01);
            x86_outb(0x43, 0xB0);
            x86_outb(0x42, (PIT_COUNT & 0xFF) as u8);
            x86_outb(0x42, (PIT_COUNT >> 8) as u8);
            let gate = x86_inb(0x61);
            x86_outb(0x61, gate & 0xFE);
            x86_outb(0x61, gate | 0x01);
            let start = x86_rdtsc();
            while (x86_inb(0x61) & 0x20) == 0 {
                core::arch::asm!("nop");
            }
            let elapsed = x86_rdtsc() - start;
            tsc_per_us = (elapsed / 10000).max(1);
        }
        X86_TSC_PER_US.store(tsc_per_us, core::sync::atomic::Ordering::Relaxed);
    }
    let end = x86_rdtsc() + tsc_per_us * (us as u64);
    while x86_rdtsc() < end {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn x86_inb(port: u16) -> u8 {
    let val: u8;
    unsafe { core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack)); }
    val
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn x86_outb(port: u16, val: u8) {
    unsafe { core::arch::asm!("out dx, al", in("al") val, in("dx") port, options(nomem, nostack)); }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn x86_rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)); }
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(target_arch = "aarch64")]
pub fn udelay(us: u32) {
    unsafe {
        let freq: u64;
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq);
        let ticks = (freq / 1_000_000) * (us as u64);
        let start: u64;
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) start);
        let end = start + ticks;
        loop {
            let now: u64;
            core::arch::asm!("mrs {}, cntpct_el0", out(reg) now);
            if now >= end { break; }
            core::arch::asm!("nop");
        }
    }
}
