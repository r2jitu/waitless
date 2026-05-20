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
    let cached = X86_TSC_PER_US.load(core::sync::atomic::Ordering::Relaxed);
    if cached != 0 {
        return cached.max(1);
    }
    // Probe order, fastest first:
    //  1. KVM pvclock (CPUID 0x40000001 bit 3) — derives TSC freq
    //     from `tsc_to_system_mul` + `tsc_shift` in the
    //     `pvclock_vcpu_time_info` struct the hypervisor populates
    //     after we write GPA|1 to MSR_KVM_SYSTEM_TIME_NEW. ~1 µs.
    //     Standard KVM exposes this; GCE's nested KVM does too.
    //     Eliminates the otherwise-mandatory PIT wait on `-cpu host`
    //     where leaves 0x15/0x16 are masked out.
    //  2. CPUID leaves 0x15/0x16 — works on modern Intel/AMD when
    //     the hypervisor passes them through (QEMU TCG, real bare
    //     metal, some KVMs).
    //  3. PIT calibration — the always-correct fallback. ~1 ms.
    if let Some(rate) = kvmclock_tsc_per_us() {
        X86_TSC_PER_US.store(rate, core::sync::atomic::Ordering::Relaxed);
        return rate.max(1);
    }
    if let Some(rate) = cpuid_tsc_per_us() {
        X86_TSC_PER_US.store(rate, core::sync::atomic::Ordering::Relaxed);
        return rate.max(1);
    }
    udelay(0);
    X86_TSC_PER_US
        .load(core::sync::atomic::Ordering::Relaxed)
        .max(1)
}

/// Try to derive TSC frequency from KVM's pvclock paravirt interface.
/// The `pvclock_vcpu_time_info` struct (Linux: `arch/x86/include/asm/pvclock-abi.h`)
/// gives us a TSC→nanosecond mapping; rearrange to get cycles per µs.
/// Returns None on any non-KVM host or if the feature bit is clear.
#[cfg(target_arch = "x86_64")]
fn kvmclock_tsc_per_us() -> Option<u64> {
    // CPUID 0x40000000: hypervisor signature. KVM identifies as
    // "KVMKVMKVM\0\0\0" in EBX/ECX/EDX. Treat anything else as
    // "no KVM pvclock here" — Hyper-V / Xen / VMware advertise
    // different feature MSRs.
    let sig = cpuid_x86(0x40000000);
    if sig.0 < 0x40000001 {
        return None;
    }
    let kvm_sig = (sig.1, sig.2, sig.3);
    if kvm_sig != (0x4b4d564b, 0x564b4d56, 0x0000004d) {
        return None;
    }
    // CPUID 0x40000001: KVM features. Bit 3 = CLOCKSOURCE2.
    let feat = cpuid_x86(0x40000001);
    if feat.0 & (1 << 3) == 0 {
        return None;
    }

    // 32-byte aligned BSS-resident struct (matches Linux's pvclock-abi).
    #[repr(C, align(32))]
    struct PvClock {
        version: u32,
        pad0: u32,
        tsc_timestamp: u64,
        system_time: u64,
        tsc_to_system_mul: u32,
        tsc_shift: i8,
        flags: u8,
        pad: [u8; 2],
    }
    static mut PVCLOCK: PvClock = PvClock {
        version: 0,
        pad0: 0,
        tsc_timestamp: 0,
        system_time: 0,
        tsc_to_system_mul: 0,
        tsc_shift: 0,
        flags: 0,
        pad: [0; 2],
    };

    // SAFETY: BSS-resident static; called single-threaded at boot.
    let pv_ptr = &raw mut PVCLOCK;
    let gpa = pv_ptr as u64;
    // Write MSR 0x4b564d01 (MSR_KVM_SYSTEM_TIME_NEW) with GPA | 1
    // (low bit = enable). The hypervisor starts updating the struct.
    unsafe {
        let val = gpa | 1;
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0x4b564d01u32,
            in("eax") val as u32,
            in("edx") (val >> 32) as u32,
            options(nomem, nostack),
        );
    }

    // Read with the standard "even version → re-read after fields"
    // protocol so we don't observe an in-flight update. Two iterations
    // is enough; if we lose twice we fall through to PIT.
    for _ in 0..2 {
        let v1 = unsafe { core::ptr::read_volatile(&raw const (*pv_ptr).version) };
        if v1 & 1 == 0 {
            let mul = unsafe { core::ptr::read_volatile(&raw const (*pv_ptr).tsc_to_system_mul) };
            let shift = unsafe { core::ptr::read_volatile(&raw const (*pv_ptr).tsc_shift) };
            let v2 = unsafe { core::ptr::read_volatile(&raw const (*pv_ptr).version) };
            if v2 == v1 && mul != 0 {
                // pvclock conversion: ns_delta = tsc_delta * mul >> (32 - shift)
                // (shift is signed: positive shifts left, negative shifts right
                // beyond the implicit 32-bit shift baked into the mul).
                // Inverting: TSC_HZ = (1 << (32 - shift)) * 1e9 / mul,
                // so cycles_per_us = TSC_HZ / 1e6.
                let total_shift = 32i32 - shift as i32;
                if total_shift < 0 || total_shift > 63 {
                    return None;
                }
                let scale: u64 = 1u64 << total_shift;
                // tsc_per_us = scale * 1000 / mul (after dividing 1e9 → 1e6).
                let tsc_per_us = scale.saturating_mul(1000) / mul as u64;
                if tsc_per_us == 0 {
                    return None;
                }
                return Some(tsc_per_us);
            }
        }
        core::hint::spin_loop();
    }
    None
}

#[cfg(target_arch = "x86_64")]
fn cpuid_tsc_per_us() -> Option<u64> {
    // Leaf 0x15: EAX = denominator, EBX = numerator, ECX = nominal
    // core crystal clock frequency in Hz. If EBX != 0 and ECX != 0,
    // TSC freq Hz = ECX * EBX / EAX (using the ratio). If EBX != 0
    // but ECX == 0, fall through to leaf 0x16 to derive ECX.
    let (a, b, c, _) = cpuid_x86(0x15);
    if b == 0 || a == 0 {
        return None;
    }
    let crystal_hz: u64 = if c != 0 {
        c as u64
    } else {
        // Leaf 0x16: EAX = base CPU frequency in MHz. From that and
        // the leaf-0x15 ratio we can derive the crystal clock.
        let (eax_mhz, _, _, _) = cpuid_x86(0x16);
        if eax_mhz == 0 {
            return None;
        }
        // tsc_hz = eax_mhz * 1_000_000; crystal_hz = tsc_hz * a / b
        ((eax_mhz as u64) * 1_000_000 * (a as u64)) / (b as u64)
    };
    // tsc_hz = crystal_hz * b / a; tsc_per_us = tsc_hz / 1_000_000
    let tsc_hz = (crystal_hz * (b as u64)) / (a as u64);
    let per_us = tsc_hz / 1_000_000;
    if per_us == 0 {
        return None;
    }
    Some(per_us)
}

#[cfg(target_arch = "x86_64")]
fn cpuid_x86(leaf: u32) -> (u32, u32, u32, u32) {
    let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, 0) };
    (r.eax, r.ebx, r.ecx, r.edx)
}

#[cfg(target_arch = "x86_64")]
static X86_TSC_PER_US: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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

static BOOT_START_CYCLES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

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

// ── kernel_core clock link seam ─────────────────────────────────────────────
//
// `kernel_core::clock::now_ms()` resolves, on the bare-metal target,
// to this `#[no_mangle]` symbol — mirroring `__kernel_bare_cpu_id` and
// `__kernel_bare_rng_fill`. `kernel_core` is the lower crate and cannot
// call up into `//crates/kernel/bare`, so it declares the `extern "Rust"` symbol
// and `//crates/kernel/bare` defines it here. This is what lets `tcp`'s
// RFC 6298 retransmission timer read a monotonic millisecond clock on
// `os:none` while resolving to a test-controllable mock under host
// unit tests.

/// Link-seam definition for `kernel_core::clock::now_ms()`. Monotonic
/// milliseconds since `mark_boot_start` — `since_boot_us` returns 0
/// until that runs, so the clock reads a clean 0 pre-boot-mark rather
/// than faulting.
#[unsafe(no_mangle)]
pub extern "Rust" fn __kernel_bare_now_ms() -> u64 {
    since_boot_us() / 1000
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
            // PIT runs at 1.193 MHz; 1193 ticks ≈ 1 ms. The original
            // 10 ms (11932) gave 0.05 % accuracy but blocked boot for
            // the full window — visible as a 10 ms gap between the
            // first two log lines on KVM where CPUID leaves 0x15/0x16
            // are masked. 1 ms is good enough for boot-log timestamps
            // and `udelay` (the only callers); a 1 % calibration error
            // turns a 10 ms `udelay(10_000)` into 9.9–10.1 ms, well
            // inside the SDM's INIT post-delay tolerance.
            const PIT_COUNT: u16 = 1193;
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
            tsc_per_us = (elapsed / 1000).max(1);
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
    unsafe {
        core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
    }
    val
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn x86_outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("al") val, in("dx") port, options(nomem, nostack));
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn x86_rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
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
            if now >= end {
                break;
            }
            core::arch::asm!("nop");
        }
    }
}
