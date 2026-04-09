// kernel/time.rs — Hardware timing utilities.

/// Busy-wait for approximately `us` microseconds.
#[cfg(target_arch = "x86_64")]
pub fn udelay(us: u32) {
    // Calibration cache: TSC ticks per microsecond. AtomicU64 because
    // multiple cores may call udelay() concurrently and the first call
    // calibrates. The calibration result is a constant property of the
    // host so a benign double-calibrate is harmless; the atomic just
    // makes the publish/observe race-free at the language level.
    static TSC_PER_US: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);

    let mut tsc_per_us = TSC_PER_US.load(core::sync::atomic::Ordering::Relaxed);
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
        TSC_PER_US.store(tsc_per_us, core::sync::atomic::Ordering::Relaxed);
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
