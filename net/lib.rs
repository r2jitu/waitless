// net/lib.rs — Bare-metal network stack (no_std)
//
// Complete TCP/IP stack: Ethernet, ARP, IPv4, TCP, DHCP.
//
// All buffers are fixed-size, statically allocated. No heap except for
// per-connection TCP receive buffers (via kmalloc/kfree FFI).

#![no_std]
// Bare-metal single-threaded code: static mut references are safe here.
#![allow(static_mut_refs)]

// ============================================================================
// Rust crate dependencies — direct calls, no FFI
// ============================================================================

extern crate kernel;
use kernel::serial;
extern crate drivers;
pub extern crate net_types as types;

pub(crate) mod ethernet;
pub(crate) mod arp;
pub(crate) mod ipv4;
pub mod tcp;
pub mod dhcp;

fn log(msg: &[u8]) {
    serial::puts(msg)
}

/// Busy-wait for approximately `us` microseconds.
#[cfg(target_arch = "x86_64")]
pub(crate) fn arch_udelay(us: u32) {
    // Use TSC for timing. Calibrate once via PIT channel 2.
    static mut TSC_PER_US: u64 = 0;

    unsafe {
        if TSC_PER_US == 0 {
            // PIT channel 2, mode 0 (one-shot), ~10ms count
            const PIT_COUNT: u16 = 11932;
            // Disable speaker, enable gate
            let gate = x86_inb(0x61);
            x86_outb(0x61, (gate & 0xFD) | 0x01);
            // Channel 2, mode 0, binary, lo/hi byte
            x86_outb(0x43, 0xB0);
            x86_outb(0x42, (PIT_COUNT & 0xFF) as u8);
            x86_outb(0x42, (PIT_COUNT >> 8) as u8);
            // Reset latch by toggling gate
            let gate = x86_inb(0x61);
            x86_outb(0x61, gate & 0xFE);
            x86_outb(0x61, gate | 0x01);
            let start = x86_rdtsc();
            // Wait for OUT pin (bit 5) to go high
            while (x86_inb(0x61) & 0x20) == 0 {
                core::arch::asm!("nop");
            }
            let elapsed = x86_rdtsc() - start;
            TSC_PER_US = if elapsed / 10000 == 0 { 1 } else { elapsed / 10000 };
        }
        let end = x86_rdtsc() + TSC_PER_US * (us as u64);
        while x86_rdtsc() < end {
            core::arch::asm!("pause", options(nomem, nostack));
        }
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
pub(crate) fn arch_udelay(us: u32) {
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

