// drivers/lib.rs — Crate root for bare-metal device drivers in Rust
//
// PCI bus enumeration, VirtIO transport (legacy + modern PCI + MMIO),
// virtio-net network driver, and virtio-console driver.
// All unsafe hardware access is confined to small helper functions;
// public APIs are safe where possible.

#![no_std]
#![allow(static_mut_refs)]
#![allow(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

// ============================================================================
// Kernel crate dependencies — direct Rust calls
// ============================================================================
extern crate kernel;
use kernel::{exceptions as kernel_exceptions, fdt as kernel_fdt, mm as kernel_mm, mmu as kernel_mmu, serial as kernel_serial};
use kernel_mm::{alloc_frame, phys_to_virt, virt_to_phys, kmalloc, kfree};
use kernel_mmu::map_device_range;

#[cfg(target_arch = "x86_64")]
use kernel::x86_64 as x86_init;

pub(crate) fn log(msg: &[u8]) {
    kernel_serial::puts(msg)
}

// ============================================================================
// Architecture helpers — safe wrappers around unsafe hardware access
// ============================================================================

// ---- Memory barriers --------------------------------------------------------

#[inline(always)]
pub(crate) fn dsb_st() {
    #[cfg(target_arch = "aarch64")]
    unsafe { asm!("dsb st", options(nostack, preserves_flags)); }
    #[cfg(target_arch = "x86_64")]
    compiler_fence(Ordering::Release);
}

#[inline(always)]
pub(crate) fn dsb_ld() {
    #[cfg(target_arch = "aarch64")]
    unsafe { asm!("dsb ld", options(nostack, preserves_flags)); }
    #[cfg(target_arch = "x86_64")]
    compiler_fence(Ordering::Acquire);
}

#[inline(always)]
pub(crate) fn dsb_sy() {
    #[cfg(target_arch = "aarch64")]
    unsafe { asm!("dsb sy", options(nostack, preserves_flags)); }
    #[cfg(target_arch = "x86_64")]
    compiler_fence(Ordering::SeqCst);
}

// ---- Volatile MMIO ----------------------------------------------------------

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
pub(crate) unsafe fn mmio_read32(addr: u64) -> u32 {
    ptr::read_volatile(addr as *const u32)
}

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
pub(crate) unsafe fn mmio_write32(addr: u64, val: u32) {
    ptr::write_volatile(addr as *mut u32, val);
}

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
pub(crate) unsafe fn mmio_read16(addr: u64) -> u16 {
    ptr::read_volatile(addr as *const u16)
}

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
pub(crate) unsafe fn mmio_write16(addr: u64, val: u16) {
    ptr::write_volatile(addr as *mut u16, val);
}

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
pub(crate) unsafe fn mmio_read8(addr: u64) -> u8 {
    ptr::read_volatile(addr as *const u8)
}

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
pub(crate) unsafe fn mmio_write8(addr: u64, val: u8) {
    ptr::write_volatile(addr as *mut u8, val);
}

// ---- x86_64 port I/O -------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) unsafe fn outl(port: u16, val: u32) {
    asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags));
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    asm!("in eax, dx", in("dx") port, out("eax") val, options(nostack, preserves_flags));
    val
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) unsafe fn outw(port: u16, val: u16) {
    asm!("out dx, ax", in("dx") port, in("ax") val, options(nostack, preserves_flags));
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    asm!("in ax, dx", in("dx") port, out("ax") val, options(nostack, preserves_flags));
    val
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!("in al, dx", in("dx") port, out("al") val, options(nostack, preserves_flags));
    val
}

// ---- Unified virtio register access -----------------------------------------

/// Read 32-bit virtio register. On x86 uses port I/O; on aarch64 uses MMIO.
#[inline(always)]
pub(crate) unsafe fn virtio_read32(base: u64) -> u32 {
    #[cfg(target_arch = "x86_64")]
    { inl(base as u16) }
    #[cfg(target_arch = "aarch64")]
    { mmio_read32(base) }
}

/// Write 32-bit virtio register.
#[inline(always)]
pub(crate) unsafe fn virtio_write32(base: u64, val: u32) {
    #[cfg(target_arch = "x86_64")]
    { outl(base as u16, val) }
    #[cfg(target_arch = "aarch64")]
    { mmio_write32(base, val) }
}

/// Read 16-bit virtio register.
#[inline(always)]
pub(crate) unsafe fn virtio_read16(base: u64) -> u16 {
    #[cfg(target_arch = "x86_64")]
    { inw(base as u16) }
    #[cfg(target_arch = "aarch64")]
    { mmio_read16(base) }
}

/// Write 16-bit virtio register.
#[inline(always)]
pub(crate) unsafe fn virtio_write16(base: u64, val: u16) {
    #[cfg(target_arch = "x86_64")]
    { outw(base as u16, val) }
    #[cfg(target_arch = "aarch64")]
    { mmio_write16(base, val) }
}

/// Read 8-bit virtio register.
#[inline(always)]
pub(crate) unsafe fn virtio_read8(base: u64) -> u8 {
    #[cfg(target_arch = "x86_64")]
    { inb(base as u16) }
    #[cfg(target_arch = "aarch64")]
    { mmio_read8(base) }
}

/// Write 8-bit virtio register.
#[inline(always)]
pub(crate) unsafe fn virtio_write8(base: u64, val: u8) {
    #[cfg(target_arch = "x86_64")]
    { outb(base as u16, val) }
    #[cfg(target_arch = "aarch64")]
    { mmio_write8(base, val) }
}

/// VZ async delay — Apple VZ processes config writes asynchronously.
/// Must be called after writing VirtIO status or feature registers.
#[inline(never)]
pub(crate) fn vz_config_delay() {
    for _ in 0..10_000 {
        unsafe { asm!("nop", options(nostack, preserves_flags)); }
    }
}

/// Long VZ delay — after DRIVER_OK, VZ needs time to initialize.
#[inline(never)]
pub(crate) fn vz_init_delay() {
    for _ in 0..1_000_000 {
        unsafe { asm!("nop", options(nostack, preserves_flags)); }
    }
}

// ============================================================================
// Submodules
// ============================================================================

pub mod pci;
pub mod virtio;
pub mod virtio_net;
pub mod virtio_console;

// ============================================================================
// Public API re-exports — keeps external callers unchanged
// ============================================================================

pub use pci::pci_init;
pub use pci::pci_enable_bus_mastering;
pub use virtio_net::virtio_net_init;
pub use virtio_net::virtio_net_get_mac;
pub use virtio_net::virtio_net_send;
pub use virtio_net::virtio_net_poll;
pub use virtio_net::virtio_net_enable_irq;
pub use virtio_net::virtio_net_irq_idle_supported;
pub use virtio_net::virtio_net_arm_rx_interrupts;
pub use virtio_net::virtio_net_has_pending_rx;
pub use virtio_console::virtio_console_init_mmio;
pub use virtio_console::virtio_console_init_pci;
pub use virtio_console::virtio_console_putc;
pub use virtio_console::virtio_console_try_getc;
