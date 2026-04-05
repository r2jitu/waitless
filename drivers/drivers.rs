// drivers/drivers.rs — Bare-metal device drivers in Rust
//
// PCI bus enumeration, VirtIO transport (legacy + modern PCI + MMIO),
// and virtio-net network driver. All unsafe hardware access is confined
// to small helper functions; public APIs are safe where possible.

#![no_std]
#![allow(static_mut_refs)]
#![allow(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

// ============================================================================
// FFI declarations — kernel functions provided by drivers_ffi.cc
// ============================================================================

// Kernel Rust rlibs — direct calls, no C++ FFI hop.
extern crate kernel_exceptions;
extern crate kernel_fdt;
extern crate kernel_mm;
extern crate kernel_mmu;
extern crate kernel_serial;
use kernel_mm::{mm_alloc_frame, mm_phys_to_virt, mm_virt_to_phys, mm_kmalloc, mm_kfree};
use kernel_mmu::mmu_map_device_range;

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn driver_register_irq(vector: u32, handler: unsafe extern "C" fn());
    fn driver_x86_enable_irq(irq: u32);
}

fn log(msg: &[u8]) {
    unsafe { kernel_serial::serial_puts(msg.as_ptr()) }
}

// ============================================================================
// Architecture helpers — safe wrappers around unsafe hardware access
// ============================================================================

// ---- Memory barriers --------------------------------------------------------

#[inline(always)]
fn dsb_st() {
    #[cfg(target_arch = "aarch64")]
    unsafe { asm!("dsb st", options(nostack, preserves_flags)); }
    #[cfg(target_arch = "x86_64")]
    compiler_fence(Ordering::Release);
}

#[inline(always)]
fn dsb_ld() {
    #[cfg(target_arch = "aarch64")]
    unsafe { asm!("dsb ld", options(nostack, preserves_flags)); }
    #[cfg(target_arch = "x86_64")]
    compiler_fence(Ordering::Acquire);
}

#[inline(always)]
fn dsb_sy() {
    #[cfg(target_arch = "aarch64")]
    unsafe { asm!("dsb sy", options(nostack, preserves_flags)); }
    #[cfg(target_arch = "x86_64")]
    compiler_fence(Ordering::SeqCst);
}

// ---- Volatile MMIO ----------------------------------------------------------

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
unsafe fn mmio_read32(addr: u64) -> u32 {
    ptr::read_volatile(addr as *const u32)
}

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
unsafe fn mmio_write32(addr: u64, val: u32) {
    ptr::write_volatile(addr as *mut u32, val);
}

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
unsafe fn mmio_read16(addr: u64) -> u16 {
    ptr::read_volatile(addr as *const u16)
}

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
unsafe fn mmio_write16(addr: u64, val: u16) {
    ptr::write_volatile(addr as *mut u16, val);
}

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
unsafe fn mmio_read8(addr: u64) -> u8 {
    ptr::read_volatile(addr as *const u8)
}

/// # Safety: addr must be a valid, mapped MMIO address.
#[inline(always)]
unsafe fn mmio_write8(addr: u64, val: u8) {
    ptr::write_volatile(addr as *mut u8, val);
}

// ---- x86_64 port I/O -------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn outl(port: u16, val: u32) {
    asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags));
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    asm!("in eax, dx", in("dx") port, out("eax") val, options(nostack, preserves_flags));
    val
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn outw(port: u16, val: u16) {
    asm!("out dx, ax", in("dx") port, in("ax") val, options(nostack, preserves_flags));
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    asm!("in ax, dx", in("dx") port, out("ax") val, options(nostack, preserves_flags));
    val
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!("in al, dx", in("dx") port, out("al") val, options(nostack, preserves_flags));
    val
}

// ---- Unified virtio register access -----------------------------------------

/// Read 32-bit virtio register. On x86 uses port I/O; on aarch64 uses MMIO.
#[inline(always)]
unsafe fn virtio_read32(base: u64) -> u32 {
    #[cfg(target_arch = "x86_64")]
    { inl(base as u16) }
    #[cfg(target_arch = "aarch64")]
    { mmio_read32(base) }
}

/// Write 32-bit virtio register.
#[inline(always)]
unsafe fn virtio_write32(base: u64, val: u32) {
    #[cfg(target_arch = "x86_64")]
    { outl(base as u16, val) }
    #[cfg(target_arch = "aarch64")]
    { mmio_write32(base, val) }
}

/// Read 16-bit virtio register.
#[inline(always)]
unsafe fn virtio_read16(base: u64) -> u16 {
    #[cfg(target_arch = "x86_64")]
    { inw(base as u16) }
    #[cfg(target_arch = "aarch64")]
    { mmio_read16(base) }
}

/// Write 16-bit virtio register.
#[inline(always)]
unsafe fn virtio_write16(base: u64, val: u16) {
    #[cfg(target_arch = "x86_64")]
    { outw(base as u16, val) }
    #[cfg(target_arch = "aarch64")]
    { mmio_write16(base, val) }
}

/// Read 8-bit virtio register.
#[inline(always)]
unsafe fn virtio_read8(base: u64) -> u8 {
    #[cfg(target_arch = "x86_64")]
    { inb(base as u16) }
    #[cfg(target_arch = "aarch64")]
    { mmio_read8(base) }
}

/// Write 8-bit virtio register.
#[inline(always)]
unsafe fn virtio_write8(base: u64, val: u8) {
    #[cfg(target_arch = "x86_64")]
    { outb(base as u16, val) }
    #[cfg(target_arch = "aarch64")]
    { mmio_write8(base, val) }
}

/// VZ async delay — Apple VZ processes config writes asynchronously.
/// Must be called after writing VirtIO status or feature registers.
#[inline(never)]
fn vz_config_delay() {
    for _ in 0..10_000 {
        unsafe { asm!("nop", options(nostack, preserves_flags)); }
    }
}

/// Long VZ delay — after DRIVER_OK, VZ needs time to initialize.
#[inline(never)]
fn vz_init_delay() {
    for _ in 0..1_000_000 {
        unsafe { asm!("nop", options(nostack, preserves_flags)); }
    }
}

// ============================================================================
// PCI subsystem
// ============================================================================

const PCI_MAX_DEVICES: usize = 64;

#[derive(Clone, Copy)]
#[repr(C)]
struct PciDevice {
    bus: u8,
    slot: u8,
    func: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    header_type: u8,
    bar: [u32; 6],
}

impl PciDevice {
    const ZERO: Self = PciDevice {
        bus: 0, slot: 0, func: 0,
        vendor_id: 0, device_id: 0,
        class_code: 0, subclass: 0, prog_if: 0,
        header_type: 0,
        bar: [0; 6],
    };
}

static mut PCI_DEVICES: [PciDevice; PCI_MAX_DEVICES] = [PciDevice::ZERO; PCI_MAX_DEVICES];
static mut PCI_DEVICE_COUNT: usize = 0;
static mut PCI_INITIALIZED: bool = false;

// ---- Config space access (arch-specific unsafe core) ------------------------

#[cfg(target_arch = "aarch64")]
static mut G_ECAM_BASE: u64 = 0x40_1000_0000;
#[cfg(target_arch = "aarch64")]
static mut G_PCI_MEM_NEXT: u64 = 0x1000_0000; // MMIO allocation pool

#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_ADDR: u16 = 0x0CF8;
#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_DATA: u16 = 0x0CFC;

/// Read 32-bit PCI config register (offset must be 4-byte aligned).
fn pci_read_config(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            let addr: u32 = (1 << 31)
                | ((bus as u32) << 16)
                | ((slot as u32) << 11)
                | ((func as u32) << 8)
                | ((offset as u32) & 0xFC);
            outl(PCI_CONFIG_ADDR, addr);
            inl(PCI_CONFIG_DATA)
        }
        #[cfg(target_arch = "aarch64")]
        {
            let ecam_addr = G_ECAM_BASE
                + ((bus as u64) << 20)
                + ((slot as u64) << 15)
                + ((func as u64) << 12)
                + ((offset as u64) & 0xFC);
            mmio_read32(ecam_addr)
        }
    }
}

/// Write 32-bit PCI config register.
fn pci_write_config(bus: u8, slot: u8, func: u8, offset: u8, val: u32) {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            let addr: u32 = (1 << 31)
                | ((bus as u32) << 16)
                | ((slot as u32) << 11)
                | ((func as u32) << 8)
                | ((offset as u32) & 0xFC);
            outl(PCI_CONFIG_ADDR, addr);
            outl(PCI_CONFIG_DATA, val);
        }
        #[cfg(target_arch = "aarch64")]
        {
            let ecam_addr = G_ECAM_BASE
                + ((bus as u64) << 20)
                + ((slot as u64) << 15)
                + ((func as u64) << 12)
                + ((offset as u64) & 0xFC);
            mmio_write32(ecam_addr, val);
        }
    }
}

/// Read 16-bit PCI config register (aarch64 ECAM supports sub-dword access).
#[cfg(target_arch = "aarch64")]
fn pci_read_config16(bus: u8, slot: u8, func: u8, offset: u8) -> u16 {
    unsafe {
        let ecam_addr = G_ECAM_BASE
            + ((bus as u64) << 20)
            + ((slot as u64) << 15)
            + ((func as u64) << 12)
            + (offset as u64);
        mmio_read16(ecam_addr)
    }
}

/// Write 16-bit PCI config register.
/// Critical for Command register (offset 0x04) to avoid clobbering Status.
#[cfg(target_arch = "aarch64")]
fn pci_write_config16(bus: u8, slot: u8, func: u8, offset: u8, val: u16) {
    unsafe {
        let ecam_addr = G_ECAM_BASE
            + ((bus as u64) << 20)
            + ((slot as u64) << 15)
            + ((func as u64) << 12)
            + (offset as u64);
        mmio_write16(ecam_addr, val);
    }
}

// ---- BAR assignment (aarch64 only) ------------------------------------------

/// Assign BARs from the MMIO pool. NEVER probes with 0xFFFFFFFF (crashes VZ).
#[cfg(target_arch = "aarch64")]
fn pci_assign_bars(dev: &mut PciDevice) {
    // Only assign for endpoint devices (header type 0x00)
    if (dev.header_type & 0x7F) != 0x00 { return; }

    // Check if Memory Space is already enabled (firmware assigned BARs)
    let cmd = pci_read_config16(dev.bus, dev.slot, dev.func, 0x04);
    if (cmd & 0x02) != 0 { return; } // Already enabled

    let mut i = 0;
    while i < 6 {
        let bar_val = dev.bar[i];
        let is_io = (bar_val & 1) != 0;
        let is_64bit = !is_io && ((bar_val >> 1) & 3) == 2;

        // Check if already assigned (non-zero address portion)
        let addr_mask = if is_io { !0x03u32 } else { !0x0Fu32 };
        if (bar_val & addr_mask) != 0 {
            i += if is_64bit { 2 } else { 1 };
            continue;
        }

        unsafe {
            if is_io {
                // Skip I/O BARs on aarch64
            } else if is_64bit {
                let alloc = (G_PCI_MEM_NEXT + 0x3F_FFFF) & !0x3F_FFFF; // 4MB align
                pci_write_config(dev.bus, dev.slot, dev.func, (0x10 + i * 4) as u8, (alloc as u32) | (bar_val & 0x0F));
                pci_write_config(dev.bus, dev.slot, dev.func, (0x10 + (i + 1) * 4) as u8, (alloc >> 32) as u32);
                dev.bar[i] = (alloc as u32) | (bar_val & 0x0F);
                dev.bar[i + 1] = (alloc >> 32) as u32;
                G_PCI_MEM_NEXT = alloc + 0x40_0000; // 4MB block
            } else {
                let alloc = (G_PCI_MEM_NEXT + 0x3F_FFFF) & !0x3F_FFFF; // 4MB align
                pci_write_config(dev.bus, dev.slot, dev.func, (0x10 + i * 4) as u8, (alloc as u32) | (bar_val & 0x0F));
                dev.bar[i] = (alloc as u32) | (bar_val & 0x0F);
                G_PCI_MEM_NEXT = alloc + 0x40_0000;
            }
        }

        i += if is_64bit { 2 } else { 1 };
    }

    // Enable I/O + Memory Space + Bus Master
    let new_cmd = cmd | 0x07;
    pci_write_config16(dev.bus, dev.slot, dev.func, 0x04, new_cmd);
}

// ---- Bus scan ---------------------------------------------------------------

fn pci_probe_function(bus: u8, slot: u8, func: u8) -> bool {
    let reg0 = pci_read_config(bus, slot, func, 0x00);
    let vendor_id = (reg0 & 0xFFFF) as u16;
    if vendor_id == 0xFFFF { return false; }

    let device_id = (reg0 >> 16) as u16;
    let reg8 = pci_read_config(bus, slot, func, 0x08);
    let class_code = (reg8 >> 24) as u8;
    let subclass = (reg8 >> 16) as u8;
    let prog_if = (reg8 >> 8) as u8;
    let regc = pci_read_config(bus, slot, func, 0x0C);
    let header_type = (regc >> 16) as u8;

    let mut dev = PciDevice {
        bus, slot, func,
        vendor_id, device_id,
        class_code, subclass, prog_if,
        header_type,
        bar: [0; 6],
    };

    // Read BARs
    for i in 0..6 {
        dev.bar[i] = pci_read_config(bus, slot, func, (0x10 + i * 4) as u8);
    }

    // Assign BARs on aarch64 if firmware hasn't
    #[cfg(target_arch = "aarch64")]
    {
        pci_assign_bars(&mut dev);
        // Re-read BARs after assignment
        for i in 0..6 {
            dev.bar[i] = pci_read_config(bus, slot, func, (0x10 + i * 4) as u8);
        }
    }

    unsafe {
        if PCI_DEVICE_COUNT < PCI_MAX_DEVICES {
            PCI_DEVICES[PCI_DEVICE_COUNT] = dev;
            PCI_DEVICE_COUNT += 1;
        }
    }

    true
}

fn pci_init_inner() {
    unsafe {
        if PCI_INITIALIZED { return; }
        PCI_INITIALIZED = true;
    }

    log(b"[PCI] Scanning bus 0...\n\0");

    #[cfg(target_arch = "aarch64")]
    unsafe {
        let fdt = kernel_fdt::info();
        if fdt.pcie_ecam_base != 0 {
            G_ECAM_BASE = fdt.pcie_ecam_base;
            if G_ECAM_BASE >= 0x1_0000_0000 {
                mmu_map_device_range(G_ECAM_BASE, fdt.pcie_ecam_size);
            }
        }
        if fdt.pci_mmio32_base != 0 {
            // Reserve first 4MB for console (init_vz uses base directly)
            G_PCI_MEM_NEXT = fdt.pci_mmio32_base + 0x40_0000;
        }
    }

    // Scan bus 0, slots 0-31
    for slot in 0..32u8 {
        if !pci_probe_function(0, slot, 0) { continue; }

        // Check multi-function bit
        let regc = pci_read_config(0, slot, 0, 0x0C);
        let header_type = (regc >> 16) as u8;
        if (header_type & 0x80) != 0 {
            for func in 1..8u8 {
                pci_probe_function(0, slot, func);
            }
        }
    }

    log(b"[PCI] Scan complete\n\0");
}

fn pci_find_device(vendor_id: u16, device_id: u16) -> Option<usize> {
    unsafe {
        for i in 0..PCI_DEVICE_COUNT {
            if PCI_DEVICES[i].vendor_id == vendor_id && PCI_DEVICES[i].device_id == device_id {
                return Some(i);
            }
        }
    }
    None
}

fn pci_enable_bus_mastering(slot: u8) {
    #[cfg(target_arch = "aarch64")]
    {
        let cmd = pci_read_config16(0, slot, 0, 0x04);
        pci_write_config16(0, slot, 0, 0x04, cmd | 0x04);
    }
    #[cfg(target_arch = "x86_64")]
    {
        let cmd = pci_read_config(0, slot, 0, 0x04);
        pci_write_config(0, slot, 0, 0x04, cmd | 0x04);
    }
}

/// Read 64-bit BAR address from a device.
fn pci_read_bar64(dev: &PciDevice, bar_idx: usize) -> u64 {
    let bar0 = dev.bar[bar_idx];
    let is_io = (bar0 & 1) != 0;
    if is_io {
        return (bar0 & !0x03u32) as u64;
    }
    let bar_type = (bar0 >> 1) & 3;
    let low = (bar0 & !0x0F) as u64;
    if bar_type == 2 && bar_idx + 1 < 6 {
        // 64-bit BAR
        low | ((dev.bar[bar_idx + 1] as u64) << 32)
    } else {
        low
    }
}

// ============================================================================
// Extern "C" API — PCI
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn driver_pci_init() {
    pci_init_inner();
}

#[unsafe(no_mangle)]
pub extern "C" fn driver_pci_enable_bus_mastering(slot: u8) {
    pci_enable_bus_mastering(slot);
}

// ============================================================================
// VirtIO PCI transport (modern, VirtIO 1.0+)
// ============================================================================

// PCI capability IDs
const PCI_CAP_ID_VNDR: u8 = 0x09;
const PCI_CAP_ID_MSIX: u8 = 0x11;

// virtio_pci_cap cfg_type values
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

// common_cfg field offsets
const CC_DEVICE_FEATURE_SELECT: u64 = 0x00;
const CC_DEVICE_FEATURE: u64 = 0x04;
const CC_DRIVER_FEATURE_SELECT: u64 = 0x08;
const CC_DRIVER_FEATURE: u64 = 0x0c;
const CC_CONFIG_MSIX_VECTOR: u64 = 0x10;
const CC_DEVICE_STATUS: u64 = 0x14;
const CC_QUEUE_SELECT: u64 = 0x16;
const CC_QUEUE_SIZE: u64 = 0x18;
const CC_QUEUE_MSIX_VECTOR: u64 = 0x1a;
const CC_QUEUE_ENABLE: u64 = 0x1c;
const CC_QUEUE_NOTIFY_OFF: u64 = 0x1e;
const CC_QUEUE_DESC_LO: u64 = 0x20;
const CC_QUEUE_DESC_HI: u64 = 0x24;
const CC_QUEUE_DRIVER_LO: u64 = 0x28;
const CC_QUEUE_DRIVER_HI: u64 = 0x2c;
const CC_QUEUE_DEVICE_LO: u64 = 0x30;
const CC_QUEUE_DEVICE_HI: u64 = 0x34;

const VIRTIO_PCI_MAX_DEVICES: usize = 8;

struct VirtioPciDevice {
    pci_idx: usize,         // index into PCI_DEVICES
    common_cfg: u64,        // MMIO address of common_cfg
    notify_base: u64,       // MMIO address of notify cap
    device_cfg: u64,        // MMIO address of device-specific cfg
    isr_cfg: u64,           // MMIO address of ISR cap
    notify_off_multiplier: u32,
    #[cfg(target_arch = "aarch64")]
    msix_cap_off: u8,
    #[cfg(target_arch = "aarch64")]
    msix_table: u64,
    #[cfg(target_arch = "aarch64")]
    msix_table_size: u16,
}

impl VirtioPciDevice {
    const ZERO: Self = VirtioPciDevice {
        pci_idx: 0,
        common_cfg: 0,
        notify_base: 0,
        device_cfg: 0,
        isr_cfg: 0,
        notify_off_multiplier: 0,
        #[cfg(target_arch = "aarch64")]
        msix_cap_off: 0,
        #[cfg(target_arch = "aarch64")]
        msix_table: 0,
        #[cfg(target_arch = "aarch64")]
        msix_table_size: 0,
    };
}

static mut VPCI_DEVICES: [VirtioPciDevice; VIRTIO_PCI_MAX_DEVICES] =
    [VirtioPciDevice::ZERO; VIRTIO_PCI_MAX_DEVICES];
static mut VPCI_DEVICE_COUNT: usize = 0;

/// Resolve a PCI BAR to a CPU virtual address. Maps above-4GB ranges on aarch64.
fn resolve_bar(pci_idx: usize, bar_idx: usize) -> u64 {
    let dev = unsafe { &PCI_DEVICES[pci_idx] };
    let addr = pci_read_bar64(dev, bar_idx);
    if addr == 0 { return 0; }

    #[cfg(target_arch = "aarch64")]
    if addr >= 0x1_0000_0000 {
        unsafe { mmu_map_device_range(addr & !0x1F_FFFF, 2 << 20); }
    }

    addr
}

/// Parse PCI capability list to find virtio-specific config structures.
fn vpci_parse_caps(dev: &mut VirtioPciDevice) -> bool {
    let pci = unsafe { &PCI_DEVICES[dev.pci_idx] };
    let (bus, slot, func) = (pci.bus, pci.slot, pci.func);

    // Check capabilities bit in Status register
    let status_cmd = pci_read_config(bus, slot, func, 0x04);
    if ((status_cmd >> 16) & (1 << 4)) == 0 { return false; }

    let mut cap_ptr = (pci_read_config(bus, slot, func, 0x34) & 0xFF) as u8;
    let mut found_common = false;
    let mut found_notify = false;

    while cap_ptr != 0 {
        let hdr = pci_read_config(bus, slot, func, cap_ptr);
        let cap_vndr = (hdr & 0xFF) as u8;
        let cap_next = ((hdr >> 8) & 0xFF) as u8;

        #[cfg(target_arch = "aarch64")]
        if cap_vndr == PCI_CAP_ID_MSIX && dev.msix_cap_off == 0 {
            dev.msix_cap_off = cap_ptr;
        }

        if cap_vndr == PCI_CAP_ID_VNDR {
            let cfg_type = ((hdr >> 24) & 0xFF) as u8;
            let bar_word = pci_read_config(bus, slot, func, cap_ptr.wrapping_add(4));
            let bar_idx = (bar_word & 0xFF) as usize;
            let offset = pci_read_config(bus, slot, func, cap_ptr.wrapping_add(8)) as u64;

            let bar_base = resolve_bar(dev.pci_idx, bar_idx);
            if bar_base != 0 {
                match cfg_type {
                    VIRTIO_PCI_CAP_COMMON_CFG => {
                        dev.common_cfg = bar_base + offset;
                        found_common = true;
                    }
                    VIRTIO_PCI_CAP_NOTIFY_CFG => {
                        dev.notify_base = bar_base + offset;
                        dev.notify_off_multiplier = pci_read_config(
                            bus, slot, func, cap_ptr.wrapping_add(16));
                        found_notify = true;
                    }
                    VIRTIO_PCI_CAP_DEVICE_CFG => {
                        dev.device_cfg = bar_base + offset;
                    }
                    VIRTIO_PCI_CAP_ISR_CFG => {
                        dev.isr_cfg = bar_base + offset;
                    }
                    _ => {}
                }
            }
        }

        cap_ptr = cap_next;
    }

    found_common && found_notify
}

/// Find a modern virtio-pci device by type (1=net, 3=console).
fn vpci_find(virtio_device_type: u16) -> Option<usize> {
    let target_id = 0x1040 + virtio_device_type;

    let pci_idx = pci_find_device(0x1AF4, target_id)?;

    unsafe {
        if VPCI_DEVICE_COUNT >= VIRTIO_PCI_MAX_DEVICES { return None; }
        let idx = VPCI_DEVICE_COUNT;
        let dev = &mut VPCI_DEVICES[idx];
        *dev = VirtioPciDevice::ZERO;
        dev.pci_idx = pci_idx;

        pci_enable_bus_mastering(PCI_DEVICES[pci_idx].slot);

        if !vpci_parse_caps(dev) { return None; }

        VPCI_DEVICE_COUNT += 1;
        Some(idx)
    }
}

// VirtIO PCI transport operations via common_cfg MMIO

fn vpci_reset(dev: &VirtioPciDevice) {
    unsafe {
        mmio_write8(dev.common_cfg + CC_DEVICE_STATUS, 0);
        while mmio_read8(dev.common_cfg + CC_DEVICE_STATUS) != 0 {
            asm!("", options(nostack, preserves_flags));
        }
    }
}

fn vpci_set_status(dev: &VirtioPciDevice, status: u8) {
    unsafe { mmio_write8(dev.common_cfg + CC_DEVICE_STATUS, status); }
    vz_config_delay();
}

fn vpci_get_status(dev: &VirtioPciDevice) -> u8 {
    unsafe { mmio_read8(dev.common_cfg + CC_DEVICE_STATUS) }
}

fn vpci_read_features(dev: &VirtioPciDevice, word: u32) -> u32 {
    unsafe {
        mmio_write32(dev.common_cfg + CC_DEVICE_FEATURE_SELECT, word);
        mmio_read32(dev.common_cfg + CC_DEVICE_FEATURE)
    }
}

fn vpci_write_features(dev: &VirtioPciDevice, word: u32, features: u32) {
    unsafe {
        mmio_write32(dev.common_cfg + CC_DRIVER_FEATURE_SELECT, word);
        mmio_write32(dev.common_cfg + CC_DRIVER_FEATURE, features);
    }
    vz_config_delay();
}

fn vpci_select_queue(dev: &VirtioPciDevice, idx: u16) {
    unsafe { mmio_write16(dev.common_cfg + CC_QUEUE_SELECT, idx); }
}

fn vpci_get_queue_size(dev: &VirtioPciDevice) -> u16 {
    unsafe { mmio_read16(dev.common_cfg + CC_QUEUE_SIZE) }
}

fn vpci_set_queue_addrs(dev: &VirtioPciDevice, desc: u64, avail: u64, used: u64) {
    unsafe {
        mmio_write32(dev.common_cfg + CC_QUEUE_DESC_LO, desc as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DESC_HI, (desc >> 32) as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DRIVER_LO, avail as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DRIVER_HI, (avail >> 32) as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DEVICE_LO, used as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DEVICE_HI, (used >> 32) as u32);
    }
}

fn vpci_enable_queue(dev: &VirtioPciDevice) {
    unsafe { mmio_write16(dev.common_cfg + CC_QUEUE_ENABLE, 1); }
}

fn vpci_get_queue_notify_off(dev: &VirtioPciDevice) -> u16 {
    unsafe { mmio_read16(dev.common_cfg + CC_QUEUE_NOTIFY_OFF) }
}

fn vpci_queue_notify_addr(dev: &VirtioPciDevice, notify_off: u16) -> u64 {
    dev.notify_base + (notify_off as u64) * (dev.notify_off_multiplier as u64)
}

fn vpci_read_dev_cfg8(dev: &VirtioPciDevice, offset: u32) -> u8 {
    if dev.device_cfg == 0 { return 0; }
    unsafe { mmio_read8(dev.device_cfg + offset as u64) }
}

fn vpci_read_isr(dev: &VirtioPciDevice) -> u8 {
    if dev.isr_cfg == 0 { return 0; }
    unsafe { mmio_read8(dev.isr_cfg) }
}

#[cfg(target_arch = "aarch64")]
fn vpci_set_queue_msix_vector(dev: &VirtioPciDevice, vector: u16) {
    unsafe { mmio_write16(dev.common_cfg + CC_QUEUE_MSIX_VECTOR, vector); }
}

// ============================================================================
// Virtio legacy transport (x86_64 PCI I/O ports, aarch64 MMIO)
// ============================================================================

// Legacy PCI I/O register offsets
const VREG_DEVICE_FEATURES: u64 = 0x00;
const VREG_GUEST_FEATURES: u64 = 0x04;
const VREG_QUEUE_ADDRESS: u64 = 0x08;
const VREG_QUEUE_SIZE: u64 = 0x0C;
const VREG_QUEUE_SELECT: u64 = 0x0E;
const VREG_QUEUE_NOTIFY: u64 = 0x10;
const VREG_DEVICE_STATUS: u64 = 0x12;
const VREG_ISR_STATUS: u64 = 0x13;
const VREG_DEVICE_CONFIG: u64 = 0x14;

// Virtio-MMIO register offsets (aarch64 QEMU)
const MMIO_BASE: u64 = 0x0a00_0000;
const MMIO_MAGIC_VALUE: u64 = 0x000;
const MMIO_VERSION: u64 = 0x004;
const MMIO_DEVICE_ID: u64 = 0x008;
const MMIO_HOST_FEATURES: u64 = 0x010;
const MMIO_DEVICE_FEATURES_SEL: u64 = 0x014;
const MMIO_GUEST_FEATURES: u64 = 0x020;
const MMIO_DRIVER_FEATURES_SEL: u64 = 0x024;
const MMIO_GUEST_PAGE_SIZE: u64 = 0x028;
const MMIO_QUEUE_SEL: u64 = 0x030;
const MMIO_QUEUE_NUM_MAX: u64 = 0x034;
const MMIO_QUEUE_NUM: u64 = 0x038;
const MMIO_QUEUE_ALIGN: u64 = 0x03c;
const MMIO_QUEUE_PFN: u64 = 0x040;
const MMIO_QUEUE_READY: u64 = 0x044;
const MMIO_QUEUE_NOTIFY: u64 = 0x050;
const MMIO_INTERRUPT_STATUS: u64 = 0x060;
const MMIO_INTERRUPT_ACK: u64 = 0x064;
const MMIO_STATUS: u64 = 0x070;
const MMIO_DEVICE_CONFIG: u64 = 0x100;
const MMIO_MAGIC: u32 = 0x74726976;
// MMIO v2 separate ring address registers
const MMIO_QUEUE_DESC_LOW: u64 = 0x080;
const MMIO_QUEUE_DESC_HIGH: u64 = 0x084;
const MMIO_QUEUE_DRIVER_LOW: u64 = 0x090;
const MMIO_QUEUE_DRIVER_HIGH: u64 = 0x094;
const MMIO_QUEUE_DEVICE_LOW: u64 = 0x0a0;
const MMIO_QUEUE_DEVICE_HIGH: u64 = 0x0a4;

// Device status bits
const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;

// Virtqueue descriptor flags
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;

// Feature bits
const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VIRTIO_NET_F_MRG_RXBUF: u32 = 1 << 15;
const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
const VIRTIO_RING_F_EVENT_IDX: u32 = 1 << 29;

// ============================================================================
// Split Virtqueue
// ============================================================================

// Virtqueue descriptor (must match hardware layout: 16 bytes packed)
#[repr(C, packed)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

// Available ring header (naturally aligned, no padding)
#[repr(C)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    // ring[queue_size] follows, then used_event (u16)
}

// Used ring element (naturally aligned)
#[repr(C)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

// Used ring header (naturally aligned)
#[repr(C)]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    // ring[queue_size] of VirtqUsedElem follows
}

struct Virtqueue {
    descs: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    queue_size: u16,
    free_head: u16,
    num_free: u16,
    last_used_idx: u16,
    io_base: u64,
    notify_addr: u64,
    queue_index: u16,
    is_mmio: bool,
    event_idx: bool,
}

impl Virtqueue {
    const ZERO: Self = Virtqueue {
        descs: ptr::null_mut(),
        avail: ptr::null_mut(),
        used: ptr::null_mut(),
        queue_size: 0,
        free_head: 0,
        num_free: 0,
        last_used_idx: 0,
        io_base: 0,
        notify_addr: 0,
        queue_index: 0,
        is_mmio: false,
        event_idx: false,
    };

    /// Allocate ring memory and set up descriptor free list.
    /// Returns (desc_phys, avail_phys, used_phys) for the caller to program the device.
    fn alloc_rings(&mut self, queue_size: u16, notify_addr: u64,
                   queue_index: u16) -> Option<(u64, u64, u64)> {
        self.queue_index = queue_index;
        self.notify_addr = notify_addr;
        self.queue_size = queue_size;

        if queue_size == 0 { return None; }

        let desc_size = (queue_size as u64) * 16; // sizeof(VirtqDesc)
        let avail_size = 6 + 2 * (queue_size as u64); // flags + idx + ring[] + used_event
        let used_size = 6 + 8 * (queue_size as u64); // flags + idx + ring[] + avail_event

        let first_region = (desc_size + avail_size + 4095) & !4095;
        let second_region = (used_size + 4095) & !4095;
        let total_size = first_region + second_region;
        let num_frames = (total_size + 4095) / 4096;

        let phys_base = unsafe { mm_alloc_frame() };
        if phys_base == 0 { return None; }
        for _ in 1..num_frames {
            unsafe { mm_alloc_frame(); }
        }

        let base_ptr = unsafe { mm_phys_to_virt(phys_base) };
        unsafe { ptr::write_bytes(base_ptr, 0, total_size as usize); }

        self.descs = base_ptr as *mut VirtqDesc;
        self.avail = unsafe { base_ptr.add(desc_size as usize) } as *mut VirtqAvail;
        self.used = unsafe { base_ptr.add(first_region as usize) } as *mut VirtqUsed;

        // Initialize free descriptor linked list
        for i in 0..queue_size {
            unsafe {
                let d = &mut *self.descs.add(i as usize);
                d.next = i + 1;
                d.flags = 0;
            }
        }
        self.free_head = 0;
        self.num_free = queue_size;
        self.last_used_idx = 0;

        // Suppress interrupts by default (polling mode)
        unsafe { ptr::write_volatile(&mut (*self.avail).flags, VIRTQ_AVAIL_F_NO_INTERRUPT); }

        let desc_phys = phys_base;
        let avail_phys = phys_base + desc_size;
        let used_phys = phys_base + first_region;

        Some((desc_phys, avail_phys, used_phys))
    }

    /// Initialize for modern PCI transport.
    fn init_pci_modern(&mut self, queue_size: u16, notify_addr: u64,
                       queue_index: u16) -> Option<(u64, u64, u64)> {
        self.is_mmio = false;
        self.alloc_rings(queue_size, notify_addr, queue_index)
    }

    /// Initialize for legacy PCI or MMIO transport.
    fn init_legacy(&mut self, base: u64, queue_index: u16,
                   is_mmio: bool, is_mmio_v2: bool) -> bool {
        self.io_base = base;
        self.is_mmio = is_mmio;

        let queue_size: u16;
        if is_mmio {
            unsafe {
                virtio_write32(base + MMIO_QUEUE_SEL, queue_index as u32);
                let qmax = virtio_read32(base + MMIO_QUEUE_NUM_MAX);
                if qmax == 0 { return false; }
                queue_size = if qmax > 256 { 256 } else { qmax as u16 };
                virtio_write32(base + MMIO_QUEUE_NUM, queue_size as u32);
                if !is_mmio_v2 {
                    virtio_write32(base + MMIO_QUEUE_ALIGN, 4096);
                }
            }
        } else {
            unsafe {
                virtio_write16(base + VREG_QUEUE_SELECT, queue_index);
                let dev_qs = virtio_read16(base + VREG_QUEUE_SIZE);
                if dev_qs == 0 { return false; }
                queue_size = dev_qs;
            }
        }

        let addrs = match self.alloc_rings(queue_size, 0, queue_index) {
            Some(a) => a,
            None => return false,
        };
        let (desc_phys, avail_phys, used_phys) = addrs;

        // Tell device where the queue lives
        unsafe {
            if is_mmio {
                if is_mmio_v2 {
                    virtio_write32(base + MMIO_QUEUE_DESC_LOW, desc_phys as u32);
                    virtio_write32(base + MMIO_QUEUE_DESC_HIGH, (desc_phys >> 32) as u32);
                    virtio_write32(base + MMIO_QUEUE_DRIVER_LOW, avail_phys as u32);
                    virtio_write32(base + MMIO_QUEUE_DRIVER_HIGH, (avail_phys >> 32) as u32);
                    virtio_write32(base + MMIO_QUEUE_DEVICE_LOW, used_phys as u32);
                    virtio_write32(base + MMIO_QUEUE_DEVICE_HIGH, (used_phys >> 32) as u32);
                    virtio_write32(base + MMIO_QUEUE_READY, 1);
                } else {
                    virtio_write32(base + MMIO_QUEUE_PFN, (desc_phys >> 12) as u32);
                }
            } else {
                virtio_write32(base + VREG_QUEUE_ADDRESS, (desc_phys >> 12) as u32);
            }
        }

        true
    }

    /// Add a buffer chain to the available ring.
    /// Returns head descriptor index, or -1 on failure.
    fn add_buf(&mut self, buf_phys: u64, buf_len: u32, out_count: u16, in_count: u16) -> i32 {
        let total = out_count + in_count;
        if total == 0 || self.num_free < total { return -1; }

        let head = self.free_head;
        let mut idx = head;

        // Output (device-readable) buffers
        for i in 0..out_count {
            unsafe {
                let d = &mut *self.descs.add(idx as usize);
                d.addr = buf_phys;
                d.len = buf_len;
                d.flags = if i < total - 1 { VIRTQ_DESC_F_NEXT } else { 0 };
                idx = d.next;
            }
        }

        // Input (device-writable) buffers
        for i in 0..in_count {
            unsafe {
                let d = &mut *self.descs.add(idx as usize);
                d.addr = buf_phys;
                d.len = buf_len;
                d.flags = VIRTQ_DESC_F_WRITE;
                if i < in_count - 1 { d.flags |= VIRTQ_DESC_F_NEXT; }
                idx = d.next;
            }
        }

        self.free_head = idx;
        self.num_free -= total;

        // Add chain head to available ring
        unsafe {
            let avail_idx = ptr::read_volatile(&(*self.avail).idx);
            let ring_slot = (avail_idx & (self.queue_size - 1)) as usize;
            let ring_ptr = (self.avail as *mut u8).add(4) as *mut u16; // skip flags+idx
            ptr::write_volatile(ring_ptr.add(ring_slot), head);

            dsb_st();

            ptr::write_volatile(&mut (*self.avail).idx, avail_idx.wrapping_add(1));
        }

        head as i32
    }

    /// Notify the device that new buffers are available.
    fn kick(&self) {
        dsb_st();
        if self.notify_addr != 0 {
            // Modern PCI: write queue_index to MMIO notify address
            unsafe { ptr::write_volatile(self.notify_addr as *mut u16, self.queue_index); }
        } else if self.is_mmio {
            unsafe { virtio_write32(self.io_base + MMIO_QUEUE_NOTIFY, self.queue_index as u32); }
        } else {
            unsafe { virtio_write16(self.io_base + VREG_QUEUE_NOTIFY, self.queue_index); }
        }
    }

    /// Check for completed buffers in the used ring.
    /// Returns (descriptor_head_id, bytes_written) or None.
    fn get_used(&mut self) -> Option<(u16, u32)> {
        dsb_ld();

        let used_idx = unsafe { ptr::read_volatile(&(*self.used).idx) };
        if self.last_used_idx == used_idx { return None; }

        let used_slot = (self.last_used_idx & (self.queue_size - 1)) as usize;
        let ring_ptr = unsafe { (self.used as *mut u8).add(4) as *mut VirtqUsedElem };
        let elem = unsafe { ptr::read_volatile(ring_ptr.add(used_slot)) };
        let id = elem.id as u16;
        let len = elem.len;

        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        // Return descriptors in this chain to the free list
        let mut idx = id;
        loop {
            self.num_free += 1;
            let d = unsafe { &mut *self.descs.add(idx as usize) };
            if (d.flags & VIRTQ_DESC_F_NEXT) == 0 {
                d.next = self.free_head;
                self.free_head = id;
                break;
            }
            idx = d.next;
        }

        Some((id, len))
    }

    fn has_used(&self) -> bool {
        let used_idx = unsafe { ptr::read_volatile(&(*self.used).idx) };
        self.last_used_idx != used_idx
    }

    fn enable_interrupts(&mut self) {
        unsafe { ptr::write_volatile(&mut (*self.avail).flags, 0); }
        if self.event_idx {
            // Write used_event = used->idx after avail->ring[queue_size]
            let used_event_ptr = unsafe {
                ((self.avail as *mut u8).add(4) as *mut u16).add(self.queue_size as usize)
            };
            let used_idx = unsafe { ptr::read_volatile(&(*self.used).idx) };
            unsafe { ptr::write_volatile(used_event_ptr, used_idx); }
            dsb_st();
        }
    }

    fn disable_interrupts(&mut self) {
        unsafe { ptr::write_volatile(&mut (*self.avail).flags, VIRTQ_AVAIL_F_NO_INTERRUPT); }
    }

    /// Get descriptor at index (for reading buffer addresses)
    fn desc(&self, idx: u16) -> &VirtqDesc {
        unsafe { &*self.descs.add(idx as usize) }
    }
}

// ============================================================================
// VirtIO-net driver
// ============================================================================

const RX_BUFFERS: usize = 64;
const BUFFER_SIZE: u32 = 2048;
const TX_POOL_SIZE: usize = 64;
const VIRTIO_NET_HDR_SIZE: usize = 12; // VirtioNetHeader (with num_buffers)
const MAX_ETH_FRAME: usize = 1514;

#[repr(C, packed)]
struct VirtioNetHeader {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

#[repr(C)]
struct TxBuf {
    hdr: VirtioNetHeader,
    data: [u8; MAX_ETH_FRAME],
}

// Transport state
#[derive(Clone, Copy, PartialEq)]
enum Transport {
    None,
    #[cfg(target_arch = "aarch64")]
    Mmio { base: u64, is_v2: bool },
    #[cfg(target_arch = "x86_64")]
    LegacyPci { base: u64, pci_idx: usize },
    ModernPci { vpci_idx: usize },
}

static mut NET_TRANSPORT: Transport = Transport::None;
static mut NET_RX_QUEUE: Virtqueue = Virtqueue::ZERO;
static mut NET_TX_QUEUE: Virtqueue = Virtqueue::ZERO;
static mut NET_MAC: [u8; 6] = [0; 6];
static mut NET_RX_BUFFERS: [*mut u8; RX_BUFFERS] = [ptr::null_mut(); RX_BUFFERS];
static mut NET_TX_POOL: [TxBuf; TX_POOL_SIZE] = unsafe { core::mem::zeroed() };
static mut NET_TX_POOL_USED: [bool; TX_POOL_SIZE] = [false; TX_POOL_SIZE];
static mut NET_IRQ_IDLE_AVAILABLE: bool = false;
static mut NET_GUEST_FEATURES: u32 = 0;

// ---- Modern PCI init (VZ.framework + QEMU modern) --------------------------

fn init_pci_modern() -> bool {
    let vpci_idx = match vpci_find(1) { // virtio device type 1 = net
        Some(i) => i,
        None => return false,
    };

    log(b"virtio_net: found modern virtio-pci net device\n\0");

    let dev = unsafe { &VPCI_DEVICES[vpci_idx] };

    vpci_reset(dev);
    vpci_set_status(dev, STATUS_ACKNOWLEDGE);
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let dev_features = vpci_read_features(dev, 0);
    // Accept all offered word-0 features (VZ may require CSUM/INDIRECT_DESC)
    let guest_features = dev_features;

    vpci_write_features(dev, 0, guest_features);
    vpci_write_features(dev, 1, 1); // VIRTIO_F_VERSION_1

    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    if (vpci_get_status(dev) & STATUS_FEATURES_OK) == 0 {
        log(b"virtio_net: device rejected features\n\0");
        vpci_set_status(dev, STATUS_FAILED);
        return false;
    }

    // Init RX queue (0)
    vpci_select_queue(dev, 0);
    let rx_qsize = vpci_get_queue_size(dev);
    let rx_notify_off = vpci_get_queue_notify_off(dev);
    let rx_notify = vpci_queue_notify_addr(dev, rx_notify_off);

    let rx_addrs = unsafe {
        match NET_RX_QUEUE.init_pci_modern(rx_qsize, rx_notify, 0) {
            Some(a) => a,
            None => {
                log(b"virtio_net: failed to init RX queue\n\0");
                vpci_set_status(dev, STATUS_FAILED);
                return false;
            }
        }
    };
    vpci_set_queue_addrs(dev, rx_addrs.0, rx_addrs.1, rx_addrs.2);
    vpci_enable_queue(dev);

    // Init TX queue (1)
    vpci_select_queue(dev, 1);
    let tx_qsize = vpci_get_queue_size(dev);
    let tx_notify_off = vpci_get_queue_notify_off(dev);
    let tx_notify = vpci_queue_notify_addr(dev, tx_notify_off);

    let tx_addrs = unsafe {
        match NET_TX_QUEUE.init_pci_modern(tx_qsize, tx_notify, 1) {
            Some(a) => a,
            None => {
                log(b"virtio_net: failed to init TX queue\n\0");
                vpci_set_status(dev, STATUS_FAILED);
                return false;
            }
        }
    };
    vpci_set_queue_addrs(dev, tx_addrs.0, tx_addrs.1, tx_addrs.2);
    vpci_enable_queue(dev);

    // EVENT_IDX
    if (guest_features & VIRTIO_RING_F_EVENT_IDX) != 0 {
        unsafe { NET_RX_QUEUE.event_idx = true; }
    }

    // Read MAC
    for i in 0..6u32 {
        unsafe { NET_MAC[i as usize] = vpci_read_dev_cfg8(dev, i); }
    }

    // Allocate and populate RX buffers
    for i in 0..RX_BUFFERS {
        let alloc = unsafe { mm_kmalloc(BUFFER_SIZE as usize + 2) };
        if alloc.is_null() {
            log(b"virtio_net: failed to allocate RX buffer\n\0");
            vpci_set_status(dev, STATUS_FAILED);
            return false;
        }
        // +2 byte shift for IPv4 alignment on ARM64
        let buf = unsafe { alloc.add(2) };
        unsafe {
            ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
            NET_RX_BUFFERS[i] = buf;
            let buf_phys = mm_virt_to_phys(buf);
            NET_RX_QUEUE.add_buf(buf_phys, BUFFER_SIZE, 0, 1);
        }
    }

    // DRIVER_OK
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER |
                         STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    unsafe { NET_RX_QUEUE.kick(); }
    vz_init_delay(); // VZ needs time after DRIVER_OK

    unsafe {
        NET_TRANSPORT = Transport::ModernPci { vpci_idx };
        NET_GUEST_FEATURES = guest_features;
    }
    log(b"virtio_net: initialization complete (PCI modern)\n\0");
    true
}

// ---- MMIO init (aarch64 QEMU) ----------------------------------------------

#[cfg(target_arch = "aarch64")]
fn init_mmio() -> bool {
    let mut io_base: u64 = 0;

    unsafe {
        let fdt = kernel_fdt::info();

        // Search FDT virtio-mmio devices for net (device_id=1)
        if fdt.virtio_count > 0 {
            for i in 0..fdt.virtio_count as usize {
                let candidate = fdt.virtio_bases[i];
                if virtio_read32(candidate + MMIO_MAGIC_VALUE) != MMIO_MAGIC { continue; }
                if virtio_read32(candidate + MMIO_DEVICE_ID) == 1 {
                    io_base = candidate;
                    break;
                }
            }
        }

        // Fallback: fixed QEMU slot scan
        if io_base == 0 {
            for slot in 0..32u64 {
                let candidate = MMIO_BASE + slot * 0x200;
                if virtio_read32(candidate + MMIO_MAGIC_VALUE) != MMIO_MAGIC { continue; }
                if virtio_read32(candidate + MMIO_DEVICE_ID) == 1 {
                    io_base = candidate;
                    break;
                }
            }
        }
    }

    if io_base == 0 { return false; }

    let ver = unsafe { virtio_read32(io_base + MMIO_VERSION) };
    let is_v2 = ver == 2;
    if ver != 1 && ver != 2 { return false; }

    log(b"virtio_net: virtio-mmio net device found\n\0");

    // Reset
    unsafe { virtio_write32(io_base + MMIO_STATUS, 0); }

    // ACKNOWLEDGE + DRIVER
    unsafe {
        virtio_write32(io_base + MMIO_STATUS, STATUS_ACKNOWLEDGE as u32);
        virtio_write32(io_base + MMIO_STATUS,
                       (STATUS_ACKNOWLEDGE | STATUS_DRIVER) as u32);
    }

    // Feature negotiation
    let mut guest_features: u32 = 0;
    unsafe {
        if is_v2 {
            virtio_write32(io_base + MMIO_DEVICE_FEATURES_SEL, 0);
            let dev_features = virtio_read32(io_base + MMIO_HOST_FEATURES);
            if (dev_features & VIRTIO_NET_F_MAC) != 0 { guest_features |= VIRTIO_NET_F_MAC; }
            if (dev_features & VIRTIO_NET_F_STATUS) != 0 { guest_features |= VIRTIO_NET_F_STATUS; }
            if (dev_features & VIRTIO_NET_F_MRG_RXBUF) != 0 { guest_features |= VIRTIO_NET_F_MRG_RXBUF; }

            virtio_write32(io_base + MMIO_DRIVER_FEATURES_SEL, 0);
            virtio_write32(io_base + MMIO_GUEST_FEATURES, guest_features);
            virtio_write32(io_base + MMIO_DRIVER_FEATURES_SEL, 1);
            virtio_write32(io_base + MMIO_GUEST_FEATURES, 0);

            virtio_write32(io_base + MMIO_STATUS,
                           (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK) as u32);
            if (virtio_read32(io_base + MMIO_STATUS) & STATUS_FEATURES_OK as u32) == 0 {
                log(b"virtio_net: device rejected features\n\0");
                virtio_write32(io_base + MMIO_STATUS, STATUS_FAILED as u32);
                return false;
            }
        } else {
            let dev_features = virtio_read32(io_base + MMIO_HOST_FEATURES);
            if (dev_features & VIRTIO_NET_F_MAC) != 0 { guest_features |= VIRTIO_NET_F_MAC; }
            if (dev_features & VIRTIO_NET_F_STATUS) != 0 { guest_features |= VIRTIO_NET_F_STATUS; }
            if (dev_features & VIRTIO_NET_F_MRG_RXBUF) != 0 { guest_features |= VIRTIO_NET_F_MRG_RXBUF; }
            virtio_write32(io_base + MMIO_GUEST_FEATURES, guest_features);
            virtio_write32(io_base + MMIO_GUEST_PAGE_SIZE, 4096);
        }
    }

    // Init RX and TX queues
    unsafe {
        if !NET_RX_QUEUE.init_legacy(io_base, 0, true, is_v2) {
            log(b"virtio_net: failed to init RX queue\n\0");
            return false;
        }
        if !NET_TX_QUEUE.init_legacy(io_base, 1, true, is_v2) {
            log(b"virtio_net: failed to init TX queue\n\0");
            return false;
        }
    }

    // Read MAC from config space
    unsafe {
        let lo = virtio_read32(io_base + MMIO_DEVICE_CONFIG);
        let hi = virtio_read32(io_base + MMIO_DEVICE_CONFIG + 4);
        NET_MAC[0] = (lo & 0xff) as u8;
        NET_MAC[1] = ((lo >> 8) & 0xff) as u8;
        NET_MAC[2] = ((lo >> 16) & 0xff) as u8;
        NET_MAC[3] = ((lo >> 24) & 0xff) as u8;
        NET_MAC[4] = (hi & 0xff) as u8;
        NET_MAC[5] = ((hi >> 8) & 0xff) as u8;
    }

    // Allocate RX buffers
    for i in 0..RX_BUFFERS {
        let alloc = unsafe { mm_kmalloc(BUFFER_SIZE as usize + 2) };
        if alloc.is_null() { return false; }
        let buf = unsafe { alloc.add(2) };
        unsafe {
            ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
            NET_RX_BUFFERS[i] = buf;
            let buf_phys = mm_virt_to_phys(buf);
            NET_RX_QUEUE.add_buf(buf_phys, BUFFER_SIZE, 0, 1);
        }
    }

    unsafe { NET_RX_QUEUE.kick(); }

    // DRIVER_OK
    let mut final_status = (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK) as u32;
    if is_v2 { final_status |= STATUS_FEATURES_OK as u32; }
    unsafe { virtio_write32(io_base + MMIO_STATUS, final_status); }

    unsafe {
        NET_TRANSPORT = Transport::Mmio { base: io_base, is_v2 };
        NET_GUEST_FEATURES = guest_features;
    }
    log(b"virtio_net: initialization complete (MMIO)\n\0");
    true
}

// ---- Legacy PCI init (x86_64) -----------------------------------------------

#[cfg(target_arch = "x86_64")]
fn init_legacy_pci() -> bool {
    // Find legacy virtio-net (0x1AF4/0x1000) or modern (0x1AF4/0x1041)
    let pci_idx = pci_find_device(0x1AF4, 0x1000)
        .or_else(|| pci_find_device(0x1AF4, 0x1041));
    let pci_idx = match pci_idx {
        Some(i) => i,
        None => return false,
    };

    let dev = unsafe { &PCI_DEVICES[pci_idx] };
    log(b"virtio_net: found legacy PCI device\n\0");

    // Verify subsystem device ID = 1 (network)
    let subsys = pci_read_config(dev.bus, dev.slot, dev.func, 0x2C);
    let subsys_device_id = ((subsys >> 16) & 0xFFFF) as u16;
    if subsys_device_id != 1 {
        log(b"virtio_net: not a network device\n\0");
        return false;
    }

    pci_enable_bus_mastering(dev.slot);

    // Get I/O base from BAR0
    let bar0 = dev.bar[0];
    if (bar0 & 0x01) == 0 {
        log(b"virtio_net: BAR0 is not I/O space\n\0");
        return false;
    }
    let io_base = (bar0 & !0x03u32) as u64;
    if io_base == 0 { return false; }

    // Reset
    unsafe { virtio_write8(io_base + VREG_DEVICE_STATUS, 0); }

    // ACKNOWLEDGE + DRIVER
    unsafe {
        virtio_write8(io_base + VREG_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
        virtio_write8(io_base + VREG_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    }

    // Feature negotiation
    let dev_features = unsafe { virtio_read32(io_base + VREG_DEVICE_FEATURES) };
    let mut guest_features: u32 = 0;
    if (dev_features & VIRTIO_NET_F_MAC) != 0 { guest_features |= VIRTIO_NET_F_MAC; }
    if (dev_features & VIRTIO_NET_F_STATUS) != 0 { guest_features |= VIRTIO_NET_F_STATUS; }
    if (dev_features & VIRTIO_NET_F_MRG_RXBUF) != 0 { guest_features |= VIRTIO_NET_F_MRG_RXBUF; }
    unsafe { virtio_write32(io_base + VREG_GUEST_FEATURES, guest_features); }

    // FEATURES_OK
    unsafe {
        virtio_write8(io_base + VREG_DEVICE_STATUS,
                      STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
        let status = virtio_read8(io_base + VREG_DEVICE_STATUS);
        if (status & STATUS_FEATURES_OK) == 0 {
            log(b"virtio_net: device did not accept features\n\0");
            virtio_write8(io_base + VREG_DEVICE_STATUS, STATUS_FAILED);
            return false;
        }
    }

    // Init RX and TX queues
    unsafe {
        if !NET_RX_QUEUE.init_legacy(io_base, 0, false, false) {
            log(b"virtio_net: failed to init RX queue\n\0");
            return false;
        }
        if !NET_TX_QUEUE.init_legacy(io_base, 1, false, false) {
            log(b"virtio_net: failed to init TX queue\n\0");
            return false;
        }
    }

    // Read MAC
    for i in 0..6u64 {
        unsafe { NET_MAC[i as usize] = virtio_read8(io_base + VREG_DEVICE_CONFIG + i); }
    }

    // Allocate RX buffers (no +2 alignment shift on x86)
    for i in 0..RX_BUFFERS {
        let buf = unsafe { mm_kmalloc(BUFFER_SIZE as usize) };
        if buf.is_null() { return false; }
        unsafe {
            ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
            NET_RX_BUFFERS[i] = buf;
            let buf_phys = mm_virt_to_phys(buf);
            NET_RX_QUEUE.add_buf(buf_phys, BUFFER_SIZE, 0, 1);
        }
    }

    unsafe { NET_RX_QUEUE.kick(); }

    // DRIVER_OK
    unsafe {
        virtio_write8(io_base + VREG_DEVICE_STATUS,
                      STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    }

    unsafe {
        NET_TRANSPORT = Transport::LegacyPci { base: io_base, pci_idx };
        NET_GUEST_FEATURES = guest_features;
    }
    log(b"virtio_net: initialization complete (legacy PCI)\n\0");
    true
}

// ---- TX drain ---------------------------------------------------------------

fn tx_drain() {
    let pool_phys = unsafe { mm_virt_to_phys(NET_TX_POOL.as_ptr() as *const u8) };
    unsafe {
        while let Some((used_id, _used_len)) = NET_TX_QUEUE.get_used() {
            let d = NET_TX_QUEUE.desc(used_id);
            let slot = ((d.addr - pool_phys) / core::mem::size_of::<TxBuf>() as u64) as usize;
            if slot < TX_POOL_SIZE {
                NET_TX_POOL_USED[slot] = false;
            }
        }
    }
}

// ---- IRQ handler -----------------------------------------------------------

// x86_64: extern "C" fn() wrapper for the idt.cc trampoline
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn driver_virtio_net_irq_handler_x86() {
    driver_virtio_net_irq_handler(0);
}

fn driver_virtio_net_irq_handler(_irq: u32) {
    unsafe {
        // NAPI: disable notifications on entry
        NET_RX_QUEUE.disable_interrupts();

        // Acknowledge device interrupt
        match NET_TRANSPORT {
            Transport::ModernPci { vpci_idx } => {
                vpci_read_isr(&VPCI_DEVICES[vpci_idx]);
            }
            #[cfg(target_arch = "aarch64")]
            Transport::Mmio { base, .. } => {
                let isr = virtio_read32(base + MMIO_INTERRUPT_STATUS);
                virtio_write32(base + MMIO_INTERRUPT_ACK, isr);
            }
            #[cfg(target_arch = "x86_64")]
            Transport::LegacyPci { base, .. } => {
                virtio_read8(base + VREG_ISR_STATUS);
            }
            Transport::None => {}
        }
    }
}

// ============================================================================
// Extern "C" API — VirtIO-net
// ============================================================================

#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_net_init() -> bool {
    log(b"virtio_net: initializing...\n\0");

    #[cfg(target_arch = "aarch64")]
    {
        if init_mmio() { return true; }
        return init_pci_modern();
    }
    #[cfg(target_arch = "x86_64")]
    {
        return init_legacy_pci();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_net_get_mac(mac_out: *mut u8) {
    unsafe {
        ptr::copy_nonoverlapping(NET_MAC.as_ptr(), mac_out, 6);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_net_send(data: *const u8, len: u32) {
    if data.is_null() || len == 0 { return; }
    unsafe {
        if let Transport::None = NET_TRANSPORT { return; }
    }
    let frame_len = if len > MAX_ETH_FRAME as u32 { MAX_ETH_FRAME as u32 } else { len };

    tx_drain();

    // Find a free pool slot; spin-drain if all busy
    let slot = loop {
        let mut found = None;
        for i in 0..TX_POOL_SIZE {
            if unsafe { !NET_TX_POOL_USED[i] } {
                found = Some(i);
                break;
            }
        }
        if let Some(s) = found { break s; }
        tx_drain();
        compiler_fence(Ordering::SeqCst);
    };

    unsafe {
        NET_TX_POOL_USED[slot] = true;
        let buf = &mut NET_TX_POOL[slot];
        buf.hdr.flags = 0;
        buf.hdr.gso_type = 0;
        buf.hdr.hdr_len = 0;
        buf.hdr.gso_size = 0;
        buf.hdr.csum_start = 0;
        buf.hdr.csum_offset = 0;
        buf.hdr.num_buffers = 1;

        ptr::copy_nonoverlapping(data, buf.data.as_mut_ptr(), frame_len as usize);

        let total_len = VIRTIO_NET_HDR_SIZE as u32 + frame_len;
        let buf_phys = mm_virt_to_phys(buf as *const TxBuf as *const u8);
        let head = NET_TX_QUEUE.add_buf(buf_phys, total_len, 1, 0);
        if head < 0 {
            NET_TX_POOL_USED[slot] = false;
            return;
        }

        NET_TX_QUEUE.kick();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_net_poll(
    callback: unsafe extern "C" fn(*const u8, u32),
) -> i32 {
    unsafe {
        if let Transport::None = NET_TRANSPORT { return 0; }
    }

    tx_drain();

    let mut count: i32 = 0;
    unsafe {
        while let Some((used_id, used_len)) = NET_RX_QUEUE.get_used() {
            let desc = NET_RX_QUEUE.desc(used_id);
            let buf = mm_phys_to_virt(desc.addr);

            if used_len > VIRTIO_NET_HDR_SIZE as u32 {
                let frame_len = used_len - VIRTIO_NET_HDR_SIZE as u32;
                let frame_data = buf.add(VIRTIO_NET_HDR_SIZE);
                callback(frame_data, frame_len);
            }

            // Re-arm RX buffer
            let buf_phys = mm_virt_to_phys(buf);
            NET_RX_QUEUE.add_buf(buf_phys, BUFFER_SIZE, 0, 1);
            count += 1;
        }

        if count > 0 {
            NET_RX_QUEUE.kick();
        }
    }

    count
}

#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_net_enable_irq() {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            let fdt = kernel_fdt::info();

            match NET_TRANSPORT {
                Transport::ModernPci { vpci_idx } if fdt.gic_dist_base != 0 => {
                    let slot = PCI_DEVICES[VPCI_DEVICES[vpci_idx].pci_idx].slot;
                    let intid = if (slot as usize) < 8 { fdt.pci_irqs[slot as usize] } else { 0 };
                    if intid != 0 {
                        NET_RX_QUEUE.enable_interrupts();
                        kernel_exceptions::exceptions_register_irq(intid, driver_virtio_net_irq_handler);
                        NET_IRQ_IDLE_AVAILABLE = true;
                    }
                }
                Transport::Mmio { base, .. } if fdt.gic_dist_base != 0 => {
                    for i in 0..fdt.virtio_count as usize {
                        if fdt.virtio_bases[i] == base && fdt.virtio_irqs[i] != 0 {
                            NET_RX_QUEUE.enable_interrupts();
                            kernel_exceptions::exceptions_register_irq(fdt.virtio_irqs[i], driver_virtio_net_irq_handler);
                            NET_IRQ_IDLE_AVAILABLE = true;
                            break;
                        }
                    }
                }
                _ => {}
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            if let Transport::LegacyPci { pci_idx, .. } = NET_TRANSPORT {
                let dev = &PCI_DEVICES[pci_idx];
                let irq_reg = pci_read_config(dev.bus, dev.slot, dev.func, 0x3C);
                let irq_line = (irq_reg & 0xFF) as u8;
                if irq_line < 16 {
                    NET_RX_QUEUE.enable_interrupts();
                    driver_register_irq(32 + irq_line as u32, driver_virtio_net_irq_handler_x86);
                    driver_x86_enable_irq(irq_line as u32);
                    NET_IRQ_IDLE_AVAILABLE = true;
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_net_irq_idle_supported() -> bool {
    unsafe { NET_IRQ_IDLE_AVAILABLE }
}

#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_net_arm_rx_interrupts() {
    unsafe { NET_RX_QUEUE.enable_interrupts(); }
}

#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_net_has_pending_rx() -> bool {
    unsafe { NET_RX_QUEUE.has_used() }
}

// ============================================================================
// VirtIO console driver (DeviceID=3)
//
// Uses static BSS memory for ring buffers so it can init before mm::init().
// Two queues: RX (queue 0) = host→guest, TX (queue 1) = guest→host.
// ============================================================================

const CON_QS: usize = 16;
const CON_AVAIL_OFF: usize = CON_QS * 16; // 256
const CON_USED_OFF: usize = 4096;

// Static ring memory (page-aligned, in BSS)
#[repr(C, align(4096))]
struct ConQueueMem([u8; 8192]);

static mut CON_TX_MEM: ConQueueMem = ConQueueMem([0; 8192]);
static mut CON_RX_MEM: ConQueueMem = ConQueueMem([0; 8192]);

static mut CON_TX_BUF: [u8; 1] = [0];
static mut CON_RX_BUFS: [u8; CON_QS] = [0; CON_QS];

static mut CON_BASE: u64 = 0; // non-zero = initialized
static mut CON_PCI_MODE: bool = false;
static mut CON_TX_NOTIFY: u64 = 0;
static mut CON_RX_NOTIFY: u64 = 0;
static mut CON_TX_AVAIL_IDX: u16 = 0;
static mut CON_TX_LAST_USED: u16 = 0;
static mut CON_RX_AVAIL_IDX: u16 = 0;
static mut CON_RX_LAST_USED: u16 = 0;

// Ring accessors using raw pointer arithmetic

unsafe fn con_desc_addr(mem: &mut ConQueueMem, i: usize) -> *mut u64 {
    mem.0.as_mut_ptr().add(i * 16) as *mut u64
}
unsafe fn con_desc_len(mem: &mut ConQueueMem, i: usize) -> *mut u32 {
    mem.0.as_mut_ptr().add(i * 16 + 8) as *mut u32
}
unsafe fn con_desc_flags(mem: &mut ConQueueMem, i: usize) -> *mut u16 {
    mem.0.as_mut_ptr().add(i * 16 + 12) as *mut u16
}
unsafe fn con_avail_idx_reg(mem: &mut ConQueueMem) -> *mut u16 {
    mem.0.as_mut_ptr().add(CON_AVAIL_OFF + 2) as *mut u16
}
unsafe fn con_avail_ring(mem: &mut ConQueueMem, i: usize) -> *mut u16 {
    mem.0.as_mut_ptr().add(CON_AVAIL_OFF + 4 + i * 2) as *mut u16
}
unsafe fn con_used_idx_reg(mem: &ConQueueMem) -> *const u16 {
    mem.0.as_ptr().add(CON_USED_OFF + 2) as *const u16
}
unsafe fn con_used_ring_id(mem: &ConQueueMem, i: usize) -> *const u32 {
    mem.0.as_ptr().add(CON_USED_OFF + 4 + i * 8) as *const u32
}

// ---- MMIO console init -------------------------------------------------------

fn con_init_mmio_queue(base: u64, qidx: u32, mem: &mut ConQueueMem, is_v2: bool) -> bool {
    unsafe {
        mmio_write32(base + MMIO_QUEUE_SEL, qidx);
        let qmax = mmio_read32(base + MMIO_QUEUE_NUM_MAX);
        if qmax == 0 { return false; }
        let qs = if (CON_QS as u32) < qmax { CON_QS as u32 } else { qmax };
        mmio_write32(base + MMIO_QUEUE_NUM, qs);

        if is_v2 {
            let desc_addr = mem.0.as_ptr() as u64;
            let avail_addr = desc_addr + CON_AVAIL_OFF as u64;
            let used_addr = desc_addr + CON_USED_OFF as u64;
            mmio_write32(base + MMIO_QUEUE_DESC_LOW, desc_addr as u32);
            mmio_write32(base + MMIO_QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);
            mmio_write32(base + MMIO_QUEUE_DRIVER_LOW, avail_addr as u32);
            mmio_write32(base + MMIO_QUEUE_DRIVER_HIGH, (avail_addr >> 32) as u32);
            mmio_write32(base + MMIO_QUEUE_DEVICE_LOW, used_addr as u32);
            mmio_write32(base + MMIO_QUEUE_DEVICE_HIGH, (used_addr >> 32) as u32);
            mmio_write32(base + MMIO_QUEUE_READY, 1);
        } else {
            mmio_write32(base + MMIO_QUEUE_ALIGN, 4096);
            mmio_write32(base + MMIO_QUEUE_PFN, (mem.0.as_ptr() as u64 >> 12) as u32);
        }
    }
    true
}

fn con_init_mmio(base_addr: u64) -> bool {
    unsafe {
        if mmio_read32(base_addr + MMIO_MAGIC_VALUE) != MMIO_MAGIC { return false; }
        let ver = mmio_read32(base_addr + MMIO_VERSION);
        if ver != 1 && ver != 2 { return false; }
        if mmio_read32(base_addr + MMIO_DEVICE_ID) != 3 { return false; }

        let is_v2 = ver == 2;

        // Reset → ACKNOWLEDGE → DRIVER
        mmio_write32(base_addr + MMIO_STATUS, 0);
        mmio_write32(base_addr + MMIO_STATUS, STATUS_ACKNOWLEDGE as u32);
        mmio_write32(base_addr + MMIO_STATUS, (STATUS_ACKNOWLEDGE | STATUS_DRIVER) as u32);

        if is_v2 {
            mmio_write32(base_addr + MMIO_DRIVER_FEATURES_SEL, 0);
            mmio_write32(base_addr + MMIO_GUEST_FEATURES, 0);
            mmio_write32(base_addr + MMIO_DRIVER_FEATURES_SEL, 1);
            mmio_write32(base_addr + MMIO_GUEST_FEATURES, 0);
            mmio_write32(base_addr + MMIO_STATUS,
                         (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK) as u32);
            if (mmio_read32(base_addr + MMIO_STATUS) & STATUS_FEATURES_OK as u32) == 0 {
                mmio_write32(base_addr + MMIO_STATUS, STATUS_FAILED as u32);
                return false;
            }
        } else {
            mmio_write32(base_addr + MMIO_GUEST_FEATURES, 0);
            mmio_write32(base_addr + MMIO_GUEST_PAGE_SIZE, 4096);
        }

        // Zero ring memory
        ptr::write_bytes(CON_RX_MEM.0.as_mut_ptr(), 0, 8192);
        ptr::write_bytes(CON_TX_MEM.0.as_mut_ptr(), 0, 8192);

        if !con_init_mmio_queue(base_addr, 0, &mut CON_RX_MEM, is_v2) { return false; }
        if !con_init_mmio_queue(base_addr, 1, &mut CON_TX_MEM, is_v2) { return false; }

        // Pre-populate RX descriptors
        for i in 0..CON_QS {
            ptr::write_volatile(con_desc_addr(&mut CON_RX_MEM, i),
                                CON_RX_BUFS.as_ptr().add(i) as u64);
            ptr::write_volatile(con_desc_len(&mut CON_RX_MEM, i), 1);
            ptr::write_volatile(con_desc_flags(&mut CON_RX_MEM, i), VIRTQ_DESC_F_WRITE);
            ptr::write_volatile(con_avail_ring(&mut CON_RX_MEM, i), i as u16);
            CON_RX_AVAIL_IDX += 1;
        }
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&mut CON_RX_MEM), CON_RX_AVAIL_IDX);
        dsb_sy();
        mmio_write32(base_addr + MMIO_QUEUE_NOTIFY, 0);

        // TX descriptor 0
        ptr::write_volatile(con_desc_addr(&mut CON_TX_MEM, 0), CON_TX_BUF.as_ptr() as u64);
        ptr::write_volatile(con_desc_len(&mut CON_TX_MEM, 0), 1);
        ptr::write_volatile(con_desc_flags(&mut CON_TX_MEM, 0), 0);

        let mut final_status = (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK) as u32;
        if is_v2 { final_status |= STATUS_FEATURES_OK as u32; }
        mmio_write32(base_addr + MMIO_STATUS, final_status);

        CON_BASE = base_addr;
        CON_PCI_MODE = false;
    }
    true
}

// ---- PCI console init (VZ.framework) -----------------------------------------

fn con_init_pci() -> bool {
    // Find console device (type 3) using Rust PCI infrastructure
    let vpci_idx = match vpci_find(3) {
        Some(i) => i,
        None => return false,
    };

    let dev = unsafe { &VPCI_DEVICES[vpci_idx] };

    vpci_reset(dev);
    vz_config_delay();
    vpci_set_status(dev, STATUS_ACKNOWLEDGE);
    vz_config_delay();
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    vz_config_delay();

    vpci_write_features(dev, 0, 0);
    vpci_write_features(dev, 1, 1); // VIRTIO_F_VERSION_1
    vz_config_delay();
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    vz_config_delay();
    if (vpci_get_status(dev) & STATUS_FEATURES_OK) == 0 {
        vpci_set_status(dev, STATUS_FAILED);
        return false;
    }

    unsafe {
        ptr::write_bytes(CON_RX_MEM.0.as_mut_ptr(), 0, 8192);
        ptr::write_bytes(CON_TX_MEM.0.as_mut_ptr(), 0, 8192);
    }

    // Init RX queue (0)
    vpci_select_queue(dev, 0);
    let qmax = vpci_get_queue_size(dev);
    if qmax == 0 { return false; }
    unsafe {
        let desc_addr = CON_RX_MEM.0.as_ptr() as u64;
        let avail_addr = desc_addr + CON_AVAIL_OFF as u64;
        let used_addr = desc_addr + CON_USED_OFF as u64;
        vpci_set_queue_addrs(dev, desc_addr, avail_addr, used_addr);
        vpci_enable_queue(dev);
    }

    // Init TX queue (1)
    vpci_select_queue(dev, 1);
    let qmax_tx = vpci_get_queue_size(dev);
    if qmax_tx == 0 { return false; }
    unsafe {
        let desc_addr = CON_TX_MEM.0.as_ptr() as u64;
        let avail_addr = desc_addr + CON_AVAIL_OFF as u64;
        let used_addr = desc_addr + CON_USED_OFF as u64;
        vpci_set_queue_addrs(dev, desc_addr, avail_addr, used_addr);
        vpci_enable_queue(dev);
    }

    // Get notify addresses
    vpci_select_queue(dev, 0);
    let rx_noff = vpci_get_queue_notify_off(dev);
    let rx_notify = vpci_queue_notify_addr(dev, rx_noff);

    vpci_select_queue(dev, 1);
    let tx_noff = vpci_get_queue_notify_off(dev);
    let tx_notify = vpci_queue_notify_addr(dev, tx_noff);

    // Pre-populate RX descriptors
    unsafe {
        for i in 0..CON_QS {
            ptr::write_volatile(con_desc_addr(&mut CON_RX_MEM, i),
                                CON_RX_BUFS.as_ptr().add(i) as u64);
            ptr::write_volatile(con_desc_len(&mut CON_RX_MEM, i), 1);
            ptr::write_volatile(con_desc_flags(&mut CON_RX_MEM, i), VIRTQ_DESC_F_WRITE);
            ptr::write_volatile(con_avail_ring(&mut CON_RX_MEM, i), i as u16);
            CON_RX_AVAIL_IDX += 1;
        }
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&mut CON_RX_MEM), CON_RX_AVAIL_IDX);
        dsb_sy();

        // TX descriptor 0
        ptr::write_volatile(con_desc_addr(&mut CON_TX_MEM, 0), CON_TX_BUF.as_ptr() as u64);
        ptr::write_volatile(con_desc_len(&mut CON_TX_MEM, 0), 1);
        ptr::write_volatile(con_desc_flags(&mut CON_TX_MEM, 0), 0);
    }

    // DRIVER_OK
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER |
                         STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    // Kick RX queue
    unsafe { ptr::write_volatile(rx_notify as *mut u16, 0); }

    vz_init_delay(); // VZ needs time after DRIVER_OK

    unsafe {
        CON_BASE = 1; // sentinel
        CON_PCI_MODE = true;
        CON_TX_NOTIFY = tx_notify;
        CON_RX_NOTIFY = rx_notify;
    }
    true
}

// ---- Console I/O ------------------------------------------------------------

fn con_putc(c: u8) {
    unsafe {
        if CON_BASE == 0 { return; }

        // Spin until previous TX completes
        while CON_TX_LAST_USED < CON_TX_AVAIL_IDX {
            let u = ptr::read_volatile(con_used_idx_reg(&CON_TX_MEM));
            if u != CON_TX_LAST_USED { CON_TX_LAST_USED = u; }
            #[cfg(target_arch = "aarch64")]
            asm!("yield", options(nostack, preserves_flags));
            #[cfg(target_arch = "x86_64")]
            asm!("pause", options(nostack, preserves_flags));
        }

        CON_TX_BUF[0] = c;

        dsb_st();
        let slot = (CON_TX_AVAIL_IDX % CON_QS as u16) as usize;
        ptr::write_volatile(con_avail_ring(&mut CON_TX_MEM, slot), 0);
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&mut CON_TX_MEM), CON_TX_AVAIL_IDX + 1);
        CON_TX_AVAIL_IDX += 1;
        dsb_sy();

        // Kick TX queue
        if CON_PCI_MODE {
            ptr::write_volatile(CON_TX_NOTIFY as *mut u16, 1);
        } else {
            mmio_write32(CON_BASE + MMIO_QUEUE_NOTIFY, 1);
        }

        // Spin until TX completes
        while ptr::read_volatile(con_used_idx_reg(&CON_TX_MEM)) == CON_TX_LAST_USED {
            #[cfg(target_arch = "aarch64")]
            asm!("yield", options(nostack, preserves_flags));
            #[cfg(target_arch = "x86_64")]
            asm!("pause", options(nostack, preserves_flags));
        }
        CON_TX_LAST_USED = ptr::read_volatile(con_used_idx_reg(&CON_TX_MEM));
    }
}

fn con_try_getc() -> i32 {
    unsafe {
        if CON_BASE == 0 { return -1; }

        let used_idx = ptr::read_volatile(con_used_idx_reg(&CON_RX_MEM));
        if used_idx == CON_RX_LAST_USED { return -1; }

        let slot = (CON_RX_LAST_USED % CON_QS as u16) as usize;
        let desc_id = ptr::read_volatile(con_used_ring_id(&CON_RX_MEM, slot)) as usize;
        let c = CON_RX_BUFS[desc_id] as i32;
        CON_RX_LAST_USED += 1;

        // Resubmit descriptor
        ptr::write_volatile(con_desc_addr(&mut CON_RX_MEM, desc_id),
                            CON_RX_BUFS.as_ptr().add(desc_id) as u64);
        ptr::write_volatile(con_desc_len(&mut CON_RX_MEM, desc_id), 1);
        ptr::write_volatile(con_desc_flags(&mut CON_RX_MEM, desc_id), VIRTQ_DESC_F_WRITE);

        dsb_st();
        let avail_slot = (CON_RX_AVAIL_IDX % CON_QS as u16) as usize;
        ptr::write_volatile(con_avail_ring(&mut CON_RX_MEM, avail_slot), desc_id as u16);
        dsb_st();
        ptr::write_volatile(con_avail_idx_reg(&mut CON_RX_MEM), CON_RX_AVAIL_IDX + 1);
        CON_RX_AVAIL_IDX += 1;
        dsb_sy();

        // Kick RX queue
        if CON_PCI_MODE {
            ptr::write_volatile(CON_RX_NOTIFY as *mut u16, 0);
        } else {
            mmio_write32(CON_BASE + MMIO_QUEUE_NOTIFY, 0);
        }

        c
    }
}

// ============================================================================
// Extern "C" API — VirtIO console
// ============================================================================

/// Initialize console via virtio-mmio at given base address.
/// Returns true if device found and initialized.
#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_console_init_mmio(base_addr: u64) -> bool {
    con_init_mmio(base_addr)
}

/// Initialize console via PCI (scans PCI bus, finds device type 3).
/// PCI must be initialized first (driver_pci_init).
#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_console_init_pci() -> bool {
    con_init_pci()
}

/// Write one byte to the console.
#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_console_putc(c: u8) {
    con_putc(c);
}

/// Try to read one byte from the console. Returns -1 if nothing available.
#[unsafe(no_mangle)]
pub extern "C" fn driver_virtio_console_try_getc() -> i32 {
    con_try_getc()
}
