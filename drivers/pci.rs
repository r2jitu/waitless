// drivers/pci.rs — PCI config space access, bus scan, BAR assignment

use crate::{log, mmio_read32, mmio_write32, mmio_read16, mmio_write16};
#[cfg(target_arch = "aarch64")]
use crate::{map_device_range, kernel_fdt};

#[cfg(target_arch = "x86_64")]
use crate::{outl, inl};

// ============================================================================
// PCI subsystem
// ============================================================================

pub(crate) const PCI_MAX_DEVICES: usize = 64;

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub header_type: u8,
    pub bar: [u32; 6],
}

impl PciDevice {
    pub(crate) const ZERO: Self = PciDevice {
        bus: 0, slot: 0, func: 0,
        vendor_id: 0, device_id: 0,
        class_code: 0, subclass: 0, prog_if: 0,
        header_type: 0,
        bar: [0; 6],
    };
}

pub(crate) static mut PCI_DEVICES: [PciDevice; PCI_MAX_DEVICES] = [PciDevice::ZERO; PCI_MAX_DEVICES];
pub(crate) static mut PCI_DEVICE_COUNT: usize = 0;
static mut PCI_INITIALIZED: bool = false;

// ---- Config space access (arch-specific unsafe core) ------------------------

#[cfg(target_arch = "aarch64")]
pub(crate) static mut G_ECAM_BASE: u64 = 0x40_1000_0000;
#[cfg(target_arch = "aarch64")]
pub(crate) static mut G_PCI_MEM_NEXT: u64 = 0x1000_0000; // MMIO allocation pool

#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_ADDR: u16 = 0x0CF8;
#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_DATA: u16 = 0x0CFC;

/// Read 32-bit PCI config register (offset must be 4-byte aligned).
pub(crate) fn pci_read_config(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
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
pub(crate) fn pci_write_config(bus: u8, slot: u8, func: u8, offset: u8, val: u32) {
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
pub(crate) fn pci_read_config16(bus: u8, slot: u8, func: u8, offset: u8) -> u16 {
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
pub(crate) fn pci_write_config16(bus: u8, slot: u8, func: u8, offset: u8, val: u16) {
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

    log(b"[PCI] Scanning bus 0...\n");

    #[cfg(target_arch = "aarch64")]
    unsafe {
        let fdt = kernel_fdt::info();
        if fdt.pcie_ecam_base != 0 {
            G_ECAM_BASE = fdt.pcie_ecam_base;
            if G_ECAM_BASE >= 0x1_0000_0000 {
                map_device_range(G_ECAM_BASE, fdt.pcie_ecam_size);
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

    log(b"[PCI] Scan complete\n");
}

pub(crate) fn pci_find_device(vendor_id: u16, device_id: u16) -> Option<usize> {
    unsafe {
        for i in 0..PCI_DEVICE_COUNT {
            if PCI_DEVICES[i].vendor_id == vendor_id && PCI_DEVICES[i].device_id == device_id {
                return Some(i);
            }
        }
    }
    None
}

pub(crate) fn pci_enable_bus_mastering_inner(slot: u8) {
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
pub(crate) fn pci_read_bar64(dev: &PciDevice, bar_idx: usize) -> u64 {
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
// Public API — PCI
// ============================================================================

// NOTE: pci_init is also called from kernel/serial.rs via FFI
// (serial cannot depend on drivers due to circular dependency).
// Keep #[unsafe(no_mangle)] + extern "C" for FFI linkage.
#[unsafe(no_mangle)]
pub extern "C" fn pci_init() {
    pci_init_inner();
}

pub fn pci_enable_bus_mastering(slot: u8) {
    pci_enable_bus_mastering_inner(slot);
}
