// drivers/pci.rs — PCI config space access, bus scan, BAR assignment

use crate::{log, mmio_read32, mmio_write32, mmio_read16, mmio_write16};
#[cfg(target_arch = "aarch64")]
use crate::map_device_range;
#[cfg(target_arch = "aarch64")]
use kernel::aarch64::fdt;
use kernel::sync::Spinlock;

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

/// Discovered PCI devices + how many slots are filled. Behind a
/// spinlock so any future cross-core read/write is sound. The bus scan
/// fills the table during init (BSP, single-threaded); the rest of the
/// driver layer reads it via `find_device`/`pci_devices_get`.
pub(crate) struct PciDeviceTable {
    pub(crate) devices: [PciDevice; PCI_MAX_DEVICES],
    pub(crate) count: usize,
}

impl PciDeviceTable {
    const fn new() -> Self {
        PciDeviceTable {
            devices: [PciDevice::ZERO; PCI_MAX_DEVICES],
            count: 0,
        }
    }
}

pub(crate) static PCI_DEVICES: Spinlock<PciDeviceTable> =
    Spinlock::new(PciDeviceTable::new());

/// Init guard. Replaces a `static mut bool` checked-then-set, which would
/// let two cores both pass the guard and double-scan the bus.
/// `compare_exchange` makes the "first caller wins, others bail" intent
/// race-free.
static PCI_INITIALIZED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// ---- Config space access (arch-specific unsafe core) ------------------------

/// ECAM base. Set once in `init_inner` from FDT (with a fallback
/// constant for platforms that don't supply an ECAM node), read by
/// every config-space access. `InitOnce` gives release/acquire
/// publication; the volatile MMIO ops on the resulting address
/// provide the actual hardware ordering.
#[cfg(target_arch = "aarch64")]
const ECAM_BASE_DEFAULT: u64 = 0x40_1000_0000;
#[cfg(target_arch = "aarch64")]
pub(crate) static G_ECAM_BASE: kernel::once::InitOnce<u64> = kernel::once::InitOnce::new();
/// MMIO allocation pool cursor. Mutated by `assign_bars` during the
/// init bus scan; the spinlock around it serialises future cross-core
/// scans (currently only the BSP scans, but the lock makes it safe).
#[cfg(target_arch = "aarch64")]
pub(crate) static G_PCI_MEM_NEXT: Spinlock<u64> = Spinlock::new(0x1000_0000);

#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_ADDR: u16 = 0x0CF8;
#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_DATA: u16 = 0x0CFC;

#[cfg(target_arch = "aarch64")]
#[inline]
fn ecam_addr(bus: u8, slot: u8, func: u8, offset: u8) -> u64 {
    let base = *G_ECAM_BASE.get();
    base
        + ((bus as u64) << 20)
        + ((slot as u64) << 15)
        + ((func as u64) << 12)
        + (offset as u64)
}

/// Read 32-bit PCI config register (offset must be 4-byte aligned).
pub(crate) fn read_config(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
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
            mmio_read32(ecam_addr(bus, slot, func, offset & 0xFC))
        }
    }
}

/// Write 32-bit PCI config register.
pub(crate) fn write_config(bus: u8, slot: u8, func: u8, offset: u8, val: u32) {
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
            mmio_write32(ecam_addr(bus, slot, func, offset & 0xFC), val);
        }
    }
}

/// Read 16-bit PCI config register (aarch64 ECAM supports sub-dword access).
#[cfg(target_arch = "aarch64")]
pub(crate) fn read_config16(bus: u8, slot: u8, func: u8, offset: u8) -> u16 {
    unsafe { mmio_read16(ecam_addr(bus, slot, func, offset)) }
}

/// Write 16-bit PCI config register.
/// Critical for Command register (offset 0x04) to avoid clobbering Status.
#[cfg(target_arch = "aarch64")]
pub(crate) fn write_config16(bus: u8, slot: u8, func: u8, offset: u8, val: u16) {
    unsafe { mmio_write16(ecam_addr(bus, slot, func, offset), val); }
}

// ---- BAR assignment (aarch64 only) ------------------------------------------

/// Assign BARs from the MMIO pool. NEVER probes with 0xFFFFFFFF (crashes VZ).
#[cfg(target_arch = "aarch64")]
fn assign_bars(dev: &mut PciDevice) {
    // Only assign for endpoint devices (header type 0x00)
    if (dev.header_type & 0x7F) != 0x00 { return; }

    // Check if Memory Space is already enabled (firmware assigned BARs)
    let cmd = read_config16(dev.bus, dev.slot, dev.func, 0x04);
    if (cmd & 0x02) != 0 { return; } // Already enabled

    let mut mmio_next = G_PCI_MEM_NEXT.lock();

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

        if is_io {
            // Skip I/O BARs on aarch64
        } else if is_64bit {
            let alloc = (*mmio_next + 0x3F_FFFF) & !0x3F_FFFF; // 4MB align
            write_config(dev.bus, dev.slot, dev.func, (0x10 + i * 4) as u8, (alloc as u32) | (bar_val & 0x0F));
            write_config(dev.bus, dev.slot, dev.func, (0x10 + (i + 1) * 4) as u8, (alloc >> 32) as u32);
            dev.bar[i] = (alloc as u32) | (bar_val & 0x0F);
            dev.bar[i + 1] = (alloc >> 32) as u32;
            *mmio_next = alloc + 0x40_0000; // 4MB block
        } else {
            let alloc = (*mmio_next + 0x3F_FFFF) & !0x3F_FFFF; // 4MB align
            write_config(dev.bus, dev.slot, dev.func, (0x10 + i * 4) as u8, (alloc as u32) | (bar_val & 0x0F));
            dev.bar[i] = (alloc as u32) | (bar_val & 0x0F);
            *mmio_next = alloc + 0x40_0000;
        }

        i += if is_64bit { 2 } else { 1 };
    }

    drop(mmio_next);

    // Enable I/O + Memory Space + Bus Master
    let new_cmd = cmd | 0x07;
    write_config16(dev.bus, dev.slot, dev.func, 0x04, new_cmd);
}

// ---- Bus scan ---------------------------------------------------------------

fn probe_function(bus: u8, slot: u8, func: u8) -> bool {
    let reg0 = read_config(bus, slot, func, 0x00);
    let vendor_id = (reg0 & 0xFFFF) as u16;
    if vendor_id == 0xFFFF { return false; }

    let device_id = (reg0 >> 16) as u16;
    let reg8 = read_config(bus, slot, func, 0x08);
    let class_code = (reg8 >> 24) as u8;
    let subclass = (reg8 >> 16) as u8;
    let prog_if = (reg8 >> 8) as u8;
    let regc = read_config(bus, slot, func, 0x0C);
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
        dev.bar[i] = read_config(bus, slot, func, (0x10 + i * 4) as u8);
    }

    // Assign BARs on aarch64 if firmware hasn't
    #[cfg(target_arch = "aarch64")]
    {
        assign_bars(&mut dev);
        // Re-read BARs after assignment
        for i in 0..6 {
            dev.bar[i] = read_config(bus, slot, func, (0x10 + i * 4) as u8);
        }
    }

    let mut table = PCI_DEVICES.lock();
    if table.count < PCI_MAX_DEVICES {
        let idx = table.count;
        table.devices[idx] = dev;
        table.count += 1;
    }

    true
}

fn init_inner() {
    use core::sync::atomic::Ordering;
    // Race-free claim: only the first caller proceeds.
    if PCI_INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    log(b"[PCI] Scanning bus 0...\n");

    #[cfg(target_arch = "aarch64")]
    {
        let fdt = fdt::info();
        if fdt.pcie_ecam_base == 0 {
            // No PCI host bridge in FDT — skip the bus scan entirely.
            // This is normal for virtio-mmio-only platforms (Firecracker,
            // custom HVF runner). The virtio-net init will find devices
            // via FDT virtio-mmio nodes instead.
            log(b"[PCI] No ECAM in FDT, skipping\n");
            return;
        }
        let ecam = fdt.pcie_ecam_base;
        if ecam >= 0x1_0000_0000 {
            map_device_range(ecam, fdt.pcie_ecam_size);
        }
        G_ECAM_BASE.init(ecam);
        if fdt.pci_mmio32_base != 0 {
            // Reserve the first 4 MB of the PCI MMIO32 window for the
            // virtio-console device, which assigns its BAR directly from
            // pci_mmio32_base before this allocator runs.
            *G_PCI_MEM_NEXT.lock() = fdt.pci_mmio32_base + 0x40_0000;
        }
    }

    // Scan bus 0, slots 0-31
    for slot in 0..32u8 {
        if !probe_function(0, slot, 0) { continue; }

        // Check multi-function bit
        let regc = read_config(0, slot, 0, 0x0C);
        let header_type = (regc >> 16) as u8;
        if (header_type & 0x80) != 0 {
            for func in 1..8u8 {
                probe_function(0, slot, func);
            }
        }
    }

    log(b"[PCI] Scan complete\n");
}

pub(crate) fn find_device(vendor_id: u16, device_id: u16) -> Option<usize> {
    let table = PCI_DEVICES.lock();
    for i in 0..table.count {
        if table.devices[i].vendor_id == vendor_id && table.devices[i].device_id == device_id {
            return Some(i);
        }
    }
    None
}

/// Snapshot of `PCI_DEVICES[idx]` returned by value. PciDevice is Copy
/// so this is a cheap struct copy out from under the lock; the caller
/// can then read fields/BARs without holding the lock.
pub(crate) fn pci_device(idx: usize) -> PciDevice {
    PCI_DEVICES.lock().devices[idx]
}

pub(crate) fn enable_bus_mastering_inner(slot: u8) {
    #[cfg(target_arch = "aarch64")]
    {
        let cmd = read_config16(0, slot, 0, 0x04);
        write_config16(0, slot, 0, 0x04, cmd | 0x04);
    }
    #[cfg(target_arch = "x86_64")]
    {
        let cmd = read_config(0, slot, 0, 0x04);
        write_config(0, slot, 0, 0x04, cmd | 0x04);
    }
}

/// Read 64-bit BAR address from a device.
pub(crate) fn read_bar64(dev: &PciDevice, bar_idx: usize) -> u64 {
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
#[unsafe(export_name = "pci_init")]
pub extern "C" fn init() {
    init_inner();
}

pub fn enable_bus_mastering(slot: u8) {
    enable_bus_mastering_inner(slot);
}
