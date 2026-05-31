// drivers/pci.rs — PCI config space access, bus scan, BAR assignment

#[cfg(target_arch = "aarch64")]
use kernel_bare::mmu::map_device_range;
use crate::{mmio_read32, mmio_write32};
#[cfg(target_arch = "aarch64")]
use crate::{mmio_read16, mmio_write16};
#[cfg(target_arch = "aarch64")]
use kernel_bare::aarch64::fdt;
use sync::Spinlock;

#[cfg(target_arch = "x86_64")]
use crate::{inl, outl};

// ============================================================================
// PCI subsystem
// ============================================================================

pub const PCI_MAX_DEVICES: usize = 64;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PciDevice {
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
    pub const ZERO: Self = PciDevice {
        bus: 0,
        slot: 0,
        func: 0,
        vendor_id: 0,
        device_id: 0,
        class_code: 0,
        subclass: 0,
        prog_if: 0,
        header_type: 0,
        bar: [0; 6],
    };
}

/// Discovered PCI devices + how many slots are filled. Behind a
/// spinlock so any future cross-core read/write is sound. The bus scan
/// fills the table during init (BSP, single-threaded); the rest of the
/// driver layer reads it via `find_device`/`pci_devices_get`.
pub struct PciDeviceTable {
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

pub static PCI_DEVICES: Spinlock<PciDeviceTable> = Spinlock::new(PciDeviceTable::new());

/// Init guard. Replaces a `static mut bool` checked-then-set, which would
/// let two cores both pass the guard and double-scan the bus.
/// `compare_exchange` makes the "first caller wins, others bail" intent
/// race-free.
static PCI_INITIALIZED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

// ---- Config space access (arch-specific unsafe core) ------------------------

/// ECAM base. Set once during `init_inner`:
///
/// - aarch64: from the FDT `pci` node's `reg` property — always
///   available on the supported platforms (QEMU virt, HVF runner,
///   VZ.framework). Required.
/// - x86_64: from the ACPI MCFG table when present (q35 + UEFI/SeaBIOS
///   on KVM/TCG, GCE OVMF). Optional — legacy `pc`/`i440fx` machines
///   don't expose MCFG, in which case config access falls back to the
///   legacy 0xCF8/0xCFC port-I/O mechanism (slower: 2 vmexits per
///   dword vs 1 MMIO touch).
///
/// `InitOnce` gives release/acquire publication; the volatile MMIO
/// ops on the resulting address provide the actual hardware ordering.
pub static G_ECAM_BASE: kernel_bare::once::InitOnce<u64> = kernel_bare::once::InitOnce::new();
/// MMIO allocation pool cursor. Mutated by `assign_bars` during the
/// init bus scan; the spinlock around it serialises future cross-core
/// scans (currently only the BSP scans, but the lock makes it safe).
#[cfg(target_arch = "aarch64")]
pub static G_PCI_MEM_NEXT: Spinlock<u64> = Spinlock::new(0x1000_0000);

#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_ADDR: u16 = 0x0CF8;
#[cfg(target_arch = "x86_64")]
const PCI_CONFIG_DATA: u16 = 0x0CFC;

#[inline]
fn ecam_addr(bus: u8, slot: u8, func: u8, offset: u8) -> u64 {
    let base = *G_ECAM_BASE.get();
    base + ((bus as u64) << 20) + ((slot as u64) << 15) + ((func as u64) << 12) + (offset as u64)
}

/// Read 32-bit PCI config register (offset must be 4-byte aligned).
pub fn read_config(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            if G_ECAM_BASE.try_get().is_some() {
                return mmio_read32(ecam_addr(bus, slot, func, offset & 0xFC));
            }
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
pub fn write_config(bus: u8, slot: u8, func: u8, offset: u8, val: u32) {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            if G_ECAM_BASE.try_get().is_some() {
                mmio_write32(ecam_addr(bus, slot, func, offset & 0xFC), val);
                return;
            }
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

/// Read 16-bit PCI config register. ECAM supports sub-dword access on
/// both arches; on x86 without ECAM this is unreachable (callers gate
/// on aarch64 today).
#[cfg(target_arch = "aarch64")]
pub fn read_config16(bus: u8, slot: u8, func: u8, offset: u8) -> u16 {
    unsafe { mmio_read16(ecam_addr(bus, slot, func, offset)) }
}

/// Write 16-bit PCI config register.
/// Critical for Command register (offset 0x04) to avoid clobbering Status.
#[cfg(target_arch = "aarch64")]
pub fn write_config16(bus: u8, slot: u8, func: u8, offset: u8, val: u16) {
    unsafe {
        mmio_write16(ecam_addr(bus, slot, func, offset), val);
    }
}

// ---- BAR assignment (aarch64 only) ------------------------------------------

/// Assign BARs from the MMIO pool. NEVER probe the BAR size by writing
/// 0xFFFFFFFF — some hypervisors (notably Apple Virtualization.framework)
/// abort the guest on that write. Allocate blindly from the pool instead.
#[cfg(target_arch = "aarch64")]
fn assign_bars(dev: &mut PciDevice) {
    // Only assign for endpoint devices (header type 0x00)
    if (dev.header_type & 0x7F) != 0x00 {
        return;
    }

    // Check if Memory Space is already enabled (firmware assigned BARs)
    let cmd = read_config16(dev.bus, dev.slot, dev.func, 0x04);
    if (cmd & 0x02) != 0 {
        return;
    } // Already enabled

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
            write_config(
                dev.bus,
                dev.slot,
                dev.func,
                (0x10 + i * 4) as u8,
                (alloc as u32) | (bar_val & 0x0F),
            );
            write_config(
                dev.bus,
                dev.slot,
                dev.func,
                (0x10 + (i + 1) * 4) as u8,
                (alloc >> 32) as u32,
            );
            dev.bar[i] = (alloc as u32) | (bar_val & 0x0F);
            dev.bar[i + 1] = (alloc >> 32) as u32;
            *mmio_next = alloc + 0x40_0000; // 4MB block
        } else {
            let alloc = (*mmio_next + 0x3F_FFFF) & !0x3F_FFFF; // 4MB align
            write_config(
                dev.bus,
                dev.slot,
                dev.func,
                (0x10 + i * 4) as u8,
                (alloc as u32) | (bar_val & 0x0F),
            );
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
    if vendor_id == 0xFFFF {
        return false;
    }

    let device_id = (reg0 >> 16) as u16;
    let reg8 = read_config(bus, slot, func, 0x08);
    let class_code = (reg8 >> 24) as u8;
    let subclass = (reg8 >> 16) as u8;
    let prog_if = (reg8 >> 8) as u8;
    let regc = read_config(bus, slot, func, 0x0C);
    let header_type = (regc >> 16) as u8;

    let mut dev = PciDevice {
        bus,
        slot,
        func,
        vendor_id,
        device_id,
        class_code,
        subclass,
        prog_if,
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

    #[cfg(target_arch = "aarch64")]
    {
        let fdt = fdt::info();
        if fdt.pcie_ecam_base == 0 {
            // No PCI host bridge in FDT — skip the bus scan entirely.
            // This is normal for virtio-mmio-only platforms (Firecracker,
            // custom HVF runner). The virtio-net init will find devices
            // via FDT virtio-mmio nodes instead.
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

    #[cfg(target_arch = "x86_64")]
    {
        // Look up ECAM via ACPI MCFG so the bus scan below — and every
        // future config-space access — uses 1-vmexit MMIO instead of
        // 2-vmexit port-I/O (outl 0xCF8 + inl 0xCFC). On nested KVM
        // this halves config-space cost; on legacy `pc`/`i440fx`
        // machines (no MCFG) we silently fall back to port-I/O.
        if let Some(base) = unsafe { kernel_bare::x86_64::acpi::mcfg_ecam_base() } {
            G_ECAM_BASE.init(base);
        }
    }

    // Scan bus 0, slots 0-31
    for slot in 0..32u8 {
        if !probe_function(0, slot, 0) {
            continue;
        }

        // Check multi-function bit
        let regc = read_config(0, slot, 0, 0x0C);
        let header_type = (regc >> 16) as u8;
        if (header_type & 0x80) != 0 {
            for func in 1..8u8 {
                probe_function(0, slot, func);
            }
        }
    }
}

pub fn find_device(vendor_id: u16, device_id: u16) -> Option<usize> {
    let table = PCI_DEVICES.lock();
    (0..table.count).find(|&i| {
        table.devices[i].vendor_id == vendor_id && table.devices[i].device_id == device_id
    })
}

/// Snapshot of `PCI_DEVICES[idx]` returned by value. PciDevice is Copy
/// so this is a cheap struct copy out from under the lock; the caller
/// can then read fields/BARs without holding the lock.
pub fn pci_device(idx: usize) -> PciDevice {
    PCI_DEVICES.lock().devices[idx]
}

/// Log one line per discovered device. Boot diagnostic — answers
/// "what's on the PCI bus on this machine?" without an external
/// `lspci`. Vendor/device IDs are 4-hex; cross-reference at
/// pci-ids.ucw.cz or Google's PCI vendor list (0x1ae0).
pub fn log_devices() {
    let table = PCI_DEVICES.lock();
    for i in 0..table.count {
        let d = &table.devices[i];
        kernel_bare::serial::write_fmt(format_args!(
            "[pci] {:02x}:{:02x}.{} vendor={:04x} device={:04x} class={:02x}.{:02x}\n",
            d.bus, d.slot, d.func, d.vendor_id, d.device_id, d.class_code, d.subclass,
        ));
    }
}

/// Number of PCI devices found on bus 0 by `init`. Boot-log diagnostic
/// only — most callers should use `find_device(vendor, device)`.
pub fn device_count() -> usize {
    PCI_DEVICES.lock().count
}

pub fn enable_bus_mastering_inner(slot: u8) {
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
pub fn read_bar64(dev: &PciDevice, bar_idx: usize) -> u64 {
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

// ============================================================================
// MSI-X — generic capability programming
// ============================================================================
//
// The virtio transport (`bus::virtio`) has its own `vpci_msix_*` helpers
// bound to `VirtioPciDevice`; these are the transport-agnostic versions
// for drivers (gve) that talk to `bus::pci` directly. MSI-X is a standard
// PCI capability (ID 0x11): a table of 16-byte entries in a BAR, each
// `{ msg_addr_lo, msg_addr_hi, msg_data, vector_ctrl }`, gated by an
// Enable bit in the capability's Message Control word.

/// PCI MSI-X capability ID.
const PCI_CAP_ID_MSIX: u8 = 0x11;
/// PCI Status register bit 4: capabilities list present.
const PCI_STATUS_CAP_LIST: u32 = 1 << 4;

/// Parsed MSI-X capability for a device.
#[derive(Clone, Copy)]
pub struct MsixCap {
    /// Config-space offset of the capability header.
    pub cap_off: u8,
    /// Number of table entries (Message Control TableSize field + 1).
    pub table_size: u16,
    /// BAR index (BIR) holding the MSI-X table.
    pub table_bar: u8,
    /// Byte offset of the table within that BAR.
    pub table_offset: u32,
}

/// Walk the PCI capability list and return the MSI-X capability, if the
/// device exposes one. Reads config space via dword-aligned reads (the
/// capability headers are dword-aligned in practice).
pub fn find_msix_cap(dev: &PciDevice) -> Option<MsixCap> {
    // Capabilities present?
    let status = read_config(dev.bus, dev.slot, dev.func, 0x04);
    if (status & PCI_STATUS_CAP_LIST) == 0 {
        return None;
    }
    // Capability pointer at config 0x34 (low byte).
    let mut ptr = (read_config(dev.bus, dev.slot, dev.func, 0x34) & 0xFF) as u8;
    // Bounded walk (cap chain can't exceed config space; cap of 48 is
    // far more than any real device's chain — a malformed loop bails).
    for _ in 0..48 {
        if ptr == 0 || ptr == 0xFF {
            break;
        }
        let hdr = read_config(dev.bus, dev.slot, dev.func, ptr & 0xFC);
        // dword at `ptr`: [id:8][next:8][msg_ctrl:16] (ptr is dword-aligned).
        let id = (hdr & 0xFF) as u8;
        let next = ((hdr >> 8) & 0xFF) as u8;
        if id == PCI_CAP_ID_MSIX {
            let msg_ctrl = ((hdr >> 16) & 0xFFFF) as u16;
            let table_size = (msg_ctrl & 0x7FF) + 1;
            let toff = read_config(dev.bus, dev.slot, dev.func, ptr.wrapping_add(4) & 0xFC);
            return Some(MsixCap {
                cap_off: ptr,
                table_size,
                table_bar: (toff & 0x7) as u8,
                table_offset: toff & !0x7,
            });
        }
        ptr = next;
    }
    None
}

/// Enable (or disable) MSI-X in the capability's Message Control word.
/// Sets the Enable bit (15) and clears the Function-Mask bit (14) so
/// per-entry masks govern delivery. Message Control is the upper 16
/// bits of the dword at `cap_off`.
pub fn msix_enable(dev: &PciDevice, cap_off: u8, enable: bool) {
    let word = read_config(dev.bus, dev.slot, dev.func, cap_off & 0xFC);
    let mc = ((word >> 16) & 0xFFFF) as u16;
    let new_mc: u16 = if enable {
        (mc | 0x8000) & !0x4000
    } else {
        mc & !0x8000
    };
    let new_word = (word & 0x0000_FFFF) | ((new_mc as u32) << 16);
    write_config(dev.bus, dev.slot, dev.func, cap_off & 0xFC, new_word);
}

/// Program one MSI-X table entry at `table_va` (the mapped VA of the
/// table). Entry layout (16 bytes): `+0` addr_lo, `+4` addr_hi, `+8`
/// data, `+12` vector control (bit 0 = mask). Writing the mask bit last
/// unmasks only after addr/data are committed.
///
/// # Safety
/// `table_va` must be the mapped MSI-X table base and `entry` within the
/// device's advertised table size.
pub unsafe fn msix_write_entry(table_va: u64, entry: u16, addr: u64, data: u32, masked: bool) {
    let slot = table_va + (entry as u64) * 16;
    unsafe {
        mmio_write32(slot, addr as u32);
        mmio_write32(slot + 4, (addr >> 32) as u32);
        mmio_write32(slot + 8, data);
        mmio_write32(slot + 12, if masked { 1 } else { 0 });
    }
}

/// Build an x86 MSI message address for fixed, edge-triggered delivery
/// to the given LAPIC. Intel SDM Vol.3 §10.11.1: bits 31:20 = 0xFEE,
/// bits 19:12 = destination APIC ID.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn msix_msg_addr(apic_id: u32) -> u64 {
    0xFEE0_0000u64 | ((apic_id as u64) << 12)
}
