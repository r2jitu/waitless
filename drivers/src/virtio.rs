// drivers/virtio.rs — VirtIO PCI transport (modern), legacy transport, and Virtqueue

use core::ptr;

use crate::{
    log, dsb_st, dsb_ld, dsb_sy,
    mmio_read32, mmio_write32, mmio_read16, mmio_write16, mmio_read8, mmio_write8,
    virtio_read32, virtio_write32, virtio_read16, virtio_write16, virtio_read8, virtio_write8,
};
use crate::pci::{
    pci_device, read_config, write_config, find_device,
    enable_bus_mastering_inner, read_bar64,
};
#[cfg(target_arch = "aarch64")]
use crate::map_device_range;
use uni_kernel::mm::{alloc_pages, phys_to_virt};

// ============================================================================
// VirtIO PCI transport (modern, VirtIO 1.0+)
// ============================================================================

// PCI capability IDs
const PCI_CAP_ID_VNDR: u8 = 0x09;
pub const PCI_CAP_ID_MSIX: u8 = 0x11;

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
pub const CC_CONFIG_MSIX_VECTOR: u64 = 0x10;
const CC_DEVICE_STATUS: u64 = 0x14;
const CC_QUEUE_SELECT: u64 = 0x16;
const CC_QUEUE_SIZE: u64 = 0x18;
pub const CC_QUEUE_MSIX_VECTOR: u64 = 0x1a;
const CC_QUEUE_ENABLE: u64 = 0x1c;
const CC_QUEUE_NOTIFY_OFF: u64 = 0x1e;
const CC_QUEUE_DESC_LO: u64 = 0x20;
const CC_QUEUE_DESC_HI: u64 = 0x24;
const CC_QUEUE_DRIVER_LO: u64 = 0x28;
const CC_QUEUE_DRIVER_HI: u64 = 0x2c;
const CC_QUEUE_DEVICE_LO: u64 = 0x30;
const CC_QUEUE_DEVICE_HI: u64 = 0x34;

pub const VIRTIO_PCI_MAX_DEVICES: usize = 8;

#[derive(Clone, Copy)]
pub struct VirtioPciDevice {
    pub pci_idx: usize,         // index into PCI_DEVICES
    pub common_cfg: u64,        // MMIO address of common_cfg
    pub notify_base: u64,       // MMIO address of notify cap
    pub device_cfg: u64,        // MMIO address of device-specific cfg
    pub isr_cfg: u64,           // MMIO address of ISR cap
    pub notify_off_multiplier: u32,
    /// Offset into PCI config space of the MSI-X capability structure,
    /// or 0 if the device doesn't expose one.
    pub msix_cap_off: u8,
    /// CPU virtual address of the MSI-X message table (BAR + offset).
    pub msix_table: u64,
    /// Number of entries in the MSI-X message table (message-control
    /// register's TableSize field + 1). Zero if MSI-X isn't supported.
    pub msix_table_size: u16,
}

impl VirtioPciDevice {
    pub const ZERO: Self = VirtioPciDevice {
        pci_idx: 0,
        common_cfg: 0,
        notify_base: 0,
        device_cfg: 0,
        isr_cfg: 0,
        notify_off_multiplier: 0,
        msix_cap_off: 0,
        msix_table: 0,
        msix_table_size: 0,
    };
}

/// VirtIO-PCI device table. Filled during init by `vpci_find`; read
/// thereafter as snapshots via `vpci_device(idx)`. Same shape as
/// `pci::PCI_DEVICES`.
pub struct VpciTable {
    pub(crate) devices: [VirtioPciDevice; VIRTIO_PCI_MAX_DEVICES],
    pub(crate) count: usize,
}

impl VpciTable {
    const fn new() -> Self {
        VpciTable {
            devices: [VirtioPciDevice::ZERO; VIRTIO_PCI_MAX_DEVICES],
            count: 0,
        }
    }
}

pub static VPCI_DEVICES: uni_kernel::sync::Spinlock<VpciTable> =
    uni_kernel::sync::Spinlock::new(VpciTable::new());

/// Snapshot of `VPCI_DEVICES[idx]` returned by value.
pub fn vpci_device(idx: usize) -> VirtioPciDevice {
    VPCI_DEVICES.lock().devices[idx]
}

/// Resolve a PCI BAR to a CPU virtual address. Maps above-4GB ranges on aarch64.
fn resolve_bar(pci_idx: usize, bar_idx: usize) -> u64 {
    let dev = pci_device(pci_idx);
    let addr = read_bar64(&dev, bar_idx);
    if addr == 0 { return 0; }

    #[cfg(target_arch = "aarch64")]
    if addr >= 0x1_0000_0000 {
        map_device_range(addr & !0x1F_FFFF, 2 << 20);
    }

    addr
}

/// Parse PCI capability list to find virtio-specific config structures.
fn vpci_parse_caps(dev: &mut VirtioPciDevice) -> bool {
    let pci = pci_device(dev.pci_idx);
    let (bus, slot, func) = (pci.bus, pci.slot, pci.func);

    // Check capabilities bit in Status register
    let status_cmd = read_config(bus, slot, func, 0x04);
    if ((status_cmd >> 16) & (1 << 4)) == 0 { return false; }

    let mut cap_ptr = (read_config(bus, slot, func, 0x34) & 0xFF) as u8;
    let mut found_common = false;
    let mut found_notify = false;

    while cap_ptr != 0 {
        let hdr = read_config(bus, slot, func, cap_ptr);
        let cap_vndr = (hdr & 0xFF) as u8;
        let cap_next = ((hdr >> 8) & 0xFF) as u8;

        if cap_vndr == PCI_CAP_ID_MSIX && dev.msix_cap_off == 0 {
            // MSI-X capability layout (PCIe base 3.0 §6.8.2):
            //   +0  cap id | next
            //   +2  message control  (bit 15 = enable, bit 14 = func mask,
            //                         bits 10..0 = TableSize - 1)
            //   +4  Table Offset/BIR (bits 2..0 = BAR index, rest = offset)
            //   +8  PBA   Offset/BIR
            dev.msix_cap_off = cap_ptr;
            let mc = (read_config(bus, slot, func, cap_ptr) >> 16) as u16;
            dev.msix_table_size = (mc & 0x7FF) + 1;
            let tbl_word = read_config(bus, slot, func, cap_ptr.wrapping_add(4));
            let bar_idx = (tbl_word & 0x7) as usize;
            let offset = (tbl_word & !0x7) as u64;
            let bar_base = resolve_bar(dev.pci_idx, bar_idx);
            if bar_base != 0 {
                dev.msix_table = bar_base + offset;
            }
        }

        if cap_vndr == PCI_CAP_ID_VNDR {
            let cfg_type = ((hdr >> 24) & 0xFF) as u8;
            let bar_word = read_config(bus, slot, func, cap_ptr.wrapping_add(4));
            let bar_idx = (bar_word & 0xFF) as usize;
            let offset = read_config(bus, slot, func, cap_ptr.wrapping_add(8)) as u64;

            let bar_base = resolve_bar(dev.pci_idx, bar_idx);
            if bar_base != 0 {
                match cfg_type {
                    VIRTIO_PCI_CAP_COMMON_CFG => {
                        dev.common_cfg = bar_base + offset;
                        found_common = true;
                    }
                    VIRTIO_PCI_CAP_NOTIFY_CFG => {
                        dev.notify_base = bar_base + offset;
                        dev.notify_off_multiplier = read_config(
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
/// Tries non-transitional ID (0x1040+type) first, then transitional
/// ID (0x1000-range) which QEMU uses by default.
///
/// Modern PCI IDs follow `0x1040 + type`; transitional IDs are
/// per-device-class and don't follow a clean formula (the v0.9.5
/// allocations were chosen before virtio types stabilised). Map
/// the ones we care about explicitly; unrecognised types fall
/// through to a "no transitional" lookup, returning None for that
/// path (callers still get the modern probe).
pub fn vpci_find(virtio_device_type: u16) -> Option<usize> {
    let modern_id = 0x1040 + virtio_device_type;
    let transitional_id: Option<u16> = match virtio_device_type {
        1 => Some(0x1000), // network card
        2 => Some(0x1001), // block device
        3 => Some(0x1003), // console (skips 0x1002 which is balloon)
        4 => Some(0x1005), // entropy
        5 => Some(0x1002), // balloon (yes — out of order in v0.9.5)
        8 => Some(0x1004), // SCSI host
        9 => Some(0x1009), // 9P transport
        _ => None,
    };

    let pci_idx = find_device(0x1AF4, modern_id)
        .or_else(|| transitional_id.and_then(|tid| find_device(0x1AF4, tid)))?;

    enable_bus_mastering_inner(pci_device(pci_idx).slot);

    // Build the VPCI entry in a local, then commit to the table.
    let mut dev = VirtioPciDevice::ZERO;
    dev.pci_idx = pci_idx;
    if !vpci_parse_caps(&mut dev) {
        return None;
    }

    let mut table = VPCI_DEVICES.lock();
    if table.count >= VIRTIO_PCI_MAX_DEVICES { return None; }
    let idx = table.count;
    table.devices[idx] = dev;
    table.count += 1;
    Some(idx)
}

// VirtIO PCI transport operations via common_cfg MMIO

pub fn vpci_reset(dev: &VirtioPciDevice) {
    unsafe {
        mmio_write8(dev.common_cfg + CC_DEVICE_STATUS, 0);
        while mmio_read8(dev.common_cfg + CC_DEVICE_STATUS) != 0 {
            core::arch::asm!("", options(nostack, preserves_flags));
        }
    }
}

pub fn vpci_set_status(dev: &VirtioPciDevice, status: u8) {
    unsafe { mmio_write8(dev.common_cfg + CC_DEVICE_STATUS, status); }
}

pub fn vpci_get_status(dev: &VirtioPciDevice) -> u8 {
    unsafe { mmio_read8(dev.common_cfg + CC_DEVICE_STATUS) }
}

pub fn vpci_read_features(dev: &VirtioPciDevice, word: u32) -> u32 {
    unsafe {
        mmio_write32(dev.common_cfg + CC_DEVICE_FEATURE_SELECT, word);
        mmio_read32(dev.common_cfg + CC_DEVICE_FEATURE)
    }
}

pub fn vpci_write_features(dev: &VirtioPciDevice, word: u32, features: u32) {
    unsafe {
        mmio_write32(dev.common_cfg + CC_DRIVER_FEATURE_SELECT, word);
        mmio_write32(dev.common_cfg + CC_DRIVER_FEATURE, features);
    }
}

pub fn vpci_select_queue(dev: &VirtioPciDevice, idx: u16) {
    unsafe { mmio_write16(dev.common_cfg + CC_QUEUE_SELECT, idx); }
}

pub fn vpci_get_queue_size(dev: &VirtioPciDevice) -> u16 {
    unsafe { mmio_read16(dev.common_cfg + CC_QUEUE_SIZE) }
}

pub fn vpci_set_queue_addrs(dev: &VirtioPciDevice, desc: u64, avail: u64, used: u64) {
    unsafe {
        mmio_write32(dev.common_cfg + CC_QUEUE_DESC_LO, desc as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DESC_HI, (desc >> 32) as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DRIVER_LO, avail as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DRIVER_HI, (avail >> 32) as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DEVICE_LO, used as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DEVICE_HI, (used >> 32) as u32);
    }
}

pub fn vpci_enable_queue(dev: &VirtioPciDevice) {
    unsafe { mmio_write16(dev.common_cfg + CC_QUEUE_ENABLE, 1); }
}

pub fn vpci_get_queue_notify_off(dev: &VirtioPciDevice) -> u16 {
    unsafe { mmio_read16(dev.common_cfg + CC_QUEUE_NOTIFY_OFF) }
}

pub fn vpci_queue_notify_addr(dev: &VirtioPciDevice, notify_off: u16) -> u64 {
    dev.notify_base + (notify_off as u64) * (dev.notify_off_multiplier as u64)
}

pub fn vpci_read_dev_cfg8(dev: &VirtioPciDevice, offset: u32) -> u8 {
    if dev.device_cfg == 0 { return 0; }
    unsafe { mmio_read8(dev.device_cfg + offset as u64) }
}

pub fn vpci_read_dev_cfg16(dev: &VirtioPciDevice, offset: u32) -> u16 {
    if dev.device_cfg == 0 { return 0; }
    unsafe { mmio_read16(dev.device_cfg + offset as u64) }
}

pub fn vpci_read_isr(dev: &VirtioPciDevice) -> u8 {
    if dev.isr_cfg == 0 { return 0; }
    unsafe { mmio_read8(dev.isr_cfg) }
}

pub fn vpci_set_queue_msix_vector(dev: &VirtioPciDevice, vector: u16) {
    unsafe { mmio_write16(dev.common_cfg + CC_QUEUE_MSIX_VECTOR, vector); }
}

pub fn vpci_set_config_msix_vector(dev: &VirtioPciDevice, vector: u16) {
    unsafe { mmio_write16(dev.common_cfg + CC_CONFIG_MSIX_VECTOR, vector); }
}

/// Toggle the `MSI-X Enable` bit in the device's message-control word.
/// The function-mask bit is cleared so individual entries control
/// delivery via their own per-vector mask.
pub fn vpci_msix_enable(dev: &VirtioPciDevice, enable: bool) {
    if dev.msix_cap_off == 0 { return; }
    let pci = pci_device(dev.pci_idx);
    let cap = dev.msix_cap_off;
    let word = read_config(pci.bus, pci.slot, pci.func, cap);
    let mc = ((word >> 16) & 0xFFFF) as u16;
    let new_mc: u16 = if enable {
        (mc | 0x8000) & !0x4000 // set Enable, clear FuncMask
    } else {
        mc & !0x8000
    };
    let new_word = (word & 0x0000_FFFF) | ((new_mc as u32) << 16);
    write_config(pci.bus, pci.slot, pci.func, cap, new_word);
}

/// Program one MSI-X table entry: address, data, and mask bit.
/// Each entry is 16 bytes: addr_lo, addr_hi, data, vector_ctrl.
pub fn vpci_msix_write_entry(
    dev: &VirtioPciDevice,
    entry: u16,
    addr: u64,
    data: u32,
    masked: bool,
) {
    if dev.msix_table == 0 || entry >= dev.msix_table_size {
        return;
    }
    let slot = dev.msix_table + (entry as u64) * 16;
    unsafe {
        mmio_write32(slot,        addr as u32);
        mmio_write32(slot + 4,   (addr >> 32) as u32);
        mmio_write32(slot + 8,    data);
        mmio_write32(slot + 12,   if masked { 1 } else { 0 });
    }
}

// ============================================================================
// Virtio legacy transport (x86_64 PCI I/O ports, aarch64 MMIO)
// ============================================================================

// Legacy PCI I/O register offsets
pub const VREG_DEVICE_FEATURES: u64 = 0x00;
pub const VREG_GUEST_FEATURES: u64 = 0x04;
pub const VREG_QUEUE_ADDRESS: u64 = 0x08;
pub const VREG_QUEUE_SIZE: u64 = 0x0C;
pub const VREG_QUEUE_SELECT: u64 = 0x0E;
pub const VREG_QUEUE_NOTIFY: u64 = 0x10;
pub const VREG_DEVICE_STATUS: u64 = 0x12;
pub const VREG_ISR_STATUS: u64 = 0x13;
pub const VREG_DEVICE_CONFIG: u64 = 0x14;

// Virtio-MMIO register offsets (aarch64 QEMU)
pub const MMIO_BASE: u64 = 0x0a00_0000;
pub const MMIO_MAGIC_VALUE: u64 = 0x000;
pub const MMIO_VERSION: u64 = 0x004;
pub const MMIO_DEVICE_ID: u64 = 0x008;
pub const MMIO_HOST_FEATURES: u64 = 0x010;
pub const MMIO_DEVICE_FEATURES_SEL: u64 = 0x014;
pub const MMIO_GUEST_FEATURES: u64 = 0x020;
pub const MMIO_DRIVER_FEATURES_SEL: u64 = 0x024;
pub const MMIO_GUEST_PAGE_SIZE: u64 = 0x028;
pub const MMIO_QUEUE_SEL: u64 = 0x030;
pub const MMIO_QUEUE_NUM_MAX: u64 = 0x034;
pub const MMIO_QUEUE_NUM: u64 = 0x038;
pub const MMIO_QUEUE_ALIGN: u64 = 0x03c;
pub const MMIO_QUEUE_PFN: u64 = 0x040;
pub const MMIO_QUEUE_READY: u64 = 0x044;
pub const MMIO_QUEUE_NOTIFY: u64 = 0x050;
pub const MMIO_INTERRUPT_STATUS: u64 = 0x060;
pub const MMIO_INTERRUPT_ACK: u64 = 0x064;
pub const MMIO_STATUS: u64 = 0x070;
pub const MMIO_DEVICE_CONFIG: u64 = 0x100;
pub const MMIO_MAGIC: u32 = 0x74726976;
// MMIO v2 separate ring address registers
pub const MMIO_QUEUE_DESC_LOW: u64 = 0x080;
pub const MMIO_QUEUE_DESC_HIGH: u64 = 0x084;
pub const MMIO_QUEUE_DRIVER_LOW: u64 = 0x090;
pub const MMIO_QUEUE_DRIVER_HIGH: u64 = 0x094;
pub const MMIO_QUEUE_DEVICE_LOW: u64 = 0x0a0;
pub const MMIO_QUEUE_DEVICE_HIGH: u64 = 0x0a4;

// Device status bits
pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_FAILED: u8 = 128;

// Virtqueue descriptor flags
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
pub const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;
/// Device sets this on used->flags to tell the driver: don't send
/// notifications for this queue. Standard virtio spec §2.7.13.
pub const VIRTQ_USED_F_NO_NOTIFY: u16 = 1;

// Feature bits
/// Driver handles packets with partial checksum (host computes for us).
/// Required as a prerequisite for `VIRTIO_NET_F_HOST_TSO4`.
pub const VIRTIO_NET_F_CSUM: u32 = 1 << 0;
pub const VIRTIO_NET_F_MAC: u32 = 1 << 5;
/// Device can handle TCPv4 GSO from the driver — we hand it a single
/// super-segment with `gso_type=TCPV4` + `gso_size=MSS`, the device
/// segments it host-side. Saves the per-MSS frame-build loop on TX.
pub const VIRTIO_NET_F_HOST_TSO4: u32 = 1 << 11;
pub const VIRTIO_NET_F_MRG_RXBUF: u32 = 1 << 15;
pub const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
pub const VIRTIO_NET_F_MQ: u32 = 1 << 22;
pub const VIRTIO_NET_F_CTRL_VQ: u32 = 1 << 17;
pub const VIRTIO_RING_F_EVENT_IDX: u32 = 1 << 29;
/// Vendor extension: device exposes per-queue used_idx at config offset 0x110.
/// When set, get_used() reads used_idx via MMIO trap instead of from shared
/// RAM, working around dcache coherency issues on Apple HVF.
pub const VIRTIO_F_USED_IDX_MMIO: u32 = 1 << 24;

// ============================================================================
// Split Virtqueue
// ============================================================================

// Virtqueue descriptor (must match hardware layout: 16 bytes packed)
#[repr(C, packed)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

// Available ring header (naturally aligned, no padding)
#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    // ring[queue_size] follows, then used_event (u16)
}

// Used ring element (naturally aligned)
#[repr(C)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

// Used ring header (naturally aligned)
#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    // ring[queue_size] of VirtqUsedElem follows
}

pub struct Virtqueue {
    pub descs: *mut VirtqDesc,
    pub avail: *mut VirtqAvail,
    pub used: *mut VirtqUsed,
    pub queue_size: u16,
    pub free_head: u16,
    pub num_free: u16,
    pub last_used_idx: u16,
    pub io_base: u64,
    pub notify_addr: u64,
    pub queue_index: u16,
    pub is_mmio: bool,
    pub event_idx: bool,
    /// Device supports MMIO-based used_idx read (VIRTIO_F_USED_IDX_MMIO).
    pub used_idx_mmio: bool,
    /// Cached used_idx from last poll_interrupt_status() call.
    pub mmio_cached_used_idx: u16,
    /// Deferred kick: set by kick(), cleared by flush_kick().
    /// Batches multiple add_buf+kick into a single MMIO notify write.
    pub pending_kick: bool,
    /// True if add_buf was called since last flush_kick(). Prevents
    /// flush_kick from issuing a spurious MMIO write when no new
    /// buffers were added.
    pub kick_dirty: bool,
}

impl Virtqueue {
    pub const ZERO: Self = Virtqueue {
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
        used_idx_mmio: false,
        mmio_cached_used_idx: 0,
        pending_kick: false,
        kick_dirty: false,
    };

    /// Allocate ring memory and set up descriptor free list.
    /// Returns (desc_phys, avail_phys, used_phys) for the caller to program the device.
    pub fn alloc_rings(&mut self, queue_size: u16, notify_addr: u64,
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

        // Single contiguous allocation. The pre-talc frame
        // allocator scanned its bitmap and effectively handed out
        // sequential pages from N back-to-back `alloc_frame` calls,
        // but the heap-backed `alloc_frame` makes no such promise —
        // virtio's `used` ring lives at `phys_base + first_region`,
        // so a non-contiguous second allocation would corrupt
        // unrelated heap memory on every device DMA.
        let phys_base = alloc_pages(num_frames as usize);
        if phys_base == 0 { return None; }

        let base_ptr = phys_to_virt(phys_base);
        unsafe { ptr::write_bytes(base_ptr, 0, total_size as usize); }

        self.descs = base_ptr as *mut VirtqDesc;
        self.avail = unsafe { base_ptr.add(desc_size as usize) } as *mut VirtqAvail;
        self.used = unsafe { base_ptr.add(first_region as usize) } as *mut VirtqUsed;

        // Initialize free descriptor linked list
        for i in 0..queue_size {
            let d = self.desc_mut(i);
            d.next = i + 1;
            d.flags = 0;
        }
        self.free_head = 0;
        self.num_free = queue_size;
        self.last_used_idx = 0;

        // Suppress interrupts by default (polling mode)
        self.set_avail_flags(VIRTQ_AVAIL_F_NO_INTERRUPT);

        let desc_phys = phys_base;
        let avail_phys = phys_base + desc_size;
        let used_phys = phys_base + first_region;

        Some((desc_phys, avail_phys, used_phys))
    }

    /// Initialize for modern PCI transport.
    pub fn init_pci_modern(&mut self, queue_size: u16, notify_addr: u64,
                       queue_index: u16) -> Option<(u64, u64, u64)> {
        self.is_mmio = false;
        self.alloc_rings(queue_size, notify_addr, queue_index)
    }

    /// Initialize for legacy PCI or MMIO transport.
    pub fn init_legacy(&mut self, base: u64, queue_index: u16,
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

    /// Add a multi-segment buffer chain to the available ring.
    ///
    /// Each element of `segs` is `(phys_addr, len, writeable)`. The
    /// `writeable = true` segments become device-writable descriptors
    /// (VIRTQ_DESC_F_WRITE); per the spec all readable segments must
    /// come first, followed by writable segments.
    ///
    /// Used by control-VQ commands where the header, data, and ack
    /// byte live in distinct buffers and must each occupy their own
    /// descriptor — QEMU 10 rejects a single descriptor that bundles
    /// header + data even when the total byte count matches.
    pub fn add_chain(&mut self, segs: &[(u64, u32, bool)]) -> i32 {
        let total = segs.len() as u16;
        if total == 0 || self.num_free < total { return -1; }

        let head = self.free_head;
        let mut idx = head;
        for (i, &(phys, len, writeable)) in segs.iter().enumerate() {
            let d = self.desc_mut(idx);
            d.addr = phys;
            d.len = len;
            d.flags = if writeable { VIRTQ_DESC_F_WRITE } else { 0 };
            if (i as u16) < total - 1 { d.flags |= VIRTQ_DESC_F_NEXT; }
            idx = d.next;
        }

        self.free_head = idx;
        self.num_free -= total;

        let avail_idx = self.avail_idx();
        let ring_slot = avail_idx & (self.queue_size - 1);
        self.set_avail_ring(ring_slot, head);
        dsb_st();
        self.set_avail_idx(avail_idx.wrapping_add(1));

        head as i32
    }

    /// Add a buffer chain to the available ring.
    /// Returns head descriptor index, or -1 on failure.
    pub fn add_buf(&mut self, buf_phys: u64, buf_len: u32, out_count: u16, in_count: u16) -> i32 {
        let total = out_count + in_count;
        if total == 0 || self.num_free < total { return -1; }

        let head = self.free_head;
        let mut idx = head;

        // Output (device-readable) buffers
        for i in 0..out_count {
            let d = self.desc_mut(idx);
            d.addr = buf_phys;
            d.len = buf_len;
            d.flags = if i < total - 1 { VIRTQ_DESC_F_NEXT } else { 0 };
            idx = d.next;
        }

        // Input (device-writable) buffers
        for i in 0..in_count {
            let d = self.desc_mut(idx);
            d.addr = buf_phys;
            d.len = buf_len;
            d.flags = VIRTQ_DESC_F_WRITE;
            if i < in_count - 1 { d.flags |= VIRTQ_DESC_F_NEXT; }
            idx = d.next;
        }

        self.free_head = idx;
        self.num_free -= total;

        // Add chain head to available ring
        {
            let avail_idx = self.avail_idx();
            let ring_slot = avail_idx & (self.queue_size - 1);
            self.set_avail_ring(ring_slot, head);

            dsb_st();

            self.set_avail_idx(avail_idx.wrapping_add(1));
        }

        head as i32
    }

    /// Notify the device that new buffers are available.
    /// For TX queues with pending_kick, defers the actual MMIO write
    /// until flush_kick() — batching multiple segments into one exit.
    pub fn kick(&mut self) {
        self.kick_dirty = true;
        if self.pending_kick {
            // Already deferred — actual write happens in flush_kick().
            return;
        }
        self.kick_now();
    }

    /// Immediate kick — writes MMIO unless device says NO_NOTIFY.
    fn kick_now(&self) {
        // Standard virtio: check if device suppressed notifications.
        let used_flags = unsafe { ptr::read_volatile(&(*self.used).flags) };
        if used_flags & VIRTQ_USED_F_NO_NOTIFY != 0 {
            return;
        }
        dsb_st();
        if self.notify_addr != 0 {
            unsafe { ptr::write_volatile(self.notify_addr as *mut u16, self.queue_index); }
        } else if self.is_mmio {
            unsafe { virtio_write32(self.io_base + MMIO_QUEUE_NOTIFY, self.queue_index as u32); }
        } else {
            unsafe { virtio_write16(self.io_base + VREG_QUEUE_NOTIFY, self.queue_index); }
        }
    }

    /// Enable deferred kick mode. kick() becomes a no-op until flush_kick().
    pub fn set_deferred_kick(&mut self, defer: bool) {
        self.pending_kick = defer;
    }

    /// Flush a deferred kick — issues one MMIO write for all batched buffers.
    /// Always kicks if pending (even if not dirty). Used on the idle path
    /// where the kick serves as a yield-to-host to let the IO thread run.
    pub fn flush_kick(&mut self) {
        if self.pending_kick {
            self.kick_dirty = false;
            self.kick_now();
        }
    }

    /// Flush only if dirty. Returns true if a kick was actually issued.
    /// Use this on the work path; the idle path should call kick_now()
    /// directly to yield to the host (even with nothing to send).
    pub fn flush_kick_if_dirty(&mut self) -> bool {
        if self.pending_kick && self.kick_dirty {
            self.kick_dirty = false;
            self.kick_now();
            true
        } else {
            false
        }
    }

    /// Check for completed buffers in the used ring.
    /// Returns (descriptor_head_id, bytes_written) or None.
    /// Read INTERRUPT_STATUS and extract the device-side used_idx
    /// packed in the upper 16 bits (VIRTIO_F_USED_IDX_MMIO extension).
    /// Call once per poll cycle; used() then uses the cached value.
    pub fn poll_interrupt_status(&mut self) -> u32 {
        if self.used_idx_mmio {
            let val = unsafe { virtio_read32(self.io_base + MMIO_INTERRUPT_STATUS) };
            // Upper 16 bits = RX used_idx from device.
            self.mmio_cached_used_idx = (val >> 16) as u16;
            val & 0xFFFF
        } else {
            0
        }
    }

    pub fn used(&mut self) -> Option<(u16, u32)> {
        let cur_used_idx = if self.used_idx_mmio {
            // First check the cached value (no MMIO exit).
            // If stale, do one MMIO read to refresh — this also
            // triggers check_rx on the host, injecting any pending frames.
            let cached = self.mmio_cached_used_idx;
            if cached == self.last_used_idx {
                self.poll_interrupt_status();
                self.mmio_cached_used_idx
            } else {
                cached
            }
        } else {
            dsb_ld();
            self.used_idx()
        };
        if self.last_used_idx == cur_used_idx { return None; }

        let used_slot = self.last_used_idx & (self.queue_size - 1);
        let id = self.used_ring_id(used_slot) as u16;
        let len = self.used_ring_len(used_slot);

        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        // Return descriptors in this chain to the free list
        let mut idx = id;
        loop {
            self.num_free += 1;
            let flags = self.desc(idx).flags;
            let next = self.desc(idx).next;
            if (flags & VIRTQ_DESC_F_NEXT) == 0 {
                self.desc_mut(idx).next = self.free_head;
                self.free_head = id;
                break;
            }
            idx = next;
        }

        Some((id, len))
    }

    pub fn has_used(&mut self) -> bool {
        if self.used_idx_mmio {
            // Check cached value first. If stale, do one MMIO read
            // to trigger check_rx and get fresh used_idx. This prevents
            // false-negative before WFI (which causes multi-hundred-ms stalls).
            if self.last_used_idx == self.mmio_cached_used_idx {
                self.poll_interrupt_status();
            }
            self.last_used_idx != self.mmio_cached_used_idx
        } else {
            self.last_used_idx != self.used_idx()
        }
    }

    pub fn enable_interrupts(&mut self) {
        self.set_avail_flags(0);
        if self.event_idx {
            // Write used_event = used->idx after avail->ring[queue_size]
            let cur_used_idx = self.used_idx();
            self.set_used_event(cur_used_idx);
        }
        // Flush the flag / used_event write to main memory BEFORE the
        // device next polls them. Without this DSB, the device can
        // read stale avail->flags (and miss the re-enable, or keep
        // firing after a disable); with weakly-ordered aarch64 that's
        // not a theoretical concern — it was the root cause of a
        // virtio-mmio IRQ storm on QEMU aarch64 where disable_interrupts
        // appeared ignored.
        dsb_st();
    }

    pub fn disable_interrupts(&mut self) {
        self.set_avail_flags(VIRTQ_AVAIL_F_NO_INTERRUPT);
        if self.event_idx {
            // Under VIRTIO_F_EVENT_IDX the device ignores avail->flags
            // and consults used_event instead (virtio 1.2 §2.7.10 / the
            // vhost vring_need_event formula:
            //   notify ⇔ (new - used_event - 1) < (new - old)
            // all u16 wrap). Writing `used_event = used_idx - 1` makes
            // that evaluate (N - (U-1) - 1) < (N - (U-1)) — i.e.
            // 1 < 1, false — for every single-batch ADD, so the device
            // stays silent until enable_interrupts() writes a fresh
            // used_event. Matches the Linux virtio-ring
            // `virtqueue_disable_cb_split` approach.
            let cur = self.used_idx();
            self.set_used_event(cur.wrapping_sub(1));
        }
        // DSB for the same reason as enable_interrupts: ensure the
        // suppression is visible before the device next reads the
        // flags / used_event and decides whether to notify.
        dsb_st();
    }

    // ---- Ring buffer access helpers ----
    // These encapsulate the raw pointer arithmetic for the split virtqueue
    // ring structures. The underlying memory is allocated by alloc_rings()
    // and these pointers are valid for the lifetime of the Virtqueue.

    /// Get a shared reference to the descriptor at `idx`.
    pub fn desc(&self, idx: u16) -> &VirtqDesc {
        // SAFETY: descs points to a valid array of queue_size VirtqDesc entries
        // allocated in alloc_rings(), and idx is expected to be < queue_size.
        unsafe { &*self.descs.add(idx as usize) }
    }

    /// Get a mutable reference to the descriptor at `idx`.
    pub fn desc_mut(&mut self, idx: u16) -> &mut VirtqDesc {
        // SAFETY: descs points to a valid array of queue_size VirtqDesc entries
        // allocated in alloc_rings(), and idx is expected to be < queue_size.
        unsafe { &mut *self.descs.add(idx as usize) }
    }

    /// Read the available ring entry at position `idx` (the descriptor index
    /// stored in avail->ring[idx % queue_size]).
    pub fn avail_ring(&self, idx: u16) -> u16 {
        // SAFETY: The avail ring entries start at offset 4 (after flags + idx)
        // from avail base. The ring has queue_size u16 entries.
        unsafe {
            let ring_ptr = (self.avail as *const u8).add(4) as *const u16;
            ptr::read_volatile(ring_ptr.add(idx as usize))
        }
    }

    /// Write a descriptor index into the available ring at position `idx`.
    pub fn set_avail_ring(&mut self, idx: u16, val: u16) {
        // SAFETY: The avail ring entries start at offset 4 (after flags + idx)
        // from avail base. The ring has queue_size u16 entries.
        unsafe {
            let ring_ptr = (self.avail as *mut u8).add(4) as *mut u16;
            ptr::write_volatile(ring_ptr.add(idx as usize), val);
        }
    }

    /// Read the id field of the used ring element at position `idx`.
    pub fn used_ring_id(&self, idx: u16) -> u32 {
        // SAFETY: The used ring elements start at offset 4 (after flags + idx)
        // from used base. Each element is a VirtqUsedElem (8 bytes).
        unsafe {
            let ring_ptr = (self.used as *const u8).add(4) as *const VirtqUsedElem;
            ptr::read_volatile(&(*ring_ptr.add(idx as usize)).id)
        }
    }

    /// Read the len field of the used ring element at position `idx`.
    pub fn used_ring_len(&self, idx: u16) -> u32 {
        // SAFETY: The used ring elements start at offset 4 (after flags + idx)
        // from used base. Each element is a VirtqUsedElem (8 bytes).
        unsafe {
            let ring_ptr = (self.used as *const u8).add(4) as *const VirtqUsedElem;
            ptr::read_volatile(&(*ring_ptr.add(idx as usize)).len)
        }
    }

    /// Read avail->idx (volatile, device may read concurrently).
    fn avail_idx(&self) -> u16 {
        // SAFETY: avail points to a valid VirtqAvail header.
        unsafe { ptr::read_volatile(&(*self.avail).idx) }
    }

    /// Write avail->idx (volatile, device may read concurrently).
    fn set_avail_idx(&mut self, val: u16) {
        // SAFETY: avail points to a valid VirtqAvail header.
        unsafe { ptr::write_volatile(&mut (*self.avail).idx, val); }
    }

    /// Read used->idx (volatile, device writes this).
    pub fn used_idx(&self) -> u16 {
        // SAFETY: used points to a valid VirtqUsed header.
        unsafe { ptr::read_volatile(&(*self.used).idx) }
    }

    /// Read our cached cursor into the used ring — how many used
    /// entries the driver has already consumed. Paired with
    /// `used_idx()`: if `used_idx() > last_used_cursor()` the device
    /// has delivered frames we haven't picked up yet.
    pub fn last_used_cursor(&self) -> u16 {
        self.last_used_idx
    }

    /// Write avail->flags (volatile).
    fn set_avail_flags(&mut self, val: u16) {
        // SAFETY: avail points to a valid VirtqAvail header.
        unsafe { ptr::write_volatile(&mut (*self.avail).flags, val); }
    }

    /// Write the used_event field (located after avail->ring[queue_size]).
    fn set_used_event(&mut self, val: u16) {
        // SAFETY: used_event is the u16 immediately after avail->ring[queue_size],
        // i.e. at offset 4 + 2*queue_size from avail base.
        unsafe {
            let used_event_ptr = ((self.avail as *mut u8).add(4) as *mut u16)
                .add(self.queue_size as usize);
            ptr::write_volatile(used_event_ptr, val);
        }
    }
}
