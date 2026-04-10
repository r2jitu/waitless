// drivers/virtio.rs — VirtIO PCI transport (modern), legacy transport, and Virtqueue

use core::ptr;

use crate::{
    log, dsb_st, dsb_ld, dsb_sy,
    mmio_read32, mmio_write32, mmio_read16, mmio_write16, mmio_read8, mmio_write8,
    virtio_read32, virtio_write32, virtio_read16, virtio_write16, virtio_read8, virtio_write8,
    vz_config_delay,
};
use crate::pci::{
    pci_device, read_config, write_config, find_device,
    enable_bus_mastering_inner, read_bar64,
};
#[cfg(target_arch = "aarch64")]
use crate::map_device_range;
use kernel::mm::{alloc_frame, phys_to_virt};

// ============================================================================
// VirtIO PCI transport (modern, VirtIO 1.0+)
// ============================================================================

// PCI capability IDs
const PCI_CAP_ID_VNDR: u8 = 0x09;
pub(crate) const PCI_CAP_ID_MSIX: u8 = 0x11;

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
pub(crate) const CC_CONFIG_MSIX_VECTOR: u64 = 0x10;
const CC_DEVICE_STATUS: u64 = 0x14;
const CC_QUEUE_SELECT: u64 = 0x16;
const CC_QUEUE_SIZE: u64 = 0x18;
pub(crate) const CC_QUEUE_MSIX_VECTOR: u64 = 0x1a;
const CC_QUEUE_ENABLE: u64 = 0x1c;
const CC_QUEUE_NOTIFY_OFF: u64 = 0x1e;
const CC_QUEUE_DESC_LO: u64 = 0x20;
const CC_QUEUE_DESC_HI: u64 = 0x24;
const CC_QUEUE_DRIVER_LO: u64 = 0x28;
const CC_QUEUE_DRIVER_HI: u64 = 0x2c;
const CC_QUEUE_DEVICE_LO: u64 = 0x30;
const CC_QUEUE_DEVICE_HI: u64 = 0x34;

pub(crate) const VIRTIO_PCI_MAX_DEVICES: usize = 8;

#[derive(Clone, Copy)]
pub(crate) struct VirtioPciDevice {
    pub pci_idx: usize,         // index into PCI_DEVICES
    pub common_cfg: u64,        // MMIO address of common_cfg
    pub notify_base: u64,       // MMIO address of notify cap
    pub device_cfg: u64,        // MMIO address of device-specific cfg
    pub isr_cfg: u64,           // MMIO address of ISR cap
    pub notify_off_multiplier: u32,
    #[cfg(target_arch = "aarch64")]
    pub msix_cap_off: u8,
    #[cfg(target_arch = "aarch64")]
    pub msix_table: u64,
    #[cfg(target_arch = "aarch64")]
    pub msix_table_size: u16,
}

impl VirtioPciDevice {
    pub(crate) const ZERO: Self = VirtioPciDevice {
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

/// VirtIO-PCI device table. Filled during init by `vpci_find`; read
/// thereafter as snapshots via `vpci_device(idx)`. Same shape as
/// `pci::PCI_DEVICES`.
pub(crate) struct VpciTable {
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

pub(crate) static VPCI_DEVICES: kernel::sync::Spinlock<VpciTable> =
    kernel::sync::Spinlock::new(VpciTable::new());

/// Snapshot of `VPCI_DEVICES[idx]` returned by value.
pub(crate) fn vpci_device(idx: usize) -> VirtioPciDevice {
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

        #[cfg(target_arch = "aarch64")]
        if cap_vndr == PCI_CAP_ID_MSIX && dev.msix_cap_off == 0 {
            dev.msix_cap_off = cap_ptr;
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
pub(crate) fn vpci_find(virtio_device_type: u16) -> Option<usize> {
    let modern_id = 0x1040 + virtio_device_type;
    // Transitional IDs: net=0x1000, block=0x1001, console=0x1003
    let transitional_id = 0x1000 + virtio_device_type - 1;

    let pci_idx = find_device(0x1AF4, modern_id)
        .or_else(|| find_device(0x1AF4, transitional_id))?;

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

pub(crate) fn vpci_reset(dev: &VirtioPciDevice) {
    unsafe {
        mmio_write8(dev.common_cfg + CC_DEVICE_STATUS, 0);
        while mmio_read8(dev.common_cfg + CC_DEVICE_STATUS) != 0 {
            core::arch::asm!("", options(nostack, preserves_flags));
        }
    }
}

pub(crate) fn vpci_set_status(dev: &VirtioPciDevice, status: u8) {
    unsafe { mmio_write8(dev.common_cfg + CC_DEVICE_STATUS, status); }
    vz_config_delay();
}

pub(crate) fn vpci_get_status(dev: &VirtioPciDevice) -> u8 {
    unsafe { mmio_read8(dev.common_cfg + CC_DEVICE_STATUS) }
}

pub(crate) fn vpci_read_features(dev: &VirtioPciDevice, word: u32) -> u32 {
    unsafe {
        mmio_write32(dev.common_cfg + CC_DEVICE_FEATURE_SELECT, word);
        mmio_read32(dev.common_cfg + CC_DEVICE_FEATURE)
    }
}

pub(crate) fn vpci_write_features(dev: &VirtioPciDevice, word: u32, features: u32) {
    unsafe {
        mmio_write32(dev.common_cfg + CC_DRIVER_FEATURE_SELECT, word);
        mmio_write32(dev.common_cfg + CC_DRIVER_FEATURE, features);
    }
    vz_config_delay();
}

pub(crate) fn vpci_select_queue(dev: &VirtioPciDevice, idx: u16) {
    unsafe { mmio_write16(dev.common_cfg + CC_QUEUE_SELECT, idx); }
}

pub(crate) fn vpci_get_queue_size(dev: &VirtioPciDevice) -> u16 {
    unsafe { mmio_read16(dev.common_cfg + CC_QUEUE_SIZE) }
}

pub(crate) fn vpci_set_queue_addrs(dev: &VirtioPciDevice, desc: u64, avail: u64, used: u64) {
    unsafe {
        mmio_write32(dev.common_cfg + CC_QUEUE_DESC_LO, desc as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DESC_HI, (desc >> 32) as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DRIVER_LO, avail as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DRIVER_HI, (avail >> 32) as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DEVICE_LO, used as u32);
        mmio_write32(dev.common_cfg + CC_QUEUE_DEVICE_HI, (used >> 32) as u32);
    }
}

pub(crate) fn vpci_enable_queue(dev: &VirtioPciDevice) {
    unsafe { mmio_write16(dev.common_cfg + CC_QUEUE_ENABLE, 1); }
}

pub(crate) fn vpci_get_queue_notify_off(dev: &VirtioPciDevice) -> u16 {
    unsafe { mmio_read16(dev.common_cfg + CC_QUEUE_NOTIFY_OFF) }
}

pub(crate) fn vpci_queue_notify_addr(dev: &VirtioPciDevice, notify_off: u16) -> u64 {
    dev.notify_base + (notify_off as u64) * (dev.notify_off_multiplier as u64)
}

pub(crate) fn vpci_read_dev_cfg8(dev: &VirtioPciDevice, offset: u32) -> u8 {
    if dev.device_cfg == 0 { return 0; }
    unsafe { mmio_read8(dev.device_cfg + offset as u64) }
}

pub(crate) fn vpci_read_dev_cfg16(dev: &VirtioPciDevice, offset: u32) -> u16 {
    if dev.device_cfg == 0 { return 0; }
    unsafe { mmio_read16(dev.device_cfg + offset as u64) }
}

pub(crate) fn vpci_read_isr(dev: &VirtioPciDevice) -> u8 {
    if dev.isr_cfg == 0 { return 0; }
    unsafe { mmio_read8(dev.isr_cfg) }
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn vpci_set_queue_msix_vector(dev: &VirtioPciDevice, vector: u16) {
    unsafe { mmio_write16(dev.common_cfg + CC_QUEUE_MSIX_VECTOR, vector); }
}

// ============================================================================
// Virtio legacy transport (x86_64 PCI I/O ports, aarch64 MMIO)
// ============================================================================

// Legacy PCI I/O register offsets
pub(crate) const VREG_DEVICE_FEATURES: u64 = 0x00;
pub(crate) const VREG_GUEST_FEATURES: u64 = 0x04;
pub(crate) const VREG_QUEUE_ADDRESS: u64 = 0x08;
pub(crate) const VREG_QUEUE_SIZE: u64 = 0x0C;
pub(crate) const VREG_QUEUE_SELECT: u64 = 0x0E;
pub(crate) const VREG_QUEUE_NOTIFY: u64 = 0x10;
pub(crate) const VREG_DEVICE_STATUS: u64 = 0x12;
pub(crate) const VREG_ISR_STATUS: u64 = 0x13;
pub(crate) const VREG_DEVICE_CONFIG: u64 = 0x14;

// Virtio-MMIO register offsets (aarch64 QEMU)
pub(crate) const MMIO_BASE: u64 = 0x0a00_0000;
pub(crate) const MMIO_MAGIC_VALUE: u64 = 0x000;
pub(crate) const MMIO_VERSION: u64 = 0x004;
pub(crate) const MMIO_DEVICE_ID: u64 = 0x008;
pub(crate) const MMIO_HOST_FEATURES: u64 = 0x010;
pub(crate) const MMIO_DEVICE_FEATURES_SEL: u64 = 0x014;
pub(crate) const MMIO_GUEST_FEATURES: u64 = 0x020;
pub(crate) const MMIO_DRIVER_FEATURES_SEL: u64 = 0x024;
pub(crate) const MMIO_GUEST_PAGE_SIZE: u64 = 0x028;
pub(crate) const MMIO_QUEUE_SEL: u64 = 0x030;
pub(crate) const MMIO_QUEUE_NUM_MAX: u64 = 0x034;
pub(crate) const MMIO_QUEUE_NUM: u64 = 0x038;
pub(crate) const MMIO_QUEUE_ALIGN: u64 = 0x03c;
pub(crate) const MMIO_QUEUE_PFN: u64 = 0x040;
pub(crate) const MMIO_QUEUE_READY: u64 = 0x044;
pub(crate) const MMIO_QUEUE_NOTIFY: u64 = 0x050;
pub(crate) const MMIO_INTERRUPT_STATUS: u64 = 0x060;
pub(crate) const MMIO_INTERRUPT_ACK: u64 = 0x064;
pub(crate) const MMIO_STATUS: u64 = 0x070;
pub(crate) const MMIO_DEVICE_CONFIG: u64 = 0x100;
pub(crate) const MMIO_MAGIC: u32 = 0x74726976;
// MMIO v2 separate ring address registers
pub(crate) const MMIO_QUEUE_DESC_LOW: u64 = 0x080;
pub(crate) const MMIO_QUEUE_DESC_HIGH: u64 = 0x084;
pub(crate) const MMIO_QUEUE_DRIVER_LOW: u64 = 0x090;
pub(crate) const MMIO_QUEUE_DRIVER_HIGH: u64 = 0x094;
pub(crate) const MMIO_QUEUE_DEVICE_LOW: u64 = 0x0a0;
pub(crate) const MMIO_QUEUE_DEVICE_HIGH: u64 = 0x0a4;

// Device status bits
pub(crate) const STATUS_ACKNOWLEDGE: u8 = 1;
pub(crate) const STATUS_DRIVER: u8 = 2;
pub(crate) const STATUS_DRIVER_OK: u8 = 4;
pub(crate) const STATUS_FEATURES_OK: u8 = 8;
pub(crate) const STATUS_FAILED: u8 = 128;

// Virtqueue descriptor flags
pub(crate) const VIRTQ_DESC_F_NEXT: u16 = 1;
pub(crate) const VIRTQ_DESC_F_WRITE: u16 = 2;
pub(crate) const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;

// Feature bits
pub(crate) const VIRTIO_NET_F_MAC: u32 = 1 << 5;
pub(crate) const VIRTIO_NET_F_MRG_RXBUF: u32 = 1 << 15;
pub(crate) const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
pub(crate) const VIRTIO_NET_F_MQ: u32 = 1 << 22;
pub(crate) const VIRTIO_NET_F_CTRL_VQ: u32 = 1 << 17;
pub(crate) const VIRTIO_RING_F_EVENT_IDX: u32 = 1 << 29;
/// Vendor extension: device exposes per-queue used_idx at config offset 0x110.
/// When set, get_used() reads used_idx via MMIO trap instead of from shared
/// RAM, working around dcache coherency issues on Apple HVF.
pub(crate) const VIRTIO_F_USED_IDX_MMIO: u32 = 1 << 24;

// ============================================================================
// Split Virtqueue
// ============================================================================

// Virtqueue descriptor (must match hardware layout: 16 bytes packed)
#[repr(C, packed)]
pub(crate) struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

// Available ring header (naturally aligned, no padding)
#[repr(C)]
pub(crate) struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    // ring[queue_size] follows, then used_event (u16)
}

// Used ring element (naturally aligned)
#[repr(C)]
pub(crate) struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

// Used ring header (naturally aligned)
#[repr(C)]
pub(crate) struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    // ring[queue_size] of VirtqUsedElem follows
}

pub(crate) struct Virtqueue {
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
}

impl Virtqueue {
    pub(crate) const ZERO: Self = Virtqueue {
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

        let phys_base = alloc_frame();
        if phys_base == 0 { return None; }
        for _ in 1..num_frames {
            alloc_frame();
        }

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
    pub fn kick(&self) {
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
    /// Read INTERRUPT_STATUS and extract the device-side used_idx
    /// packed in the upper 16 bits (VIRTIO_F_USED_IDX_MMIO extension).
    /// Call once per poll cycle; get_used() then uses the cached value.
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

    pub fn get_used(&mut self) -> Option<(u16, u32)> {
        let cur_used_idx = if self.used_idx_mmio {
            self.mmio_cached_used_idx
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
            // On HVF, rely on the IRQ handler's cached used_idx.
            // Don't do an MMIO read here — it causes a vCPU exit.
            // The SPI will wake us from WFI when frames are available.
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
            dsb_st();
        }
    }

    pub fn disable_interrupts(&mut self) {
        self.set_avail_flags(VIRTQ_AVAIL_F_NO_INTERRUPT);
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
    fn used_idx(&self) -> u16 {
        // SAFETY: used points to a valid VirtqUsed header.
        unsafe { ptr::read_volatile(&(*self.used).idx) }
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
