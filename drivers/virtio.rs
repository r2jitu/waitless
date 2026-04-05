// drivers/virtio.rs — VirtIO PCI transport (modern), legacy transport, and Virtqueue

use core::ptr;

use crate::{
    log, dsb_st, dsb_ld, dsb_sy,
    mmio_read32, mmio_write32, mmio_read16, mmio_write16, mmio_read8, mmio_write8,
    virtio_read32, virtio_write32, virtio_read16, virtio_write16, virtio_read8, virtio_write8,
    vz_config_delay, map_device_range,
};
use crate::pci::{
    PCI_DEVICES, pci_read_config, pci_write_config, pci_find_device,
    pci_enable_bus_mastering_inner, pci_read_bar64,
};
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

pub(crate) static mut VPCI_DEVICES: [VirtioPciDevice; VIRTIO_PCI_MAX_DEVICES] =
    [VirtioPciDevice::ZERO; VIRTIO_PCI_MAX_DEVICES];
pub(crate) static mut VPCI_DEVICE_COUNT: usize = 0;

/// Resolve a PCI BAR to a CPU virtual address. Maps above-4GB ranges on aarch64.
fn resolve_bar(pci_idx: usize, bar_idx: usize) -> u64 {
    let dev = unsafe { &PCI_DEVICES[pci_idx] };
    let addr = pci_read_bar64(dev, bar_idx);
    if addr == 0 { return 0; }

    #[cfg(target_arch = "aarch64")]
    if addr >= 0x1_0000_0000 {
        map_device_range(addr & !0x1F_FFFF, 2 << 20);
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
pub(crate) fn vpci_find(virtio_device_type: u16) -> Option<usize> {
    let target_id = 0x1040 + virtio_device_type;

    let pci_idx = pci_find_device(0x1AF4, target_id)?;

    unsafe {
        if VPCI_DEVICE_COUNT >= VIRTIO_PCI_MAX_DEVICES { return None; }
        let idx = VPCI_DEVICE_COUNT;
        let dev = &mut VPCI_DEVICES[idx];
        *dev = VirtioPciDevice::ZERO;
        dev.pci_idx = pci_idx;

        pci_enable_bus_mastering_inner(PCI_DEVICES[pci_idx].slot);

        if !vpci_parse_caps(dev) { return None; }

        VPCI_DEVICE_COUNT += 1;
        Some(idx)
    }
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
pub(crate) const VIRTIO_RING_F_EVENT_IDX: u32 = 1 << 29;

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
    pub fn get_used(&mut self) -> Option<(u16, u32)> {
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

    pub fn has_used(&self) -> bool {
        let used_idx = unsafe { ptr::read_volatile(&(*self.used).idx) };
        self.last_used_idx != used_idx
    }

    pub fn enable_interrupts(&mut self) {
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

    pub fn disable_interrupts(&mut self) {
        unsafe { ptr::write_volatile(&mut (*self.avail).flags, VIRTQ_AVAIL_F_NO_INTERRUPT); }
    }

    /// Get descriptor at index (for reading buffer addresses)
    pub fn desc(&self, idx: u16) -> &VirtqDesc {
        unsafe { &*self.descs.add(idx as usize) }
    }
}
