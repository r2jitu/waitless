// drivers/virtio_net.rs — VirtIO network device: TX/RX, feature negotiation, IRQ

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

use crate::{
    log, dsb_st,
    virtio_read32, virtio_write32, virtio_read8, virtio_write8,
    vz_init_delay,
};
#[cfg(target_arch = "aarch64")]
use kernel::aarch64::{exceptions, fdt};
use crate::pci::{PCI_DEVICES, read_config, find_device, enable_bus_mastering_inner};
use crate::virtio::{
    VPCI_DEVICES, Virtqueue,
    vpci_find, vpci_reset, vpci_set_status, vpci_get_status,
    vpci_read_features, vpci_write_features,
    vpci_select_queue, vpci_get_queue_size, vpci_get_queue_notify_off,
    vpci_queue_notify_addr, vpci_set_queue_addrs, vpci_enable_queue,
    vpci_read_dev_cfg8, vpci_read_isr,
    STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK, STATUS_FAILED,
    VIRTIO_NET_F_MAC, VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_STATUS,
    VIRTIO_RING_F_EVENT_IDX,
    VREG_DEVICE_FEATURES, VREG_GUEST_FEATURES, VREG_DEVICE_STATUS, VREG_ISR_STATUS,
    VREG_DEVICE_CONFIG,
    MMIO_BASE, MMIO_MAGIC_VALUE, MMIO_VERSION, MMIO_DEVICE_ID,
    MMIO_HOST_FEATURES, MMIO_DEVICE_FEATURES_SEL,
    MMIO_GUEST_FEATURES, MMIO_DRIVER_FEATURES_SEL, MMIO_GUEST_PAGE_SIZE,
    MMIO_STATUS, MMIO_DEVICE_CONFIG, MMIO_MAGIC,
    MMIO_INTERRUPT_STATUS, MMIO_INTERRUPT_ACK,
};
use kernel::mm::{kmalloc, virt_to_phys, phys_to_virt};

#[cfg(target_arch = "x86_64")]
use crate::x86_init;

// ============================================================================
// VirtIO-net constants and types
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
pub(crate) enum Transport {
    None,
    #[cfg(target_arch = "aarch64")]
    Mmio { base: u64, is_v2: bool },
    #[cfg(target_arch = "x86_64")]
    LegacyPci { base: u64, pci_idx: usize },
    ModernPci { vpci_idx: usize },
}

// ============================================================================
// VirtIO-net driver state
// ============================================================================

struct NetDevice {
    transport: Transport,
    rx_queue: Virtqueue,
    tx_queue: Virtqueue,
    mac: [u8; 6],
    rx_buffers: [*mut u8; RX_BUFFERS],
    tx_pool: [TxBuf; TX_POOL_SIZE],
    tx_pool_used: [bool; TX_POOL_SIZE],
    irq_idle_available: bool,
    guest_features: u32,
}

impl NetDevice {
    const ZEROED: Self = NetDevice {
        transport: Transport::None,
        rx_queue: Virtqueue::ZERO,
        tx_queue: Virtqueue::ZERO,
        mac: [0; 6],
        rx_buffers: [ptr::null_mut(); RX_BUFFERS],
        tx_pool: unsafe { core::mem::zeroed() },
        tx_pool_used: [false; TX_POOL_SIZE],
        irq_idle_available: false,
        guest_features: 0,
    };
}

static mut NET: NetDevice = NetDevice::ZEROED;

// ---- Modern PCI init (VZ.framework + QEMU modern) --------------------------

fn init_pci_modern() -> bool {
    let vpci_idx = match vpci_find(1) { // virtio device type 1 = net
        Some(i) => i,
        None => return false,
    };

    log(b"virtio_net: found modern virtio-pci net device\n");

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
        log(b"virtio_net: device rejected features\n");
        vpci_set_status(dev, STATUS_FAILED);
        return false;
    }

    // Init RX queue (0)
    vpci_select_queue(dev, 0);
    let rx_qsize = vpci_get_queue_size(dev);
    let rx_notify_off = vpci_get_queue_notify_off(dev);
    let rx_notify = vpci_queue_notify_addr(dev, rx_notify_off);

    let rx_addrs = unsafe {
        match NET.rx_queue.init_pci_modern(rx_qsize, rx_notify, 0) {
            Some(a) => a,
            None => {
                log(b"virtio_net: failed to init RX queue\n");
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
        match NET.tx_queue.init_pci_modern(tx_qsize, tx_notify, 1) {
            Some(a) => a,
            None => {
                log(b"virtio_net: failed to init TX queue\n");
                vpci_set_status(dev, STATUS_FAILED);
                return false;
            }
        }
    };
    vpci_set_queue_addrs(dev, tx_addrs.0, tx_addrs.1, tx_addrs.2);
    vpci_enable_queue(dev);

    // EVENT_IDX
    if (guest_features & VIRTIO_RING_F_EVENT_IDX) != 0 {
        unsafe { NET.rx_queue.event_idx = true; }
    }

    // Read MAC
    for i in 0..6u32 {
        unsafe { NET.mac[i as usize] = vpci_read_dev_cfg8(dev, i); }
    }

    // Allocate and populate RX buffers
    for i in 0..RX_BUFFERS {
        let alloc = kmalloc(BUFFER_SIZE as usize + 2);
        if alloc.is_null() {
            log(b"virtio_net: failed to allocate RX buffer\n");
            vpci_set_status(dev, STATUS_FAILED);
            return false;
        }
        // +2 byte shift for IPv4 alignment on ARM64
        let buf = unsafe { alloc.add(2) };
        unsafe {
            ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
            NET.rx_buffers[i] = buf;
            let buf_phys = virt_to_phys(buf);
            NET.rx_queue.add_buf(buf_phys, BUFFER_SIZE, 0, 1);
        }
    }

    // DRIVER_OK
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER |
                         STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    unsafe { NET.rx_queue.kick(); }
    vz_init_delay(); // VZ needs time after DRIVER_OK

    unsafe {
        NET.transport = Transport::ModernPci { vpci_idx };
        NET.guest_features = guest_features;
    }
    log(b"virtio_net: initialization complete (PCI modern)\n");
    true
}

// ---- MMIO init (aarch64 QEMU) ----------------------------------------------

#[cfg(target_arch = "aarch64")]
fn init_mmio() -> bool {
    let mut io_base: u64 = 0;

    unsafe {
        let fdt = fdt::info();

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

    log(b"virtio_net: virtio-mmio net device found\n");

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
                log(b"virtio_net: device rejected features\n");
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
        if !NET.rx_queue.init_legacy(io_base, 0, true, is_v2) {
            log(b"virtio_net: failed to init RX queue\n");
            return false;
        }
        if !NET.tx_queue.init_legacy(io_base, 1, true, is_v2) {
            log(b"virtio_net: failed to init TX queue\n");
            return false;
        }
    }

    // Read MAC from config space
    unsafe {
        let lo = virtio_read32(io_base + MMIO_DEVICE_CONFIG);
        let hi = virtio_read32(io_base + MMIO_DEVICE_CONFIG + 4);
        NET.mac[0] = (lo & 0xff) as u8;
        NET.mac[1] = ((lo >> 8) & 0xff) as u8;
        NET.mac[2] = ((lo >> 16) & 0xff) as u8;
        NET.mac[3] = ((lo >> 24) & 0xff) as u8;
        NET.mac[4] = (hi & 0xff) as u8;
        NET.mac[5] = ((hi >> 8) & 0xff) as u8;
    }

    // Allocate RX buffers
    for i in 0..RX_BUFFERS {
        let alloc = kmalloc(BUFFER_SIZE as usize + 2);
        if alloc.is_null() { return false; }
        let buf = unsafe { alloc.add(2) };
        unsafe {
            ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
            NET.rx_buffers[i] = buf;
            let buf_phys = virt_to_phys(buf);
            NET.rx_queue.add_buf(buf_phys, BUFFER_SIZE, 0, 1);
        }
    }

    unsafe { NET.rx_queue.kick(); }

    // DRIVER_OK
    let mut final_status = (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK) as u32;
    if is_v2 { final_status |= STATUS_FEATURES_OK as u32; }
    unsafe { virtio_write32(io_base + MMIO_STATUS, final_status); }

    unsafe {
        NET.transport = Transport::Mmio { base: io_base, is_v2 };
        NET.guest_features = guest_features;
    }
    log(b"virtio_net: initialization complete (MMIO)\n");
    true
}

// ---- Legacy PCI init (x86_64) -----------------------------------------------

#[cfg(target_arch = "x86_64")]
fn init_legacy_pci() -> bool {
    // Find legacy virtio-net (0x1AF4/0x1000) or modern (0x1AF4/0x1041)
    let pci_idx = find_device(0x1AF4, 0x1000)
        .or_else(|| find_device(0x1AF4, 0x1041));
    let pci_idx = match pci_idx {
        Some(i) => i,
        None => return false,
    };

    let dev = unsafe { &PCI_DEVICES[pci_idx] };
    log(b"virtio_net: found legacy PCI device\n");

    // Verify subsystem device ID = 1 (network)
    let subsys = read_config(dev.bus, dev.slot, dev.func, 0x2C);
    let subsys_device_id = ((subsys >> 16) & 0xFFFF) as u16;
    if subsys_device_id != 1 {
        log(b"virtio_net: not a network device\n");
        return false;
    }

    enable_bus_mastering_inner(dev.slot);

    // Get I/O base from BAR0
    let bar0 = dev.bar[0];
    if (bar0 & 0x01) == 0 {
        log(b"virtio_net: BAR0 is not I/O space\n");
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
            log(b"virtio_net: device did not accept features\n");
            virtio_write8(io_base + VREG_DEVICE_STATUS, STATUS_FAILED);
            return false;
        }
    }

    // Init RX and TX queues
    unsafe {
        if !NET.rx_queue.init_legacy(io_base, 0, false, false) {
            log(b"virtio_net: failed to init RX queue\n");
            return false;
        }
        if !NET.tx_queue.init_legacy(io_base, 1, false, false) {
            log(b"virtio_net: failed to init TX queue\n");
            return false;
        }
    }

    // Read MAC
    for i in 0..6u64 {
        unsafe { NET.mac[i as usize] = virtio_read8(io_base + VREG_DEVICE_CONFIG + i); }
    }

    // Allocate RX buffers (no +2 alignment shift on x86)
    for i in 0..RX_BUFFERS {
        let buf = kmalloc(BUFFER_SIZE as usize);
        if buf.is_null() { return false; }
        unsafe {
            ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
            NET.rx_buffers[i] = buf;
            let buf_phys = virt_to_phys(buf);
            NET.rx_queue.add_buf(buf_phys, BUFFER_SIZE, 0, 1);
        }
    }

    unsafe { NET.rx_queue.kick(); }

    // DRIVER_OK
    unsafe {
        virtio_write8(io_base + VREG_DEVICE_STATUS,
                      STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    }

    unsafe {
        NET.transport = Transport::LegacyPci { base: io_base, pci_idx };
        NET.guest_features = guest_features;
    }
    log(b"virtio_net: initialization complete (legacy PCI)\n");
    true
}

// ---- TX drain ---------------------------------------------------------------

fn tx_drain() {
    let pool_phys = unsafe { virt_to_phys(NET.tx_pool.as_ptr() as *const u8) };
    unsafe {
        while let Some((used_id, _used_len)) = NET.tx_queue.get_used() {
            let d = NET.tx_queue.desc(used_id);
            let slot = ((d.addr - pool_phys) / core::mem::size_of::<TxBuf>() as u64) as usize;
            if slot < TX_POOL_SIZE {
                NET.tx_pool_used[slot] = false;
            }
        }
    }
}

// ---- IRQ handler -----------------------------------------------------------

// x86_64: extern "C" fn() wrapper for the idt.cc trampoline
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn irq_handler_x86(_frame: *mut x86_init::idt::InterruptFrame) {
    irq_handler(0);
}

fn irq_handler(_irq: u32) {
    unsafe {
        // NAPI: disable notifications on entry
        NET.rx_queue.disable_interrupts();

        // Acknowledge device interrupt
        match NET.transport {
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
// Public API — VirtIO-net
// ============================================================================

pub fn init() -> bool {
    log(b"virtio_net: initializing...\n");

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

pub fn get_mac(mac_out: *mut u8) {
    unsafe {
        ptr::copy_nonoverlapping(NET.mac.as_ptr(), mac_out, 6);
    }
}

pub fn send(data: &[u8]) {
    if data.is_empty() { return; }
    unsafe {
        if let Transport::None = NET.transport { return; }
    }
    let len = data.len() as u32;
    let frame_len = if len > MAX_ETH_FRAME as u32 { MAX_ETH_FRAME as u32 } else { len };

    tx_drain();

    // Find a free pool slot; spin-drain if all busy
    let slot = loop {
        let mut found = None;
        for i in 0..TX_POOL_SIZE {
            if unsafe { !NET.tx_pool_used[i] } {
                found = Some(i);
                break;
            }
        }
        if let Some(s) = found { break s; }
        tx_drain();
        compiler_fence(Ordering::SeqCst);
    };

    unsafe {
        NET.tx_pool_used[slot] = true;
        let buf = &mut NET.tx_pool[slot];
        buf.hdr.flags = 0;
        buf.hdr.gso_type = 0;
        buf.hdr.hdr_len = 0;
        buf.hdr.gso_size = 0;
        buf.hdr.csum_start = 0;
        buf.hdr.csum_offset = 0;
        buf.hdr.num_buffers = 1;

        ptr::copy_nonoverlapping(data.as_ptr(), buf.data.as_mut_ptr(), frame_len as usize);

        let total_len = VIRTIO_NET_HDR_SIZE as u32 + frame_len;
        let buf_phys = virt_to_phys(buf as *const TxBuf as *const u8);
        let head = NET.tx_queue.add_buf(buf_phys, total_len, 1, 0);
        if head < 0 {
            NET.tx_pool_used[slot] = false;
            return;
        }

        NET.tx_queue.kick();
    }
}

pub fn poll(
    callback: fn(&[u8]),
) -> i32 {
    unsafe {
        if let Transport::None = NET.transport { return 0; }
    }

    tx_drain();

    let mut count: i32 = 0;
    unsafe {
        while let Some((used_id, used_len)) = NET.rx_queue.get_used() {
            let desc = NET.rx_queue.desc(used_id);
            let buf = phys_to_virt(desc.addr);

            if used_len > VIRTIO_NET_HDR_SIZE as u32 {
                let frame_len = (used_len - VIRTIO_NET_HDR_SIZE as u32) as usize;
                let frame_data = buf.add(VIRTIO_NET_HDR_SIZE);
                let slice = core::slice::from_raw_parts(frame_data, frame_len);
                callback(slice);
            }

            // Re-arm RX buffer
            let buf_phys = virt_to_phys(buf);
            NET.rx_queue.add_buf(buf_phys, BUFFER_SIZE, 0, 1);
            count += 1;
        }

        if count > 0 {
            NET.rx_queue.kick();
        }
    }

    count
}

pub fn enable_irq() {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            let fdt = fdt::info();

            match NET.transport {
                Transport::ModernPci { vpci_idx } if fdt.gic_dist_base != 0 => {
                    let slot = PCI_DEVICES[VPCI_DEVICES[vpci_idx].pci_idx].slot;
                    let intid = if (slot as usize) < 8 { fdt.pci_irqs[slot as usize] } else { 0 };
                    if intid != 0 {
                        NET.rx_queue.enable_interrupts();
                        exceptions::register_irq(intid, irq_handler);
                        NET.irq_idle_available = true;
                    }
                }
                Transport::Mmio { base, .. } if fdt.gic_dist_base != 0 => {
                    for i in 0..fdt.virtio_count as usize {
                        if fdt.virtio_bases[i] == base && fdt.virtio_irqs[i] != 0 {
                            NET.rx_queue.enable_interrupts();
                            exceptions::register_irq(fdt.virtio_irqs[i], irq_handler);
                            NET.irq_idle_available = true;
                            break;
                        }
                    }
                }
                _ => {}
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            if let Transport::LegacyPci { pci_idx, .. } = NET.transport {
                let dev = &PCI_DEVICES[pci_idx];
                let irq_reg = read_config(dev.bus, dev.slot, dev.func, 0x3C);
                let irq_line = (irq_reg & 0xFF) as u8;
                if irq_line < 16 {
                    NET.rx_queue.enable_interrupts();
                    x86_init::idt::register_handler(32 + irq_line, irq_handler_x86);
                    x86_init::idt::enable_irq(irq_line);
                    NET.irq_idle_available = true;
                }
            }
        }
    }
}

pub fn irq_idle_supported() -> bool {
    unsafe { NET.irq_idle_available }
}

pub fn arm_rx_interrupts() {
    unsafe { NET.rx_queue.enable_interrupts(); }
}

pub fn has_pending_rx() -> bool {
    unsafe { NET.rx_queue.has_used() }
}
