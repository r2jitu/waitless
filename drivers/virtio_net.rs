// drivers/virtio_net.rs — VirtIO network device: TX/RX, feature negotiation, IRQ

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

use crate::{
    log, dsb_st,
    virtio_read32, virtio_write32, virtio_read16, virtio_read8, virtio_write8,
};
#[cfg(target_arch = "aarch64")]
use kernel::aarch64::{exceptions, fdt};
use crate::pci::{pci_device, read_config, find_device, enable_bus_mastering_inner};
use crate::virtio::{
    vpci_device, Virtqueue, VirtioPciDevice,
    vpci_find, vpci_reset, vpci_set_status, vpci_get_status,
    vpci_read_features, vpci_write_features,
    vpci_select_queue, vpci_get_queue_size, vpci_get_queue_notify_off,
    vpci_queue_notify_addr, vpci_set_queue_addrs, vpci_enable_queue,
    vpci_read_dev_cfg8, vpci_read_dev_cfg16, vpci_read_isr,
    vpci_set_queue_msix_vector, vpci_set_config_msix_vector,
    vpci_msix_enable, vpci_msix_write_entry,
    STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK, STATUS_FAILED,
    VIRTIO_NET_F_MAC, VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_STATUS,
    VIRTIO_NET_F_MQ, VIRTIO_NET_F_CTRL_VQ,
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_F_USED_IDX_MMIO,
    VREG_DEVICE_FEATURES, VREG_GUEST_FEATURES, VREG_DEVICE_STATUS, VREG_ISR_STATUS,
    VREG_DEVICE_CONFIG,
    MMIO_BASE, MMIO_MAGIC_VALUE, MMIO_VERSION, MMIO_DEVICE_ID,
    MMIO_HOST_FEATURES, MMIO_DEVICE_FEATURES_SEL,
    MMIO_GUEST_FEATURES, MMIO_DRIVER_FEATURES_SEL, MMIO_GUEST_PAGE_SIZE,
    MMIO_STATUS, MMIO_DEVICE_CONFIG, MMIO_MAGIC,
    MMIO_INTERRUPT_STATUS, MMIO_INTERRUPT_ACK,
};
use kernel::mm::{kmalloc, virt_to_phys, phys_to_virt};

// ============================================================================
// VirtIO-net constants and types
// ============================================================================

/// Set by the IRQ handler when SPI 35 fires with new RX frames.
/// The poll path checks this instead of doing an MMIO read every iteration.
static IRQ_PENDING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

const RX_BUFFERS: usize = 256;
const BUFFER_SIZE: u32 = 2048;
const TX_POOL_SIZE: usize = 64;
const VIRTIO_NET_HDR_SIZE: usize = 12; // VirtioNetHeader (with num_buffers)
const MAX_ETH_FRAME: usize = 1514;
const MAX_QUEUE_PAIRS: usize = 8;

/// NAPI-style IP-header alignment shift. Layout of each RX buffer:
///
///   [virtio_net_hdr (12)][eth hdr (14)][IP hdr ...]
///
/// kmalloc returns 4-byte-aligned pointers, so the IP header lands at
/// `buf + 26` — not 4-aligned, which on aarch64 makes the network
/// stack's u32 reads (src/dst IP, checksum) fall back to the slow
/// misaligned path. Shifting the DMA target by 2 moves the IP header
/// to `buf + 28`, back on a 4-byte boundary. The x86 legacy-mmio
/// init path (`init_legacy_mmio`) intentionally skips this shift —
/// x86 handles misaligned loads at full speed.
const RX_IP_ALIGN: usize = 2;

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

impl TxBuf {
    const ZERO: Self = TxBuf {
        hdr: VirtioNetHeader {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        },
        data: [0; MAX_ETH_FRAME],
    };
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
// Per-queue-pair state (one per core in Tier 1)
// ============================================================================

struct QueuePairState {
    tx_pool: [TxBuf; TX_POOL_SIZE],
    tx_pool_used: [bool; TX_POOL_SIZE],
    rx_buffers: [*mut u8; RX_BUFFERS],
}

impl QueuePairState {
    const ZEROED: Self = QueuePairState {
        tx_pool: [const { TxBuf::ZERO }; TX_POOL_SIZE],
        tx_pool_used: [false; TX_POOL_SIZE],
        rx_buffers: [ptr::null_mut(); RX_BUFFERS],
    };
}

// ============================================================================
// VirtIO-net driver state
// ============================================================================

struct NetDevice {
    transport: Transport,
    // Queue pair 0 is always initialized (single-queue or first of multi-queue).
    // Additional pairs [1..num_queue_pairs) are for Tier 1 multi-queue.
    rx_queues: [Virtqueue; MAX_QUEUE_PAIRS],
    tx_queues: [Virtqueue; MAX_QUEUE_PAIRS],
    ctrl_queue: Virtqueue,              // Control VQ for multi-queue commands
    qp_state: [QueuePairState; MAX_QUEUE_PAIRS],
    mac: [u8; 6],
    num_queue_pairs: u16,               // 1 = single-queue, >1 = multi-queue
    /// Number of queue pairs the device has been initialized for. Stays
    /// fixed after init; used by `activate_multi_queue()` to know how
    /// many pairs to activate via VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET.
    negotiated_queue_pairs: u16,
    irq_idle_available: bool,
    guest_features: u32,
    has_mq: bool,                       // VIRTIO_NET_F_MQ negotiated
    irq_edge: bool,                     // SPI is edge-triggered (from FDT)
}

impl NetDevice {
    const ZEROED: Self = NetDevice {
        transport: Transport::None,
        rx_queues: [const { Virtqueue::ZERO }; MAX_QUEUE_PAIRS],
        tx_queues: [const { Virtqueue::ZERO }; MAX_QUEUE_PAIRS],
        ctrl_queue: Virtqueue::ZERO,
        qp_state: [const { QueuePairState::ZEROED }; MAX_QUEUE_PAIRS],
        mac: [0; 6],
        num_queue_pairs: 1,
        negotiated_queue_pairs: 1,
        irq_idle_available: false,
        guest_features: 0,
        has_mq: false,
        irq_edge: false,
    };
}

/// Driver state singleton.
///
/// Wrapped in `UnsafeCell` so cross-core access is via raw-pointer place
/// expressions (`(*ndev()).foo`) rather than via `&mut NetDevice`. Forming
/// `&mut NetDevice` from multiple cores would alias even when the
/// underlying memory accesses target disjoint per-qp slots — undefined
/// behaviour by the Rust aliasing model regardless of whether they
/// actually overlap.
///
/// Per-field SPSC/ownership rules (e.g. "rx_queues[qp] is owned by the
/// core whose id == qp under Tier 1 multi-queue") are documented at the
/// access sites; the wrapper just makes "no &mut NetDevice" enforceable
/// at the syntactic level.
struct NetCell(core::cell::UnsafeCell<NetDevice>);
unsafe impl Sync for NetCell {}

static NET: NetCell = NetCell(core::cell::UnsafeCell::new(NetDevice::ZEROED));

/// Raw pointer to the driver state. Use as `(*ndev()).field` so the
/// place expression yields a `&mut Field` directly without going via
/// `&mut NetDevice`.
#[inline(always)]
fn ndev() -> *mut NetDevice {
    NET.0.get()
}

/// Get the number of active queue pairs.
pub fn num_queue_pairs() -> u16 {
    unsafe { (*ndev()).num_queue_pairs }
}

// ---- Modern PCI init (VirtIO 1.0+) -----------------------------------------

fn init_pci_modern() -> bool {
    let vpci_idx = match vpci_find(1) { // virtio device type 1 = net
        Some(i) => i,
        None => return false,
    };

    log(b"virtio_net: found modern virtio-pci net device\n");

    let dev_snap = vpci_device(vpci_idx);
    let dev = &dev_snap;

    vpci_reset(dev);
    vpci_set_status(dev, STATUS_ACKNOWLEDGE);
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let dev_features = vpci_read_features(dev, 0);
    // Accept every offered word-0 feature. Some hypervisors (notably Apple
    // Virtualization.framework) require CSUM/INDIRECT_DESC and reject us if
    // we don't ack them, and there's nothing in word-0 we'd want to refuse.
    let guest_features = dev_features;

    // Check for multi-queue support
    let has_mq = (dev_features & VIRTIO_NET_F_MQ) != 0
              && (dev_features & VIRTIO_NET_F_CTRL_VQ) != 0;

    vpci_write_features(dev, 0, guest_features);
    vpci_write_features(dev, 1, 1); // VIRTIO_F_VERSION_1

    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    if (vpci_get_status(dev) & STATUS_FEATURES_OK) == 0 {
        log(b"virtio_net: device rejected features\n");
        vpci_set_status(dev, STATUS_FAILED);
        return false;
    }

    // Read max queue pairs from device config (offset 8, u16)
    // Use UNIKERNEL_CPUS env var (set in QEMU args) since percpu::init()
    // hasn't run yet. Fall back to 1 if not available.
    #[cfg(target_arch = "x86_64")]
    let desired_pairs = unsafe { kernel::x86_64::acpi::detect_cpus() as u16 };
    #[cfg(target_arch = "aarch64")]
    let desired_pairs = kernel::aarch64::fdt::info().cpu_count as u16;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let desired_pairs = 1u16;
    let max_pairs = if has_mq {
        vpci_read_dev_cfg16(dev, 8).max(1)
    } else {
        1
    };
    let num_pairs = desired_pairs.min(max_pairs).min(MAX_QUEUE_PAIRS as u16);

    // Init queue pairs (RX=2i, TX=2i+1)
    for pair in 0..num_pairs as usize {
        let rx_qi = (pair * 2) as u16;
        let tx_qi = (pair * 2 + 1) as u16;

        // RX queue
        vpci_select_queue(dev, rx_qi);
        let rx_qsize = vpci_get_queue_size(dev);
        let rx_notify_off = vpci_get_queue_notify_off(dev);
        let rx_notify = vpci_queue_notify_addr(dev, rx_notify_off);
        // SAFETY: ndev() returns the singleton; per-qp init runs once during boot
        // before any other core touches rx_queues[pair].
        let rx_init = unsafe { (*ndev()).rx_queues[pair].init_pci_modern(rx_qsize, rx_notify, rx_qi) };
        let rx_addrs = match rx_init {
            Some(a) => a,
            None => {
                log(b"virtio_net: failed to init RX queue\n");
                vpci_set_status(dev, STATUS_FAILED);
                return false;
            }
        };
        vpci_set_queue_addrs(dev, rx_addrs.0, rx_addrs.1, rx_addrs.2);
        vpci_enable_queue(dev);

        // TX queue
        vpci_select_queue(dev, tx_qi);
        let tx_qsize = vpci_get_queue_size(dev);
        let tx_notify_off = vpci_get_queue_notify_off(dev);
        let tx_notify = vpci_queue_notify_addr(dev, tx_notify_off);
        // SAFETY: see RX comment above.
        let tx_init = unsafe { (*ndev()).tx_queues[pair].init_pci_modern(tx_qsize, tx_notify, tx_qi) };
        let tx_addrs = match tx_init {
            Some(a) => a,
            None => {
                log(b"virtio_net: failed to init TX queue\n");
                vpci_set_status(dev, STATUS_FAILED);
                return false;
            }
        };
        vpci_set_queue_addrs(dev, tx_addrs.0, tx_addrs.1, tx_addrs.2);
        vpci_enable_queue(dev);
    }

    // Init control VQ only when we'll actually use it (multi-queue
    // activation via MQ_VQ_PAIRS_SET). Initialising ctrl for single
    // queue and then leaving it untouched appears to wedge the RX
    // path on QEMU 10 vhost-net — the device happily delivers the
    // first few packets (DHCP) but subsequent traffic is silently
    // dropped. Leaving ctrl uninitialised in the single-queue case
    // avoids the wedge.
    if has_mq && num_pairs > 1 {
        let ctrl_qi = (2 * max_pairs) as u16;
        vpci_select_queue(dev, ctrl_qi);
        let ctrl_qsize = vpci_get_queue_size(dev);
        if ctrl_qsize > 0 {
            let ctrl_notify_off = vpci_get_queue_notify_off(dev);
            let ctrl_notify = vpci_queue_notify_addr(dev, ctrl_notify_off);
            // SAFETY: single-threaded boot init.
            let ctrl_init = unsafe {
                (*ndev()).ctrl_queue.init_pci_modern(ctrl_qsize, ctrl_notify, ctrl_qi)
            };
            let ctrl_addrs = match ctrl_init {
                Some(a) => a,
                None => {
                    log(b"virtio_net: failed to init CTRL queue\n");
                    unsafe {
                        (*ndev()).num_queue_pairs = 1;
                        (*ndev()).has_mq = false;
                    }
                    (0, 0, 0)
                }
            };
            if ctrl_addrs.0 != 0 {
                vpci_set_queue_addrs(dev, ctrl_addrs.0, ctrl_addrs.1, ctrl_addrs.2);
                vpci_enable_queue(dev);
            }
        }
    }

    // EVENT_IDX
    if (guest_features & VIRTIO_RING_F_EVENT_IDX) != 0 {
        for pair in 0..num_pairs as usize {
            unsafe { (*ndev()).rx_queues[pair].event_idx = true; }
        }
    }

    // Read MAC
    for i in 0..6u32 {
        unsafe { (*ndev()).mac[i as usize] = vpci_read_dev_cfg8(dev, i); }
    }

    // Allocate and populate RX buffers for all queue pairs.
    // See RX_IP_ALIGN for why the DMA target is shifted by 2 bytes.
    for pair in 0..num_pairs as usize {
        for i in 0..RX_BUFFERS {
            let alloc = kmalloc(BUFFER_SIZE as usize + RX_IP_ALIGN);
            if alloc.is_null() {
                log(b"virtio_net: failed to allocate RX buffer\n");
                vpci_set_status(dev, STATUS_FAILED);
                return false;
            }
            let buf = unsafe { alloc.add(RX_IP_ALIGN) };
            unsafe {
                ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
                (*ndev()).qp_state[pair].rx_buffers[i] = buf;
                let buf_phys = virt_to_phys(buf);
                (*ndev()).rx_queues[pair].add_buf(buf_phys, BUFFER_SIZE, 0, 1);
            }
        }
    }

    // DRIVER_OK
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER |
                         STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    for pair in 0..num_pairs as usize {
        unsafe { (*ndev()).rx_queues[pair].kick(); }
    }

    unsafe {
        (*ndev()).transport = Transport::ModernPci { vpci_idx };
        (*ndev()).guest_features = guest_features;
        // Multi-queue is NOT activated yet — defer until after DHCP.
        // DHCP only polls queue 0, so we want the device to keep its
        // default single-pair behaviour until DHCP completes. Once it
        // does, boot/entry.rs calls activate_multi_queue() to promote
        // to N pairs and engage Tier 1 RX polling.
        (*ndev()).num_queue_pairs = 1;
        (*ndev()).negotiated_queue_pairs = num_pairs;
        (*ndev()).has_mq = has_mq && num_pairs > 1;
    }

    if num_pairs > 1 {
        log(b"virtio_net: multi-queue available: ");
        log(&[b'0' + (num_pairs as u8 % 10)]);
        log(b" pairs (deferred until after DHCP)\n");
    }
    log(b"virtio_net: initialization complete (PCI modern)\n");
    true
}

/// Promote the device from single-queue to multi-queue after DHCP.
/// No-op for single-queue (count=1) because telling vhost-net to
/// "use 1 pair" via MQ_VQ_PAIRS_SET(1) appears to wedge the RX path
/// on QEMU 10 — packets stop arriving in the guest even though the
/// send-side still looks healthy. Leaving the count unset means
/// vhost-net falls back to its default single-pair behaviour, which
/// empirically works fine for 1-vCPU guests.
pub fn activate_multi_queue() {
    unsafe {
        let dev = &mut *ndev();
        if !dev.has_mq || dev.negotiated_queue_pairs <= 1 {
            return;
        }
        if dev.num_queue_pairs == dev.negotiated_queue_pairs {
            return; // already active
        }
        let target = dev.negotiated_queue_pairs;
        ctrl_mq_set_pairs(target);
        if (*ndev()).has_mq {
            (*ndev()).num_queue_pairs = target;
            log(b"virtio_net: multi-queue: ");
            log(&[b'0' + (target as u8 % 10)]);
            log(b" queue pairs\n");
        }
    }
}

/// Backing memory for ctrl-vq commands. Placed in kernel BSS (.bss)
/// so its physical address lives with the kernel image — Limine
/// loads us below 4 GiB on every machine we've seen. GCE's legacy
/// virtio backend silently halts RX on all queues if the MQ ctrl
/// command's buffers live above 4 GiB or aren't contiguous, so we
/// park everything in one static 16-byte chunk and chain into it.
///
/// Layout, single contiguous buffer:
///   [0..2]   class, cmd  (readable by device)
///   [2..4]   u16 num_pairs (LE, readable)
///   [4..8]   padding for alignment
///   [8..9]   ack byte (writable by device)
#[repr(C, align(16))]
struct CtrlMqBuf {
    hdr_class: u8,
    hdr_cmd: u8,
    data: [u8; 2],
    _pad: [u8; 4],
    ack: u8,
    _tail: [u8; 7],
}
static mut CTRL_MQ_BUF: CtrlMqBuf = CtrlMqBuf {
    hdr_class: 0, hdr_cmd: 0, data: [0; 2], _pad: [0; 4], ack: 0, _tail: [0; 7],
};

/// Send VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET to activate N queue pairs.
fn ctrl_mq_set_pairs(num_pairs: u16) {
    // Control VQ command format (spec 1.2 §5.1.6.5):
    //   struct virtio_net_ctrl_hdr { u8 class; u8 cmd; }   (device-readable)
    //   command-specific data...                            (device-readable)
    //   u8 ack                                              (device-writable)
    //
    // QEMU's virtio-net requires the header and data to live in distinct
    // descriptors; packing { class, cmd, data } into a single 4-byte
    // buffer triggers "virtio-net ctrl missing headers" and the command
    // is silently rejected.
    unsafe {
        // Write into the static buffer (guaranteed low-memory / contiguous).
        let buf_ptr = &raw mut CTRL_MQ_BUF;
        (*buf_ptr).hdr_class = 4; // VIRTIO_NET_CTRL_MQ
        (*buf_ptr).hdr_cmd = 0;   // VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET
        (*buf_ptr).data = num_pairs.to_le_bytes();
        (*buf_ptr).ack = 0xFF;

        // Descriptor layout: two descriptors. One readable segment
        // covers class+cmd+data packed contiguously (4 bytes); one
        // writable segment is the ack byte. GCE's vhost requires the
        // header-plus-data portion to live in a single contiguous
        // buffer in low memory — the older "3 separate descriptors"
        // variant works on QEMU but makes GCE silently halt RX
        // delivery on all queues. Keeping hdr+data together, ack
        // separate, matches what legacy Linux virtio-net actually
        // sends for `virtio_net_ctrl_simple_hdr`.
        let hdrdata_phys = virt_to_phys(&(*buf_ptr).hdr_class as *const u8);
        let ack_phys     = virt_to_phys(&(*buf_ptr).ack as *const u8);

        (*ndev()).ctrl_queue.add_chain(&[
            (hdrdata_phys, 4, false), // readable: class + cmd + num_pairs
            (ack_phys,     1, true),  // writable: ack byte
        ]);
        (*ndev()).ctrl_queue.kick();

        // Wait for completion.
        for _ in 0..1_000_000u32 {
            if (*ndev()).ctrl_queue.get_used().is_some() { break; }
        }
        let _ = (*ndev()).ctrl_queue.get_used();

        let ack = core::ptr::read_volatile(&(*buf_ptr).ack as *const u8);
        if ack == 0 {
            log(b"virtio_net: MQ activated\n");
        } else {
            log(b"virtio_net: MQ activation failed\n");
            (*ndev()).has_mq = false;
            (*ndev()).num_queue_pairs = 1;
        }
    }
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
    let mut has_used_idx_mmio = false;
    let mut has_mq = false;
    unsafe {
        if is_v2 {
            virtio_write32(io_base + MMIO_DEVICE_FEATURES_SEL, 0);
            let dev_features = virtio_read32(io_base + MMIO_HOST_FEATURES);
            if (dev_features & VIRTIO_NET_F_MAC) != 0 { guest_features |= VIRTIO_NET_F_MAC; }
            if (dev_features & VIRTIO_NET_F_STATUS) != 0 { guest_features |= VIRTIO_NET_F_STATUS; }
            if (dev_features & VIRTIO_NET_F_MRG_RXBUF) != 0 { guest_features |= VIRTIO_NET_F_MRG_RXBUF; }
            if (dev_features & VIRTIO_F_USED_IDX_MMIO) != 0 {
                guest_features |= VIRTIO_F_USED_IDX_MMIO;
                has_used_idx_mmio = true;
            }
            if (dev_features & VIRTIO_NET_F_MQ) != 0 { guest_features |= VIRTIO_NET_F_MQ; }
            if (dev_features & VIRTIO_NET_F_CTRL_VQ) != 0 { guest_features |= VIRTIO_NET_F_CTRL_VQ; }
            has_mq = (guest_features & VIRTIO_NET_F_MQ) != 0
                  && (guest_features & VIRTIO_NET_F_CTRL_VQ) != 0;
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

    // Determine number of queue pairs
    let desired_pairs = fdt::info().cpu_count as u16;
    let max_pairs = if has_mq {
        let cfg_val = unsafe { virtio_read32(io_base + MMIO_DEVICE_CONFIG + 8) };
        ((cfg_val & 0xFFFF) as u16).max(1)
    } else {
        1
    };
    let num_pairs = desired_pairs.min(max_pairs).min(MAX_QUEUE_PAIRS as u16);

    // Init N queue pairs (RX=2i, TX=2i+1)
    for pair in 0..num_pairs as usize {
        let rx_qi = (pair * 2) as u16;
        let tx_qi = (pair * 2 + 1) as u16;
        unsafe {
            if !(*ndev()).rx_queues[pair].init_legacy(io_base, rx_qi, true, is_v2) {
                log(b"virtio_net: failed to init RX queue\n");
                return false;
            }
            if !(*ndev()).tx_queues[pair].init_legacy(io_base, tx_qi, true, is_v2) {
                log(b"virtio_net: failed to init TX queue\n");
                return false;
            }
            if has_used_idx_mmio {
                (*ndev()).rx_queues[pair].used_idx_mmio = true;
                (*ndev()).tx_queues[pair].used_idx_mmio = true;
            }
        }
    }

    // Init ctrl VQ if MQ negotiated and num_pairs > 1
    if has_mq && num_pairs > 1 {
        let ctrl_qi = (2 * max_pairs) as u16;
        unsafe {
            if !(*ndev()).ctrl_queue.init_legacy(io_base, ctrl_qi, true, is_v2) {
                log(b"virtio_net: failed to init ctrl queue, falling back to 1 pair\n");
                has_mq = false;
            }
        }
    }

    // Read MAC from config space
    unsafe {
        let lo = virtio_read32(io_base + MMIO_DEVICE_CONFIG);
        let hi = virtio_read32(io_base + MMIO_DEVICE_CONFIG + 4);
        (*ndev()).mac[0] = (lo & 0xff) as u8;
        (*ndev()).mac[1] = ((lo >> 8) & 0xff) as u8;
        (*ndev()).mac[2] = ((lo >> 16) & 0xff) as u8;
        (*ndev()).mac[3] = ((lo >> 24) & 0xff) as u8;
        (*ndev()).mac[4] = (hi & 0xff) as u8;
        (*ndev()).mac[5] = ((hi >> 8) & 0xff) as u8;
    }

    // Allocate RX buffers for all queue pairs. See RX_IP_ALIGN.
    for pair in 0..num_pairs as usize {
        for i in 0..RX_BUFFERS {
            let alloc = kmalloc(BUFFER_SIZE as usize + RX_IP_ALIGN);
            if alloc.is_null() { return false; }
            let buf = unsafe { alloc.add(RX_IP_ALIGN) };
            unsafe {
                ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
                (*ndev()).qp_state[pair].rx_buffers[i] = buf;
                let buf_phys = virt_to_phys(buf);
                (*ndev()).rx_queues[pair].add_buf(buf_phys, BUFFER_SIZE, 0, 1);
            }
        }
        unsafe { (*ndev()).rx_queues[pair].kick(); }
    }

    // DRIVER_OK
    let mut final_status = (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK) as u32;
    if is_v2 { final_status |= STATUS_FEATURES_OK as u32; }
    unsafe { virtio_write32(io_base + MMIO_STATUS, final_status); }

    unsafe {
        (*ndev()).transport = Transport::Mmio { base: io_base, is_v2 };
        (*ndev()).guest_features = guest_features;
        // See init_pci_modern: defer multi-queue activation until after DHCP.
        (*ndev()).num_queue_pairs = 1;
        (*ndev()).negotiated_queue_pairs = num_pairs;
        (*ndev()).has_mq = has_mq && num_pairs > 1;
    }

    if num_pairs > 1 {
        log(b"virtio_net: multi-queue available: ");
        log(&[b'0' + (num_pairs as u8 % 10)]);
        log(b" pairs (MMIO, deferred until after DHCP)\n");
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

    let dev_snap = pci_device(pci_idx);
    let dev = &dev_snap;
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

    // Feature negotiation. Legacy virtio-pci only exposes word 0
    // (32 bits), so VIRTIO_F_VERSION_1 (bit 32) is out of reach —
    // which matches GCE: its virtio-net backend is hard-locked to
    // legacy v0.95 and rejects modern feature negotiation outright.
    // MQ (bit 22) and CTRL_VQ (bit 17) live in word 0 and are safe.
    let dev_features = unsafe { virtio_read32(io_base + VREG_DEVICE_FEATURES) };
    let mut guest_features: u32 = 0;
    if (dev_features & VIRTIO_NET_F_MAC) != 0 { guest_features |= VIRTIO_NET_F_MAC; }
    if (dev_features & VIRTIO_NET_F_STATUS) != 0 { guest_features |= VIRTIO_NET_F_STATUS; }
    if (dev_features & VIRTIO_NET_F_MRG_RXBUF) != 0 { guest_features |= VIRTIO_NET_F_MRG_RXBUF; }
    if (dev_features & VIRTIO_NET_F_MQ) != 0 { guest_features |= VIRTIO_NET_F_MQ; }
    if (dev_features & VIRTIO_NET_F_CTRL_VQ) != 0 { guest_features |= VIRTIO_NET_F_CTRL_VQ; }
    let has_mq = (guest_features & VIRTIO_NET_F_MQ) != 0
              && (guest_features & VIRTIO_NET_F_CTRL_VQ) != 0;
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

    // Determine how many queue pairs to set up. Device config layout
    // in legacy mode (MSI-X off, always our case): MAC[6] + STATUS[2]
    // + max_virtqueue_pairs[2] starts at VREG_DEVICE_CONFIG + 8.
    #[cfg(target_arch = "x86_64")]
    let desired_pairs = unsafe { kernel::x86_64::acpi::detect_cpus() as u16 };
    #[cfg(not(target_arch = "x86_64"))]
    let desired_pairs = 1u16;
    let max_pairs = if has_mq {
        unsafe { virtio_read16(io_base + VREG_DEVICE_CONFIG + 8).max(1) }
    } else {
        1
    };
    let num_pairs = desired_pairs.min(max_pairs).min(MAX_QUEUE_PAIRS as u16);

    // Queue init order: ALL RX and TX pairs fully allocated and
    // their PFNs published via VREG_QUEUE_ADDRESS *before* we send
    // the MQ control command. GCE's backend drops RX delivery if it
    // sees VQ_PAIRS_SET before every pair's ring is programmed.
    for pair in 0..num_pairs as usize {
        let rx_qi = (pair * 2) as u16;
        let tx_qi = (pair * 2 + 1) as u16;
        unsafe {
            if !(*ndev()).rx_queues[pair].init_legacy(io_base, rx_qi, false, false) {
                log(b"virtio_net: failed to init RX queue\n");
                return false;
            }
            if !(*ndev()).tx_queues[pair].init_legacy(io_base, tx_qi, false, false) {
                log(b"virtio_net: failed to init TX queue\n");
                return false;
            }
        }
    }

    // Control VQ at index 2*max_pairs. Only initialised when we
    // intend to activate multi-queue — see the vhost-net wedge in
    // init_pci_modern's comment.
    let mut has_mq_final = has_mq;
    if has_mq && num_pairs > 1 {
        let ctrl_qi = (2 * max_pairs) as u16;
        unsafe {
            if !(*ndev()).ctrl_queue.init_legacy(io_base, ctrl_qi, false, false) {
                log(b"virtio_net: failed to init ctrl queue, falling back to 1 pair\n");
                has_mq_final = false;
            }
        }
    }

    // Read MAC
    for i in 0..6u64 {
        unsafe { (*ndev()).mac[i as usize] = virtio_read8(io_base + VREG_DEVICE_CONFIG + i); }
    }

    // Populate RX buffers for every queue pair (kick happens after
    // DRIVER_OK; the virtio spec says pre-DRIVER_OK kicks are
    // undefined and some backends drop them).
    for pair in 0..num_pairs as usize {
        for i in 0..RX_BUFFERS {
            let buf = kmalloc(BUFFER_SIZE as usize);
            if buf.is_null() { return false; }
            unsafe {
                ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
                (*ndev()).qp_state[pair].rx_buffers[i] = buf;
                let buf_phys = virt_to_phys(buf);
                (*ndev()).rx_queues[pair].add_buf(buf_phys, BUFFER_SIZE, 0, 1);
            }
        }
    }

    // DRIVER_OK — queues must be fully set up by this point.
    unsafe {
        virtio_write8(io_base + VREG_DEVICE_STATUS,
                      STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    }

    for pair in 0..num_pairs as usize {
        unsafe { (*ndev()).rx_queues[pair].kick(); }
    }

    unsafe {
        (*ndev()).transport = Transport::LegacyPci { base: io_base, pci_idx };
        (*ndev()).guest_features = guest_features;
        // DHCP needs single-queue (it only polls qp 0); boot/entry
        // later calls activate_multi_queue() to promote to N pairs.
        (*ndev()).num_queue_pairs = 1;
        (*ndev()).negotiated_queue_pairs = num_pairs;
        (*ndev()).has_mq = has_mq_final && num_pairs > 1;
    }

    if num_pairs > 1 {
        log(b"virtio_net: multi-queue available: ");
        log(&[b'0' + (num_pairs as u8 % 10)]);
        log(b" pairs (legacy PCI, deferred until after DHCP)\n");
    }
    log(b"virtio_net: initialization complete (legacy PCI)\n");
    true
}

// ---- TX drain ---------------------------------------------------------------

fn tx_drain_qp(qp: usize) {
    let pool_phys = unsafe { virt_to_phys((*ndev()).qp_state[qp].tx_pool.as_ptr() as *const u8) };
    unsafe {
        while let Some((used_id, _used_len)) = (*ndev()).tx_queues[qp].get_used() {
            let d = (*ndev()).tx_queues[qp].desc(used_id);
            let slot = ((d.addr - pool_phys) / core::mem::size_of::<TxBuf>() as u64) as usize;
            if slot < TX_POOL_SIZE {
                (*ndev()).qp_state[qp].tx_pool_used[slot] = false;
            }
        }
    }
}

fn tx_drain() {
    tx_drain_qp(0);
}

// ---- IRQ handler -----------------------------------------------------------

// x86_64: extern "C" fn() wrapper for the IDT stub trampoline
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn irq_handler_x86(_frame: *mut kernel::x86_64::idt::InterruptFrame) {
    irq_handler(0);
}

fn irq_handler(_irq: u32) {
    unsafe {
        // NAPI: disable notifications on entry
        (*ndev()).rx_queues[0].disable_interrupts();

        // Acknowledge device interrupt
        match (*ndev()).transport {
            Transport::ModernPci { vpci_idx } => {
                let dev = vpci_device(vpci_idx);
                vpci_read_isr(&dev);
            }
            #[cfg(target_arch = "aarch64")]
            Transport::Mmio { base, .. } => {
                // Always read ISR and write INTERRUPT_ACK. The FDT
                // `interrupts` flag (edge vs level) describes how the
                // GIC samples the line, not how the virtio-mmio device
                // implements interrupt signalling on the other side —
                // QEMU's virtio-mmio sets the line via
                // `!!vdev->isr` and keeps it asserted until the guest
                // acks, so skipping the ACK (which commit 6d7d749
                // did for an HVF-specific edge-pulse extension) causes
                // an unending IRQ storm on stock QEMU.
                let isr = virtio_read32(base + MMIO_INTERRUPT_STATUS);
                if (*ndev()).rx_queues[0].used_idx_mmio {
                    (*ndev()).rx_queues[0].mmio_cached_used_idx = (isr >> 16) as u16;
                }
                IRQ_PENDING.store(true, core::sync::atomic::Ordering::Release);
                virtio_write32(base + MMIO_INTERRUPT_ACK, isr & 0xFFFF);
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
    }
    // Try modern PCI first (supports multi-queue), fall back to legacy.
    if init_pci_modern() { return true; }
    #[cfg(target_arch = "x86_64")]
    {
        return init_legacy_pci();
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

pub fn get_mac(mac_out: *mut u8) {
    unsafe {
        ptr::copy_nonoverlapping((*ndev()).mac.as_ptr(), mac_out, 6);
    }
}

/// Send a frame on a specific queue pair.
fn send_on_qp(qp: usize, data: &[u8]) {
    if data.is_empty() { return; }
    unsafe {
        if let Transport::None = (*ndev()).transport { return; }
    }
    let len = data.len() as u32;
    let frame_len = if len > MAX_ETH_FRAME as u32 { MAX_ETH_FRAME as u32 } else { len };

    tx_drain_qp(qp);

    // Find a free pool slot; spin-drain if all busy
    let slot = loop {
        let mut found = None;
        for i in 0..TX_POOL_SIZE {
            if unsafe { !(*ndev()).qp_state[qp].tx_pool_used[i] } {
                found = Some(i);
                break;
            }
        }
        if let Some(s) = found { break s; }
        // Force any deferred kick to fire so the host can process
        // the pending TX batch and produce completions. With deferred
        // kicks + a host that delivers RX in big batches (HVF), we'd
        // otherwise deadlock here: the kick we're waiting on is
        // sitting in kick_dirty, not in the MMIO register.
        unsafe { (*ndev()).tx_queues[qp].flush_kick(); }
        tx_drain_qp(qp);
        compiler_fence(Ordering::SeqCst);
    };

    unsafe {
        (*ndev()).qp_state[qp].tx_pool_used[slot] = true;
        let buf = &mut (*ndev()).qp_state[qp].tx_pool[slot];
        // VirtIO net header: all zero except num_buffers = 1.
        buf.hdr = VirtioNetHeader {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 1,
        };

        ptr::copy_nonoverlapping(data.as_ptr(), buf.data.as_mut_ptr(), frame_len as usize);

        let total_len = VIRTIO_NET_HDR_SIZE as u32 + frame_len;
        let buf_phys = virt_to_phys(buf as *const TxBuf as *const u8);
        let head = (*ndev()).tx_queues[qp].add_buf(buf_phys, total_len, 1, 0);
        if head < 0 {
            (*ndev()).qp_state[qp].tx_pool_used[slot] = false;
            return;
        }

        (*ndev()).tx_queues[qp].kick();
    }
}

/// Flag: set by APs when they stage TX.
static TX_PENDING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// TX lock: protects the VirtIO TX queue. Any core can acquire to
/// flush or send. Wraps `()` because the underlying state lives in
/// `(*ndev()).tx_queues[0]` and is mutable through the existing
/// raw-pointer accessors; this lock just provides mutual exclusion.
static TX_LOCK: kernel::sync::Spinlock<()> = kernel::sync::Spinlock::new(());

/// Send a frame. Two paths:
///   * Multi-queue device: each core sends on its own per-core queue pair
///     with no locking.
///   * Single-queue (or extra cores beyond `num_queue_pairs`): push to a
///     per-core SPSC staging ring and flag `TX_PENDING`. Any core can later
///     batch-flush all staged frames into the shared queue under `TX_LOCK`
///     via `flush_tx_staging()`. The staging path is a throughput
///     optimisation — it lets `send()` stay non-blocking on hot paths while
///     a single core drains all rings under one lock acquisition.
pub fn send(data: &[u8]) {
    let cc = kernel::percpu::CurrentCore::enter();
    let id = cc.id();
    let nqp = unsafe { (*ndev()).num_queue_pairs };
    if nqp > 1 && (id as u16) < nqp {
        // Per-core queue pair: no contention, no locking.
        send_on_qp(id as usize, data);
    } else if kernel::percpu::num_cores() <= 1 {
        // Single-core: no contention possible, send directly.
        send_on_qp(0, data);
    } else {
        // Single shared queue, multiple cores: stage to per-core ring.
        cc.percore().tx_staging.push(data);
        TX_PENDING.store(true, Ordering::Release);
    }
}

/// True if any AP has staged TX packets waiting for flush.
pub fn has_pending_tx() -> bool {
    TX_PENDING.load(Ordering::Acquire)
}

/// Flush all per-core TX staging buffers into the VirtIO TX queue.
/// Any core may call this; concurrent calls are serialised via TX_LOCK.
pub fn flush_tx_staging() {
    if !TX_PENDING.load(Ordering::Acquire) {
        return;
    }
    // Only one core should flush at a time. The returned guard
    // releases the lock automatically on scope exit.
    let _guard = match TX_LOCK.try_lock() {
        Some(g) => g,
        None => return,
    };
    TX_PENDING.store(false, Ordering::Release);
    let n = kernel::percpu::num_cores();
    let mut buf = [0u8; 1514];
    for i in 0..n {
        unsafe {
            let core = kernel::percpu::get(i);
            while let Some(len) = core.tx_staging.pop_into(&mut buf) {
                send_on_qp(0, &buf[..len]);
            }
        }
    }
    // _guard released at end of scope.
}

/// Read the virtio INTERRUPT_STATUS register. This is a no-op from the
/// kernel's perspective (the value is discarded), but on HVF it forces
/// an MMIO exit that lets the host inject pending RX frames. Called from
/// DHCP's poll-wait loop to ensure DHCP replies are delivered during the
/// tight polling window where no other MMIO exits occur.
pub fn poke_interrupt_status() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if let Transport::Mmio { base, .. } = (*ndev()).transport {
            let isr = virtio_read32(base + MMIO_INTERRUPT_STATUS);
            // Cache used_idx from upper 16 bits (HVF extension).
            if (*ndev()).rx_queues[0].used_idx_mmio {
                (*ndev()).rx_queues[0].mmio_cached_used_idx = (isr >> 16) as u16;
            }
        }
    }
}

pub fn poll(
    callback: fn(&[u8]),
) -> i32 {
    poll_qp(0, callback)
}

/// Per-queue RX counters. Incremented once per consumed frame.
/// Read via `rx_counts()` from app code (e.g. the /stats handler)
/// to see which queues are actually getting traffic — useful for
/// diagnosing RSS / flow-hash distribution under Tier 1 MQ.
static RX_COUNTS: [core::sync::atomic::AtomicU64; MAX_QUEUE_PAIRS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MAX_QUEUE_PAIRS];

/// Snapshot of per-queue RX frame counts.
pub fn rx_counts() -> [u64; MAX_QUEUE_PAIRS] {
    let mut out = [0u64; MAX_QUEUE_PAIRS];
    for i in 0..MAX_QUEUE_PAIRS {
        out[i] = RX_COUNTS[i].load(core::sync::atomic::Ordering::Relaxed);
    }
    out
}

/// Raw used-ring cursors per RX queue:
///   [ (device_idx, driver_cursor), ... ]
///
/// `device_idx` is the volatile `used->idx` the device advances as
/// it writes RX buffers. `driver_cursor` is the driver's local
/// `last_used_idx`, incremented each time `poll_qp` consumes one.
///
/// Use the two together to tell where traffic is getting stuck:
///   device_idx == driver_cursor == 0   → device never delivered here
///   device_idx >  driver_cursor        → device delivered but we're
///                                        not polling fast enough / at all
///   device_idx == driver_cursor, both large → healthy: fully drained
pub fn rx_used_cursors() -> [(u16, u16); MAX_QUEUE_PAIRS] {
    let mut out = [(0u16, 0u16); MAX_QUEUE_PAIRS];
    // Only negotiated queues are actually initialised — the rest have
    // null `used` pointers and reading `used_idx()` on them would
    // page-fault in the kernel. `negotiated_queue_pairs` caps the
    // loop at what `init_pci_*` / `init_legacy_pci` wired up.
    let n = unsafe { (*ndev()).negotiated_queue_pairs as usize }
        .min(MAX_QUEUE_PAIRS);
    unsafe {
        for i in 0..n {
            out[i] = (
                (*ndev()).rx_queues[i].used_idx(),
                (*ndev()).rx_queues[i].last_used_cursor(),
            );
        }
    }
    out
}

/// Poll a specific queue pair for received frames.
pub fn poll_qp(qp: usize, callback: fn(&[u8])) -> i32 {
    unsafe {
        if let Transport::None = (*ndev()).transport { return 0; }
    }

    // For VIRTIO_F_USED_IDX_MMIO devices: the IRQ handler already
    // cached the used_idx when it read INTERRUPT_STATUS. Just consume
    // the flag — no extra MMIO exit needed.
    if IRQ_PENDING.swap(false, core::sync::atomic::Ordering::Acquire) {
        // used_idx was cached by irq_handler; get_used() will find it.
    }

    // Tier 1 (per-core RX queue) — qp is owned by this core, no
    // lock needed. Tier 2 (single shared queue) — serialise via
    // TX_LOCK so cores don't race the same TX descriptors.
    let nqp = unsafe { (*ndev()).num_queue_pairs };
    if kernel::percpu::num_cores() <= 1 || (nqp as usize) > 1 {
        tx_drain_qp(qp);
    } else if let Some(_g) = TX_LOCK.try_lock() {
        tx_drain_qp(qp);
        // _g released at end of scope.
    }

    let mut count: i32 = 0;
    unsafe {
        while let Some((used_id, used_len)) = (*ndev()).rx_queues[qp].get_used() {
            let desc = (*ndev()).rx_queues[qp].desc(used_id);
            let buf = phys_to_virt(desc.addr);

            if used_len > VIRTIO_NET_HDR_SIZE as u32 {
                let frame_len = (used_len - VIRTIO_NET_HDR_SIZE as u32) as usize;
                let frame_data = buf.add(VIRTIO_NET_HDR_SIZE);
                let slice = core::slice::from_raw_parts(frame_data, frame_len);
                callback(slice);
            }

            // Re-arm RX buffer
            let buf_phys = virt_to_phys(buf);
            (*ndev()).rx_queues[qp].add_buf(buf_phys, BUFFER_SIZE, 0, 1);
            count += 1;
        }

        if count > 0 {
            (*ndev()).rx_queues[qp].kick();
            if qp < MAX_QUEUE_PAIRS {
                RX_COUNTS[qp].fetch_add(
                    count as u64,
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
        }
    }

    count
}

/// Maximum frames per batch poll.
const BATCH_SIZE: usize = 32;

/// A batch of received frames. Frames are stored contiguously with
/// a length prefix: [len: u16][frame data][len: u16][frame data]...
pub struct RxBatch {
    pub data: [u8; BATCH_SIZE * 1600], // worst case: 32 × 1514-byte frames
    pub len: usize,                     // bytes used in data
    pub count: usize,                   // number of frames
}

impl RxBatch {
    pub const fn new() -> Self {
        RxBatch { data: [0; BATCH_SIZE * 1600], len: 0, count: 0 }
    }

    /// Iterate over frames in the batch.
    pub fn iter(&self) -> RxBatchIter<'_> {
        RxBatchIter { data: &self.data[..self.len], pos: 0 }
    }
}

pub struct RxBatchIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for RxBatchIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.pos + 2 > self.data.len() { return None; }
        let len = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]) as usize;
        self.pos += 2;
        if self.pos + len > self.data.len() { return None; }
        let frame = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some(frame)
    }
}

/// Poll VirtIO RX queue pair 0 and collect frames into a batch buffer.
pub fn poll_batch(batch: &mut RxBatch) {
    poll_batch_qp(0, batch);
}

/// Poll a specific queue pair's RX queue into a batch buffer.
pub fn poll_batch_qp(qp: usize, batch: &mut RxBatch) {
    batch.len = 0;
    batch.count = 0;

    unsafe {
        if let Transport::None = (*ndev()).transport { return; }
    }

    // Drain TX completions. Tier 1 owns qp per core (no lock needed),
    // Tier 2 has the single shared queue and must serialise.
    let nqp = unsafe { (*ndev()).num_queue_pairs };
    if kernel::percpu::num_cores() <= 1 || (nqp as usize) > 1 {
        tx_drain_qp(qp);
    } else if let Some(_g) = TX_LOCK.try_lock() {
        tx_drain_qp(qp);
    }

    unsafe {
        while batch.count < BATCH_SIZE {
            let (used_id, used_len) = match (*ndev()).rx_queues[qp].get_used() {
                Some(v) => v,
                None => break,
            };
            let desc = (*ndev()).rx_queues[qp].desc(used_id);
            let buf = phys_to_virt(desc.addr);

            if used_len > VIRTIO_NET_HDR_SIZE as u32 {
                let frame_len = (used_len - VIRTIO_NET_HDR_SIZE as u32) as usize;
                if batch.len + 2 + frame_len <= batch.data.len() {
                    let len_bytes = (frame_len as u16).to_le_bytes();
                    batch.data[batch.len] = len_bytes[0];
                    batch.data[batch.len + 1] = len_bytes[1];
                    let frame_data = buf.add(VIRTIO_NET_HDR_SIZE);
                    core::ptr::copy_nonoverlapping(
                        frame_data, batch.data.as_mut_ptr().add(batch.len + 2), frame_len);
                    batch.len += 2 + frame_len;
                    batch.count += 1;
                }
            }

            // Re-arm RX buffer
            let buf_phys = virt_to_phys(buf);
            (*ndev()).rx_queues[qp].add_buf(buf_phys, BUFFER_SIZE, 0, 1);
        }

        if batch.count > 0 {
            (*ndev()).rx_queues[0].kick();
        }
    }
}

pub fn enable_irq() {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            let fdt = fdt::info();

            match (*ndev()).transport {
                Transport::ModernPci { vpci_idx } if fdt.gic_dist_base != 0 => {
                    let slot = pci_device(vpci_device(vpci_idx).pci_idx).slot;
                    let intid = if (slot as usize) < 8 { fdt.pci_irqs[slot as usize] } else { 0 };
                    if intid != 0 {
                        (*ndev()).rx_queues[0].enable_interrupts();
                        exceptions::register_irq(intid, irq_handler);
                        (*ndev()).irq_idle_available = true;
                    }
                }
                Transport::Mmio { base, .. } if fdt.gic_dist_base != 0 => {
                    for i in 0..fdt.virtio_count as usize {
                        if fdt.virtio_bases[i] == base && fdt.virtio_irqs[i] != 0 {
                            (*ndev()).rx_queues[0].enable_interrupts();
                            exceptions::register_irq(fdt.virtio_irqs[i], irq_handler);
                            (*ndev()).irq_idle_available = true;
                            // FDT flags bit 0: 1=edge-triggered, 0=level.
                            // Edge SPIs don't need ISR read or ACK write.
                            (*ndev()).irq_edge = (fdt.virtio_irq_flags[i] & 1) != 0;
                            break;
                        }
                    }
                }
                _ => {}
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            match (*ndev()).transport {
                Transport::LegacyPci { pci_idx, .. } => {
                    let dev = pci_device(pci_idx);
                    let irq_reg = read_config(dev.bus, dev.slot, dev.func, 0x3C);
                    let irq_line = (irq_reg & 0xFF) as u8;
                    if irq_line < 16 {
                        (*ndev()).rx_queues[0].enable_interrupts();
                        kernel::x86_64::idt::register_handler(32 + irq_line, irq_handler_x86);
                        kernel::x86_64::idt::enable_irq(irq_line);
                        (*ndev()).irq_idle_available = true;
                    }
                }
                Transport::ModernPci { vpci_idx } => {
                    let dev = vpci_device(vpci_idx);
                    if dev.msix_cap_off != 0 && dev.msix_table != 0 {
                        init_msix_x86(&dev, (*ndev()).num_queue_pairs as usize);
                        // Enable notifications on each RX queue pair so the
                        // first incoming packet triggers an MSI-X entry we
                        // unmasked in init_msix_x86.
                        let nqp = (*ndev()).num_queue_pairs as usize;
                        for qp in 0..nqp {
                            (*ndev()).rx_queues[qp].enable_interrupts();
                        }
                        (*ndev()).irq_idle_available = true;
                    }
                }
                _ => {}
            }
        }
    }
}

/// Wire MSI-X for ModernPCI on x86_64. One vector per RX queue pair;
/// each vector is steered to the owning vCPU's Local APIC so `arch::idle`
/// on that core wakes directly on its own RX queue. TX queues and the
/// config-change vector are set to VIRTIO_MSI_NO_VECTOR because the
/// driver polls TX completions itself.
///
/// Must be called with all queue pairs already enabled and before
/// DRIVER_OK is set (which the `enable_irq` caller arranges: in the
/// current flow enable_irq runs from the boot path after DRIVER_OK,
/// and QEMU's virtio-net happily accepts MSI-X vector updates then).
#[cfg(target_arch = "x86_64")]
fn init_msix_x86(dev: &VirtioPciDevice, num_pairs: usize) {
    const NO_VEC: u16 = 0xFFFF;
    // IDT base for virtio-net MSI-X vectors. Sits above the PIC/APIC
    // timer range and well under the spurious vector (0xFF). One
    // vector per RX queue pair — up to MAX_QUEUE_PAIRS.
    const MSIX_IDT_BASE: u8 = 0x60;

    // Enable MSI-X in the device's PCI config.
    vpci_msix_enable(dev, true);

    // Config-change interrupt: unused.
    vpci_set_config_msix_vector(dev, NO_VEC);

    let topo = kernel::x86_64::acpi::topology();
    let cpu_count = topo.cpu_count as usize;

    for qp in 0..num_pairs {
        // Steer each queue pair's RX IRQ at the vCPU that owns it.
        let target_cpu = if qp < cpu_count { qp } else { 0 };
        let apic_id = topo.apic_ids[target_cpu] as u64;
        let idt_vector = MSIX_IDT_BASE + qp as u8;
        // MSI address (Intel SDM 10.11.1): 0xFEE0_0000 | dest<<12.
        // MSI data: low byte = vector, rest zero (fixed delivery, edge).
        let addr = 0xFEE0_0000u64 | (apic_id << 12);
        let data = idt_vector as u32;
        vpci_msix_write_entry(dev, qp as u16, addr, data, false);

        // Install the IDT handler for this vector. All per-queue
        // handlers share one implementation that reads the current
        // core's id and sets the RX_PENDING flag for that core.
        kernel::x86_64::idt::register_handler(idt_vector, msix_rx_isr_trampoline);

        // Point the RX queue at the vector; TX stays unvectored.
        let rx_qi = (qp * 2) as u16;
        let tx_qi = (qp * 2 + 1) as u16;
        vpci_select_queue(dev, rx_qi);
        vpci_set_queue_msix_vector(dev, qp as u16);
        vpci_select_queue(dev, tx_qi);
        vpci_set_queue_msix_vector(dev, NO_VEC);
    }

    log(b"virtio_net: MSI-X enabled (");
    log(&[b'0' + (num_pairs as u8 % 10)]);
    log(b" RX vectors)\n");
}

/// ISR trampoline for all virtio-net MSI-X RX vectors.
/// Sets `IRQ_PENDING` so the event-loop poll drains the queue on the
/// next iteration. Fires on the target vCPU because the MSI address
/// was programmed with that vCPU's LAPIC id.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn msix_rx_isr_trampoline(
    _frame: *mut kernel::x86_64::idt::InterruptFrame,
) {
    IRQ_PENDING.store(true, core::sync::atomic::Ordering::Release);
}

pub fn irq_idle_supported() -> bool {
    unsafe { (*ndev()).irq_idle_available }
}

pub fn arm_rx_interrupts() {
    unsafe { (*ndev()).rx_queues[0].enable_interrupts(); }
}

pub fn has_pending_rx() -> bool {
    unsafe { (*ndev()).rx_queues[0].has_used() }
}

/// NAPI re-arm for the event loop: enable RX notifications on the
/// queue pair that `core_id` owns, then re-check for work that arrived
/// in the arm window. Returns true iff the caller should skip HLT and
/// loop back to poll.
///
/// Tier 1 multi-queue: each core owns `rx_queues[core_id]`.
/// Tier 2 / single-queue: every core arms queue 0, and only the core
/// currently acting as distributor (whichever wins the RX_LOCK in the
/// net crate) actually reads from it.
pub fn rearm_rx_napi(core_id: u32) -> bool {
    unsafe {
        let nqp = (*ndev()).num_queue_pairs;
        let qp = if nqp > 1 && (core_id as u16) < nqp {
            core_id as usize
        } else {
            0
        };
        (*ndev()).rx_queues[qp].enable_interrupts();
        (*ndev()).rx_queues[qp].has_used()
    }
}

/// Enable deferred TX kick mode. After this, kick() on the TX queue
/// is a no-op; the caller must call flush_tx_kick() to issue the
/// actual MMIO write. Batches multiple send_segment() calls into
/// one virtio notification, reducing MMIO exits.
pub fn enable_deferred_tx_kick() {
    let nqp = unsafe { (*ndev()).num_queue_pairs } as usize;
    for qp in 0..nqp {
        unsafe { (*ndev()).tx_queues[qp].set_deferred_kick(true); }
    }
}

/// Flush deferred TX kick — issues one MMIO notify for all batched TX.
/// Only kicks if new buffers were added since last flush (kick_dirty).
pub fn flush_tx_kick() {
    unsafe { (*ndev()).tx_queues[0].flush_kick(); }
}

/// Flush only if dirty. Returns true if a kick was issued.
/// In multi-queue mode, flushes the calling core's TX queue pair.
pub fn flush_tx_kick_if_dirty() -> bool {
    let nqp = unsafe { (*ndev()).num_queue_pairs };
    if nqp > 1 {
        let core = kernel::cpu_id() as usize;
        let qp = if core < nqp as usize { core } else { 0 };
        unsafe { (*ndev()).tx_queues[qp].flush_kick_if_dirty() }
    } else {
        unsafe { (*ndev()).tx_queues[0].flush_kick_if_dirty() }
    }
}
