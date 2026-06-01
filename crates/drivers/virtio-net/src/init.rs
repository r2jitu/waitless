// Device-init paths: modern VirtIO-PCI bring-up, aarch64
// VirtIO-MMIO bring-up, per-queue-pair storage allocation, and the
// MQ control-VQ command we send to activate multi-queue after DHCP.

use core::ptr;

// virtio-net device feature bits (defined in this crate, not the bus
// transport). MAC/MRG_RXBUF/STATUS are used only by the aarch64 MMIO path.
use crate::{
    VIRTIO_NET_F_CSUM, VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_MQ,
    VIRTIO_NET_RX_OFFLOAD_MASK,
};
#[cfg(target_arch = "aarch64")]
use crate::{VIRTIO_NET_F_MAC, VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_STATUS};
use bus::virtio::{
    STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED, STATUS_FEATURES_OK,
    VIRTIO_RING_F_EVENT_IDX, Virtqueue, vpci_device, vpci_enable_queue, vpci_find,
    vpci_get_queue_notify_off, vpci_get_queue_size, vpci_get_status, vpci_queue_notify_addr,
    vpci_read_dev_cfg8, vpci_read_dev_cfg16, vpci_read_features, vpci_reset, vpci_select_queue,
    vpci_set_queue_addrs, vpci_set_status, vpci_write_features,
};
// MMIO transport symbols — used only by the aarch64 `init_mmio` path.
#[cfg(target_arch = "aarch64")]
use bus::virtio::{
    MMIO_BASE, MMIO_DEVICE_CONFIG, MMIO_DEVICE_FEATURES_SEL, MMIO_DEVICE_ID,
    MMIO_DRIVER_FEATURES_SEL, MMIO_GUEST_FEATURES, MMIO_GUEST_PAGE_SIZE, MMIO_HOST_FEATURES,
    MMIO_MAGIC, MMIO_MAGIC_VALUE, MMIO_STATUS, MMIO_VERSION, VIRTIO_F_USED_IDX_MMIO,
};
use bus::log;
// virtio register I/O — used only by the aarch64 `init_mmio` path.
#[cfg(target_arch = "aarch64")]
use bus::{virtio_read32, virtio_write32};
#[cfg(target_arch = "aarch64")]
use kernel_bare::aarch64::fdt;
use kernel_bare::mm::{kmalloc, virt_to_phys};

use crate::{
    BUFFER_SIZE, QueuePairState, RX_BUFFERS, RX_IP_ALIGN, Transport, TxBufBig, TX_POOL_BIG_SIZE,
    VIRTIO_NET_HDR_SIZE, WorkerTxPool, ndev, qps, rx_q, tx_q,
};

/// Heap-allocate storage for `num_pairs` rx/tx queues + qp state.
/// Idempotent: a successful first call followed by a fallback-
/// transport re-init keeps the existing storage rather than
/// re-allocating (ownership during driver re-init is not well-
/// defined). Returns `false` on OOM.
pub(crate) unsafe fn init_qp_storage(num_pairs: usize, has_tso: bool) -> bool {
    use alloc::alloc::{Layout, alloc};
    if num_pairs == 0 {
        return false;
    }
    let num_workers = kernel_bare::percpu::num_cores().max(1) as usize;
    unsafe {
        if !(*ndev()).rx_queues.is_null() {
            return true;
        }
        let q_layout = match Layout::array::<Virtqueue>(num_pairs) {
            Ok(l) => l,
            Err(_) => return false,
        };
        let s_layout = match Layout::array::<QueuePairState>(num_pairs) {
            Ok(l) => l,
            Err(_) => return false,
        };
        let p_layout = match Layout::array::<WorkerTxPool>(num_workers) {
            Ok(l) => l,
            Err(_) => return false,
        };
        let rx = alloc(q_layout) as *mut Virtqueue;
        let tx = alloc(q_layout) as *mut Virtqueue;
        let qs = alloc(s_layout) as *mut QueuePairState;
        let wp = alloc(p_layout) as *mut WorkerTxPool;
        if rx.is_null() || tx.is_null() || qs.is_null() || wp.is_null() {
            return false;
        }
        for i in 0..num_pairs {
            ptr::write(rx.add(i), Virtqueue::ZERO);
            ptr::write(tx.add(i), Virtqueue::ZERO);
            ptr::write(qs.add(i), QueuePairState::ZEROED);
        }
        for i in 0..num_workers {
            ptr::write(wp.add(i), WorkerTxPool::ZEROED);
        }
        (*ndev()).rx_queues = rx;
        (*ndev()).tx_queues = tx;
        (*ndev()).qp_state = qs;
        (*ndev()).worker_pools = wp;
        (*ndev()).num_workers = num_workers;

        // Allocate big TX pool per-worker only when TSO is
        // negotiated. ~264 KiB extra per worker; skipped entirely
        // on TSO-disabled devices so they pay nothing for unused
        // slots.
        if has_tso {
            let big_layout = match Layout::array::<TxBufBig>(TX_POOL_BIG_SIZE) {
                Ok(l) => l,
                Err(_) => return false,
            };
            for i in 0..num_workers {
                let big = alloc(big_layout) as *mut TxBufBig;
                if big.is_null() {
                    // Best-effort: leave the previously-allocated
                    // workers' big pools in place. TSO requests on
                    // workers without a big pool fall back to per-MSS.
                    return false;
                }
                for slot in 0..TX_POOL_BIG_SIZE {
                    ptr::write(big.add(slot), TxBufBig::ZERO);
                }
                (*wp.add(i)).big = big;
            }
        }
    }
    true
}

// ---- Modern PCI init (VirtIO 1.0+) -----------------------------------------

pub(crate) fn init_pci_modern() -> bool {
    let vpci_idx = match vpci_find(1) {
        // virtio device type 1 = net
        Some(i) => i,
        None => return false,
    };

    let dev_snap = vpci_device(vpci_idx);
    let dev = &dev_snap;

    vpci_reset(dev);
    vpci_set_status(dev, STATUS_ACKNOWLEDGE);
    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let dev_features = vpci_read_features(dev, 0);
    // Accept every offered word-0 feature EXCEPT the guest-side RX
    // offloads (VIRTIO_NET_RX_OFFLOAD_MASK). Some hypervisors (notably
    // Apple Virtualization.framework) require CSUM/INDIRECT_DESC and
    // reject us if we don't ack them — those stay. But the RX path
    // (`poll_qp`) handles only single-descriptor ≤MTU frames: echoing
    // GUEST_TSO4/MRG_RXBUF back lets a tap+vhost-net backend hand us
    // GRO-coalesced, multi-descriptor super-frames it then shreds,
    // which stalls large uploads on the `--env kvm` bench path. SLIRP
    // never coalesces, so plain `--env qemu` never tripped it. VERSION_1
    // is negotiated below, so the virtio-net header stays 12 bytes
    // regardless of MRG_RXBUF.
    let guest_features = dev_features & !VIRTIO_NET_RX_OFFLOAD_MASK;

    // Check for multi-queue support
    let has_mq =
        (dev_features & VIRTIO_NET_F_MQ) != 0 && (dev_features & VIRTIO_NET_F_CTRL_VQ) != 0;
    // Check for TSOv4 support. Requires both VIRTIO_NET_F_CSUM (so the
    // device computes the per-segment TCP/IP checksum we don't bother
    // with on TSO sends) AND VIRTIO_NET_F_HOST_TSO4 (so the device can
    // segment a super-segment we hand it). When both are negotiated the
    // TCP layer can collapse its per-MSS frame-build loop into a single
    // submit_tx_tso call.
    let has_tso4 =
        (dev_features & VIRTIO_NET_F_CSUM) != 0 && (dev_features & VIRTIO_NET_F_HOST_TSO4) != 0;
    let has_csum = (dev_features & VIRTIO_NET_F_CSUM) != 0;

    vpci_write_features(dev, 0, guest_features);
    vpci_write_features(dev, 1, 1); // VIRTIO_F_VERSION_1

    vpci_set_status(dev, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    if (vpci_get_status(dev) & STATUS_FEATURES_OK) == 0 {
        log(b"virtio_net: device rejected features\n");
        vpci_set_status(dev, STATUS_FAILED);
        return false;
    }

    // Read max queue pairs from device config (offset 8, u16)
    // Use WAITLESS_CPUS env var (set in QEMU args) since percpu::init()
    // hasn't run yet. Fall back to 1 if not available.
    #[cfg(target_arch = "x86_64")]
    let desired_pairs = unsafe { kernel_bare::x86_64::acpi::detect_cpus() as u16 };
    #[cfg(target_arch = "aarch64")]
    let desired_pairs = kernel_bare::aarch64::fdt::info().cpu_count as u16;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let desired_pairs = 1u16;
    let max_pairs = if has_mq {
        vpci_read_dev_cfg16(dev, 8).max(1)
    } else {
        1
    };
    let num_pairs = desired_pairs.min(max_pairs);

    // Heap-allocate per-qp storage for the negotiated count, then
    // init each queue.
    if !unsafe { init_qp_storage(num_pairs as usize, has_tso4) } {
        log(b"virtio_net: failed to allocate per-qp storage\n");
        vpci_set_status(dev, STATUS_FAILED);
        return false;
    }

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
        let rx_init = unsafe { (*rx_q(pair)).init_pci_modern(rx_qsize, rx_notify, rx_qi) };
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
        let tx_init = unsafe { (*tx_q(pair)).init_pci_modern(tx_qsize, tx_notify, tx_qi) };
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
        let ctrl_qi = 2 * max_pairs;
        vpci_select_queue(dev, ctrl_qi);
        let ctrl_qsize = vpci_get_queue_size(dev);
        if ctrl_qsize > 0 {
            let ctrl_notify_off = vpci_get_queue_notify_off(dev);
            let ctrl_notify = vpci_queue_notify_addr(dev, ctrl_notify_off);
            // SAFETY: single-threaded boot init.
            let ctrl_init = unsafe {
                (*ndev())
                    .ctrl_queue
                    .init_pci_modern(ctrl_qsize, ctrl_notify, ctrl_qi)
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
            unsafe {
                (*rx_q(pair)).event_idx = true;
            }
        }
    }

    // Read MAC
    for i in 0..6u32 {
        unsafe {
            (*ndev()).mac[i as usize] = vpci_read_dev_cfg8(dev, i);
        }
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
                (*qps(pair)).rx_buffers[i] = buf;
                let buf_phys = virt_to_phys(buf);
                (*rx_q(pair)).add_buf(buf_phys, BUFFER_SIZE, 0, 1);
            }
        }
    }

    // DRIVER_OK
    vpci_set_status(
        dev,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
    );

    for pair in 0..num_pairs as usize {
        unsafe {
            (*rx_q(pair)).kick();
        }
    }

    unsafe {
        (*ndev()).transport = Transport::ModernPci { vpci_idx };
        (*ndev()).guest_features = guest_features;
        (*ndev()).num_queue_pairs = 1;
        (*ndev()).negotiated_queue_pairs = num_pairs;
        (*ndev()).has_mq = has_mq && num_pairs > 1;
        (*ndev()).has_tso4 = has_tso4;
        (*ndev()).has_csum = has_csum;
    }
    activate_multi_queue();

    true
}

/// Promote the device from single-queue to multi-queue after DHCP.
/// No-op for single-queue (count=1) because telling vhost-net to
/// "use 1 pair" via MQ_VQ_PAIRS_SET(1) appears to wedge the RX path
/// on QEMU 10 — packets stop arriving in the guest even though the
/// send-side still looks healthy. Leaving the count unset means
/// vhost-net falls back to its default single-pair behaviour, which
/// empirically works fine for 1-vCPU guests.
fn activate_multi_queue() {
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
// CTRL-VQ scratch. Only written from `ctrl_mq_set_pairs`, which the
// driver init path calls once on the BSP before any AP is running.
struct CtrlMqBufCell(core::cell::UnsafeCell<CtrlMqBuf>);
// SAFETY: BSP-only during driver init; no concurrent access.
unsafe impl Sync for CtrlMqBufCell {}

static CTRL_MQ_BUF: CtrlMqBufCell = CtrlMqBufCell(core::cell::UnsafeCell::new(CtrlMqBuf {
    hdr_class: 0,
    hdr_cmd: 0,
    data: [0; 2],
    _pad: [0; 4],
    ack: 0,
    _tail: [0; 7],
}));

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
        let buf_ptr = CTRL_MQ_BUF.0.get();
        (*buf_ptr).hdr_class = 4; // VIRTIO_NET_CTRL_MQ
        (*buf_ptr).hdr_cmd = 0; // VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET
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
        let ack_phys = virt_to_phys(&(*buf_ptr).ack as *const u8);

        (*ndev()).ctrl_queue.add_chain(&[
            (hdrdata_phys, 4, false), // readable: class + cmd + num_pairs
            (ack_phys, 1, true),      // writable: ack byte
        ]);
        (*ndev()).ctrl_queue.kick();

        // Wait for completion.
        for _ in 0..1_000_000u32 {
            if (*ndev()).ctrl_queue.used().is_some() {
                break;
            }
        }
        let _ = (*ndev()).ctrl_queue.used();

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
pub(crate) fn init_mmio() -> bool {
    let mut io_base: u64 = 0;

    unsafe {
        let fdt = fdt::info();

        // Search FDT virtio-mmio devices for net (device_id=1)
        if fdt.virtio_count > 0 {
            for i in 0..fdt.virtio_count as usize {
                let candidate = fdt.virtio_bases[i];
                if bus::virtio_read32(candidate + MMIO_MAGIC_VALUE) != MMIO_MAGIC {
                    continue;
                }
                if bus::virtio_read32(candidate + MMIO_DEVICE_ID) == 1 {
                    io_base = candidate;
                    break;
                }
            }
        }

        // Fallback: fixed QEMU slot scan
        if io_base == 0 {
            for slot in 0..32u64 {
                let candidate = MMIO_BASE + slot * 0x200;
                if virtio_read32(candidate + MMIO_MAGIC_VALUE) != MMIO_MAGIC {
                    continue;
                }
                if virtio_read32(candidate + MMIO_DEVICE_ID) == 1 {
                    io_base = candidate;
                    break;
                }
            }
        }
    }

    if io_base == 0 {
        return false;
    }

    let ver = unsafe { virtio_read32(io_base + MMIO_VERSION) };
    let is_v2 = ver == 2;
    if ver != 1 && ver != 2 {
        return false;
    }

    // Reset
    unsafe {
        virtio_write32(io_base + MMIO_STATUS, 0);
    }

    // ACKNOWLEDGE + DRIVER
    unsafe {
        virtio_write32(io_base + MMIO_STATUS, STATUS_ACKNOWLEDGE as u32);
        virtio_write32(
            io_base + MMIO_STATUS,
            (STATUS_ACKNOWLEDGE | STATUS_DRIVER) as u32,
        );
    }

    // Feature negotiation
    let mut guest_features: u32 = 0;
    let mut has_used_idx_mmio = false;
    let mut has_mq = false;
    let mut has_tso4 = false;
    let mut has_csum = false;
    unsafe {
        if is_v2 {
            virtio_write32(io_base + MMIO_DEVICE_FEATURES_SEL, 0);
            let dev_features = virtio_read32(io_base + MMIO_HOST_FEATURES);
            if (dev_features & VIRTIO_NET_F_CSUM) != 0 {
                guest_features |= VIRTIO_NET_F_CSUM;
            }
            if (dev_features & VIRTIO_NET_F_MAC) != 0 {
                guest_features |= VIRTIO_NET_F_MAC;
            }
            if (dev_features & VIRTIO_NET_F_HOST_TSO4) != 0 {
                guest_features |= VIRTIO_NET_F_HOST_TSO4;
            }
            if (dev_features & VIRTIO_NET_F_STATUS) != 0 {
                guest_features |= VIRTIO_NET_F_STATUS;
            }
            if (dev_features & VIRTIO_NET_F_MRG_RXBUF) != 0 {
                guest_features |= VIRTIO_NET_F_MRG_RXBUF;
            }
            if (dev_features & VIRTIO_F_USED_IDX_MMIO) != 0 {
                guest_features |= VIRTIO_F_USED_IDX_MMIO;
                has_used_idx_mmio = true;
            }
            if (dev_features & VIRTIO_NET_F_MQ) != 0 {
                guest_features |= VIRTIO_NET_F_MQ;
            }
            if (dev_features & VIRTIO_NET_F_CTRL_VQ) != 0 {
                guest_features |= VIRTIO_NET_F_CTRL_VQ;
            }
            has_mq = (guest_features & VIRTIO_NET_F_MQ) != 0
                && (guest_features & VIRTIO_NET_F_CTRL_VQ) != 0;
            // TSOv4 needs both CSUM (host computes per-segment cksums)
            // and HOST_TSO4 (device segments super-segments); both
            // negotiated → TCP layer can collapse its per-MSS loop.
            has_tso4 = (guest_features & VIRTIO_NET_F_CSUM) != 0
                && (guest_features & VIRTIO_NET_F_HOST_TSO4) != 0;
            has_csum = (guest_features & VIRTIO_NET_F_CSUM) != 0;
            virtio_write32(io_base + MMIO_DRIVER_FEATURES_SEL, 0);
            virtio_write32(io_base + MMIO_GUEST_FEATURES, guest_features);
            virtio_write32(io_base + MMIO_DRIVER_FEATURES_SEL, 1);
            virtio_write32(io_base + MMIO_GUEST_FEATURES, 0);

            virtio_write32(
                io_base + MMIO_STATUS,
                (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK) as u32,
            );
            if (virtio_read32(io_base + MMIO_STATUS) & STATUS_FEATURES_OK as u32) == 0 {
                log(b"virtio_net: device rejected features\n");
                virtio_write32(io_base + MMIO_STATUS, STATUS_FAILED as u32);
                return false;
            }
        } else {
            let dev_features = virtio_read32(io_base + MMIO_HOST_FEATURES);
            if (dev_features & VIRTIO_NET_F_MAC) != 0 {
                guest_features |= VIRTIO_NET_F_MAC;
            }
            if (dev_features & VIRTIO_NET_F_STATUS) != 0 {
                guest_features |= VIRTIO_NET_F_STATUS;
            }
            if (dev_features & VIRTIO_NET_F_MRG_RXBUF) != 0 {
                guest_features |= VIRTIO_NET_F_MRG_RXBUF;
            }
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
    let num_pairs = desired_pairs.min(max_pairs);

    if !unsafe { init_qp_storage(num_pairs as usize, has_tso4) } {
        log(b"virtio_net: failed to allocate per-qp storage\n");
        return false;
    }

    // Init N queue pairs (RX=2i, TX=2i+1)
    for pair in 0..num_pairs as usize {
        let rx_qi = (pair * 2) as u16;
        let tx_qi = (pair * 2 + 1) as u16;
        unsafe {
            if !(*rx_q(pair)).init_legacy(io_base, rx_qi, true, is_v2) {
                log(b"virtio_net: failed to init RX queue\n");
                return false;
            }
            if !(*tx_q(pair)).init_legacy(io_base, tx_qi, true, is_v2) {
                log(b"virtio_net: failed to init TX queue\n");
                return false;
            }
            if has_used_idx_mmio {
                (*rx_q(pair)).used_idx_mmio = true;
                (*tx_q(pair)).used_idx_mmio = true;
            }
        }
    }

    // Init ctrl VQ if MQ negotiated and num_pairs > 1
    if has_mq && num_pairs > 1 {
        let ctrl_qi = 2 * max_pairs;
        unsafe {
            if !(*ndev())
                .ctrl_queue
                .init_legacy(io_base, ctrl_qi, true, is_v2)
            {
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
            if alloc.is_null() {
                return false;
            }
            let buf = unsafe { alloc.add(RX_IP_ALIGN) };
            unsafe {
                ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
                (*qps(pair)).rx_buffers[i] = buf;
                let buf_phys = virt_to_phys(buf);
                (*rx_q(pair)).add_buf(buf_phys, BUFFER_SIZE, 0, 1);
            }
        }
        unsafe {
            (*rx_q(pair)).kick();
        }
    }

    // DRIVER_OK
    let mut final_status = (STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK) as u32;
    if is_v2 {
        final_status |= STATUS_FEATURES_OK as u32;
    }
    unsafe {
        virtio_write32(io_base + MMIO_STATUS, final_status);
    }

    unsafe {
        (*ndev()).transport = Transport::Mmio {
            base: io_base,
            is_v2,
        };
        (*ndev()).guest_features = guest_features;
        (*ndev()).num_queue_pairs = 1;
        (*ndev()).negotiated_queue_pairs = num_pairs;
        (*ndev()).has_mq = has_mq && num_pairs > 1;
        (*ndev()).has_tso4 = has_tso4;
        (*ndev()).has_csum = has_csum;
    }
    activate_multi_queue();

    true
}

// Legacy virtio-pci init (`init_legacy_pci`, x86_64-only) was
// removed at commit-time-of-this-comment. It was originally
// written for GCE's legacy virtio-net backend (no modern PCI
// caps, hard-locked to v0.95 features), but GCE deployments
// now use the gve driver as the preferred NIC. In every other
// x86_64 environment we test (QEMU 9.x, KVM-on-host) the
// `init_pci_modern` path succeeds. Resurrect from git history
// (`waitless-driver-virtio-net: remove unreachable legacy PCI init`)
// if a future hypervisor surfaces one that only exposes the
// legacy I/O-port surface.
