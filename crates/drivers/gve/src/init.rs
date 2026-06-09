// Probe + device initialisation + per-queue resource setup.
//
// Owns the bring-up sequence from PCI probe through DESCRIBE_DEVICE,
// CONFIGURE_DEVICE_RESOURCES, REGISTER_PAGE_LIST × 2N, and
// CREATE_*_QUEUE × 2N (+ CONFIGURE_RSS when num_qp > 1). The DQO vs
// GQI queue-format negotiation lives here too — the chosen format is
// committed to the `QUEUE_FORMAT_DQO` hot-path flag at the end of
// `init()` and consumed by the tx/rx dispatch functions in `tx.rs` /
// `rx.rs`.
//
// Wire-level command layouts are documented inline at each builder
// so the admin-queue reference file doesn't have to be open to
// follow along. Sizes + field offsets are from the FreeBSD
// `gve_adminq.h`; the payload lives at offset 8 within the 64-byte
// command (opcode + status + 56 bytes of per-command data).

use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

use bus::{log, pci};
use iobuf::IOBufPool;
use kernel_bare::mm::{alloc_pages, phys_to_virt};

use crate::adminq::{
    self, AdminqCommand, OP_CONFIGURE_DEVICE_RESOURCES, OP_CONFIGURE_RSS, OP_CREATE_RX_QUEUE,
    OP_CREATE_TX_QUEUE, OP_DESCRIBE_DEVICE, OP_REGISTER_PAGE_LIST,
};
use crate::{
    BAR0, BAR2_VA, COUNTER_ARRAY_VA, DEVICE_DESCRIPTOR_VERSION, GVE_RAW_ADDRESSING_QPL_ID,
    GVNIC_OK, MAX_QUEUE_PAIRS, NUM_QP, OPT_ID_DQO_RDA, OPT_ID_GQI_QPL, OPT_ID_MODIFY_RING,
    PAGE_SIZE, PCI_DEVICE_GVE, PCI_VENDOR_GVE, QF_DQO_RDA, QF_GQI_QPL, QUEUE_FORMAT_DQO, QueueFormat,
    REG_DEVICE_STATUS, REG_MAX_RX_QUEUES, REG_MAX_TX_QUEUES, RSS_HASH_ALG_TOEPLITZ, RSS_HASH_TCPV4,
    RSS_HASH_TCPV6, RSS_HASH_UDPV4, RSS_HASH_UDPV6, RSS_KEY_SIZE, RSS_LUT_SIZE, RX_BUFFER_SIZE,
    RX_QUEUES, RX_RING_ENTRIES, RxQueue, STATE, State, TX_BIG_POOL_SLOTS, TX_QUEUES,
    TX_RING_ENTRIES, TX_SMALL_POOL_SLOTS, TxQueue, dqo, gqi, log_mac, log_u32, read_be16,
    read_be32, reg_read32, slice_at,
};

/// Probe the PCI bus for a gVNIC device. Returns `true` if one is
/// present and init was attempted successfully. Intended as the
/// first-choice NIC on GCE; callers fall back to virtio-net on
/// `false`.
pub(crate) fn init() -> bool {
    if GVNIC_OK.load(Ordering::Acquire) {
        return true;
    }

    // gvnic-not-present is the common case on every platform that
    // isn't GCE — silent miss; the higher-level boot doesn't print
    // a NIC line and the next driver in the registry gets a turn.
    let idx = match pci::find_device(PCI_VENDOR_GVE, PCI_DEVICE_GVE) {
        Some(i) => i,
        None => return false,
    };
    let dev = pci::pci_device(idx);

    // Enable bus master + memory space (bits 1 + 2 of Command). The
    // firmware on GCE's kernel-mode VM already programs BAR0, so we
    // only need to flip the enables.
    pci::enable_bus_mastering(dev.slot);
    // Memory Space enable (bit 1) isn't covered by enable_bus_mastering;
    // read Command and OR in 0x02. Do it via the 32-bit path since
    // GCE is x86_64.
    #[cfg(target_arch = "x86_64")]
    {
        let cmd = pci::read_config(dev.bus, dev.slot, dev.func, 0x04);
        pci::write_config(dev.bus, dev.slot, dev.func, 0x04, cmd | 0x06);
    }

    let bar_phys = pci::read_bar64(&dev, 0);
    if bar_phys == 0 {
        log(b"[gvnic] BAR0 is zero - firmware didn't assign it\n");
        return false;
    }
    let bar_virt = phys_to_virt(bar_phys) as u64;
    BAR0.store(bar_virt, Ordering::Release);

    // ── Read device advertising ──────────────────────────────────────────
    // dev_status / max_tx / max_rx are sanity reads only — values are
    // identical across every healthy GCE n2 boot and the per-queue
    // count we actually use lands in the `nic` line at end of init.
    let _dev_status = unsafe { reg_read32(REG_DEVICE_STATUS) };
    let max_tx = unsafe { reg_read32(REG_MAX_TX_QUEUES) };
    let max_rx = unsafe { reg_read32(REG_MAX_RX_QUEUES) };

    // ── Allocate admin queue (one contiguous 4 KiB page) ─────────────────
    //
    // Legacy PFN addressing: we hand the device `phys >> 12` in the
    // ADMINQ_PFN register, so the ring MUST start on a 4 KiB boundary
    // and be exactly one page. `alloc_pages(1)` satisfies both and
    // returns a physical address on both architectures.
    let adminq_phys = alloc_pages(1);
    if adminq_phys == 0 {
        log(b"[gvnic] failed to allocate admin queue page\n");
        return false;
    }
    let adminq_va = phys_to_virt(adminq_phys) as u64;
    unsafe {
        ptr::write_bytes(adminq_va as *mut u8, 0, adminq::ADMINQ_SIZE);
    }

    // Publish the ring PFN. `adminq_phys >> 12` is what the device
    // expects. Reading it back is how Linux / FreeBSD check the
    // device accepted it.
    if !adminq::init(adminq_va, adminq_phys) {
        return false;
    }

    {
        let mut st = STATE.lock();
        *st = Some(State {
            queue_format: None,
            mac: [0; 6],
            max_tx_queues: max_tx,
            max_rx_queues: max_rx,
            default_num_queues: 0,
            mtu: 0,
            num_event_counters: 0,
            max_tx_ring: 0,
            min_tx_ring: 0,
            max_rx_ring: 0,
            min_rx_ring: 0,
            num_qp: 0,
            tx: [const { None }; MAX_QUEUE_PAIRS],
            rx: [const { None }; MAX_QUEUE_PAIRS],
        });
    }

    // ── DESCRIBE_DEVICE ─────────────────────────────────────────────────
    if !describe_device() {
        log(b"[gvnic] DESCRIBE_DEVICE failed - aborting bring-up\n");
        return false;
    }

    // ── Queue bring-up ──────────────────────────────────────────────────
    //
    // Negotiated queue format — see `higher_priority`: we prefer
    // DQO_RDA on c3+ where it's offered, falling back to GQI_QPL on
    // n2/n2d/e2 (which only advertise GQI_QPL).
    let fmt = match STATE.lock().as_ref().and_then(|s| s.queue_format) {
        Some(f) => f,
        None => return false,
    };
    QUEUE_FORMAT_DQO.store(matches!(fmt, QueueFormat::DqoRda), Ordering::Release);

    let bar2_phys = pci::read_bar64(&dev, 2);
    if bar2_phys == 0 {
        log(b"[gvnic] BAR2 is zero - cannot reach per-queue doorbells\n");
        return false;
    }
    let bar2_va = phys_to_virt(bar2_phys) as u64;

    // Decide how many queue pairs to bring up. `default_num_queues`
    // is what GCE advertises for this machine type (2 on
    // n2-standard-2); `max_tx/rx_queues` is the hardware ceiling.
    // We cap at MAX_QUEUE_PAIRS because the diagnostic + net layer
    // APIs are sized to that constant.
    let (default_nq, max_tx, max_rx) = {
        let st = STATE.lock();
        let s = st.as_ref().unwrap();
        (
            s.default_num_queues as u32,
            s.max_tx_queues,
            s.max_rx_queues,
        )
    };
    let num_qp = default_nq
        .min(max_tx)
        .min(max_rx)
        .min(MAX_QUEUE_PAIRS as u32)
        .max(1);

    if !configure_device_resources(bar2_va, num_qp, fmt) {
        return false;
    }

    if !create_all_queues_batched(num_qp, fmt) {
        return false;
    }

    {
        let mut st = STATE.lock();
        if let Some(s) = st.as_mut() {
            s.num_qp = num_qp as u16;
        }
    }
    NUM_QP.store(num_qp as u16, Ordering::Release);

    post_initial_rx();
    // CONFIGURE_RSS already submitted into Phase B's batch by
    // `create_all_queues_batched` and verified with the others;
    // no separate admin-queue round-trip here.

    GVNIC_OK.store(true, Ordering::Release);
    log(b"[gvnic] ready (");
    log_u32(num_qp);
    log(b" queue pairs)\n");
    true
}

/// Returns true if `init()` has completed successfully.
pub(crate) fn probe_ok() -> bool {
    GVNIC_OK.load(Ordering::Acquire)
}

// ---- DESCRIBE_DEVICE implementation ---------------------------------------
//
// One admin-queue command, one response DMA page. Submit, poll the
// event counter, parse the device descriptor, walk its option list,
// and remember everything queue bring-up will need.

fn describe_device() -> bool {
    // Allocate a response page. The device writes the device
    // descriptor + option list into this buffer.
    let desc_phys = alloc_pages(1);
    if desc_phys == 0 {
        log(b"[gvnic] failed to allocate DESCRIBE_DEVICE response page\n");
        return false;
    }
    let desc_virt = phys_to_virt(desc_phys);
    unsafe {
        ptr::write_bytes(desc_virt, 0, 4096);
    }

    // Build the command. DESCRIBE_DEVICE payload (per `gve_adminq.h`):
    //   u8[8..16]  device_descriptor_addr (be64, physical)
    //   u8[16..20] device_descriptor_version (be32, = 1)
    //   u8[20..24] available_length (be32, = page size)
    let mut cmd = AdminqCommand::new(OP_DESCRIBE_DEVICE);
    cmd.put_be64(8, desc_phys);
    cmd.put_be32(16, DEVICE_DESCRIPTOR_VERSION);
    cmd.put_be32(20, adminq::ADMINQ_SIZE as u32);

    if !adminq::execute_cmd(b"DESCRIBE_DEVICE", &cmd) {
        return false;
    }

    parse_device_descriptor(desc_virt)
}

fn parse_device_descriptor(desc_virt: *mut u8) -> bool {
    // Device descriptor layout (40 bytes, all big-endian), per
    // Linux's `struct gve_device_descriptor` in `gve_adminq.h`:
    //
    //   u64 max_registered_pages   // offset  0
    //   u16 reserved1              //         8
    //   u16 tx_queue_entries       //        10
    //   u16 rx_queue_entries       //        12
    //   u16 default_num_queues     //        14
    //   u16 mtu                    //        16
    //   u16 counters               //        18
    //   u16 tx_pages_per_qpl       //        20
    //   u16 rx_pages_per_qpl       //        22
    //   u8[6] mac                  //        24
    //   u16 num_device_options     //        30
    //   u16 total_length           //        32
    //   u8[6] reserved3            //        34
    //
    // followed by `num_device_options` copies of `{ u16 id, u16 len,
    // u32 req_features }` plus a per-option payload of `len` bytes.

    let header_len = 40;
    let header: &[u8] = unsafe { core::slice::from_raw_parts(desc_virt, header_len) };

    let tx_entries = read_be16(header, 10);
    let rx_entries = read_be16(header, 12);
    let default_num_queues = read_be16(header, 14);
    let tx_pages_per_qpl = read_be16(header, 20);
    let mtu = read_be16(header, 16);
    let counters = read_be16(header, 18);
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&header[24..30]);
    let num_options = read_be16(header, 30);
    let total_len = read_be16(header, 32) as usize;

    // Walk the option list to negotiate the queue format. Preference
    // order matches Linux: DQO_RDA > DQO_QPL > GQI_RDA > GQI_QPL.
    // Log every option the device offers — the set varies between
    // n2/n2d/e2 (GQI_QPL only) and c3/c4 (GQI_QPL + DQO_RDA), and
    // future SKUs may add more. Visibility makes negotiation
    // mismatches diagnosable from serial alone.
    let mut best: Option<QueueFormat> = None;
    // MODIFY_RING bounds — left at 0 if the option isn't advertised
    // (no known GCE SKU omits it, but we don't want to assume).
    let mut max_tx_ring: u16 = 0;
    let mut min_tx_ring: u16 = 0;
    let mut max_rx_ring: u16 = 0;
    let mut min_rx_ring: u16 = 0;
    let mut offset = header_len;
    let end = if total_len > 0 && total_len <= adminq::ADMINQ_SIZE {
        total_len
    } else {
        adminq::ADMINQ_SIZE
    };
    for _ in 0..num_options {
        if offset + 8 > end {
            break;
        }
        let opt_hdr: &[u8] = unsafe { core::slice::from_raw_parts(desc_virt.add(offset), 8) };
        let id = read_be16(opt_hdr, 0);
        let len = read_be16(opt_hdr, 2) as usize;

        log(b"[gvnic]  option id=");
        log_u32(id as u32);
        log(b" len=");
        log_u32(len as u32);
        log(b"\n");

        let fmt = match id {
            OPT_ID_DQO_RDA => Some(QueueFormat::DqoRda),
            OPT_ID_GQI_QPL => Some(QueueFormat::GqiQpl),
            _ => None,
        };
        if let Some(new) = fmt {
            best = Some(match best {
                None => new,
                Some(cur) => higher_priority(cur, new),
            });
        }

        // MODIFY_RING payload (per `gve_device_option_modify_ring`):
        //   u32 supported_features_mask  // currently unused
        //   u16 max_rx_ring_size         // offset 4 of payload
        //   u16 max_tx_ring_size         // offset 6
        //   u16 min_rx_ring_size         // offset 8
        //   u16 min_tx_ring_size         // offset 10
        // All big-endian. Total 12 bytes — older firmware may
        // advertise only the first 8 (just the maxes), so we guard
        // on `len >= 12` before reading mins.
        if id == OPT_ID_MODIFY_RING && offset + 8 + len <= end && len >= 8 {
            let payload: &[u8] =
                unsafe { core::slice::from_raw_parts(desc_virt.add(offset + 8), len) };
            max_rx_ring = read_be16(payload, 4);
            max_tx_ring = read_be16(payload, 6);
            if len >= 12 {
                min_rx_ring = read_be16(payload, 8);
                min_tx_ring = read_be16(payload, 10);
            }
        }

        offset += 8 + len;
    }

    let fmt_name = match best {
        Some(f) => f.name(),
        None => {
            log(b"[gvnic] no known queue format advertised - incompatible device\n");
            return false;
        }
    };

    // One summary line covering everything an operator actually
    // wants to see at boot. Static device caps (counters, max regs,
    // entry sizes etc.) live in the source — only `mtu`, `qps`,
    // `mac`, and the negotiated format vary in practice.
    log(b"[gvnic] device ");
    log(fmt_name);
    log(b" mtu=");
    log_u32(mtu as u32);
    log(b" qps=");
    log_u32(default_num_queues as u32);
    // Device's advertised TX/RX ring sizes. Currently we use static
    // `TX_RING_ENTRIES = 256` / `RX_RING_ENTRIES = 512` regardless;
    // if these advertised numbers diverge (especially on a future
    // GCE SKU), the gap is visible here for a follow-up that
    // heap-allocates `TxQueue.slot_used` from the runtime value.
    log(b" tx_entries=");
    log_u32(tx_entries as u32);
    log(b" rx_entries=");
    log_u32(rx_entries as u32);
    log(b" tx_pages_per_qpl=");
    log_u32(tx_pages_per_qpl as u32);
    // MODIFY_RING bounds. Logged so a future ring-size experiment
    // can pick a runtime-valid value from this line alone. Zeros
    // mean the device didn't advertise the option.
    log(b" rx_ring=[");
    log_u32(min_rx_ring as u32);
    log(b"..");
    log_u32(max_rx_ring as u32);
    log(b"] tx_ring=[");
    log_u32(min_tx_ring as u32);
    log(b"..");
    log_u32(max_tx_ring as u32);
    log(b"] mac=");
    log_mac(&mac);
    log(b"\n");

    // The device advertises `tx_pages_per_qpl` as the MAXIMUM tx
    // pages per registered QPL. Linux packs many packets per page
    // via a FIFO (`tx_desc_cnt / GVE_QPL_DIVISOR = 4`). We
    // deliberately use `1 page per ring slot` (TX_QPL_PAGES = 256)
    // which exceeds the advertised cap on most GCE generations;
    // REGISTER_PAGE_LIST has accepted it on every SKU we've tested.
    // If a future device enforces the cap strictly, CREATE_TX_QUEUE
    // will fail and the log line above shows the gap.

    let mut st = STATE.lock();
    if let Some(s) = st.as_mut() {
        s.mac = mac;
        s.default_num_queues = default_num_queues;
        s.mtu = mtu;
        s.num_event_counters = counters;
        s.queue_format = best;
        s.max_tx_ring = max_tx_ring;
        s.min_tx_ring = min_tx_ring;
        s.max_rx_ring = max_rx_ring;
        s.min_rx_ring = min_rx_ring;
    }
    true
}

fn higher_priority(a: QueueFormat, b: QueueFormat) -> QueueFormat {
    // Linux's gve ranks DQO_RDA highest on c3+ — modern 32 B desc
    // shape, real Toeplitz RSS, better completion-ring layout.
    // n2/n2d/e2 only advertise GQI_QPL so they fall back naturally.
    use QueueFormat::{DqoRda, GqiQpl};
    match (a, b) {
        (DqoRda, _) | (_, DqoRda) => DqoRda,
        (GqiQpl, GqiQpl) => GqiQpl,
    }
}

// ---- Resource + queue bring-up --------------------------------------------

/// IRQ doorbell entry stride. The device treats each doorbell as a
/// cache-line-aligned `u32`, which on all our targets is 64 bytes.
const IRQ_DB_STRIDE: u32 = 64;

/// RX QPL size in pages. The reference driver allocates
/// `rx_desc_cnt` pages — one full page per ring entry, even though
/// each packet only uses the first 2 KiB of that page. Smaller
/// allocations are silently rejected by the device with
/// FAILED_PRECONDITION. `rx_pages_per_qpl = 1024` in the device
/// descriptor matches `rx_desc_cnt`, confirming this 1:1 sizing.
const RX_QPL_PAGES: u32 = RX_RING_ENTRIES as u32;

/// Total TX QPL backing pages — small pool + big pool's per-slot
/// footprint. Sized to fit one max-size TLS-1.3 record per big slot
/// plus L2/L3/L4 headers (see the constants in lib.rs for the full
/// argument).
const TX_QPL_PAGES: u32 = TX_SMALL_POOL_SLOTS + TX_BIG_POOL_SLOTS * crate::TX_BIG_SLOT_PAGES;

/// QPL IDs the driver assigns to itself. The spec just requires
/// uniqueness across live QPLs, so we pack TX ids into the low
/// half and RX ids above them. `tx_qpl_id(i)` = i, `rx_qpl_id(i)`
/// = MAX_QUEUE_PAIRS + i.
#[inline]
fn tx_qpl_id(qp: u32) -> u32 {
    qp
}
#[inline]
fn rx_qpl_id(qp: u32) -> u32 {
    qp + MAX_QUEUE_PAIRS as u32
}

/// Notification-block ids. TX queues claim the first `num_qp`
/// slots, RX queues the next `num_qp`. Matches the reference
/// driver's layout and avoids the "two queues can't share an
/// ntfy_id" rejection.
#[inline]
fn tx_ntfy_id(qp: u32) -> u32 {
    qp
}
#[inline]
fn rx_ntfy_id(num_qp: u32, qp: u32) -> u32 {
    num_qp + qp
}

fn configure_device_resources(bar2_va: u64, num_qp: u32, fmt: QueueFormat) -> bool {
    // Pull the device-advertised counter count out of state. This is
    // the value we must match — Linux passes this straight through
    // to the admin-queue command. Hardcoding a number here once
    // caused the device to reject the command with INVALID_ARGUMENT.
    let num_event_counters = {
        let st = STATE.lock();
        st.as_ref().map(|s| s.num_event_counters).unwrap_or(0)
    } as u32;
    if num_event_counters == 0 {
        log(b"[gvnic] device advertised zero event counters\n");
        return false;
    }

    // Allocate counter array + irq-db array. Both live for the
    // lifetime of the driver; we never unregister them.
    let counter_phys = alloc_pages(1);
    if counter_phys == 0 {
        log(b"[gvnic] failed to alloc counter array\n");
        return false;
    }
    let counter_va = phys_to_virt(counter_phys) as u64;
    unsafe {
        ptr::write_bytes(counter_va as *mut u8, 0, PAGE_SIZE as usize);
    }

    // IRQ-db array: one entry per notification block. Each entry is
    // IRQ_DB_STRIDE bytes (a full cache line) to avoid false sharing
    // between the device's writes. Size at 2 × 64 = 128 B; rounds
    // up to one page.
    let irq_db_phys = alloc_pages(1);
    if irq_db_phys == 0 {
        log(b"[gvnic] failed to alloc irq-db array\n");
        return false;
    }
    let irq_db_va = phys_to_virt(irq_db_phys) as u64;
    unsafe {
        ptr::write_bytes(irq_db_va as *mut u8, 0, PAGE_SIZE as usize);
    }

    // Build CONFIGURE_DEVICE_RESOURCES. Payload layout (40 bytes
    // at offset 8 of the command):
    //
    //   u64  counter_array (be, DMA)
    //   u64  irq_db_addr   (be, DMA)
    //   u32  num_counters  (be)
    //   u32  num_irq_dbs   (be)
    //   u32  irq_db_stride (be, 64 for our cache-line layout)
    //   u32  ntfy_blk_msix_base_idx (be, = 0 when we don't use MSI-X)
    //   u8   queue_format
    //   u8[7] padding
    let mut cmd = AdminqCommand::new(OP_CONFIGURE_DEVICE_RESOURCES);
    cmd.put_be64(8, counter_phys);
    cmd.put_be64(16, irq_db_phys);
    cmd.put_be32(24, num_event_counters);
    // num_irq_dbs = one notification block per active queue.
    // `num_qp * 2` covers both TX and RX queue pairs. Linux derives
    // this from the MSI-X count; we poll-only but the device still
    // wants a valid count here matching what the CREATE_*_QUEUE
    // ntfy_ids will reference.
    cmd.put_be32(28, num_qp * 2);
    cmd.put_be32(32, IRQ_DB_STRIDE);
    cmd.put_be32(36, 0);
    cmd.set_byte(
        40,
        match fmt {
            QueueFormat::GqiQpl => QF_GQI_QPL,
            QueueFormat::DqoRda => QF_DQO_RDA,
        },
    );

    if !adminq::execute_cmd(b"CONFIGURE_DEVICE_RESOURCES", &cmd) {
        return false;
    }

    // Publish for the lock-free hot path. These values are read by
    // `send_on_qp` / `tx_drain_qp` on every packet; going through
    // `STATE.lock()` on a shared spinlock would serialise all TX
    // across cores.
    BAR2_VA.store(bar2_va, Ordering::Release);
    COUNTER_ARRAY_VA.store(counter_va, Ordering::Release);
    // The device populated the irq-db array during the command above
    // (one BAR2 IRQ-doorbell index per notification block). Publish its
    // VA so `irq::enable_irq` can read those indices back when wiring
    // MSI-X for wake-on-packet idle (T7). Kept even in polling-only
    // boots — `enable_irq` is a no-op cost when MSI-X can't be set up.
    crate::IRQ_DB_VA.store(irq_db_va, Ordering::Release);
    log(b"[gvnic] device resources configured\n");
    true
}

/// Build a REGISTER_PAGE_LIST command for `num_pages` physically-
/// contiguous pages starting at `base_phys`, identified by
/// `page_list_id`. Allocates the per-page DMA address list (8 bytes
/// per page, in its own page-aligned DMA-coherent buffer) and fills
/// it with big-endian page addresses. Returns the command ready to
/// submit (sync via `execute_cmd` or batched via `submit_no_wait`),
/// or None if the address-list allocation failed.
fn build_register_page_list_cmd(
    page_list_id: u32,
    base_phys: u64,
    num_pages: u32,
) -> Option<AdminqCommand> {
    // The device wants an array of per-page DMA addresses (be64
    // each) in a separate DMA-coherent buffer. 8 bytes per page,
    // rounded up. A 1024-page RX QPL needs 2 pages here.
    let list_bytes = (num_pages as usize) * 8;
    let list_pages = list_bytes.div_ceil(PAGE_SIZE as usize);
    let page_addrs_phys = alloc_pages(list_pages);
    if page_addrs_phys == 0 {
        log(b"[gvnic] failed to alloc page-address list\n");
        return None;
    }
    let page_addrs_va = phys_to_virt(page_addrs_phys);
    unsafe {
        ptr::write_bytes(page_addrs_va, 0, list_pages * PAGE_SIZE as usize);
    }

    // Fill in the per-page addresses. The QPL is contiguous, so
    // the i-th page is at base_phys + i*4096.
    for i in 0..num_pages as usize {
        let page_addr = base_phys + (i as u64) * (PAGE_SIZE as u64);
        let buf = page_addr.to_be_bytes();
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), page_addrs_va.add(i * 8), 8);
        }
    }

    // Payload layout (24 bytes at offset 8):
    //   u32  page_list_id (be)
    //   u32  num_pages    (be)
    //   u64  page_address_list_addr (be, DMA)
    //   u64  page_size    (be, 4096)
    let mut cmd = AdminqCommand::new(OP_REGISTER_PAGE_LIST);
    cmd.put_be32(8, page_list_id);
    cmd.put_be32(12, num_pages);
    cmd.put_be64(16, page_addrs_phys);
    cmd.put_be64(24, PAGE_SIZE as u64);
    Some(cmd)
}

/// Issue CONFIGURE_RSS so the device hashes incoming flows across
/// the `num_qp` active queue pairs. We build a 128-entry
/// indirection table that cycles `qp = i % num_qp` and a static
/// 40-byte Toeplitz key (any bit-diverse constant works for
/// driver-controlled hashing; Microsoft's classic MS-DRSH test
/// key would be overkill for this use case).
///
/// Returns true on success. On failure we log and continue —
/// the driver still works with queue 0 handling all traffic.
/// Build a CONFIGURE_RSS command + its DMA-coherent backing
/// allocations (Toeplitz key + 128-entry indirection LUT). The
/// device processes admin commands in order, so this can be
/// queued in the same `kick_and_wait` batch as the CREATE_*_QUEUE
/// commands — the device sees CREATE_RX_QUEUE × N first, then
/// reads the LUT pointing into queues that now exist. Saves ~3 ms
/// of separate-batch wait time.
///
/// Payload (24 bytes at offset 8):
///   u16 hash_types    (be)
///   u8  hash_alg      (1 = Toeplitz)
///   u8  reserved
///   u16 hash_key_size (be)
///   u16 hash_lut_size (be)
///   u64 hash_key_addr (be, DMA)
///   u64 hash_lut_addr (be, DMA)
fn build_configure_rss_cmd(num_qp: u32) -> Option<AdminqCommand> {
    // 40-byte Toeplitz RSS key.
    //
    // **Default: symmetric `0x6d5a` × 20.** A symmetric key gives
    // identical hashes for both directions of a 4-tuple, which
    // is what we want when one peer (the bench client, in
    // particular) holds a single source IP with many ephemeral
    // ports — the asymmetric MS key hashes those flows to a tiny
    // subset of qps because the source-port LSBs feed the hash
    // weakly. Concrete observation (2026-05-11): `static_1m_tls_max`
    // (16 conns from kvm-vm) with the MS key pinned ~all conns to
    // core 1, leaving cores 0/2/3 at 28-29% real idle and capping
    // throughput at 1.07 Gbps; the symmetric key spreads evenly.
    //
    // `--cfg=rss_key=microsoft` flips back to the asymmetric MS key
    // (every Linux/Windows NIC driver's default), useful only when
    // production traffic is *not* single-source-IP — e.g. real
    // Internet-facing serving with many distinct source IPs, where
    // the asymmetric key's anti-correlation properties win.
    //
    // Our first attempt used a synthetic key
    // (`i * 0x9E3779B1 >> 24`) which happened to hash ~99 % of
    // wrk's flows onto qp 0 on n2-highcpu-4 — kept as a
    // cautionary tale in this comment.
    #[cfg(not(rss_key = "microsoft"))]
    let key: [u8; RSS_KEY_SIZE] = [
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d,
        0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    ];
    #[cfg(rss_key = "microsoft")]
    let key: [u8; RSS_KEY_SIZE] = [
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f,
        0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
        0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    ];

    // LUT: 128 entries of be32 queue index. Cycle through the
    // active qps so 4-tuple hash distribution maps evenly.
    let mut lut_bytes = [0u8; RSS_LUT_SIZE * 4];
    for i in 0..RSS_LUT_SIZE {
        let q = (i as u32) % num_qp;
        lut_bytes[i * 4..i * 4 + 4].copy_from_slice(&q.to_be_bytes());
    }

    let key_phys = alloc_pages(1);
    let lut_phys = alloc_pages(1);
    if key_phys == 0 || lut_phys == 0 {
        log(b"[gvnic] RSS alloc failed\n");
        return None;
    }
    unsafe {
        let key_va = phys_to_virt(key_phys);
        ptr::copy_nonoverlapping(key.as_ptr(), key_va, RSS_KEY_SIZE);
        let lut_va = phys_to_virt(lut_phys);
        ptr::copy_nonoverlapping(lut_bytes.as_ptr(), lut_va, lut_bytes.len());
    }

    let mut cmd = AdminqCommand::new(OP_CONFIGURE_RSS);
    let hash_types = RSS_HASH_TCPV4 | RSS_HASH_TCPV6 | RSS_HASH_UDPV4 | RSS_HASH_UDPV6;
    cmd.put_be16(8, hash_types);
    cmd.set_byte(10, RSS_HASH_ALG_TOEPLITZ);
    cmd.put_be16(12, RSS_KEY_SIZE as u16);
    cmd.put_be16(14, RSS_LUT_SIZE as u16);
    cmd.put_be64(16, key_phys);
    cmd.put_be64(24, lut_phys);
    Some(cmd)
}

/// Allocate a contiguous physical region of `num_pages` 4 KiB pages.
/// Returns (phys, va). Both will be nonzero on success; logs + returns
/// (0, 0) on failure.
fn alloc_contig(num_pages: usize) -> (u64, u64) {
    let phys = alloc_pages(num_pages);
    if phys == 0 {
        return (0, 0);
    }
    let va = phys_to_virt(phys) as u64;
    unsafe {
        ptr::write_bytes(va as *mut u8, 0, num_pages * PAGE_SIZE as usize);
    }
    (phys, va)
}

// ---- Per-queue resource allocation ----------------------------------------
//
// Bring-up is split into "alloc resources" → "submit admin commands"
// → "wait once" → "finalize" so that all per-queue admin commands
// can be batched (Linux's `gve_adminq_kick_and_wait` pattern). The
// bottleneck on GCE is admin-queue device latency (~3 ms per command);
// 18 commands run sequentially is ~54 ms, batched into 2 phases is
// ~6 ms in the best case.

#[derive(Clone, Copy)]
struct TxAlloc {
    ring_phys: u64,
    ring_va: u64,
    qres_phys: u64,
    qres_va: u64,
    /// In GQI_QPL mode this is the QPL backing pages
    /// (TX_QPL_PAGES × 4 KiB). In DQO_RDA mode this is the TX
    /// bounce-buffer pool (DQO_TX_POOL_BUFS × RX_BUFFER_SIZE
    /// rounded up to pages); send() copies the packet here, the
    /// device DMA-reads it via the descriptor's `buf_addr`.
    qpl_phys: u64,
    qpl_va: u64,
    /// DQO_RDA only — TX completion ring backing
    /// (DQO_TX_COMPL_SIZE × ring_entries). 0 in GQI_QPL mode.
    tx_compl_phys: u64,
    tx_compl_va: u64,
}

#[derive(Clone, Copy)]
struct RxAlloc {
    compl_phys: u64,
    compl_va: u64,
    data_phys: u64,
    data_va: u64,
    qres_phys: u64,
    qres_va: u64,
    /// In GQI_QPL mode this is the QPL backing pages
    /// (RX_QPL_PAGES × 4 KiB) — the device DMA-writes packet
    /// payloads here. In DQO_RDA mode this is the RX buffer pool
    /// (DQO_RX_POOL_BUFS × RX_BUFFER_SIZE rounded up to pages); the
    /// driver posts each buffer's DMA addr to the buffer ring at
    /// `data_va` and the device returns the matching `buf_id` in
    /// the completion at `compl_va`.
    qpl_phys: u64,
    qpl_va: u64,
}

fn alloc_tx_resources(fmt: QueueFormat) -> Option<TxAlloc> {
    // TX descriptor ring: one page of 16-byte descriptors
    // (TX_RING_ENTRIES = 256). Same shape in both formats.
    let (ring_phys, ring_va) = alloc_contig(1);
    if ring_phys == 0 {
        log(b"[gvnic] failed to alloc TX ring\n");
        return None;
    }
    let (qres_phys, qres_va) = alloc_contig(1);
    if qres_phys == 0 {
        log(b"[gvnic] failed to alloc TX queue_resources\n");
        return None;
    }

    let (qpl_phys, qpl_va) = match fmt {
        QueueFormat::GqiQpl => {
            // Backing QPL pages — TX_QPL_PAGES contiguous 4 KiB.
            // The device DMA-reads packet payloads via QPL offsets.
            alloc_contig(TX_QPL_PAGES as usize)
        }
        QueueFormat::DqoRda => {
            // TX bounce-buffer pool: one packet buffer per ring slot
            // (standard sends copy/direct-fill here), followed by the
            // TSO big-segment pool (one ≈20 KiB slot per concurrent
            // super-segment) appended at `DQO_TX_BIG_POOL_OFFSET`. The
            // descriptors hand the device stable DMA addresses into
            // this region.
            let bytes = dqo::DQO_TX_POOL_BUFS * (RX_BUFFER_SIZE as u32)
                + dqo::DQO_TX_BIG_SLOTS * dqo::DQO_TX_BIG_SLOT_SIZE;
            let pages = bytes.div_ceil(PAGE_SIZE);
            alloc_contig(pages as usize)
        }
    };
    if qpl_phys == 0 {
        log(b"[gvnic] failed to alloc TX backing pages\n");
        return None;
    }

    let (tx_compl_phys, tx_compl_va) = match fmt {
        QueueFormat::DqoRda => {
            // TX completion ring — 8 bytes per entry, sized to
            // tx_compl_ring_size (use ring_entries for symmetry).
            let bytes = (TX_RING_ENTRIES as u32) * (dqo::DQO_TX_COMPL_SIZE as u32);
            let pages = bytes.div_ceil(PAGE_SIZE);
            let (p, v) = alloc_contig(pages as usize);
            if p == 0 {
                log(b"[gvnic] failed to alloc TX compl ring\n");
                return None;
            }
            (p, v)
        }
        _ => (0, 0),
    };

    Some(TxAlloc {
        ring_phys,
        ring_va,
        qres_phys,
        qres_va,
        qpl_phys,
        qpl_va,
        tx_compl_phys,
        tx_compl_va,
    })
}

fn alloc_rx_resources(fmt: QueueFormat) -> Option<RxAlloc> {
    // RX completion ring: GQI uses 64 B descriptors, DQO uses 32 B.
    let compl_desc_size: u32 = match fmt {
        QueueFormat::GqiQpl => 64,
        QueueFormat::DqoRda => dqo::DQO_RX_COMPL_SIZE as u32,
    };
    let compl_pages = ((RX_RING_ENTRIES as u32) * compl_desc_size).div_ceil(PAGE_SIZE);
    let (compl_phys, compl_va) = alloc_contig(compl_pages as usize);
    if compl_phys == 0 {
        log(b"[gvnic] failed to alloc RX completion ring\n");
        return None;
    }

    // RX data ring:
    //   GQI: 8-byte slot ring of QPL offsets.
    //   DQO: 32-byte buffer descriptors carrying buf_id + buf_addr.
    let data_desc_size: u32 = match fmt {
        QueueFormat::GqiQpl => 8,
        QueueFormat::DqoRda => dqo::DQO_RX_DESC_SIZE as u32,
    };
    let data_pages = ((RX_RING_ENTRIES as u32) * data_desc_size).div_ceil(PAGE_SIZE);
    let (data_phys, data_va) = alloc_contig(data_pages as usize);
    if data_phys == 0 {
        log(b"[gvnic] failed to alloc RX data ring\n");
        return None;
    }

    let (qres_phys, qres_va) = alloc_contig(1);
    if qres_phys == 0 {
        log(b"[gvnic] failed to alloc RX queue_resources\n");
        return None;
    }

    let (qpl_phys, qpl_va) = match fmt {
        QueueFormat::GqiQpl => alloc_contig(RX_QPL_PAGES as usize),
        QueueFormat::DqoRda => {
            // RX buffer pool: one 2 KiB packet buffer per pool slot.
            // The device DMA-writes received frames into these and
            // returns the matching buf_id in the completion.
            let bytes = dqo::DQO_RX_POOL_BUFS * (RX_BUFFER_SIZE as u32);
            let pages = bytes.div_ceil(PAGE_SIZE);
            alloc_contig(pages as usize)
        }
    };
    if qpl_phys == 0 {
        log(b"[gvnic] failed to alloc RX backing pages\n");
        return None;
    }

    if matches!(fmt, QueueFormat::GqiQpl) {
        // Pre-fill the GQI data-slot ring: slot `i` points at QPL
        // offset `i * PAGE_SIZE`. Each ring entry gets a whole 4 KiB
        // page even though packets only use the first 2 KiB — matches
        // the reference driver layout (rx_pages_per_qpl == rx_desc_cnt).
        for i in 0..RX_RING_ENTRIES as usize {
            let offset: u64 = (i as u64) * (PAGE_SIZE as u64);
            let bytes = offset.to_be_bytes();
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), (data_va as *mut u8).add(i * 8), 8);
            }
        }
    }
    // DQO data ring is populated lazily by post_initial_rx_for_qp_dqo
    // after CREATE_RX_QUEUE returns the db_offset (the buffer-ring
    // doorbell is what tells the device "buffers are available").

    Some(RxAlloc {
        compl_phys,
        compl_va,
        data_phys,
        data_va,
        qres_phys,
        qres_va,
        qpl_phys,
        qpl_va,
    })
}

/// CREATE_TX_QUEUE command builder. Payload layout (48 bytes at offset 8):
///   u32  queue_id
///   u32  reserved
///   u64  queue_resources_addr (be, DMA)
///   u64  tx_ring_addr (be, DMA)
///   u32  queue_page_list_id (be)        — GQI only; 0 in DQO_RDA
///   u32  ntfy_id (be)
///   u64  tx_comp_ring_addr               — DQO only; 0 in GQI
///   u16  tx_ring_size (be)
///   u16  tx_comp_ring_size (be)          — DQO only; 0 in GQI
///   u8[4] padding
fn build_create_tx_queue_cmd(qp: u32, alloc: &TxAlloc, fmt: QueueFormat) -> AdminqCommand {
    // Honor the device-advertised MODIFY_RING bounds. If the option
    // wasn't seen (`max_tx_ring == 0`) we skip the check rather than
    // refusing to bring up older devices that didn't advertise it.
    {
        let st = STATE.lock();
        if let Some(s) = st.as_ref()
            && s.max_tx_ring != 0
        {
            assert!(
                TX_RING_ENTRIES >= s.min_tx_ring && TX_RING_ENTRIES <= s.max_tx_ring,
                "TX_RING_ENTRIES out of MODIFY_RING bounds"
            );
        }
    }
    let mut cmd = AdminqCommand::new(OP_CREATE_TX_QUEUE);
    cmd.put_be32(8, qp);
    cmd.put_be64(16, alloc.qres_phys);
    cmd.put_be64(24, alloc.ring_phys);
    cmd.put_be32(
        32,
        match fmt {
            QueueFormat::GqiQpl => tx_qpl_id(qp),
            QueueFormat::DqoRda => GVE_RAW_ADDRESSING_QPL_ID,
        },
    );
    cmd.put_be32(36, tx_ntfy_id(qp));
    if matches!(fmt, QueueFormat::DqoRda) {
        cmd.put_be64(40, alloc.tx_compl_phys);
    }
    cmd.put_be16(48, TX_RING_ENTRIES);
    if matches!(fmt, QueueFormat::DqoRda) {
        cmd.put_be16(50, TX_RING_ENTRIES);
    }
    cmd
}

/// CREATE_RX_QUEUE command builder. Payload (56 bytes at offset 8):
///   u32  queue_id
///   u32  index
///   u32  reserved
///   u32  ntfy_id
///   u64  queue_resources_addr (DMA)
///   u64  rx_desc_ring_addr (DMA — completion ring; 64 B desc on GQI, 32 B on DQO)
///   u64  rx_data_ring_addr (DMA — slot ring on GQI, buffer ring on DQO)
///   u32  queue_page_list_id              — GQI only; 0 in DQO_RDA
///   u16  rx_ring_size
///   u16  packet_buffer_size
///   u16  rx_buff_ring_size               — DQO only; 0 in GQI   (off 56)
///   u8   enable_rsc                       — DQO HW-GRO          (off 58)
///   u8   padding1                                              (off 59)
///   u16  header_buffer_size              — 0 = header-split OFF (off 60)
///   u8[2] padding2                                             (off 62)
///
/// Layout verified byte-for-byte against upstream
/// `struct gve_adminq_create_rx_queue` (56-byte body; our +8 header).
/// We leave `header_buffer_size = 0`: RSC does NOT require header-split
/// (upstream: "HW-GRO packets have complete TCP/IP headers in frag[0]
/// when split is disabled"), and our multi-buf RX accumulator (item I)
/// reassembles the coalesced super-frame from frag[0] onward.
fn build_create_rx_queue_cmd(
    qp: u32,
    alloc: &RxAlloc,
    num_qp: u32,
    fmt: QueueFormat,
) -> AdminqCommand {
    {
        let st = STATE.lock();
        if let Some(s) = st.as_ref()
            && s.max_rx_ring != 0
        {
            assert!(
                RX_RING_ENTRIES >= s.min_rx_ring && RX_RING_ENTRIES <= s.max_rx_ring,
                "RX_RING_ENTRIES out of MODIFY_RING bounds"
            );
        }
    }
    let mut cmd = AdminqCommand::new(OP_CREATE_RX_QUEUE);
    cmd.put_be32(8, qp);
    // `index` field. Linux + FreeBSD set this only for GQI; for
    // DQO they leave it 0. We had it set unconditionally; the DQO
    // device may interpret a non-zero `index` differently from
    // `queue_id` and silently route packets oddly.
    if matches!(fmt, QueueFormat::GqiQpl) {
        cmd.put_be32(12, qp);
    }
    cmd.put_be32(20, rx_ntfy_id(num_qp, qp));
    cmd.put_be64(24, alloc.qres_phys);
    cmd.put_be64(32, alloc.compl_phys);
    cmd.put_be64(40, alloc.data_phys);
    cmd.put_be32(
        48,
        match fmt {
            QueueFormat::GqiQpl => rx_qpl_id(qp),
            QueueFormat::DqoRda => GVE_RAW_ADDRESSING_QPL_ID,
        },
    );
    cmd.put_be16(52, RX_RING_ENTRIES);
    cmd.put_be16(54, RX_BUFFER_SIZE);
    if matches!(fmt, QueueFormat::DqoRda) {
        cmd.put_be16(56, RX_RING_ENTRIES);
        // enable_rsc (T4 item J): DQO HW-GRO. The device coalesces
        // consecutive in-order TCP segments into multi-buffer
        // super-frames (EOP only on the last buffer), which our item-I
        // RX accumulator (`dqo::poll_qp_inner`) stitches into one chain.
        // The only create-queue field RSC needs; header-split stays off
        // (header_buffer_size at off 60 = 0). RSC is a receive/upload
        // throughput lever (fewer per-frame cycles on bulk RX); it does
        // not touch the serve/TX path.
        cmd.put_u8(58, 1);
    }
    cmd
}

/// Read the device's CREATE_TX_QUEUE response from the qres page and
/// install the resulting `TxQueue` into `STATE` + publish via
/// `TX_QUEUES`. Must run after the corresponding CREATE_TX_QUEUE
/// command has completed (i.e. after `kick_and_wait_to`). Format-
/// specific fields are zeroed for the inactive mode.
fn finalize_tx_queue(qp: u32, alloc: &TxAlloc, fmt: QueueFormat) {
    // gve_queue_resources: u32 db_index (be) + u32 counter_index (be).
    let db_index;
    let counter_index;
    unsafe {
        let bytes = slice_at(alloc.qres_va, 8);
        db_index = read_be32(bytes, 0);
        counter_index = read_be32(bytes, 4);
    }
    let mut st = STATE.lock();
    if let Some(s) = st.as_mut() {
        s.tx[qp as usize] = Some(TxQueue {
            ring_va: alloc.ring_va,
            ring_entries: TX_RING_ENTRIES,
            qpl_base_va: alloc.qpl_va,
            qpl_base_phys: alloc.qpl_phys,
            db_offset: db_index * 4,
            counter_index,
            fill_cnt: AtomicU32::new(0),
            done_cnt: AtomicU32::new(0),
            last_kicked: AtomicU32::new(0),
            stall_until: AtomicU64::new(0),
            stall_done_snap: AtomicU32::new(0),
            tx_compl_va: alloc.tx_compl_va,
            tx_compl_entries: match fmt {
                QueueFormat::DqoRda => TX_RING_ENTRIES,
                _ => 0,
            },
            tx_compl_head: AtomicU32::new(0),
            // Generation starts at 1: the device fills entries with
            // the current generation on each completion, then flips
            // each ring wrap. Ring is initially zeroed (gen=0), so we
            // expect the first entry to read with gen=1.
            tx_compl_gen: AtomicU8::new(1),
            // Initialise last_re_at_fill = -DQO_TX_RE_INTERVAL
            // (wrapping). With fill_cnt starting at 0, the first
            // submit's `interval = 0 - (-32) = 32` fires the
            // `>= 32` check and sets RE — so the device's
            // completion stream bootstraps on the first packet.
            last_re_at_fill: AtomicU32::new(0u32.wrapping_sub(dqo::DQO_TX_RE_INTERVAL)),
            small_slot_used: [const { AtomicBool::new(false) }; TX_SMALL_POOL_SLOTS as usize],
            big_slot_used: [const { AtomicBool::new(false) }; TX_BIG_POOL_SLOTS as usize],
        });
        // Publish a raw pointer to the TxQueue living inside State
        // so the hot path (`send_on_qp`) can reach it without
        // taking the STATE spinlock. State is only ever written
        // to once, so the Option's `Some` variant sits at a
        // stable address for the rest of the driver's life.
        let ptr = s.tx[qp as usize].as_ref().unwrap() as *const TxQueue as *mut TxQueue;
        TX_QUEUES[qp as usize].store(ptr, Ordering::Release);
    }
}

fn finalize_rx_queue(qp: u32, alloc: &RxAlloc, fmt: QueueFormat) {
    let db_index;
    unsafe {
        let bytes = slice_at(alloc.qres_va, 8);
        db_index = read_be32(bytes, 0);
        // counter_index at offset 4 — RX doesn't use it (we never
        // read the device's RX counter slot).
    }
    // GQI uses flags_seq starting at 1; DQO uses generation bit
    // starting at 1 (ring is zeroed, device fills with current gen,
    // flips each wrap).
    let initial_seq: u8 = 1;
    // GQI's RX poll copies each frame into a recycle-pool slab —
    // it can't lend device QPL pages up the stack. DQO lends its
    // device buffers directly (no pool). Build the pool before
    // taking `STATE` so the 512 KiB slab-region allocation +
    // zero-fill doesn't run under the spinlock.
    let rx_pool = match fmt {
        QueueFormat::GqiQpl => Some(IOBufPool::new(
            gqi::GQI_RX_POOL_SLABS,
            gqi::GQI_RX_SLAB_SIZE,
        )),
        QueueFormat::DqoRda => None,
    };
    let mut st = STATE.lock();
    if let Some(s) = st.as_mut() {
        s.rx[qp as usize] = Some(RxQueue {
            compl_va: alloc.compl_va,
            data_va: alloc.data_va,
            ring_entries: RX_RING_ENTRIES,
            qpl_base_va: alloc.qpl_va,
            qpl_base_phys: alloc.qpl_phys,
            db_offset: db_index * 4,
            fill_cnt: AtomicU32::new(0),
            cons_cnt: AtomicU32::new(0),
            expected_seq: AtomicU8::new(initial_seq),
            rx_pool,
        });
        let ptr = s.rx[qp as usize].as_ref().unwrap() as *const RxQueue as *mut RxQueue;
        RX_QUEUES[qp as usize].store(ptr, Ordering::Release);
    }
}

/// Bring up all `num_qp` queue pairs in two batched admin-queue
/// phases: REGISTER_PAGE_LIST × 2*num_qp, then CREATE_*_QUEUE
/// × 2*num_qp. Each phase doorbells once and waits once. On a
/// device that pipelines admin commands this collapses ~16 sync
/// waits (~3 ms each on GCE) into 2.
fn create_all_queues_batched(num_qp: u32, fmt: QueueFormat) -> bool {
    let n = num_qp as usize;
    if n == 0 || n > MAX_QUEUE_PAIRS {
        return false;
    }

    // Phase 0: allocate all per-queue local resources (no admin
    // commands). Order doesn't matter; do TX then RX.
    let mut tx_allocs: [Option<TxAlloc>; MAX_QUEUE_PAIRS] = [None; MAX_QUEUE_PAIRS];
    let mut rx_allocs: [Option<RxAlloc>; MAX_QUEUE_PAIRS] = [None; MAX_QUEUE_PAIRS];
    for slot in tx_allocs.iter_mut().take(n) {
        *slot = alloc_tx_resources(fmt);
        if slot.is_none() {
            return false;
        }
    }
    for slot in rx_allocs.iter_mut().take(n) {
        *slot = alloc_rx_resources(fmt);
        if slot.is_none() {
            return false;
        }
    }

    let mut last_prod = 0u32;

    // Phase A: REGISTER_PAGE_LIST × 2n (TX then RX), batched. Only
    // needed in GQI_QPL mode — DQO_RDA descriptors carry raw DMA
    // addresses so there are no QPLs to register, and we skip the
    // entire phase (~5 ms wait).
    if matches!(fmt, QueueFormat::GqiQpl) {
        let mut tx_rpl_slots = [0usize; MAX_QUEUE_PAIRS];
        let mut rx_rpl_slots = [0usize; MAX_QUEUE_PAIRS];
        for qp in 0..n {
            let alloc = tx_allocs[qp].as_ref().unwrap();
            let cmd = match build_register_page_list_cmd(
                tx_qpl_id(qp as u32),
                alloc.qpl_phys,
                TX_QPL_PAGES,
            ) {
                Some(c) => c,
                None => return false,
            };
            match adminq::submit_no_wait(&cmd) {
                Some((slot, prod)) => {
                    tx_rpl_slots[qp] = slot;
                    last_prod = prod;
                }
                None => return false,
            }
        }
        for qp in 0..n {
            let alloc = rx_allocs[qp].as_ref().unwrap();
            let cmd = match build_register_page_list_cmd(
                rx_qpl_id(qp as u32),
                alloc.qpl_phys,
                RX_QPL_PAGES,
            ) {
                Some(c) => c,
                None => return false,
            };
            match adminq::submit_no_wait(&cmd) {
                Some((slot, prod)) => {
                    rx_rpl_slots[qp] = slot;
                    last_prod = prod;
                }
                None => return false,
            }
        }
        if !adminq::kick_and_wait_to(last_prod) {
            return false;
        }
        for qp in 0..n {
            if !adminq::check_slot_status(tx_rpl_slots[qp], b"REGISTER_PAGE_LIST tx") {
                return false;
            }
            if !adminq::check_slot_status(rx_rpl_slots[qp], b"REGISTER_PAGE_LIST rx") {
                return false;
            }
        }
    }

    // Phase B: CREATE_*_QUEUE × 2n (TX then RX) + CONFIGURE_RSS,
    // batched. The qres page contents are device-written, so
    // finalize must run after the wait completes. CONFIGURE_RSS
    // goes last in the batch so it processes after all the
    // CREATE_RX_QUEUE commands that its LUT references.
    let mut tx_create_slots = [0usize; MAX_QUEUE_PAIRS];
    let mut rx_create_slots = [0usize; MAX_QUEUE_PAIRS];
    for qp in 0..n {
        let cmd = build_create_tx_queue_cmd(qp as u32, tx_allocs[qp].as_ref().unwrap(), fmt);
        match adminq::submit_no_wait(&cmd) {
            Some((slot, prod)) => {
                tx_create_slots[qp] = slot;
                last_prod = prod;
            }
            None => return false,
        }
    }
    for qp in 0..n {
        let cmd =
            build_create_rx_queue_cmd(qp as u32, rx_allocs[qp].as_ref().unwrap(), num_qp, fmt);
        match adminq::submit_no_wait(&cmd) {
            Some((slot, prod)) => {
                rx_create_slots[qp] = slot;
                last_prod = prod;
            }
            None => return false,
        }
    }
    let rss_slot = if num_qp > 1 {
        let cmd = match build_configure_rss_cmd(num_qp) {
            Some(c) => c,
            None => return false,
        };
        match adminq::submit_no_wait(&cmd) {
            Some((slot, prod)) => {
                last_prod = prod;
                Some(slot)
            }
            None => return false,
        }
    } else {
        None
    };
    if !adminq::kick_and_wait_to(last_prod) {
        return false;
    }
    for qp in 0..n {
        if !adminq::check_slot_status(tx_create_slots[qp], b"CREATE_TX_QUEUE") {
            return false;
        }
        finalize_tx_queue(qp as u32, tx_allocs[qp].as_ref().unwrap(), fmt);
    }
    for qp in 0..n {
        if !adminq::check_slot_status(rx_create_slots[qp], b"CREATE_RX_QUEUE") {
            return false;
        }
        finalize_rx_queue(qp as u32, rx_allocs[qp].as_ref().unwrap(), fmt);
    }
    if let Some(slot) = rss_slot {
        // RSS failure is non-fatal — log and fall through to qp 0
        // single-queue delivery, matching the previous behaviour.
        if !adminq::check_slot_status(slot, b"CONFIGURE_RSS") {
            log(b"[gvnic] RSS not configured (falling back to single-queue delivery)\n");
        }
    }

    true
}

fn post_initial_rx() {
    // After CREATE_RX_QUEUE the data ring needs a doorbell so the
    // device starts using the posted buffers/slots. GQI: data-slot
    // ring is already pre-filled with QPL offsets; write the full
    // ring count to the doorbell. DQO: write 32-byte buffer
    // descriptors carrying buf_id+buf_addr, then doorbell.
    let is_dqo = QUEUE_FORMAT_DQO.load(Ordering::Acquire);
    let bar2_va = BAR2_VA.load(Ordering::Acquire);
    for rx_slot in RX_QUEUES.iter() {
        let rx_ptr = rx_slot.load(Ordering::Acquire);
        if rx_ptr.is_null() {
            continue;
        }
        // SAFETY: pointer published with Release, only null means
        // "not installed". RxQueue's non-atomic fields are only
        // written during init (before this Release); reading them
        // here through Acquire is a valid synchronisation.
        let rx = unsafe { &*rx_ptr };
        if is_dqo {
            dqo::post_initial_rx_for_qp(rx);
        } else {
            let fill = rx.ring_entries as u32;
            rx.fill_cnt.store(fill, Ordering::Release);
            gqi::doorbell_write(bar2_va, rx.db_offset, fill);
        }
    }
    log(b"[gvnic] posted initial RX buffers\n");
}
