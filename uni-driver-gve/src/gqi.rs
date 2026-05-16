// GQI_QPL datapath — original gVNIC queue format used on
// n2 / n2d / e2 (and also offered on c3 / c4, but DQO_RDA is
// preferred there). Outbound packets are memcpy'd into a
// pre-registered Queue Page List; the descriptor carries an
// offset into the QPL (not a DMA address). RX is similarly
// QPL-backed.
//
// The TX side runs a two-pool zero-copy direct-fill allocator:
// small slots (1 × 4 KiB page each) hold one std packet; big
// slots (4 × 4 KiB pages each) hold one TSO super-segment.
// Drain reads the device-written completion counter and frees
// completed slots from descriptor seg_addrs.
//
// Wire format: every multi-byte field is big-endian (matches
// Linux's `iowrite32be` doorbell convention; opposite of DQO).

use core::ptr;
use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

use drivers_infra::mmio_write32;
use uni_iobuf::{Chain, OwnedIOBuf};

use crate::{
    put_be16, put_be64, read_be16, record_tx_desc, tx_desc_kind, BAR2_VA,
    COUNTER_ARRAY_VA, DEFERRED_KICK, GQI_RECYCLE_POOL_EXHAUSTED, MAX_QUEUE_PAIRS,
    PAGE_SIZE, RX_BUF_REPOST_COUNT, RX_BYTES_PER_QP, RX_QUEUES, TX_BIG_ACQUIRES,
    TX_BIG_FULL_RETURNS, TX_BIG_POOL_QPL_OFFSET, TX_BIG_POOL_SLOTS, TX_BIG_SLOT_SIZE,
    TX_BYTES_PER_QP, TX_PACKETS_PER_QP, TX_QUEUES, TX_SMALL_ACQUIRES,
    TX_SMALL_FULL_SPINS, TX_SMALL_POOL_SLOTS, TX_SMALL_SCAN_ITERS, TxQueue, _GVE_RX_PAD,
};

// ---- RX recycle pool sizing ------------------------------------------------

/// Per-queue-pair recycle-pool slab size. GQI cannot lend a device
/// QPL page up the stack (the device reposts RX buffers strictly
/// in order, so the page must be returned the moment the frame is
/// copied out), so each received frame is copied into one of these
/// slabs. 2 KiB covers a standard 1500-byte MTU frame plus Ethernet
/// and alignment slack — matches `RX_BUFFER_SIZE`.
pub(crate) const GQI_RX_SLAB_SIZE: usize = 2048;

/// Per-queue-pair recycle-pool depth. Sized well above `MAX_BATCH`
/// (64 frames per poll) and the Tier-2 cross-core inbox depth so a
/// transiently slow consumer doesn't exhaust the pool; on
/// exhaustion the frame is dropped and `GQI_RECYCLE_POOL_EXHAUSTED`
/// counts it (TCP retransmit / UDP retry recover the loss).
pub(crate) const GQI_RX_POOL_SLABS: usize = 256;

// ---- GQI descriptor type/flag constants (gve_desc.h) ----------------------
//
// `type_flags` byte layout: low 4 bits = type, upper 4 bits = flags
// for STD/TSO; for SEG the upper bit (GVE_TXSF_IPV6) is the only
// flag we care about.
const GVE_TXD_STD: u8 = 0x0 << 4;     // 0x00 — std packet (single-seg or first of multi-seg non-TSO)
const GVE_TXD_TSO: u8 = 0x1 << 4;     // 0x10 — TSO header desc (first desc of a TSO super-segment)
const GVE_TXD_SEG: u8 = 0x2 << 4;     // 0x20 — segment desc (TSO continuation)
const GVE_TXF_L4CSUM: u8 = 1 << 0;    // device computes L4 csum
const GVE_TXSF_IPV6: u8 = 1 << 1;     // TSO is over IPv6 (vs v4)

// ---- RX completion descriptor layout (gve_desc.h, big-endian) -------------

/// RSS hash layout in the GQI_RX completion descriptor is the last
/// 64 bytes worth of the 64-byte descriptor. Offsets within it:
///
///   u8[0..48]   padding (device implementation detail)
///   u8[48..52]  rss_hash (be32)
///   u8[52..54]  mss (be16)
///   u8[54..56]  reserved
///   u8[56]      hdr_len
///   u8[57]      hdr_off (64-byte-scaled)
///   u8[58..60]  csum (host-endian per the reference driver)
///   u8[60..62]  len (be16)
///   u8[62..64]  flags_seq (be16)
///
/// Only `len` and `flags_seq` are needed by this driver — csum +
/// hash are hints for the stack and can be ignored here.
const RX_DESC_SIZE: usize = 64;
const RX_DESC_LEN_OFF: usize = 60;
const RX_DESC_FLAGS_SEQ_OFF: usize = 62;

/// Start-of-frame offset inside each 4 KiB RX page. The device
/// prepends `_GVE_RX_PAD = 2` bytes of padding before the Ethernet
/// header so IPv4 header bytes land 4-byte aligned. The *actual*
/// offset the device writes into `hdr_off` is scaled by 64 — with
/// one packet per page there's only one valid value
/// (hdr_off = 0, actual start = `_GVE_RX_PAD`).
const RX_DATA_OFFSET_IN_PAGE: usize = _GVE_RX_PAD as usize;

/// TX descriptor size (gve_tx_pkt_desc, packed, 16 bytes).
const TX_DESC_SIZE: usize = 16;

/// Highest packet length we're willing to stage at once. Matches
/// the device-advertised MTU + Ethernet + safety slack; see
/// `send()` below for the actual check.
const TX_MAX_PKT_LEN: usize = 2048;

/// Highest TSO super-segment length we accept. A big-pool slot is
/// 5 contiguous 4 KiB pages; we leave ~256 bytes of headroom over
/// the Linux 16 KiB max-segment guidance for safety. The TCP layer
/// will only build super-segments up to its own configured cap.
const TX_MAX_TSO_LEN: usize = TX_BIG_SLOT_SIZE as usize - 256;

const POOL_ID_SMALL: u8 = 0;
const POOL_ID_BIG: u8 = 1;

// ---- Doorbell ---------------------------------------------------------------

/// GQI doorbell write. Big-endian on the wire — Linux's
/// `gve_*_write_doorbell` use `iowrite32be`. Opposite of DQO.
///
/// Includes `host_dma_fence()` (an `sfence` on x86) — every GQI
/// doorbell write here signals the device to DMA-read host
/// memory (descriptors or replenished RX QPL offsets), so the
/// fence is always required. See `host_dma_fence` for the full
/// story.
#[inline]
pub(crate) fn doorbell_write(bar2_va: u64, offset: u32, value: u32) {
    crate::host_dma_fence();
    unsafe {
        mmio_write32(bar2_va + offset as u64, value.to_be());
    }
}

// ---- Token encoding for direct-fill TX slots ------------------------------

/// Encode `(qp, slot, pool_id)` into the opaque `driver_token` of
/// a [`uni_net_driver::TxBufHandle`]. Layout:
///   * bit  63    : pool_id (0 = small, 1 = big)
///   * bits 32..62: qp index
///   * bits  0..32: slot index (within the pool)
#[inline]
fn encode_token(qp: usize, slot: usize, pool: u8) -> u64 {
    let pool_bit = ((pool & 1) as u64) << 63;
    pool_bit | (((qp as u64) & 0x7FFF_FFFF) << 32) | (slot as u64 & 0xFFFF_FFFF)
}

#[inline]
fn decode_token(token: u64) -> (usize, usize, u8) {
    let pool = ((token >> 63) & 1) as u8;
    let qp = ((token >> 32) & 0x7FFF_FFFF) as usize;
    let slot = (token & 0xFFFF_FFFF) as usize;
    (qp, slot, pool)
}

/// Drop callback for an unsubmitted handle: returns the slot to
/// the right pool. `submit_tx_inner` / `submit_tx_tso_inner`
/// mem-forget the handle on the success leg.
fn release_tx_slot(token: u64) {
    let (qp, slot, pool) = decode_token(token);
    if qp >= MAX_QUEUE_PAIRS { return; }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return; }
    let tx = unsafe { &*tx_ptr };
    match pool {
        POOL_ID_BIG if slot < TX_BIG_POOL_SLOTS as usize => {
            tx.big_slot_used[slot].store(false, Ordering::Release);
        }
        _ if slot < TX_SMALL_POOL_SLOTS as usize => {
            tx.small_slot_used[slot].store(false, Ordering::Release);
        }
        _ => {}
    }
}

// ---- TX completion drain ---------------------------------------------------

/// Reclaim TX slots on `qp` from the device's completion counter.
/// Lock-free fast path — reads TxQueue via the pre-published
/// pointer + device counter via an atomic. For each completed
/// descriptor in the range `[done_cnt, nic_done)`, reads the
/// descriptor's type byte + `seg_addr` to recover the pool +
/// slot index and marks the slot free.
///
/// Three GQI descriptor types end up in our ring (`gve_desc.h`
/// type field, low 4 bits of `type_flags`):
///   * `GVE_TXD_STD` (0x00) — single-segment packet; one desc
///     references one small-pool page. Free `small_slot_used`.
///   * `GVE_TXD_TSO` (0x10) — first desc of a TSO super-segment;
///     references the header bytes at the start of a big-pool
///     slot. Free `big_slot_used`.
///   * `GVE_TXD_SEG` (0x20) — continuation desc of a TSO; its
///     `seg_addr` is mid-big-slot (header + offset). Skip — the
///     paired TSO desc already freed the slot.
#[inline]
pub(crate) fn tx_drain(tx: &TxQueue) {
    let counter_va = COUNTER_ARRAY_VA.load(Ordering::Acquire);
    if counter_va == 0 { return; }
    let counter_ptr = counter_va as *const u32;
    let raw = unsafe { ptr::read_volatile(counter_ptr.add(tx.counter_index as usize)) };
    let nic_done = u32::from_be(raw);
    let prev = tx.done_cnt.load(Ordering::Relaxed);
    if nic_done == prev { return; }

    // Walk completed descriptors and free their slots.
    let mask = (tx.ring_entries - 1) as u32;
    let mut k = prev;
    while k != nic_done {
        let ring_idx = (k & mask) as usize;
        let desc_ptr = (tx.ring_va as *const u8).wrapping_add(ring_idx * TX_DESC_SIZE);
        // SAFETY: ring_va is a registered DMA-mapped page; idx is in
        // bounds via `& mask`; descriptor is 16 bytes wide.
        let type_flags = unsafe { ptr::read_volatile(desc_ptr) };
        let dtype = type_flags & 0xF0; // upper nibble = type
        // gve_tx_pkt_desc / gve_tx_seg_desc: seg_addr at offset 8,
        // big-endian u64.
        let seg_addr_be = unsafe {
            ptr::read_unaligned(desc_ptr.add(8) as *const u64)
        };
        let seg_addr = u64::from_be(seg_addr_be);
        match dtype {
            GVE_TXD_TSO => {
                // First desc of a TSO packet — header lives at the
                // start of a big-pool slot, so subtract the pool
                // base and divide by big-slot size.
                if seg_addr >= TX_BIG_POOL_QPL_OFFSET as u64 {
                    let off = seg_addr - TX_BIG_POOL_QPL_OFFSET as u64;
                    let big_slot = (off / TX_BIG_SLOT_SIZE as u64) as usize;
                    if big_slot < TX_BIG_POOL_SLOTS as usize {
                        tx.big_slot_used[big_slot].store(false, Ordering::Release);
                    }
                }
            }
            GVE_TXD_SEG => {
                // Continuation desc of a TSO — paired TSO desc
                // already freed the slot. Skip.
            }
            _ /* GVE_TXD_STD = 0x00, plus any unexpected type */ => {
                let slot = (seg_addr / PAGE_SIZE as u64) as usize;
                if slot < TX_SMALL_POOL_SLOTS as usize {
                    tx.small_slot_used[slot].store(false, Ordering::Release);
                }
            }
        }
        k = k.wrapping_add(1);
    }
    tx.done_cnt.store(nic_done, Ordering::Relaxed);
}

// ---- TX direct-fill: acquire ----------------------------------------------

/// Slice-shaped wrapper over the direct-fill path: acquire a slot
/// from the QP's pool, memcpy data into it, submit. Used by `send`
/// (the per-core dispatcher) when GQI is the negotiated format.
pub(crate) fn send_on_qp(qp: usize, data: &[u8]) -> bool {
    if data.is_empty() || data.len() > TX_MAX_PKT_LEN {
        return false;
    }
    let mut handle = match acquire_tx_buf_for_qp(qp) {
        Some(h) => h,
        None => return false,
    };
    let n = data.len();
    handle.data_mut()[..n].copy_from_slice(data);
    submit_tx_inner(handle, n, uni_net_driver::CsumOffload::NONE);
    true
}

/// Acquire a small-pool TX slot for a specific qp. Used by
/// `send_on_qp` (which has already picked the qp by core or
/// fallback) and by the public `acquire_tx_buf` (which picks the
/// worker's qp). Spin-drains on full pool — the caller is the qp's
/// owning worker (Tier 1) so this is cooperative scheduling, not
/// deadlock-prone.
pub(crate) fn acquire_tx_buf_for_qp(qp: usize) -> Option<uni_net_driver::TxBufHandle> {
    if qp >= MAX_QUEUE_PAIRS { return None; }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return None; }
    let tx = unsafe { &*tx_ptr };

    let mut local_iters: u64 = 0;
    loop {
        // Need both: a free slot in the pool AND ring-fill capacity
        // (fill_cnt - done_cnt < ring_entries). Drain first so the
        // small pool reflects the latest device-completed work.
        tx_drain(tx);
        let fill = tx.fill_cnt.load(Ordering::Relaxed);
        let done = tx.done_cnt.load(Ordering::Relaxed);
        if fill.wrapping_sub(done) < tx.ring_entries as u32 {
            for slot in 0..(TX_SMALL_POOL_SLOTS as usize) {
                local_iters += 1;
                if !tx.small_slot_used[slot].load(Ordering::Acquire) {
                    tx.small_slot_used[slot].store(true, Ordering::Relaxed);
                    // Diag: record cumulative scan-iters + acquire
                    // count so the reader can compute the average
                    // scan depth. Single relaxed atomic each — off
                    // the per-packet hot path's critical chain.
                    TX_SMALL_SCAN_ITERS.fetch_add(local_iters, Ordering::Relaxed);
                    TX_SMALL_ACQUIRES.fetch_add(1, Ordering::Relaxed);
                    let qpl_offset = (slot as u32) * PAGE_SIZE;
                    let data_ptr = (tx.qpl_base_va + qpl_offset as u64) as *mut u8;
                    return Some(uni_net_driver::TxBufHandle {
                        data_ptr,
                        data_cap: TX_MAX_PKT_LEN as u32,
                        driver_token: encode_token(qp, slot, POOL_ID_SMALL),
                        release_fn: release_tx_slot,
                    });
                }
            }
        }
        // No capacity. Force any deferred kick so the host sees
        // pending descriptors and can produce completions. Each
        // wrap-around counts as one saturation event.
        TX_SMALL_FULL_SPINS.fetch_add(1, Ordering::Relaxed);
        let bar2_va = BAR2_VA.load(Ordering::Acquire);
        if bar2_va != 0 {
            let last = tx.last_kicked.load(Ordering::Relaxed);
            if fill != last {
                doorbell_write(bar2_va, tx.db_offset, fill);
                tx.last_kicked.store(fill, Ordering::Relaxed);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Acquire a big-pool TX slot for a specific qp. Returns `None`
/// when the big pool is full — caller falls back to per-MSS
/// segmentation via the small pool. We don't spin-drain the big
/// pool: TSO super-segments are best-effort batching, and a
/// transient saturation should not block the worker; the per-MSS
/// path is the safety net.
pub(crate) fn acquire_tx_tso_buf_for_qp(qp: usize) -> Option<uni_net_driver::TxTsoBufHandle> {
    if qp >= MAX_QUEUE_PAIRS { return None; }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return None; }
    let tx = unsafe { &*tx_ptr };

    // Drain so completions free big slots before we try to claim
    // one. The ring-fill check uses `ring_entries - 1` headroom
    // (TSO uses 2 descs per packet, leave space for one).
    tx_drain(tx);
    let fill = tx.fill_cnt.load(Ordering::Relaxed);
    let done = tx.done_cnt.load(Ordering::Relaxed);
    if fill.wrapping_sub(done) >= tx.ring_entries as u32 - 1 {
        TX_BIG_FULL_RETURNS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    for slot in 0..(TX_BIG_POOL_SLOTS as usize) {
        if !tx.big_slot_used[slot].load(Ordering::Acquire) {
            tx.big_slot_used[slot].store(true, Ordering::Relaxed);
            TX_BIG_ACQUIRES.fetch_add(1, Ordering::Relaxed);
            let qpl_offset = TX_BIG_POOL_QPL_OFFSET + (slot as u32) * TX_BIG_SLOT_SIZE;
            let data_ptr = (tx.qpl_base_va + qpl_offset as u64) as *mut u8;
            return Some(uni_net_driver::TxTsoBufHandle(uni_net_driver::TxBufHandle {
                data_ptr,
                data_cap: TX_MAX_TSO_LEN as u32,
                driver_token: encode_token(qp, slot, POOL_ID_BIG),
                release_fn: release_tx_slot,
            }));
        }
    }
    TX_BIG_FULL_RETURNS.fetch_add(1, Ordering::Relaxed);
    None
}

// ---- TX direct-fill: submit ------------------------------------------------

/// Build the gve_tx_pkt_desc at the next ring position, advance
/// `fill_cnt`, and (unless deferred) write the doorbell. Caller
/// has already filled `handle.data_mut()[..frame_len]` with the
/// frame bytes; the descriptor's `seg_addr` references the slot's
/// QPL page so the device DMAs from there.
///
/// gve_tx_pkt_desc layout (16 bytes), per Linux gve_desc.h:
///   u8  type_flags     (low 4 bits = type, upper 4 bits = flags;
///                       type = GVE_TXD_STD (0x00); flags include
///                       GVE_TXF_L4CSUM (bit 0))
///   u8  l4_csum_offset (16-bit-WORD offset within L4 header to
///                       the checksum field — TCP=8, UDP=3)
///   u8  l4_hdr_offset  (16-bit-WORD offset of L4 header in
///                       packet — Eth+IPv4 = 34/2 = 17)
///   u8  desc_cnt       (1 — single-segment packet)
///   u16 len            (be, total packet length)
///   u16 seg_len        (be, this segment length)
///   u64 seg_addr       (be, QPL byte offset in QPL mode)
///
/// `csum.is_some()` activates L4-CSUM offload: the device
/// computes the L4 checksum at byte
/// `l4_hdr_offset*2 + l4_csum_offset*2` of the frame.
pub(crate) fn submit_tx_inner(
    handle: uni_net_driver::TxBufHandle,
    frame_len: usize,
    csum: uni_net_driver::CsumOffload,
) {
    let (qp, slot, _pool) = decode_token(handle.driver_token);
    // mem::forget skips Drop's `release_fn` — the slot is about
    // to be in-flight, not unused. `tx_drain` returns it to the
    // pool when the device signals descriptor completion.
    core::mem::forget(handle);

    // Type-distinct handles guarantee a `TxBufHandle` here came
    // from the small pool (big-pool slots flow through
    // `TxTsoBufHandle` + `submit_tx_tso`). Defensive bound checks
    // for slot/qp index only.
    if qp >= MAX_QUEUE_PAIRS || slot >= TX_SMALL_POOL_SLOTS as usize {
        return;
    }
    if frame_len == 0 || frame_len > TX_MAX_PKT_LEN {
        let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
        if !tx_ptr.is_null() {
            unsafe { (*tx_ptr).small_slot_used[slot].store(false, Ordering::Release); }
        }
        return;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return; }
    let tx = unsafe { &*tx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    let fill_cnt = tx.fill_cnt.load(Ordering::Relaxed);
    let mask = (tx.ring_entries - 1) as u32;
    let ring_idx = (fill_cnt & mask) as usize;

    let qpl_offset = (slot as u32) * PAGE_SIZE;
    let desc_ptr = (tx.ring_va as *mut u8).wrapping_add(ring_idx * TX_DESC_SIZE);
    let mut desc = [0u8; TX_DESC_SIZE];
    // type_flags: GVE_TXD_STD (0x00) | GVE_TXF_L4CSUM (0x01) when
    // offload is on. Linux uses the upper-4-bit type encoding
    // (`(0x0 << 4) = GVE_TXD_STD`) plus low-bit flags.
    desc[0] = GVE_TXD_STD | if csum.is_some() { GVE_TXF_L4CSUM } else { 0 };
    if csum.is_some() {
        // Both fields are in 16-bit-word units per the spec
        // (`csum_offset >> 1`, `l4_hdr_offset >> 1` in Linux).
        // The caller's `csum.start` is the byte offset of the L4
        // header in the frame; `csum.offset` is the byte offset
        // of the checksum field within the L4 header.
        desc[1] = (csum.offset >> 1) as u8;
        desc[2] = (csum.start >> 1) as u8;
    }
    desc[3] = 1; // desc_cnt
    put_be16(&mut desc, 4, frame_len as u16);
    put_be16(&mut desc, 6, frame_len as u16);
    put_be64(&mut desc, 8, qpl_offset as u64);
    unsafe {
        ptr::copy_nonoverlapping(desc.as_ptr(), desc_ptr, TX_DESC_SIZE);
    }
    record_tx_desc(qp as u8, tx_desc_kind::STD, &desc);

    let new_fill = fill_cnt.wrapping_add(1);
    tx.fill_cnt.store(new_fill, Ordering::Release);

    let near_full = new_fill.wrapping_sub(tx.done_cnt.load(Ordering::Relaxed))
        >= (tx.ring_entries as u32) - 16;
    if !DEFERRED_KICK.load(Ordering::Relaxed) || near_full {
        doorbell_write(bar2_va, tx.db_offset, new_fill);
        tx.last_kicked.store(new_fill, Ordering::Relaxed);
    }

    // Per-qp TX packet count for load-distribution diagnostics.
    if qp < TX_PACKETS_PER_QP.len() {
        TX_PACKETS_PER_QP[qp].fetch_add(1, Ordering::Relaxed);
        TX_BYTES_PER_QP[qp].fetch_add(frame_len as u64, Ordering::Relaxed);
    }
}

/// Submit a TSO super-segment on `qp`. Emits two GQI descriptors:
///   * `desc[0]` (TSO pkt_desc): type=`GVE_TXD_TSO|GVE_TXF_L4CSUM`,
///     header at the start of the big-pool slot, `desc_cnt=2`.
///   * `desc[1]` (SEG desc): type=`GVE_TXD_SEG` (+ `GVE_TXSF_IPV6`
///     if v6), `mss=gso_size`, payload immediately after the header
///     in the same big-pool slot.
///
/// Per Linux's `gve_tx_fill_pkt_desc` / `gve_tx_fill_seg_desc`:
///   * `l4_csum_offset` and `l4_hdr_offset` are in 16-bit-word units
///     (`>> 1`); for TCP `csum_offset = 16` so `l4_csum_offset = 8`.
///   * `l3_offset` is also in 16-bit-word units; for plain Ethernet
///     it's `14 >> 1 = 7`.
///   * `len` on the TSO desc is the **total** frame length (Linux
///     passes `skb->len`); the device uses `desc_cnt` to know how
///     many descs to fetch, then segments the payload using `mss`.
pub(crate) fn submit_tx_tso_inner(
    handle: uni_net_driver::TxTsoBufHandle,
    frame_len: usize,
    hdr_len: u16,
    csum_start: u16,
    gso_size: u16,
) {
    let (qp, slot, _pool) = decode_token(handle.0.driver_token);
    // See `submit_tx_inner` for the mem::forget rationale.
    core::mem::forget(handle);

    // `TxTsoBufHandle` is type-distinct so we know this came from
    // the big pool. Defensive index checks only.
    if qp >= MAX_QUEUE_PAIRS || slot >= TX_BIG_POOL_SLOTS as usize {
        return;
    }
    if frame_len == 0
        || frame_len > TX_MAX_TSO_LEN
        || hdr_len as usize >= frame_len
        || gso_size == 0
        || (csum_start as usize) >= frame_len
    {
        let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
        if !tx_ptr.is_null() {
            unsafe { (*tx_ptr).big_slot_used[slot].store(false, Ordering::Release); }
        }
        return;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return; }
    let tx = unsafe { &*tx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    let fill_cnt = tx.fill_cnt.load(Ordering::Relaxed);
    let mask = (tx.ring_entries - 1) as u32;
    let ring_idx_0 = (fill_cnt & mask) as usize;
    let ring_idx_1 = (fill_cnt.wrapping_add(1) & mask) as usize;

    let qpl_off_hdr = TX_BIG_POOL_QPL_OFFSET + (slot as u32) * TX_BIG_SLOT_SIZE;
    let qpl_off_payload = qpl_off_hdr + hdr_len as u32;
    let payload_len = (frame_len - hdr_len as usize) as u16;

    // Detect IPv4 vs IPv6 from the IP version nibble. `csum_start`
    // points at the L4 header, so the IP version is at `csum_start
    // - IP_HDR_LEN`. We sniff the byte just after the Ethernet
    // header (offset 14) instead — robust to v4 vs v6 since both
    // start with a `version<<4 | ...` byte.
    let buf_ptr = (tx.qpl_base_va + qpl_off_hdr as u64) as *const u8;
    let ip_ver = unsafe { ptr::read_volatile(buf_ptr.add(14)) >> 4 };
    let is_v6 = ip_ver == 6;

    // Fixed: TCP csum field is at offset 16 within TCP header.
    // 16 >> 1 = 8.
    const L4_CSUM_OFFSET_WORDS: u8 = 8;
    // Plain Ethernet (no VLAN) — IP header begins at byte 14.
    // 14 >> 1 = 7.
    const L3_OFFSET_WORDS: u8 = 7;

    // ---- desc[0]: TSO pkt_desc ----
    let mut desc0 = [0u8; TX_DESC_SIZE];
    desc0[0] = GVE_TXD_TSO | GVE_TXF_L4CSUM;
    desc0[1] = L4_CSUM_OFFSET_WORDS;
    desc0[2] = (csum_start >> 1) as u8;
    desc0[3] = 2; // desc_cnt — TSO + 1 SEG
    put_be16(&mut desc0, 4, frame_len as u16);
    put_be16(&mut desc0, 6, hdr_len);
    put_be64(&mut desc0, 8, qpl_off_hdr as u64);

    // ---- desc[1]: SEG desc ----
    let mut desc1 = [0u8; TX_DESC_SIZE];
    desc1[0] = GVE_TXD_SEG | if is_v6 { GVE_TXSF_IPV6 } else { 0 };
    desc1[1] = L3_OFFSET_WORDS;
    // bytes 2..4 reserved
    put_be16(&mut desc1, 4, gso_size);  // mss
    put_be16(&mut desc1, 6, payload_len);
    put_be64(&mut desc1, 8, qpl_off_payload as u64);

    let desc_ptr_0 = (tx.ring_va as *mut u8).wrapping_add(ring_idx_0 * TX_DESC_SIZE);
    let desc_ptr_1 = (tx.ring_va as *mut u8).wrapping_add(ring_idx_1 * TX_DESC_SIZE);
    unsafe {
        ptr::copy_nonoverlapping(desc0.as_ptr(), desc_ptr_0, TX_DESC_SIZE);
        ptr::copy_nonoverlapping(desc1.as_ptr(), desc_ptr_1, TX_DESC_SIZE);
    }
    // Capture both descriptors so /diag-gve can render the TSO +
    // SEG pair the device sees. Recorded in the same chronological
    // order they were placed on the ring.
    record_tx_desc(qp as u8, tx_desc_kind::TSO, &desc0);
    record_tx_desc(qp as u8, tx_desc_kind::SEG, &desc1);

    let new_fill = fill_cnt.wrapping_add(2);
    tx.fill_cnt.store(new_fill, Ordering::Release);

    let near_full = new_fill.wrapping_sub(tx.done_cnt.load(Ordering::Relaxed))
        >= (tx.ring_entries as u32) - 16;
    if !DEFERRED_KICK.load(Ordering::Relaxed) || near_full {
        doorbell_write(bar2_va, tx.db_offset, new_fill);
        tx.last_kicked.store(new_fill, Ordering::Relaxed);
    }

    // One super-segment carries many MSS-sized packets on the wire,
    // but to the driver it's one TX submission. Count it as one
    // packet so per-qp load-distribution maths still maps to
    // descriptor-pair submits. The byte count is the
    // pre-segmentation frame length (not the wire-emitted bytes
    // after the device duplicates headers per segment).
    if qp < TX_PACKETS_PER_QP.len() {
        TX_PACKETS_PER_QP[qp].fetch_add(1, Ordering::Relaxed);
        TX_BYTES_PER_QP[qp].fetch_add(frame_len as u64, Ordering::Relaxed);
    }
}

/// UDP-GSO submit. Layout-identical to [`submit_tx_tso_inner`]
/// except the L4 checksum offset is 3 (UDP cksum at byte 6 of
/// the UDP header) instead of 8 (TCP cksum at byte 16). The
/// device decides "TCP vs UDP segmentation" from the IP-header
/// protocol byte sniffed at offset `csum_start - IP_HDR_LEN`,
/// so a single descriptor format covers both modes — we only
/// need to point the device at the correct csum field.
pub(crate) fn submit_tx_udp_gso_inner(
    handle: uni_net_driver::TxUdpGsoBufHandle,
    frame_len: usize,
    hdr_len: u16,
    csum_start: u16,
    gso_size: u16,
) {
    let (qp, slot, _pool) = decode_token(handle.0.driver_token);
    core::mem::forget(handle);

    if qp >= MAX_QUEUE_PAIRS || slot >= TX_BIG_POOL_SLOTS as usize {
        return;
    }
    if frame_len == 0
        || frame_len > TX_MAX_TSO_LEN
        || hdr_len as usize >= frame_len
        || gso_size == 0
        || (csum_start as usize) >= frame_len
    {
        let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
        if !tx_ptr.is_null() {
            unsafe { (*tx_ptr).big_slot_used[slot].store(false, Ordering::Release); }
        }
        return;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return; }
    let tx = unsafe { &*tx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    let fill_cnt = tx.fill_cnt.load(Ordering::Relaxed);
    let mask = (tx.ring_entries - 1) as u32;
    let ring_idx_0 = (fill_cnt & mask) as usize;
    let ring_idx_1 = (fill_cnt.wrapping_add(1) & mask) as usize;

    let qpl_off_hdr = TX_BIG_POOL_QPL_OFFSET + (slot as u32) * TX_BIG_SLOT_SIZE;
    let qpl_off_payload = qpl_off_hdr + hdr_len as u32;
    let payload_len = (frame_len - hdr_len as usize) as u16;

    let buf_ptr = (tx.qpl_base_va + qpl_off_hdr as u64) as *const u8;
    let ip_ver = unsafe { ptr::read_volatile(buf_ptr.add(14)) >> 4 };
    let is_v6 = ip_ver == 6;

    // UDP checksum at byte 6 of the UDP header. 6 >> 1 = 3.
    const L4_CSUM_OFFSET_WORDS_UDP: u8 = 3;
    const L3_OFFSET_WORDS: u8 = 7;

    let mut desc0 = [0u8; TX_DESC_SIZE];
    desc0[0] = GVE_TXD_TSO | GVE_TXF_L4CSUM;
    desc0[1] = L4_CSUM_OFFSET_WORDS_UDP;
    desc0[2] = (csum_start >> 1) as u8;
    desc0[3] = 2;
    put_be16(&mut desc0, 4, frame_len as u16);
    put_be16(&mut desc0, 6, hdr_len);
    put_be64(&mut desc0, 8, qpl_off_hdr as u64);

    let mut desc1 = [0u8; TX_DESC_SIZE];
    desc1[0] = GVE_TXD_SEG | if is_v6 { GVE_TXSF_IPV6 } else { 0 };
    desc1[1] = L3_OFFSET_WORDS;
    put_be16(&mut desc1, 4, gso_size);
    put_be16(&mut desc1, 6, payload_len);
    put_be64(&mut desc1, 8, qpl_off_payload as u64);

    let desc_ptr_0 = (tx.ring_va as *mut u8).wrapping_add(ring_idx_0 * TX_DESC_SIZE);
    let desc_ptr_1 = (tx.ring_va as *mut u8).wrapping_add(ring_idx_1 * TX_DESC_SIZE);
    unsafe {
        ptr::copy_nonoverlapping(desc0.as_ptr(), desc_ptr_0, TX_DESC_SIZE);
        ptr::copy_nonoverlapping(desc1.as_ptr(), desc_ptr_1, TX_DESC_SIZE);
    }
    record_tx_desc(qp as u8, tx_desc_kind::TSO, &desc0);
    record_tx_desc(qp as u8, tx_desc_kind::SEG, &desc1);

    let new_fill = fill_cnt.wrapping_add(2);
    tx.fill_cnt.store(new_fill, Ordering::Release);

    let near_full = new_fill.wrapping_sub(tx.done_cnt.load(Ordering::Relaxed))
        >= (tx.ring_entries as u32) - 16;
    if !DEFERRED_KICK.load(Ordering::Relaxed) || near_full {
        doorbell_write(bar2_va, tx.db_offset, new_fill);
        tx.last_kicked.store(new_fill, Ordering::Relaxed);
    }

    if qp < TX_PACKETS_PER_QP.len() {
        TX_PACKETS_PER_QP[qp].fetch_add(1, Ordering::Relaxed);
        TX_BYTES_PER_QP[qp].fetch_add(frame_len as u64, Ordering::Relaxed);
    }
}

// ---- RX poll ---------------------------------------------------------------

/// Drain the RX completion ring for the given queue pair,
/// delivering each frame as an owned one-part [`IOBufChain`].
/// Returns the number of frames handed to `callback`.
///
/// Progress is detected by sequence number, not producer index:
/// each completion descriptor carries `flags_seq` whose low 3 bits
/// cycle 1..7. When the next descriptor's sequence matches what
/// we're expecting, it's a new completion.
///
/// GQI reposts RX buffers to the device strictly in order, so —
/// unlike DQO — it cannot lend a device QPL page up the stack and
/// rely on an auto-repost when the chain drops. Instead each frame
/// is copied into a slab from the queue's recycle pool
/// ([`uni_iobuf::IOBufPool`]); the device page is reposted in the
/// batch-end `fill_cnt` advance + doorbell below, and the *slab*
/// travels up the stack, recycling to the pool when its IOBuf
/// drops. `consumed` counts completions drained (= device buffers
/// reposted); `delivered` counts frames a slab was actually
/// allocated for — they differ only when the pool is exhausted.
pub(crate) fn poll_qp_inner<F: FnMut(Chain<OwnedIOBuf>)>(qp: usize, mut callback: F) -> u32 {
    if qp >= MAX_QUEUE_PAIRS {
        return 0;
    }
    let rx_ptr = RX_QUEUES[qp].load(Ordering::Acquire);
    if rx_ptr.is_null() {
        return 0;
    }
    // SAFETY: pointer is published once after init. RxQueue's
    // non-atomic fields (ring_va, db_offset, rx_pool, …) are only
    // written during init under STATE lock, before the Release
    // publish; Acquire above synchronises with that. Mutable
    // fields (cons_cnt, expected_seq, fill_cnt) are AtomicU32/U8,
    // which tolerate concurrent access if another core ever calls
    // in — though in Tier 1 each queue is polled by exactly one
    // core.
    let rx = unsafe { &*rx_ptr };

    let mask = (rx.ring_entries - 1) as u32;
    let mut cons = rx.cons_cnt.load(Ordering::Relaxed);
    let mut expected = rx.expected_seq.load(Ordering::Relaxed);
    let mut delivered: u32 = 0;
    let mut consumed: u32 = 0;

    // Batch limit. A runaway (matching-seq loop, or huge single
    // burst) could otherwise monopolise this core; the event loop
    // wouldn't get a chance to flush TX, check shutdown, etc. 64
    // packets per poll call is plenty for throughput and keeps us
    // responsive.
    const MAX_BATCH: u32 = 64;

    while consumed < MAX_BATCH {
        let idx = (cons & mask) as usize;
        let desc_ptr = (rx.compl_va as *const u8).wrapping_add(idx * RX_DESC_SIZE);
        // SAFETY: descriptor is 64 bytes inside a DMA-coherent page.
        // x86 is cache-coherent so a volatile read is sufficient
        // to see the device's writes.
        let desc: &[u8] = unsafe { core::slice::from_raw_parts(desc_ptr, RX_DESC_SIZE) };

        let flags_seq = read_be16(desc, RX_DESC_FLAGS_SEQ_OFF);
        let seq = (flags_seq & 0x7) as u8;
        if seq != expected {
            break;
        }

        let len = read_be16(desc, RX_DESC_LEN_OFF) as usize;
        if len > 0 {
            // Borrow the frame in the device QPL page. The page is
            // reposted at end of batch regardless, so the bytes must
            // be copied into a recycle-pool slab before then.
            //
            // SAFETY: `page_va` is the QPL page assigned to slot
            // `idx`, DMA-coherent memory from `init`;
            // `RX_DATA_OFFSET_IN_PAGE + len <= PAGE_SIZE` by device
            // contract (one packet per page, MTU + headers fits well
            // under 4 KiB).
            let page_va = rx.qpl_base_va as usize + idx * (PAGE_SIZE as usize);
            let frame: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    (page_va + RX_DATA_OFFSET_IN_PAGE) as *const u8,
                    len,
                )
            };
            // `alloc` copies `frame` into a pooled slab and hands
            // back a filled, `Send`-able `OwnedIOBuf` — the copy
            // lives in the pool because only the pool knows its
            // slabs are writable. The slab recycles to the pool when
            // its IOBuf drops, possibly on another core.
            match rx.rx_pool.as_ref().and_then(|p| p.alloc(frame)) {
                Some(slab) => {
                    if qp < RX_BYTES_PER_QP.len() {
                        RX_BYTES_PER_QP[qp].fetch_add(len as u64, Ordering::Relaxed);
                    }
                    callback(Chain::from(slab));
                    delivered += 1;
                }
                None => {
                    // Recycle pool exhausted (or — never in practice
                    // — an oversize frame): drop it. The device page
                    // is still reposted below, so the device ring
                    // stays consistent with the completion ring;
                    // TCP retransmit / UDP retry recover the frame.
                    if qp < GQI_RECYCLE_POOL_EXHAUSTED.len() {
                        GQI_RECYCLE_POOL_EXHAUSTED[qp].fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        consumed += 1;
        cons = cons.wrapping_add(1);
        expected = if expected == 7 { 1 } else { expected + 1 };
    }

    if consumed > 0 {
        // Repost every drained completion's device buffer in one
        // batch: advance `fill_cnt` and doorbell the cumulative
        // tail. GQI's data-slot ring entries are static QPL
        // offsets, so "repost" is purely advancing the producer
        // counter — and it covers exhausted-pool frames too, so the
        // device ring never desyncs from the completion ring.
        let bar2_va = BAR2_VA.load(Ordering::Acquire);
        let new_fill = rx.fill_cnt.load(Ordering::Relaxed).wrapping_add(consumed);
        rx.cons_cnt.store(cons, Ordering::Relaxed);
        rx.expected_seq.store(expected, Ordering::Relaxed);
        rx.fill_cnt.store(new_fill, Ordering::Relaxed);
        doorbell_write(bar2_va, rx.db_offset, new_fill);
        if qp < RX_BUF_REPOST_COUNT.len() {
            RX_BUF_REPOST_COUNT[qp].fetch_add(consumed as u64, Ordering::Relaxed);
        }
    }

    delivered
}

// Suppress unused warnings for items only used by sibling lib.rs
// at compile time — the `AtomicBool` import is needed via Drop's
// release_fn closure but not directly referenced in this module.
#[allow(dead_code)]
const _: AtomicBool = AtomicBool::new(false);
