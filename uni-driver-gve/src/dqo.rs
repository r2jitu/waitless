// DQO_RDA datapath — modern descriptor format used on c3 / c4 /
// future GCE generations.
//
// Differences from GQI_QPL: little-endian wire format throughout, raw
// DMA addresses in TX descriptors (no QPL offsets — we still bounce
// through a per-slot buffer to keep memory layout simple), separate
// TX completion ring and RX buffer ring, and "generation bit" polling
// instead of GQI's flags_seq cycle. Layout matches Linux's
// `gve_desc_dqo.h`.

use core::ptr;
use core::sync::atomic::Ordering;

use drivers_infra::mmio_write32;

use crate::{
    BAR2_VA, DEFERRED_KICK, MAX_QUEUE_PAIRS, RX_BUFFER_SIZE,
    RX_BYTES_PER_QP, RX_QUEUES, RxQueue, TX_QUEUES, TxQueue,
};

// ---- DQO_RDA descriptor formats -------------------------------------------

/// DQO TX packet descriptor — 16 bytes.
///   0..8   buf_addr     (LE64)            DMA addr of packet buffer
///   8      type_flags                     bits[4:0]=dtype (0xC), bit5=end_of_packet,
///                                         bit6=checksum_offload, bit7=report_event
///   9      reserved0
///   10..12 reserved1                      (LE16)
///   12..14 compl_tag                      (LE16)  device echoes in TX completion
///   14..16 buf_size_and_resv              bits[13:0]=buf_size (max 16383)
pub(crate) const DQO_TX_DESC_SIZE: usize = 16;
pub(crate) const DQO_TX_DTYPE_PKT: u8 = 0xC;
/// General context descriptor type, per `gve_desc_dqo.h`'s
/// `GVE_TX_GENERAL_CTX_DESC_DTYPE_DQO`. Linux emits one of
/// these IMMEDIATELY before each data descriptor; without it,
/// our packets miss the metadata preamble the device expects.
pub(crate) const DQO_TX_DTYPE_GENERAL_CTX: u8 = 0x4;
pub(crate) const DQO_TX_FLAG_EOP: u8 = 1 << 5;
/// `checksum_offload_enable` (byte 8 bit 6) — instructs the device
/// to compute the L4 checksum host-side. Equivalent of virtio's
/// NEEDS_CSUM. Per gve_desc_dqo.h.
pub(crate) const DQO_TX_FLAG_CSUM: u8 = 1 << 6;
pub(crate) const DQO_TX_FLAG_REPORT_EVENT: u8 = 1 << 7;
/// `report_event` flags MUST be spaced at least this many TX
/// descriptors apart per `gve_desc_dqo.h`'s GVE_TX_MIN_RE_INTERVAL
/// (= 32). Linux's gve_tx_dqo bumps `last_re_idx` after setting RE
/// and only sets it again once `interval >= 32`. Setting RE on
/// every descriptor (which an earlier version of this driver did)
/// stalls the device under sustained load: completions stop
/// arriving and the per-qp ring saturates at fill_cnt - done_cnt
/// = ring_entries.
pub(crate) const DQO_TX_RE_INTERVAL: u32 = 32;

/// DQO TX completion descriptor — 8 bytes (device-written).
///   0..2   header                         bits[10:0]=id, [13:11]=type,
///                                         bit14=reserved, bit15=generation
///   2..4   tx_head_or_tag                 (LE16)  packet=compl_tag, descriptor=head+1
///   4..8   reserved                       (LE32)
pub(crate) const DQO_TX_COMPL_SIZE: usize = 8;
/// Per Linux's `gve_desc_dqo.h`:
///   2: PKT      — normal per-packet completion (success)
///   3: MISS     — device dropped this packet mid-flight; will try to
///                 reinject. The MISS bit may also be encoded inline
///                 in a PKT-typed completion via `GVE_ALT_MISS_COMPL_BIT`.
///   4: DESC     — emitted when `report_event` was set on a desc;
///                 carries `tx_head` (last desc fetched by HW + 1).
///   5: REINJECT — previously-missed packet was eventually sent.
const DQO_TX_COMPL_TYPE_PKT: u8 = 0x2;
const DQO_TX_COMPL_TYPE_MISS: u8 = 0x3;
const DQO_TX_COMPL_TYPE_DESC: u8 = 0x4;
const DQO_TX_COMPL_TYPE_REINJECT: u8 = 0x5;
/// Bit on a PKT-typed completion's `completion_tag` field that
/// means "this PKT completion is actually a MISS". Per Linux's
/// `GVE_ALT_MISS_COMPL_BIT`.
const GVE_ALT_MISS_COMPL_BIT: u16 = 1 << 15;

/// Diagnostic counters — how often the device emits MISS or
/// REINJECT completions. MISS > 0 means the device internally
/// dropped one of our TX packets and is attempting reinjection.
/// REINJECT > 0 means a previously-missed packet eventually went
/// out. On well-behaved flows both stay at 0.
///
/// We deliberately do NOT count the hot PKT/DESC completion types
/// here — per-completion atomic increments on a shared cache line
/// cost ~30% TX throughput at par=4 fresh-conn rates (measured
/// 2026-05-13: 10.7k → 6.9k RPS with all four counted). The per-qp
/// TX_PACKETS_PER_QP counter already tracks successful sends; the
/// device's PKT-completion count just confirms the same fact from
/// the other side, so the duplication isn't worth the cost.
pub static DQO_TX_MISS_COMPL: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static DQO_TX_REINJECT_COMPL: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// DQO RX buffer descriptor — 32 bytes (driver-written, points to a
/// device-readable packet buffer).
///   0..2   buf_id                         (LE16)  echoed back in RX completion
///   2..4   reserved0                      (LE16)
///   4..8   reserved1                      (LE32)
///   8..16  buf_addr                       (LE64)  DMA addr of packet buffer
///   16..24 header_buf_addr                (LE64)  DMA addr of header buffer (we use 0)
///   24..32 reserved2
pub(crate) const DQO_RX_DESC_SIZE: usize = 32;

/// DQO RX completion descriptor — 32 bytes (device-written).
///   Layout per Linux gve_desc_dqo.h. We only use a few fields:
///     offset 0  (1 byte)  rxdid (low 4 bits, must be 1) + reserved
///     offset 4..6 (LE16)  packet_len (low 14 bits) + generation (bit 14) + bq_id (bit 15)
///     offset 8  (1 byte)  status flags: bit0=descriptor_done, bit1=end_of_packet, ...
///     offset 12..14 (LE16) buf_id
pub(crate) const DQO_RX_COMPL_SIZE: usize = 32;
const DQO_RX_COMPL_STATUS_EOP: u8 = 1 << 1;

/// DQO RX buffer pool. Each pre-allocated 2 KiB packet buffer maps to
/// a `buf_id` (the index in this pool). On post we tell the device
/// "buffer at DMA addr X has buf_id Y"; on completion the device
/// returns "buffer Y holds a packet of N bytes" and we look up the VA
/// at `pool_base_va + Y * RX_BUFFER_SIZE` to deliver to the callback.
pub(crate) const DQO_RX_POOL_BUFS: u32 = crate::RX_RING_ENTRIES as u32;
/// DQO TX bounce buffer pool. Mirrors GQI's QPL pages — one buffer
/// per TX ring slot, indexed by ring slot. send() copies the packet
/// in; completion frees the slot.
pub(crate) const DQO_TX_POOL_BUFS: u32 = crate::TX_RING_ENTRIES as u32;

// ---- Doorbell ---------------------------------------------------------------

/// DQO doorbell write. Unlike GQI_QPL (big-endian), DQO doorbells are
/// little-endian on the wire — Linux's `gve_*_write_doorbell_dqo` use
/// `writel` (LE on x86) vs GQI's `iowrite32be`.
///
/// Includes `host_dma_fence()` (an `sfence` on x86) so callers don't
/// have to remember. Every call site here writes WB-cached descriptor
/// state before the doorbell, so the fence is always required.
#[inline]
pub(crate) fn doorbell_write_le(bar2_va: u64, offset: u32, value: u32) {
    crate::host_dma_fence();
    unsafe {
        mmio_write32(bar2_va + offset as u64, value);
    }
}

// ---- TX completion drain ---------------------------------------------------

/// Drain the DQO TX completion ring up to the first entry whose
/// generation bit doesn't match what we expect, then advance
/// `done_cnt` to the device-reported `tx_head` from the last
/// observed DESC completion.
///
/// DQO TX-completion descriptor layout (8 bytes), per Linux's
/// `gve_tx_compl_desc` (gve_desc_dqo.h):
///
///   bytes 0-1: LE-bitfield u16
///     bits  0..10 = id (compl_tag, for PKT/MISS/REINJECT compls;
///                   queue ID for DESC compls — informational)
///     bits 11..13 = type (DQO_TX_COMPL_TYPE_*)
///     bit 14      = reserved
///     bit 15      = generation
///   bytes 2-3: union — `tx_head` (DESC compl) or
///              `completion_tag` (PKT compl), LE u16
///   bytes 4-7: reserved
///
/// `tx_head` from a DESC completion is "the last descriptor
/// fetched by HW plus one" (the authoritative driver `done_cnt`
/// value). PKT/MISS/REINJECT completions only convey per-packet
/// status — we don't need them for slot reuse since this driver
/// uses the slot==ring_idx convention; ring positions cycle
/// implicitly as `done_cnt` advances.
pub(crate) fn tx_drain(tx: &TxQueue) {
    if tx.tx_compl_va == 0 || tx.tx_compl_entries == 0 { return; }
    let cmask = (tx.tx_compl_entries - 1) as u32;
    let rmask = (tx.ring_entries - 1) as u32;
    let mut head = tx.tx_compl_head.load(Ordering::Relaxed);
    let mut cur_gen = tx.tx_compl_gen.load(Ordering::Relaxed);
    let mut latest_tx_head: Option<u16> = None;
    loop {
        let idx = (head & cmask) as usize;
        let desc_ptr = (tx.tx_compl_va as *const u8).wrapping_add(idx * DQO_TX_COMPL_SIZE);
        let hdr_word = u16::from_le_bytes([
            unsafe { ptr::read_volatile(desc_ptr) },
            unsafe { ptr::read_volatile(desc_ptr.add(1)) },
        ]);
        let desc_gen = ((hdr_word >> 15) & 1) as u8;
        if desc_gen != cur_gen { break; }
        let cmpl_type = ((hdr_word >> 11) & 0x7) as u8;
        match cmpl_type {
            DQO_TX_COMPL_TYPE_DESC => {
                let tx_head = u16::from_le_bytes([
                    unsafe { ptr::read_volatile(desc_ptr.add(2)) },
                    unsafe { ptr::read_volatile(desc_ptr.add(3)) },
                ]);
                latest_tx_head = Some(tx_head);
            }
            DQO_TX_COMPL_TYPE_PKT => {
                // Per Linux, GVE_ALT_MISS_COMPL_BIT can be set on
                // a PKT-typed completion's completion_tag to mean
                // "this is actually a MISS". Read the tag's high
                // bit; only do an atomic increment for that rare
                // case so the hot per-packet path stays free.
                let tag_hi = unsafe { ptr::read_volatile(desc_ptr.add(3)) };
                if tag_hi & ((GVE_ALT_MISS_COMPL_BIT >> 8) as u8) != 0 {
                    DQO_TX_MISS_COMPL.fetch_add(1, Ordering::Relaxed);
                }
            }
            DQO_TX_COMPL_TYPE_MISS => {
                DQO_TX_MISS_COMPL.fetch_add(1, Ordering::Relaxed);
            }
            DQO_TX_COMPL_TYPE_REINJECT => {
                DQO_TX_REINJECT_COMPL.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        // PKT / MISS / REINJECTION completions: not used for slot
        // reuse (slot==ring_idx convention); only MISS / REINJECT
        // counted as diagnostic.
        head = head.wrapping_add(1);
        if (head & cmask) == 0 {
            cur_gen ^= 1;
        }
    }
    tx.tx_compl_head.store(head, Ordering::Relaxed);
    tx.tx_compl_gen.store(cur_gen, Ordering::Relaxed);
    if let Some(tx_head) = latest_tx_head {
        // Translate the device's u16 ring-position `tx_head` into
        // an advance for our cumulative `done_cnt` (u32). Both
        // `done_cnt`'s low ring-mask bits and `tx_head` index into
        // the same ring; the delta between them (mod ring_entries)
        // is the number of descriptors the device has fetched
        // since our last drain.
        let mask16 = rmask as u16;
        let prev = tx.done_cnt.load(Ordering::Relaxed);
        let prev_low = (prev as u16) & mask16;
        let tx_head_low = tx_head & mask16;
        let delta = (tx_head_low.wrapping_sub(prev_low)) & mask16;
        if delta > 0 {
            tx.done_cnt.store(prev.wrapping_add(delta as u32), Ordering::Relaxed);
        }
    }
}

// ---- Outbound frame classification -----------------------------------------

/// Inspect an outbound frame and report:
///   - whether CSUM offload should be enabled (TCP/UDP only — those
///     have a pseudo-header partial in the L4 cksum field that the
///     device adds the payload sum to).
///   - a 15-bit path hash derived from the L4 4-tuple, used as the
///     `path_hash` metadata in the general context descriptor. Linux
///     sets this from `skb->hash` for any flow with `skb->l4_hash`;
///     we compute the same shape from the 4-tuple here. Setting it
///     to a real per-flow value (rather than a constant zero) is
///     what Linux does — the device exposes this as an opaque tag
///     in TX completions, where it's mostly informational for the
///     OS's queue tracking. We follow the spec for symmetry with
///     Linux even though it doesn't move our benchmarks much.
struct TxClassify {
    csum: bool,
    path_hash: u16, // 15-bit, never zero (matches Linux's sentinel rule)
}

fn classify_outbound(frame: &[u8]) -> TxClassify {
    let default = TxClassify { csum: false, path_hash: 0 };
    if frame.len() < 14 { return default; }
    let etype = u16::from_be_bytes([frame[12], frame[13]]);
    let (l4_proto, l4_off, ip_off, ip_hdr_len) = match etype {
        0x0800 => {
            if frame.len() < 14 + 20 { return default; }
            let ihl = (frame[14] & 0x0f) as usize;
            if ihl < 5 { return default; }
            (frame[14 + 9], 14 + ihl * 4, 14, ihl * 4)
        }
        0x86dd => {
            if frame.len() < 14 + 40 { return default; }
            (frame[14 + 6], 14 + 40, 14, 40)
        }
        _ => return default,
    };
    if !matches!(l4_proto, 6 | 17) { return default; }
    if l4_off + 4 > frame.len() { return default; }
    // Cheap 4-tuple hash: XOR-fold the src/dst IP words with the
    // src/dst port words. Linux uses a Jenkins-style hash; we just
    // need something that distributes across distinct flows.
    let mut h: u32 = 0;
    let ip_end = ip_off + ip_hdr_len;
    let ip_addrs_off = match etype {
        0x0800 => ip_off + 12, // IPv4 src+dst at offsets 12-19
        _      => ip_off + 8,  // IPv6 src at 8-23, dst at 24-39
    };
    let addrs_len = if etype == 0x0800 { 8 } else { 32 };
    let mut i = ip_addrs_off;
    while i + 1 < (ip_addrs_off + addrs_len).min(ip_end) {
        h ^= u16::from_be_bytes([frame[i], frame[i + 1]]) as u32;
        h = h.wrapping_mul(0x9e37); // mix
        i += 2;
    }
    // Add src/dst port words (first 4 bytes of L4 for both TCP/UDP).
    let sp = u16::from_be_bytes([frame[l4_off], frame[l4_off + 1]]) as u32;
    let dp = u16::from_be_bytes([frame[l4_off + 2], frame[l4_off + 3]]) as u32;
    h ^= sp.wrapping_mul(0x9e37);
    h ^= dp.wrapping_mul(0xc2b2);
    let path_hash = (h ^ (h >> 16)) as u16 & 0x7fff;
    let path_hash = if path_hash == 0 { 0x7fff } else { path_hash };
    TxClassify { csum: true, path_hash }
}

// ---- TX descriptor builders ------------------------------------------------

/// Pack a DQO general context descriptor into a 16-byte u128. The
/// layout matches `struct gve_tx_general_context_desc_dqo` from
/// `gve_desc_dqo.h`. We zero everything except byte 8 (cmd_dtype)
/// and bytes 13-14 (path_hash low + high in metadata.bytes[1..3]).
#[inline]
fn build_ctx_desc(path_hash: u16) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[8] = DQO_TX_DTYPE_GENERAL_CTX;
    bytes[13] = (path_hash & 0xff) as u8;
    bytes[14] = ((path_hash >> 8) & 0x7f) as u8;
    u128::from_le_bytes(bytes)
}

/// Pack a DQO TX packet descriptor into a 16-byte u128. Matches
/// `struct gve_tx_pkt_desc_dqo`. Single u128 store is atomic on x86
/// when 16-byte-aligned (which our ring descriptors are).
#[inline]
fn build_pkt_desc(buf_addr: u64, flags: u8, compl_tag: u16, buf_size: u16) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&buf_addr.to_le_bytes());
    bytes[8] = flags;
    bytes[12..14].copy_from_slice(&compl_tag.to_le_bytes());
    bytes[14..16].copy_from_slice(&(buf_size & 0x3FFF).to_le_bytes());
    u128::from_le_bytes(bytes)
}

// ---- TX send path ----------------------------------------------------------

/// Slice-shaped send: copy `data` into the next ring's bounce buffer,
/// emit a (general-ctx, pkt) descriptor pair, advance fill_cnt,
/// doorbell unless deferred.
pub(crate) fn send_on_qp(qp: usize, data: &[u8]) -> bool {
    if qp >= MAX_QUEUE_PAIRS || data.is_empty() || data.len() > (RX_BUFFER_SIZE as usize) {
        return false;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return false; }
    let tx = unsafe { &*tx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    tx_drain(tx);

    let fill_cnt = tx.fill_cnt.load(Ordering::Relaxed);
    let done_cnt = tx.done_cnt.load(Ordering::Relaxed);
    let in_flight = fill_cnt.wrapping_sub(done_cnt);
    // Each packet emits 2 descriptors (general context + pkt).
    if in_flight + 2 > tx.ring_entries as u32 {
        return false;
    }

    let mask = (tx.ring_entries - 1) as u32;
    let ctx_idx = (fill_cnt & mask) as usize;
    let pkt_idx = (fill_cnt.wrapping_add(1) & mask) as usize;
    let slot = pkt_idx;

    // Per-slot bounce buffer: send copies the packet here so the
    // descriptor can hand the device a stable DMA address.
    let buf_offset = (slot as u32) * (RX_BUFFER_SIZE as u32);
    let buf_va = (tx.qpl_base_va + buf_offset as u64) as *mut u8;
    let buf_phys = tx.qpl_base_phys + buf_offset as u64;
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), buf_va, data.len()); }

    // Classify the outbound frame: figure out whether the device
    // should do CSUM offload (for TCP/UDP), and compute a path_hash
    // for Andromeda's per-flow fast path.
    let cls = classify_outbound(unsafe {
        core::slice::from_raw_parts(buf_va as *const u8, data.len())
    });

    // Build the 16-byte general context descriptor as a single u128
    // so the store hits memory atomically. Layout per gve_desc_dqo.h:
    //   byte  8       cmd_dtype.dtype = 0x4
    //   bytes 13..15  metadata.bytes[1..3] = path_hash:15 + rehash:1
    //   all other bytes zero (version=0, no path_hash high bits set)
    //
    // Building as u128 lets LLVM emit a single 16-byte store; the
    // previous byte-array + ptr::copy_nonoverlapping path translated
    // to two movq stores, which the device could theoretically
    // prefetch between, seeing a half-written desc.
    let ctx_val: u128 = build_ctx_desc(cls.path_hash);
    let ctx_ptr = (tx.ring_va as *mut u128).wrapping_add(ctx_idx);
    unsafe { ptr::write_volatile(ctx_ptr, ctx_val); }

    // Packet descriptor. RE every 32nd descriptor per the device's
    // GVE_TX_MIN_RE_INTERVAL.
    let last_re = tx.last_re_at_fill.load(Ordering::Relaxed);
    let want_re = fill_cnt.wrapping_sub(last_re) >= DQO_TX_RE_INTERVAL;
    let mut flags = DQO_TX_DTYPE_PKT | DQO_TX_FLAG_EOP;
    if cls.csum {
        flags |= DQO_TX_FLAG_CSUM;
    }
    if want_re {
        flags |= DQO_TX_FLAG_REPORT_EVENT;
        tx.last_re_at_fill.store(fill_cnt, Ordering::Relaxed);
    }
    let pkt_val: u128 = build_pkt_desc(buf_phys, flags, slot as u16, data.len() as u16);
    let pkt_ptr = (tx.ring_va as *mut u128).wrapping_add(pkt_idx);
    unsafe { ptr::write_volatile(pkt_ptr, pkt_val); }

    let new_fill = fill_cnt.wrapping_add(2);
    tx.fill_cnt.store(new_fill, Ordering::Release);

    let near_full = new_fill.wrapping_sub(done_cnt) >= (tx.ring_entries as u32) - 16;
    if !DEFERRED_KICK.load(Ordering::Relaxed) || near_full {
        // `doorbell_write_le` includes the `sfence` that drains the
        // CPU store buffer before the BAR2 write — required because
        // PCIe DMA reads snoop L1/L2/L3 but not the store buffer.
        // See `host_dma_fence` for the full story.
        doorbell_write_le(bar2_va, tx.db_offset, new_fill & mask);
        tx.last_kicked.store(new_fill, Ordering::Relaxed);
    }
    true
}

// ---- RX post / poll --------------------------------------------------------

/// Post buffers on this queue's buffer ring and kick the doorbell.
/// Leaves the last slot empty so the device sees `tail != head` —
/// otherwise `tail & mask == head` is the device's "empty ring"
/// signal and incoming packets get dropped silently. Doorbell
/// receives the masked tail position (Linux's
/// `gve_rx_write_doorbell_dqo` convention; raw cumulative values
/// like our previous `DQO_RX_POOL_BUFS = 512` masked to 0 and
/// equalled the device's `head = 0` → ring looks empty → unicast
/// RX never delivers. Broadcast still works because GCE's DHCP
/// server takes its own per-flow path; `dhcp: configured IP` got
/// printed even with the bug active).
pub(crate) fn post_initial_rx_for_qp(rx: &RxQueue) {
    let pool_base_phys = rx.qpl_base_phys;
    let ring = rx.ring_entries as u32;
    let mask = ring - 1;
    let initial = ring - 1; // leave one slot empty
    for i in 0..initial {
        let post_idx = (i & mask) as usize;
        let desc_ptr = (rx.data_va as *mut u8).wrapping_add(post_idx * DQO_RX_DESC_SIZE);
        let mut desc = [0u8; DQO_RX_DESC_SIZE];
        desc[0..2].copy_from_slice(&(i as u16).to_le_bytes());
        let buf_phys = pool_base_phys + (i as u64) * (RX_BUFFER_SIZE as u64);
        desc[8..16].copy_from_slice(&buf_phys.to_le_bytes());
        unsafe { ptr::copy_nonoverlapping(desc.as_ptr(), desc_ptr, DQO_RX_DESC_SIZE); }
    }
    rx.fill_cnt.store(initial, Ordering::Release);
    let bar2_va = BAR2_VA.load(Ordering::Acquire);
    doorbell_write_le(bar2_va, rx.db_offset, initial & mask);
}

pub(crate) fn poll_qp_inner<F: FnMut(&[u8])>(qp: usize, mut callback: F) -> u32 {
    if qp >= MAX_QUEUE_PAIRS { return 0; }
    let rx_ptr = RX_QUEUES[qp].load(Ordering::Acquire);
    if rx_ptr.is_null() { return 0; }
    let rx = unsafe { &*rx_ptr };

    let mask = (rx.ring_entries - 1) as u32;
    let mut cons = rx.cons_cnt.load(Ordering::Relaxed);
    let mut cur_gen = rx.expected_seq.load(Ordering::Relaxed);
    let mut delivered: u32 = 0;
    const MAX_BATCH: u32 = 64;

    while delivered < MAX_BATCH {
        let idx = (cons & mask) as usize;
        let desc_ptr = (rx.compl_va as *const u8).wrapping_add(idx * DQO_RX_COMPL_SIZE);
        // packet_len LE16 at offset 4: bits[13:0]=len, bit14=generation.
        let pkt_word = u16::from_le_bytes([
            unsafe { ptr::read_volatile(desc_ptr.add(4)) },
            unsafe { ptr::read_volatile(desc_ptr.add(5)) },
        ]);
        let desc_gen = ((pkt_word >> 14) & 1) as u8;
        if desc_gen != cur_gen { break; }

        let pkt_len = (pkt_word & 0x3FFF) as usize;
        let status = unsafe { ptr::read_volatile(desc_ptr.add(8)) };
        let buf_id = u16::from_le_bytes([
            unsafe { ptr::read_volatile(desc_ptr.add(12)) },
            unsafe { ptr::read_volatile(desc_ptr.add(13)) },
        ]) as u32;

        if buf_id < DQO_RX_POOL_BUFS && (status & DQO_RX_COMPL_STATUS_EOP) != 0 && pkt_len > 0 {
            let buf_va = rx.qpl_base_va + (buf_id as u64) * (RX_BUFFER_SIZE as u64);
            if qp < RX_BYTES_PER_QP.len() {
                RX_BYTES_PER_QP[qp].fetch_add(pkt_len as u64, Ordering::Relaxed);
            }
            // Hand the buf_id-backed page to the callback as a
            // `&[u8]`. Valid for the duration of the callback only —
            // the inline repost below puts buf_id back on the data
            // ring, where the device may overwrite it on its next
            // pass. Callback must copy out anything it wants to keep.
            //
            // SAFETY: `buf_va` is the DMA-coherent buffer for buf_id
            // posted at init; `pkt_len <= RX_BUFFER_SIZE` is enforced
            // by the device (descriptor length field).
            let frame: &[u8] = unsafe {
                core::slice::from_raw_parts(buf_va as *const u8, pkt_len)
            };
            callback(frame);

            // Repost buf_id at the next free data-ring slot —
            // inline, no MMIO doorbell here (a single batch-end
            // doorbell below covers all reposts in this poll).
            let fill = rx.fill_cnt.load(Ordering::Relaxed);
            let post_idx = (fill & mask) as usize;
            let post_ptr = (rx.data_va as *mut u8).wrapping_add(post_idx * DQO_RX_DESC_SIZE);
            let mut post_desc = [0u8; DQO_RX_DESC_SIZE];
            post_desc[0..2].copy_from_slice(&(buf_id as u16).to_le_bytes());
            let buf_phys = rx.qpl_base_phys + (buf_id as u64) * (RX_BUFFER_SIZE as u64);
            post_desc[8..16].copy_from_slice(&buf_phys.to_le_bytes());
            unsafe { ptr::copy_nonoverlapping(post_desc.as_ptr(), post_ptr, DQO_RX_DESC_SIZE); }
            rx.fill_cnt.store(fill.wrapping_add(1), Ordering::Release);
            rx.cons_cnt.store(cons.wrapping_add(1), Ordering::Relaxed);
            delivered += 1;
        }

        cons = cons.wrapping_add(1);
        if (cons & mask) == 0 {
            cur_gen ^= 1;
        }
    }

    rx.cons_cnt.store(cons, Ordering::Release);
    rx.expected_seq.store(cur_gen, Ordering::Relaxed);

    if delivered > 0 {
        let bar2_va = BAR2_VA.load(Ordering::Acquire);
        let fill = rx.fill_cnt.load(Ordering::Relaxed);
        // Doorbell wants the masked tail position (Linux:
        // `iowrite32(bufq->tail, db)` where `bufq->tail` is always
        // `& bufq->mask`). Our cumulative `fill_cnt` grows
        // unbounded; mask it before writing.
        doorbell_write_le(bar2_va, rx.db_offset, fill & mask);
    }

    delivered
}
