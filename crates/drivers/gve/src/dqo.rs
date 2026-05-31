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
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use bus::mmio_write32;
use iobuf::{Chain, IOBufDropFn, OwnedIOBuf};

use crate::{
    BAR2_VA, DEFERRED_KICK, MAX_QUEUE_PAIRS, RX_BUF_REPOST_COUNT, RX_BUFFER_SIZE, RX_BYTES_PER_QP,
    RX_QUEUES, RxQueue, TX_QUEUES, TxQueue, record_tx_desc, tx_desc_kind,
};

// ---- DQO_RDA descriptor formats -------------------------------------------

/// DQO TX packet descriptor layout (16 bytes, see `build_pkt_desc`):
///   0..8   buf_addr     (LE64)            DMA addr of packet buffer
///   8      type_flags                     bits[4:0]=dtype (0xC), bit5=end_of_packet,
///                                         bit6=checksum_offload, bit7=report_event
///   9      reserved0
///   10..12 reserved1                      (LE16)
///   12..14 compl_tag                      (LE16)  device echoes in TX completion
///   14..16 buf_size_and_resv              bits[13:0]=buf_size (max 16383)
const DQO_TX_DTYPE_PKT: u8 = 0xC;
/// General context descriptor type, per `gve_desc_dqo.h`'s
/// `GVE_TX_GENERAL_CTX_DESC_DTYPE_DQO`. Linux emits one of
/// these IMMEDIATELY before each data descriptor; without it,
/// our packets miss the metadata preamble the device expects.
const DQO_TX_DTYPE_GENERAL_CTX: u8 = 0x4;
const DQO_TX_FLAG_EOP: u8 = 1 << 5;
/// `checksum_offload_enable` (byte 8 bit 6) — instructs the device
/// to compute the L4 checksum host-side. Equivalent of virtio's
/// NEEDS_CSUM. Per gve_desc_dqo.h.
const DQO_TX_FLAG_CSUM: u8 = 1 << 6;
const DQO_TX_FLAG_REPORT_EVENT: u8 = 1 << 7;
/// `report_event` flags MUST be spaced at least this many TX
/// descriptors apart per `gve_desc_dqo.h`'s GVE_TX_MIN_RE_INTERVAL
/// (= 32). Linux's gve_tx_dqo bumps `last_re_idx` after setting RE
/// and only sets it again once `interval >= 32`. Setting RE on
/// every descriptor (which an earlier version of this driver did)
/// stalls the device under sustained load: completions stop
/// arriving and the per-qp ring saturates at fill_cnt - done_cnt
/// = ring_entries.
pub(crate) const DQO_TX_RE_INTERVAL: u32 = 32;

/// TSO context descriptor type — `GVE_TX_TSO_CTX_DESC_DTYPE_DQO`
/// (`gve_desc_dqo.h`). Goes in byte 8 of the 16-byte descriptor
/// (`cmd_dtype.dtype`, low 5 bits), OR'd with the `tso` bit.
const DQO_TX_DTYPE_TSO_CTX: u8 = 0x5;
/// `cmd_dtype.tso` — bit 5 of the cmd_dtype byte (after the 5-bit
/// dtype). Set on the TSO context descriptor to request segmentation.
const DQO_TX_TSO_CTX_TSO_BIT: u8 = 1 << 5;
/// `GVE_TX_MAX_BUF_SIZE_DQO` = (16 KiB − 1). The 14-bit `buf_size`
/// field caps one packet data descriptor at this many bytes; a buffer
/// longer than this is split across multiple data descriptors
/// (scatter-gather), `end_of_packet` set only on the last.
pub(crate) const GVE_TX_MAX_BUF_SIZE_DQO: u32 = (16 * 1024) - 1;

/// DQO TSO big-segment bounce pool. A TSO super-segment (one TLS
/// record ≈ 16 KiB + headers) doesn't fit a 2 KiB per-ring-slot
/// bounce buffer, so DQO grows the TX bounce allocation by a second
/// pool of `DQO_TX_BIG_SLOTS` slots of `DQO_TX_BIG_SLOT_SIZE` each,
/// appended right after the small per-slot pool. Sizes mirror GQI's
/// big pool (`TX_BIG_POOL_SLOTS` / `TX_BIG_SLOT_SIZE`) and reuse the
/// `TxQueue::big_slot_used` allocator bitmap — GQI and DQO never run
/// at once (one negotiated format per boot).
pub(crate) const DQO_TX_BIG_SLOTS: u32 = crate::TX_BIG_POOL_SLOTS;
pub(crate) const DQO_TX_BIG_SLOT_SIZE: u32 = crate::TX_BIG_SLOT_SIZE;
/// Byte offset of the big pool within the TX bounce allocation — it
/// starts immediately after the small pool (`DQO_TX_POOL_BUFS`
/// buffers of `RX_BUFFER_SIZE`).
pub(crate) const DQO_TX_BIG_POOL_OFFSET: u32 = DQO_TX_POOL_BUFS * (RX_BUFFER_SIZE as u32);
/// `compl_tag` base for big-pool slots. Small (slice / direct-fill)
/// sends use `compl_tag = pkt_idx` (< `TX_RING_ENTRIES`) and are
/// reclaimed by the slot==ring-idx convention; big-pool TSO sends use
/// `compl_tag = DQO_TX_BIG_COMPL_TAG_BASE + big_slot` so `tx_drain`
/// can free the exact big slot when its PKT completion arrives.
const DQO_TX_BIG_COMPL_TAG_BASE: u16 = crate::TX_RING_ENTRIES;
/// Max ring descriptors one TSO submission can consume: TSO-ctx +
/// general-ctx + up to 2 packet data descriptors (a ~16.5 KiB
/// super-segment spans two ≤16383-byte chunks). `acquire_tx_tso_buf`
/// reserves this much ring headroom up front.
const DQO_TX_TSO_MAX_DESCS: u32 = 4;

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
pub static DQO_TX_MISS_COMPL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static DQO_TX_REINJECT_COMPL: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Count of TSO super-segments submitted via `submit_tx_tso` (one per
/// big-pool TSO send, NOT per emitted wire segment). A cold counter —
/// TSO sends are large-response-only, far rarer than the per-packet
/// hot path, so the single relaxed increment is well off the critical
/// chain. Surfaced via `/obs` so a c3 run can confirm the DQO TSO path
/// is actually being exercised (> 0 on `/static-*`, 0 on `/health`).
pub static DQO_TX_TSO_SENT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Count of frames `send_on_qp` rejected because the TX ring was
/// within 2 descriptors of full — the masked-tail == head "device
/// sees an empty ring" hazard guard (see the drop site in
/// `send_on_qp`). Unlike virtio/GQI, the DQO path does NOT spin to
/// wait for a free slot: it returns `false` and the frame is
/// recovered by TCP RTO retransmit. So a non-zero value means
/// latency stalls under TX saturation (one RTO per drop), NOT data
/// loss. This is a COLD-site counter (only bumped when actually
/// dropping); it deliberately avoids the per-send/per-completion hot
/// path, where a shared-cache-line atomic costs ~30% TX throughput
/// (see `DQO_TX_MISS_COMPL` note above).
pub static DQO_TX_RING_FULL_DROPS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Count of RX completion descriptors we saw with a valid generation
/// (device has written this slot) but that we did NOT deliver to the
/// callback because one of: `buf_id` out of range, EOP bit clear, or
/// `pkt_len == 0`. Non-zero means the device is emitting completions
/// for malformed/error packets and the upper stack never sees them.
/// Diagnostic for distinguishing in-driver drops vs NIC/fabric drops.
pub static DQO_RX_COMPL_SKIPPED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// Snapshot of the status byte (offset 8) of the most-recently-seen
/// skipped completion descriptor. Lets us tell whether skipped
/// descs are "EOP clear" (fragmented?), "RX error" (bit-pattern in
/// reserved bits), or some other anomaly without re-flashing.
pub static DQO_RX_LAST_SKIP_STATUS: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);

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
    if tx.tx_compl_va == 0 || tx.tx_compl_entries == 0 {
        return;
    }
    let cmask = (tx.tx_compl_entries - 1) as u32;
    let rmask = (tx.ring_entries - 1) as u32;
    let mut head = tx.tx_compl_head.load(Ordering::Relaxed);
    let mut cur_gen = tx.tx_compl_gen.load(Ordering::Relaxed);
    let mut latest_tx_head: Option<u16> = None;
    loop {
        let idx = (head & cmask) as usize;
        let desc_ptr = (tx.tx_compl_va as *const u8).wrapping_add(idx * DQO_TX_COMPL_SIZE);
        let hdr_word = unsafe { ptr::read_volatile(desc_ptr as *const u16) };
        let desc_gen = ((hdr_word >> 15) & 1) as u8;
        if desc_gen != cur_gen {
            break;
        }
        // Mirror of the RX-side fence — bar LLVM from reordering
        // type/tx_head reads ahead of the gen-bit check.
        core::sync::atomic::compiler_fence(Ordering::Acquire);
        let cmpl_type = ((hdr_word >> 11) & 0x7) as u8;
        match cmpl_type {
            DQO_TX_COMPL_TYPE_DESC => {
                let tx_head = unsafe { ptr::read_volatile(desc_ptr.add(2) as *const u16) };
                latest_tx_head = Some(tx_head);
            }
            DQO_TX_COMPL_TYPE_PKT => {
                // Per Linux, GVE_ALT_MISS_COMPL_BIT can be set on
                // a PKT-typed completion's completion_tag to mean
                // "this is actually a MISS". Read the tag as u16
                // and test the high bit.
                let tag = unsafe { ptr::read_volatile(desc_ptr.add(2) as *const u16) };
                if tag & GVE_ALT_MISS_COMPL_BIT != 0 {
                    DQO_TX_MISS_COMPL.fetch_add(1, Ordering::Relaxed);
                }
                // Big-pool TSO slots are the one case that needs the
                // compl_tag for reclaim: standard sends ride the
                // slot==ring_idx convention (tag < TX_RING_ENTRIES,
                // ignored here), but a TSO super-segment lives in a
                // big-pool slot decoupled from any ring position, so
                // free it when its packet completes. The branch is
                // free for the small-packet hot path (a compare, no
                // atomic) — only big-slot completions touch `_used`.
                let ctag = tag & !GVE_ALT_MISS_COMPL_BIT;
                if ctag >= DQO_TX_BIG_COMPL_TAG_BASE {
                    let big_slot = (ctag - DQO_TX_BIG_COMPL_TAG_BASE) as usize;
                    if big_slot < DQO_TX_BIG_SLOTS as usize {
                        tx.big_slot_used[big_slot].store(false, Ordering::Release);
                    }
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
        // Standard PKT/MISS/REINJECT completions don't drive slot reuse
        // (slot==ring_idx convention); MISS/REINJECT are diagnostic and
        // big-pool TSO slots are freed by `compl_tag` above.
        head = head.wrapping_add(1);
        if (head & cmask) == 0 {
            cur_gen ^= 1;
        }
    }
    tx.tx_compl_head.store(head, Ordering::Relaxed);
    tx.tx_compl_gen.store(cur_gen, Ordering::Relaxed);
    if let Some(tx_head) = latest_tx_head {
        // Translate the device's u16 ring-position `tx_head` into a
        // cumulative `done_cnt` advance. `done_cnt`'s low ring-mask
        // bits and `tx_head` index into the same ring; the masked
        // delta is the descriptor count the device fetched since the
        // last drain.
        //
        // This relies on `send_on_qp` capping `fill_cnt - done_cnt`
        // strictly below `ring_entries` (it leaves a packet of
        // headroom): the device can therefore never have advanced a
        // full ring between drains, which would alias mod-ring_entries
        // to a delta of 0 and freeze `done_cnt`. Don't remove that
        // cap without revisiting this.
        let mask16 = rmask as u16;
        let prev = tx.done_cnt.load(Ordering::Relaxed);
        let prev_low = (prev as u16) & mask16;
        let tx_head_low = tx_head & mask16;
        let delta = (tx_head_low.wrapping_sub(prev_low) & mask16) as u32;
        if delta > 0 {
            tx.done_cnt
                .store(prev.wrapping_add(delta), Ordering::Relaxed);
        }
    }
}

// ---- Outbound frame classification -----------------------------------------

/// Compute the 15-bit TX path-hash for an outbound frame — the
/// 4-tuple hash carried as `path_hash` metadata in the general
/// context descriptor. Linux sets it from `skb->hash` for any flow
/// with `skb->l4_hash`; we fold the same shape from the L4 4-tuple.
/// The device exposes it as an opaque tag in TX completions, mostly
/// informational for the OS's queue tracking. Zero for a non-
/// TCP/UDP frame (ARP, ICMPv6, runt) — there's no 4-tuple to hash.
///
/// CSUM-offload classification used to live here too; it is now the
/// caller's `CsumOffload` hint, threaded in through `send`.
fn tx_path_hash(frame: &[u8]) -> u16 {
    if frame.len() < 14 {
        return 0;
    }
    let etype = u16::from_be_bytes([frame[12], frame[13]]);
    let (l4_proto, l4_off, ip_off, ip_hdr_len) = match etype {
        0x0800 => {
            if frame.len() < 14 + 20 {
                return 0;
            }
            let ihl = (frame[14] & 0x0f) as usize;
            if ihl < 5 {
                return 0;
            }
            (frame[14 + 9], 14 + ihl * 4, 14, ihl * 4)
        }
        0x86dd => {
            if frame.len() < 14 + 40 {
                return 0;
            }
            (frame[14 + 6], 14 + 40, 14, 40)
        }
        _ => return 0,
    };
    if !matches!(l4_proto, 6 | 17) {
        return 0;
    }
    if l4_off + 4 > frame.len() {
        return 0;
    }
    // Cheap 4-tuple hash: XOR-fold the src/dst IP words with the
    // src/dst port words. Linux uses a Jenkins-style hash; we just
    // need something that distributes across distinct flows.
    let mut h: u32 = 0;
    let ip_end = ip_off + ip_hdr_len;
    let ip_addrs_off = match etype {
        0x0800 => ip_off + 12, // IPv4 src+dst at offsets 12-19
        _ => ip_off + 8,       // IPv6 src at 8-23, dst at 24-39
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
    if path_hash == 0 { 0x7fff } else { path_hash }
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

/// Pack a DQO TSO context descriptor into a 16-byte u128. Matches
/// `struct gve_tx_tso_context_desc_dqo` (`gve_desc_dqo.h`, `__packed`):
///
///   bytes 0..3   `tso_total_len:24` (LE) — L4 payload bytes across
///                all segments (`frame_len - header_len`); byte 3 is
///                `flex10` (metadata, 0 for us — the path hash rides
///                the general-ctx desc that follows).
///   bytes 4..6   `mss:14` (LE) + `reserved:2` — the segment size the
///                device cuts the payload into.
///   byte  6      `header_len` — bytes of L2+L3+L4 template the device
///                replicates in front of each segment.
///   byte  7      `flex11` (0)
///   byte  8      `cmd_dtype`: `dtype` (low 5 bits) = 0x5, `tso` = bit 5.
///   byte  9      `cmd_dtype.reserved2` (0)
///   bytes 10..16 `flex0,flex5,flex6,flex7,flex8,flex9` (metadata, 0).
///
/// Layout verified against the verbatim upstream struct; the
/// general-context sibling (same `cmd_dtype` at byte 8) matches our
/// proven `build_ctx_desc`, which anchors the byte offsets.
#[inline]
fn build_tso_ctx_desc(tso_total_len: u32, mss: u16, header_len: u8) -> u128 {
    let mut bytes = [0u8; 16];
    let tl = tso_total_len & 0x00FF_FFFF; // 24-bit; byte 3 (flex10) stays 0
    bytes[0] = (tl & 0xff) as u8;
    bytes[1] = ((tl >> 8) & 0xff) as u8;
    bytes[2] = ((tl >> 16) & 0xff) as u8;
    let m = mss & 0x3FFF;
    bytes[4] = (m & 0xff) as u8;
    bytes[5] = ((m >> 8) & 0x3f) as u8; // top 2 bits are `reserved` = 0
    bytes[6] = header_len;
    bytes[8] = DQO_TX_DTYPE_TSO_CTX | DQO_TX_TSO_CTX_TSO_BIT;
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

/// Reserve room for one more packet (a general-ctx + pkt descriptor
/// pair) and return the `fill_cnt` to emit at, or `None` if the ring
/// is within the masked-tail headroom of full.
///
/// Drains the completion ring only when we're getting close to a full
/// ring. Linux's `gve_tx_dqo` drains only from NAPI poll, not
/// per-send; the event loop's `poll_qp_inner` keeps `done_cnt` fresh
/// in the common case. Per-send drain was costing significant cycles
/// on the fresh-conn hot path (touching the completion ring's
/// DMA-coherent cache line on every send).
///
/// The headroom check rejects with one packet (2 descriptors) of
/// slack — the TX ring must never fill *completely*. The doorbell
/// carries the masked producer position `fill_cnt & mask`; with a
/// full ring `fill_cnt - done == ring_entries`, so
/// `fill_cnt & mask == done & mask` — the masked tail collides with
/// the device's head, and the device reads tail == head as "ring
/// empty" and stops servicing the queue entirely. That stall is
/// permanent (the driver then can't send to un-stick it) and silently
/// drops every egress packet, SYN-ACKs included. It's the same
/// masked-position hazard the RX ring already avoids by leaving its
/// last slot empty (see `post_initial_rx_for_qp`). Capping `in_flight`
/// at `ring_entries - 2` guarantees the masked tail and head always
/// differ.
///
/// On `None` the caller bumps `DQO_TX_RING_FULL_DROPS` (slice path) or
/// returns to the slice fallback (direct-fill `acquire_tx_buf`).
///
/// `n_descs` is how many ring descriptors the caller is about to emit
/// (2 for a standard packet's ctx+pkt pair; up to `DQO_TX_TSO_MAX_DESCS`
/// for a TSO super-segment). The headroom check keeps `in_flight`
/// strictly below `ring_entries - 1` so the masked tail never collides
/// with the device head.
#[inline]
fn tx_reserve_n(tx: &TxQueue, n_descs: u32) -> Option<u32> {
    let fill_cnt = tx.fill_cnt.load(Ordering::Relaxed);
    let mut done_cnt = tx.done_cnt.load(Ordering::Relaxed);
    let mut in_flight = fill_cnt.wrapping_sub(done_cnt);
    let ring_entries = tx.ring_entries as u32;
    if in_flight + 64 > ring_entries {
        tx_drain(tx);
        done_cnt = tx.done_cnt.load(Ordering::Relaxed);
        in_flight = fill_cnt.wrapping_sub(done_cnt);
        if in_flight + n_descs > ring_entries - 2 {
            return None;
        }
    }
    Some(fill_cnt)
}

/// Reserve room for one standard packet (general-ctx + pkt pair).
#[inline]
fn tx_reserve(tx: &TxQueue) -> Option<u32> {
    tx_reserve_n(tx, 2)
}

/// `DQO_TX_FLAG_REPORT_EVENT` if at least `DQO_TX_RE_INTERVAL`
/// descriptors have passed since the last RE-flagged one (advancing
/// the marker), else 0. Set on one packet descriptor per interval so
/// the device keeps emitting DESC completions (which drive `done_cnt`)
/// — flagging *every* descriptor instead stalls the queue under load.
#[inline]
fn re_flag(tx: &TxQueue, fill_pos: u32) -> u8 {
    if fill_pos.wrapping_sub(tx.last_re_at_fill.load(Ordering::Relaxed)) >= DQO_TX_RE_INTERVAL {
        tx.last_re_at_fill.store(fill_pos, Ordering::Relaxed);
        DQO_TX_FLAG_REPORT_EVENT
    } else {
        0
    }
}

/// Publish `new_fill` as the producer position and ring the TX
/// doorbell, unless deferred-kick is on and the ring isn't near full.
/// `doorbell_write_le`'s `sfence` drains the store buffer so the
/// descriptors are PCIe-visible before the device sees the advanced
/// tail. Shared by every DQO emit path (standard + TSO).
#[inline]
fn dqo_kick(tx: &TxQueue, bar2_va: u64, new_fill: u32) {
    tx.fill_cnt.store(new_fill, Ordering::Release);
    let done_cnt = tx.done_cnt.load(Ordering::Relaxed);
    let near_full = new_fill.wrapping_sub(done_cnt) >= (tx.ring_entries as u32) - 16;
    if !DEFERRED_KICK.load(Ordering::Relaxed) || near_full {
        let mask = (tx.ring_entries - 1) as u32;
        doorbell_write_le(bar2_va, tx.db_offset, new_fill & mask);
        tx.last_kicked.store(new_fill, Ordering::Relaxed);
    }
}

/// Emit the (general-ctx, pkt) descriptor pair for one packet whose
/// bytes already live in the per-slot bounce buffer at the pkt-desc
/// ring position (DMA address `buf_phys`), advance `fill_cnt` by 2,
/// and doorbell unless deferred. `frame` is the packet bytes — used
/// for the flow path-hash and the descriptor `buf_size`; it must be
/// the same bytes the device will DMA from `buf_phys`.
///
/// Shared by the slice path (`send_on_qp`, after its memcpy into the
/// bounce buffer) and the direct-fill path (`submit_tx`, where the
/// caller filled the slot in place). `buf_phys` must be the bounce
/// buffer for `slot == (fill_cnt + 1) & mask` (the pkt-desc position)
/// — both callers derive it that way, and this fn re-derives the same
/// `pkt_idx` for the ring write and completion tag, so they coincide.
#[inline]
fn emit_ctx_pkt(
    tx: &TxQueue,
    bar2_va: u64,
    fill_cnt: u32,
    buf_phys: u64,
    frame: &[u8],
    csum: nic_api::CsumOffload,
) {
    let mask = (tx.ring_entries - 1) as u32;
    let ctx_idx = (fill_cnt & mask) as usize;
    let pkt_idx = (fill_cnt.wrapping_add(1) & mask) as usize;

    // Flow-hash for Andromeda's per-flow fast path. The CSUM-offload
    // decision is the caller's `csum` hint, applied to the packet
    // descriptor below.
    let path_hash = tx_path_hash(frame);

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
    let ctx_val: u128 = build_ctx_desc(path_hash);
    let ctx_ptr = (tx.ring_va as *mut u128).wrapping_add(ctx_idx);
    unsafe {
        ptr::write_volatile(ctx_ptr, ctx_val);
    }

    // Packet descriptor. RE every 32nd descriptor per the device's
    // GVE_TX_MIN_RE_INTERVAL.
    let mut flags = DQO_TX_DTYPE_PKT | DQO_TX_FLAG_EOP | re_flag(tx, fill_cnt);
    if csum.is_some() {
        flags |= DQO_TX_FLAG_CSUM;
    }
    let pkt_val: u128 = build_pkt_desc(buf_phys, flags, pkt_idx as u16, frame.len() as u16);
    let pkt_ptr = (tx.ring_va as *mut u128).wrapping_add(pkt_idx);
    unsafe {
        ptr::write_volatile(pkt_ptr, pkt_val);
    }

    dqo_kick(tx, bar2_va, fill_cnt.wrapping_add(2));
}

/// `(va, phys)` of the per-slot bounce buffer for the pkt descriptor
/// at `fill_cnt + 1`. The bounce pool mirrors the ring slot 1:1
/// (`DQO_TX_POOL_BUFS == TX_RING_ENTRIES`), so the slot index == the
/// pkt-desc ring position and reuse is implicit as `fill_cnt` cycles
/// past it (gated below `ring_entries - 2` so the device has long
/// finished DMA-reading that buffer before we wrap onto it).
#[inline]
fn pkt_bounce_buf(tx: &TxQueue, fill_cnt: u32) -> (u64, u64) {
    let mask = (tx.ring_entries - 1) as u32;
    let slot = (fill_cnt.wrapping_add(1) & mask) as u32;
    let buf_offset = slot * (RX_BUFFER_SIZE as u32);
    (
        tx.qpl_base_va + buf_offset as u64,
        tx.qpl_base_phys + buf_offset as u64,
    )
}

/// Slice-shaped send: copy `data` into the next ring's bounce buffer,
/// emit a (general-ctx, pkt) descriptor pair, advance fill_cnt,
/// doorbell unless deferred. `csum` enables the device's L4 CSUM
/// offload for the packet descriptor; `tx_path_hash` fills the
/// general-context descriptor's flow-hash.
///
/// This is the fallback for callers that build the frame elsewhere
/// (e.g. control segments, or any path that didn't take the
/// direct-fill `acquire_tx_buf` route). It carries one extra memcpy
/// vs direct-fill — the scratch→bounce copy below.
pub(crate) fn send_on_qp(qp: usize, data: &[u8], csum: nic_api::CsumOffload) -> bool {
    if qp >= MAX_QUEUE_PAIRS || data.is_empty() || data.len() > (RX_BUFFER_SIZE as usize) {
        return false;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() {
        return false;
    }
    let tx = unsafe { &*tx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    let fill_cnt = match tx_reserve(tx) {
        Some(f) => f,
        None => {
            DQO_TX_RING_FULL_DROPS.fetch_add(1, Ordering::Relaxed);
            return false;
        }
    };

    let (buf_va, buf_phys) = pkt_bounce_buf(tx, fill_cnt);
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), buf_va as *mut u8, data.len());
    }
    emit_ctx_pkt(tx, bar2_va, fill_cnt, buf_phys, data, csum);
    true
}

/// DQO direct-fill acquire. Reserve the next packet's bounce-buffer
/// slot and hand the caller a writable view of it so the upper layer
/// (TCP `build_and_send_frame`) assembles the L2 frame directly in
/// the DMA buffer — eliminating the scratch→bounce memcpy the slice
/// `send_on_qp` path pays. Returns `None` when the ring is within the
/// masked-tail headroom of full so the caller falls back to the slice
/// path (which then drops + counts if still full).
///
/// Does NOT advance `fill_cnt`: the matching [`submit_tx`] recomputes
/// the slot from the (unchanged) `fill_cnt` and emits the descriptor
/// pair. Acquire+submit must be paired synchronously on the qp's
/// owning core — Tier 1 pins one core per qp, exactly the contract
/// GQI's direct-fill path already documents. A dropped (unsubmitted)
/// handle is a no-op: `fill_cnt` never moved, so the next acquire
/// returns the same slot (`release_noop`).
///
/// Buffer lifetime is identical to the slice path: the bounce buffer
/// is driver-owned and reused only when `fill_cnt` cycles back onto
/// its ring position, well after the device has DMA-read and
/// completed it (the `tx_reserve` headroom guarantees this). So
/// direct-fill adds no new lifetime hazard over the proven slice
/// path — it just fills the same buffer in place.
pub(crate) fn acquire_tx_buf(qp: usize) -> Option<nic_api::TxBufHandle> {
    if qp >= MAX_QUEUE_PAIRS {
        return None;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() {
        return None;
    }
    let tx = unsafe { &*tx_ptr };
    let fill_cnt = tx_reserve(tx)?;
    let (buf_va, _buf_phys) = pkt_bounce_buf(tx, fill_cnt);
    Some(nic_api::TxBufHandle {
        data_ptr: buf_va as *mut u8,
        data_cap: RX_BUFFER_SIZE as u32,
        driver_token: qp as u64,
        release_fn: release_noop,
    })
}

/// No-op release for a dropped (unsubmitted) DQO direct-fill handle.
/// `acquire_tx_buf` doesn't advance `fill_cnt`, so dropping a handle
/// leaves the ring untouched and the next acquire returns the same
/// slot — there's nothing to free.
fn release_noop(_token: u64) {}

/// DQO direct-fill submit. The caller filled the bounce buffer that
/// [`acquire_tx_buf`] handed back; emit the (ctx, pkt) descriptor
/// pair pointing at it. Recomputes the slot from the current
/// `fill_cnt` — unchanged since acquire under the synchronous-pairing
/// contract, so it addresses exactly the buffer the caller wrote.
pub(crate) fn submit_tx(handle: nic_api::TxBufHandle, frame_len: usize, csum: nic_api::CsumOffload) {
    let qp = handle.driver_token as usize;
    // The slot is going in-flight, not idle — skip the drop's
    // `release_noop` (a no-op anyway; mem::forget keeps the intent
    // explicit and matches GQI's `submit_tx_inner`).
    core::mem::forget(handle);
    if qp >= MAX_QUEUE_PAIRS || frame_len == 0 || frame_len > RX_BUFFER_SIZE as usize {
        return;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() {
        return;
    }
    let tx = unsafe { &*tx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    let fill_cnt = tx.fill_cnt.load(Ordering::Relaxed);
    let (buf_va, buf_phys) = pkt_bounce_buf(tx, fill_cnt);
    // SAFETY: the bounce buffer at this slot was just filled by the
    // caller via the handle's `data_mut()`; the device DMAs the same
    // `frame_len` bytes from `buf_phys`. Reading them back here for
    // the flow path-hash is sound (driver-owned DMA-coherent memory,
    // `frame_len <= RX_BUFFER_SIZE` checked above).
    let frame = unsafe { core::slice::from_raw_parts(buf_va as *const u8, frame_len) };
    emit_ctx_pkt(tx, bar2_va, fill_cnt, buf_phys, frame, csum);
}

// ---- TSO (TCP segmentation offload) ----------------------------------------

/// `(va, phys)` of DQO big-pool TSO slot `big_slot`. The big pool is
/// appended after the small per-ring-slot bounce pool in the same TX
/// bounce allocation (see `DQO_TX_BIG_POOL_OFFSET`).
#[inline]
fn big_slot_addr(tx: &TxQueue, big_slot: usize) -> (u64, u64) {
    let off = DQO_TX_BIG_POOL_OFFSET + (big_slot as u32) * DQO_TX_BIG_SLOT_SIZE;
    (tx.qpl_base_va + off as u64, tx.qpl_base_phys + off as u64)
}

/// Encode `(qp, big_slot)` into a TSO handle's `driver_token`. Bit 63
/// marks the big pool — distinct from the small-pool direct-fill token
/// (`= qp`), though they also flow through type-distinct handles
/// (`TxTsoBufHandle` vs `TxBufHandle`) and separate submit fns.
#[inline]
fn encode_tso_token(qp: usize, big_slot: usize) -> u64 {
    (1u64 << 63) | (((qp as u64) & 0xFFFF) << 32) | (big_slot as u64 & 0xFFFF)
}

#[inline]
fn decode_tso_token(token: u64) -> (usize, usize) {
    (((token >> 32) & 0xFFFF) as usize, (token & 0xFFFF) as usize)
}

/// Release a dropped (unsubmitted, or validation-rejected) TSO handle:
/// free its big-pool slot. On the success path `submit_tx_tso`
/// `mem::forget`s the handle instead, so the slot stays claimed until
/// its TX completion frees it (`tx_drain`, by `compl_tag`).
fn release_big_slot(token: u64) {
    let (qp, big_slot) = decode_tso_token(token);
    if qp >= MAX_QUEUE_PAIRS {
        return;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() {
        return;
    }
    let tx = unsafe { &*tx_ptr };
    if big_slot < DQO_TX_BIG_SLOTS as usize {
        tx.big_slot_used[big_slot].store(false, Ordering::Release);
    }
}

/// DQO TSO acquire. Reserve ring headroom for the (TSO-ctx,
/// general-ctx, ≤2 pkt) descriptor burst and claim a big-pool slot
/// (≈20 KiB) for the caller to assemble one TSO super-segment into
/// (header + up to one TLS record of payload). Returns `None` when the
/// ring lacks headroom or the big pool is saturated — the caller
/// (`send_super_segment_from_cursor` / `try_send_tso`) then falls back
/// to the per-MSS path. Doesn't spin: TSO is best-effort batching.
///
/// Does NOT advance `fill_cnt`; `submit_tx_tso` emits the descriptors.
/// Acquire+submit pair synchronously on the qp's owning core (Tier 1),
/// same contract as the standard direct-fill path.
pub(crate) fn acquire_tx_tso_buf(qp: usize) -> Option<nic_api::TxTsoBufHandle> {
    if qp >= MAX_QUEUE_PAIRS {
        return None;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() {
        return None;
    }
    let tx = unsafe { &*tx_ptr };
    tx_reserve_n(tx, DQO_TX_TSO_MAX_DESCS)?;
    for slot in 0..(DQO_TX_BIG_SLOTS as usize) {
        if !tx.big_slot_used[slot].load(Ordering::Acquire) {
            tx.big_slot_used[slot].store(true, Ordering::Relaxed);
            let (va, _phys) = big_slot_addr(tx, slot);
            return Some(nic_api::TxTsoBufHandle(nic_api::TxBufHandle {
                data_ptr: va as *mut u8,
                data_cap: DQO_TX_BIG_SLOT_SIZE,
                driver_token: encode_tso_token(qp, slot),
                release_fn: release_big_slot,
            }));
        }
    }
    None
}

/// DQO TSO submit. The caller filled the big-pool slot with one
/// super-segment `[L2|L3|L4 headers][payload]` of `frame_len` bytes
/// (`hdr_len` of header). Emit the descriptor burst the device needs
/// to segment it host-side into `gso_size`-byte chunks:
///
///   1. TSO context desc (`tso_total_len = frame_len - hdr_len`,
///      `mss = gso_size`, `header_len = hdr_len`).
///   2. General context desc (carries the 4-tuple path hash).
///   3. One or more packet data descs covering the whole buffer,
///      split at `GVE_TX_MAX_BUF_SIZE_DQO` (scatter-gather),
///      `end_of_packet` only on the last, `checksum_offload_enable`
///      set (the device computes each segment's L4 checksum).
///
/// `csum_start` is unused on DQO: unlike GQI's descriptor (explicit
/// l4 offsets), the DQO device parses the headers itself, bounded by
/// `header_len` from the TSO ctx. The caller still zeroes the template
/// L4 checksum field so the device fills it per segment.
///
/// On any validation failure `handle` is dropped → `release_big_slot`
/// frees the slot; on success the handle is `mem::forget`-ed and the
/// slot is freed later when its PKT completion arrives (`tx_drain`),
/// since the device DMA-reads the slot until then.
pub(crate) fn submit_tx_tso(
    handle: nic_api::TxTsoBufHandle,
    frame_len: usize,
    hdr_len: u16,
    _csum_start: u16,
    gso_size: u16,
) {
    let (qp, big_slot) = decode_tso_token(handle.0.driver_token);
    if qp >= MAX_QUEUE_PAIRS || big_slot >= DQO_TX_BIG_SLOTS as usize {
        return; // drop frees the slot
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() {
        return; // drop frees the slot
    }
    let tx = unsafe { &*tx_ptr };
    if frame_len == 0
        || frame_len > DQO_TX_BIG_SLOT_SIZE as usize
        || hdr_len as usize >= frame_len
        || gso_size == 0
    {
        return; // drop frees the slot
    }
    let bar2_va = BAR2_VA.load(Ordering::Acquire);
    let (buf_va, buf_phys) = big_slot_addr(tx, big_slot);
    // SAFETY: the caller filled `frame_len` bytes of this big slot via
    // the handle's `data_mut()`; the device DMAs the same bytes. We
    // read them here only for the flow path-hash.
    let frame = unsafe { core::slice::from_raw_parts(buf_va as *const u8, frame_len) };
    emit_tso_descs(tx, qp, bar2_va, big_slot, buf_phys, frame, hdr_len, gso_size);
    // Slot is in-flight; the PKT completion (compl_tag) frees it.
    core::mem::forget(handle);
}

/// Emit the TSO descriptor burst (TSO-ctx, general-ctx, SG pkt descs)
/// for a super-segment already in big-pool slot `big_slot` at DMA
/// address `buf_phys`, advance `fill_cnt`, doorbell unless deferred.
fn emit_tso_descs(
    tx: &TxQueue,
    qp: usize,
    bar2_va: u64,
    big_slot: usize,
    buf_phys: u64,
    frame: &[u8],
    hdr_len: u16,
    gso_size: u16,
) {
    let mask = (tx.ring_entries - 1) as u32;
    let fill_cnt = tx.fill_cnt.load(Ordering::Relaxed);
    let frame_len = frame.len();
    let compl_tag = DQO_TX_BIG_COMPL_TAG_BASE + big_slot as u16;
    let tso_total_len = (frame_len - hdr_len as usize) as u32;

    // desc 0: TSO context. Capture it for `/diag-gve` — the byte-exact
    // TSO-ctx layout is the one thing on this path the device silently
    // drops if wrong, and serial is gated on GCE, so this is how we
    // read back what we wrote on a live c3.
    let tso_val = build_tso_ctx_desc(tso_total_len, gso_size, hdr_len as u8);
    record_tx_desc(qp as u8, tx_desc_kind::TSO, &tso_val.to_le_bytes());
    let tso_ptr = (tx.ring_va as *mut u128).wrapping_add((fill_cnt & mask) as usize);
    unsafe {
        ptr::write_volatile(tso_ptr, tso_val);
    }
    // desc 1: general context (flow path hash).
    let gctx_val = build_ctx_desc(tx_path_hash(frame));
    let gctx_ptr = (tx.ring_va as *mut u128).wrapping_add((fill_cnt.wrapping_add(1) & mask) as usize);
    unsafe {
        ptr::write_volatile(gctx_ptr, gctx_val);
    }

    // desc 2..: packet data descriptors covering the whole buffer,
    // scatter-gather split at GVE_TX_MAX_BUF_SIZE_DQO, EOP on the last.
    let mut desc_off = 2u32;
    let mut remaining = frame_len;
    let mut addr = buf_phys;
    while remaining > 0 {
        let chunk = remaining.min(GVE_TX_MAX_BUF_SIZE_DQO as usize);
        let is_last = chunk == remaining;
        // The device computes each emitted segment's L4 checksum. EOP +
        // an RE flag (per the 32-desc interval) go on the last desc.
        let mut flags = DQO_TX_DTYPE_PKT | DQO_TX_FLAG_CSUM;
        if is_last {
            flags |= DQO_TX_FLAG_EOP | re_flag(tx, fill_cnt.wrapping_add(desc_off));
        }
        let pkt_val = build_pkt_desc(addr, flags, compl_tag, chunk as u16);
        record_tx_desc(qp as u8, tx_desc_kind::SEG, &pkt_val.to_le_bytes());
        let pkt_ptr =
            (tx.ring_va as *mut u128).wrapping_add((fill_cnt.wrapping_add(desc_off) & mask) as usize);
        unsafe {
            ptr::write_volatile(pkt_ptr, pkt_val);
        }
        addr += chunk as u64;
        remaining -= chunk;
        desc_off += 1;
    }

    DQO_TX_TSO_SENT.fetch_add(1, Ordering::Relaxed);
    dqo_kick(tx, bar2_va, fill_cnt.wrapping_add(desc_off));
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
        unsafe {
            ptr::copy_nonoverlapping(desc.as_ptr(), desc_ptr, DQO_RX_DESC_SIZE);
        }
    }
    rx.fill_cnt.store(initial, Ordering::Release);
    let bar2_va = BAR2_VA.load(Ordering::Acquire);
    doorbell_write_le(bar2_va, rx.db_offset, initial & mask);
}

/// Drop callback for a delivered DQO RX `IOBuf` — reposts the
/// device buffer `buf_id` to the data-buffer ring. Installed by
/// [`poll_qp_inner`] via [`OwnedIOBuf::wrap_owned`]; runs from
/// `IOBuf::drop`, possibly on a core other than the one that
/// received the frame (item C moves chains cross-core).
///
/// `ctx` packs `(qp << 16) | buf_id` — both small (qp < 8, buf_id
/// < `DQO_RX_POOL_BUFS`), so no allocation is needed for the
/// context. `base` / `capacity` are the originals from
/// `wrap_owned` and are not needed here (buf_id is the device
/// handle); they're accepted to satisfy [`IOBufDropFn`].
///
/// Cross-core repost safety: each invocation reserves a unique
/// data-ring slot via an atomic `fetch_add` on `fill_cnt`, writes
/// its 32-byte buffer descriptor there, and rings the doorbell.
/// `doorbell_write_le`'s `host_dma_fence` (an `sfence`) drains
/// this core's store buffer so the descriptor bytes are
/// PCIe-visible before the device sees the advanced tail. With
/// item B's inline-on-the-polling-core drops the reservations are
/// serialized, so the doorbell values are monotonic; the
/// cross-core case (item C) where a higher-slot doorbell could
/// race a lower-slot descriptor write is a known follow-up that
/// needs a contiguous-publish cursor.
///
/// Panic-safe: an out-of-range `qp` or a null queue pointer leaks
/// the buffer (the RX pool shrinks by one) rather than panicking —
/// a panic in a `#![no_std]` `Drop` is poison. Neither is
/// reachable under correct use; both arise only from a corrupted
/// `ctx`.
unsafe fn dqo_repost(_base: NonNull<u8>, _capacity: u32, ctx: *mut ()) {
    let packed = ctx as usize;
    let qp = (packed >> 16) & 0xFFFF;
    let buf_id = (packed & 0xFFFF) as u32;
    if qp >= MAX_QUEUE_PAIRS {
        return; // impossible under correct use — leak, never panic
    }
    let rx_ptr = RX_QUEUES[qp].load(Ordering::Acquire);
    if rx_ptr.is_null() {
        return; // queue torn down — leak the buffer
    }
    // SAFETY: pointer published once at init with Release; the
    // non-atomic fields read here (ring_entries, data_va,
    // qpl_base_phys, db_offset) are init-only, and the Acquire
    // load above synchronises with their publish.
    let rx = unsafe { &*rx_ptr };
    let mask = (rx.ring_entries - 1) as u32;

    // Reserve a data-ring slot. `Release` publishes the descriptor
    // write that follows to any core that later `Acquire`-reads
    // `fill_cnt` (the cross-core observation item C relies on).
    let slot = rx.fill_cnt.fetch_add(1, Ordering::Release);
    let post_idx = (slot & mask) as usize;
    let post_ptr = (rx.data_va as *mut u8).wrapping_add(post_idx * DQO_RX_DESC_SIZE);
    let mut post_desc = [0u8; DQO_RX_DESC_SIZE];
    post_desc[0..2].copy_from_slice(&(buf_id as u16).to_le_bytes());
    let buf_phys = rx.qpl_base_phys + (buf_id as u64) * (RX_BUFFER_SIZE as u64);
    post_desc[8..16].copy_from_slice(&buf_phys.to_le_bytes());
    // SAFETY: `post_idx < ring_entries`, so `post_ptr` addresses
    // one 32-byte descriptor inside the data ring allocated at init.
    unsafe {
        ptr::copy_nonoverlapping(post_desc.as_ptr(), post_ptr, DQO_RX_DESC_SIZE);
    }

    // Doorbell the new masked tail. The fence inside drains the
    // store buffer so the descriptor above is visible to the
    // device's DMA read before it sees the tail advance.
    let bar2_va = BAR2_VA.load(Ordering::Acquire);
    doorbell_write_le(bar2_va, rx.db_offset, slot.wrapping_add(1) & mask);

    if qp < RX_BUF_REPOST_COUNT.len() {
        RX_BUF_REPOST_COUNT[qp].fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn poll_qp_inner<F: FnMut(Chain<OwnedIOBuf>)>(qp: usize, mut callback: F) -> u32 {
    if qp >= MAX_QUEUE_PAIRS {
        return 0;
    }
    let rx_ptr = RX_QUEUES[qp].load(Ordering::Acquire);
    if rx_ptr.is_null() {
        return 0;
    }
    let rx = unsafe { &*rx_ptr };

    let mask = (rx.ring_entries - 1) as u32;
    let mut cons = rx.cons_cnt.load(Ordering::Relaxed);
    let mut cur_gen = rx.expected_seq.load(Ordering::Relaxed);
    let mut delivered: u32 = 0;
    const MAX_BATCH: u32 = 64;

    while delivered < MAX_BATCH {
        let idx = (cons & mask) as usize;
        let desc_ptr = (rx.compl_va as *const u8).wrapping_add(idx * DQO_RX_COMPL_SIZE);
        // Read pkt_word + len + gen + bq_id as a single aligned u16
        // (was byte-by-byte). The descriptor is at a 32-byte-aligned
        // offset inside a page-aligned ring; the u16 at offset 4 is
        // naturally aligned. A single-instruction load is atomic at
        // the CPU level, eliminating a software-level tearing window
        // between the two bytes — without this, if the device's TLP
        // updates the cache line exactly between the two byte loads,
        // we'd assemble a half-old/half-new u16.
        let pkt_word = unsafe { ptr::read_volatile(desc_ptr.add(4) as *const u16) };
        let desc_gen = ((pkt_word >> 14) & 1) as u8;
        if desc_gen != cur_gen {
            break;
        }
        // `compiler_fence(Acquire)` is Linux's `dma_rmb()` analog: on
        // x86 it doesn't emit a hardware fence (TSO already orders
        // loads) but it bars LLVM from hoisting the subsequent
        // volatile loads of status/buf_id ahead of the gen-bit
        // observation.
        core::sync::atomic::compiler_fence(Ordering::Acquire);

        let pkt_len = (pkt_word & 0x3FFF) as usize;
        let status = unsafe { ptr::read_volatile(desc_ptr.add(8)) };
        // buf_id at offset 12 — aligned u16 read, same rationale as
        // pkt_word above.
        let buf_id = unsafe { ptr::read_volatile(desc_ptr.add(12) as *const u16) } as u32;

        let deliver =
            buf_id < DQO_RX_POOL_BUFS && (status & DQO_RX_COMPL_STATUS_EOP) != 0 && pkt_len > 0;
        if deliver {
            let buf_va = rx.qpl_base_va + (buf_id as u64) * (RX_BUFFER_SIZE as u64);
            if qp < RX_BYTES_PER_QP.len() {
                RX_BYTES_PER_QP[qp].fetch_add(pkt_len as u64, Ordering::Relaxed);
            }
            // Wrap the device's RX buffer as an owned, one-part
            // IOBufChain. DQO_RDA descriptors carry raw DMA
            // addresses, so the device buffer can be lent straight
            // up the stack with no copy. `dqo_repost` puts buf_id
            // back on the data ring when the chain's IOBuf drops —
            // the slice-shaped path's explicit inline repost now
            // lives entirely in that drop callback, so it fires
            // wherever (and on whichever core) the chain is
            // released.
            //
            // SAFETY: `buf_va` is the DMA-coherent buffer for
            // buf_id (non-null, posted at init); `pkt_len <=
            // RX_BUFFER_SIZE` is enforced by the device's
            // descriptor length field, so `0 + pkt_len <=
            // capacity`. `dqo_repost` is sound to invoke once at
            // drop and panic-safe; `(qp, buf_id)` packed in `ctx`
            // survives the cross-core move `ExternalOwned` allows.
            let ctx = (((qp & 0xFFFF) << 16) | (buf_id as usize & 0xFFFF)) as *mut ();
            let owned = unsafe {
                OwnedIOBuf::wrap_owned(
                    NonNull::new_unchecked(buf_va as *mut u8),
                    RX_BUFFER_SIZE as u32,
                    0,
                    pkt_len as u32,
                    dqo_repost as IOBufDropFn,
                    ctx,
                )
            };
            callback(Chain::from(owned));
            delivered += 1;
        } else {
            DQO_RX_COMPL_SKIPPED.fetch_add(1, Ordering::Relaxed);
            DQO_RX_LAST_SKIP_STATUS.store(status, Ordering::Relaxed);
            // Observability doctrine: retain the qp + a timestamp
            // alongside the status byte (`docs/observability.md`).
            crate::diag::record_rx_skip(qp as u8, status);
        }

        cons = cons.wrapping_add(1);
        if (cons & mask) == 0 {
            cur_gen ^= 1;
        }
    }

    rx.cons_cnt.store(cons, Ordering::Release);
    rx.expected_seq.store(cur_gen, Ordering::Relaxed);

    // No batch-end RX doorbell here: each delivered buffer reposts
    // itself — descriptor write + masked-tail doorbell — from
    // `dqo_repost` when its chain drops. With item B's inline drops
    // that is one doorbell per frame instead of one per poll batch;
    // the cost is measured at the GCE checkpoint (expected ±0% for
    // DQO; a posted BAR2 write is cheap).

    // Drain the TX completion ring for this qp from the poll path,
    // matching Linux's NAPI-clean pattern. Keeps `done_cnt` fresh
    // so `send_on_qp` (above) can skip its per-send drain in the
    // common case. We do this regardless of whether RX delivered
    // anything — the event loop calls us at high frequency.
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if !tx_ptr.is_null() {
        let tx = unsafe { &*tx_ptr };
        tx_drain(tx);
    }

    delivered
}
