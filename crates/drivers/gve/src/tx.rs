// TX dispatch — the public send/submit entry points and the GQI vs
// DQO mode switch on the send path.
//
// Each function here checks `QUEUE_FORMAT_DQO` once (one Acquire load
// + branch), then jumps to the per-format datapath in `gqi` / `dqo`.
// Slot acquisition (small / TSO / UDP-GSO direct-fill) is GQI-only —
// DQO acquire functions return `None` and callers fall back to the
// slice-shaped `send_on_qp` path (one extra memcpy per frame).
//
// Doorbell-batching policy lives here too: `flush_tx_kick_if_dirty_qp`
// is what makes the deferred-kick mode safe — the kernel event loop
// calls it once per service pass so anything `send_on_qp` enqueued
// without a doorbell write lands on the wire before the CPU idles.

use core::sync::atomic::Ordering;

use crate::{
    BAR2_VA, DEFERRED_KICK, MAX_QUEUE_PAIRS, NUM_QP, QUEUE_FORMAT_DQO, TX_QUEUES, dqo, gqi,
};

/// Queue-pair index for the current core, or `None` if the driver
/// isn't ready (`num_qp == 0`). Tier 1 mode pins core N to qp N when
/// `N < num_qp`; cores beyond fall back to qp 0 (no NIC TX from them
/// in practice — they handle handlers, not the polling path).
#[inline]
pub(crate) fn current_qp() -> Option<usize> {
    let num_qp = NUM_QP.load(Ordering::Acquire) as u32;
    if num_qp == 0 {
        return None;
    }
    let core = kernel_bare::cpu_id();
    Some(if core < num_qp { core as usize } else { 0 })
}

/// Master gate for hardware UDP-GSO on gve. Drives BOTH the NicOps
/// `udp_gso_available` flag AND `acquire_tx_udp_gso_buf` so they agree
/// (QUIC's `take_gso_datagram_buf` gates on acquire returning `Some`;
/// keeping the two in sync is what lets `udp_gso_available` stay the
/// single switch). Per-format: ON for DQO (the device segments UDP
/// super-packets — see the body), OFF for GQI (unsupported → per-datagram
/// fallback). TODO(productionize): extend to per-device runtime detection
/// so virtio-without-USO / HVF also fall back even if a future format adds
/// the queue type.
pub(crate) fn udp_gso_enabled() -> bool {
    // HW UDP segmentation is DQO-ONLY on gVNIC. Per Google's gve CHANGELOG
    // (v1.4.10: "Enable support for UDP GSO when using DQO format") the
    // device segments UDP super-packets in DQO mode — it infers TCP vs UDP
    // from the IP-protocol byte, so the TSO descriptor path applies as-is.
    // GQI does NOT support it (de-risked on n2/GQI: h3 bulk completed=0,
    // client saw only control packets) → off there, per-datagram fallback.
    QUEUE_FORMAT_DQO.load(Ordering::Acquire)
}

pub(crate) fn acquire_tx_udp_gso_buf() -> Option<nic_api::TxUdpGsoBufHandle> {
    let qp = current_qp()?;
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        // DQO: the UDP-GSO super-packet rides the same big-pool slot +
        // (TSO-ctx, general-ctx, SG pkt) descriptor burst as TCP TSO; the
        // device segments by `gso_size` and picks UDP from the proto byte.
        return dqo::acquire_tx_tso_buf(qp).map(|t| nic_api::TxUdpGsoBufHandle(t.0));
    }
    // GQI: unsupported by the device — caller falls back to per-datagram.
    None
}

pub(crate) fn submit_tx_udp_gso(
    handle: nic_api::TxUdpGsoBufHandle,
    frame_len: usize,
    hdr_len: u16,
    csum_start: u16,
    gso_size: u16,
) {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        // Reuse the DQO TSO submit verbatim — `emit_tso_descs` is L4-
        // protocol-agnostic (the device reads the proto byte); the UDP
        // super-buffer drives UDP segmentation. The handle's token is the
        // shared `encode_tso_token` shape, so rewrapping is sound.
        dqo::submit_tx_tso(
            nic_api::TxTsoBufHandle(handle.0),
            frame_len,
            hdr_len,
            csum_start,
            gso_size,
        );
        return;
    }
    // GQI: unsupported; acquire returns None so this is unreachable, but
    // drop the handle defensively (frees nothing it didn't claim).
    drop(handle);
}

/// Public direct-fill TX entry — picks the calling worker's qp and
/// returns a handle into the per-slot send buffer the caller fills
/// in place (no scratch→buffer memcpy).
///
/// * GQI_QPL: a slot from the two-pool QPL allocator.
/// * DQO_RDA: the next ring slot's bounce buffer
///   ([`dqo::acquire_tx_buf`]). The descriptor emission is the same
///   proven (general-ctx, pkt) pair the slice path uses — RE spaced
///   ≥ 32 descriptors, `tx_head`-driven `done_cnt`. The original DQO
///   direct-fill stall was an RE-on-every-descriptor +
///   completion-decode bug, both long fixed in that shared path.
///
/// Returns `None` when the ring/pool is full; the caller
/// (`build_and_send_frame`) falls back to the slice `send`.
pub(crate) fn acquire_tx_buf() -> Option<nic_api::TxBufHandle> {
    let qp = current_qp()?;
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        return dqo::acquire_tx_buf(qp);
    }
    gqi::acquire_tx_buf_for_qp(qp)
}

/// Public submit — paired with [`acquire_tx_buf`]. Consumes the
/// handle; the slot is freed/recycled on device completion.
/// Dispatches on the negotiated queue format, mirroring `send`.
pub(crate) fn submit_tx(handle: nic_api::TxBufHandle, frame_len: usize, csum: nic_api::CsumOffload) {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        dqo::submit_tx(handle, frame_len, csum);
    } else {
        gqi::submit_tx_inner(handle, frame_len, csum);
    }
}

/// Public TSO acquire — picks the calling worker's qp and returns a
/// big-pool handle for one TSO super-segment (or `None` on pool
/// saturation, so the caller falls back to the per-MSS path).
///
/// * GQI_QPL: a 16 KiB QPL big-pool slot.
/// * DQO_RDA: a ≈20 KiB big-segment bounce slot
///   ([`dqo::acquire_tx_tso_buf`]); `submit_tx_tso` emits the
///   TSO-ctx + general-ctx + scatter-gather packet descriptors.
pub(crate) fn acquire_tx_tso_buf() -> Option<nic_api::TxTsoBufHandle> {
    let qp = current_qp()?;
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        return dqo::acquire_tx_tso_buf(qp);
    }
    gqi::acquire_tx_tso_buf_for_qp(qp)
}

/// Public TSO submit — paired with [`acquire_tx_tso_buf`]. The device
/// segments the super-segment into `gso_size`-byte chunks host-side,
/// fixing up L3/L4 headers and checksums per segment. Dispatches on
/// the negotiated queue format (GQI: TSO+SEG desc pair; DQO: TSO-ctx +
/// general-ctx + SG packet descs).
pub(crate) fn submit_tx_tso(
    handle: nic_api::TxTsoBufHandle,
    frame_len: usize,
    hdr_len: u16,
    csum_start: u16,
    gso_size: u16,
) {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        dqo::submit_tx_tso(handle, frame_len, hdr_len, csum_start, gso_size);
    } else {
        gqi::submit_tx_tso_inner(handle, frame_len, hdr_len, csum_start, gso_size);
    }
}

/// Flush the deferred TX kick for the given queue pair. Returns
/// true if a doorbell write was issued. Called by the event loop
/// after each service pass to push whatever `send_on_qp` batched
/// onto the wire before the CPU sits idle.
pub(crate) fn flush_tx_kick_if_dirty_qp(qp: usize) -> bool {
    if qp >= MAX_QUEUE_PAIRS {
        return false;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() {
        return false;
    }
    let tx = unsafe { &*tx_ptr };
    let fill = tx.fill_cnt.load(Ordering::Relaxed);
    let kicked = tx.last_kicked.load(Ordering::Relaxed);
    if fill == kicked {
        return false;
    }
    let bar2_va = BAR2_VA.load(Ordering::Acquire);
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        // DQO doorbell wants the masked tail position; raw cumulative
        // fill_cnt wraps differently than what the device expects
        // and wedges the queue after the first ring cycle.
        let mask = (tx.ring_entries - 1) as u32;
        dqo::doorbell_write_le(bar2_va, tx.db_offset, fill & mask);
    } else {
        gqi::doorbell_write(bar2_va, tx.db_offset, fill);
    }
    tx.last_kicked.store(fill, Ordering::Relaxed);
    true
}

/// Flush the current core's TX queue if dirty. Matches the
/// `NicOps::flush_tx_kick_if_dirty` signature so the `nic` dispatch
/// crate can call it through the active-ops slot.
pub(crate) fn flush_tx_kick_if_dirty() -> bool {
    match current_qp() {
        Some(qp) => flush_tx_kick_if_dirty_qp(qp),
        None => false,
    }
}

/// Flush every TX queue's pending kick. Not strictly needed in
/// per-core-queue Tier 1 mode (each core's `flush_tx_kick_if_dirty`
/// covers its own queue), but useful if something batches sends
/// across cores. Called from the shim's `flush_tx_staging()`.
pub(crate) fn flush_all_tx_kicks() {
    let n = NUM_QP.load(Ordering::Acquire) as usize;
    for qp in 0..n.min(MAX_QUEUE_PAIRS) {
        flush_tx_kick_if_dirty_qp(qp);
    }
}

/// Diagnostic totals across all active TX queue pairs:
/// `(descriptors submitted = Σ fill_cnt, descriptors completed = Σ done_cnt)`.
/// `done_cnt` is driven by the device's TX completions (descriptors the NIC
/// fetched/transmitted), so this lets `/obs` triangulate egress drops:
/// submitted (our `datagrams_sent`) → NIC-completed (here) → received on the
/// wire (tcpdump). A near-equal fill/done with packets missing on the wire
/// means the NIC transmitted them and the drop is downstream (host/network/
/// receiver); done ≪ fill means our TX/NIC stalled. The u32 ring counters are
/// widened to u64; a short measurement window won't wrap.
pub(crate) fn tx_desc_totals() -> (u64, u64) {
    let mut fill = 0u64;
    let mut done = 0u64;
    let n = (NUM_QP.load(Ordering::Acquire) as usize).min(MAX_QUEUE_PAIRS);
    for qp in 0..n {
        let p = TX_QUEUES[qp].load(Ordering::Acquire);
        if !p.is_null() {
            let tx = unsafe { &*p };
            fill += tx.fill_cnt.load(Ordering::Relaxed) as u64;
            done += tx.done_cnt.load(Ordering::Relaxed) as u64;
        }
    }
    (fill, done)
}

/// Turn on batched TX doorbells. Called once by the kernel after
/// it has wired `flush_tx_kick_if_dirty` into the event loop —
/// without that guarantee the device would never see the doorbell
/// writes and TX would stall once the ring fills.
pub(crate) fn enable_deferred_tx_kick() {
    DEFERRED_KICK.store(true, Ordering::Release);
}

/// Submit a single-segment packet on queue pair `qp`. Returns
/// `true` on success, `false` when the ring has no free slots
/// (device hasn't caught up) or the frame exceeds the format's
/// per-packet limit. Dispatches to GQI_QPL or DQO_RDA based on
/// the queue format committed at init time.
fn send_on_qp(qp: usize, data: &[u8], csum: nic_api::CsumOffload) -> bool {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        dqo::send_on_qp(qp, data, csum)
    } else {
        gqi::send_on_qp(qp, data, csum)
    }
}

/// Per-core TX. Picks the queue pair matching `cpu_id()` when that
/// fits within `num_qp`, else falls back to qp 0. Matches the
/// virtio-net "send on your own core's queue" semantics so Tier 1
/// scaling keeps working.
pub(crate) fn send(data: &[u8], csum: nic_api::CsumOffload) {
    if let Some(qp) = current_qp() {
        let _ = send_on_qp(qp, data, csum);
    }
}
