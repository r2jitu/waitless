// drivers/net.rs — NIC dispatch through `uni_net_driver::active_ops()`.
//
// `init()` walks `linked_ethernet_drivers()`, calls the `probe` fn
// pointer on each registration, and installs the first success into
// the active-ops slot. Before that — and on native, where no section
// exists — `active_ops()` resolves to `NULL_OPS` (all no-ops), so
// every dispatcher below is a single load + direct call with no
// null branch.

use uni_net_driver::{
    active_ops, is_installed, linked_ethernet_drivers, set_active_ops, Chain, OwnedIOBuf,
};

pub use uni_net_driver::{CsumOffload, CsumStampConvention};

// ---- Init / lifecycle -----------------------------------------------------

/// Installs the first driver whose `probe` succeeds.
pub fn init() -> bool {
    for reg in linked_ethernet_drivers() {
        if (reg.ops.probe)() {
            set_active_ops(reg.ops);
            return true;
        }
    }
    false
}

pub fn get_mac(mac_out: *mut u8) { (active_ops().get_mac)(mac_out) }
pub fn num_queue_pairs() -> u16 { (active_ops().num_queue_pairs)() }
pub fn driver_name() -> &'static str { active_ops().name }
pub fn enable_irq() { (active_ops().enable_irq)() }

// ---- RX / TX datapath -----------------------------------------------------

/// Drain every queue pair into `callback`, one owned
/// `Chain<OwnedIOBuf>` per received frame. The callback owns the
/// chain and may retain it past return — each part's drop callback
/// reposts the backing buffer to the device / pool. Used by Tier 2
/// (single-queue distribute) and the pre-`set_ready` boot window
/// where APs aren't polling yet.
pub fn poll(callback: fn(Chain<OwnedIOBuf>)) -> usize {
    (active_ops().poll_rx)(callback)
}

/// Per-queue variant for Tier 1 multi-queue, where each core only
/// polls its own RX queue pair.
pub fn poll_qp(qp: usize, callback: fn(Chain<OwnedIOBuf>)) -> usize {
    (active_ops().poll_qp)(qp, callback)
}

pub fn send(data: &[u8]) { (active_ops().send)(data) }

/// Acquire a writable TX buffer from the driver's pool. Caller fills
/// the returned region in place, then [`submit_tx`]s it for
/// transmission. Returns `None` when the driver doesn't support
/// the direct-fill path (Tier 2 shared queue, GVE, native), or
/// when the pool is full — caller falls back to [`send`] (which
/// memcpys through the legacy slice path).
///
/// On `Some(handle)`:
///   * Caller writes the L2 frame into `handle.data_mut()[..len]`.
///   * Caller hands the handle to [`submit_tx`].
///   * Dropping the handle without submission returns the slot
///     to the pool (the caller's error path doesn't need to do
///     bookkeeping).
pub fn acquire_tx_buf() -> Option<uni_net_driver::TxBufHandle> {
    let f = active_ops().acquire_tx_buf?;
    f()
}

/// Submit a previously-acquired TX buffer with `frame_len` bytes of
/// frame data at the head of `handle.data_mut()`. Consumes the
/// handle. `csum` is the optional L4-checksum-offload hint — pass
/// [`uni_net_driver::CsumOffload::NONE`] when the caller already
/// computed and stamped the L4 checksum.
pub fn submit_tx(
    handle: uni_net_driver::TxBufHandle,
    frame_len: usize,
    csum: uni_net_driver::CsumOffload,
) {
    if let Some(f) = active_ops().submit_tx {
        f(handle, frame_len, csum);
    } else {
        // Only reachable via API misuse — `acquire_tx_buf` returns
        // `None` when the driver lacks the surface, so a caller that
        // does proper acquire+submit can never end up here. Drop the
        // handle (its `Drop` returns the slot to the pool).
        drop(handle);
    }
}

/// True iff the driver negotiated TSOv4 (`VIRTIO_NET_F_HOST_TSO4`
/// + `VIRTIO_NET_F_CSUM`, or equivalent). When true,
/// [`acquire_tx_tso_buf`] returns 16-KiB-capacity slots that
/// the TCP layer fills with a single super-segment and ships
/// via [`submit_tx_tso`].
pub fn tso_available() -> bool {
    (active_ops().tso_available)()
}

/// True iff the driver supports L4 checksum-offload-on-TX
/// (`VIRTIO_NET_F_CSUM` or equivalent). Callers branch on
/// this AND on [`csum_stamp_convention`] to decide what
/// (if anything) to stamp at the L4 checksum field.
pub fn csum_tx_offload() -> bool {
    (active_ops().csum_tx_offload)()
}

/// What value the active driver expects at the L4 checksum
/// field when CSUM offload is requested. Returns
/// `PseudoHeaderPartial` for virtio-class NICs, `Zero` for gve.
/// Only meaningful when [`csum_tx_offload`] returns `true`.
pub fn csum_stamp_convention() -> CsumStampConvention {
    (active_ops().csum_stamp_convention)()
}

/// Acquire a big-slot TX buffer (16 KiB capacity) for a TCP TSO
/// super-segment. Returns `None` when TSO isn't negotiated, the
/// big pool is full, or the driver doesn't support this surface;
/// caller falls back to per-MSS segmentation via
/// [`acquire_tx_buf`].
///
/// Returns a [`TxTsoBufHandle`] — type-distinct from
/// [`TxBufHandle`] so it can only be submitted via
/// [`submit_tx_tso`], not via [`submit_tx`].
pub fn acquire_tx_tso_buf() -> Option<uni_net_driver::TxTsoBufHandle> {
    let f = active_ops().acquire_tx_tso_buf?;
    f()
}

/// Submit a TSO super-segment for TCPv4. Same shape as
/// [`submit_tx`] plus the gso fields: `hdr_len` is the offset
/// of the TCP payload (Eth + IP + TCP), `csum_start` is the
/// offset of the TCP header (Eth + IP), `gso_size` is the MSS.
/// The device segments the payload into `gso_size`-byte chunks
/// host-side and computes per-segment TCP checksums.
///
/// Caller must have verified [`tso_available`] before reaching
/// this; if the surface is unavailable, the slot is returned
/// to the pool and no traffic emitted.
pub fn submit_tx_tso(
    handle: uni_net_driver::TxTsoBufHandle,
    frame_len: usize,
    hdr_len: u16,
    csum_start: u16,
    gso_size: u16,
) {
    if let Some(f) = active_ops().submit_tx_tso {
        f(handle, frame_len, hdr_len, csum_start, gso_size);
    } else {
        drop(handle);
    }
}

/// True iff the driver advertises UDP-GSO (UDP analogue of TSO).
pub fn udp_gso_available() -> bool {
    (active_ops().udp_gso_available)()
}

/// Acquire a 16-KiB big-slot for a UDP-GSO super-packet. None
/// when the surface isn't supported or the big pool is full;
/// caller falls back to per-datagram `acquire_tx_buf` sends.
pub fn acquire_tx_udp_gso_buf() -> Option<uni_net_driver::TxUdpGsoBufHandle> {
    let f = active_ops().acquire_tx_udp_gso_buf?;
    f()
}

/// Submit a UDP-GSO super-packet. The slot bytes are laid out as
/// `[Eth | IP | UDP | seg₀ | seg₁ | … | seg_N]` and the device
/// emits N UDP datagrams with the UDP header replicated per
/// segment. See [`uni_net_driver::NicOps::submit_tx_udp_gso`] for
/// field semantics.
pub fn submit_tx_udp_gso(
    handle: uni_net_driver::TxUdpGsoBufHandle,
    frame_len: usize,
    hdr_len: u16,
    csum_start: u16,
    gso_size: u16,
) {
    if let Some(f) = active_ops().submit_tx_udp_gso {
        f(handle, frame_len, hdr_len, csum_start, gso_size);
    } else {
        drop(handle);
    }
}

// ---- Idle / TX-flush knobs -----------------------------------------------

pub fn flush_tx_staging() { (active_ops().flush_tx_staging)() }
pub fn flush_tx_kick_if_dirty() -> bool { (active_ops().flush_tx_kick_if_dirty)() }
pub fn enable_deferred_tx_kick() { (active_ops().enable_deferred_tx_kick)() }
pub fn poke_interrupt_status() { (active_ops().poke_interrupt_status)() }

/// Presence of `idle` ops is the signal — NAPI-capable drivers
/// populate it, polling-only drivers leave it `None`.
pub fn irq_idle_supported() -> bool { active_ops().idle.is_some() }

pub fn arm_rx_interrupts() {
    if let Some(i) = active_ops().idle { (i.arm_rx_interrupts)(); }
}
pub fn has_pending_rx() -> bool {
    active_ops().idle.map(|i| (i.has_pending_rx)()).unwrap_or(false)
}
pub fn has_pending_tx() -> bool {
    active_ops().idle.map(|i| (i.has_pending_tx)()).unwrap_or(false)
}
pub fn rearm_rx_napi(core_id: u32) -> bool {
    active_ops().idle.map(|i| (i.rearm_rx_napi)(core_id)).unwrap_or(false)
}

// ---- Diagnostics (/stats) ------------------------------------------------

pub fn rx_counts() -> [u64; 8] {
    active_ops().diag.map(|d| (d.rx_counts)()).unwrap_or([0; 8])
}
pub fn rx_used_cursors() -> [(u16, u16); 8] {
    active_ops().diag.map(|d| (d.rx_used_cursors)()).unwrap_or([(0, 0); 8])
}

/// TX-side diagnostics — per-qp packet counts + small/big pool
/// saturation counters. Returns `None` when either no driver is
/// active or the active driver hasn't wired up the `tx_diag`
/// accessor (it's `Option`-shaped on `NicDiagOps` so legacy
/// drivers compile without filling the struct).
pub fn tx_diag() -> Option<uni_net_driver::TxDiag> {
    active_ops()
        .diag
        .and_then(|d| d.tx_diag)
        .map(|f| f())
}

/// Snapshot the active driver's TX descriptor capture log into the
/// caller's buffer. Returns 0 when no driver is active or when the
/// driver doesn't keep a per-descriptor log (currently only gve
/// does, for TSO debug on GCE).
pub fn tx_desc_log_snapshot(out: &mut [uni_net_driver::TxDescLogEntry]) -> usize {
    active_ops()
        .diag
        .and_then(|d| d.tx_desc_log_snapshot)
        .map(|f| f(out))
        .unwrap_or(0)
}

pub use uni_net_driver::{TxDescLogEntry, TxDiag, DIAG_QP_CAP};

/// Cold-path: used by `uni::Net::enable` to tell "no driver linked"
/// from "drivers linked but none bound hardware".
pub fn installed() -> bool { is_installed() }
