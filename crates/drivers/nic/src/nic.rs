// drivers/nic.rs — the `nic` crate: NIC dispatch through
// `nic_api::active_ops()`.
//
// Standalone host-buildable crate whose only dependency is the
// host-buildable `nic_api` interface crate. Sibling of the
// os:none `//crates/drivers/bus` (`bus`) hardware-access crate, kept
// separate so the TX-side net crates that call these dispatchers
// (`net_eth_tx`, `tcp`, …) stay host-buildable — they depend on
// `//crates/drivers/nic` directly, never on the os:none `//crates/drivers/bus`.
//
// `init()` walks `linked_ethernet_drivers()`, calls the `probe` fn
// pointer on each registration, and installs the first success into
// the active-ops slot. Before that — and on native, where no section
// exists — `active_ops()` resolves to `NULL_OPS` (all no-ops), so
// every dispatcher below is a single load + direct call with no
// null branch.

#![no_std]

use nic_api::{
    Chain, OwnedIOBuf, active_ops, is_installed, linked_ethernet_drivers, set_active_ops,
};

pub use nic_api::CsumOffload;

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

pub fn get_mac(mac_out: *mut u8) {
    (active_ops().get_mac)(mac_out)
}
pub fn num_queue_pairs() -> u16 {
    (active_ops().num_queue_pairs)()
}
pub fn driver_name() -> &'static str {
    active_ops().name
}
pub fn enable_irq() {
    (active_ops().enable_irq)()
}

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

/// Slice-shaped TX. The driver memcpys `data` into a TX-pool slot
/// and submits it; `csum` is the L4 checksum-offload descriptor
/// (see [`submit_tx`]). Pass [`CsumOffload::NONE`] for a frame that
/// already carries a full checksum or needs none (ARP, ...).
pub fn send(data: &[u8], csum: nic_api::CsumOffload) {
    (active_ops().send)(data, csum)
}

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
pub fn acquire_tx_buf() -> Option<nic_api::TxBufHandle> {
    let f = active_ops().acquire_tx_buf?;
    f()
}

/// Submit a previously-acquired TX buffer with `frame_len` bytes of
/// frame data at the head of `handle.data_mut()`. Consumes the
/// handle. `csum` is the optional L4-checksum-offload hint — pass
/// [`nic_api::CsumOffload::NONE`] when the caller already
/// computed and stamped the L4 checksum.
pub fn submit_tx(handle: nic_api::TxBufHandle, frame_len: usize, csum: nic_api::CsumOffload) {
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

/// True iff the driver negotiated TSOv4
/// (`VIRTIO_NET_F_HOST_TSO4` + `VIRTIO_NET_F_CSUM`, or equivalent).
/// When true, [`acquire_tx_tso_buf`] returns 16-KiB-capacity slots
/// that the TCP layer fills with a single super-segment and ships
/// via [`submit_tx_tso`].
pub fn tso_available() -> bool {
    (active_ops().tso_available)()
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
pub fn acquire_tx_tso_buf() -> Option<nic_api::TxTsoBufHandle> {
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
    handle: nic_api::TxTsoBufHandle,
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
pub fn acquire_tx_udp_gso_buf() -> Option<nic_api::TxUdpGsoBufHandle> {
    let f = active_ops().acquire_tx_udp_gso_buf?;
    f()
}

/// Submit a UDP-GSO super-packet. The slot bytes are laid out as
/// `[Eth | IP | UDP | seg₀ | seg₁ | … | seg_N]` and the device
/// emits N UDP datagrams with the UDP header replicated per
/// segment. See [`nic_api::NicOps::submit_tx_udp_gso`] for
/// field semantics.
pub fn submit_tx_udp_gso(
    handle: nic_api::TxUdpGsoBufHandle,
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

pub fn flush_tx_staging() {
    (active_ops().flush_tx_staging)()
}
pub fn flush_tx_kick_if_dirty() -> bool {
    (active_ops().flush_tx_kick_if_dirty)()
}
pub fn enable_deferred_tx_kick() {
    (active_ops().enable_deferred_tx_kick)()
}
pub fn poke_interrupt_status() {
    (active_ops().poke_interrupt_status)()
}

/// Presence of `idle` ops is the signal — NAPI-capable drivers
/// populate it, polling-only drivers leave it `None`.
pub fn irq_idle_supported() -> bool {
    active_ops().idle.is_some()
}

pub fn arm_rx_interrupts() {
    if let Some(i) = active_ops().idle {
        (i.arm_rx_interrupts)();
    }
}
pub fn has_pending_rx() -> bool {
    active_ops()
        .idle
        .map(|i| (i.has_pending_rx)())
        .unwrap_or(false)
}
pub fn has_pending_tx() -> bool {
    active_ops()
        .idle
        .map(|i| (i.has_pending_tx)())
        .unwrap_or(false)
}
pub fn rearm_rx_napi(core_id: u32) -> bool {
    active_ops()
        .idle
        .map(|i| (i.rearm_rx_napi)(core_id))
        .unwrap_or(false)
}

// ---- Diagnostics (/obs `nic` block) ---------------------------------------

pub fn rx_counts() -> [u64; DIAG_QP_CAP] {
    active_ops()
        .diag
        .map(|d| (d.rx_counts)())
        .unwrap_or([0; DIAG_QP_CAP])
}
pub fn rx_used_cursors() -> [(u16, u16); DIAG_QP_CAP] {
    active_ops()
        .diag
        .map(|d| (d.rx_used_cursors)())
        .unwrap_or([(0, 0); DIAG_QP_CAP])
}

/// TX-side diagnostics — per-qp packet counts + small/big pool
/// saturation counters. Returns `None` when either no driver is
/// active or the active driver hasn't wired up the `tx_diag`
/// accessor (it's `Option`-shaped on `NicDiagOps` so legacy
/// drivers compile without filling the struct).
pub fn tx_diag() -> Option<nic_api::TxDiag> {
    active_ops().diag.and_then(|d| d.tx_diag).map(|f| f())
}

/// Snapshot the active driver's TX descriptor capture log into the
/// caller's buffer. Returns 0 when no driver is active or when the
/// driver doesn't keep a per-descriptor log (currently only gve
/// does, for TSO debug on GCE).
pub fn tx_desc_log_snapshot(out: &mut [nic_api::TxDescLogEntry]) -> usize {
    active_ops()
        .diag
        .and_then(|d| d.tx_desc_log_snapshot)
        .map(|f| f(out))
        .unwrap_or(0)
}

/// Render the active driver's observability block as a JSON object
/// — the `nic` block's `counters` for `/obs` (see
/// `docs/observability.md`). Dispatches to the driver's `obs_json`;
/// writes `{}` when no driver is bound (native, or pre-probe).
pub fn obs_json(w: &mut dyn core::fmt::Write) -> core::fmt::Result {
    match active_ops().diag {
        Some(d) => (d.obs_json)(w),
        None => w.write_str("{}"),
    }
}

pub use nic_api::{DIAG_QP_CAP, TxDescLogEntry, TxDiag};

/// Cold-path: used by `waitless::Net::enable` to tell "no driver linked"
/// from "drivers linked but none bound hardware".
pub fn installed() -> bool {
    is_installed()
}
