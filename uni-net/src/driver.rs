// `NicOps` POD + link-time registry. Leaf crate so NIC drivers can
// depend here without inheriting the full net stack.

#![no_std]

pub mod error;
pub use error::{DhcpError, NetError, NicError};

pub use uni_iobuf::IOBuf;

use core::sync::atomic::{AtomicPtr, Ordering};

// ---- Core ops --------------------------------------------------------------

/// Handle returned by [`NicOps::acquire_tx_buf`]. Wraps a writable
/// region of driver-owned TX-pool storage so the caller can fill
/// frame bytes in place — no memcpy through an intermediate
/// stack buffer when handing the frame to the driver.
///
/// Lifecycle:
///   * Acquire → driver marks the slot busy, returns this handle.
///   * Caller fills `data_mut()[..frame_len]` with the L2 frame.
///   * Caller passes the handle to [`NicOps::submit_tx`], which
///     mem-forgets it (skipping `Drop`) and enqueues a virtio
///     descriptor pointing at the slot. The slot stays busy
///     until the device signals descriptor completion (via the
///     driver's `tx_drain`).
///   * If the caller drops the handle without submitting (e.g.
///     a frame-build error path), `Drop` calls `release_fn` to
///     return the slot to the pool unused.
///
/// `release_fn` is the driver's "release this slot back to the
/// pool" entry point; it takes the opaque `driver_token` we
/// gave the caller. Usually a small bookkeeping write (clearing
/// a `tx_pool_used[slot]` bit).
pub struct TxBufHandle {
    /// Pointer to the writable data region (the frame body — the
    /// virtio_net header lives in driver-private bytes adjacent
    /// to this region and is filled by `submit_tx`).
    pub data_ptr: *mut u8,
    /// Bytes available at `data_ptr` (≥ 1514 for an Ethernet
    /// MTU 1500 frame; drivers may expose more if they support
    /// jumbo frames in the future).
    pub data_cap: u32,
    /// Driver-private opaque token — the driver decodes this in
    /// `submit_tx` / `release_fn` to find the slot. Caller treats
    /// it as opaque.
    pub driver_token: u64,
    /// Released on `Drop` if the handle isn't submitted. Driver
    /// uses this to put the slot back in the free pool.
    pub release_fn: fn(driver_token: u64),
}

// SAFETY: `data_ptr` is a writable region of driver-owned static
// storage with a stable address; `release_fn` is a `fn` pointer
// (always Sync). `TxBufHandle` is logically per-acquirer — it
// can be moved between threads as long as the caller doesn't
// share it (which would defeat the "exclusive write" property).
unsafe impl Send for TxBufHandle {}

/// L4 checksum-offload hint passed to [`NicOps::submit_tx`]. When
/// `start != 0`, the driver tells the device to compute the
/// per-segment L4 checksum host-side. Saves the guest CPU one
/// full pass over the packet payload.
///
/// What the caller must stamp at the L4 checksum field is
/// driver-specific — see [`CsumStampConvention`] returned by
/// `csum_stamp_convention()`. Two conventions in the wild:
///   * `PseudoHeaderPartial` (virtio): caller pre-stamps the
///     16-bit pseudo-header partial sum; device adds data,
///     folds, inverts.
///   * `Zero` (gve): caller stamps zero; device builds the
///     pseudo-header itself from the IP header and produces the
///     full checksum.
///
/// Use [`Self::NONE`] when the caller already computed the full
/// checksum and stamped it (control segments built at boot, etc.).
#[derive(Clone, Copy, Debug)]
pub struct CsumOffload {
    /// Byte offset within the frame where checksum coverage
    /// starts (= start of the L4 header). For TCP/UDP over IPv4:
    /// `ETH(14) + IPv4(20) = 34`. Over IPv6:
    /// `ETH(14) + IPv6(40) = 54`. `0` disables offload.
    pub start: u16,
    /// Byte offset of the L4 checksum field, RELATIVE to `start`.
    /// TCP: 16. UDP: 6.
    pub offset: u16,
}

impl CsumOffload {
    /// No offload — caller computed the full checksum and stamped
    /// it before submit. Drivers ship the frame verbatim.
    pub const NONE: Self = Self { start: 0, offset: 0 };

    /// True when the caller wants offload (any non-zero `start`).
    #[inline]
    pub fn is_some(&self) -> bool {
        self.start != 0
    }
}

/// What the caller must stamp at the L4 checksum field when
/// requesting CSUM offload. Different NICs follow different
/// conventions; the driver advertises which one it expects via
/// [`NicOps::csum_stamp_convention`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsumStampConvention {
    /// Driver pre-stamps the 16-bit pseudo-header partial sum
    /// (un-inverted folded sum of pseudo-header bytes). Device
    /// adds the L4-payload data sum and folds/inverts. Used by
    /// virtio-net (`VIRTIO_NET_HDR_F_NEEDS_CSUM`).
    PseudoHeaderPartial,
    /// Driver stamps zero at the checksum field. Device builds
    /// the pseudo-header itself from the IP header in the frame,
    /// computes the L4 data sum, and writes the final 16-bit
    /// checksum. Used by gve.
    Zero,
}

impl TxBufHandle {
    /// Mutable view of the writable frame region. Caller fills
    /// `data_mut()[..frame_len]` with the L2 frame bytes.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        // SAFETY: the driver guarantees `data_ptr` is valid and
        // `data_cap` accurate for the handle's lifetime, with
        // exclusive write access (no other holder of the same
        // slot exists between acquire and submit/drop).
        unsafe {
            core::slice::from_raw_parts_mut(self.data_ptr, self.data_cap as usize)
        }
    }
}

impl Drop for TxBufHandle {
    fn drop(&mut self) {
        (self.release_fn)(self.driver_token);
    }
}

/// Handle returned by [`NicOps::acquire_tx_tso_buf`] for a TCP
/// TSO super-segment. Type-distinct from `TxBufHandle` so
/// [`NicOps::submit_tx`] can't accept it (and vice versa) — the
/// big-pool / small-pool distinction is enforced at compile
/// time, not just by a runtime pool-ID check on the token.
///
/// Lifecycle and field layout match `TxBufHandle` (this is a
/// newtype wrapper). Drop fires the wrapped handle's
/// `release_fn` automatically.
#[repr(transparent)]
pub struct TxTsoBufHandle(pub TxBufHandle);

// SAFETY: same rationale as `TxBufHandle::Send`.
unsafe impl Send for TxTsoBufHandle {}

impl TxTsoBufHandle {
    /// Mutable view of the writable frame region. The big-pool
    /// slot's capacity is sized to fit one TSO super-segment
    /// (~16 KiB).
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.0.data_mut()
    }

    /// Capacity of the writable region, in bytes.
    #[inline]
    pub fn data_cap(&self) -> u32 {
        self.0.data_cap
    }
}

/// All fn pointers a NIC driver exposes. A single `&'static NicOps`
/// is published via `AtomicPtr` at boot; every dispatcher call does
/// one Acquire load + one direct call.
///
/// `probe` returns `true` iff the driver bound hardware. It's the
/// only method callers may invoke before bring-up completes; every
/// other call is a no-op / zero until the first probe succeeds.
pub struct NicOps {
    pub name: &'static str,
    pub probe: fn() -> bool,

    // ── Data path ───────────────────────────────────────────────────
    pub send: fn(&[u8]),
    /// Optional zero-copy TX: caller acquires a slot from the
    /// driver's TX pool, fills frame bytes in place, submits.
    /// `None` means the driver doesn't support this surface (or
    /// the runtime context — e.g. Tier-2 shared queue under
    /// multi-core — can't supply a slot without lock contention);
    /// caller falls back to `send(&[u8])`.
    ///
    /// On `Some(handle)` return:
    ///   * Caller fills `handle.data_mut()[..frame_len]` with the
    ///     full Ethernet frame (no virtio_net header — that's
    ///     filled by `submit_tx` from driver-private bytes
    ///     adjacent to the data region).
    ///   * Caller hands the handle to `submit_tx(handle, frame_len)`.
    ///   * If the caller drops the handle without submitting (e.g.
    ///     on an error path), the slot returns to the pool via
    ///     `TxBufHandle::Drop`.
    ///
    /// Returns `None` on pool exhaustion — caller may retry, fall
    /// back to `send`, or drop the packet (UDP / QUIC retransmit).
    pub acquire_tx_buf: Option<fn() -> Option<TxBufHandle>>,
    /// Submit a previously-acquired TX buffer for transmission.
    /// `frame_len` is the bytes the caller wrote at the start of
    /// `handle.data_mut()`. `csum` carries the optional checksum-
    /// offload hint — non-zero `csum.start` activates device-side
    /// L4 checksum compute (caller stamped the pseudo-header
    /// partial sum at `csum.start + csum.offset`). Consumes the
    /// handle (slot returns to pool when the device signals
    /// descriptor completion via `tx_drain`, NOT when this fn
    /// returns). `None` mirrors `acquire_tx_buf`'s `None`.
    pub submit_tx: Option<fn(TxBufHandle, usize, CsumOffload)>,
    /// TSOv4 capability: `true` when the device negotiated
    /// `VIRTIO_NET_F_HOST_TSO4` + `VIRTIO_NET_F_CSUM` (or the
    /// equivalent on non-virtio drivers). When true,
    /// [`acquire_tx_tso_buf`] returns 16-KiB-capacity slots that
    /// the TCP layer fills with a single super-segment and ships
    /// via [`submit_tx_tso`]. When false, callers must split
    /// into MSS-sized segments themselves and use the small-pool
    /// `acquire_tx_buf` + `submit_tx` path.
    pub tso_available: fn() -> bool,
    /// L4 checksum-offload-on-TX capability: `true` when the
    /// device negotiated `VIRTIO_NET_F_CSUM` (or the equivalent
    /// on non-virtio drivers). When true, callers should stamp
    /// the value dictated by [`Self::csum_stamp_convention`] at
    /// the L4 checksum field and pass [`CsumOffload`] with
    /// non-zero `start`; the device finishes the checksum
    /// host-side. When false, callers must compute and stamp the
    /// full checksum themselves and pass [`CsumOffload::NONE`].
    pub csum_tx_offload: fn() -> bool,
    /// What the caller must stamp at the L4 checksum field when
    /// `csum_tx_offload` is true. virtio uses
    /// `PseudoHeaderPartial`; gve uses `Zero` (its hardware
    /// builds the pseudo-header itself from the IP header).
    pub csum_stamp_convention: fn() -> CsumStampConvention,
    /// Acquire a big-slot TX buffer (16 KiB capacity) for a TCP
    /// TSO super-segment. Returns `None` when:
    ///   * TSO isn't negotiated (no big pool allocated), OR
    ///   * the big pool is full, OR
    ///   * the driver doesn't expose this surface (`None`
    ///     variant of the option).
    /// Caller falls back to per-MSS segmentation via
    /// [`acquire_tx_buf`] when None.
    ///
    /// Returns the type-distinct [`TxTsoBufHandle`] so the
    /// caller can't accidentally hand it to [`submit_tx`] (the
    /// type system enforces big-pool slots → `submit_tx_tso`,
    /// small-pool slots → `submit_tx`).
    pub acquire_tx_tso_buf: Option<fn() -> Option<TxTsoBufHandle>>,
    /// Submit a TSO super-segment. Same shape as `submit_tx` plus
    /// the gso fields the device needs to segment host-side:
    ///
    ///   * `hdr_len`: bytes from the start of the frame up to
    ///     (but not including) the TCP payload — i.e.
    ///     `Eth(14) + IP(20|40) + TCP(20)`. The device copies
    ///     these headers to every emitted segment, fixing up
    ///     length and seq fields per segment.
    ///   * `csum_start`: offset of the TCP header within the
    ///     frame — `Eth(14) + IP(20|40)`. The device computes
    ///     the per-segment TCP checksum (placed at
    ///     `csum_start + 16`, the TCP `checksum` field).
    ///   * `gso_size`: MSS — bytes of TCP payload per emitted
    ///     segment.
    ///
    /// `None` when the driver doesn't support TSO (mirror of
    /// `tso_available()`); caller falls back to per-MSS
    /// `submit_tx` calls.
    ///
    /// Takes a [`TxTsoBufHandle`] (the type-distinct wrapper
    /// from `acquire_tx_tso_buf`) — a small-pool `TxBufHandle`
    /// won't compile here, eliminating the previous runtime
    /// pool-ID check.
    pub submit_tx_tso: Option<fn(
        handle: TxTsoBufHandle,
        frame_len: usize,
        hdr_len: u16,
        csum_start: u16,
        gso_size: u16,
    )>,
    /// Zero-copy RX. The callback receives an owned [`IOBuf`]
    /// (typically `IOBuf::External` wrapping the descriptor's
    /// storage) per frame; the IOBuf's drop callback returns the
    /// buffer to the driver's pool. There used to be a parallel
    /// `poll_rx: fn(fn(&[u8]))` / `poll_qp: fn(usize, fn(&[u8]))`
    /// pair for backends that hadn't been ported to IOBuf yet, but
    /// every backend now implements this surface — so the legacy
    /// `&[u8]` path is gone and the net stack only has one RX
    /// shape to reason about.
    pub poll_rx: fn(fn(IOBuf)) -> usize,
    pub poll_qp: fn(usize, fn(IOBuf)) -> usize,

    // ── Config / bring-up ───────────────────────────────────────────
    pub get_mac: fn(*mut u8),
    pub num_queue_pairs: fn() -> u16,
    pub enable_irq: fn(),
    pub enable_deferred_tx_kick: fn(),

    // ── Per-batch TX flush ──────────────────────────────────────────
    pub flush_tx_staging: fn(),
    pub flush_tx_kick_if_dirty: fn() -> bool,

    // ── Per-cycle interrupt-ack (virtio MMIO ISR) ───────────────────
    pub poke_interrupt_status: fn(),

    // ── Optional capabilities ───────────────────────────────────────
    /// NAPI-style idle hooks. `None` = polling-only driver; the
    /// dispatcher treats `irq_idle_supported` as `false`.
    pub idle: Option<&'static NicIdleOps>,

    /// Per-queue diagnostics. `None` = driver doesn't expose them;
    /// dispatcher returns zero arrays.
    pub diag: Option<&'static NicDiagOps>,
}

/// NAPI-style idle hooks. A driver that implements interrupt-driven
/// idle arms the RX IRQ before WFI / HLT, then checks for pending
/// work on wake.
pub struct NicIdleOps {
    pub arm_rx_interrupts: fn(),
    pub has_pending_rx: fn() -> bool,
    pub has_pending_tx: fn() -> bool,
    pub rearm_rx_napi: fn(u32) -> bool,
}

/// Per-queue diagnostic snapshots. Wired into the stats endpoint but
/// never on the hot path. The `tx_diag` accessor is `Option`-shaped
/// so legacy backends without TX-side instrumentation can return
/// `None` without filling a zero struct.
pub struct NicDiagOps {
    pub rx_counts: fn() -> [u64; 8],
    pub rx_used_cursors: fn() -> [(u16, u16); 8],
    /// Snapshot of TX-pool saturation + per-qp TX packet counts.
    /// `None` when the driver hasn't been instrumented (kept as
    /// an Option to avoid forcing every backend to fill the
    /// struct on every release). Returns a single `TxDiag`
    /// covering all qps — per-qp arrays are indexed up to
    /// `DIAG_QP_CAP`.
    pub tx_diag: Option<fn() -> TxDiag>,
    /// Snapshot the driver's TX-descriptor capture log into the
    /// caller's buffer. Returns the number of valid entries
    /// written. `None` for drivers that don't keep a per-descriptor
    /// log (only gve currently does, for TSO debug on GCE where
    /// serial output is gated). The log is bounded; older entries
    /// roll off as new ones land.
    pub tx_desc_log_snapshot: Option<fn(&mut [TxDescLogEntry]) -> usize>,
}

/// Driver-emitted TX descriptor record. The `kind` field tells the
/// renderer how to interpret `bytes` — gve has three descriptor
/// shapes (STD, TSO pkt, SEG); virtio-net would have its own. The
/// raw 16 bytes are forwarded as-is so the renderer can decode
/// per-driver field semantics.
#[derive(Clone, Copy, Default)]
pub struct TxDescLogEntry {
    pub seq: u32,
    pub qp: u8,
    pub kind: u8,
    pub bytes: [u8; 16],
}

/// Cap on per-qp diagnostic arrays. Mirrors `rx_counts: [u64; 8]`
/// so a single `TxDiag` snapshot fits the common case without
/// heap allocation. Drivers with more queue-pairs sum the tail
/// into `[7]` so the total still reflects the device.
pub const DIAG_QP_CAP: usize = 8;

/// TX-side counters surfaced via [`NicDiagOps::tx_diag`]. All
/// fields are zeroed at boot and only ever incremented (relaxed
/// atomic on the hot path), so a snapshot's value differences
/// across a sampling window give per-second rates.
///
/// The two pools (`small` for single-segment frames, `big` for
/// TSO super-segments) report their max sizes alongside their
/// in-flight + saturation counts so the reader can compute
/// utilisation without knowing driver constants.
#[derive(Clone, Copy, Default)]
pub struct TxDiag {
    /// Per-qp count of TX packets submitted to the device.
    /// Reflects load distribution across qps — uneven values
    /// mean RSS / per-core dispatch isn't spreading evenly.
    pub packets_per_qp: [u64; DIAG_QP_CAP],
    /// Per-qp count of descriptors currently in flight to the
    /// device (`fill_cnt - done_cnt`). Should hover well below
    /// `small_pool_size` under healthy load. Pinned at
    /// `small_pool_size` across multiple snapshots = stall:
    /// the driver has slots queued but the device isn't
    /// emitting completions. Direct smoking gun for the gve
    /// DQO-direct-fill stall on c3.
    pub inflight_per_qp: [u32; DIAG_QP_CAP],
    /// Cumulative number of times `acquire_tx_buf` had to spin
    /// because the small pool was fully in-flight. High counts
    /// = pool is undersized for the load.
    pub small_pool_full_spins: u64,
    /// Cumulative scan-iterations across all small-pool
    /// acquires. `small_pool_scan_iters / acquire_count` gives
    /// the average linear-scan depth — high values motivate a
    /// real freelist.
    pub small_pool_scan_iters: u64,
    /// Number of small-pool acquires that succeeded. Pair with
    /// `small_pool_scan_iters` to compute mean.
    pub small_pool_acquires: u64,
    /// Cumulative number of times `acquire_tx_tso_buf` returned
    /// `None` because the big pool was full. Each event means
    /// the caller fell back to per-MSS segmentation (TSO win
    /// lost on that send).
    pub big_pool_full_returns: u64,
    /// Number of TSO super-segments successfully submitted.
    pub big_pool_acquires: u64,
    /// Static pool sizes, snapshot at boot. Reader divides
    /// `acquires - releases` if it needs in-flight count.
    pub small_pool_size: u32,
    pub big_pool_size: u32,
}


// ---- Link-time registry ---------------------------------------------------

/// One entry per linked driver crate, placed in `.uni_drivers_ethernet`
/// by `register_ethernet_driver!`.
#[repr(C)]
pub struct EthernetDriverReg {
    pub ops: &'static NicOps,
}

/// Register a driver with `uni_net` at link time. Expands to a
/// `static EthernetDriverReg` in the `.uni_drivers_ethernet` section;
/// `init()` discovers it via section-boundary symbols.
///
/// ```ignore
/// static MY_OPS: uni_net_driver::NicOps = uni_net_driver::NicOps { /* … */ };
/// uni_net_driver::register_ethernet_driver!(MY_OPS);
/// ```
#[macro_export]
macro_rules! register_ethernet_driver {
    ($ops:expr) => {
        #[used]
        #[unsafe(link_section = ".uni_drivers_ethernet")]
        static ETHERNET_DRIVER_REG: $crate::EthernetDriverReg =
            $crate::EthernetDriverReg { ops: &$ops };
    };
}

// Section-boundary symbols from the linker script. Native hosts have
// no custom script, so `linked_ethernet_drivers()` stubs to `&[]`.
#[cfg(target_os = "none")]
unsafe extern "Rust" {
    static __start_uni_drivers_ethernet: EthernetDriverReg;
    static __stop_uni_drivers_ethernet: EthernetDriverReg;
}

/// All ethernet drivers linked into this binary.
#[cfg(target_os = "none")]
pub fn linked_ethernet_drivers() -> &'static [EthernetDriverReg] {
    // SAFETY: linker guarantees `[start, stop)` is a contiguous
    // run of `EthernetDriverReg` values (the macro is the only
    // writer). Entries live in `.rodata`, materialised at link time.
    unsafe {
        let start = &__start_uni_drivers_ethernet as *const EthernetDriverReg;
        let end = &__stop_uni_drivers_ethernet as *const EthernetDriverReg;
        let count = end.offset_from(start) as usize;
        core::slice::from_raw_parts(start, count)
    }
}

#[cfg(not(target_os = "none"))]
pub fn linked_ethernet_drivers() -> &'static [EthernetDriverReg] {
    &[]
}

// ---- Active driver slot ---------------------------------------------------

// Null-object backstop. `ACTIVE_OPS` points here until the first
// probe succeeds, so every dispatcher call resolves to a real
// `&'static NicOps` without a null check. Hot-path cost per call:
// one Acquire load + one direct fn-pointer call.

fn null_send(_: &[u8]) {}
fn null_poll(_: fn(IOBuf)) -> usize { 0 }
fn null_poll_qp(_: usize, _: fn(IOBuf)) -> usize { 0 }
fn null_probe() -> bool { false }
fn null_get_mac(_: *mut u8) {}
fn null_num_queue_pairs() -> u16 { 1 }
fn null_void() {}
fn null_false() -> bool { false }

static NULL_OPS: NicOps = NicOps {
    name: "none",
    probe: null_probe,
    send: null_send,
    acquire_tx_buf: None,
    submit_tx: None,
    tso_available: null_false,
    csum_tx_offload: null_false,
    csum_stamp_convention: || CsumStampConvention::PseudoHeaderPartial,
    acquire_tx_tso_buf: None,
    submit_tx_tso: None,
    poll_rx: null_poll,
    poll_qp: null_poll_qp,
    get_mac: null_get_mac,
    num_queue_pairs: null_num_queue_pairs,
    enable_irq: null_void,
    enable_deferred_tx_kick: null_void,
    flush_tx_staging: null_void,
    flush_tx_kick_if_dirty: null_false,
    poke_interrupt_status: null_void,
    idle: None,
    diag: None,
};

static ACTIVE_OPS: AtomicPtr<NicOps> =
    AtomicPtr::new(&NULL_OPS as *const NicOps as *mut NicOps);

/// Install `ops` as the active driver. Called once by `init()` when
/// the first `probe` succeeds.
pub fn set_active_ops(ops: &'static NicOps) {
    ACTIVE_OPS.store(ops as *const _ as *mut _, Ordering::Release);
}

/// Currently-active ops. Returns `NULL_OPS` (all no-ops) before the
/// first successful probe and on native — callers never need to
/// branch on "is a driver installed?". Use `is_installed()` if a
/// cold-path caller genuinely needs to know.
#[inline]
pub fn active_ops() -> &'static NicOps {
    // SAFETY: `ACTIVE_OPS` is always non-null — it starts pointing
    // at `NULL_OPS` and `set_active_ops` only stores pointers
    // derived from `&'static NicOps`. The Release/Acquire pair
    // synchronises store with readers.
    unsafe { &*(ACTIVE_OPS.load(Ordering::Acquire) as *const NicOps) }
}

/// Whether a real driver has been installed. Cold-path — used by
/// `Net::enable` to distinguish "no driver linked" from "drivers
/// linked but none probed".
pub fn is_installed() -> bool {
    !core::ptr::eq(
        ACTIVE_OPS.load(Ordering::Acquire) as *const NicOps,
        &NULL_OPS as *const NicOps,
    )
}
