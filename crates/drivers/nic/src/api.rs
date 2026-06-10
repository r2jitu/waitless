// `Nic` trait + link-time registry. Leaf crate so NIC drivers can
// depend here without inheriting the full net stack.

#![no_std]

pub mod error;
pub use error::NicError;

pub use iobuf::{Chain, IOBuf, IOBufChain, OwnedIOBuf};

use core::sync::atomic::{AtomicPtr, Ordering};

// ---- TX frame layout contract ----------------------------------------------

/// Bytes a TX-frame builder must reserve at the FRONT of any
/// driver/TX-pool buffer for the Ethernet + IP + UDP headers the
/// backend fills in at submit time. Sized for the largest case
/// (ETH 14 + IPv6 40 + UDP 8 = 62); IPv4 senders use the trailing 42
/// and leave the leading 20 untouched. Callers write payload bytes at
/// `data[MAX_L2_HEADROOM..]`. This is part of the handle contract
/// ([`TxBufHandle`] and friends), which is why it lives in this leaf:
/// the net stack, the QUIC encoder, and the reactor all share it
/// without any of them depending on the others.
pub const MAX_L2_HEADROOM: usize = 14 + 40 + 8;

// ---- Core ops --------------------------------------------------------------

/// Handle returned by [`Nic::acquire_tx_buf`]. Wraps a writable
/// region of driver-owned TX-pool storage so the caller can fill
/// frame bytes in place — no memcpy through an intermediate
/// stack buffer when handing the frame to the driver.
///
/// Lifecycle:
///   * Acquire → driver marks the slot busy, returns this handle.
///   * Caller fills `data_mut()[..frame_len]` with the L2 frame.
///   * Caller passes the handle to [`Nic::submit_tx`], which
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

/// L4 checksum-offload hint passed to [`Nic::submit_tx`]. When
/// `start != 0`, the driver tells the device to compute the
/// per-segment L4 checksum host-side. Saves the guest CPU one
/// full pass over the packet payload.
///
/// The caller pre-stamps the 16-bit pseudo-header partial sum at
/// the L4 checksum field; the device adds the payload data sum,
/// folds, and inverts. Every NIC the stack drives expects this one
/// convention — virtio (`VIRTIO_NET_HDR_F_NEEDS_CSUM`) and gve.
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
    pub const NONE: Self = Self {
        start: 0,
        offset: 0,
    };

    /// True when the caller wants offload (any non-zero `start`).
    #[inline]
    pub fn is_some(&self) -> bool {
        self.start != 0
    }
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
        unsafe { core::slice::from_raw_parts_mut(self.data_ptr, self.data_cap as usize) }
    }
}

impl Drop for TxBufHandle {
    fn drop(&mut self) {
        (self.release_fn)(self.driver_token);
    }
}

/// Handle returned by [`Nic::acquire_tx_tso_buf`] for a TCP
/// TSO super-segment. Type-distinct from `TxBufHandle` so
/// [`Nic::submit_tx`] can't accept it (and vice versa) — the
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

/// Handle returned by [`Nic::acquire_tx_udp_gso_buf`] for a
/// UDP-GSO super-packet. Same big-pool storage as
/// [`TxTsoBufHandle`] — the type distinction is so the API surface
/// can route to the correct `submit_tx_*` variant (TCP TSO vs UDP
/// GSO emit different descriptor bytes on the wire).
#[repr(transparent)]
pub struct TxUdpGsoBufHandle(pub TxBufHandle);

// SAFETY: same rationale as `TxBufHandle::Send`.
unsafe impl Send for TxUdpGsoBufHandle {}

impl TxUdpGsoBufHandle {
    /// Mutable view of the writable frame region (~16 KiB).
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

/// All entry points a NIC driver exposes. A single `&'static dyn Nic`
/// is published at boot (through a thin `&'static DynSlot` in an
/// `AtomicPtr`); every dispatcher call does one Acquire load, one
/// `.rodata` slot load, and one vtable call.
///
/// `probe` returns `true` iff the driver bound hardware. It's the
/// only method callers may invoke before bring-up completes; every
/// other call is a no-op / zero until the first probe succeeds.
pub trait Nic: Sync {
    fn name(&self) -> &'static str;
    fn probe(&self) -> bool;

    // ── Data path ───────────────────────────────────────────────────
    /// Slice-shaped TX: the driver memcpys the frame into a TX-pool
    /// slot and submits it. `csum` is the L4 checksum-offload
    /// descriptor — same one [`Self::submit_tx`] takes — finished
    /// via device offload, or a software pass when the device never
    /// negotiated it. Pass [`CsumOffload::NONE`] for a frame that
    /// already carries a full checksum or needs none (ARP, ...).
    fn send(&self, data: &[u8], csum: CsumOffload);
    /// Whether the driver implements the zero-copy direct-fill TX
    /// surface ([`Self::acquire_tx_buf`]) at all. Lets the
    /// dispatcher distinguish "no surface — use the slice `send`
    /// path" from "surface present but the pool is full right now —
    /// apply back-pressure and retry". Drivers that override
    /// `acquire_tx_buf` override this to return `true`.
    fn has_direct_fill(&self) -> bool {
        false
    }
    /// Optional zero-copy TX: caller acquires a slot from the
    /// driver's TX pool, fills frame bytes in place, submits.
    /// The default (never-`Some`) implementation means the driver
    /// doesn't support this surface (or the runtime context —
    /// e.g. Tier-2 shared queue under multi-core — can't supply a
    /// slot without lock contention); caller falls back to
    /// `send(&[u8])`.
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
    fn acquire_tx_buf(&self) -> Option<TxBufHandle> {
        None
    }
    /// Submit a previously-acquired TX buffer for transmission.
    /// `frame_len` is the bytes the caller wrote at the start of
    /// `handle.data_mut()`. `csum` carries the optional checksum-
    /// offload hint — non-zero `csum.start` activates device-side
    /// L4 checksum compute (caller stamped the pseudo-header
    /// partial sum at `csum.start + csum.offset`). Consumes the
    /// handle (slot returns to pool when the device signals
    /// descriptor completion via `tx_drain`, NOT when this fn
    /// returns). The default implementation mirrors
    /// `acquire_tx_buf`'s default `None`: only reachable via API
    /// misuse — a caller that does proper acquire+submit can never
    /// end up here — and just drops the handle (its `Drop` returns
    /// the slot to the pool).
    fn submit_tx(&self, handle: TxBufHandle, _frame_len: usize, _csum: CsumOffload) {
        drop(handle);
    }
    /// TSOv4 capability: `true` when the device negotiated
    /// `VIRTIO_NET_F_HOST_TSO4` + `VIRTIO_NET_F_CSUM` (or the
    /// equivalent on non-virtio drivers). When true,
    /// [`Self::acquire_tx_tso_buf`] returns 16-KiB-capacity slots that
    /// the TCP layer fills with a single super-segment and ships
    /// via [`Self::submit_tx_tso`]. When false, callers must split
    /// into MSS-sized segments themselves and use the small-pool
    /// `acquire_tx_buf` + `submit_tx` path.
    fn tso_available(&self) -> bool;
    /// Acquire a big-slot TX buffer (16 KiB capacity) for a TCP
    /// TSO super-segment. Returns `None` when:
    ///   * TSO isn't negotiated (no big pool allocated), OR
    ///   * the big pool is full, OR
    ///   * the driver doesn't expose this surface (the default
    ///     implementation).
    ///
    /// Caller falls back to per-MSS segmentation via
    /// [`Self::acquire_tx_buf`] when None.
    ///
    /// Returns the type-distinct [`TxTsoBufHandle`] so the
    /// caller can't accidentally hand it to [`Self::submit_tx`] (the
    /// type system enforces big-pool slots → `submit_tx_tso`,
    /// small-pool slots → `submit_tx`).
    fn acquire_tx_tso_buf(&self) -> Option<TxTsoBufHandle> {
        None
    }
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
    /// The default implementation covers drivers that don't
    /// support TSO (mirror of `tso_available()`): it drops the
    /// handle, returning the slot to the pool with no traffic
    /// emitted; the caller falls back to per-MSS `submit_tx`
    /// calls.
    ///
    /// Takes a [`TxTsoBufHandle`] (the type-distinct wrapper
    /// from `acquire_tx_tso_buf`) — a small-pool `TxBufHandle`
    /// won't compile here, eliminating the previous runtime
    /// pool-ID check.
    fn submit_tx_tso(
        &self,
        handle: TxTsoBufHandle,
        _frame_len: usize,
        _hdr_len: u16,
        _csum_start: u16,
        _gso_size: u16,
    ) {
        drop(handle);
    }
    /// UDP-GSO (`UDP_SEGMENT` / `GSO_UDP_L4`) capability — the UDP
    /// analogue of `tso_available`. `true` when the device can
    /// segment a single big UDP super-packet into N same-size
    /// per-datagram outputs host-side, replicating the UDP header
    /// for each emitted segment and computing per-segment
    /// checksums. The natural beneficiary is QUIC, which sends
    /// streams of fixed-MTU datagrams to the same peer.
    fn udp_gso_available(&self) -> bool;
    /// Acquire a big-slot TX buffer for a UDP-GSO super-packet.
    /// Same shape and pool as `acquire_tx_tso_buf` — drivers may
    /// reuse the same big pool internally; the type-distinct
    /// [`TxUdpGsoBufHandle`] enforces "this slot was acquired for
    /// UDP GSO" at the API surface.
    fn acquire_tx_udp_gso_buf(&self) -> Option<TxUdpGsoBufHandle> {
        None
    }
    /// Submit a UDP-GSO super-packet. The slot's bytes are laid
    /// out as
    /// `[Eth | IP | UDP | seg₀(gso_size) | seg₁(gso_size) | … | seg_N]`
    /// — one UDP header followed by N concatenated payload
    /// segments. The device emits N UDP datagrams, each with a
    /// copy of the UDP header (length-fixed up per segment) and
    /// one `gso_size`-byte chunk of the payload.
    ///
    ///   * `hdr_len`: Eth + IP + UDP = 42 (v4) or 62 (v6); the
    ///     prefix the device replicates per segment.
    ///   * `csum_start`: offset of the UDP header within the
    ///     frame (Eth + IP) — same value as for TSO's TCP-header
    ///     offset, modulo the L4 protocol.
    ///   * `gso_size`: payload bytes per emitted UDP datagram.
    ///     The total payload length must be a multiple of
    ///     `gso_size` (no short last segment) — devices generally
    ///     enforce this.
    ///
    /// Takes a [`TxUdpGsoBufHandle`]; same handling rules as the
    /// TSO wrapper (the default implementation drops the handle).
    fn submit_tx_udp_gso(
        &self,
        handle: TxUdpGsoBufHandle,
        _frame_len: usize,
        _hdr_len: u16,
        _csum_start: u16,
        _gso_size: u16,
    ) {
        drop(handle);
    }
    /// RX callback: the driver delivers each received L2 frame
    /// (Eth + IP + L4 + payload) as an owned `Chain<OwnedIOBuf>`.
    /// `OwnedIOBuf` is `Send` by derivation, so the chain — and the
    /// frame it carries — can be moved cross-core (the Tier 2
    /// distributor → per-core inbox) with no `unsafe impl Send`.
    /// A single-buffer frame is a one-part chain (the zero-alloc
    /// `Single` arm); a hardware-coalesced super-segment is a
    /// multi-part chain (item I). The callback takes the chain by
    /// value — it owns it, and may retain it past return.
    ///
    /// Each part is an `IOBuf` whose drop callback returns the
    /// backing storage to the device or pool:
    ///   * DQO / virtio-net wrap the device's own RX buffer as
    ///     `ExternalOwned`; the drop callback reposts that buffer
    ///     to the receive ring (zero-copy delivery).
    ///   * GQI cannot lend device buffers (strict in-order
    ///     repost), so it copies each frame into a pooled MTU
    ///     slab and delivers that; the slab recycles to the pool
    ///     on drop.
    ///
    /// This is the shape that replaced an earlier borrowed-`&[u8]`
    /// design. The slice form forced a synchronous copy at the
    /// driver boundary and made cross-core delivery a memcpy; the
    /// owned chain lets the net stack thread RX bytes through to
    /// the application without that copy. The earlier *first*
    /// attempt at owned delivery was unsound because it had no
    /// auto-repost — a stalled consumer could pin a device buffer
    /// past the ring-wrap window. `ExternalOwned`'s drop callback
    /// (item A) closes that hole: the buffer always reposts when
    /// the chain drops, wherever and whenever that happens. Each
    /// driver's drop callback MUST be panic-safe — it can run from
    /// `IOBuf::drop` on any core.
    fn poll_rx(&self, deliver: fn(Chain<OwnedIOBuf>)) -> usize;
    /// Per-queue-pair RX delivery. Takes the qp index and the
    /// per-frame `IOBuf`-chain callback the dispatcher uses to
    /// forward frames into the net stack.
    fn poll_qp(&self, qp: usize, deliver: fn(Chain<OwnedIOBuf>)) -> usize;

    // ── Config / bring-up ───────────────────────────────────────────
    fn get_mac(&self, mac_out: *mut u8);
    fn num_queue_pairs(&self) -> u16;
    fn enable_irq(&self);
    fn enable_deferred_tx_kick(&self);

    // ── Per-batch TX flush ──────────────────────────────────────────
    fn flush_tx_staging(&self);
    fn flush_tx_kick_if_dirty(&self) -> bool;

    // ── Per-cycle interrupt-ack (virtio MMIO ISR) ───────────────────
    fn poke_interrupt_status(&self);

    // ── Optional capabilities ───────────────────────────────────────
    /// NAPI-style idle hooks. `None` (the default) = polling-only
    /// driver; the dispatcher treats `irq_idle_supported` as `false`.
    fn idle(&self) -> Option<&'static NicIdleOps> {
        None
    }

    /// Lightweight "arm RX interrupt ahead of a sustained-idle sleep"
    /// hook for *polling* drivers (those that keep `idle()` `None` so
    /// their busy-poll-under-load path is untouched). Called by the
    /// event loop's sustained-idle gate just before it commits to a
    /// timer-bounded HLT: the driver unmasks the calling core's RX
    /// interrupt so the HLT wakes on a packet instead of only the timer
    /// backstop, and returns `true` if RX work is *already* pending (the
    /// caller then skips the sleep and re-polls). The default
    /// (`false`-returning) implementation = driver has no
    /// interrupt-arming surface; the gate just sleeps on the timer.
    ///
    /// Distinct from [`Self::idle`]: that reroutes the whole idle path
    /// through `wait_for_events` (abandoning the sustained-idle gate);
    /// this is an arm-only add-on so a polling driver gains
    /// wake-on-packet without changing its load-path behaviour. The
    /// interrupt is armed only from the deep-idle gate, so a busy core
    /// never arms it (zero hot-path cost).
    fn arm_rx_idle(&self) -> bool {
        false
    }

    /// Per-queue diagnostics. `None` (the default) = driver doesn't
    /// expose them; dispatcher returns zero arrays.
    fn diag(&self) -> Option<&'static NicDiagOps> {
        None
    }
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
    pub rx_counts: fn() -> [u64; DIAG_QP_CAP],
    pub rx_used_cursors: fn() -> [(u16, u16); DIAG_QP_CAP],
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
    /// Render the driver's observability block as a JSON object —
    /// its failure / anomaly counters, throughput totals, and a
    /// `last_*` snapshot, per the observability doctrine
    /// (`docs/observability.md`). The first field is `"driver"`, so
    /// the rendered object self-identifies which NIC produced it.
    /// Required (not `Option`): the doctrine mandates every
    /// subsystem expose a `write_obs_json`. `nic::obs_json`
    /// dispatches here for the `/obs` `nic` block's `counters`.
    pub obs_json: fn(&mut dyn core::fmt::Write) -> core::fmt::Result,
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

/// Cap on per-qp diagnostic arrays. Sized to match `MAX_QUEUE_PAIRS`
/// in the gve / virtio-net drivers. 22 covers c3-highcpu-22's queue
/// pair count; lift here + in the driver `MAX_QUEUE_PAIRS` constants
/// in lockstep if you ever need to go higher. Drivers with fewer
/// active queues than the cap leave the tail entries at 0.
pub const DIAG_QP_CAP: usize = 22;

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
    /// Per-qp cumulative TX wire bytes — sum of `frame_len` over
    /// every submit. For TSO the value is the *pre-segmentation*
    /// super-segment length, not the post-segmentation wire
    /// bytes the device actually emits (so apples-to-apples
    /// throughput comparison vs the small-pool path under-
    /// counts TSO by the per-segment header duplication).
    pub tx_bytes_per_qp: [u64; DIAG_QP_CAP],
    /// Per-qp cumulative RX wire bytes — driver-side count of
    /// frame lengths the callback receives (includes Eth + IP +
    /// L4 headers + payload).
    pub rx_bytes_per_qp: [u64; DIAG_QP_CAP],
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

/// Thin, statically-addressable carrier for a `&'static dyn Nic` fat
/// pointer. Rust has no atomic fat pointer, so the active-driver slot
/// stores a thin `*mut DynSlot` and dereferences through it — one
/// extra `.rodata` load on dispatch.
pub struct DynSlot {
    pub nic: &'static dyn Nic,
}

/// One entry per linked driver crate, placed in `.waitless_drivers_ethernet`
/// by `register_ethernet_driver!`.
#[repr(C)]
pub struct EthernetDriverReg {
    pub nic: &'static DynSlot,
}

/// Register a driver with `waitless_net` at link time. Expands to a
/// `static EthernetDriverReg` in the `.waitless_drivers_ethernet` section;
/// `init()` discovers it via section-boundary symbols.
///
/// ```ignore
/// struct MyNic;
/// impl nic_api::Nic for MyNic { /* … */ }
/// nic_api::register_ethernet_driver!(MyNic);
/// ```
#[macro_export]
macro_rules! register_ethernet_driver {
    ($nic:expr) => {
        #[used]
        #[unsafe(link_section = ".waitless_drivers_ethernet")]
        static ETHERNET_DRIVER_REG: $crate::EthernetDriverReg = $crate::EthernetDriverReg {
            nic: &$crate::DynSlot { nic: &$nic },
        };
    };
}

// Section-boundary symbols from the linker script. Native hosts have
// no custom script, so `linked_ethernet_drivers()` stubs to `&[]`.
#[cfg(target_os = "none")]
unsafe extern "Rust" {
    static __start_waitless_drivers_ethernet: EthernetDriverReg;
    static __stop_waitless_drivers_ethernet: EthernetDriverReg;
}

/// All ethernet drivers linked into this binary.
#[cfg(target_os = "none")]
pub fn linked_ethernet_drivers() -> &'static [EthernetDriverReg] {
    // SAFETY: linker guarantees `[start, stop)` is a contiguous
    // run of `EthernetDriverReg` values (the macro is the only
    // writer). Entries live in `.rodata`, materialised at link time.
    unsafe {
        let start = &__start_waitless_drivers_ethernet as *const EthernetDriverReg;
        let end = &__stop_waitless_drivers_ethernet as *const EthernetDriverReg;
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
// `&'static dyn Nic` without a null check. Hot-path cost per call:
// one Acquire load + one slot load + one vtable call.

struct NullNic;

impl Nic for NullNic {
    fn name(&self) -> &'static str {
        "none"
    }
    fn probe(&self) -> bool {
        false
    }
    fn send(&self, _data: &[u8], _csum: CsumOffload) {}
    fn tso_available(&self) -> bool {
        false
    }
    fn udp_gso_available(&self) -> bool {
        false
    }
    fn poll_rx(&self, _deliver: fn(Chain<OwnedIOBuf>)) -> usize {
        0
    }
    fn poll_qp(&self, _qp: usize, _deliver: fn(Chain<OwnedIOBuf>)) -> usize {
        0
    }
    fn get_mac(&self, _mac_out: *mut u8) {}
    fn num_queue_pairs(&self) -> u16 {
        1
    }
    fn enable_irq(&self) {}
    fn enable_deferred_tx_kick(&self) {}
    fn flush_tx_staging(&self) {}
    fn flush_tx_kick_if_dirty(&self) -> bool {
        false
    }
    fn poke_interrupt_status(&self) {}
}

static NULL_OPS: DynSlot = DynSlot { nic: &NullNic };

static ACTIVE_OPS: AtomicPtr<DynSlot> = AtomicPtr::new(&NULL_OPS as *const DynSlot as *mut DynSlot);

/// Install `slot`'s driver as the active driver. Called once by
/// `init()` when the first `probe` succeeds.
pub fn set_active_ops(slot: &'static DynSlot) {
    ACTIVE_OPS.store(slot as *const _ as *mut _, Ordering::Release);
}

/// Currently-active driver. Returns the null object (all no-ops)
/// before the first successful probe and on native — callers never
/// need to branch on "is a driver installed?". Use `is_installed()`
/// if a cold-path caller genuinely needs to know.
#[inline]
pub fn active_ops() -> &'static dyn Nic {
    // SAFETY: `ACTIVE_OPS` is always non-null — it starts pointing
    // at `NULL_OPS` and `set_active_ops` only stores pointers
    // derived from `&'static DynSlot`. The Release/Acquire pair
    // synchronises store with readers.
    unsafe { (*(ACTIVE_OPS.load(Ordering::Acquire) as *const DynSlot)).nic }
}

/// Whether a real driver has been installed. Cold-path — used by
/// `Net::enable` to distinguish "no driver linked" from "drivers
/// linked but none probed".
pub fn is_installed() -> bool {
    !core::ptr::eq(
        ACTIVE_OPS.load(Ordering::Acquire) as *const DynSlot,
        &NULL_OPS as *const DynSlot,
    )
}
