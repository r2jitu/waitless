// kernel/percpu.rs — Per-core state for the multi-core event loop.
//
// Each core owns a PerCore struct containing its work queues, timer wheel,
// TX staging, and inbox. Core 0 allocates all PerCore structs during boot.
//
// Cross-core sharing model:
//   `percpu::get(id)` returns a *shared* `&'static PerCore`. Producer/consumer
//   discipline on each field is enforced by convention (and documented per
//   field), with interior mutability via `UnsafeCell` / `Atomic*` so multiple
//   cores can safely hold the same shared reference. Returning `&mut PerCore`
//   would require aliased mutable references whenever two cores touched
//   different cores' state simultaneously — undefined behaviour even when
//   the underlying memory accesses don't actually overlap.

use crate::deque::{Deque, Task};
use crate::rx_inbox::{RxInbox, RxNodePool};
use crate::spsc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use iobuf::{Chain, OwnedIOBuf};

// ── Tier 2 cross-core RX inbox ──────────────────────────────────────
//
// `rx_inbox` holds the generic lock-free machinery; the kernel pins
// the payload type and sizes the node pool here.

/// The Tier 2 cross-core RX inbox payload: one received frame — its
/// `Chain` of device RX buffers plus the L2/L3 parse the distributor's
/// classify pass already computed. Carrying the parse lets the owning
/// core skip re-walking eth + IPv4 and go straight to `tcp_receive` /
/// `udp_receive`. Moving it core-to-core copies no frame bytes;
/// dropping the `chain` reposts the backing buffers.
pub struct RxChain {
    /// The L2/L3 parse, computed once on the distributor core.
    pub parsed: net_types::ParsedL3,
    /// The received frame as an owned chain of device RX buffers.
    pub chain: Chain<OwnedIOBuf>,
}

/// Node count of the shared Tier-2 RX node pool.
///
/// The intrusive inbox parks at most one node per device RX buffer
/// not yet reposted, and Tier 2 polls a single RX queue — so the
/// inbox provably never holds more nodes than that queue has buffers
/// (see `rx_inbox`'s overflow proof). This must therefore be ≥ the
/// single-queue RX-buffer count of any driver that runs Tier 2.
/// virtio-net — the only one in this tree — posts `RX_BUFFERS = 256`;
/// gve always runs Tier 1 (per-core queues). 512 is 2× that headroom
/// and also clears gve's 512-entry DQO ring should gve ever be forced
/// single-queue. Bump this if a Tier-2-capable driver with a larger
/// single-queue RX ring is added.
pub const RX_NODE_POOL_CAP: usize = 512;

/// The one shared Tier-2 RX node pool. `static` — no allocator, a
/// stable address for the lifetime of the kernel. Valid only after
/// [`init`] has run its `RX_NODE_POOL.init()`.
static RX_NODE_POOL: RxNodePool<RxChain, RX_NODE_POOL_CAP> = RxNodePool::new();

/// The global Tier-2 RX node pool — the net layer's distributor
/// (`distribute_frame`) and per-core drain callback both route
/// through it.
#[inline]
pub fn rx_node_pool() -> &'static RxNodePool<RxChain, RX_NODE_POOL_CAP> {
    &RX_NODE_POOL
}

/// A cross-core control message — a small copyable fact one core
/// learned that a *different* core owns. Carried by each core's
/// `PerCore::ctrl_inbox` over [`ctrl_node_pool`]: the control twin of
/// the Tier-2 RX data lane (`rx_inbox` + [`rx_node_pool`]), reusing the
/// same MPSC mechanism. The lane is message-generic on purpose — every
/// future cross-core fact (flow rebalancing, migration hints, …) should
/// add a variant here and ride this one audited channel rather than
/// grow a bespoke one. The net stack owns the send/handle policy.
pub enum CtrlMsg {
    /// A TCP Path-MTU report (ICMPv4 Fragmentation-Needed / ICMPv6
    /// Packet-Too-Big) that arrived on a core that does not own the
    /// quoted flow: a multi-queue NIC RSS-hashes the ICMP error by its
    /// *own* header, not the quoted TCP 4-tuple, so it usually lands on
    /// the wrong core. Broadcast so the owning core — whichever it is —
    /// applies it; every other recipient's lookup misses and ignores it.
    PathMtu {
        remote_ip: net_types::IpAddr,
        remote_port: u16,
        local_port: u16,
        /// Quoted first sequence number of the segment the router dropped.
        seq: u32,
        /// Advertised next-hop MTU minus the IP+TCP headers.
        candidate_mss: u16,
    },
}

/// Node count of the shared control-lane pool. Control messages are
/// rare (a PMTUD report fires once per flow per path-MTU change) and a
/// broadcast parks at most `num_cores − 1` nodes until the next drain
/// pass, so 64 is generous. On momentary exhaustion `distribute`
/// returns the message to the sender, which drops it — every current
/// message is an advisory hint whose trigger re-fires (a too-big
/// retransmit elicits a fresh ICMP error).
pub const CTRL_NODE_POOL_CAP: usize = 64;

/// The one shared control-lane node pool. Valid only after [`init`]
/// has run its `CTRL_NODE_POOL.init()`.
static CTRL_NODE_POOL: RxNodePool<CtrlMsg, CTRL_NODE_POOL_CAP> = RxNodePool::new();

/// The global control-lane node pool — senders (`distribute` to a
/// target core's `ctrl_inbox`) and the per-core drain both route
/// through it.
#[inline]
pub fn ctrl_node_pool() -> &'static RxNodePool<CtrlMsg, CTRL_NODE_POOL_CAP> {
    &CTRL_NODE_POOL
}

// `CurrentWorker` + `PerWorker<T>` (runtime-sized) live in `//crates/runtime/worker`
// so native can share them. Kept under the `kernel_bare::percpu` path via
// re-export so existing callers don't shift.
pub use worker::{CurrentWorker, PerWorker};

/// Maximum packet size for TX staging.
const TX_BUF_SIZE: usize = 1514;

/// Number of TX staging slots per core.
const TX_POOL_SIZE: usize = 8;

/// A staged TX packet: length + data.
#[derive(Clone, Copy)]
pub struct TxPacket {
    pub len: usize,
    pub data: [u8; TX_BUF_SIZE],
}

impl spsc::Zero for Task {
    const ZERO: Self = Task { func: noop, arg: 0 };
}

fn noop(_: usize) {}

/// Per-core state. Each core has exactly one of these.
/// The TLS register (GS_BASE on x86_64, TPIDR_EL1 on aarch64) points
/// to this struct. Fields at known offsets can be read directly via
/// the TLS register without indirection.
///
/// "Core" here is the bare-metal name for what `worker` calls a
/// "worker"; this struct lives inside `PerWorker<PerCore>` and is the
/// kernel's concrete per-worker state aggregate, not a separate
/// abstraction.
///
/// IMPORTANT: `id` must be the first field (offset 0) — cpu_id() reads
/// it directly via `gs:[0]` / TPIDR_EL1 without going through Rust.
#[repr(C)]
pub struct PerCore {
    /// Core ID — MUST be at offset 0 (read by cpu_id() via TLS register).
    pub id: u32,

    _pad: u32, // align next field to 8 bytes

    /// RX inbox for Tier 2 cross-core delivery — the distributor
    /// parks a received `Chain<OwnedIOBuf>` here (in a node from the
    /// shared `rx_inbox` node pool, no frame copy); this core drains
    /// it via `net_drain_cb`. See [`crate::rx_inbox`].
    pub rx_inbox: RxInbox,

    /// Control inbox — the cross-core lane for [`CtrlMsg`] facts
    /// (first consumer: wrong-core PMTUD reports). Same MPSC mechanism
    /// as `rx_inbox`, over [`ctrl_node_pool`]; drained by this core in
    /// the same event-loop stage.
    pub ctrl_inbox: RxInbox,

    /// Inbox for Tier 2 RX delivery (SPSC: core 0 writes, this core reads).
    pub inbox: spsc::Ring<Task>,

    /// Pinned tasks — connection-bound work, only this core reads/writes.
    pub pinned: spsc::Ring<Task>,

    /// Stealable tasks — pure compute, thieves can steal from here.
    pub stealable: Deque,

    /// TX staging buffer — this core writes packets here, core 0 flushes (Tier 2).
    pub tx_staging: TxStaging,
}

/// TX staging: fixed pool of packet buffers + SPSC index ring.
///
/// SPSC discipline: a single producer (the owning core) calls `push`, and
/// a single consumer (core 0, the flusher) calls `pop_into`. Both take
/// `&self` so they may run concurrently on different cores.
pub struct TxStaging {
    pool: [UnsafeCell<TxPacket>; TX_POOL_SIZE],
    /// Indices of filled packets, ready for core 0 to flush.
    ready: spsc::Ring<u32>,
    /// Producer-only cursor into `pool`.
    next_slot: AtomicUsize,
}

// SAFETY: producer/consumer discipline above; release/acquire on `ready`.
unsafe impl Sync for TxStaging {}

impl Default for TxStaging {
    fn default() -> Self {
        Self::new()
    }
}

impl TxStaging {
    pub const fn new() -> Self {
        TxStaging {
            pool: [const {
                UnsafeCell::new(TxPacket {
                    len: 0,
                    data: [0; TX_BUF_SIZE],
                })
            }; TX_POOL_SIZE],
            ready: spsc::Ring::new(),
            next_slot: AtomicUsize::new(0),
        }
    }

    /// Stage a packet for transmission (called by owning core).
    pub fn push(&self, data: &[u8]) -> bool {
        if data.len() > TX_BUF_SIZE {
            return false;
        }
        let slot = self.next_slot.load(Ordering::Relaxed);
        if slot >= TX_POOL_SIZE {
            return false; // pool exhausted
        }
        // SAFETY: producer-only write; consumer can only observe via the
        // release-store inside `ready.push`.
        unsafe {
            let pkt = &mut *self.pool[slot].get();
            pkt.data[..data.len()].copy_from_slice(data);
            pkt.len = data.len();
        }
        if !self.ready.push(slot as u32) {
            return false;
        }
        let next = if slot + 1 >= TX_POOL_SIZE {
            0
        } else {
            slot + 1
        };
        self.next_slot.store(next, Ordering::Relaxed);
        true
    }

    /// Pop a ready packet into a caller-provided buffer (called by core 0
    /// during flush). Returns bytes copied, or None if empty.
    pub fn pop_into(&self, out: &mut [u8]) -> Option<usize> {
        let idx = self.ready.pop()?;
        // SAFETY: acquire-load on `ready.tail` synchronises with producer.
        let pkt = unsafe { &*self.pool[idx as usize].get() };
        let n = pkt.len.min(out.len());
        out[..n].copy_from_slice(&pkt.data[..n]);
        Some(n)
    }
}

impl PerCore {
    pub const fn new(id: u32) -> Self {
        PerCore {
            id,
            _pad: 0,
            rx_inbox: RxInbox::new(),
            ctrl_inbox: RxInbox::new(),
            inbox: spsc::Ring::new(),
            pinned: spsc::Ring::new(),
            stealable: Deque::new(),
            tx_staging: TxStaging::new(),
        }
    }
}

/// Global array of per-core state. Heap-allocated by `init(n)` once
/// the BSP knows the actual core count, then read-shared from every
/// core. `PerWorker<T>` handles the indexing + interior mutability;
/// before `init`, accesses panic in debug.
static CORES: PerWorker<PerCore> = PerWorker::new();

/// AP poll function: registered by the network layer, called by APs in
/// their event loop. Returns true if work was done. Stored as a typed
/// `AtomicFn` so cross-core publish/subscribe is a real release/acquire
/// pair without per-call-site fn-pointer transmutes.
static AP_POLL_FN: sync::AtomicFn<fn(u32) -> bool> = sync::AtomicFn::null();

/// Initialise per-core state for `count` cores. Publishes `count`
/// via `set_num_workers` so every `PerWorker<T>` (here, in
/// `executor`, in `net::*`) sizes itself the same.
///
/// # Safety
///
/// BSP-only, single-threaded: must run before any AP starts and
/// before any `get()` call. The implementation initialises shared
/// globals (`CORES`, `RX_NODE_POOL`, `executor`) without
/// synchronisation, relying on no other core being live.
pub unsafe fn init(count: u32) {
    worker::set_num_workers(count);
    CORES.init(count, PerCore::new);
    // Link the shared Tier-2 cross-core RX node pool's free-list.
    // BSP-only, single-threaded — no AP has started, so this races
    // nothing.
    RX_NODE_POOL.init();
    CTRL_NODE_POOL.init();
    executor::init(count);
}

/// Get a shared reference to a core's state.
///
/// # Safety
///
/// Caller must ensure `init()` has completed and `id < num_cores()`.
/// Multiple cores may safely call this concurrently — interior mutability
/// (`Atomic*`, `UnsafeCell` behind SPSC discipline) makes shared access sound.
pub unsafe fn get(id: u32) -> &'static PerCore {
    CORES.at(id)
}

/// Total number of cores. Bare-metal-friendly alias for
/// `worker::num_workers()`.
pub fn num_cores() -> u32 {
    worker::num_workers()
}

// `CurrentWorker` used to expose a `.percore()` convenience that walked
// the kernel-specific `CORES` array; now that the token is shared with
// native (which has no `PerCore`) it lives in `worker`. This free
// function fills the same role for bare-metal callers.
#[inline(always)]
pub fn percore(cc: &CurrentWorker) -> &'static PerCore {
    CORES.current(cc)
}

/// Register the AP poll function (called by net layer during init).
/// Release-stores via `AtomicFn` so APs that observe it via acquire-load
/// also see all writes that happened-before this store.
pub fn set_ap_poll_fn(f: fn(u32) -> bool) {
    AP_POLL_FN.store(f);
}

/// Get the AP poll function (called by APs in their event loop).
pub fn ap_poll_fn() -> Option<fn(u32) -> bool> {
    AP_POLL_FN.load()
}
