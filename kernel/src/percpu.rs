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

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::deque::{Deque, Task};
use crate::spsc;

// `CurrentCore` + `PerCpu<T, N>` now live in `//uni-percpu` so native
// can share them. Kept under the `uni_kernel::percpu` path via re-export
// so existing callers don't shift.
pub use uni_percpu::{CurrentCore, PerCpu, MAX_WORKERS};

/// Maximum number of cores. Alias for `uni_percpu::MAX_WORKERS` kept
/// for readability inside the kernel.
pub const MAX_CORES: usize = MAX_WORKERS;

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

impl spsc::Default for Task {
    const DEFAULT: Self = Task { func: noop, arg: 0 };
}

fn noop(_: usize) {}

/// Maximum packet size for RX inbox.
const RX_BUF_SIZE: usize = 1514;

/// Number of RX inbox slots per core.
const RX_POOL_SIZE: usize = 16;

/// A received packet in the inbox: length + data.
#[derive(Clone, Copy)]
pub struct RxPacket {
    pub len: usize,
    pub data: [u8; RX_BUF_SIZE],
}

/// RX inbox: core 0 pushes received frames here, owning core pops and processes.
///
/// SPSC discipline: a single producer (core 0, the distributor) calls `push`,
/// and a single consumer (the owning core) calls `pop_into`. Both take `&self`
/// because they may run concurrently on different cores.
pub struct RxInbox {
    pool: [UnsafeCell<RxPacket>; RX_POOL_SIZE],
    /// Indices of filled packets, ready for the owning core to process.
    ready: spsc::Ring<u32>,
    /// Producer-only cursor into `pool`. AtomicUsize for interior mutability;
    /// only the producer ever stores, so Relaxed is sufficient.
    next_slot: AtomicUsize,
}

// SAFETY: producer/consumer discipline above. The pool slot at `next_slot`
// is written exclusively by the producer before its release-store on the
// `ready` ring's tail, and read exclusively by the consumer after its
// matching acquire-load — same release/acquire chain as `spsc::Ring`.
unsafe impl Sync for RxInbox {}

impl RxInbox {
    pub const fn new() -> Self {
        RxInbox {
            pool: [const { UnsafeCell::new(RxPacket { len: 0, data: [0; RX_BUF_SIZE] }) }; RX_POOL_SIZE],
            ready: spsc::Ring::new(),
            next_slot: AtomicUsize::new(0),
        }
    }

    /// Push a frame into the inbox (called by core 0 during distribution).
    pub fn push(&self, data: &[u8]) -> bool {
        if data.len() > RX_BUF_SIZE {
            return false;
        }
        let slot = self.next_slot.load(Ordering::Relaxed);
        // SAFETY: producer-only write to its current slot. The consumer can
        // only observe this write after the release-store inside `ready.push`.
        unsafe {
            let pkt = &mut *self.pool[slot].get();
            pkt.data[..data.len()].copy_from_slice(data);
            pkt.len = data.len();
        }
        if !self.ready.push(slot as u32) {
            return false;
        }
        self.next_slot.store((slot + 1) % RX_POOL_SIZE, Ordering::Relaxed);
        true
    }

    /// Pop a ready frame into a caller-provided buffer (called by owning core).
    /// Returns the number of bytes copied, or None if the inbox is empty.
    pub fn pop_into(&self, out: &mut [u8]) -> Option<usize> {
        let idx = self.ready.pop()?;
        // SAFETY: the matching acquire-load inside `ready.pop` synchronises
        // with the producer's release on `ready.tail`, so the slot data is
        // visible and stable until the producer's pool wraps RX_POOL_SIZE
        // slots later. Single consumer ⇒ no concurrent reader.
        let pkt = unsafe { &*self.pool[idx as usize].get() };
        let n = pkt.len.min(out.len());
        out[..n].copy_from_slice(&pkt.data[..n]);
        Some(n)
    }
}

/// Per-core state. Each core has exactly one of these.
/// The TLS register (GS_BASE on x86_64, TPIDR_EL1 on aarch64) points
/// to this struct. Fields at known offsets can be read directly via
/// the TLS register without indirection.
///
/// IMPORTANT: `id` must be the first field (offset 0) — cpu_id() reads
/// it directly via `gs:[0]` / TPIDR_EL1 without going through Rust.
#[repr(C)]
pub struct PerCore {
    /// Core ID — MUST be at offset 0 (read by cpu_id() via TLS register).
    pub id: u32,

    _pad: u32, // align next field to 8 bytes

    /// RX inbox for Tier 2 delivery (core 0 writes, this core reads).
    pub rx_inbox: RxInbox,

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

impl TxStaging {
    pub const fn new() -> Self {
        TxStaging {
            pool: [const { UnsafeCell::new(TxPacket { len: 0, data: [0; TX_BUF_SIZE] }) }; TX_POOL_SIZE],
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
        let next = if slot + 1 >= TX_POOL_SIZE { 0 } else { slot + 1 };
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
            inbox: spsc::Ring::new(),
            pinned: spsc::Ring::new(),
            stealable: Deque::new(),
            tx_staging: TxStaging::new(),
        }
    }
}

/// Global array of per-core state. Initialized by core 0 during boot
/// (single-threaded), then read-shared from all cores via the `PerCpu`
/// primitive (which encapsulates the `[UnsafeCell<T>; N]` + per-core
/// indexing pattern that this module used to open-code).
static CORES: PerCpu<PerCore, MAX_CORES> =
    PerCpu::new([const { PerCore::new(0) }; MAX_CORES]);

/// Number of online cores. Set once by `init()` on the BSP, then read
/// by every core. AtomicU32 with Relaxed ordering — there is no other
/// shared state synchronised by this counter; cores merely query it
/// to know how many slots in `CORES` are valid.
static NUM_CORES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(1);

/// AP poll function: registered by the network layer, called by APs in
/// their event loop. Returns true if work was done. Stored as a typed
/// `AtomicFn` so cross-core publish/subscribe is a real release/acquire
/// pair without per-call-site fn-pointer transmutes.
static AP_POLL_FN: crate::sync::AtomicFn<fn(u32) -> bool> = crate::sync::AtomicFn::null();

/// Initialize per-core state for `count` cores. Must be called exactly
/// once, single-threaded, before any AP starts and before any call to
/// `get()`. After init, all access is via shared `&'static PerCore`.
pub unsafe fn init(count: u32) {
    let n = count.min(MAX_CORES as u32);
    NUM_CORES.store(n, core::sync::atomic::Ordering::Release);
    // Stamp each core's id into its slot. We bypass the `current()`
    // accessor here because at boot time the id field hasn't been
    // written yet — the convention "PerCore.id == its slot index" is
    // what we're establishing right now.
    for i in 0..n {
        // SAFETY: init runs single-threaded on the BSP before APs
        // start; no other core has a reference to any slot yet.
        unsafe {
            let slot = CORES.at(i) as *const PerCore as *mut PerCore;
            (*slot).id = i;
        }
    }
}

/// Get a shared reference to a core's state.
///
/// SAFETY: caller must ensure `init()` has completed and `id < num_cores()`.
/// Multiple cores may safely call this concurrently — interior mutability
/// (`Atomic*`, `UnsafeCell` behind SPSC discipline) makes shared access sound.
pub unsafe fn get(id: u32) -> &'static PerCore {
    CORES.at(id)
}

/// Get the total number of cores.
pub fn num_cores() -> u32 {
    NUM_CORES.load(core::sync::atomic::Ordering::Acquire)
}

// `CurrentCore` used to expose a `.percore()` convenience that walked
// the kernel-specific `CORES` array; now that the token is shared with
// native (which has no `PerCore`) it lives in `uni-percpu`. This free
// function fills the same role for bare-metal callers.
#[inline(always)]
pub fn percore(cc: &CurrentCore) -> &'static PerCore {
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
