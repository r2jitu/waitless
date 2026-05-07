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

// `CurrentWorker` + `PerWorker<T>` (runtime-sized) live in `//uni-worker`
// so native can share them. Kept under the `uni_kernel::percpu` path via
// re-export so existing callers don't shift.
pub use uni_worker::{CurrentWorker, PerWorker};

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

/// Per-core RX inbox slot count for Tier 2 cross-core delivery.
const RX_POOL_SIZE: usize = 16;

/// Zero-copy cross-core RX inbox — the distributor hands an owned
/// [`uni_iobuf::IOBuf`] (typically `IOBuf::External` wrapping a NIC
/// descriptor's storage) and the owning core takes ownership of it.
/// No memcpy on either side: the cross-core hand-off is just an
/// SPSC ring exchange of a pointer-sized index, and the IOBuf
/// itself moves by-value through the slot.
///
/// SPSC discipline: a single producer (the distributor on the
/// receiving core) calls `push`, a single consumer (the owning
/// core) calls `pop`. Both take `&self` and rely on producer-only
/// `next_slot` advance + the `ready` ring's release/acquire pair
/// for visibility.
///
/// Slot lifecycle: each `Option<IOBuf>` cell starts as `None`.
/// `push` writes `Some(iobuf)` into `pool[next_slot]` and then
/// publishes the index via `ready.push`. `pop` reads the index,
/// `take()`s the IOBuf out of the slot (leaving `None`), and
/// returns it. The producer can only wrap back to a slot once the
/// consumer has drained it (by ring-capacity invariant), so the
/// `Some → take → Some` sequence on the same slot is well-ordered.
pub struct RxInbox {
    pool: [UnsafeCell<Option<uni_iobuf::IOBuf>>; RX_POOL_SIZE],
    ready: spsc::Ring<u32>,
    next_slot: AtomicUsize,
}

// SAFETY: same producer/consumer discipline as `RxInbox`. The
// `IOBuf` payload is `Send` (heap variant: `Box<[u8]>`; static:
// `&'static [u8]`; external: explicit `unsafe impl Send`) so
// moving it across cores via the slot is sound. Producer publishes
// the slot's `Some(iobuf)` write with `ready.push`'s release-tail
// store; consumer's `ready.pop` acquire-load makes that write
// visible before it `take()`s.
unsafe impl Sync for RxInbox {}

impl RxInbox {
    pub const fn new() -> Self {
        RxInbox {
            pool: [const { UnsafeCell::new(None) }; RX_POOL_SIZE],
            ready: spsc::Ring::new(),
            next_slot: AtomicUsize::new(0),
        }
    }

    /// Push an `IOBuf` into the inbox. Returns `false` (and drops
    /// `iobuf` — the IOBuf's own Drop runs, releasing any backing
    /// storage / NIC descriptor) when the ring is full. The slot at
    /// `next_slot` is guaranteed `None` by the ring-capacity
    /// invariant: consumer must have drained the previous content
    /// before producer wraps to it.
    pub fn push(&self, iobuf: uni_iobuf::IOBuf) -> bool {
        let slot = self.next_slot.load(Ordering::Relaxed);
        // SAFETY: producer-only write to its current slot. The
        // consumer can only observe this Some after the release-
        // store inside `ready.push`. The slot is guaranteed to be
        // `None` here because the ring's capacity equals the pool
        // size — wrapping back to slot N requires the consumer to
        // have already `pop`'d it.
        unsafe {
            let cell = &mut *self.pool[slot].get();
            *cell = Some(iobuf);
        }
        if !self.ready.push(slot as u32) {
            // Ring is full despite the wrap-invariant — should not
            // happen, but undo the slot write so we don't leak.
            // SAFETY: we just wrote `Some(iobuf)` above; nobody
            // else has touched this slot.
            unsafe {
                let cell = &mut *self.pool[slot].get();
                *cell = None;
            }
            return false;
        }
        self.next_slot.store((slot + 1) % RX_POOL_SIZE, Ordering::Relaxed);
        true
    }

    /// Pop a ready `IOBuf` from the inbox.
    pub fn pop(&self) -> Option<uni_iobuf::IOBuf> {
        let idx = self.ready.pop()?;
        // SAFETY: the matching acquire-load inside `ready.pop`
        // synchronises with the producer's release on
        // `ready.tail`, so the `Some(iobuf)` write is visible.
        // Single consumer ⇒ no concurrent reader.
        let cell = unsafe { &mut *self.pool[idx as usize].get() };
        cell.take()
    }
}

/// Per-core state. Each core has exactly one of these.
/// The TLS register (GS_BASE on x86_64, TPIDR_EL1 on aarch64) points
/// to this struct. Fields at known offsets can be read directly via
/// the TLS register without indirection.
///
/// "Core" here is the bare-metal name for what `uni-worker` calls a
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

    /// RX inbox for Tier 2 cross-core delivery — distributor on
    /// the polling core pushes IOBufs here; owning core pops and
    /// processes via `net_drain_cb` → `net_receive_iobuf`.
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

/// Global array of per-core state. Heap-allocated by `init(n)` once
/// the BSP knows the actual core count, then read-shared from every
/// core. `PerWorker<T>` handles the indexing + interior mutability;
/// before `init`, accesses panic in debug.
static CORES: PerWorker<PerCore> = PerWorker::new();

/// AP poll function: registered by the network layer, called by APs in
/// their event loop. Returns true if work was done. Stored as a typed
/// `AtomicFn` so cross-core publish/subscribe is a real release/acquire
/// pair without per-call-site fn-pointer transmutes.
static AP_POLL_FN: crate::sync::AtomicFn<fn(u32) -> bool> = crate::sync::AtomicFn::null();

/// Initialise per-core state for `count` cores. BSP-only, single-
/// threaded, before any AP starts and before any `get()`. Publishes
/// `count` via `set_num_workers` so every `PerWorker<T>` (here, in
/// `uni-runtime`, in `net::*`) sizes itself the same.
pub unsafe fn init(count: u32) {
    uni_worker::set_num_workers(count);
    CORES.init(count, |i| PerCore::new(i));
    uni_runtime::init(count);
}

/// Get a shared reference to a core's state.
///
/// SAFETY: caller must ensure `init()` has completed and `id < num_cores()`.
/// Multiple cores may safely call this concurrently — interior mutability
/// (`Atomic*`, `UnsafeCell` behind SPSC discipline) makes shared access sound.
pub unsafe fn get(id: u32) -> &'static PerCore {
    CORES.at(id)
}

/// Total number of cores. Bare-metal-friendly alias for
/// `uni_worker::num_workers()`.
pub fn num_cores() -> u32 {
    uni_worker::num_workers()
}

// `CurrentWorker` used to expose a `.percore()` convenience that walked
// the kernel-specific `CORES` array; now that the token is shared with
// native (which has no `PerCore`) it lives in `uni-worker`. This free
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
