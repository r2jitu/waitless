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
use crate::timer::{TimerWheel, PendingTimers};

/// Maximum number of cores.
pub const MAX_CORES: usize = 8;

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

    /// Timer wheel — only this core fires timers.
    pub timers: TimerWheel,

    /// Pending timers — any core can push, this core drains into wheel.
    pub pending_timers: PendingTimers,

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
            timers: TimerWheel::new(),
            pending_timers: PendingTimers::new(),
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
static mut NUM_CORES: u32 = 1;

/// AP poll function: registered by the network layer, called by APs in
/// their event loop. Returns true if work was done.
///
/// Stored as `AtomicPtr<()>` rather than `static mut` so the cross-core
/// publish/subscribe is a real release/acquire pair, not a volatile read
/// (which is not a synchronisation primitive). The `Option<fn>` is encoded
/// as a nullable raw pointer: null = `None`, non-null = `Some(fn)`.
static AP_POLL_FN: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Initialize per-core state for `count` cores. Must be called exactly
/// once, single-threaded, before any AP starts and before any call to
/// `get()`. After init, all access is via shared `&'static PerCore`.
pub unsafe fn init(count: u32) {
    unsafe {
        let n = count.min(MAX_CORES as u32);
        NUM_CORES = n;
    }
    // Stamp each core's id into its slot. We bypass the `current()`
    // accessor here because at boot time the id field hasn't been
    // written yet — the convention "PerCore.id == its slot index" is
    // what we're establishing right now.
    let n = unsafe { NUM_CORES };
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
    unsafe { NUM_CORES }
}

// ============================================================================
// CurrentCore token: zero-cost proof-of-current-core for typed accessors
// ============================================================================
//
// `CurrentCore` is a non-Send, non-Sync, zero-sized token whose existence
// proves the holder is running on the core whose id is recorded inside it.
// It's obtained by calling `CurrentCore::enter()`, which reads the TLS
// register (TPIDR_EL1 / GS_BASE) once. Subsequent uses of the token avoid
// the syscall-equivalent of re-reading the TLS register on every access.
//
// The token's value is in encoding the per-core ownership rule that
// otherwise lives in comments: "this code path runs on the core whose
// id == cpu_id() at the time of entry." Methods that take `&CurrentCore`
// can rely on that invariant for lock-free per-core mutation.
//
// Zero cost: `CurrentCore` is a `repr(C)` ZST containing only `id: u32`,
// so it occupies one register at most. `enter()` inlines to a single TLS
// register read. The `!Send`/`!Sync` markers are PhantomData<*mut ()> —
// ZSTs that produce no codegen. The end result is exactly the same
// machine code as `let id = cpu_id();` followed by manual checks.

/// Token proving that the holder is currently running on `core(id)`.
/// Cannot be sent to or shared with another thread/core.
#[derive(Clone, Copy)]
pub struct CurrentCore {
    id: u32,
    _not_send: core::marker::PhantomData<*mut ()>,
}

impl CurrentCore {
    /// Read the current core id from the TLS register and bind it into
    /// a token. Cheap (one MRS or `mov gs:[0], eax`).
    #[inline(always)]
    pub fn enter() -> Self {
        CurrentCore {
            id: crate::cpu_id(),
            _not_send: core::marker::PhantomData,
        }
    }

    /// Construct a token from a core id the caller already knows is
    /// the current core (e.g., from the event loop callback dispatch
    /// which threaded `cpu_id()` through earlier). Saves the second
    /// TLS read that `enter()` would do.
    ///
    /// SAFETY: caller must guarantee that `id == cpu_id()` at the time
    /// of the call AND that the token does not outlive the iteration
    /// (which can never happen across threads because `CurrentCore` is
    /// `!Send`).
    #[inline(always)]
    pub unsafe fn from_id_unchecked(id: u32) -> Self {
        CurrentCore {
            id,
            _not_send: core::marker::PhantomData,
        }
    }

    /// The id of the core this token represents.
    #[inline(always)]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get a shared reference to this core's `PerCore` state. Safe by
    /// construction: the token proves we're running on `core(self.id)`,
    /// and `PerCpu::current` returns the corresponding slot.
    #[inline(always)]
    pub fn percore(&self) -> &'static PerCore {
        CORES.current(self)
    }
}

/// Register the AP poll function (called by net layer during init).
/// Release-stores the pointer so APs that observe it via acquire-load
/// also see all writes that happened-before this store.
pub fn set_ap_poll_fn(f: fn(u32) -> bool) {
    AP_POLL_FN.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// Get the AP poll function (called by APs in their event loop).
/// Acquire-loads to pair with `set_ap_poll_fn`'s release-store.
pub fn ap_poll_fn() -> Option<fn(u32) -> bool> {
    let p = AP_POLL_FN.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: only `set_ap_poll_fn` writes here, and it always writes a
        // valid `fn(u32) -> bool` pointer.
        Some(unsafe { core::mem::transmute::<*mut (), fn(u32) -> bool>(p) })
    }
}

// ============================================================================
// PerCpu<T, const N>: typed per-core array
// ============================================================================
//
// The "array of N per-core slots" pattern was open-coded in five places
// before this primitive (CORES, RxInbox/TxStaging pool/ready, tcp::POOLS,
// uni::native::THREADS, net::lib::WAKEUP). Each got the indexing right but
// the *pattern* repeated, with subtly different access functions and
// `unsafe { ... }` justifications.
//
// `PerCpu<T, N>` consolidates the pattern: N slots stored in `UnsafeCell<T>`,
// accessed via either:
//   - `current(&CurrentCore) -> &T` — safe, returns the slot owned by the
//     calling core (the token proves we're on it)
//   - `at(id) -> &T` — needs the caller to follow the per-core ownership
//     discipline (e.g. only the owning core mutates), but is safe at the
//     reference level since cross-core read of fields with interior
//     mutability is fine
//
// `T` itself must use interior mutability (Atomic*, UnsafeCell) for any
// mutation — the same convention as `kernel::percpu::PerCore`.
//
// Zero cost: `PerCpu<T, N>` is `repr(transparent)` over `[UnsafeCell<T>; N]`.
// `current()` inlines to a single array index using the token's id (which
// itself is one register move from the TLS read in `enter()`). The
// `unsafe impl Sync` is the only unsafe in the type; the safety contract
// is documented as "T must be Sync OR the caller must use the per-core
// ownership discipline."

/// Typed per-CPU array of `N` slots of `T`.
#[repr(transparent)]
pub struct PerCpu<T, const N: usize> {
    slots: [core::cell::UnsafeCell<T>; N],
}

// SAFETY: PerCpu provides shared (`&T`) access only. T is responsible
// for its own interior mutability (Atomic*, UnsafeCell, lock, etc.).
// We require T: Sync because cross-core read access is shared, and
// T: Send because the slot is logically transferable between cores
// (though in practice each slot is owned by one core).
unsafe impl<T: Sync + Send, const N: usize> Sync for PerCpu<T, N> {}

impl<T, const N: usize> PerCpu<T, N> {
    /// Construct from an array of N initial values. Const-callable so
    /// the array can live in a `static`.
    #[inline]
    pub const fn new(values: [T; N]) -> Self {
        // Convert [T; N] -> [UnsafeCell<T>; N] field-by-field via ptr
        // copy. This is the only way to do the conversion in const
        // context as of stable Rust. SAFETY: UnsafeCell<T> is
        // repr(transparent) over T, so the layouts match exactly.
        let cells: [core::cell::UnsafeCell<T>; N] = unsafe {
            let cells = core::mem::ManuallyDrop::new(values);
            core::ptr::read(&cells as *const _ as *const [core::cell::UnsafeCell<T>; N])
        };
        PerCpu { slots: cells }
    }

    /// Get a shared reference to the slot for the current core.
    /// Safe by construction: the `&CurrentCore` token proves we hold
    /// exclusive access to the calling core's identity, and the slot's
    /// inner `T` uses interior mutability for any actual mutation.
    #[inline(always)]
    pub fn current(&self, cc: &CurrentCore) -> &T {
        // SAFETY: cc.id() is the calling core's id; reading from the
        // slot returns a `&T` whose mutation discipline is T's job.
        // PerCpu just guarantees that two different cores get
        // different slots.
        unsafe { &*self.slots[cc.id() as usize].get() }
    }

    /// Get a shared reference to slot `id`. Safe at the reference level
    /// (T uses interior mutability), but the caller is responsible for
    /// the per-core ownership convention if they intend to mutate.
    /// Useful for cross-core read access (e.g. core 0 walking every
    /// per-core inbox) and for indexing into a slot whose id was
    /// computed elsewhere.
    #[inline(always)]
    pub fn at(&self, id: u32) -> &T {
        // SAFETY: same as current(); cross-core access is sound at the
        // reference level because T provides its own synchronisation.
        unsafe { &*self.slots[id as usize].get() }
    }

    /// Number of slots.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        N
    }
}
