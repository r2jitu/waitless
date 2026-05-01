// uni-runtime/src/net.rs — UDP reactor with per-worker inboxes.
//
// ## Model
//
// `UdpSocket::bind(port)` claims one of `MAX_UDP_SOCKETS` static
// slots. Each slot owns `MAX_WORKERS` independent SPSC inboxes —
// one per worker. Inbound datagrams are pushed into the inbox of
// the worker that received them (bare-metal Tier 1: the core whose
// RX queue fired; Tier 2: the distributor; native: the worker whose
// kqueue/epoll fired for the sibling fd). `recv_from` pulls from
// the calling worker's inbox.
//
// Packets delivered to worker N stay on worker N — no cross-core
// push, no cross-core pop, no cross-core waker walk. The NIC's flow
// hash already distributes traffic across workers; the reactor
// preserves that fan-out all the way to the async handler.
//
// ## User API
//
// The common pattern — "run a per-worker handler loop" — is the
// `run` method:
//
// ```rust
// let echo = UdpSocket::bind(7)?.run(|sock| async move {
//     let mut buf = [0u8; 1500];
//     loop {
//         let (ip, port, n) = sock.recv_from(&mut buf).await;
//         let _ = sock.send_to(ip, port, &buf[..n]);
//     }
// });
// // store `echo` (a `UdpHandle`) on a long-lived owner so it
// // tears down cleanly when the owner drops.
// ```
//
// `run` consumes the socket, wraps it in an `Arc`, and arranges
// the same async body to be spawned on every worker on that
// worker's next tick. Forgetting to spawn-per-worker is
// impossible — bind+spawn happen together.
//
// The lower-level `bind` + `recv_from` / `send_to` is still
// exposed for short-lived request/reply patterns (DHCP client,
// DNS query, fire-and-forget emit) that don't need fan-out.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};

use uni_worker::{CurrentWorker, PerWorker, num_workers};

// ---- Sizing -----------------------------------------------------------------

pub const MAX_UDP_SOCKETS: usize = 256;
/// Per-worker inbox depth. The hot path (same-core producer + same-
/// core consumer) drains one entry per task poll, so this is purely
/// burst tolerance for when delivery outpaces task scheduling (NIC
/// RX interrupt coalescing, slow handler work, cross-core delivery
/// on Tier 2).
///
/// History: 16 → 128 → 64. The original 16 was tuned for low-pps
/// workloads; 128 was bumped for udp_peak's ~700k pps headroom
/// (NIC poll batches of 32+ packets per IRQ + slow drain → mid-
/// batch drops at 16 slots, ~22 µs of tolerance). The current 64
/// gives ~88 µs burst tolerance — empirical udp_peak rates match
/// the 128-slot peak — while letting `gateway_max` scale to 64
/// conns/core without overwhelming the kernel heap. With the
/// 96 MB heap, even higher inbox sizes are affordable; this is
/// the sweet spot where udp_peak is unaffected and per-conn
/// memory stays under 100 KB.
///
/// At gateway_max's headline shape (64 conns × 3 workers, each
/// conn binding one ephemeral UDP socket), heap cost is `64 × 3
/// × 64 × 1508 ≈ 18 MB`. The 96 MB heap (see kernel/src/mm.rs)
/// covers this with plenty of margin for the rest of the runtime.
///
/// Storage is **heap-allocated** lazily on `bind()` (see the
/// `slots` field of `WorkerInbox`) rather than living in static BSS.
/// The aarch64 boot path's BSS-zero loop has an empirically observed
/// ~3 MB ceiling above which the guest hangs before the first serial
/// write — broken on HVF and on QEMU TCG, didn't reproduce on the
/// x86 deploy path because the sectional layout is different.
/// Keeping the buffer off-BSS sidesteps that limit entirely (and
/// also means apps that never bind a UDP socket pay zero RAM).
/// Server-style bind inbox depth. Sized for udp_peak's bursty
/// workload (NIC poll batches of 32+ packets per IRQ + slow drain
/// → mid-batch drops at 16). 64 slots = 64 × 1508 B ≈ 96 KB per
/// (worker, port) — affordable for the small set of declared
/// listening ports.
const SERVER_INBOX_CAPACITY: usize = 64;
/// Ephemeral bind inbox depth. Tuned for request-response shapes
/// (gateway flows, DNS clients, NTP) where there's only ever 1–2
/// in-flight datagrams per binding. At thousands of concurrent
/// ephemerals the per-binding inbox memory dominates the heap, so
/// keep this small. 8 slots = 8 × 1508 B ≈ 12 KB per binding ⇒
/// 5 000 binds ≈ 60 MB total inbox memory.
const EPH_INBOX_CAPACITY: usize = 8;
const MAX_PAYLOAD: usize = 1500;

// ---- SpinLock (waker cell) --------------------------------------------------

struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}

struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> SpinLock<T> {
    const fn new(v: T) -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(v),
        }
    }

    fn lock(&self) -> SpinGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        SpinGuard { lock: self }
    }
}

impl<'a, T> core::ops::Deref for SpinGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: holding the lock gives us exclusive access.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for SpinGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: holding the lock gives us exclusive access.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

// ---- Waker helper -----------------------------------------------------------

/// Store `w` into `slot` unless it already holds a waker that
/// would wake the same task (`Waker::will_wake`). Used on the
/// slow path of every `poll` that parks on a per-port waker slot
/// to keep the clone off the hot path when the same task repolls
/// in a tight loop.
fn store_waker_if_needed(slot: &SpinLock<Option<Waker>>, w: &Waker) {
    let mut slot = slot.lock();
    let need_store = match &*slot {
        Some(existing) => !existing.will_wake(w),
        None => true,
    };
    if need_store {
        *slot = Some(w.clone());
    }
}

// ---- Launcher helper --------------------------------------------------------

/// Install a freshly-spawned worker task into its per-worker slot,
/// handling the drop-race with `*Handle::Drop`: if `stopping` was
/// set between the launcher's first check and now, abort the task
/// we just spawned instead of stashing it (its abort flag would
/// otherwise go unseen until the next drop, leaking the task for
/// the rest of the process). Taking the lock once keeps the common
/// case to a single acquire/release.
fn install_worker_task(
    stopping: &AtomicBool,
    handles: &PerWorker<SpinLock<Option<crate::TaskHandle>>>,
    h: crate::TaskHandle,
) {
    let cc = CurrentWorker::enter();
    let mut slot = handles.current(&cc).lock();
    if stopping.load(Ordering::Acquire) {
        drop(slot);
        h.abort();
    } else {
        *slot = Some(h);
    }
}

// ---- Datagram + worker inbox ------------------------------------------------

#[repr(C)]
struct Datagram {
    src_ip: [u8; 4],
    src_port: u16,
    len: u16,
    payload: [u8; MAX_PAYLOAD],
}

impl Datagram {
    const ZERO: Self = Datagram {
        src_ip: [0; 4],
        src_port: 0,
        len: 0,
        payload: [0; MAX_PAYLOAD],
    };
}

/// One worker's view of a socket. Producer and consumer are the
/// same worker in the common case: the delivery path runs on the
/// core that received the packet, and the `recv_from` task awaits
/// on that same worker.
///
/// Capacity is per-bind, not a global const, so server bindings
/// can keep deep buffers for burst tolerance (e.g. udp_peak) while
/// ephemeral bindings — almost always request-response, so 1–2
/// in-flight at most — stay cheap. At thousands of concurrent
/// ephemeral binds the per-binding inbox memory is the dominant
/// heap cost: a 64-slot inbox is ~96 KB; an 8-slot inbox is ~12 KB.
struct WorkerInbox {
    head: AtomicU32,
    tail: AtomicU32,
    /// Heap-allocated `[Datagram; capacity]`, allocated on first
    /// bind via `ensure_alloc` (capacity baked in at that point)
    /// and preserved across rebinds. Null until the first bind.
    slots: AtomicPtr<Datagram>,
    /// Capacity is a power of two so wrap-around is `(idx+1) & mask`
    /// instead of a runtime modulo. Stored on the inbox itself so
    /// different bindings can use different capacities.
    mask: AtomicU32,
    /// Hot-path gate for the producer's "wake the receiver" step.
    /// `false` means there is no parked task to wake — the producer
    /// can skip the `waker.lock()` round-trip entirely. Skipping
    /// the lock is the single biggest win on the udp_peak hot path:
    /// at ~700k pps, two atomic ops on the spinlock cache line per
    /// packet was costing ~half the throughput.
    waker_present: core::sync::atomic::AtomicBool,
    waker: SpinLock<Option<Waker>>,
}

unsafe impl Sync for WorkerInbox {}
unsafe impl Send for WorkerInbox {}

impl WorkerInbox {
    const fn new() -> Self {
        WorkerInbox {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            slots: AtomicPtr::new(core::ptr::null_mut()),
            mask: AtomicU32::new(0),
            waker_present: core::sync::atomic::AtomicBool::new(false),
            waker: SpinLock::new(None),
        }
    }

    /// Lazily allocate this inbox's slot array. `capacity` must be
    /// a power of two ≤ 1024. Idempotent across rebinds; once
    /// allocated, the array (and its capacity) stick for the
    /// process. Returns `false` on allocation failure.
    fn ensure_alloc(&self, capacity: usize) -> bool {
        if !self.slots.load(Ordering::Acquire).is_null() {
            return true;
        }
        debug_assert!(capacity.is_power_of_two());
        debug_assert!(capacity > 0);
        let mut buf: alloc::vec::Vec<Datagram> =
            alloc::vec::Vec::with_capacity(capacity);
        for _ in 0..capacity {
            buf.push(Datagram::ZERO);
        }
        let boxed = buf.into_boxed_slice();
        let ptr = Box::leak(boxed).as_mut_ptr();
        self.mask.store((capacity as u32) - 1, Ordering::Release);
        self.slots.store(ptr, Ordering::Release);
        true
    }

    fn try_push(&self, src_ip: [u8; 4], src_port: u16, payload: &[u8]) -> bool {
        let slots_ptr = self.slots.load(Ordering::Acquire);
        if slots_ptr.is_null() {
            return false;
        }
        let mask = self.mask.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        let next = tail.wrapping_add(1) & mask;
        if next == head {
            return false;
        }
        // SAFETY: SPSC — producer owns the tail slot until Release store
        // below; `slots_ptr` was published by `ensure_alloc` with Release
        // ordering before the owning UdpState's port was set non-zero,
        // and we only get here once a valid `UdpSocket` is in scope.
        let slot = unsafe { &mut *slots_ptr.add(tail as usize) };
        slot.src_ip = src_ip;
        slot.src_port = src_port;
        let n = payload.len().min(MAX_PAYLOAD);
        slot.len = n as u16;
        slot.payload[..n].copy_from_slice(&payload[..n]);
        self.tail.store(next, Ordering::Release);
        true
    }

    fn pop_into(&self, buf: &mut [u8]) -> Option<([u8; 4], u16, usize)> {
        let slots_ptr = self.slots.load(Ordering::Acquire);
        if slots_ptr.is_null() {
            return None;
        }
        let mask = self.mask.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        // SAFETY: SPSC — consumer owns the head slot until Release store
        // below; same publication argument as `try_push`.
        let slot = unsafe { &*slots_ptr.add(head as usize) };
        let n = (slot.len as usize).min(buf.len());
        buf[..n].copy_from_slice(&slot.payload[..n]);
        let r = (slot.src_ip, slot.src_port, n);
        let next = head.wrapping_add(1) & mask;
        self.head.store(next, Ordering::Release);
        Some(r)
    }

    /// Zero-copy peek + commit: invoke `f` with a borrow of the head
    /// slot's payload (and its source) when one is available, then
    /// advance `head`. Returns `f`'s return value on success, or
    /// hands the closure back unchanged (`Err(f)`) when the inbox is
    /// empty so the caller can retry on a later tick.
    ///
    /// POSIX equivalent: `recv()` — but `recv()` *must* copy because
    /// the kernel can't trust user code to release the buffer in
    /// finite time. We can: the closure has to return.
    fn pop_with<F, R>(&self, f: F) -> Result<R, F>
    where
        F: FnOnce(&[u8], [u8; 4], u16) -> R,
    {
        let slots_ptr = self.slots.load(Ordering::Acquire);
        if slots_ptr.is_null() {
            return Err(f);
        }
        let mask = self.mask.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return Err(f);
        }
        // SAFETY: same SPSC ownership argument as `pop_into` — we
        // own the head slot for the duration of the closure call.
        let slot = unsafe { &*slots_ptr.add(head as usize) };
        let n = slot.len as usize;
        let r = f(&slot.payload[..n], slot.src_ip, slot.src_port);
        let next = head.wrapping_add(1) & mask;
        self.head.store(next, Ordering::Release);
        Ok(r)
    }

    fn reset(&self) {
        self.head.store(0, Ordering::Relaxed);
        self.tail.store(0, Ordering::Relaxed);
        *self.waker.lock() = None;
        self.waker_present.store(false, Ordering::Release);
    }

    /// Receiver-side: park `w` for the producer to wake when the next
    /// datagram arrives. Sets the `waker_present` gate so the
    /// producer's hot path knows there's work to do.
    fn park_waker(&self, w: &Waker) {
        let mut slot = self.waker.lock();
        let need_store = match &*slot {
            Some(existing) => !existing.will_wake(w),
            None => true,
        };
        if need_store {
            *slot = Some(w.clone());
        }
        // Release ordering so the producer's Acquire-load sees the
        // waker store before the gate flips on.
        self.waker_present.store(true, Ordering::Release);
    }

    /// Receiver-side: drop any parked waker. Called when the receiver
    /// picks up a datagram via the slow-path's re-check (i.e., we
    /// parked, but the producer-side store landed before our
    /// re-pop), so the producer can short-circuit the next packet.
    fn unpark(&self) {
        self.waker_present.store(false, Ordering::Release);
        *self.waker.lock() = None;
    }

    /// Producer-side: wake the parked receiver if any. The
    /// `waker_present` gate makes this branch-free in the steady-state
    /// `recv_from` loop where the receiver pops in the fast path and
    /// never parks.
    fn wake_if_parked(&self) {
        // Acquire so we observe the receiver's prior waker store
        // before reading the slot.
        if !self.waker_present.load(Ordering::Acquire) {
            return;
        }
        let taken = self.waker.lock().take();
        if let Some(w) = taken {
            self.waker_present.store(false, Ordering::Release);
            w.wake();
        }
    }
}

// ---- Per-port state ---------------------------------------------------------

/// Server-style binding: one slot per declared listening port.
/// Inbound delivery fans out to every worker's inbox so a multi-
/// `run` listener sees the receiving worker's flow. Owner-pinned
/// delivery (single-task-on-one-worker) is the ephemeral path's
/// job and lives in `EphPool` instead.
struct UdpState {
    port: AtomicU16,
    inboxes: PerWorker<WorkerInbox>,
}

impl UdpState {
    const fn new() -> Self {
        UdpState {
            port: AtomicU16::new(0),
            inboxes: PerWorker::new(),
        }
    }
}

static UDP_REGISTRY: [UdpState; MAX_UDP_SOCKETS] =
    [const { UdpState::new() }; MAX_UDP_SOCKETS];

// ---- Ephemeral port pool (per-worker) ---------------------------------------
//
// Ephemeral binds use a separate registry from server-style `bind(port)`:
// every owner-pinned socket lives in a per-worker pool, with the slot
// index encoding the port number. That gives `deliver_udp` an O(1)
// port→slot mapping for ephemeral traffic, eliminates the linear-scan
// hot path under heavy ephemeral churn, and removes any compile-time
// cap (a worker can hold up to `EPH_RANGE / num_workers` concurrent
// flows, the limit being the protocol-level port number space).
//
// Encoding: `port = EPHEMERAL_BASE + slot_idx * num_workers + worker_id`.
// Inverse: `worker = (port - base) % num_workers`,
//          `slot   = (port - base) / num_workers`.
//
// Storage is chunked: each worker has up to `MAX_CHUNKS_PER_WORKER`
// pointers to lazily-allocated `EphChunk`s of `EPH_CHUNK_SIZE` slots.
// New chunks are allocated on the owner worker only; cross-worker
// readers (`deliver_udp`) acquire-load the chunk pointer and treat
// null as "not bound."
//
// Per-slot bookkeeping is single-writer (the owner worker handles
// every bind/unbind), so the free-list is a plain `Vec<u32>` behind
// `UnsafeCell` rather than a lock-free queue.

const EPHEMERAL_BASE: u16 = 49152;
/// Slot count per chunk. Sized so a chunk fits comfortably in a few
/// pages and so most workloads only ever allocate the first chunk.
const EPH_CHUNK_SIZE: usize = 256;
/// Worst-case (single-worker) ephemeral capacity is the full
/// 16 384-port range divided into `EPH_CHUNK_SIZE` chunks. Higher
/// worker counts use fewer chunks per worker; the surplus pointer
/// slots stay null.
const MAX_CHUNKS_PER_WORKER: usize = 64;

struct EphSlot {
    /// 0 ⇒ free; otherwise equals the encoded port for this slot
    /// position. Cross-worker readers Acquire-load to observe the
    /// inbox initialisation that the owner published before the
    /// store of the port.
    port: AtomicU16,
    /// Single inbox owned by the worker that allocated this slot.
    /// Producers (any worker via `deliver_udp`) push; the consumer
    /// (the owning worker only, since `UdpSocket` is `!Send`) pops
    /// via `recv_from`.
    inbox: WorkerInbox,
}

impl EphSlot {
    const fn new() -> Self {
        EphSlot {
            port: AtomicU16::new(0),
            inbox: WorkerInbox::new(),
        }
    }
}

#[repr(C)]
struct EphChunk {
    slots: [EphSlot; EPH_CHUNK_SIZE],
}

struct EphPool {
    chunks: [AtomicPtr<EphChunk>; MAX_CHUNKS_PER_WORKER],
    /// Owner-worker-only bookkeeping. `UnsafeCell` because no other
    /// worker reads or writes these fields; the pool is single-writer
    /// for everything except `chunks` (cross-worker readable) and
    /// `EphSlot::port` / `EphSlot::inbox` (cross-worker via SPSC).
    bookkeeping: UnsafeCell<EphBookkeeping>,
}

struct EphBookkeeping {
    /// Slots that were allocated and later freed; reused before
    /// growing into never-allocated territory.
    free_list: alloc::vec::Vec<u32>,
    /// First slot index that has never been allocated.
    next_alloc: u32,
}

// SAFETY: `chunks` is cross-worker-readable via Acquire/Release on
// the AtomicPtrs; `bookkeeping` is single-writer (owner worker only).
// Both invariants are upheld by the bind/unbind paths.
unsafe impl Sync for EphPool {}

impl EphPool {
    fn new() -> Self {
        EphPool {
            chunks: [const { AtomicPtr::new(core::ptr::null_mut()) };
                     MAX_CHUNKS_PER_WORKER],
            bookkeeping: UnsafeCell::new(EphBookkeeping {
                free_list: alloc::vec::Vec::new(),
                next_alloc: 0,
            }),
        }
    }
}

static EPH_POOLS: PerWorker<EphPool> = PerWorker::new();

/// Idempotent boot-time init. Called from the first ephemeral
/// `open` on each worker; cheap if already done.
fn ensure_eph_init() {
    EPH_POOLS.ensure_init(num_workers(), |_| EphPool::new());
}

/// Decode `(worker, slot_idx)` from a port in the ephemeral range,
/// or `None` if the port is outside the range.
#[inline]
fn decode_eph(port: u16) -> Option<(u32, u32)> {
    if port < EPHEMERAL_BASE {
        return None;
    }
    let n = num_workers();
    if n == 0 {
        return None;
    }
    let off = (port - EPHEMERAL_BASE) as u32;
    Some((off % n, off / n))
}

/// Look up the live `EphSlot` for `port`, returning `None` if the
/// port is unbound (chunk null or slot's port field is 0). Acquire-
/// loads the chunk pointer + slot port so the producer's Release
/// stores in the bind path are observed.
fn lookup_eph(port: u16) -> Option<&'static EphSlot> {
    let (worker, slot_idx) = decode_eph(port)?;
    if !EPH_POOLS.is_initialized() {
        return None;
    }
    if worker >= EPH_POOLS.len() {
        return None;
    }
    let pool = EPH_POOLS.at(worker);
    let chunk_idx = (slot_idx as usize) / EPH_CHUNK_SIZE;
    if chunk_idx >= MAX_CHUNKS_PER_WORKER {
        return None;
    }
    let chunk = pool.chunks[chunk_idx].load(Ordering::Acquire);
    if chunk.is_null() {
        return None;
    }
    // SAFETY: chunks once published live for the process lifetime.
    let slot = unsafe { &(*chunk).slots[(slot_idx as usize) % EPH_CHUNK_SIZE] };
    if slot.port.load(Ordering::Acquire) == 0 {
        return None;
    }
    Some(slot)
}

// ---- Backend vtable (UDP) ---------------------------------------------------

/// All UDP backend hooks. Installed once at boot by the platform
/// backend — native (POSIX sockets) or bare-metal (integrated NIC
/// driver + protocol stack). `UdpSocket::bind` / `send_to` /
/// `Drop` dispatch through a single atomic load instead of one
/// per hook.
pub struct UdpBackend {
    /// Called after `UdpSocket::bind` claims a UDP_REGISTRY slot.
    /// `None` on bare-metal (routing is REGISTRY-only); `Some` on
    /// native.
    ///
    /// `owner_worker == None` is the fanout case (`UdpSocket::bind`):
    /// native opens NUM_THREADS SO_REUSEPORT siblings so the kernel
    /// distributes inbound by 4-tuple hash across the per-worker
    /// recv loops.
    ///
    /// `owner_worker == Some(w)` is the single-owner case
    /// (`bind_ephemeral`, gateway / sidecar pattern): native opens
    /// just one socket on worker `w`, no SO_REUSEPORT — every reply
    /// lands on `w`'s kqueue, and the runtime's owner-aware
    /// `deliver_udp` keeps the one-bound-socket invariant.
    pub bind: Option<fn(port: u16, owner_worker: Option<u32>) -> Result<(), ()>>,
    /// Mirror of `bind` — called on port release to let the
    /// backend tear down per-bind state. Same optional-on-bare-
    /// metal rationale.
    pub unbind: Option<fn(port: u16)>,
    /// Datagram send transport. Mandatory: `UdpSocket::send_to`
    /// returns `Err(())` if the backend isn't installed yet.
    pub send: fn(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]),
}

static UDP_BACKEND: AtomicPtr<UdpBackend> =
    AtomicPtr::new(core::ptr::null_mut());

/// Install the UDP backend. Call once at boot, before any
/// `UdpSocket::bind` / `send_to`. Safe to call more than once —
/// last writer wins — but that's not a supported runtime pattern.
pub fn register_udp_backend(b: &'static UdpBackend) {
    UDP_BACKEND.store(b as *const _ as *mut _, Ordering::Release);
}

#[inline]
fn udp_backend() -> Option<&'static UdpBackend> {
    let p = UDP_BACKEND.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: `register_udp_backend` stores `&'static` references;
        // the pointer is either null or a valid `&'static UdpBackend`.
        Some(unsafe { &*p })
    }
}

// ---- Public API -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpBindError {
    AllSlotsBusy,
    PortInUse,
    InvalidPort,
    /// Backend-side bind step failed (native OS refused to open the
    /// SO_REUSEPORT sibling sockets for this port).
    BackendFailed,
}

/// A UDP socket bound to one port.
///
/// Two lifecycles, backed by two different storage paths:
///   * **Server-style** (`UdpSocket::bind(port)`): claims a slot in
///     the static `UDP_REGISTRY`. Apps and shared listeners use this.
///     Inbound delivery fans out to every worker's inbox so a
///     `run`-style fanout body sees the receiving worker's flow.
///   * **Ephemeral** (`UdpSocket::open_ephemeral`): allocates a slot
///     in the calling worker's `EphPool`. The slot's *position* in
///     the pool encodes the port number, so `deliver_udp` can route
///     inbound packets in O(1) without scanning a registry. Owner-
///     pinned: every reply lands in the allocating worker's inbox.
#[must_use = "UdpSocket releases its port on drop; bind without \
              using the socket immediately releases it again"]
pub struct UdpSocket {
    port: u16,
    slot: SlotRef,
    /// `UdpHandle::Drop` releases the port slot and calls the
    /// backend's unbind hook eagerly so a subsequent
    /// `bind(same_port)` works without waiting for aborted tasks
    /// to actually drop their `Arc<UdpSocket>` clones. This flag
    /// makes the later `UdpSocket::Drop` (on the last Arc drop) a
    /// no-op. Plain `bind + drop` paths leave it clear and get
    /// the release here.
    released: AtomicBool,
}

#[derive(Clone, Copy)]
enum SlotRef {
    /// Index into the static `UDP_REGISTRY`.
    Server(u32),
    /// Position in the per-worker ephemeral pool. The port number
    /// is fully determined by `(worker, slot_idx)`, which means
    /// `deliver_udp` can recover the slot from the inbound port
    /// without consulting a registry.
    Ephemeral { worker: u32, slot_idx: u32 },
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        if self.released.swap(true, Ordering::AcqRel) {
            // Already released by `UdpHandle::Drop`.
            return;
        }
        match self.slot {
            SlotRef::Server(idx) => {
                // Clear the registry slot first (so the port is
                // immediately available for a new bind on this
                // thread) and only then notify the backend. Native's
                // unbind hook closes POSIX fds, which is much
                // slower and doesn't need to happen before the slot
                // is reusable.
                UDP_REGISTRY[idx as usize].port.store(0, Ordering::Release);
            }
            SlotRef::Ephemeral { worker, slot_idx } => {
                release_eph_slot(worker, slot_idx);
            }
        }
        if let Some(unbind) = udp_backend().and_then(|b| b.unbind) {
            unbind(self.port);
        }
        // The inbox's unconsumed entries (if any) stay — the next
        // bind that lands on this slot calls `reset()` on every
        // worker's inbox before use.
    }
}

/// Free an ephemeral slot. Owner-worker only: the bookkeeping
/// (free list + next-alloc cursor) is single-writer by design.
fn release_eph_slot(worker: u32, slot_idx: u32) {
    if !EPH_POOLS.is_initialized() || worker >= EPH_POOLS.len() {
        return;
    }
    let pool = EPH_POOLS.at(worker);
    let chunk_idx = (slot_idx as usize) / EPH_CHUNK_SIZE;
    if chunk_idx >= MAX_CHUNKS_PER_WORKER {
        return;
    }
    let chunk = pool.chunks[chunk_idx].load(Ordering::Acquire);
    if !chunk.is_null() {
        // SAFETY: chunks once published live for the process lifetime.
        let slot = unsafe {
            &(*chunk).slots[(slot_idx as usize) % EPH_CHUNK_SIZE]
        };
        slot.port.store(0, Ordering::Release);
    }
    // Push slot index to the free list (owner-only access).
    // SAFETY: `release_eph_slot` is invoked from `UdpSocket::Drop`,
    // which runs on the owning worker (sockets are not migrated
    // across workers; the recv future is `!Send`).
    let bk = unsafe { &mut *pool.bookkeeping.get() };
    bk.free_list.push(slot_idx);
}

impl UdpSocket {
    pub fn bind(port: u16) -> Result<UdpSocket, UdpBindError> {
        if port == 0 {
            return Err(UdpBindError::InvalidPort);
        }
        for state in UDP_REGISTRY.iter() {
            if state.port.load(Ordering::Acquire) == port {
                return Err(UdpBindError::PortInUse);
            }
        }
        for (idx, state) in UDP_REGISTRY.iter().enumerate() {
            if state
                .port
                .compare_exchange(0, port, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                state.inboxes.ensure_init(num_workers(), |_| WorkerInbox::new());
                for w in 0..num_workers() {
                    let inbox = state.inboxes.at(w);
                    if !inbox.ensure_alloc(SERVER_INBOX_CAPACITY) {
                        state.port.store(0, Ordering::Release);
                        return Err(UdpBindError::BackendFailed);
                    }
                    inbox.reset();
                }
                if let Some(bind) = udp_backend().and_then(|b| b.bind) {
                    if bind(port, None).is_err() {
                        state.port.store(0, Ordering::Release);
                        return Err(UdpBindError::BackendFailed);
                    }
                }
                return Ok(UdpSocket {
                    port,
                    slot: SlotRef::Server(idx as u32),
                    released: AtomicBool::new(false),
                });
            }
        }
        Err(UdpBindError::AllSlotsBusy)
    }

    /// Open an ephemeral UDP socket pinned to the calling worker.
    ///
    /// Allocates a slot from the worker's `EphPool` (lock-free
    /// per-worker free-list / bump allocator) and derives the port
    /// number from the slot position via
    /// `port = EPHEMERAL_BASE + slot_idx * num_workers + worker_id`.
    /// That encoding lets `deliver_udp` route inbound packets to
    /// the right slot in O(1) by decoding the port; no global
    /// registry scan, no compile-time slot cap, no cross-worker
    /// contention on bind.
    ///
    /// Owner-pinned by construction: every reply for this port
    /// lands on the allocating worker's inbox regardless of which
    /// core observed the wire packet (the same correctness
    /// guarantee `bind_ephemeral` provided before this rewrite).
    pub fn open_ephemeral() -> Result<UdpSocket, UdpBindError> {
        ensure_eph_init();
        let me = CurrentWorker::enter().id();
        let pool = EPH_POOLS.at(me);
        let n = num_workers();
        if n == 0 {
            return Err(UdpBindError::AllSlotsBusy);
        }

        // Owner-only access to bookkeeping: pop a recycled slot or
        // bump the never-allocated frontier.
        // SAFETY: only the owning worker reaches this branch
        // (PerWorker indexed by `me`), so the UnsafeCell is single-
        // writer.
        let slot_idx = unsafe {
            let bk = &mut *pool.bookkeeping.get();
            if let Some(idx) = bk.free_list.pop() {
                idx
            } else {
                let idx = bk.next_alloc;
                bk.next_alloc = bk.next_alloc.saturating_add(1);
                idx
            }
        };

        // Bound on the slot index so the encoded port stays inside
        // the IANA ephemeral range.
        let max_slots_per_worker = ((u16::MAX as u32) - EPHEMERAL_BASE as u32 + 1) / n;
        if slot_idx >= max_slots_per_worker {
            // Out of port space for this worker; push back the
            // bumped index and bail.
            // SAFETY: same owner-only bookkeeping invariant.
            unsafe {
                let bk = &mut *pool.bookkeeping.get();
                bk.free_list.push(slot_idx);
            }
            return Err(UdpBindError::AllSlotsBusy);
        }

        // Lazily allocate the chunk for this slot index.
        let chunk_idx = (slot_idx as usize) / EPH_CHUNK_SIZE;
        if chunk_idx >= MAX_CHUNKS_PER_WORKER {
            return Err(UdpBindError::AllSlotsBusy);
        }
        let chunk_ptr = pool.chunks[chunk_idx].load(Ordering::Acquire);
        let chunk = if chunk_ptr.is_null() {
            let boxed: Box<EphChunk> = Box::new(EphChunk {
                slots: [const { EphSlot::new() }; EPH_CHUNK_SIZE],
            });
            let raw = Box::into_raw(boxed);
            // Cross-worker readers acquire-load this pointer; we
            // only ever publish a fully-initialised chunk.
            match pool.chunks[chunk_idx].compare_exchange(
                core::ptr::null_mut(),
                raw,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => raw,
                Err(existing) => {
                    // Another path won; drop our box.
                    // SAFETY: `raw` was never published.
                    drop(unsafe { Box::from_raw(raw) });
                    existing
                }
            }
        } else {
            chunk_ptr
        };

        // Initialise the slot's inbox + reset queue state.
        // SAFETY: chunk is now published; slot index is in range.
        let slot = unsafe { &(*chunk).slots[(slot_idx as usize) % EPH_CHUNK_SIZE] };
        if !slot.inbox.ensure_alloc(EPH_INBOX_CAPACITY) {
            return Err(UdpBindError::BackendFailed);
        }
        slot.inbox.reset();

        let port = EPHEMERAL_BASE + (slot_idx * n + me) as u16;

        // Publish the port AFTER inbox init so cross-worker readers
        // never see a non-zero port for an uninitialised inbox.
        slot.port.store(port, Ordering::Release);

        // Notify the backend (native opens an actual fd; bare-metal
        // is a no-op since routing is registry-only).
        if let Some(bind) = udp_backend().and_then(|b| b.bind) {
            if bind(port, Some(me)).is_err() {
                // Roll back: clear port, mark slot free.
                slot.port.store(0, Ordering::Release);
                // SAFETY: owner-only access.
                unsafe {
                    let bk = &mut *pool.bookkeeping.get();
                    bk.free_list.push(slot_idx);
                }
                return Err(UdpBindError::BackendFailed);
            }
        }

        Ok(UdpSocket {
            port,
            slot: SlotRef::Ephemeral { worker: me, slot_idx },
            released: AtomicBool::new(false),
        })
    }

    /// Port this socket is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Send a datagram from this socket to `(dst_ip, dst_port)`.
    /// Returns `Err(())` if the backend isn't wired (should only
    /// happen pre-init) — backend failures themselves (full TX
    /// ring on bare-metal, `sendto` EAGAIN on native) are swallowed
    /// today since they're harmless for UDP; add a proper error
    /// enum when QUIC needs to observe them.
    pub fn send_to(&self, dst_ip: [u8; 4], dst_port: u16, data: &[u8]) -> Result<(), ()> {
        let b = udp_backend().ok_or(())?;
        (b.send)(dst_ip, self.port, dst_port, data);
        Ok(())
    }

    /// Await one datagram on the **calling worker's** inbox. The
    /// copy into `buf` happens on the single poll that returns
    /// `Ready`. Oversized payloads truncate to `buf.len()`.
    pub fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> UdpRecv<'a> {
        UdpRecv {
            sock: self,
            buf,
            _not_send: PhantomData,
        }
    }

    /// Zero-copy receive: await one datagram, then invoke `f` with
    /// a slice borrow of the payload (and its source) sitting in
    /// the inbox slot — no copy into a user buffer. The closure
    /// runs synchronously on the single poll that completes the
    /// future; its return value becomes the future's output.
    ///
    /// POSIX `recv()` must copy into a user buffer because the
    /// kernel can't borrow user code's lifetime. We can — the
    /// closure has to return before this future resolves, so the
    /// inbox slot can be safely reused after that. For
    /// header-only parses (QUIC short headers, DNS labels, statsd
    /// keys) the saved memcpy is the bulk of the per-packet cost.
    pub fn recv_inplace<F, R>(&self, f: F) -> UdpRecvInplace<'_, F, R>
    where
        F: FnOnce(&[u8], [u8; 4], u16) -> R + Unpin,
    {
        UdpRecvInplace {
            sock: self,
            f: Some(f),
            _not_send: PhantomData,
        }
    }

    /// Spawn `body` once per worker. Each invocation gets its own
    /// `Arc<UdpSocket>` clone and typically loops on `recv_from`
    /// (and replies via `send_to`) to drive the per-worker inbox.
    ///
    /// Returns a [`UdpHandle`] whose `Drop` aborts the per-worker
    /// tasks and releases the port. Store the handle on a
    /// long-lived owner (typically your `App` struct) so the
    /// listener tears down cleanly when the owner drops.
    pub fn run<H, F>(self, body: H) -> UdpHandle
    where
        H: Fn(Arc<UdpSocket>) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + 'static,
    {
        self.run_boxed(Box::new(move |sock| Box::pin(body(sock))))
    }

    fn run_boxed(self, body: BoxedBody) -> UdpHandle {
        let handles = PerWorker::new();
        handles.init(num_workers(), |_| SpinLock::new(None));
        let ctx = Arc::new(UdpFanoutCtx {
            sock: Arc::new(self),
            body,
            stopping: AtomicBool::new(false),
            handles,
        });
        // Launcher captures a strong `Arc<ctx>` clone. When
        // `UdpHandle::drop` frees the launcher slot, the captured
        // clone drops; if it was the last one, `Arc<ctx>` drops
        // (cascading `sock` Arc drop and thus `UdpSocket::Drop`),
        // so there's no permanent leak.
        let ctx_for_launcher = Arc::clone(&ctx);
        let launcher_slot = register_net_launcher(Box::new(move || {
            if ctx_for_launcher.stopping.load(Ordering::Acquire) {
                return;
            }
            let sock = Arc::clone(&ctx_for_launcher.sock);
            let fut = (ctx_for_launcher.body)(sock);
            if let Ok(h) = crate::spawn(fut) {
                install_worker_task(
                    &ctx_for_launcher.stopping,
                    &ctx_for_launcher.handles,
                    h,
                );
            }
        }));
        UdpHandle { ctx, launcher_slot }
    }
}

// ---- Connected ephemeral flow ----------------------------------------------

/// An ephemeral UDP socket connected to a fixed peer.
///
/// Wraps an [`UdpSocket`] from [`UdpSocket::open_ephemeral`] with
/// the peer address baked in, so `send` / `recv` don't repeat the
/// destination on every call. This is the shape QUIC client setup
/// wants — one server, ephemeral source port, owner-pinned to the
/// calling worker — and it composes with future per-flow
/// optimisations (peer-filtered inbound, cached route lookup,
/// compile-time-known QoS) without further API churn.
///
/// Inbound datagrams from any peer still arrive on this flow's
/// inbox today. Filtering replies to `(peer_ip, peer_port)` is a
/// future hardening step; the wire-level shape is identical.
///
/// `!Send + !Sync` follows from `UdpRecv` — the flow stays on the
/// worker that opened it.
#[must_use = "UdpFlow releases its port on drop; open without using it \
              immediately releases it again"]
pub struct UdpFlow {
    inner: UdpSocket,
    peer_ip: [u8; 4],
    peer_port: u16,
}

impl UdpFlow {
    /// Open an ephemeral UDP socket and connect it to `(peer_ip,
    /// peer_port)`. The local source port is allocated from the
    /// calling worker's per-worker ephemeral pool; the peer
    /// address is stored on the flow for `send` / `peer`.
    pub fn connect(peer_ip: [u8; 4], peer_port: u16) -> Result<UdpFlow, UdpBindError> {
        let inner = UdpSocket::open_ephemeral()?;
        Ok(UdpFlow { inner, peer_ip, peer_port })
    }

    /// Send a datagram to the connected peer.
    #[inline]
    pub fn send(&self, data: &[u8]) -> Result<(), ()> {
        self.inner.send_to(self.peer_ip, self.peer_port, data)
    }

    /// Await one datagram on this flow's inbox. Returns the source
    /// `(ip, port, n)`; today inbound is not peer-filtered, so the
    /// caller still sees datagrams from non-peer senders. Future
    /// versions will drop those at delivery time.
    #[inline]
    pub fn recv<'a>(&'a self, buf: &'a mut [u8]) -> UdpRecv<'a> {
        self.inner.recv_from(buf)
    }

    /// Zero-copy receive — see [`UdpSocket::recv_inplace`]. The
    /// closure runs against a slice borrow of the inbox slot, no
    /// copy into a user buffer. For QUIC client-side parsing where
    /// the short-header decode is the bulk of the per-packet cost
    /// this is the fastest receive path the runtime offers.
    #[inline]
    pub fn recv_inplace<F, R>(&self, f: F) -> UdpRecvInplace<'_, F, R>
    where
        F: FnOnce(&[u8], [u8; 4], u16) -> R + Unpin,
    {
        self.inner.recv_inplace(f)
    }

    /// Local source port allocated for this flow.
    #[inline]
    pub fn local_port(&self) -> u16 {
        self.inner.port()
    }

    /// The peer this flow is connected to.
    #[inline]
    pub fn peer(&self) -> ([u8; 4], u16) {
        (self.peer_ip, self.peer_port)
    }
}

// ---- UdpHandle: owning reference returned by `run` --------------------------

type BoxedBody = Box<
    dyn Fn(Arc<UdpSocket>) -> Pin<Box<dyn Future<Output = ()>>>
        + Send + Sync + 'static,
>;

/// Per-fanout shared state: the socket, the user's body closure,
/// a stop flag, and one `TaskHandle` slot per worker. Owned by
/// `UdpHandle` (strong `Arc`) and by the launcher closure inside
/// `NET_LAUNCHERS` (strong `Arc`). When `UdpHandle::drop` frees
/// the launcher slot, the only strong ref left is the handle's
/// own clone; dropping it drops `UdpFanoutCtx`, which drops
/// `Arc<UdpSocket>`, which (on the last worker's per-task Arc
/// release) runs `UdpSocket::Drop`.
struct UdpFanoutCtx {
    sock: Arc<UdpSocket>,
    body: BoxedBody,
    stopping: AtomicBool,
    handles: PerWorker<SpinLock<Option<crate::TaskHandle>>>,
}

/// Owning handle to a running `UdpSocket` fanout. Use via `Deref`
/// for `send_to` / `recv_from` / `port`; `Drop` aborts the
/// per-worker recv tasks and releases the port slot. Call
/// `.leak()` for process-lifetime listeners.
#[must_use = "UdpHandle stops the recv tasks and releases the port \
              on drop; for a long-lived listener call .leak()"]
pub struct UdpHandle {
    ctx: Arc<UdpFanoutCtx>,
    launcher_slot: usize,
}

impl UdpHandle {
    /// Relinquish ownership — the socket + recv tasks live for
    /// the rest of the process. Idiomatic for app-lifetime UDP
    /// listeners (UDP echo, QUIC endpoints).
    pub fn leak(self) {
        core::mem::forget(self);
    }
}

impl core::ops::Deref for UdpHandle {
    type Target = UdpSocket;
    fn deref(&self) -> &UdpSocket {
        &self.ctx.sock
    }
}

impl Drop for UdpHandle {
    fn drop(&mut self) {
        // 1. Block any launcher that hasn't fired yet. Store
        //    first so any worker that proceeds past the `stopping`
        //    check after `handles` is iterated still sees `true`
        //    on its re-check in the launcher closure.
        self.ctx.stopping.store(true, Ordering::Release);
        // 2. Abort tasks already spawned. `TaskHandle::abort` is
        //    cross-worker-safe: sets the abort flag + forces a
        //    tick on the owning worker so the future is dropped
        //    promptly.
        for w in 0..self.ctx.handles.len() {
            if let Some(h) = self.ctx.handles.at(w).lock().take() {
                h.abort();
            }
        }
        // 3. Eager port release so a subsequent `bind(same_port)`
        //    succeeds without waiting for aborted tasks to
        //    actually drop their `Arc<UdpSocket>` clones.
        //    `UdpSocket::Drop` will see `released = true` on the
        //    last Arc drop and no-op.
        let sock = &*self.ctx.sock;
        if !sock.released.swap(true, Ordering::AcqRel) {
            match sock.slot {
                SlotRef::Server(idx) => {
                    UDP_REGISTRY[idx as usize]
                        .port
                        .store(0, Ordering::Release);
                }
                SlotRef::Ephemeral { worker, slot_idx } => {
                    release_eph_slot(worker, slot_idx);
                }
            }
            if let Some(unbind) = udp_backend().and_then(|b| b.unbind) {
                unbind(sock.port);
            }
        }
        // 4. Free the launcher Box — this drops the launcher's
        //    strong `Arc<ctx>` clone. Combined with our own Arc
        //    dropping at end of scope, the ctx refcount falls to
        //    zero once all per-worker tasks have actually dropped
        //    (on their next tick after abort). At that point the
        //    Arc<UdpSocket> inside also drops and the backing
        //    heap memory is reclaimed.
        release_launcher_slot(self.launcher_slot);
    }
}

/// The UdpRecv future holds a mutable borrow of the caller's buffer
/// plus a shared ref to the socket. `!Send + !Sync` via
/// `PhantomData<*mut ()>` so the future can't migrate across workers
/// mid-await — the per-worker inbox semantics depend on staying on
/// the worker where we first polled.
pub struct UdpRecv<'a> {
    sock: &'a UdpSocket,
    buf: &'a mut [u8],
    _not_send: PhantomData<*mut ()>,
}

impl<'a> Future for UdpRecv<'a> {
    type Output = ([u8; 4], u16, usize);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let cc = CurrentWorker::enter();
        let inbox = match this.sock.slot {
            SlotRef::Server(idx) => {
                UDP_REGISTRY[idx as usize].inboxes.current(&cc)
            }
            SlotRef::Ephemeral { worker, slot_idx } => {
                // The recv future is `!Send`, so we're guaranteed
                // to be on the owning worker (where the slot was
                // allocated). The slot pointer is stable for the
                // socket's lifetime because chunks are leaked.
                let slot = lookup_eph_position(worker, slot_idx)
                    .expect("ephemeral slot vanished mid-recv");
                debug_assert_eq!(cc.id(), worker);
                &slot.inbox
            }
        };

        // Fast path: data already in this worker's inbox.
        if let Some(r) = inbox.pop_into(this.buf) {
            return Poll::Ready(r);
        }
        // Slow path: register the waker, then re-check — closes the
        // race where `deliver_udp` pushed between the fast-path pop
        // and the waker registration.
        inbox.park_waker(cx.waker());
        if let Some(r) = inbox.pop_into(this.buf) {
            inbox.unpark();
            return Poll::Ready(r);
        }
        Poll::Pending
    }
}

/// Future returned by [`UdpSocket::recv_inplace`]. Holds the closure
/// until data arrives, then invokes it with a borrow of the inbox
/// slot's payload — no copy. `!Send` for the same reason as
/// [`UdpRecv`]: the per-worker inbox semantics require staying on
/// the worker where we first polled.
pub struct UdpRecvInplace<'a, F, R>
where
    F: FnOnce(&[u8], [u8; 4], u16) -> R + Unpin,
{
    sock: &'a UdpSocket,
    f: Option<F>,
    _not_send: PhantomData<*mut ()>,
}

impl<'a, F, R> Future for UdpRecvInplace<'a, F, R>
where
    F: FnOnce(&[u8], [u8; 4], u16) -> R + Unpin,
{
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
        let this = self.get_mut();
        let cc = CurrentWorker::enter();
        let inbox = match this.sock.slot {
            SlotRef::Server(idx) => {
                UDP_REGISTRY[idx as usize].inboxes.current(&cc)
            }
            SlotRef::Ephemeral { worker, slot_idx } => {
                let slot = lookup_eph_position(worker, slot_idx)
                    .expect("ephemeral slot vanished mid-recv");
                debug_assert_eq!(cc.id(), worker);
                &slot.inbox
            }
        };

        // Fast path: data already in this worker's inbox.
        let f = this.f.take()
            .expect("UdpRecvInplace polled after completion");
        let f = match inbox.pop_with(f) {
            Ok(r) => return Poll::Ready(r),
            Err(f) => f,
        };

        // Slow path: park, re-check.
        inbox.park_waker(cx.waker());
        match inbox.pop_with(f) {
            Ok(r) => {
                inbox.unpark();
                Poll::Ready(r)
            }
            Err(f) => {
                this.f = Some(f);
                Poll::Pending
            }
        }
    }
}

/// Position-based ephemeral slot lookup. Unlike `lookup_eph` (which
/// rejects free / out-of-range slots), this returns the slot
/// reference even if `port` is 0 — it's used by paths where we
/// already hold a `UdpSocket` and just need the inbox pointer.
fn lookup_eph_position(worker: u32, slot_idx: u32) -> Option<&'static EphSlot> {
    if !EPH_POOLS.is_initialized() || worker >= EPH_POOLS.len() {
        return None;
    }
    let pool = EPH_POOLS.at(worker);
    let chunk_idx = (slot_idx as usize) / EPH_CHUNK_SIZE;
    if chunk_idx >= MAX_CHUNKS_PER_WORKER {
        return None;
    }
    let chunk = pool.chunks[chunk_idx].load(Ordering::Acquire);
    if chunk.is_null() {
        return None;
    }
    // SAFETY: chunks once published live for the process lifetime.
    Some(unsafe { &(*chunk).slots[(slot_idx as usize) % EPH_CHUNK_SIZE] })
}

// ---- Backend entry point ----------------------------------------------------

/// Deliver one inbound UDP datagram. Must be called from the
/// network RX path on the core that observed the packet. Returns
/// `true` if a socket was found.
///
/// Routing dispatches by port:
///   * **Ephemeral range** (port ≥ `EPHEMERAL_BASE`): decode
///     `(worker, slot)` from the port number and push directly
///     into the owning worker's inbox. O(1), no registry scan.
///   * **Server-style** (port < `EPHEMERAL_BASE`): scan
///     `UDP_REGISTRY` for a matching `bind`. The bound count is
///     typically a handful (one per declared listening port), so
///     the scan stays cheap. Delivery routes to the receiving
///     worker's inbox — server `run` listeners spawn one task per
///     worker and the NIC's flow hash has already steered here.
pub fn deliver_udp(dst_port: u16, src_ip: [u8; 4], src_port: u16, payload: &[u8]) -> bool {
    // Fast path: ephemeral ports.
    if let Some(slot) = lookup_eph(dst_port) {
        let _ = slot.inbox.try_push(src_ip, src_port, payload);
        slot.inbox.wake_if_parked();
        return true;
    }

    // Server-style ports.
    let cc = CurrentWorker::enter();
    for state in UDP_REGISTRY.iter() {
        if state.port.load(Ordering::Acquire) == dst_port {
            let inbox = state.inboxes.current(&cc);
            let _ = inbox.try_push(src_ip, src_port, payload);
            inbox.wake_if_parked();
            return true;
        }
    }
    false
}

// ============================================================================
// TCP accept reactor
// ============================================================================
//
// `TcpListener::bind(port)` claims a slot in a parallel registry.
// The backend (bare-metal `net::tcp` / native `drain_tcp_listener`)
// calls `deliver_tcp_ready(port)` on the core that observed a new
// accept-able connection; `accept()` await-loops
// `tcp_backend_accept` (the backend's non-blocking accept fn) under
// the familiar "try → register waker → re-check" pattern.
//
// Unlike the UDP reactor, the TCP reactor does NOT buffer accepted
// connections itself — the backend's own accept queue is the source
// of truth. `TcpAccept::poll` simply calls the backend's accept
// hook; the reactor layer is purely "notify when there's something
// to accept".
//
// Accepted connections are returned as `TcpStream(*mut ())` —
// the same opaque handle `uni_backend::tcp_accept` returns today.
// Higher layers wrap it into `uni::TcpStream` for the typed API.

pub const MAX_TCP_LISTENERS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpBindError {
    AllSlotsBusy,
    PortInUse,
    InvalidPort,
    /// Backend refused to open the listener (port already in use
    /// by another process on native, etc.).
    BackendFailed,
}

/// Owned handle to an accepted TCP connection.
///
/// `generation` is the backend-assigned generation for this conn
/// slot. Every per-stream hook (`recv`, `send`, `close`) verifies
/// it matches the conn's current generation; a stale handle that
/// survived a close + slot reuse is detected and short-circuits
/// to the "closed" path (recv returns 0, waker registration
/// immediately wakes, close no-ops).
///
/// `!Send + !Copy + !Clone + Drop`:
/// - `!Send` because backends return pointers into per-worker
///   state; moving a stream across workers is wrong. The task
///   system already keeps futures pinned to their spawning worker.
/// - `!Copy + !Clone` because the stream owns the conn — at most
///   one `Drop` per accepted conn keeps the close path
///   single-shot.
/// - `Drop` sends FIN and releases the backend's per-stream state
///   via `TcpBackend::close`. Apps don't need an explicit
///   `close()` call on every exit path; `return` from a `run`
///   body drops the stream and tears down cleanly.
pub struct TcpStream {
    handle: *mut (),
    generation: u16,
    _not_send: PhantomData<*mut ()>,
}

impl TcpStream {
    /// Sentinel returned by `TcpBackend::accept` when no
    /// connection is ready. Carries a null pointer; `is_null` is
    /// the way for the reactor to detect this without ever
    /// constructing a real `TcpStream` for "nothing yet".
    ///
    /// SAFETY (for Drop): a null pointer never reaches user code —
    /// the `TcpAccept` future filters it out before the stream is
    /// moved into a body. `TcpStream::Drop` (and `TcpBackend::close`)
    /// no-op on a null handle.
    pub const NULL: Self = TcpStream {
        handle: core::ptr::null_mut(),
        generation: 0,
        _not_send: PhantomData,
    };

    /// Construct directly from a backend handle + generation.
    /// Backends call this from their `accept` hook when a fresh
    /// conn is ready.
    #[inline]
    pub const fn from_raw(handle: *mut (), generation: u16) -> Self {
        TcpStream { handle, generation, _not_send: PhantomData }
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        self.handle.is_null()
    }

    /// Async read. Resolves with the byte count when data is
    /// available (or `0` on peer close / stale generation).
    #[inline]
    pub fn recv<'a>(&'a self, buf: &'a mut [u8]) -> TcpRecv<'a> {
        TcpRecv::new(self.handle, self.generation, buf)
    }

    /// Async write. Resolves `Ok(())` when every byte of `data`
    /// has been queued to the backend, `Err(())` if the conn is
    /// broken.
    #[inline]
    pub fn send<'a>(&'a self, data: &'a [u8]) -> TcpSend<'a> {
        TcpSend::new(self.handle, self.generation, data)
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if self.handle.is_null() {
            // The NULL sentinel produced by `accept` when nothing
            // was ready. Filtered out before reaching user code,
            // but Drop runs on every value in scope — guard here.
            return;
        }
        if let Some(b) = tcp_backend() {
            (b.close)(self.handle, self.generation);
        }
    }
}

struct TcpState {
    port: AtomicU16,
    /// Per-worker waker slot. Backend `deliver_tcp_ready` fires on
    /// the core that has the newly-accept-able conn; the waker
    /// wakes a task on that same core.
    wakers: PerWorker<SpinLock<Option<Waker>>>,
}

impl TcpState {
    const fn new() -> Self {
        TcpState {
            port: AtomicU16::new(0),
            wakers: PerWorker::new(),
        }
    }
}

static TCP_REGISTRY: [TcpState; MAX_TCP_LISTENERS] =
    [const { TcpState::new() }; MAX_TCP_LISTENERS];

// ---- Backend vtable (TCP) ---------------------------------------------------

/// All TCP backend hooks. Installed once at boot by the platform
/// backend — native (kqueue/epoll over POSIX sockets) or bare-
/// metal (integrated NIC driver + handshake stack). Every TCP
/// reactor dispatch — listen/accept/unlisten plus per-stream
/// recv/send readiness and transport — goes through a single
/// atomic load of this pointer instead of one load per hook.
///
/// Generation discipline: every per-stream hook receives the
/// `generation` stamped into the `TcpStream` when it was handed
/// out via `TcpAccept`. A mismatch against the conn's current
/// generation means the slot was reused, and the backend short-
/// circuits to the "closed" path — recv returns 0, try_send
/// returns -1, waker registration fires immediately so the task
/// observes closure on its next poll.
pub struct TcpBackend {
    /// Claim the listener for `port`. Bare-metal opens one TCB per
    /// core; native opens a single listen fd shared across workers.
    pub listen: fn(port: u16) -> Result<(), ()>,
    /// Non-blocking accept. Returns `TcpStream::NULL` when
    /// nothing is ready; otherwise returns a handle paired with
    /// the accepted conn's current generation.
    pub accept: fn(port: u16) -> TcpStream,
    /// Optional release hook — native closes its listen fd,
    /// bare-metal frees its per-core Listen TCB slots. Backends
    /// without per-listener state can leave this `None`.
    pub unlisten: Option<fn(port: u16)>,

    // Per-stream recv hooks (hot path — TcpRecv::poll).
    /// Cheap non-blocking probe. Returns `true` also on close or
    /// stale `gen` so the caller's `recv` resolves to `0` in those
    /// cases.
    pub has_data: fn(handle: *mut (), generation: u16) -> bool,
    /// Sync read into `buf`; `0` = EOF / close / stale `gen`.
    pub do_recv: fn(handle: *mut (), generation: u16, buf: &mut [u8]) -> usize,
    /// Store this waker. Called before the final has-data re-check;
    /// the backend de-dupes with `Waker::will_wake`. A stale `gen`
    /// fires `waker` immediately.
    pub register_recv_waker:
        fn(handle: *mut (), generation: u16, waker: &Waker),
    /// Drop the stored recv waker. Called after Ready. Stale `gen`
    /// is a no-op.
    pub clear_recv_waker: fn(handle: *mut (), generation: u16),

    /// Send FIN on the conn and release the backend's per-stream
    /// state. Idempotent: a stale `gen` (slot already reused) or
    /// already-closed conn is a no-op. Called from
    /// `TcpStream::Drop` so apps don't have to track close
    /// explicitly.
    pub close: fn(handle: *mut (), generation: u16),

    // Per-stream send hooks (hot path — TcpSend::poll).
    /// Non-blocking write. Returns bytes-queued on success (may be
    /// partial), `0` if the backend is full (caller should park a
    /// waker and re-poll), or negative on fatal conn error /
    /// stale `gen`.
    pub try_send: fn(handle: *mut (), generation: u16, buf: &[u8]) -> isize,
    /// Park `waker` on the conn's send slot; a subsequent writable
    /// event fires it. Stale `gen` fires immediately.
    pub register_send_waker:
        fn(handle: *mut (), generation: u16, waker: &Waker),
    /// Drop the stored send waker.
    pub clear_send_waker: fn(handle: *mut (), generation: u16),
}

static TCP_BACKEND: AtomicPtr<TcpBackend> =
    AtomicPtr::new(core::ptr::null_mut());

/// Install the TCP backend. Call once at boot.
pub fn register_tcp_backend(b: &'static TcpBackend) {
    TCP_BACKEND.store(b as *const _ as *mut _, Ordering::Release);
}

#[inline]
fn tcp_backend() -> Option<&'static TcpBackend> {
    let p = TCP_BACKEND.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: `register_tcp_backend` stores `&'static` references;
        // the pointer is either null or a valid `&'static TcpBackend`.
        Some(unsafe { &*p })
    }
}

/// A TCP listener bound to one port.
///
/// Two lifecycles, same shape as [`UdpSocket`]: drop directly for
/// a short-lived bind (releases the port); call
/// `bound.run(handler)` for the fan-out pattern and drop / leak
/// the returned [`TcpHandle`].
#[must_use = "TcpListener releases its port on drop"]
pub struct TcpListener {
    port: u16,
    idx: usize,
    /// Same pattern as `UdpSocket::released` — set by
    /// `TcpHandle::Drop` so the later `TcpListener::Drop` on the
    /// last `Arc` release no-ops instead of double-invoking the
    /// backend unlisten hook.
    released: AtomicBool,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }
        TCP_REGISTRY[self.idx].port.store(0, Ordering::Release);
        if let Some(unlisten) = tcp_backend().and_then(|b| b.unlisten) {
            unlisten(self.port);
        }
    }
}

impl TcpListener {
    pub fn bind(port: u16) -> Result<TcpListener, TcpBindError> {
        if port == 0 {
            return Err(TcpBindError::InvalidPort);
        }
        for state in TCP_REGISTRY.iter() {
            if state.port.load(Ordering::Acquire) == port {
                return Err(TcpBindError::PortInUse);
            }
        }
        for (idx, state) in TCP_REGISTRY.iter().enumerate() {
            if state
                .port
                .compare_exchange(0, port, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                state.wakers.ensure_init(num_workers(), |_| SpinLock::new(None));
                for w in 0..num_workers() {
                    *state.wakers.at(w).lock() = None;
                }
                let b = tcp_backend().ok_or(TcpBindError::BackendFailed)?;
                if (b.listen)(port).is_err() {
                    state.port.store(0, Ordering::Release);
                    return Err(TcpBindError::BackendFailed);
                }
                return Ok(TcpListener {
                    port,
                    idx,
                    released: AtomicBool::new(false),
                });
            }
        }
        Err(TcpBindError::AllSlotsBusy)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Await the next accepted connection on the **calling worker**.
    /// Resolves with a `TcpStream`. The stream pointer is
    /// non-null by construction of the `accept` hook contract — a
    /// null return from the hook means "not ready yet" and keeps
    /// the future Pending.
    pub fn accept<'a>(&'a self) -> TcpAccept<'a> {
        TcpAccept {
            listener: self,
            _not_send: PhantomData,
        }
    }

    /// Spawn `body` once per accepted connection. The framework
    /// owns the accept loop; each `body(stream)` invocation runs
    /// as its own task on the worker that accepted the connection.
    ///
    /// Returns a [`TcpHandle`] whose `Drop` aborts the per-worker
    /// accept tasks and releases the port. In-flight per-connection
    /// tasks already spawned keep running until they return
    /// normally (the handle drop doesn't force-close live conns).
    /// Long-lived listeners should call `.leak()` on the handle.
    pub fn run<H, F>(self, body: H) -> TcpHandle
    where
        H: Fn(TcpStream) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + 'static,
    {
        let body = Arc::new(body);
        let handles = PerWorker::new();
        handles.init(num_workers(), |_| SpinLock::new(None));
        let ctx = Arc::new(TcpFanoutCtx {
            listener: Arc::new(self),
            accept_body: Box::new(move |stream| {
                let body = Arc::clone(&body);
                Box::pin(async move { body(stream).await })
            }),
            stopping: AtomicBool::new(false),
            handles,
        });
        let ctx_for_launcher = Arc::clone(&ctx);
        let launcher_slot = register_net_launcher(Box::new(move || {
            if ctx_for_launcher.stopping.load(Ordering::Acquire) {
                return;
            }
            // Clone the listener Arc for the accept task — the
            // task's future owns it for as long as it runs.
            let listener = Arc::clone(&ctx_for_launcher.listener);
            let ctx_inner = Arc::clone(&ctx_for_launcher);
            if let Ok(h) = crate::spawn(async move {
                loop {
                    let stream = listener.accept().await;
                    // `accept_body` wraps the user's body in a
                    // factory that itself clones its captured
                    // Arc<body> for the per-conn task.
                    let fut = (ctx_inner.accept_body)(stream);
                    let _ = crate::spawn(fut);
                }
            }) {
                install_worker_task(
                    &ctx_for_launcher.stopping,
                    &ctx_for_launcher.handles,
                    h,
                );
            }
        }));
        TcpHandle { ctx, launcher_slot }
    }
}

type BoxedAcceptBody = Box<
    dyn Fn(TcpStream) -> Pin<Box<dyn Future<Output = ()>>>
        + Send + Sync + 'static,
>;

/// Per-fanout shared state for `TcpListener::run`. Shape mirrors
/// `UdpFanoutCtx`; separated because the two reactors register
/// different body signatures. Owned by `TcpHandle` + the launcher
/// closure (both strong `Arc`s); the launcher's ref drops when
/// `TcpHandle::Drop` frees the launcher slot.
struct TcpFanoutCtx {
    listener: Arc<TcpListener>,
    accept_body: BoxedAcceptBody,
    stopping: AtomicBool,
    handles: PerWorker<SpinLock<Option<crate::TaskHandle>>>,
}

/// Owning handle to a running `TcpListener` fanout. Use via
/// `Deref` for `port` / `accept`; `Drop` aborts the per-worker
/// accept tasks and releases the port slot. Call `.leak()` for
/// process-lifetime listeners.
#[must_use = "TcpHandle stops the accept tasks and releases the \
              port on drop; for a long-lived listener call .leak()"]
pub struct TcpHandle {
    ctx: Arc<TcpFanoutCtx>,
    launcher_slot: usize,
}

impl TcpHandle {
    pub fn leak(self) {
        core::mem::forget(self);
    }
}

impl core::ops::Deref for TcpHandle {
    type Target = TcpListener;
    fn deref(&self) -> &TcpListener {
        &self.ctx.listener
    }
}

impl Drop for TcpHandle {
    fn drop(&mut self) {
        self.ctx.stopping.store(true, Ordering::Release);
        for w in 0..self.ctx.handles.len() {
            if let Some(h) = self.ctx.handles.at(w).lock().take() {
                h.abort();
            }
        }
        // Eager port release — mirror `TcpListener::Drop` so a
        // rebind works without waiting for aborted accept tasks
        // to drop their `Arc<TcpListener>` clones.
        let l = &*self.ctx.listener;
        if !l.released.swap(true, Ordering::AcqRel) {
            TCP_REGISTRY[l.idx].port.store(0, Ordering::Release);
            if let Some(unlisten) = tcp_backend().and_then(|b| b.unlisten) {
                unlisten(l.port);
            }
        }
        release_launcher_slot(self.launcher_slot);
    }
}

pub struct TcpAccept<'a> {
    listener: &'a TcpListener,
    _not_send: PhantomData<*mut ()>,
}

impl<'a> Future for TcpAccept<'a> {
    type Output = TcpStream;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let port = this.listener.port;
        let b = match tcp_backend() {
            Some(b) => b,
            None => return Poll::Pending, // backend not wired yet
        };

        // Fast path
        let stream = (b.accept)(port);
        if !stream.is_null() {
            return Poll::Ready(stream);
        }

        // Register waker on this worker's slot, then re-check.
        let cc = CurrentWorker::enter();
        let state = &TCP_REGISTRY[this.listener.idx];
        store_waker_if_needed(state.wakers.current(&cc), cx.waker());

        let stream = (b.accept)(port);
        if !stream.is_null() {
            *state.wakers.current(&cc).lock() = None;
            return Poll::Ready(stream);
        }

        Poll::Pending
    }
}

// ---- Per-stream async recv -------------------------------------------------
//
// `TcpStream::recv(buf).await` resolves with the byte count once the
// backend has data available on the underlying conn (or zero on peer
// close). The backend owns the readiness signal (kqueue/epoll on
// native, rx-ring enqueue on bare-metal) and parks / wakes a single
// per-stream `Waker` via the `register_recv_waker` / `has_data` /
// `do_recv` / `clear_recv_waker` fields of `TcpBackend`. The stream
// handle is an opaque `*mut ()` — identical to the `TcpStream`
// the accept reactor returns.

/// Future returned by `TcpStream::recv`. Holds a mutable borrow of
/// the caller's buffer plus the conn handle + generation. `!Send`
/// because the underlying handle points into per-worker state.
pub struct TcpRecv<'a> {
    handle: *mut (),
    generation: u16,
    buf: &'a mut [u8],
    _not_send: PhantomData<*mut ()>,
}

impl<'a> TcpRecv<'a> {
    #[inline]
    pub fn new(handle: *mut (), generation: u16, buf: &'a mut [u8]) -> Self {
        TcpRecv { handle, generation, buf, _not_send: PhantomData }
    }
}

impl<'a> Future for TcpRecv<'a> {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
        let this = self.get_mut();
        let h = this.handle;
        let g = this.generation;
        let b = match tcp_backend() {
            Some(b) => b,
            None => return Poll::Pending,
        };
        // Fast path — probe, read, clear any stale waker.
        if (b.has_data)(h, g) {
            (b.clear_recv_waker)(h, g);
            return Poll::Ready((b.do_recv)(h, g, this.buf));
        }
        // Register waker, then re-check — closes the wake-before-park
        // race with the backend's wake site.
        (b.register_recv_waker)(h, g, cx.waker());
        if (b.has_data)(h, g) {
            (b.clear_recv_waker)(h, g);
            return Poll::Ready((b.do_recv)(h, g, this.buf));
        }
        Poll::Pending
    }
}

// ---- Per-stream async send ------------------------------------------------
//
// `TcpStream::send(data).await` resolves when every byte in `data`
// has been queued to the backend (kernel send buffer on native, NIC
// TX ring on bare-metal) or the connection is dead. Same waker
// protocol as recv but parked on a separate slot so reads and
// writes can pend concurrently on the same conn. Hook semantics
// live on `TcpBackend::{try_send, register_send_waker,
// clear_send_waker}`.

/// Future returned by `TcpStream::send`. Resolves `Ok(())` when
/// every byte in `data` has been queued, or `Err(())` if the
/// connection breaks. `!Send`.
pub struct TcpSend<'a> {
    handle: *mut (),
    generation: u16,
    buf: &'a [u8],
    sent: usize,
    _not_send: PhantomData<*mut ()>,
}

impl<'a> TcpSend<'a> {
    #[inline]
    pub fn new(handle: *mut (), generation: u16, buf: &'a [u8]) -> Self {
        TcpSend { handle, generation, buf, sent: 0, _not_send: PhantomData }
    }
}

impl<'a> Future for TcpSend<'a> {
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        let this = self.get_mut();
        let h = this.handle;
        let g = this.generation;
        let b = match tcp_backend() {
            Some(b) => b,
            None => return Poll::Pending,
        };

        // Drain as much as the backend will take this tick.
        loop {
            if this.sent == this.buf.len() {
                (b.clear_send_waker)(h, g);
                return Poll::Ready(Ok(()));
            }
            let remaining = &this.buf[this.sent..];
            let n = (b.try_send)(h, g, remaining);
            if n < 0 {
                (b.clear_send_waker)(h, g);
                return Poll::Ready(Err(()));
            }
            if n == 0 {
                // Backend is full. Park waker, then re-probe once —
                // closes the wake-before-park race with the writable
                // event site. If the second try also returns 0, pend.
                (b.register_send_waker)(h, g, cx.waker());
                let n2 = (b.try_send)(h, g, remaining);
                if n2 < 0 {
                    (b.clear_send_waker)(h, g);
                    return Poll::Ready(Err(()));
                }
                if n2 == 0 {
                    return Poll::Pending;
                }
                this.sent += n2 as usize;
                continue;
            }
            this.sent += n as usize;
        }
    }
}

/// Notify the reactor that the backend has a newly accept-able
/// connection for `dst_port`. Must be called from the core that
/// owns the new connection (bare-metal: core whose RX queue
/// observed the handshake completion; native: worker whose
/// kqueue/epoll fired for the listen fd). Returns `true` if a
/// matching listener was found.
pub fn deliver_tcp_ready(dst_port: u16) -> bool {
    let cc = CurrentWorker::enter();
    for state in TCP_REGISTRY.iter() {
        if state.port.load(Ordering::Acquire) == dst_port {
            let taken = state.wakers.current(&cc).lock().take();
            if let Some(waker) = taken {
                waker.wake();
            }
            return true;
        }
    }
    false
}

// ---- Shared launcher table (UDP + TCP + future reactors) --------------------
//
// Any reactor's `run`-style method registers a type-erased launcher
// closure in `NET_LAUNCHERS` (a `LaunchTable`) via
// `register_net_launcher`. `fire_pending_net_launchers` — called
// from `uni_runtime::tick` on every worker every iteration — walks
// the table from that worker's cursor to the global count and
// invokes each live launcher. Each launcher typically calls
// `spawn(body(...))` on the calling worker.
//
// See `uni-runtime/src/launcher.rs` for the ownership / tombstone /
// monotonic-counter invariants that back the table. `MAX_NET_LAUNCHERS
// = 256` is the lifetime-allocation cap (not live-at-once); bump
// it if an app creates more than that many listeners over its
// entire uptime.

/// Bounded cap on launchers ever allocated, not live at once.
/// Each `UdpSocket::run` / `TcpListener::run` / etc. costs one
/// slot; handle drop marks the slot as a tombstone but doesn't
/// free it for reuse. 256 covers a realistic long-running app.
const MAX_NET_LAUNCHERS: usize = 256;

static NET_LAUNCHERS: crate::launcher::LaunchTable<MAX_NET_LAUNCHERS> =
    crate::launcher::LaunchTable::new();

#[inline]
fn register_net_launcher(launcher: crate::launcher::Launcher) -> usize {
    NET_LAUNCHERS.register(launcher)
}

#[inline]
fn release_launcher_slot(idx: usize) {
    NET_LAUNCHERS.release(idx);
}

/// Fire every net launcher added since `worker_id` last called
/// here. Thin wrapper over `NET_LAUNCHERS.fire_pending` so
/// `uni_runtime::tick` has a named entry point.
#[inline]
pub fn fire_pending_net_launchers(worker_id: u32) {
    NET_LAUNCHERS.fire_pending(worker_id);
}
