// crates/runtime/executor/src/net/udp.rs — UDP reactor, server (bound port)
// + ephemeral pool + connected client.
//
// See `super` (`net/mod.rs`) for the shared primitives (`SpinLock`,
// waker helpers, the launcher table) consumed here and by the TCP
// module.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};

use worker::{CurrentWorker, PerWorker, num_workers};

use super::{SpinLock, install_worker_task, register_net_launcher, release_launcher_slot};

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
// ---- Datagram + worker inbox ------------------------------------------------

/// One slot in the per-(socket, worker) UDP inbox. Source-address
/// metadata + inline payload bytes. The producer (driver RX +
/// stack) copies bytes into `data[..len]` at push time; the
/// consumer (`recv_from` / `recv_inplace`) reads them at pop time.
///
/// Previously this slot held an `Option<IOBuf>` so the producer
/// could move ownership of a driver-pool descriptor straight into
/// the inbox. That shape is gone with the &[u8] driver callback —
/// inbound bytes are only visible to the stack synchronously, so
/// the inbox must copy them out. The trade is one `memcpy(<=1500)`
/// at push time vs. one heap allocation + one drop callback per
/// datagram in the old shape; even at gateway_max rates this is
/// cheaper.
struct Datagram {
    src_ip: IpAddr,
    src_port: u16,
    len: u16,
    data: [u8; MAX_PAYLOAD],
}

impl Datagram {
    const ZERO: Self = Datagram {
        src_ip: IpAddr::V4_ANY,
        src_port: 0,
        len: 0,
        data: [0; MAX_PAYLOAD],
    };
}

use crate::ip::IpAddr;

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
        let mut buf: alloc::vec::Vec<Datagram> = alloc::vec::Vec::with_capacity(capacity);
        for _ in 0..capacity {
            buf.push(Datagram::ZERO);
        }
        let boxed = buf.into_boxed_slice();
        let ptr = Box::leak(boxed).as_mut_ptr();
        self.mask.store((capacity as u32) - 1, Ordering::Release);
        self.slots.store(ptr, Ordering::Release);
        true
    }

    /// Push a datagram. Copies up to `MAX_PAYLOAD` bytes from
    /// `payload` into the next slot. Returns `false` (and drops
    /// the payload) when the inbox ring is full — equivalent to
    /// NIC-level packet loss, recovered by application retry.
    fn try_push(&self, src_ip: IpAddr, src_port: u16, payload: &[u8]) -> bool {
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
        // SAFETY: SPSC — producer owns the tail slot until Release
        // store below; `slots_ptr` was published by `ensure_alloc`
        // with Release ordering before the owning UdpState's port
        // was set non-zero, and we only get here once a valid
        // `UdpSocket` is in scope.
        let slot = unsafe { &mut *slots_ptr.add(tail as usize) };
        slot.src_ip = src_ip;
        slot.src_port = src_port;
        let n = payload.len().min(MAX_PAYLOAD);
        slot.data[..n].copy_from_slice(&payload[..n]);
        slot.len = n as u16;
        self.tail.store(next, Ordering::Release);
        true
    }

    fn pop_into(&self, buf: &mut [u8]) -> Option<(IpAddr, u16, usize)> {
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
        // SAFETY: SPSC — consumer owns the head slot until Release
        // store below; same publication argument as `try_push`.
        let slot = unsafe { &*slots_ptr.add(head as usize) };
        let len = slot.len as usize;
        let n = len.min(buf.len());
        buf[..n].copy_from_slice(&slot.data[..n]);
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
        F: FnOnce(&[u8], IpAddr, u16) -> R,
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
        let r = f(&slot.data[..n], slot.src_ip, slot.src_port);
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

static UDP_REGISTRY: [UdpState; MAX_UDP_SOCKETS] = [const { UdpState::new() }; MAX_UDP_SOCKETS];

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
            chunks: [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CHUNKS_PER_WORKER],
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
    pub send: fn(dst_ip: IpAddr, src_port: u16, dst_port: u16, data: &[u8]),
    /// Optional acquire-from-TX-pool entry. Returns a writable
    /// frame buffer drawn from the driver's TX pool; the caller
    /// fills `[..MAX_L2_HEADROOM]` later via the matching
    /// `send_via_tx_handle` and writes the UDP payload at
    /// `[MAX_L2_HEADROOM..]`. `None` (returned by the backend or
    /// the function itself) means the caller falls back to `send`
    /// (which memcpys through a stack buffer).
    ///
    /// Used by the QUIC encoder's `take_datagram_buf` to write
    /// packet bytes straight into a TX-pool slot — saves the
    /// driver-side memcpy that the slice-based `send` path pays.
    pub acquire_tx_buf: Option<fn() -> Option<nic_api::TxBufHandle>>,
    /// Optional submit-via-TX-handle entry. Caller has filled
    /// `handle.data_mut()[MAX_L2_HEADROOM..MAX_L2_HEADROOM+payload_len]`
    /// with the UDP payload; the backend fills the L2/L3/L4
    /// headers in the headroom in place and submits the slot to
    /// the driver via `submit_tx`. `frame_len` is `MAX_L2_HEADROOM
    /// + payload_len`.
    pub send_via_tx_handle: Option<
        fn(
            dst_ip: IpAddr,
            src_port: u16,
            dst_port: u16,
            handle: nic_api::TxBufHandle,
            frame_len: usize,
        ),
    >,
    /// Optional zero-copy send: caller hands a frame buffer where
    /// the first [`MAX_L2_HEADROOM`] bytes are reserved for the
    /// L2/L3/L4 headers and the UDP payload starts at
    /// `frame[MAX_L2_HEADROOM..]`. The backend fills the headers
    /// in place and ships the contiguous frame to the driver — no
    /// payload memcpy. `None` means the caller falls back to
    /// `send` over `frame[MAX_L2_HEADROOM..]`.
    ///
    /// `MAX_L2_HEADROOM = 62` accommodates v6 (14 + 40 + 8). For
    /// v4 destinations the backend uses only the trailing 42 bytes
    /// of that reserve and ships from the family-correct offset
    /// (the leading 20 bytes go on the wire as part of the frame
    /// the driver receives — the backend writes the actual ETH
    /// header at `frame[MAX_L2_HEADROOM - 42] = frame[20]` and
    /// passes `&frame[20..]` to the driver).
    ///
    /// Used by the QUIC reactor to skip the per-packet
    /// `udp::send_to_addr → ipv4_send → ethernet_send → driver`
    /// memcpy chain. Bare-metal sets this; native leaves it `None`
    /// (the OS does the wrap on `sendto`).
    pub send_with_l2_headroom:
        Option<fn(dst_ip: IpAddr, src_port: u16, dst_port: u16, frame: &mut [u8])>,
}

/// Max bytes a caller of `UdpSocket::send_to_with_l2_headroom`
/// must reserve at the front of its frame buffer for the
/// Ethernet + IP + UDP headers. Sized for v6 (14 + 40 + 8); v4
/// uses 42 of these, the leading 20 are unused.
pub const MAX_L2_HEADROOM: usize = 14 + 40 + 8;

/// Acquire a writable frame buffer drawn from the driver's TX
/// pool. Free function (no `UdpSocket` needed) — used by the
/// QUIC encoder's `take_datagram_buf`, which doesn't have a
/// socket reference but still wants to land packet bytes
/// directly in a slot.
///
/// Caller writes the UDP payload at
/// `handle.data_mut()[MAX_L2_HEADROOM..MAX_L2_HEADROOM+payload_len]`
/// and submits via [`UdpSocket::send_via_tx_handle`]. The
/// L2/L3/L4 headers are filled in the headroom by the backend
/// at submit time (for v4 destinations the backend does a
/// 20-byte in-place memmove of payload bytes to align with the
/// 42-byte v4 header — same memcpy count as the slice-shaped
/// path; for v6 it's a clean win).
///
/// `None` means the backend doesn't support direct-fill TX
/// (native), the driver doesn't either (GVE today), or the
/// pool is full. Caller falls back to a heap-allocated
/// `Vec<u8>` + slice-shaped send.
pub fn acquire_tx_buf() -> Option<nic_api::TxBufHandle> {
    let b = udp_backend()?;
    let f = b.acquire_tx_buf?;
    f()
}

static UDP_BACKEND: AtomicPtr<UdpBackend> = AtomicPtr::new(core::ptr::null_mut());

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
        let slot = unsafe { &(*chunk).slots[(slot_idx as usize) % EPH_CHUNK_SIZE] };
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
                state
                    .inboxes
                    .ensure_init(num_workers(), |_| WorkerInbox::new());
                for w in 0..num_workers() {
                    let inbox = state.inboxes.at(w);
                    if !inbox.ensure_alloc(SERVER_INBOX_CAPACITY) {
                        state.port.store(0, Ordering::Release);
                        return Err(UdpBindError::BackendFailed);
                    }
                    inbox.reset();
                }
                if let Some(bind) = udp_backend().and_then(|b| b.bind)
                    && bind(port, None).is_err()
                {
                    state.port.store(0, Ordering::Release);
                    return Err(UdpBindError::BackendFailed);
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
    pub(crate) fn open_ephemeral() -> Result<UdpSocket, UdpBindError> {
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
        if let Some(bind) = udp_backend().and_then(|b| b.bind)
            && bind(port, Some(me)).is_err()
        {
            // Roll back: clear port, mark slot free.
            slot.port.store(0, Ordering::Release);
            // SAFETY: owner-only access.
            unsafe {
                let bk = &mut *pool.bookkeeping.get();
                bk.free_list.push(slot_idx);
            }
            return Err(UdpBindError::BackendFailed);
        }

        Ok(UdpSocket {
            port,
            slot: SlotRef::Ephemeral {
                worker: me,
                slot_idx,
            },
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
    pub fn send_to(&self, dst_ip: IpAddr, dst_port: u16, data: &[u8]) -> Result<(), ()> {
        let b = udp_backend().ok_or(())?;
        (b.send)(dst_ip, self.port, dst_port, data);
        Ok(())
    }

    /// Submit a previously-[acquired](acquire_tx_buf) TX
    /// handle. `frame_len` is `MAX_L2_HEADROOM + payload_len` (the
    /// total bytes the bare-metal backend ships, after filling
    /// the L2/L3/L4 headers in the headroom). Consumes the
    /// handle.
    ///
    /// `Err(())` if the backend doesn't support handle-based send;
    /// the handle is dropped (slot returns to the pool unused).
    pub fn send_via_tx_handle(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        handle: nic_api::TxBufHandle,
        frame_len: usize,
    ) -> Result<(), ()> {
        let b = udp_backend().ok_or(())?;
        if let Some(f) = b.send_via_tx_handle {
            f(dst_ip, self.port, dst_port, handle, frame_len);
            Ok(())
        } else {
            // No bare-metal-style hook (e.g. native): drop the
            // handle (returns slot to pool) and let the caller
            // retry via the slice-shaped path. Should not happen
            // when paired with `acquire_tx_buf`'s `None` gating.
            drop(handle);
            Err(())
        }
    }

    /// Zero-copy send: caller pre-reserves `MAX_L2_HEADROOM` bytes
    /// at the front of `frame`; the UDP payload lives at
    /// `frame[MAX_L2_HEADROOM..]`. On bare-metal the backend fills
    /// the L2/L3/L4 headers in place and ships the contiguous
    /// frame to the driver — no payload memcpy. On native (no
    /// headroom-aware backend) falls back to a slice-based `send`
    /// over `frame[MAX_L2_HEADROOM..]`, which incurs the kernel's
    /// own buffer copy on `sendto`.
    ///
    /// Used by the QUIC reactor to skip the per-packet UDP-wrap
    /// memcpy that `send_to` would otherwise pay.
    pub fn send_to_with_l2_headroom(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        frame: &mut [u8],
    ) -> Result<(), ()> {
        let b = udp_backend().ok_or(())?;
        if let Some(fast) = b.send_with_l2_headroom {
            fast(dst_ip, self.port, dst_port, frame);
        } else {
            (b.send)(dst_ip, self.port, dst_port, &frame[MAX_L2_HEADROOM..]);
        }
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
        F: FnOnce(&[u8], IpAddr, u16) -> R + Unpin,
    {
        UdpRecvInplace {
            sock: self,
            f: Some(f),
            _not_send: PhantomData,
        }
    }

    /// Non-blocking single-shot recv. Returns `Some((src_ip,
    /// src_port, n))` if a datagram was waiting, `None` otherwise.
    /// `!Send` enforced via `&UdpRecvNotSend` — the call must
    /// happen on the worker that owns the inbox.
    pub fn try_recv_from(&self, buf: &mut [u8]) -> Option<(IpAddr, u16, usize)> {
        let _: PhantomData<*mut ()> = PhantomData; // !Send marker
        let cc = CurrentWorker::enter();
        let inbox = self.current_inbox(&cc);
        inbox.pop_into(buf)
    }

    /// Non-blocking zero-copy recv via closure. Returns the
    /// closure's output if a datagram was waiting, `None`
    /// otherwise — useful inside drain loops that consume
    /// everything currently buffered before yielding.
    pub fn try_recv_inplace<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&[u8], IpAddr, u16) -> R,
    {
        let cc = CurrentWorker::enter();
        let inbox = self.current_inbox(&cc);
        inbox.pop_with(f).ok()
    }

    fn current_inbox<'a>(&'a self, cc: &'a CurrentWorker) -> &'a WorkerInbox {
        match self.slot {
            SlotRef::Server(idx) => UDP_REGISTRY[idx as usize].inboxes.current(cc),
            SlotRef::Ephemeral { worker, slot_idx } => {
                let slot = lookup_eph_position(worker, slot_idx)
                    .expect("ephemeral slot vanished mid-recv");
                debug_assert_eq!(cc.id(), worker);
                &slot.inbox
            }
        }
    }
}

/// `bind(port).map(|s| s.run(body))` in one call. The 80%-case
/// shortcut for "open a UDP server on port N and run this loop on
/// every worker." Use [`UdpSocket::bind`] + [`UdpSocket::run`]
/// directly when you need to inspect / configure the socket
/// between bind and run.
pub fn udp_listen<H, F>(port: u16, body: H) -> Result<UdpHandle, UdpBindError>
where
    H: Fn(Arc<UdpSocket>) -> F + Send + Sync + 'static,
    F: Future<Output = ()> + 'static,
{
    UdpSocket::bind(port).map(|s| s.run(body))
}

impl UdpSocket {
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
            // `body` already returns a `BoxedFuture`, so route
            // through `spawn_boxed` to skip a redundant `Box::pin`.
            let fut = (ctx_for_launcher.body)(sock);
            if let Ok(h) = crate::spawn_boxed(fut) {
                install_worker_task(&ctx_for_launcher.stopping, &ctx_for_launcher.handles, h);
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
#[must_use = "UdpClient releases its port on drop; open without using it \
              immediately releases it again"]
pub struct UdpClient {
    inner: UdpSocket,
    peer_ip: IpAddr,
    peer_port: u16,
}

impl UdpClient {
    /// Open an ephemeral UDP client connected to `(peer_ip,
    /// peer_port)`. The local source port is allocated from the
    /// calling worker's per-worker ephemeral pool; the peer
    /// address is stored on the client and used implicitly by
    /// every send / recv method on this type.
    ///
    /// `UdpClient` is *always* connected — there is no
    /// unconnected variant. If you need to talk to multiple
    /// peers, open one client per peer (cheap — each is a single
    /// slot in the per-worker pool).
    pub fn connect(peer_ip: IpAddr, peer_port: u16) -> Result<UdpClient, UdpBindError> {
        let inner = UdpSocket::open_ephemeral()?;
        Ok(UdpClient {
            inner,
            peer_ip,
            peer_port,
        })
    }

    /// Send a datagram to the connected peer.
    #[inline]
    pub fn send(&self, data: &[u8]) -> Result<(), ()> {
        self.inner.send_to(self.peer_ip, self.peer_port, data)
    }

    /// Receive one datagram from the connected peer into `buf`,
    /// returning the byte count (truncating at `buf.len()`). The
    /// source address is implicit (it's [`peer`](Self::peer)).
    pub async fn recv(&self, buf: &mut [u8]) -> usize {
        self.recv_payload(move |payload| {
            let n = payload.len().min(buf.len());
            buf[..n].copy_from_slice(&payload[..n]);
            n
        })
        .await
    }

    /// Zero-copy receive: invoke `f` with a slice borrow of the
    /// payload (no copy into a user buffer, no source-address
    /// arguments — peer is fixed at `connect` time). For QUIC
    /// header parsing this is the fastest receive path the
    /// runtime offers.
    pub async fn recv_payload<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R + Unpin,
    {
        self.inner
            .recv_inplace(move |payload, _src_ip, _src_port| f(payload))
            .await
    }

    /// Non-blocking [`recv`](Self::recv). Returns `None` if no
    /// datagram is currently buffered.
    #[inline]
    pub fn try_recv(&self, buf: &mut [u8]) -> Option<usize> {
        self.inner.try_recv_inplace(move |payload, _, _| {
            let n = payload.len().min(buf.len());
            buf[..n].copy_from_slice(&payload[..n]);
            n
        })
    }

    /// Non-blocking [`recv_payload`](Self::recv_payload).
    #[inline]
    pub fn try_recv_payload<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&[u8]) -> R,
    {
        self.inner.try_recv_inplace(move |payload, _, _| f(payload))
    }

    /// Local source port allocated for this client.
    #[inline]
    pub fn local_port(&self) -> u16 {
        self.inner.port()
    }

    /// The peer this client is connected to.
    #[inline]
    pub fn peer(&self) -> (IpAddr, u16) {
        (self.peer_ip, self.peer_port)
    }
}

// ---- UdpHandle: owning reference returned by `run` --------------------------

type BoxedBody =
    Box<dyn Fn(Arc<UdpSocket>) -> Pin<Box<dyn Future<Output = ()>>> + Send + Sync + 'static>;

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
                    UDP_REGISTRY[idx as usize].port.store(0, Ordering::Release);
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
    type Output = (IpAddr, u16, usize);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let cc = CurrentWorker::enter();
        let inbox = match this.sock.slot {
            SlotRef::Server(idx) => UDP_REGISTRY[idx as usize].inboxes.current(&cc),
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
    F: FnOnce(&[u8], IpAddr, u16) -> R + Unpin,
{
    sock: &'a UdpSocket,
    f: Option<F>,
    _not_send: PhantomData<*mut ()>,
}

impl<'a, F, R> Future for UdpRecvInplace<'a, F, R>
where
    F: FnOnce(&[u8], IpAddr, u16) -> R + Unpin,
{
    type Output = R;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
        let this = self.get_mut();
        let cc = CurrentWorker::enter();
        let inbox = match this.sock.slot {
            SlotRef::Server(idx) => UDP_REGISTRY[idx as usize].inboxes.current(&cc),
            SlotRef::Ephemeral { worker, slot_idx } => {
                let slot = lookup_eph_position(worker, slot_idx)
                    .expect("ephemeral slot vanished mid-recv");
                debug_assert_eq!(cc.id(), worker);
                &slot.inbox
            }
        };

        // Fast path: data already in this worker's inbox.
        let f = this
            .f
            .take()
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
///
/// Deliver a UDP datagram to its bound socket's inbox.
///
/// The caller threads an owned `IOBuf` whose visible payload is the
/// UDP datagram body (Eth/IP/UDP headers consumed via
/// `IOBuf::consume` upstream). On dispatch, the IOBuf moves into
/// the inbox slot — no memcpy at the protocol-recv boundary.
///
/// Returns `true` if a registered binding was found (whether or not
/// the inbox push itself succeeded). `payload` is borrowed for the
/// duration of the call; bytes are copied into the matched inbox
/// slot (or dropped on a full ring).
pub fn deliver_udp(dst_port: u16, src_ip: IpAddr, src_port: u16, payload: &[u8]) -> bool {
    if let Some(slot) = lookup_eph(dst_port) {
        let _ = slot.inbox.try_push(src_ip, src_port, payload);
        slot.inbox.wake_if_parked();
        return true;
    }
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
