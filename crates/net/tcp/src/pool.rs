// Per-core slot pool, 4-tuple hash index, and connection-handle
// encoding. All state in this module is single-writer per core — the
// per-core ownership discipline of the rest of the stack carries over.

use crate::state::{MAX_SEGMENTS, NULL_SLOT, SEGMENT_SIZE, TcpConnection, TcpState};
use alloc::boxed::Box;
use types::IpAddr;

// Per-core connection pools. Core N owns POOLS[N].
//
// Each `TcpConnection` is wrapped in `TcpConnCell` (an `UnsafeCell`
// newtype) so cores share the `POOLS` static via shared references
// rather than aliased `&mut`. The outer per-core array is held in
// `kernel_core::percpu::PerWorker`, which provides typed `current(&CurrentWorker)`
// access without manual unsafe at the call site.
//
// SAFETY discipline (enforced by flow-hash routing in net/lib.rs and by
// the API's `cpu_id()` calls): the connection at `POOLS[core][slot]` is
// only mutated by code running on the matching core. The handles
// returned by `encode_handle` carry the core id, and every public TCP
// API decodes the handle and only ever accesses the matching core's
// slots. Tier 2 RX is delivered to the owning core via `rx_inbox` before
// `tcp_receive` runs, so cross-core access cannot occur there either.
struct TcpConnCell(core::cell::UnsafeCell<TcpConnection>);
// SAFETY: per-core ownership documented above; each core only mutates
// its own slots, no two threads ever hold &mut to the same TcpConnection.
unsafe impl Sync for TcpConnCell {}
unsafe impl Send for TcpConnCell {}
impl TcpConnCell {
    fn new() -> Self {
        TcpConnCell(core::cell::UnsafeCell::new(TcpConnection::new()))
    }
}

// ---- Segmented per-core slot pool ------------------------------------
//
// Replaces the previous fixed `[TcpConnCell; CONNECTIONS_PER_CORE]`
// per-core array. Two changes:
//
//   1. Slots live on the heap in `SEGMENT_SIZE`-slot segments. New
//      segments are added on demand, capped at `MAX_SEGMENTS` (~64k
//      slots/core, way past the SPSC inbox + handler-task scaling
//      limit). The fixed-array hard cap is gone — bursting connection
//      load no longer wedges the listener after 128 conns.
//   2. Free slots form an embedded singly-linked list rooted at
//      `free_head`. `alloc` is a pointer pop, `free` is a push —
//      both O(1), replacing the previous linear-scan-for-Closed +
//      linear-scan-for-half-closed dance that walked the whole
//      array on every accept.
//
// All operations are single-threaded per worker (the per-core
// ownership discipline carries over). No atomics on the fast path.
pub(crate) struct TcpPool {
    /// Heap-resident segments. Pushed-only — once a segment is
    /// allocated its `Box<[TcpConnCell]>` lives until process exit,
    /// keeping slot pointers stable for handles that encode
    /// (core, slot_idx).
    segments: core::cell::UnsafeCell<alloc::vec::Vec<Box<[TcpConnCell]>>>,
    /// Head of the free-slot linked list, or `NULL_SLOT` if empty.
    /// On alloc we pop here and follow `next_free` on the popped
    /// slot to advance the head; on free we push the slot's index
    /// here.
    free_head: core::cell::UnsafeCell<u16>,
}
// SAFETY: per-core ownership — only the owning worker accesses its
// `TcpPool`. The interior mutability (UnsafeCell) is single-writer
// at all times.
unsafe impl Sync for TcpPool {}
unsafe impl Send for TcpPool {}

impl TcpPool {
    pub const fn new() -> Self {
        TcpPool {
            segments: core::cell::UnsafeCell::new(alloc::vec::Vec::new()),
            free_head: core::cell::UnsafeCell::new(NULL_SLOT),
        }
    }

    /// Total allocated slots across all segments.
    fn capacity(&self) -> u16 {
        // SAFETY: per-core ownership.
        let segs = unsafe { &*self.segments.get() };
        (segs.len() as u32 * SEGMENT_SIZE as u32) as u16
    }

    /// Resolve a slot index into its `*mut TcpConnection`. The
    /// pointer is stable for the slot's lifetime (we never move
    /// segments after pushing them).
    fn slot_ptr(&self, slot: u16) -> *mut TcpConnection {
        let seg_idx = (slot / SEGMENT_SIZE) as usize;
        let off = (slot % SEGMENT_SIZE) as usize;
        // SAFETY: per-core ownership; caller passes a slot from
        // `alloc`/`capacity` so the index is in range.
        let segs = unsafe { &*self.segments.get() };
        segs[seg_idx][off].0.get()
    }

    /// O(1) allocation: pop the free-list head. Grows the pool by
    /// one segment if the list is empty. Returns `None` only if
    /// `MAX_SEGMENTS` is hit.
    fn alloc(&self) -> Option<u16> {
        // SAFETY: per-core ownership.
        let head = unsafe { *self.free_head.get() };
        if head != NULL_SLOT {
            // Pop: read the popped slot's `next_free` to find the
            // new head. The slot itself gets reset by the caller
            // before any other code observes it (see
            // `alloc_connection`).
            let next = unsafe { (*self.slot_ptr(head)).next_free };
            unsafe {
                *self.free_head.get() = next;
            }
            return Some(head);
        }
        // Free list empty — try to grow.
        if !self.grow_segment() {
            return None;
        }
        // Recurse: grow_segment populated the free list.
        self.alloc()
    }

    /// O(1) free: push the slot onto the free list. Caller is
    /// responsible for having reset the slot's state to `Closed`
    /// (or otherwise made it inert) before this call.
    fn free_slot(&self, slot: u16) {
        // SAFETY: per-core ownership.
        let head = unsafe { *self.free_head.get() };
        unsafe {
            (*self.slot_ptr(slot)).next_free = head;
            *self.free_head.get() = slot;
        }
    }

    /// Append a fresh segment of `SEGMENT_SIZE` slots and link them
    /// all into the free list. Returns false at `MAX_SEGMENTS`.
    fn grow_segment(&self) -> bool {
        // SAFETY: per-core ownership.
        let segs = unsafe { &mut *self.segments.get() };
        if segs.len() >= MAX_SEGMENTS {
            return false;
        }
        let segment_idx = segs.len() as u16;
        let base = segment_idx.saturating_mul(SEGMENT_SIZE);
        let mut new_seg: alloc::vec::Vec<TcpConnCell> =
            alloc::vec::Vec::with_capacity(SEGMENT_SIZE as usize);
        for i in 0..SEGMENT_SIZE {
            let cell = TcpConnCell::new();
            // SAFETY: just-allocated cell, no aliasing yet — safe to
            // stamp the self-identifier before publishing.
            unsafe {
                (*cell.0.get()).slot_index = base + i;
            }
            new_seg.push(cell);
        }
        segs.push(new_seg.into_boxed_slice());
        // Link new slots into the free list. Push in reverse so
        // pops happen in ascending order — better cache behavior
        // for the typical "fill up sequentially" pattern.
        for i in (0..SEGMENT_SIZE).rev() {
            self.free_slot(base + i);
        }
        true
    }
}

pub(crate) static POOLS: kernel_core::percpu::PerWorker<TcpPool> =
    kernel_core::percpu::PerWorker::new();

// ---- Per-core 4-tuple → slot hash table ------------------------------------
//
// The hot RX path needs to map (src_ip, src_port, dst_port) to the
// TcpConnection slot hosting that flow. A linear scan over
// `CONNECTIONS_PER_CORE` slots per packet was costing ~10 % of a
// core at 113 k rps with 32 live conns. An open-addressed hash table
// with a simple Fibonacci hash lookup is effectively O(1).
//
// Per-core, single-writer discipline. All state lives in the
// `TcpHashCore::keys` + `slots` pair, protected by the same
// "only the owning core touches its slot" contract as `POOLS`.
//
// Key packing: `(ip << 32) | (rport << 16) | lport | (1 << 63)`.
// The top-bit flag makes "key == 0" the unambiguous empty marker.
//
// Sized at 32K entries per core. Below ~50% load the open-addressed
// probe stays bounded; the segmented TCP slot pool now reaches up
// to MAX_SEGMENTS*64 ≈ 65K slots per core, so 32K is "half its peak"
// — enough headroom that the high-conn path keeps O(1) lookups, but
// not so big that small-conn workloads pay for it (640 KB/core BSS,
// only touched by the per-core owner so zero false sharing). Pure
// experiment for now — if it moves the 10K-conn cliff we observed
// on the Pareto bench rig, follow up with a segmented hash that
// grows in lockstep with the pool.
const TCP_HASH_SIZE: usize = 32768;
const TCP_HASH_MASK: usize = TCP_HASH_SIZE - 1;
// log2(TCP_HASH_SIZE) — bit count for the Fibonacci-hash top-bit
// extract. Must match TCP_HASH_SIZE: extracting only 8 bits with a
// 32K table funnels every key into 256 starting buckets, so
// open-addressed probes from a clustered start spill across hundreds
// of slots even at low load factor.
const TCP_HASH_SHIFT: u32 = TCP_HASH_SIZE.trailing_zeros();

pub(crate) struct TcpHashCore {
    keys: core::cell::UnsafeCell<[u64; TCP_HASH_SIZE]>,
    slots: core::cell::UnsafeCell<[u16; TCP_HASH_SIZE]>,
}
unsafe impl Sync for TcpHashCore {}
unsafe impl Send for TcpHashCore {}
impl TcpHashCore {
    pub(crate) const fn new() -> Self {
        TcpHashCore {
            keys: core::cell::UnsafeCell::new([0; TCP_HASH_SIZE]),
            slots: core::cell::UnsafeCell::new([0; TCP_HASH_SIZE]),
        }
    }
}

pub(crate) static TCP_HASH: kernel_core::percpu::PerWorker<TcpHashCore> =
    kernel_core::percpu::PerWorker::new();

// ── Per-core armed-timer list ─────────────────────────────────────────
//
// Head of the intrusive linked list of slots with armed timers (see
// `TcpConnection::arm_for_tick`). `on_tcp_tick` walks this list
// instead of scanning the whole per-core pool — at 10% armed
// steady-state on the kvm-iterate bench (10K conns × 4 cores, /health-
// TLS), that's a 10× reduction in tick-loop iterations and a matching
// reduction in cache pressure (each pool slot is ~3 cache lines).
//
// Single-core write/read (per-core ownership invariant), so the cell
// is a plain `UnsafeCell<u16>` — no atomics needed.

pub(crate) struct TickHead {
    pub(crate) head: core::cell::UnsafeCell<u16>,
}

unsafe impl Sync for TickHead {}
unsafe impl Send for TickHead {}

impl TickHead {
    pub(crate) const fn new() -> Self {
        TickHead {
            head: core::cell::UnsafeCell::new(NULL_SLOT),
        }
    }
    pub(crate) fn get(&self) -> *mut u16 {
        self.head.get()
    }
}

pub(crate) static TICK_HEAD: kernel_core::percpu::PerWorker<TickHead> =
    kernel_core::percpu::PerWorker::new();

// ── Accept fast path: per-(core, port) ring of ready-to-accept slots ──
//
// `accept_on_port_core` used to linear-scan the entire per-core pool
// for any `Established && !accepted` slot — O(pool_size) per accept,
// dominant cost at high conn counts (measured 1257 iters/call at 10K
// conns on the kvm-iterate bench). The Established transition in
// `tcp_receive` pushes the slot onto this ring; `accept_on_port_core`
// pops O(1) from it and only falls back to the full scan on miss
// (handles the case where the ring overflowed or wasn't registered).
//
// Single-core SPSC: the slot's owner core writes on the Established
// transition and reads on accept — same core for both (slot
// allocation, hand-shake completion, and accept all run on the core
// the SYN's RX queue landed on). No atomics needed; plain volatile
// reads/writes keep the compiler from reordering the cursor updates
// across the slot stores.

pub(crate) const MAX_ACCEPT_RINGS: usize = 8;
const ACCEPT_RING_CAPACITY: usize = 4096;
const ACCEPT_RING_MASK: u32 = (ACCEPT_RING_CAPACITY as u32) - 1;

pub(crate) struct AcceptRing {
    port: core::cell::Cell<u16>,
    head: core::cell::Cell<u32>, // producer cursor (Established push)
    tail: core::cell::Cell<u32>, // consumer cursor (accept pop)
    slots: core::cell::UnsafeCell<[u16; ACCEPT_RING_CAPACITY]>,
}

pub(crate) struct AcceptRingTable {
    rings: [AcceptRing; MAX_ACCEPT_RINGS],
}

unsafe impl Sync for AcceptRingTable {}
unsafe impl Send for AcceptRingTable {}

impl AcceptRingTable {
    pub(crate) const fn new() -> Self {
        // Cannot use `[expr; N]` initializer with `UnsafeCell` (not Copy).
        const fn empty_ring() -> AcceptRing {
            AcceptRing {
                port: core::cell::Cell::new(0),
                head: core::cell::Cell::new(0),
                tail: core::cell::Cell::new(0),
                slots: core::cell::UnsafeCell::new([0; ACCEPT_RING_CAPACITY]),
            }
        }
        AcceptRingTable {
            rings: [
                empty_ring(), empty_ring(), empty_ring(), empty_ring(),
                empty_ring(), empty_ring(), empty_ring(), empty_ring(),
            ],
        }
    }
}

pub(crate) static ACCEPT_RINGS: kernel_core::percpu::PerWorker<AcceptRingTable> =
    kernel_core::percpu::PerWorker::new();

// ── Listener slot lookup: per-core port → slot index ────────────────
//
// `tcp_receive`'s SYN handler used to linear-scan the per-core pool
// to find the matching `Listen` slot for the SYN's dst_port
// (measured 1285 iters/call at 10K conns). Same shape of bug as the
// accept-side scan: data structure sized for tiny N, scanned at
// O(pool_size). Apps register listeners at `listen_on_core`; we
// remember (port → slot) on each core and the SYN handler does an
// O(MAX_LISTENERS_PER_CORE) linear-array probe — tiny N, hot in
// L1, single load per probe.

pub(crate) const MAX_LISTENERS_PER_CORE: usize = 8;

pub(crate) struct ListenerMap {
    ports: core::cell::UnsafeCell<[u16; MAX_LISTENERS_PER_CORE]>,
    slots: core::cell::UnsafeCell<[u16; MAX_LISTENERS_PER_CORE]>,
}

unsafe impl Sync for ListenerMap {}
unsafe impl Send for ListenerMap {}

impl ListenerMap {
    pub(crate) const fn new() -> Self {
        ListenerMap {
            ports: core::cell::UnsafeCell::new([0; MAX_LISTENERS_PER_CORE]),
            slots: core::cell::UnsafeCell::new([0; MAX_LISTENERS_PER_CORE]),
        }
    }
}

pub(crate) static LISTENERS: kernel_core::percpu::PerWorker<ListenerMap> =
    kernel_core::percpu::PerWorker::new();

/// Register a listener slot for `(core, port)`. Called from
/// `listen_on_core` at bind time. No-op (silent) when the per-core
/// table is full — the SYN handler then falls back to its linear
/// pool scan, so correctness is preserved.
pub(crate) fn listener_register(core: u32, port: u16, slot: u16) {
    let m = LISTENERS.at(core);
    // SAFETY: per-core ownership; `listen_on_core` is the only writer
    // and runs single-threaded at bind time.
    let ports = unsafe { &mut *m.ports.get() };
    let slots = unsafe { &mut *m.slots.get() };
    for i in 0..MAX_LISTENERS_PER_CORE {
        if ports[i] == 0 || ports[i] == port {
            ports[i] = port;
            slots[i] = slot;
            return;
        }
    }
}

/// O(MAX_LISTENERS_PER_CORE) probe for the listener slot matching
/// `(core, port)`. Returns `None` if no slot was registered for
/// this port (caller falls back to the linear pool scan).
pub(crate) fn listener_find(core: u32, port: u16) -> Option<usize> {
    let m = LISTENERS.at(core);
    let ports = unsafe { &*m.ports.get() };
    let slots = unsafe { &*m.slots.get() };
    for i in 0..MAX_LISTENERS_PER_CORE {
        if ports[i] == port {
            return Some(slots[i] as usize);
        }
        if ports[i] == 0 {
            return None;
        }
    }
    None
}

/// Find or allocate the per-port ring on the calling core.
/// Returns `None` if MAX_ACCEPT_RINGS ports already registered on
/// this core — caller falls back to the linear-scan slow path.
fn ring_for_port(core: u32, port: u16) -> Option<&'static AcceptRing> {
    let t = ACCEPT_RINGS.at(core);
    // First pass: existing port match.
    for r in &t.rings {
        if r.port.get() == port {
            return Some(r);
        }
    }
    // Second pass: claim the first unused (port == 0) slot.
    for r in &t.rings {
        if r.port.get() == 0 {
            r.port.set(port);
            return Some(r);
        }
    }
    None
}

/// Push `slot` onto the (core, port) accept ring. Called from the
/// SYN-ACK→Established transition in `tcp_receive`. Silently drops
/// on overflow — `accept_on_port_core` falls back to its linear
/// scan in that case, so correctness is preserved.
pub(crate) fn accept_ring_push(core: u32, port: u16, slot: u16) {
    let Some(r) = ring_for_port(core, port) else {
        return;
    };
    let head = r.head.get();
    let tail = r.tail.get();
    if head.wrapping_sub(tail) >= ACCEPT_RING_CAPACITY as u32 {
        return; // full
    }
    let idx = (head & ACCEPT_RING_MASK) as usize;
    // SAFETY: per-core ownership; the producing core is the only
    // writer to head AND to slots[idx].
    unsafe { (*r.slots.get())[idx] = slot };
    r.head.set(head.wrapping_add(1));
}

/// Pop the oldest pending slot for (core, port), or `None` if the
/// ring is empty.
pub(crate) fn accept_ring_pop(core: u32, port: u16) -> Option<u16> {
    let r = ring_for_port(core, port)?;
    let head = r.head.get();
    let tail = r.tail.get();
    if head == tail {
        return None;
    }
    let idx = (tail & ACCEPT_RING_MASK) as usize;
    // SAFETY: per-core ownership; same core writes head/slot and
    // reads tail. Read-then-advance is fine in this single-core
    // model — no other thread can re-publish the slot.
    let slot = unsafe { (*r.slots.get())[idx] };
    r.tail.set(tail.wrapping_add(1));
    Some(slot)
}

// TCP diagnostic counters moved to `crate::diag` (the observability
// doctrine — `docs/observability.md`). `syn_rx` / `synack_tx` and the
// `rx_chunk_*` zero-copy pair now live in `diag::COUNTERS`.

#[inline]
pub(crate) fn tcp_hash_key(src_ip: IpAddr, src_port: u16, dst_port: u16) -> u64 {
    // Fold the source address to 32 bits so the existing
    // (ip<<32 | ports) packing keeps working. v6 collisions on
    // the 32-bit fold are benign — `tcp_hash_find` linear-probes
    // and the consumer (process_one_packet) re-verifies the full
    // 4-tuple via `c.remote_ip == src_ip` before dispatching.
    let ip32 = match src_ip {
        IpAddr::V4(a) => u32::from_be_bytes(a.octets()),
        IpAddr::V6(a) => {
            let o = a.octets;
            u32::from_be_bytes([o[0], o[1], o[2], o[3]])
                ^ u32::from_be_bytes([o[4], o[5], o[6], o[7]])
                ^ u32::from_be_bytes([o[8], o[9], o[10], o[11]])
                ^ u32::from_be_bytes([o[12], o[13], o[14], o[15]])
        }
    };
    let ip = ip32 as u64;
    // Salt v6 keys with bit 62 so they can't collide with v4
    // keys whose 32-bit fold happens to match.
    let family_bit = if matches!(src_ip, IpAddr::V6(_)) {
        1u64 << 62
    } else {
        0
    };
    (ip << 32) | ((src_port as u64) << 16) | (dst_port as u64) | (1u64 << 63) | family_bit
}

#[inline]
fn tcp_hash_bucket(key: u64) -> usize {
    // Fibonacci hash — multiplies by 2^64/phi and takes the top
    // log2(TCP_HASH_SIZE) bits. Fast (one imul), good distribution
    // for arbitrary 64-bit keys.
    let h = key.wrapping_mul(0x9E3779B97F4A7C15);
    (h >> (64 - TCP_HASH_SHIFT)) as usize
}

pub(crate) fn tcp_hash_find(core: u32, key: u64) -> Option<usize> {
    let h = TCP_HASH.at(core);
    // SAFETY: per-core ownership, only the owning core reads/writes.
    let keys = unsafe { &*h.keys.get() };
    let slots = unsafe { &*h.slots.get() };
    let start = tcp_hash_bucket(key);
    // Track max probe length seen — a worst-case sample is cheaper
    // than a per-probe counter (which dominates rps in the hot path
    // by adding an atomic to every probe step). `hash_find_probes`
    // gets one bump at exit equal to the iteration count, so the
    // ratio hash_find_probes / hash_find_calls is still the average
    // probe depth.
    let mut probes: u64 = 0;
    for i in 0..TCP_HASH_SIZE {
        probes += 1;
        let idx = (start + i) & TCP_HASH_MASK;
        let k = keys[idx];
        if k == 0 {
            crate::diag::COUNTERS.hash_find_probes.add(probes);
            return None;
        }
        if k == key {
            crate::diag::COUNTERS.hash_find_probes.add(probes);
            return Some(slots[idx] as usize);
        }
    }
    crate::diag::COUNTERS.hash_find_probes.add(probes);
    None
}

pub(crate) fn tcp_hash_insert(core: u32, key: u64, slot: usize) {
    let h = TCP_HASH.at(core);
    let keys = unsafe { &mut *h.keys.get() };
    let slots = unsafe { &mut *h.slots.get() };
    let start = tcp_hash_bucket(key);
    for i in 0..TCP_HASH_SIZE {
        let idx = (start + i) & TCP_HASH_MASK;
        if keys[idx] == 0 || keys[idx] == key {
            keys[idx] = key;
            slots[idx] = slot as u16;
            return;
        }
    }
    // Table full — under load up to roughly TCP_HASH_SIZE/2 live
    // conns the open-addressed probe stays bounded; past that we
    // silently drop hash inserts (not connections — the slot is
    // still allocated, it just won't appear in the fast lookup,
    // forcing a linear scan in `tcp_receive`). Future work: grow
    // the hash table in lockstep with the segmented pool.
}

pub(crate) fn tcp_hash_remove(core: u32, key: u64) {
    let h = TCP_HASH.at(core);
    let keys = unsafe { &mut *h.keys.get() };
    let slots = unsafe { &mut *h.slots.get() };
    let start = tcp_hash_bucket(key);
    // First find the entry.
    let mut found_idx = None;
    for i in 0..TCP_HASH_SIZE {
        let idx = (start + i) & TCP_HASH_MASK;
        let k = keys[idx];
        if k == 0 {
            return;
        }
        if k == key {
            found_idx = Some(idx);
            break;
        }
    }
    let idx = match found_idx {
        Some(i) => i,
        None => return,
    };
    keys[idx] = 0;
    slots[idx] = 0;
    // Back-shift the open-addressing run so later probes for keys
    // that collided past this slot still find them. Stop at the
    // first empty slot.
    let mut i = (idx + 1) & TCP_HASH_MASK;
    while keys[i] != 0 {
        let moving_key = keys[i];
        let moving_slot = slots[i];
        keys[i] = 0;
        slots[i] = 0;
        // Re-insert the displaced entry from its ideal bucket.
        let mut new_idx = tcp_hash_bucket(moving_key);
        while keys[new_idx] != 0 {
            new_idx = (new_idx + 1) & TCP_HASH_MASK;
        }
        keys[new_idx] = moving_key;
        slots[new_idx] = moving_slot;
        i = (i + 1) & TCP_HASH_MASK;
    }
}

/// Get a `*mut TcpConnection` for `(core, slot)`. The caller must
/// uphold the per-core ownership discipline (only the owning core may
/// dereference the resulting pointer mutably). Delegates to the
/// segmented pool's slot lookup; pointers stay stable for the slot's
/// lifetime, so handles encoding `(core, slot_idx)` remain valid even
/// across pool growth.
#[inline]
pub(crate) fn conn_ptr(core: u32, slot: usize) -> *mut TcpConnection {
    POOLS.at(core).slot_ptr(slot as u16)
}

/// Snapshot of `core`'s pool capacity — number of slots that have
/// been materialized so far. Linear-scan callers walk `0..pool_capacity(core)`.
#[inline]
pub(crate) fn pool_capacity(core: u32) -> usize {
    POOLS.at(core).capacity() as usize
}

/// Linear-scan fallback for `tcp_hash_find`: walk the pool for a
/// live connection matching the 4-tuple.
///
/// The 4-tuple hash index is a fixed `TCP_HASH_SIZE` (256) entries,
/// but the connection pool grows to `MAX_SEGMENTS × SEGMENT_SIZE`
/// (65 472). Once more than ~256 connections are live — or lingering
/// in a closing state the stack can't time out — `tcp_hash_insert`
/// silently drops the new entry. Without this fallback every
/// post-SYN segment for an overflowed connection misses the hash
/// and `tcp_receive` drops it, stalling the connection a full RTO;
/// a sustained fresh-conn workload then collapses to a few req/s.
///
/// With the fallback the hash is a pure optimisation: a miss is
/// still correct, just `O(pool_capacity)`. Match criteria mirror the
/// RST handler — `remote_ip`/`remote_port`/`local_port`; `local_ip`
/// isn't part of the key (a host with multiple local IPs would need
/// it, but the unikernel binds one).
pub(crate) fn tcp_linear_find(
    core: u32,
    src_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
) -> Option<usize> {
    crate::diag::COUNTERS.linear_find_calls.bump();
    let cap = pool_capacity(core);
    let mut iters: u64 = 0;
    for i in 0..cap {
        iters += 1;
        // SAFETY: per-core ownership — only the owning core scans.
        let c = unsafe { &*conn_ptr(core, i) };
        if c.state != TcpState::Closed
            && c.state != TcpState::Listen
            && c.remote_ip == src_ip
            && c.local_port == dst_port
            && c.remote_port == src_port
        {
            crate::diag::COUNTERS.linear_find_iterations.add(iters);
            return Some(i);
        }
    }
    crate::diag::COUNTERS.linear_find_iterations.add(iters);
    None
}

/// Draw a per-connection initial sequence number.
///
/// Previously this was a global counter that stepped by 64 000, which
/// made the ISN trivially guessable and invited off-path sequence
/// injection. Each new connection now gets a fresh 32-bit sample from
/// the kernel RNG (SHA-256 hash chain, seeded from jitter + RDRAND on
/// x86). One SHA-256 block / connection is well below SYN cost.
#[inline]
pub(crate) fn next_seq() -> u32 {
    let mut buf = [0u8; 4];
    kernel_core::rng::fill_bytes(&mut buf);
    u32::from_ne_bytes(buf)
}

/// Encode a connection handle from core + slot index. Slots are
/// now u16-wide (the segmented pool can grow well past the 8-bit
/// slot space the original encoding allowed); the high bits of the
/// usize hold the core id, low 16 hold the slot.
/// Handle = ((core << 16) | slot) + 1, +1 to avoid null.
pub(crate) fn encode_handle(core: u32, slot: usize) -> *mut () {
    let v = ((core as usize) << 16) | (slot & 0xFFFF);
    (v + 1) as *mut ()
}

/// Decode a handle into (core, slot). The slot is bounds-checked
/// against the owning core's current pool capacity (which grows as
/// segments are added) — a stale handle pointing past `capacity()`
/// is treated as invalid.
pub(crate) fn decode_handle(handle: *mut ()) -> Option<(u32, usize)> {
    let v = (handle as usize).wrapping_sub(1);
    let core = (v >> 16) as u32;
    let slot = v & 0xFFFF;
    if core >= POOLS.len() || slot >= pool_capacity(core) {
        None
    } else {
        Some((core, slot))
    }
}

pub(crate) fn alloc_connection(core: u32) -> Option<usize> {
    let pool = POOLS.at(core);
    // O(1) fast path: pop from the free list. The pool grows by
    // one segment if the list is empty.
    if let Some(slot) = pool.alloc() {
        // SAFETY: per-core ownership; only the owning core (which is `core`
        // by the public API contract) calls this. The slot was just popped
        // from the free list, so no other code holds a reference.
        let c = unsafe { &mut *conn_ptr(core, slot as usize) };
        // Preserve generation across reuse so any still-outstanding
        // async handle observes the bump on its next hook call. Also
        // preserve the 8 KiB RX ring allocation — `free_connection`
        // already kept it across the close cycle, but the `*c =
        // TcpConnection::new()` reset would drop it without this
        // hand-off, costing one heap free + one re-allocation per
        // close-conn /health cycle on the bench hot path.
        let preserved_gen = c.generation;
        let preserved_ring = c.rx_ring.take();
        let preserved_rtx = c.rtx_buf.take();
        let preserved_slot_index = c.slot_index;
        *c = TcpConnection::new();
        c.generation = preserved_gen;
        c.rx_ring = preserved_ring;
        c.rtx_buf = preserved_rtx;
        c.slot_index = preserved_slot_index;
        return Some(slot as usize);
    }
    // Pool grew to MAX_SEGMENTS without a free slot — try to reclaim
    // a half-closed slot whose peer never completed the FIN exchange.
    // Without a retransmit/RTO timer the stack can't age these out,
    // so a misbehaving (or just hard-killed) client that opens many
    // short connections without a clean close would otherwise wedge
    // the listener once we hit the `MAX_SEGMENTS` ceiling. Walk in
    // priority order — FinWait* first (we already initiated close,
    // peer is the only one we're waiting on), then LastAck/TimeWait
    // (similar), then CloseWait last (peer FIN'd but we haven't
    // shipped a response yet — least safe to drop).
    let cap = pool.capacity() as usize;
    for state in [
        TcpState::FinWait1,
        TcpState::FinWait2,
        TcpState::LastAck,
        TcpState::TimeWait,
        TcpState::CloseWait,
    ] {
        for i in 0..cap {
            let c = unsafe { &*conn_ptr(core, i) };
            if c.state == state {
                // free_connection bumps generation, resets the slot,
                // and pushes onto the free list. Re-pop and return.
                // The reclaim is a forced teardown — trace it.
                crate::diag::record_teardown(crate::diag::TeardownReason::PoolReclaim, state);
                free_connection(core, i);
                return pool.alloc().map(|s| s as usize);
            }
        }
    }
    None
}

pub(crate) fn free_connection(core: u32, slot: usize) {
    // SAFETY: per-core ownership.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    // Already on the free list (state == Closed AND we already
    // returned this slot to the pool). Idempotent no-op so callers
    // can fire-and-forget without tracking lifecycle.
    if c.state == TcpState::Closed && c.next_free != NULL_SLOT {
        return;
    }
    // The free-list head sentinel is also `NULL_SLOT`, so a slot
    // that's the current head AND in Closed state is technically
    // free; checking `state == Closed && head == this_slot` would
    // catch that case. Cheaper to just skip the special-case (the
    // hash-table lookup below will no-op for a Closed slot anyway).

    // Remove this connection's 4-tuple from the per-core hash index
    // so future packets won't hit a stale entry. No-op for listeners
    // (they aren't inserted).
    if c.state != TcpState::Closed && c.state != TcpState::Listen {
        let key = tcp_hash_key(c.remote_ip, c.remote_port, c.local_port);
        tcp_hash_remove(core, key);
    }
    // Fire any parked `TcpRecv` / `TcpSendChain` waker before the slot
    // is reset — the app handler needs to observe teardown (recv
    // returns 0, send resolves `Err`) rather than sleeping on a stale
    // waker that would get dropped.
    if let Some(w) = c.recv_waker.take() {
        w.wake();
    }
    if let Some(w) = c.send_waker.take() {
        w.wake();
    }
    // Bump generation so any still-outstanding async handle detects
    // the slot has been reused on its next hook call. Preserved
    // across the reset below.
    let next_gen = c.generation.wrapping_add(1);
    // Preserve the 8 KiB heap-allocated RX ring across reuse — re-
    // allocating it on every SYN would cost a `Box::new([0; 8192])`
    // per accept on the close-conn /health hot path. The next SYN's
    // `ensure_rx_ring` short-circuits when `rx_ring.is_some()`.
    let preserved_ring = c.rx_ring.take();
    let preserved_rtx = c.rtx_buf.take();
    let preserved_slot_index = c.slot_index;
    *c = TcpConnection::new();
    c.generation = next_gen;
    c.rx_ring = preserved_ring;
    c.rtx_buf = preserved_rtx;
    c.slot_index = preserved_slot_index;
    // Don't manually unlink from the armed-timer list here — the
    // `*c = TcpConnection::new()` reset zeroed `tick_in_list` and
    // all deadlines, so the next `on_tcp_tick` walk drops this
    // slot from the list naturally (lazy unlink). `tick_next` is
    // junk after the reset but harmless: `on_tcp_tick` reads it
    // only for slots `tick_in_list == true`, and the next
    // `arm_for_tick` overwrites it before flipping the flag.
    // Return the slot to the pool's free list. O(1) push; the next
    // `alloc_connection` call picks it up in O(1) too.
    POOLS.at(core).free_slot(slot as u16);
}

