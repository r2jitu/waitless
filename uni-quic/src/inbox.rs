// uni-tls/src/quic/inbox.rs — per-connection async queue.
//
// The QUIC server's listener task receives every UDP datagram
// arriving at the bound port and, after a quick header parse to
// extract the DCID, routes the bytes to the matching connection.
// "Routes" here means: pushes the datagram into a per-connection
// queue + signals an `AsyncEvent` so the connection's task wakes.
//
// Both halves (listener and conn task) run on the same worker —
// QUIC connections are pinned to a single core via 4-tuple flow
// hash on the NIC side, so cross-worker synchronisation never
// arises. That means the queue can use a `RefCell<VecDeque>`
// (single-threaded interior mutability) instead of a lock or
// lock-free MPSC structure — half a cycle of overhead per push
// and pop, vs the dozens of cycles a `Mutex` would cost.
//
// The cooperative-multitasking model + `.await` boundaries make
// the borrow rules trivially satisfiable: producer borrows
// mutably to push, drops the borrow before signalling; consumer
// borrows mutably to pop, drops the borrow before yielding to
// process. No two tasks ever hold a borrow simultaneously
// because there's no preemption between the borrow and the next
// suspension point.
//
// The slot-table layer (`SlotTable` below) keeps the routing
// indirection cheap: connections register a `Weak<ConnInbox>`
// when they spawn; lookups resolve the `Weak` to a strong `Rc`
// for the push. When the conn task drops, the strong count hits
// zero and the slot's `Weak::upgrade()` returns `None` — no
// manual deregistration needed.

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::{Rc, Weak};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use uni::runtime::AsyncEvent;

/// One inbound UDP datagram waiting to be processed by a
/// connection task. Owned `Vec<u8>` rather than a borrow into a
/// shared buffer because the listener can outrun a slow conn
/// task by pushing to its inbox; we hand the conn task its own
/// copy.
#[derive(Clone)]
pub struct Datagram {
    pub src_ip: uni::runtime::IpAddr,
    pub src_port: u16,
    pub bytes: Vec<u8>,
}

/// Per-connection async queue. The listener (producer) calls
/// `push`; the conn task (consumer) `.await`s `pop`.
///
/// Capacity is bounded so a misbehaving peer can't OOM the
/// server by flooding a single connection. When full, the
/// listener drops new datagrams — equivalent to UDP packet loss,
/// which the QUIC loss-detection layer already tolerates.
pub struct ConnInbox {
    queue: RefCell<VecDeque<Datagram>>,
    event: AsyncEvent,
    closed: Cell<bool>,
    /// Maximum queued datagrams. Anything past this is dropped.
    /// Sized for sustained pipelined traffic — a Chrome session
    /// rapidly refreshing a page bursts dozens of request +
    /// ACK datagrams faster than the conn task can drain them
    /// (each task iteration does parse + dispatch + flush of up
    /// to 33 packets + sendto the lot). At capacity 16 the
    /// listener silently drops new datagrams, Chrome takes
    /// several seconds to discover the loss via its own PTO,
    /// and retransmitted stragglers later show up as
    /// `aead_decrypt_failed` once our state has moved on.
    /// Real flow control arrives via the QUIC connection-level
    /// limits, not here.
    capacity: usize,
}

// SAFETY: `ConnInbox` is `!Send + !Sync` by virtue of `RefCell`,
// `Cell`, and `Rc`. It MUST stay on the worker that created it.
// The QUIC listener and the conn tasks for slots assigned to
// this worker never leave the worker, so the constraint is
// trivially satisfied.

impl ConnInbox {
    pub const DEFAULT_CAPACITY: usize = 256;

    pub fn new() -> Rc<Self> {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Rc<Self> {
        Rc::new(Self {
            queue: RefCell::new(VecDeque::with_capacity(capacity)),
            event: AsyncEvent::new(),
            closed: Cell::new(false),
            capacity,
        })
    }

    /// Push a datagram. Returns `false` if the inbox is closed
    /// (consumer has gone away) or full (drop-on-overflow).
    pub fn push(&self, datagram: Datagram) -> bool {
        if self.closed.get() {
            return false;
        }
        let mut q = self.queue.borrow_mut();
        if q.len() >= self.capacity {
            return false;
        }
        q.push_back(datagram);
        drop(q);
        self.event.set();
        true
    }

    /// Async pop. Returns `None` if the inbox is closed AND
    /// empty (terminal state — conn task should exit).
    pub async fn pop(&self) -> Option<Datagram> {
        loop {
            // Bind the RefMut to a local so the borrow drops
            // before we call `borrow()` again to reset the event.
            // Holding the RefMut through the `if let` body would
            // panic the second `borrow()` with BorrowError.
            let popped = self.queue.borrow_mut().pop_front();
            if let Some(dgram) = popped {
                if self.queue.borrow().is_empty() {
                    self.event.reset();
                }
                return Some(dgram);
            }
            if self.closed.get() {
                return None;
            }
            self.event.wait().await;
        }
    }

    /// Try-pop without awaiting. Useful for batch-drain inside a
    /// conn-task `pop` loop where a single wake services multiple
    /// queued datagrams.
    pub fn try_pop(&self) -> Option<Datagram> {
        // Same RefMut-temporary discipline as `pop`: bind to a
        // local first so the mutable borrow drops before the
        // subsequent immutable borrow.
        let popped = self.queue.borrow_mut().pop_front();
        let dgram = popped?;
        if self.queue.borrow().is_empty() {
            self.event.reset();
        }
        Some(dgram)
    }

    /// Mark the inbox closed and wake any parked consumer so it
    /// can exit. After `close`, further `push` calls return
    /// `false` and `pop` returns `None` once drained.
    pub fn close(&self) {
        self.closed.set(true);
        self.event.set();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.get()
    }

    pub fn len(&self) -> usize {
        self.queue.borrow().len()
    }
}

// ============================================================================
// Slot table — DCID-encoded routing
// ============================================================================
//
// Each `Slot` holds a generation counter and a `Weak<ConnInbox>`.
// The connection's chosen Connection ID encodes (slot_index,
// generation, random) — see `make_local_cid` in conn.rs. Lookup
// is a single array index + generation match + Weak::upgrade,
// which is roughly 5 cycles on a hot cache line:
//
//   ~3 cycles: bounds-checked array read (slots[idx])
//   ~1 cycle:  generation compare
//   ~1 cycle:  Weak::upgrade increment + None test
//
// Compare with the alternatives we considered:
//
//   Hash table (HashMap<[u8;8], slot_idx>): ~50 cycles even on
//     a hot hit (FxHash + probe + Eq compare on 8 bytes).
//     Cache-cold: 200+ cycles. Doesn't scale to high conn
//     density without periodic rehashing.
//
//   Linear scan (walk all slots): for N=128 slots × 8-byte
//     CIDs that's 16 cache lines and ~50-100 cycles per lookup.
//     For N=1024 it's 128 cache lines, easily 500+ cycles.
//
//   Slot encoding (this approach): O(1) regardless of N, fits
//     in one cache line per slot, no probe collisions, no
//     hash compute, no string compare.
//
// At 10⁵ packets/sec/core (a healthy Tier-1 QUIC server target)
// the lookup cost difference is ~5 µs/sec for slot encoding vs
// 50-500 µs/sec for hash / scan — small absolute, but the cache
// pressure of a hash table on the same core that's also doing
// AEAD seal/open is what really hurts. Slot encoding keeps the
// L1 working set tight.

/// One per-connection routing entry. The `Weak<ConnInbox>` is
/// the only thing holding the conn alive at the slot level;
/// when the conn task drops its strong `Rc<ConnInbox>`, the
/// slot's `Weak::upgrade` returns `None` on the next lookup.
/// The slot is also explicitly returned to the free list when
/// the conn task exits (see `SlotTable::free_slot`), so allocs
/// don't have to scan for dead slots.
struct Slot {
    /// Bumped every time the slot is allocated. The DCID's
    /// generation field must match this for a lookup to succeed,
    /// so a late packet for an old conn that happens to land in
    /// a now-reused slot is correctly dropped.
    generation: u16,
    /// `None` after slot is initialized but before allocate;
    /// `Some(Weak)` after install. The Weak's upgrade fails when
    /// the conn task ends — that's a fast-path "is this still
    /// live?" check before the explicit free arrives.
    inbox: Option<Weak<ConnInbox>>,
    /// Source IP that allocated this slot. Used by `allocate` to
    /// enforce a per-source-IP cap: a single peer (or attacker
    /// spoofing a single source) cannot consume more than
    /// `PER_IP_SLOT_LIMIT` slots, leaving room for legitimate
    /// new connections from other peers.
    src_ip: uni::runtime::IpAddr,
    /// Free-list link. `NULL_SLOT` when this slot is allocated;
    /// otherwise the index of the next free slot in the chain
    /// (or `NULL_SLOT` for end-of-list). The pool's `free_head`
    /// is the entry point.
    next_free: u16,
}

impl Default for Slot {
    fn default() -> Self {
        Slot {
            generation: 0,
            inbox: None,
            src_ip: uni::runtime::IpAddr::V4_ANY,
            next_free: NULL_SLOT,
        }
    }
}

/// Slots per heap-allocated segment. Segments are appended to the
/// outer `Vec<Box<[Slot]>>` on demand; growth caps at
/// `max_capacity / SEGMENT_SIZE` segments. Small enough that an
/// idle worker pays zero (no segments allocated until first conn)
/// instead of the previous fixed 80 KiB (1024 slots × ~80 B each).
const SEGMENT_SIZE: usize = 64;
const NULL_SLOT: u16 = 0xFFFF;

/// Pack an `IpAddr` into a u128 so it can key into a `BTreeMap`.
/// `IpAddr` itself doesn't implement `Ord` (the enum's variant
/// types don't), so we go through this fold for the per-IP
/// counter map. The top bit distinguishes v4 (0) from v6 (1) so
/// the v4 0.0.0.0 → 0u128 fold can't collide with v6 ::0.
fn ip_key(ip: uni::runtime::IpAddr) -> u128 {
    match ip {
        uni::runtime::IpAddr::V4(a) => a.addr as u128,
        uni::runtime::IpAddr::V6(a) => {
            (1u128 << 127) | u128::from_be_bytes(a.octets)
        }
    }
}

/// Per-worker slot table. Single-worker access; no locks.
///
/// Two parallel maps:
///   * `slots`: indexed by `(slot_idx, generation)` derived from
///     OUR server-chosen SCID. This is what every packet *after*
///     the first server reply uses — clients echo our SCID as
///     their DCID, so we can decode the slot trivially.
///   * `initial_dcids`: keyed by the CLIENT's chosen DCID. When a
///     client splits its ClientHello across multiple Initial
///     packets (Chrome's PQ-key_share CHs are routinely 2.2 KiB),
///     every one of those packets carries the same client-chosen
///     DCID — but our SCID isn't picked yet, so the `slots`
///     lookup misses. Without the second map, each Initial would
///     create a fresh conn with a fresh server SCID, fragmenting
///     the ClientHello reassembly across multiple ghost
///     connections and stalling the handshake. Entries are evicted
///     when the slot dies (conn task ends).
pub struct SlotTable {
    /// Segmented slot storage. Outer `Vec` grows by one
    /// `Box<[Slot; SEGMENT_SIZE]>` segment per
    /// `grow_segment` call; inner segments never move, so slot
    /// pointers (and the slot-index → CID encoding) stay stable
    /// across growth. Idle workers pay zero — the first segment
    /// is allocated only when the first conn arrives.
    segments: RefCell<Vec<Box<[Slot]>>>,
    /// Head of the free-slot linked list, `NULL_SLOT` when empty.
    /// Replaces the previous "scan for first dead slot" walk on
    /// every `allocate` — alloc is now a pointer-pop, free is a
    /// pointer-push. O(1) both.
    free_head: Cell<u16>,
    /// Per-source-IP live-slot counter. Replaces the second walk
    /// (counting per-IP usage during `allocate`) with O(1) map
    /// lookups, decrementing on `free_slot` so the counter never
    /// drifts. The map only holds entries for IPs that currently
    /// hold ≥1 slot; we evict on hit-zero to keep the working set
    /// proportional to live-peer count, not lifetime peer count.
    /// Keyed by `ip_key(addr)` (u128 fold) — `IpAddr` itself
    /// doesn't implement `Ord`.
    per_ip: RefCell<alloc::collections::BTreeMap<u128, u16>>,
    initial_dcids: RefCell<alloc::collections::BTreeMap<Vec<u8>, (u16, u16)>>,
    /// Hard ceiling on the number of slots ever allocated. A
    /// segment is always `SEGMENT_SIZE` slots, so the pool may
    /// internally hold a few more slots than this — allocs past
    /// `max_capacity` are rejected even when the current segment
    /// has room. Lets tests construct small tables to exercise
    /// the table-full path without paying for a 64-slot segment.
    max_capacity: u16,
    /// Live allocation count. Bumped on `allocate`, decremented
    /// on `free_slot`. Used to enforce `max_capacity` in O(1).
    live: Cell<u16>,
}

impl SlotTable {
    pub fn new(max_capacity: usize) -> Self {
        let max_capacity = max_capacity.min(NULL_SLOT as usize) as u16;
        SlotTable {
            segments: RefCell::new(Vec::new()),
            free_head: Cell::new(NULL_SLOT),
            per_ip: RefCell::new(alloc::collections::BTreeMap::new()),
            initial_dcids: RefCell::new(alloc::collections::BTreeMap::new()),
            max_capacity,
            live: Cell::new(0),
        }
    }

    /// Resolve a slot index into a `*mut Slot`. The pointer is
    /// stable for the slot's lifetime; safe to dereference under
    /// the per-worker single-writer discipline.
    fn slot_ptr(&self, idx: u16) -> *mut Slot {
        let seg_idx = (idx as usize) / SEGMENT_SIZE;
        let off = (idx as usize) % SEGMENT_SIZE;
        let segs = self.segments.borrow();
        // SAFETY: caller passes idx returned by `allocate` (or
        // pre-validated by `lookup`); the segment was pushed and
        // never moves. `Box<[Slot]>` derefs to `[Slot]` whose
        // contents are stable.
        let slot_ref: &Slot = &segs[seg_idx][off];
        slot_ref as *const Slot as *mut Slot
    }

    /// Append a new segment of `SEGMENT_SIZE` slots and link them
    /// all into the free list. Returns false if growing would
    /// exceed `max_capacity`.
    fn grow_segment(&self) -> bool {
        let mut segs = self.segments.borrow_mut();
        let new_cap = (segs.len() + 1) * SEGMENT_SIZE;
        if new_cap > NULL_SLOT as usize {
            // Would exceed the u16 slot index space.
            return false;
        }
        let segment_idx = segs.len();
        let base = (segment_idx * SEGMENT_SIZE) as u16;
        let mut new_seg: Vec<Slot> = Vec::with_capacity(SEGMENT_SIZE);
        for _ in 0..SEGMENT_SIZE {
            new_seg.push(Slot::default());
        }
        segs.push(new_seg.into_boxed_slice());
        // Link new slots into the free list, in reverse so pops
        // happen in ascending order. Done in-place under the
        // active borrow_mut to avoid a double-borrow round-trip.
        let new_seg_ref = segs.last_mut().expect("just pushed");
        let mut head = self.free_head.get();
        for i in (0..SEGMENT_SIZE).rev() {
            new_seg_ref[i].next_free = head;
            head = base + i as u16;
        }
        self.free_head.set(head);
        true
    }

    /// Look up the inbox for a client-chosen Initial DCID. Returns
    /// `None` if no Initial has been seen yet for this DCID, or
    /// if the conn whose Initial it was has since terminated. The
    /// caller (listener loop) only consults this map for long-
    /// header Initial packets that miss the primary slot lookup.
    pub fn lookup_initial_dcid(&self, dcid: &[u8]) -> Option<Rc<ConnInbox>> {
        let map = self.initial_dcids.borrow();
        let (idx, generation) = *map.get(dcid)?;
        drop(map);
        let inbox = self.lookup(idx, generation);
        if inbox.is_none() {
            // Defense-in-depth eviction: `free_slot` already evicts
            // entries pointing at slots it frees, so this branch
            // shouldn't fire under the normal conn-drop path.
            // Kept for the corner case where the slot's `Weak<ConnInbox>`
            // failed to upgrade *before* `free_slot` ran (e.g. the
            // conn task dropped its strong Rc but hasn't yet hit
            // the `slots.free_slot(...)` line at the bottom of
            // `conn_task`).
            self.initial_dcids.borrow_mut().remove(dcid);
        }
        inbox
    }

    /// Register a client-chosen Initial DCID → slot mapping.
    /// Called immediately after `allocate` for a new conn whose
    /// first Initial packet carried this DCID. Subsequent Initial
    /// packets sharing the DCID get routed to the same slot via
    /// `lookup_initial_dcid`.
    pub fn register_initial_dcid(&self, dcid: &[u8], idx: u16, generation: u16) {
        self.initial_dcids
            .borrow_mut()
            .insert(dcid.to_vec(), (idx, generation));
    }

    /// Allocate a free slot for a new conn from `src_ip`. Returns
    /// `(slot_index, generation)` to embed in the local CID.
    /// `None` if the per-segment ceiling is hit **or** `src_ip`
    /// already holds the per-IP cap. The per-IP cap stops a
    /// single peer (or an attacker spoofing one) from monopolising
    /// the slot table — a flood of Initial packets from one source
    /// can fill at most `PER_IP_SLOT_LIMIT` slots, leaving the rest
    /// for legitimate peers.
    ///
    /// O(1) on the steady-state path: per-IP counter check is a
    /// `BTreeMap` lookup, free-slot acquisition is a free-list
    /// pop. The previous implementation walked every slot on every
    /// allocate to find the first dead slot AND count per-IP
    /// usage in one pass; both walks are gone.
    pub fn allocate(&self, src_ip: uni::runtime::IpAddr) -> Option<(u16, u16)> {
        const PER_IP_SLOT_LIMIT: u16 = 64;
        // Global cap — reject before bumping any state.
        if self.live.get() >= self.max_capacity {
            return None;
        }
        // Per-IP cap check — O(1) BTreeMap lookup. The map only
        // holds entries for IPs that currently hold ≥1 slot.
        let key = ip_key(src_ip);
        {
            let per_ip = self.per_ip.borrow();
            if per_ip.get(&key).copied().unwrap_or(0) >= PER_IP_SLOT_LIMIT {
                return None;
            }
        }
        // Pop a slot from the free list, growing by one segment
        // if the list is empty.
        let idx = loop {
            let head = self.free_head.get();
            if head != NULL_SLOT {
                break head;
            }
            if !self.grow_segment() {
                return None;
            }
        };
        // SAFETY: per-worker single-threaded ownership; no other
        // borrow of this slot is active because we just popped it
        // off the free list.
        let slot = unsafe { &mut *self.slot_ptr(idx) };
        // Advance the free-list head to whatever this slot pointed
        // at, then mark this slot allocated.
        self.free_head.set(slot.next_free);
        slot.next_free = NULL_SLOT;
        slot.generation = slot.generation.wrapping_add(1);
        slot.inbox = None; // cleared until install
        slot.src_ip = src_ip;
        // Bump per-IP and global counters.
        *self.per_ip.borrow_mut().entry(key).or_insert(0) += 1;
        self.live.set(self.live.get() + 1);
        Some((idx, slot.generation))
    }

    /// Install an inbox at `(idx, gen)`. The caller has just
    /// called `allocate` and must use the same `gen`.
    pub fn install(&self, idx: u16, generation: u16, inbox: &Rc<ConnInbox>) {
        // SAFETY: per-worker single-threaded ownership.
        let slot = unsafe { &mut *self.slot_ptr(idx) };
        if slot.generation == generation {
            slot.inbox = Some(Rc::downgrade(inbox));
        }
    }

    /// Look up the inbox for `(idx, generation)`. Returns `None`
    /// if the slot is empty, the generation doesn't match, or the
    /// owning conn task has terminated (Weak fails to upgrade).
    pub fn lookup(&self, idx: u16, generation: u16) -> Option<Rc<ConnInbox>> {
        if (idx as usize) >= self.capacity() {
            return None;
        }
        // SAFETY: per-worker ownership; index is in range.
        let slot = unsafe { &*self.slot_ptr(idx) };
        if slot.generation != generation {
            return None;
        }
        slot.inbox.as_ref().and_then(Weak::upgrade)
    }

    /// Return a slot to the free list. Called by the conn task at
    /// exit — without this, dead slots would only be reclaimed via
    /// the `Weak::upgrade` failing on the next lookup, which
    /// doesn't put them back on the free list. Combined with the
    /// per-IP counter decrement, this keeps both invariants
    /// (free-list completeness, per-IP accounting) tight.
    ///
    /// The `gen` argument guards against a stale call from a
    /// previously-occupied generation (e.g. a delayed cleanup
    /// firing after the slot has already been re-allocated).
    pub fn free_slot(&self, idx: u16, generation: u16) {
        if (idx as usize) >= self.capacity() {
            return;
        }
        // SAFETY: per-worker ownership; index is in range.
        let slot = unsafe { &mut *self.slot_ptr(idx) };
        if slot.generation != generation {
            return; // stale — slot has already been re-allocated
        }
        // Decrement per-IP counter; evict the entry on hit-zero
        // to keep the map sparse.
        {
            let key = ip_key(slot.src_ip);
            let mut per_ip = self.per_ip.borrow_mut();
            if let Some(c) = per_ip.get_mut(&key) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    per_ip.remove(&key);
                }
            }
        }
        // Evict any initial_dcids entries pointing at this slot.
        // The map's docstring promises "entries are evicted when
        // the slot dies"; the previous lazy-on-miss-lookup path
        // left orphan entries (Vec<u8> key + BTreeMap node) live
        // forever for any DCID that wasn't queried again post-
        // conn-drop. A linear walk is fine here: free_slot fires
        // once per conn (rare relative to packet arrivals), and
        // the map's working set is tiny — a Chrome PQ-CH session
        // has ≤1 dcid registered per conn.
        self.initial_dcids
            .borrow_mut()
            .retain(|_, (slot_idx, slot_gen)| {
                !(*slot_idx == idx && *slot_gen == generation)
            });
        // Push onto the free list. Don't bump generation here —
        // that happens on the next `allocate`, so reads racing
        // against a free-then-realloc cycle still see a coherent
        // generation transition.
        slot.inbox = None;
        slot.next_free = self.free_head.get();
        self.free_head.set(idx);
        self.live.set(self.live.get().saturating_sub(1));
    }

    pub fn capacity(&self) -> usize {
        self.segments.borrow().len() * SEGMENT_SIZE
    }

    /// Currently-allocated slot count. O(1) via the live counter.
    /// Note: a slot whose conn task has dropped its `Rc<ConnInbox>`
    /// but hasn't yet called `free_slot` is still counted as live
    /// here — `live` tracks pool-allocated state, not Weak liveness.
    pub fn live_count(&self) -> usize {
        self.live.get() as usize
    }
}

// ============================================================================
// DCID slot encoding
// ============================================================================
//
// The server's chosen Connection ID is exactly 8 bytes:
//
//     [0..2] slot index (u16, big-endian)
//     [2..4] slot generation (u16, big-endian)
//     [4..8] cryptographically-random nonce (collision resistance
//            against off-path attackers who guess slot indices)
//
// The nonce is essential: without it, an attacker who learns the
// slot count + generation pattern could craft a packet whose DCID
// happens to match a victim conn's slot+generation, causing the
// listener to route their packet to the victim. The 32 bits of
// random per CID is enough that brute-force guessing requires
// 2^31 packets per connection on average — dwarfed by network
// round-trips long before a match.

/// Number of bytes the server's local CID occupies on the wire.
pub const SERVER_CID_LEN: usize = 8;

/// Build a server-chosen CID from `(slot, generation, nonce)`.
pub fn make_local_cid(slot: u16, generation: u16, nonce: [u8; 4]) -> [u8; SERVER_CID_LEN] {
    let mut cid = [0u8; SERVER_CID_LEN];
    cid[0..2].copy_from_slice(&slot.to_be_bytes());
    cid[2..4].copy_from_slice(&generation.to_be_bytes());
    cid[4..8].copy_from_slice(&nonce);
    cid
}

/// Decode `(slot, generation)` from a DCID. Returns `None` if
/// the DCID isn't `SERVER_CID_LEN` bytes (in which case it's not
/// one we issued, so the caller routes via the
/// "is-this-a-new-Initial" path).
pub fn parse_local_cid(dcid: &[u8]) -> Option<(u16, u16)> {
    if dcid.len() != SERVER_CID_LEN {
        return None;
    }
    let slot = u16::from_be_bytes([dcid[0], dcid[1]]);
    let generation = u16::from_be_bytes([dcid[2], dcid[3]]);
    Some((slot, generation))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn dgram(byte: u8) -> Datagram {
        Datagram {
            src_ip: uni::runtime::IpAddr::V4(uni::runtime::Ipv4Addr {
                addr: u32::from_ne_bytes([127, 0, 0, 1]),
            }),
            src_port: 5000,
            bytes: alloc::vec![byte; 8],
        }
    }

    #[test]
    fn push_and_try_pop_round_trip() {
        let inbox = ConnInbox::new();
        assert!(inbox.push(dgram(0x11)));
        assert!(inbox.push(dgram(0x22)));
        let a = inbox.try_pop().unwrap();
        assert_eq!(a.bytes[0], 0x11);
        let b = inbox.try_pop().unwrap();
        assert_eq!(b.bytes[0], 0x22);
        assert!(inbox.try_pop().is_none());
    }

    #[test]
    fn push_full_drops() {
        let inbox = ConnInbox::with_capacity(2);
        assert!(inbox.push(dgram(0x01)));
        assert!(inbox.push(dgram(0x02)));
        assert!(!inbox.push(dgram(0x03))); // full → dropped
        assert_eq!(inbox.len(), 2);
    }

    #[test]
    fn push_after_close_rejected() {
        let inbox = ConnInbox::new();
        assert!(inbox.push(dgram(0x01)));
        inbox.close();
        assert!(!inbox.push(dgram(0x02)));
    }

    fn ip(b: u8) -> uni::runtime::IpAddr {
        uni::runtime::IpAddr::V4(uni::runtime::Ipv4Addr {
            addr: u32::from_be_bytes([10, 0, 0, b]),
        })
    }

    #[test]
    fn slot_table_allocate_lookup_recycle() {
        let table = SlotTable::new(4);
        let inbox1 = ConnInbox::new();
        let (idx, gen1) = table.allocate(ip(1)).expect("first allocate");
        table.install(idx, gen1, &inbox1);

        // Lookup with right gen returns a strong Rc.
        let found = table.lookup(idx, gen1).expect("lookup hit");
        assert!(Rc::ptr_eq(&found, &inbox1));
        // Lookup with wrong gen misses.
        assert!(table.lookup(idx, gen1.wrapping_add(1)).is_none());

        // Drop the only strong refs except `inbox1` — slot still
        // sees it alive.
        drop(found);
        assert_eq!(table.live_count(), 1);

        // Drop the conn-task's strong ref → slot's Weak fails.
        // Lookup correctly returns None (Weak::upgrade misses)
        // but the slot remains allocated until we explicitly
        // call `free_slot` — that's the new lifecycle (the
        // listener used to walk-and-reclaim on every allocate;
        // now the conn task hands the slot back at exit so
        // alloc is O(1)).
        drop(inbox1);
        assert!(table.lookup(idx, gen1).is_none());
        assert_eq!(table.live_count(), 1, "slot still allocated until explicit free");

        // Conn task exit handoff — returns the slot to the free list.
        table.free_slot(idx, gen1);
        assert_eq!(table.live_count(), 0);

        // Allocate again: same slot can be re-used; gen bumps.
        let inbox2 = ConnInbox::new();
        let (idx2, gen2) = table.allocate(ip(1)).expect("re-allocate");
        assert_eq!(idx2, idx);
        assert_ne!(gen2, gen1);
        table.install(idx2, gen2, &inbox2);
        // Old gen still misses; new gen hits.
        assert!(table.lookup(idx, gen1).is_none());
        assert!(table.lookup(idx2, gen2).is_some());
    }

    #[test]
    fn slot_table_full_returns_none() {
        let table = SlotTable::new(2);
        let i1 = ConnInbox::new();
        let i2 = ConnInbox::new();
        let (a, ga) = table.allocate(ip(1)).unwrap();
        table.install(a, ga, &i1);
        let (b, gb) = table.allocate(ip(2)).unwrap();
        table.install(b, gb, &i2);
        assert!(table.allocate(ip(3)).is_none());
        // Drop the strong ref AND explicitly hand the slot back —
        // the new lifecycle requires both. Without `free_slot` the
        // slot stays allocated; lookup misses but alloc still sees
        // no free.
        drop(i1);
        assert!(table.allocate(ip(3)).is_none(),
                "drop alone doesn't free; allocate should still miss");
        table.free_slot(a, ga);
        assert!(table.allocate(ip(3)).is_some());
    }

    /// Per-IP cap (PER_IP_SLOT_LIMIT = 64 in the impl). One IP
    /// can fill at most that many slots; further allocations from
    /// it are rejected even if there's global headroom.
    #[test]
    fn slot_table_per_ip_cap() {
        // Use a table larger than PER_IP_SLOT_LIMIT so it's the
        // per-IP cap, not the global cap, that bites first.
        let table = SlotTable::new(128);
        let attacker = ip(7);
        let mut held: alloc::vec::Vec<Rc<ConnInbox>> = alloc::vec::Vec::new();
        for _ in 0..64 {
            let inbox = ConnInbox::new();
            let (i, g) = table
                .allocate(attacker)
                .expect("under cap should still succeed");
            table.install(i, g, &inbox);
            held.push(inbox);
        }
        // 65th from same IP — rejected.
        assert!(table.allocate(attacker).is_none());
        // But a different IP can still allocate (table is far
        // from full globally — 128 slots, 64 used).
        assert!(table.allocate(ip(8)).is_some());
    }

    #[test]
    fn cid_encode_decode_round_trip() {
        let cid = make_local_cid(0x1234, 0xabcd, [0xde, 0xad, 0xbe, 0xef]);
        let (slot, generation) = parse_local_cid(&cid).unwrap();
        assert_eq!(slot, 0x1234);
        assert_eq!(generation, 0xabcd);
        // Wrong-length CIDs are rejected (caller treats as
        // "not one of ours" → new-conn path).
        assert!(parse_local_cid(&[]).is_none());
        assert!(parse_local_cid(&[0u8; 16]).is_none());
    }
}
