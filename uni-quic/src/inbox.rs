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
    /// Sized for the worst-case handshake burst (4-5 packets)
    /// plus a few in-flight 1-RTT packets. Real flow control
    /// arrives via the QUIC connection-level limits, not here.
    capacity: usize,
}

// SAFETY: `ConnInbox` is `!Send + !Sync` by virtue of `RefCell`,
// `Cell`, and `Rc`. It MUST stay on the worker that created it.
// The QUIC listener and the conn tasks for slots assigned to
// this worker never leave the worker, so the constraint is
// trivially satisfied.

impl ConnInbox {
    pub const DEFAULT_CAPACITY: usize = 16;

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
/// slot's `Weak::upgrade` returns `None` on the next lookup and
/// the slot is implicitly free.
struct Slot {
    /// Bumped every time the slot is allocated. The DCID's
    /// generation field must match this for a lookup to succeed,
    /// so a late packet for an old conn that happens to land in
    /// a now-reused slot is correctly dropped.
    generation: u16,
    /// `None` after slot is initialized but before allocate;
    /// `Some(Weak)` after install. The Weak's upgrade fails when
    /// the conn task ends — that's the implicit free.
    inbox: Option<Weak<ConnInbox>>,
}

impl Default for Slot {
    fn default() -> Self {
        Slot { generation: 0, inbox: None }
    }
}

/// Per-worker slot table. Single-worker access; no locks.
pub struct SlotTable {
    slots: RefCell<Vec<Slot>>,
}

impl SlotTable {
    pub fn new(capacity: usize) -> Self {
        let mut v = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            v.push(Slot::default());
        }
        SlotTable { slots: RefCell::new(v) }
    }

    /// Allocate a free slot. Returns `(slot_index, generation)`
    /// to embed in the local CID. `None` if the table is full.
    pub fn allocate(&self) -> Option<(u16, u16)> {
        let mut slots = self.slots.borrow_mut();
        for (i, s) in slots.iter_mut().enumerate() {
            // Slot is "free" iff its Weak upgrade returns None
            // (or the slot has never been used). We keep stale
            // Weak references in the slot until the next allocate
            // hits them — saves a sweep loop.
            let live = s.inbox.as_ref().and_then(Weak::upgrade).is_some();
            if !live {
                s.generation = s.generation.wrapping_add(1);
                s.inbox = None; // clear stale Weak
                return Some((i as u16, s.generation));
            }
        }
        None
    }

    /// Install an inbox at `(idx, gen)`. The caller has just
    /// called `allocate` and must use the same `gen`.
    pub fn install(&self, idx: u16, generation: u16, inbox: &Rc<ConnInbox>) {
        let mut slots = self.slots.borrow_mut();
        let slot = match slots.get_mut(idx as usize) {
            Some(s) => s,
            None => return,
        };
        if slot.generation == generation {
            slot.inbox = Some(Rc::downgrade(inbox));
        }
    }

    /// Look up the inbox for `(idx, generation)`. Returns `None`
    /// if the slot is empty, the generation doesn't match, or the
    /// owning conn task has terminated (Weak fails to upgrade).
    pub fn lookup(&self, idx: u16, generation: u16) -> Option<Rc<ConnInbox>> {
        let slots = self.slots.borrow();
        let slot = slots.get(idx as usize)?;
        if slot.generation != generation {
            return None;
        }
        slot.inbox.as_ref().and_then(Weak::upgrade)
    }

    pub fn capacity(&self) -> usize {
        self.slots.borrow().len()
    }

    pub fn live_count(&self) -> usize {
        self.slots
            .borrow()
            .iter()
            .filter(|s| s.inbox.as_ref().and_then(Weak::upgrade).is_some())
            .count()
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

    #[test]
    fn slot_table_allocate_lookup_recycle() {
        let table = SlotTable::new(4);
        let inbox1 = ConnInbox::new();
        let (idx, gen1) = table.allocate().expect("first allocate");
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
        drop(inbox1);
        assert_eq!(table.live_count(), 0);

        // Allocate again: same slot can be re-used; gen bumps.
        let inbox2 = ConnInbox::new();
        let (idx2, gen2) = table.allocate().expect("re-allocate");
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
        let (a, ga) = table.allocate().unwrap();
        table.install(a, ga, &i1);
        let (b, gb) = table.allocate().unwrap();
        table.install(b, gb, &i2);
        assert!(table.allocate().is_none());
        // Free one — allocate succeeds again.
        drop(i1);
        assert!(table.allocate().is_some());
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
