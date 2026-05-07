// net/tcp.rs — TCP state machine, per-core connection pool, ring buffers.
//
// Connections are partitioned across cores. Each core owns a slice of
// the global pool. The flow hash (in net/lib.rs) routes packets to the
// owning core. All connection operations are core-local — no locks.

#![no_std]

extern crate alloc;
extern crate uni_kernel;
extern crate uni_runtime;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate net_ipv4 as ipv4;
extern crate net_ipv6 as ipv6;
extern crate net_ipv6_send as ipv6_send;
extern crate bitflags;

use alloc::boxed::Box;
use core::ptr;
use core::task::Waker;
use from_bytes::FromBytes;
use types::{IpAddr, tcp_checksum_any, htons, ntohs, htonl, ntohl};
use ipv4::{ipv4_send, PROTO_TCP};

bitflags::bitflags! {
    struct TcpFlags: u8 {
        const FIN = 0x01;
        const SYN = 0x02;
        const RST = 0x04;
        const PSH = 0x08;
        const ACK = 0x10;
    }
}

const TCP_FIN: u8 = TcpFlags::FIN.bits();
const TCP_SYN: u8 = TcpFlags::SYN.bits();
const TCP_RST: u8 = TcpFlags::RST.bits();
const TCP_PSH: u8 = TcpFlags::PSH.bits();
const TCP_ACK: u8 = TcpFlags::ACK.bits();

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpState {
    Closed = 0,
    Listen,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
}

#[repr(C, packed)]
struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_offset: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent: u16,
}

// SAFETY: repr(C, packed), all fields are POD integers.
unsafe impl FromBytes for TcpHeader {}

/// Initial slots per core. The pool grows by `SEGMENT_SIZE`-slot
/// segments on demand thereafter, so this is a soft floor — once a
/// core's segment fills the pool allocates another. Keeping the
/// segment small keeps the per-core base memory footprint low for
/// idle cores; it's a stride for the slot→pointer index, not a hard
/// connection cap. (Pre-segmented-pool this was 128 and a hard cap;
/// reaching it wedged the listener until conns died.)
const SEGMENT_SIZE: u16 = 64;
/// Cap on segments per core. 1023 × 64 = 65472 slots, fits in a u16
/// slot index with `0xFFFF` reserved as the "null" / end-of-free-list
/// sentinel. Hitting this means 65k+ live conns on a single core,
/// which is several orders of magnitude past anything we can
/// realistically service — well before that, the per-core RX-inbox
/// and per-conn handler tasks will have starved out.
const MAX_SEGMENTS: usize = 1023;
const NULL_SLOT: u16 = 0xFFFF;
const RX_BUF_SIZE: usize = 8192;
/// Inline RX-chunk slots per `TcpConnection`. 8 slots × ~1024 B per
/// chunk covers `RX_BUF_SIZE` (8 KiB) comfortably for the common
/// MSS-1460 case (≤ 6 chunks fill the window). Inline avoids the
/// per-conn `VecDeque` heap allocation that the previous design
/// paid on every SYN-receive AND the `Option<VecDeque>` branch on
/// every per-segment `rx_push` / `rx_pop` call.
const RX_SLOTS: usize = 8;
/// IPv4 max TCP segment payload: MTU(1500) - IP(20) - TCP(20) = 1460.
const MSS_V4: usize = 1460;
/// IPv6 max TCP segment payload: MTU(1500) - IPv6(40) - TCP(20) = 1440.
/// Sending a 1460-byte payload over a v6 conn produces a 1534-byte
/// Ethernet frame that the userspace bridge truncates (or drops),
/// silently corrupting any response that needs more than one
/// full-size segment. /health works on v6 because it fits in one
/// short segment; multi-part HTML responses (which need full-size
/// segments after the first chunk's headers) lose data starting at
/// the first 1460-byte payload — observable as Chrome's
/// ERR_SSL_PROTOCOL_ERROR over `https://localhost/`.
const MSS_V6: usize = 1440;
/// Conservative buffer cap that fits both. Used as the stack
/// allocation for `send_segment`'s on-stack TCP segment.
const MSS_MAX: usize = MSS_V4;

/// Pick the MSS for a given local IP family.
fn mss_for(local_ip: IpAddr) -> usize {
    match local_ip {
        IpAddr::V4(_) => MSS_V4,
        IpAddr::V6(_) => MSS_V6,
    }
}

pub struct TcpConnection {
    pub state: TcpState,
    /// Peer's IP — IPv4 or IPv6. Used as the destination of every
    /// outbound segment AND as part of the per-conn lookup key.
    remote_ip: IpAddr,
    /// Our IP that the peer addressed when they SYN'd. Recorded so
    /// outbound segments use the matching pseudo-header (different
    /// for v4 vs v6) and so we reply from whichever of our
    /// addresses the peer expects to see.
    local_ip: IpAddr,
    local_port: u16,
    remote_port: u16,
    snd_nxt: u32,
    snd_una: u32,
    rcv_nxt: u32,
    rcv_wnd: u16,
    /// In-order RX chunk list. `None` until the connection is
    /// accepted (allocated in `tcp_receive` SYN handling), then a
    /// `VecDeque<IOBuf>` whose total visible-payload length is at
    /// most `RX_BUF_SIZE` bytes. Each `rx_push` appends one chunk;
    /// `rx_pop` walks chunks left-to-right copying into the user
    /// buffer, dropping each chunk when fully drained or trimming
    /// it via `IOBuf::consume(n)` on partial drain. Drop runs the
    /// IOBuf chain's drop on connection reset, which returns each
    /// chunk's backing buffer to its driver pool.
    ///
    /// The `Option` is the SYN-time admission gate — if the
    /// `VecDeque::with_capacity` allocation fails on a fresh
    /// connection we refuse the connection rather than panic.
    rx_slots: [Option<uni_iobuf::IOBuf>; RX_SLOTS],
    rx_head: u8,
    rx_tail: u8,
    /// Cached total length of `rx_slots` payloads. Avoids walking
    /// the slots on every `rx_used` / `rx_free` call (TCP segment
    /// processing reads them per-segment for the window field).
    rx_used: usize,
    listener_port: u16,
    accepted: bool,
    /// Incremented every time `free_connection` resets this slot, so
    /// a stale async handle that survived a close+reuse sees a
    /// generation mismatch on its next hook call and short-circuits
    /// to the "closed" path. Preserved across reset — `new()` does
    /// NOT reset it; `free_connection` bumps it explicitly.
    generation: u16,
    /// Parked `TcpRecv` waker. Set by `register_recv_waker` on the
    /// owning core; woken when data lands in `rx_slots` or the
    /// peer closes. Per-core ownership — no lock needed.
    recv_waker: Option<Waker>,
    /// Free-list link. When this slot is on the free list (state ==
    /// Closed AND the slot has been returned to the pool), this
    /// holds the index of the next free slot, or `NULL_SLOT` for
    /// end-of-list. Untouched while the slot is live; on `free` the
    /// pool overwrites it; on `alloc` the pool reads it once.
    next_free: u16,
}

impl TcpConnection {
    const fn new() -> Self {
        TcpConnection {
            state: TcpState::Closed,
            remote_ip: IpAddr::V4_ANY,
            local_ip: IpAddr::V4_ANY,
            local_port: 0,
            remote_port: 0,
            snd_nxt: 0,
            snd_una: 0,
            rcv_nxt: 0,
            rcv_wnd: RX_BUF_SIZE as u16,
            rx_slots: [const { None }; RX_SLOTS],
            rx_head: 0,
            rx_tail: 0,
            rx_used: 0,
            listener_port: 0,
            accepted: false,
            generation: 0,
            recv_waker: None,
            next_free: NULL_SLOT,
        }
    }

    #[inline]
    fn rx_used(&self) -> usize {
        self.rx_used
    }

    #[inline]
    fn rx_free(&self) -> usize {
        // -1 to leave room for the FIN-with-data edge case the
        // ring-buffer version reserved; behavioural parity.
        RX_BUF_SIZE.saturating_sub(self.rx_used).saturating_sub(1)
    }

    /// True when the slot ring has no IOBuf available to push into.
    /// Caller treats this the same as window-full: drop the
    /// segment and let the sender retransmit when our advertised
    /// `rcv_wnd` opens.
    #[inline]
    fn rx_slots_full(&self) -> bool {
        ((self.rx_tail as usize + 1) % RX_SLOTS) == self.rx_head as usize
    }

    /// Append an IOBuf chunk to the rx queue. `iobuf.data()` should
    /// already be just the TCP segment payload (caller has consumed
    /// past the TCP header). Returns the number of bytes accepted —
    /// may be less than `iobuf.data().len()` if the receive window
    /// is partially full, in which case the IOBuf is trimmed via
    /// `IOBuf::trim_end(...)` before being pushed (the dropped
    /// suffix isn't kept; the sender will retransmit when our
    /// advertised window opens up).
    fn rx_push(&mut self, mut iobuf: uni_iobuf::IOBuf) -> usize {
        if self.rx_slots_full() { return 0; }
        let free = RX_BUF_SIZE.saturating_sub(self.rx_used).saturating_sub(1);
        if free == 0 { return 0; }
        let len = iobuf.data().len();
        let n = len.min(free);
        if n == 0 { return 0; }
        if n < len {
            // Window can't take the whole segment; trim the trailing
            // bytes so the chunk fits exactly. The sender will
            // re-send those bytes on retransmit once `rcv_wnd` opens.
            if iobuf.trim_end(len - n).is_err() {
                return 0;
            }
        }
        // SAFETY: `rx_tail < RX_SLOTS` always (kept in range by the
        // mod below) and the slot at `rx_tail` is `None` because
        // either it was just produced fresh by `new()` or `rx_pop`
        // cleared it via `Option::take`. The full-check above
        // guarantees we're not overwriting an in-flight chunk.
        self.rx_slots[self.rx_tail as usize] = Some(iobuf);
        self.rx_tail = ((self.rx_tail as usize + 1) % RX_SLOTS) as u8;
        self.rx_used += n;
        n
    }

    fn rx_pop(&mut self, out: &mut [u8]) -> usize {
        let mut written = 0;
        while written < out.len() {
            let head_idx = self.rx_head as usize;
            let head = match &mut self.rx_slots[head_idx] {
                Some(h) => h,
                None => break,
            };
            let head_data = head.data();
            let want = out.len() - written;
            let take = want.min(head_data.len());
            if take == 0 {
                // Defensive: empty chunk shouldn't happen post-push,
                // but if it does, drop and advance.
                self.rx_slots[head_idx] = None;
                self.rx_head = ((head_idx + 1) % RX_SLOTS) as u8;
                continue;
            }
            out[written..written + take].copy_from_slice(&head_data[..take]);
            written += take;
            if take == head_data.len() {
                // Fully drained — drop the IOBuf (releases its
                // backing buffer to the driver pool) and advance.
                self.rx_slots[head_idx] = None;
                self.rx_head = ((head_idx + 1) % RX_SLOTS) as u8;
            } else {
                // Partial drain — advance the visible payload.
                let _ = head.consume(take);
            }
        }
        self.rx_used -= written;
        written
    }
}

// Per-core connection pools. Core N owns POOLS[N].
//
// Each `TcpConnection` is wrapped in `TcpConnCell` (an `UnsafeCell`
// newtype) so cores share the `POOLS` static via shared references
// rather than aliased `&mut`. The outer per-core array is held in
// `uni_kernel::percpu::PerWorker`, which provides typed `current(&CurrentWorker)`
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
            unsafe { *self.free_head.get() = next; }
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
        for _ in 0..SEGMENT_SIZE {
            new_seg.push(TcpConnCell::new());
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

static POOLS: uni_kernel::percpu::PerWorker<TcpPool> =
    uni_kernel::percpu::PerWorker::new();

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
const TCP_HASH_SIZE: usize = 256;
const TCP_HASH_MASK: usize = TCP_HASH_SIZE - 1;

struct TcpHashCore {
    keys: core::cell::UnsafeCell<[u64; TCP_HASH_SIZE]>,
    slots: core::cell::UnsafeCell<[u16; TCP_HASH_SIZE]>,
}
unsafe impl Sync for TcpHashCore {}
unsafe impl Send for TcpHashCore {}
impl TcpHashCore {
    const fn new() -> Self {
        TcpHashCore {
            keys: core::cell::UnsafeCell::new([0; TCP_HASH_SIZE]),
            slots: core::cell::UnsafeCell::new([0; TCP_HASH_SIZE]),
        }
    }
}

static TCP_HASH: uni_kernel::percpu::PerWorker<TcpHashCore> =
    uni_kernel::percpu::PerWorker::new();

#[inline]
fn tcp_hash_key(src_ip: IpAddr, src_port: u16, dst_port: u16) -> u64 {
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
    let family_bit = if matches!(src_ip, IpAddr::V6(_)) { 1u64 << 62 } else { 0 };
    (ip << 32) | ((src_port as u64) << 16) | (dst_port as u64) | (1u64 << 63) | family_bit
}

#[inline]
fn tcp_hash_bucket(key: u64) -> usize {
    // Fibonacci hash — multiplies by 2^64/phi and takes the top
    // bits. Fast (one imul), good distribution for arbitrary
    // 64-bit keys.
    let h = key.wrapping_mul(0x9E3779B97F4A7C15);
    (h >> (64 - 8)) as usize
}

fn tcp_hash_find(core: u32, key: u64) -> Option<usize> {
    let h = TCP_HASH.at(core);
    // SAFETY: per-core ownership, only the owning core reads/writes.
    let keys = unsafe { &*h.keys.get() };
    let slots = unsafe { &*h.slots.get() };
    let start = tcp_hash_bucket(key);
    for i in 0..TCP_HASH_SIZE {
        let idx = (start + i) & TCP_HASH_MASK;
        let k = keys[idx];
        if k == 0 { return None; }
        if k == key { return Some(slots[idx] as usize); }
    }
    None
}

fn tcp_hash_insert(core: u32, key: u64, slot: usize) {
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

fn tcp_hash_remove(core: u32, key: u64) {
    let h = TCP_HASH.at(core);
    let keys = unsafe { &mut *h.keys.get() };
    let slots = unsafe { &mut *h.slots.get() };
    let start = tcp_hash_bucket(key);
    // First find the entry.
    let mut found_idx = None;
    for i in 0..TCP_HASH_SIZE {
        let idx = (start + i) & TCP_HASH_MASK;
        let k = keys[idx];
        if k == 0 { return; }
        if k == key { found_idx = Some(idx); break; }
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
fn conn_ptr(core: u32, slot: usize) -> *mut TcpConnection {
    POOLS.at(core).slot_ptr(slot as u16)
}

/// Snapshot of `core`'s pool capacity — number of slots that have
/// been materialized so far. Linear-scan callers walk `0..pool_capacity(core)`.
#[inline]
fn pool_capacity(core: u32) -> usize {
    POOLS.at(core).capacity() as usize
}

/// Draw a per-connection initial sequence number.
///
/// Previously this was a global counter that stepped by 64 000, which
/// made the ISN trivially guessable and invited off-path sequence
/// injection. Each new connection now gets a fresh 32-bit sample from
/// the kernel RNG (ChaCha20 keystream, seeded from jitter + RDRAND on
/// x86). One ChaCha block / connection is well below SYN cost.
#[inline]
fn next_seq() -> u32 {
    let mut buf = [0u8; 4];
    uni_kernel::rng::fill_bytes(&mut buf);
    u32::from_ne_bytes(buf)
}

/// Encode a connection handle from core + slot index. Slots are
/// now u16-wide (the segmented pool can grow well past the 8-bit
/// slot space the original encoding allowed); the high bits of the
/// usize hold the core id, low 16 hold the slot.
/// Handle = ((core << 16) | slot) + 1, +1 to avoid null.
fn encode_handle(core: u32, slot: usize) -> *mut () {
    let v = ((core as usize) << 16) | (slot & 0xFFFF);
    (v + 1) as *mut ()
}

/// Decode a handle into (core, slot). The slot is bounds-checked
/// against the owning core's current pool capacity (which grows as
/// segments are added) — a stale handle pointing past `capacity()`
/// is treated as invalid.
fn decode_handle(handle: *mut ()) -> Option<(u32, usize)> {
    let v = (handle as usize).wrapping_sub(1);
    let core = (v >> 16) as u32;
    let slot = v & 0xFFFF;
    if core >= POOLS.len() || slot >= pool_capacity(core) {
        None
    } else {
        Some((core, slot))
    }
}

fn alloc_connection(core: u32) -> Option<usize> {
    let pool = POOLS.at(core);
    // O(1) fast path: pop from the free list. The pool grows by
    // one segment if the list is empty.
    if let Some(slot) = pool.alloc() {
        // SAFETY: per-core ownership; only the owning core (which is `core`
        // by the public API contract) calls this. The slot was just popped
        // from the free list, so no other code holds a reference.
        let c = unsafe { &mut *conn_ptr(core, slot as usize) };
        // Preserve generation across reuse so any still-outstanding
        // async handle observes the bump on its next hook call.
        let preserved_gen = c.generation;
        *c = TcpConnection::new();
        c.generation = preserved_gen;
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
        TcpState::FinWait1, TcpState::FinWait2,
        TcpState::LastAck, TcpState::TimeWait, TcpState::CloseWait,
    ] {
        for i in 0..cap {
            let c = unsafe { &*conn_ptr(core, i) };
            if c.state == state {
                // free_connection bumps generation, resets the slot,
                // and pushes onto the free list. Re-pop and return.
                free_connection(core, i);
                return pool.alloc().map(|s| s as usize);
            }
        }
    }
    None
}

fn free_connection(core: u32, slot: usize) {
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
    // Fire any parked `TcpRecv` waker before the slot is reset —
    // the app handler needs to observe teardown (recv returns 0)
    // rather than sleeping on a stale waker that would get dropped.
    if let Some(w) = c.recv_waker.take() {
        w.wake();
    }
    // Bump generation so any still-outstanding async handle detects
    // the slot has been reused on its next hook call. Preserved
    // across the reset below.
    let next_gen = c.generation.wrapping_add(1);
    // Assigning a fresh TcpConnection drops the old one, which
    // walks `rx_slots: [Option<IOBuf>; RX_SLOTS]` and drops each
    // remaining IOBuf — running its drop callback returns each
    // chunk's backing buffer to the driver pool (or frees the
    // heap allocation on the legacy IPv6 wrap path).
    *c = TcpConnection::new();
    c.generation = next_gen;
    // Return the slot to the pool's free list. O(1) push; the next
    // `alloc_connection` call picks it up in O(1) too.
    POOLS.at(core).free_slot(slot as u16);
}

fn send_segment(
    local_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) {
    // Caller already chunked to per-family MSS via `mss_for(local_ip)`,
    // but clamp again with the conservative `MSS_MAX` so a misuse
    // doesn't blow the stack-allocated `buf` below.
    let payload_len = payload.len().min(MSS_MAX);
    let seg_len = 20 + payload_len;

    let mut buf = core::mem::MaybeUninit::<[u8; 20 + MSS_MAX]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;

    unsafe {
        let hdr = &mut *(p as *mut TcpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.seq = htonl(seq);
        hdr.ack = htonl(ack);
        hdr.data_offset = 0x50;
        hdr.flags = flags;
        hdr.window = htons(window);
        hdr.checksum = 0;
        hdr.urgent = 0;

        if !payload.is_empty() {
            ptr::copy_nonoverlapping(payload.as_ptr(), p.add(20), payload_len);
        }

        hdr.checksum = tcp_checksum_any(local_ip, dst_ip, PROTO_TCP, p, seg_len);

        let bytes = core::slice::from_raw_parts(p, seg_len);
        send_l3(local_ip, dst_ip, bytes);
    }
}

fn send_rst(local_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, seq: u32, ack: u32) {
    let mut buf = core::mem::MaybeUninit::<[u8; 20]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;
    unsafe {
        let hdr = &mut *(p as *mut TcpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.seq = htonl(seq);
        hdr.ack = htonl(ack);
        hdr.data_offset = 0x50;
        hdr.flags = TCP_RST | TCP_ACK;
        hdr.window = 0;
        hdr.checksum = 0;
        hdr.urgent = 0;

        hdr.checksum = tcp_checksum_any(local_ip, dst_ip, PROTO_TCP, p, 20);

        let bytes = core::slice::from_raw_parts(p, 20);
        send_l3(local_ip, dst_ip, bytes);
    }
}

/// Family-aware L3 send. Dispatches to `ipv4_send` (which handles
/// ARP internally) for v4 destinations and to `ipv6_send` (which
/// handles NDP internally) for v6. The `local_ip` is currently
/// just used by the checksum calculator; v4 uses CONFIG.ip(), v6
/// uses our link-local — both selected upstream when the TCB
/// captured `local_ip` from the SYN.
fn send_l3(local_ip: IpAddr, dst_ip: IpAddr, segment: &[u8]) {
    match (local_ip, dst_ip) {
        (_, IpAddr::V4(d)) => ipv4_send(d, PROTO_TCP, segment),
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            ipv6_send::ipv6_send(&s, &d, ipv6::next_header::TCP, 64, segment);
        }
        // Mismatched family — should never happen in correct code.
        // Drop silently rather than crash the kernel.
        _ => {}
    }
}

/// Process an incoming TCP packet. Called on the owning core (via flow hash).
/// `src_ip` and `dst_ip` are family-tagged so v4 and v6 connections
/// share the same TCB pool, hash table, and dispatch path.
///
/// Takes ownership of the segment as an `IOBuf` whose `data()` is
/// the full TCP segment (header + payload). After header parse,
/// `iobuf.consume(data_offset)` advances the visible payload past
/// the header so the IOBuf can be moved into `rx_push` directly
/// (no memcpy at the protocol-recv boundary). Control-only
/// segments (SYN, RST, FIN-only, ACK-only) drop the IOBuf at
/// end-of-scope, returning its backing buffer to the driver pool.
pub fn tcp_receive(src_ip: IpAddr, dst_ip: IpAddr, mut iobuf: uni_iobuf::IOBuf) {
    let data = iobuf.data();
    let hdr = match TcpHeader::try_ref_from(data) {
        Some(h) => h,
        None => return,
    };
    let src_port = ntohs(hdr.src_port);
    let dst_port = ntohs(hdr.dst_port);
    let seq = ntohl(hdr.seq);
    let ack = ntohl(hdr.ack);
    let flags = hdr.flags;
    let data_offset = ((hdr.data_offset >> 4) as usize) * 4;
    let payload_len = if data.len() > data_offset { data.len() - data_offset } else { 0 };

    // Determine which core owns this packet.
    let core = uni_kernel::cpu_id();

    // SAFETY for the closures below: per-core ownership — only this
    // core (== `core`) is touching POOLS[core][*].

    // RST handling.
    //
    // RFC 5961 §3.2: a blind off-path attacker with knowledge of the
    // 4-tuple could otherwise send `RST, seq=<anything>` to tear the
    // connection down. Only accept the reset if seq == rcv_nxt (the
    // strict in-sequence position). Any other seq is silently dropped.
    if flags & TCP_RST != 0 {
        let cap = pool_capacity(core);
        for i in 0..cap {
            let c = unsafe { &*conn_ptr(core, i) };
            if c.state != TcpState::Closed
                && c.state != TcpState::Listen
                && c.remote_ip == src_ip
                && c.local_port == dst_port
                && c.remote_port == src_port
            {
                if seq == c.rcv_nxt {
                    free_connection(core, i);
                }
                return;
            }
        }
        return;
    }

    // SYN — new connection from client
    if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
        // Find listener on this core
        let listener_idx = {
            let mut found = None;
            let cap = pool_capacity(core);
            for i in 0..cap {
                let c = unsafe { &*conn_ptr(core, i) };
                if c.state == TcpState::Listen && c.local_port == dst_port {
                    found = Some(i);
                    break;
                }
            }
            found
        };

        if listener_idx.is_none() {
            send_rst(dst_ip, src_ip, dst_port, src_port, 0, seq + 1);
            return;
        }

        // Allocate new connection on this core
        let slot = match alloc_connection(core) {
            Some(i) => i,
            None => return,
        };

        {
            let c = unsafe { &mut *conn_ptr(core, slot) };
            c.state = TcpState::SynReceived;
            c.remote_ip = src_ip;
            c.local_ip = dst_ip;
            c.local_port = dst_port;
            c.remote_port = src_port;
            let isn = next_seq();
            c.snd_nxt = isn;
            c.snd_una = c.snd_nxt;
            c.rcv_nxt = seq + 1;
            c.listener_port = dst_port;
            c.accepted = false;

            // RX chunk slots are inline (`rx_slots: [Option<IOBuf>;
            // RX_SLOTS]`) and pre-zeroed by `TcpConnection::new()` —
            // no per-conn heap allocation here. Reset cursors so the
            // connection starts with an empty ring whether the slot
            // was freshly allocated or reused from the free list.
            c.rx_head = 0;
            c.rx_tail = 0;
            c.rx_used = 0;
        }

        // Publish this 4-tuple to the per-core hash index so the
        // subsequent ACK + data segments land in `tcp_hash_find`
        // with one probe instead of a 128-slot linear scan.
        let key = tcp_hash_key(src_ip, src_port, dst_port);
        tcp_hash_insert(core, key, slot);

        // Send SYN+ACK
        {
            let c = unsafe { &*conn_ptr(core, slot) };
            send_segment(dst_ip, src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_SYN | TCP_ACK, RX_BUF_SIZE as u16, &[]);
        }
        unsafe {
            let cp = conn_ptr(core, slot);
            (*cp).snd_nxt = (*cp).snd_nxt.wrapping_add(1);
        }
        return;
    }

    // O(1) hash lookup by 4-tuple (replaces an O(128) linear scan
    // that used to dominate cost on the RX hot path under
    // wrk-c128 load). Also verify state — the linear scan used to
    // filter out Closed/Listen implicitly; with the hash we must
    // guard against stale entries left behind if any transition to
    // Closed took a path that skipped `free_connection`.
    let key = tcp_hash_key(src_ip, src_port, dst_port);
    let slot = match tcp_hash_find(core, key) {
        Some(s) => s,
        None => return,
    };
    {
        let c = unsafe { &*conn_ptr(core, slot) };
        if c.state == TcpState::Closed || c.state == TcpState::Listen {
            return;
        }
    }

    let c = unsafe { &mut *conn_ptr(core, slot) };

    // Process ACK
    if flags & TCP_ACK != 0 {
        if c.state == TcpState::SynReceived {
            c.state = TcpState::Established;
            c.snd_una = ack;
            // Wake any async `TcpListener::accept` awaiting on this
            // port. Runs on the core that received the 3-way-ACK,
            // which is the same core that owns this conn slot, so
            // the reactor's per-worker waker fires the right task.
            let port = c.listener_port;
            uni_runtime::net::deliver_tcp_ready(port);
        } else if c.state == TcpState::LastAck {
            free_connection(core, slot);
            return;
        } else if c.state == TcpState::FinWait1 && ack == c.snd_nxt {
            // Peer ACK'd our FIN. Move to FinWait2 to await the peer's
            // FIN. Without this transition the slot stays in FinWait1
            // forever if the peer doesn't piggyback its FIN with the
            // ACK (Linux clients on a half-closed conn frequently send
            // the ACK and the FIN as separate segments).
            c.state = TcpState::FinWait2;
            c.snd_una = ack;
        } else {
            c.snd_una = ack;
        }
    }

    // Process data
    if payload_len > 0 && (c.state == TcpState::Established || c.state == TcpState::FinWait1 || c.state == TcpState::FinWait2) {
        if seq == c.rcv_nxt {
            // Advance the IOBuf's visible payload past the TCP
            // header so `data()` is just the segment body, then
            // hand ownership to `rx_push`. Trim trailing pad
            // bytes (the IPv4 caller already trimmed at the IP
            // layer, so `visible == payload_len` typically; the
            // belt-and-braces check costs nothing).
            if iobuf.consume(data_offset).is_err() {
                return;
            }
            let visible = iobuf.data().len();
            if visible > payload_len
                && iobuf.trim_end(visible - payload_len).is_err()
            {
                return;
            }
            let pushed = c.rx_push(iobuf);
            c.rcv_nxt = c.rcv_nxt.wrapping_add(pushed as u32);
            c.rcv_wnd = c.rx_free() as u16;
            // Wake any `TcpRecvReady` parked on this conn. Same core
            // owns the waker and the rx ring, so no cross-core hop.
            if pushed > 0 {
                if let Some(w) = c.recv_waker.take() {
                    w.wake();
                }
            }
            // Send an immediate ACK. The previous version of this code
            // deferred ACKs to piggyback on the next outbound data
            // segment (avoiding a stall on macOS's delayed-ACK
            // interaction with our own output), but that assumed the
            // app would always have outbound data to send right after
            // receiving input — true on keep-alive /health requests,
            // false on the TLS handshake path where the server has no
            // imminent response after receiving, say, the client's
            // Finished. Without an immediate ACK here the Linux peer
            // waits out its delayed-ACK timer (~40ms) before sending
            // its next handshake record, which capped GCP KVM's
            // `tls_handshake_max` at ~20 hs/s.
            //
            // The immediate ACK does double segment count on the pure
            // receive path (one ACK + one eventual data segment,
            // rather than one data segment carrying the ACK), which
            // on our existing benches costs ~2-3 % on
            // `health_max` / `health_tls_max` — well worth eating to
            // unbreak the handshake path. If the macOS delayed-ACK
            // regression from the old comment shows up again we'll
            // want a real timer-based ACK coalescer rather than
            // pinning this to "next data segment".
            send_segment(dst_ip, src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_ACK, c.rx_free() as u16, &[]);
        } else if seq_lt(seq, c.rcv_nxt) {
            // Duplicate/retransmitted segment — send ACK immediately so the
            // sender knows we already have this data (fast retransmit signal).
            send_segment(dst_ip, src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_ACK, c.rx_free() as u16, &[]);
        }
    }

    // Process FIN.
    //
    // A FIN is in-sequence iff its own seq number (seq + payload_len)
    // equals our current rcv_nxt. Anything else — including an
    // off-path FIN with a guessed seq or a delayed retransmission
    // whose FIN was already consumed — is ignored. Advancing rcv_nxt
    // unconditionally (as the previous version did) let any FIN-bit
    // segment close the connection and desync the receive stream.
    if flags & TCP_FIN != 0 && seq.wrapping_add(payload_len as u32) == c.rcv_nxt {
        c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
        send_segment(dst_ip, src_ip, dst_port, src_port, c.snd_nxt, c.rcv_nxt, TCP_ACK, c.rx_free() as u16, &[]);

        match c.state {
            TcpState::Established | TcpState::SynReceived => {
                c.state = TcpState::CloseWait;
            }
            TcpState::FinWait1 => {
                free_connection(core, slot);
            }
            TcpState::FinWait2 => {
                free_connection(core, slot);
            }
            _ => {}
        }
        // Peer FIN is also a readable-state transition: any pending
        // `recv_ready` must resolve so the handler can observe the
        // close via `is_closed()` / `recv() == 0`. `free_connection`
        // above already resets the whole conn (including `recv_waker`)
        // via `TcpConnection::new()`; in the CloseWait branch we still
        // hold the waker, so fire it here.
        if c.state == TcpState::CloseWait {
            if let Some(w) = c.recv_waker.take() {
                w.wake();
            }
        }
    }
}

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

// ============================================================================
// TCP public API — handles encode (core, slot) for transparent routing.
// ============================================================================

/// Initialize TCP connection pools. Each per-core pool starts
/// empty; the first `alloc_connection` call grows it by a segment.
/// No per-core slot pre-init is needed — segment construction
/// initializes every slot to a fresh `TcpConnection` and links them
/// into the free list before publishing the segment.
pub fn init() {
    let n = uni_kernel::percpu::num_cores();
    POOLS.init(n, |_| TcpPool::new());
    TCP_HASH.init(n, |_| TcpHashCore::new());
}

/// Create a listener on a specific core. Called from
/// `net::tcp_backend_listen` once per core at `TcpListener::bind`
/// time.
pub fn listen_on_core(core: u32, port: u16) -> *mut () {
    let slot = match alloc_connection(core) {
        Some(i) => i,
        None => return ptr::null_mut(),
    };
    // SAFETY: per-core ownership; only the owning core mutates this slot.
    // listen_on_core is called from app init, single-threaded.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    c.state = TcpState::Listen;
    c.local_port = port;
    encode_handle(core, slot)
}

/// Accept a connection on the **current core** by port — the
/// entry point used by `uni_runtime::net::TcpListener`'s backend
/// hook. Returns `TcpStream::NULL` if no connection is ready
/// on this core.
pub fn accept_on_port(port: u16) -> uni_runtime::net::TcpStream {
    accept_on_port_core(uni_kernel::cpu_id(), port)
}

fn accept_on_port_core(core: u32, port: u16) -> uni_runtime::net::TcpStream {
    use uni_runtime::net::TcpStream;
    let cap = pool_capacity(core);
    for i in 0..cap {
        // SAFETY: per-core ownership.
        let c = unsafe { &mut *conn_ptr(core, i) };
        if c.state == TcpState::Established && c.listener_port == port && !c.accepted {
            c.accepted = true;
            return TcpStream::from_raw(encode_handle(core, i), c.generation);
        }
    }
    TcpStream::NULL
}

/// Async-readiness probe — returns `true` when there's inbound
/// data to consume OR the connection is in a terminal state
/// (Closed / CloseWait / LastAck / TimeWait), so the `TcpRecv`
/// future resolves on peer FIN and the caller sees `recv() == 0`.
/// A `generation` mismatch also reports "ready" so stale handles
/// promptly resolve to closed. Registered as the `TCP_HAS_DATA`
/// hook.
pub fn is_readable_or_closed(handle: *mut (), generation: u16) -> bool {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return true,
    };
    let c = unsafe { &*conn_ptr(core, slot) };
    if c.generation != generation {
        return true; // stale → treat as closed
    }
    if c.rx_used() > 0 {
        return true;
    }
    matches!(c.state, TcpState::Closed | TcpState::CloseWait
                     | TcpState::LastAck | TcpState::TimeWait)
}

pub fn close(handle: *mut (), generation: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    // SAFETY: per-core ownership.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    // Stale handle: slot was already reused. Drop on the floor —
    // the slot has its own lifecycle now.
    if c.generation != generation {
        return;
    }
    // Advertise the actual receive-buffer space in the FIN. Sending
    // FIN with `win=0` is technically legal but Linux clients treat
    // it as a zero-window event and queue the FIN+ACK behind a persist
    // timer, leaving the connection orphaned in FIN_WAIT_1 on our side.
    // Since we've drained the request out of the rx ring before
    // responding, `rx_free()` is the full buffer here.
    let win = c.rx_free() as u16;
    match c.state {
        TcpState::Established => {
            send_segment(
                c.local_ip, c.remote_ip, c.local_port, c.remote_port,
                c.snd_nxt, c.rcv_nxt, TCP_FIN | TCP_ACK, win, &[],
            );
            c.snd_nxt = c.snd_nxt.wrapping_add(1);
            c.state = TcpState::FinWait1;
        }
        TcpState::CloseWait => {
            send_segment(
                c.local_ip, c.remote_ip, c.local_port, c.remote_port,
                c.snd_nxt, c.rcv_nxt, TCP_FIN | TCP_ACK, win, &[],
            );
            free_connection(core, slot);
            return;
        }
        _ => {
            free_connection(core, slot);
        }
    }
}

/// RST every active connection in every core's pool. Called from
/// `uni::shutdown_and_drop` so the peer sees an immediate close
/// instead of a silently-vanishing VM (which would only time out
/// via TCP keepalive — minutes later). Walks every slot once,
/// emits one RST per non-Closed/Listen conn, frees the slot.
///
/// Safety: by the time this fires, BSP has already broken out of
/// the eventloop and AP cores are spin-looping past their break
/// before they hit PSCI CPU_OFF. They aren't actively mutating
/// their pools, so cross-core read access is race-free for the
/// shutdown window.
pub fn shutdown_all() {
    let n = uni_kernel::percpu::num_cores();
    for core in 0..n {
        let cap = pool_capacity(core);
        for slot in 0..cap {
            // SAFETY: see fn-level comment — APs have left the
            // eventloop; only BSP runs this and it owns its own
            // slots, with read-only access to AP slots.
            let c = unsafe { &mut *conn_ptr(core, slot) };
            if c.state == TcpState::Closed || c.state == TcpState::Listen {
                continue;
            }
            send_rst(c.local_ip, c.remote_ip, c.local_port, c.remote_port, c.snd_nxt, c.rcv_nxt);
            free_connection(core, slot);
        }
    }
    // The caller (`net::bare_shutdown_all`) flushes the virtio TX
    // staging + kick after this returns — `net_tcp` deliberately
    // doesn't depend on `uni_drivers`.
}

/// Async `TcpRecv` sync read hook. Verifies `generation`; stale
/// handles return 0 (observed by caller as EOF / close).
pub fn async_recv(handle: *mut (), generation: u16, buf: &mut [u8]) -> usize {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return 0,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return 0;
    }
    c.rx_pop(buf)
}

/// Park the current task's waker on this conn, to be woken when
/// data arrives or the peer FINs. Called from
/// `uni_runtime::net::TcpRecv::poll` on the owning core. A
/// `generation` mismatch fires the waker immediately so the task
/// observes closure on its next poll.
pub fn register_recv_waker(handle: *mut (), generation: u16, waker: &Waker) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => { waker.wake_by_ref(); return; }
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        waker.wake_by_ref();
        return;
    }
    match &c.recv_waker {
        Some(w) if w.will_wake(waker) => {}
        _ => c.recv_waker = Some(waker.clone()),
    }
}

/// Drop the parked waker without firing it. Called from
/// `TcpRecv::poll` after resolving Ready so a subsequent data
/// arrival doesn't wake a no-longer-interested task. Stale
/// `generation` is a no-op.
pub fn clear_recv_waker(handle: *mut (), generation: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return;
    }
    c.recv_waker = None;
}

/// Async `TcpSendChain` try-send hook. Walks `chain` via cursor
/// and emits MSS-sized TCP segments, copying directly from chain
/// nodes into each segment's payload area — no user-space
/// scratch coalesce. Drains the chain as bytes hit the wire so
/// `External` IOBufs (NIC RX descriptors etc.) return to the
/// driver pool as the response leaves the box, not all at the
/// end.
///
/// Bare-metal's NIC TX never blocks under this stack's load
/// model, so this always sends every byte in the chain (or
/// returns `Err(())` on a dead conn / stale `gen`).
pub fn async_try_send_chain(
    handle: *mut (),
    generation: u16,
    chain: &mut uni_iobuf::IOBufChain,
) -> Result<usize, ()> {
    let (core, slot) = decode_handle(handle).ok_or(())?;
    // SAFETY: per-core ownership; the worker that registered this
    // backend is the one polling its `TcpSendChain`.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return Err(());
    }
    if c.state != TcpState::Established {
        return Err(());
    }

    let total = chain.total_len();
    if total == 0 {
        return Ok(0);
    }

    let mss = mss_for(c.local_ip);
    let mut cursor = chain.cursor();
    let mut sent = 0usize;
    while sent < total {
        let chunk = (total - sent).min(mss);
        send_segment_from_cursor(
            c.local_ip,
            c.remote_ip,
            c.local_port,
            c.remote_port,
            c.snd_nxt,
            c.rcv_nxt,
            TCP_ACK | TCP_PSH,
            c.rx_free() as u16,
            &mut cursor,
            chunk,
        );
        c.snd_nxt = c.snd_nxt.wrapping_add(chunk as u32);
        sent += chunk;
    }

    // Bytes are on the wire — release the cursor's borrow on the
    // chain and drain it. Drops fire in chain order (External
    // callbacks recycle NIC descriptors back to driver pools).
    drop(cursor);
    chain.clear();
    Ok(sent)
}

/// Like `send_segment` but reads `payload_len` bytes from a chain
/// cursor (advancing it) instead of borrowing from a contiguous
/// slice. Caller must have ensured the cursor has at least
/// `payload_len` bytes remaining.
fn send_segment_from_cursor(
    local_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    cursor: &mut uni_iobuf::Cursor<'_>,
    payload_len: usize,
) {
    let payload_len = payload_len.min(MSS_MAX);
    let seg_len = 20 + payload_len;

    let mut buf = core::mem::MaybeUninit::<[u8; 20 + MSS_MAX]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;

    unsafe {
        let hdr = &mut *(p as *mut TcpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.seq = htonl(seq);
        hdr.ack = htonl(ack);
        hdr.data_offset = 0x50;
        hdr.flags = flags;
        hdr.window = htons(window);
        hdr.checksum = 0;
        hdr.urgent = 0;

        if payload_len > 0 {
            // Copy chain bytes straight into the segment's
            // payload area; cursor walks node boundaries
            // transparently. This is the "one memcpy, no
            // intermediate buffer" property the IOBuf chain
            // design exists for.
            let dst = core::slice::from_raw_parts_mut(p.add(20), payload_len);
            let n = cursor.read(dst);
            debug_assert_eq!(n, payload_len);
            let _ = n;
        }

        hdr.checksum = tcp_checksum_any(local_ip, dst_ip, PROTO_TCP, p, seg_len);

        let bytes = core::slice::from_raw_parts(p, seg_len);
        send_l3(local_ip, dst_ip, bytes);
    }
}

/// Park the send-side waker. On bare-metal `async_try_send_chain`
/// always accepts the whole buffer, so this path is effectively
/// unreachable during steady-state sends; kept symmetric with the
/// recv side so future NIC-TX-backpressure plumbing (or a proper
/// TCP send-window) can light it up without API churn. Stale
/// `generation` wakes the waker immediately so the task observes
/// closure.
pub fn register_send_waker(handle: *mut (), generation: u16, waker: &Waker) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => { waker.wake_by_ref(); return; }
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        waker.wake_by_ref();
        return;
    }
    // Write-readiness on bare-metal: the NIC TX path is always
    // "ready" for this stack. Fire immediately so the future
    // re-probes and resolves.
    waker.wake_by_ref();
    let _ = c;  // placate unused-var lint if we ever remove the wake.
}

pub fn clear_send_waker(_handle: *mut (), _generation: u16) {
    // No-op on bare-metal — no send-waker state to clear.
}

