// net/tcp.rs — TCP state machine, per-core connection pool, ring buffers.
//
// Connections are partitioned across cores. Each core owns a slice of
// the global pool. The flow hash (in net/lib.rs) routes packets to the
// owning core. All connection operations are core-local — no locks.

#![no_std]

extern crate alloc;
extern crate uni_kernel;
extern crate uni_runtime;
extern crate uni_drivers;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate net_dst_mac as dst_mac;
extern crate net_ethernet as ethernet;
extern crate net_ipv4 as ipv4;
extern crate net_ipv6 as ipv6;
extern crate net_ipv6_send as ipv6_send;
extern crate bitflags;

use alloc::boxed::Box;
use core::ptr;
use core::task::Waker;
use from_bytes::FromBytes;
use types::{IpAddr, MacAddr, tcp_checksum_any, tcp_pseudo_partial, htons, ntohs, htonl, ntohl};
use ipv4::PROTO_TCP;

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
/// the kernel RNG (SHA-256 hash chain, seeded from jitter + RDRAND on
/// x86). One SHA-256 block / connection is well below SYN cost.
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

// ─── Unified TCP-frame builder ───────────────────────────────────────────────
//
// Build the full Ethernet+IP+TCP+payload frame in one stack buffer
// and hand it directly to the driver. Replaces the legacy chain of
// `send_l3 → ipv4_send → ethernet_send`, which built a fresh stack
// buffer at each layer and `memcpy`'d the inner bytes forward —
// three memcpys per byte just to attach 54 B of headers.
//
// The two payload-source variants (slice / chain cursor) share
// `fill_tcp_frame_headers` for header-fill and family dispatch;
// only the payload-write step differs.
//
// Frame layout:
//   v4: [ETH 14][IPv4 20][TCP 20][payload ≤ MSS_V4 = 1460]  → ≤ 1514 B
//   v6: [ETH 14][IPv6 40][TCP 20][payload ≤ MSS_V6 = 1440]  → ≤ 1514 B
//
// Same total bound for both families, so one stack buffer fits all.
// TSO super-segments (up to ~16 KiB payload) bypass the stack
// buffer — they always use the driver's direct-fill TX-pool slot
// via `acquire_tx_buf` (which has the larger `data_cap` for the
// super-segment shape). When acquire fails on the TSO path, we
// fall back to the per-MSS loop rather than expanding this stack
// buffer to ~16 KiB.

const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = ipv4::HEADER_LEN;       // 20
const IPV6_HDR_LEN: usize = ipv6::HEADER_LEN;       // 40
const TCP_HDR_LEN: usize = 20;
const FRAME_BUF_LEN: usize = ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN + MSS_V4;
/// Per-conn-state cap on TSO super-segments: the maximum bytes we
/// hand to `submit_tx_tso` in one frame. Sized to cover one TLS
/// 1.3 record (16384 plaintext + 22-byte envelope) plus the
/// L2/L3/L4 headers. The driver's TX-pool slots are sized to
/// match (`MAX_ETH_FRAME` in uni-driver-virtio-net).
const TSO_FRAME_BUF_LEN: usize =
    ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN + 16384 + 24;

/// Compute the TCP-payload offset within a frame buffer for `local_ip`'s family.
#[inline]
fn payload_offset(local_ip: IpAddr) -> usize {
    match local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN,   // 54
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN,   // 74
    }
}

/// Fill the ETH + IP + TCP headers of `frame` in place. `frame` must
/// already contain the TCP payload at `frame[payload_offset(local_ip)..]`.
/// `payload_len` is the bytes past the TCP header (TCP segment payload
/// length); 0 for control-only segments. Computes both IP and TCP
/// checksums in place.
unsafe fn fill_tcp_frame_headers(
    frame: &mut [u8],
    local_ip: IpAddr,
    dst_ip: IpAddr,
    dst_mac: MacAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload_len: usize,
) {
    let tcp_off = match local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN,
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN,
    };
    let tcp_seg_len = TCP_HDR_LEN + payload_len;

    // ── TCP header ───────────────────────────────────────────────────
    // SAFETY: frame[tcp_off..tcp_off+TCP_HDR_LEN] is in-bounds (caller
    // sized the buffer). `TcpHeader` is `repr(C)` POD bytes.
    let tcp_hdr = unsafe {
        &mut *(frame.as_mut_ptr().add(tcp_off) as *mut TcpHeader)
    };
    tcp_hdr.src_port = htons(src_port);
    tcp_hdr.dst_port = htons(dst_port);
    tcp_hdr.seq = htonl(seq);
    tcp_hdr.ack = htonl(ack);
    tcp_hdr.data_offset = 0x50;
    tcp_hdr.flags = flags;
    tcp_hdr.window = htons(window);
    tcp_hdr.checksum = 0;
    tcp_hdr.urgent = 0;
    // What we stamp depends on the active NIC's CSUM-offload
    // convention. virtio expects pseudo-header partial sum;
    // gve expects zero (device builds the pseudo-header from
    // the IP header). Without offload, we compute the full
    // checksum on the guest.
    tcp_hdr.checksum = if uni_drivers::net::csum_tx_offload() {
        match uni_drivers::net::csum_stamp_convention() {
            uni_drivers::net::CsumStampConvention::PseudoHeaderPartial => {
                tcp_pseudo_partial(local_ip, dst_ip, PROTO_TCP, tcp_seg_len)
            }
            uni_drivers::net::CsumStampConvention::Zero => 0,
        }
    } else {
        unsafe {
            tcp_checksum_any(
                local_ip, dst_ip, PROTO_TCP,
                frame.as_ptr().add(tcp_off), tcp_seg_len,
            )
        }
    };

    // ── IP header (family-dispatched) ────────────────────────────────
    let ip_total = (tcp_off - ETH_HDR_LEN + tcp_seg_len) as u16;
    match (local_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            ipv4::fill_header(
                &mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN],
                s, d, PROTO_TCP, ip_total,
            );
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            ipv6::fill_header(
                &mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV6_HDR_LEN],
                &s, &d, ipv6::next_header::TCP, 64, tcp_seg_len as u16,
            );
        }
        _ => unreachable!("mismatched family"),
    }

    // ── Ethernet header ──────────────────────────────────────────────
    let ethertype = match dst_ip {
        IpAddr::V4(_) => ethernet::ETHERTYPE_IPV4,
        IpAddr::V6(_) => ipv6::ETHERTYPE_IPV6,
    };
    ethernet::fill_header(
        &mut frame[..ETH_HDR_LEN],
        dst_mac,
        ethernet::ethernet_our_mac(),
        ethertype,
    );
}

/// Acquire a TX-pool slot from the driver and run `fill` over its
/// frame region; submit it for transmission. `csum_tcp_off` is
/// the byte offset of the TCP header within the frame (= `0` if
/// the caller doesn't want CSUM offload) — `submit_tx` reads
/// this to populate the offload-hint field.
///
/// Falls back to a stack-staged frame + slice-shaped `send` when
/// the driver doesn't expose direct-fill (`acquire_tx_buf == None`)
/// — the gve driver's DQO_RDA path surfaces this today.
///
/// `fill` writes `frame_len` bytes starting at the head of the
/// passed `&mut [u8]` (≥ `FRAME_BUF_LEN` bytes). Caller is
/// responsible for ensuring `frame_len <= FRAME_BUF_LEN`.
#[inline]
fn build_and_send_frame<F>(frame_len: usize, csum_tcp_off: u16, fill: F)
where
    F: FnOnce(&mut [u8]),
{
    debug_assert!(frame_len <= FRAME_BUF_LEN);
    let csum = if csum_tcp_off != 0 && uni_drivers::net::csum_tx_offload() {
        // 16 = byte offset of the TCP `checksum` field within
        // the TCP header.
        uni_drivers::net::CsumOffload { start: csum_tcp_off, offset: 16 }
    } else {
        uni_drivers::net::CsumOffload::NONE
    };
    if let Some(mut handle) = uni_drivers::net::acquire_tx_buf() {
        let cap = handle.data_cap as usize;
        debug_assert!(frame_len <= cap);
        // SAFETY: the handle's `data_mut()` returns a slice of
        // `data_cap` writable bytes; we narrow to `frame_len`
        // for the closure but the underlying buffer covers the
        // full slot.
        fill(&mut handle.data_mut()[..frame_len]);
        uni_drivers::net::submit_tx(handle, frame_len, csum);
        return;
    }
    // Slice-shaped fallback: stage on the stack, hand to the
    // driver's slice-shaped `send`. Driver-specific memcpy
    // happens inside; csum-offload hint is lost here (the slice
    // path doesn't carry it), so callers requesting offload
    // would see a broken checksum on a fallback driver. The
    // caller's `fill` already stamped the correct shape (full
    // checksum if `csum_tx_offload()` returned false at
    // header-fill time, partial otherwise) — but partial only
    // works when paired with a NEEDS_CSUM submit. So when we
    // fall back, the partial-stamped frame would be incorrect.
    //
    // In practice this can't bite today: the only fallback driver
    // is gve-DQO, which reports `csum_tx_offload() == false`, so
    // `fill` stamped the full checksum and the slice path ships
    // a correct frame. If a future driver returns true for offload
    // but None from acquire, we'll need to redo the checksum at
    // fallback time. Marked here so we catch it.
    let _ = csum;
    let mut buf = core::mem::MaybeUninit::<[u8; FRAME_BUF_LEN]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;
    // SAFETY: `from_raw_parts_mut` over uninit memory is fine
    // as long as the resulting slice is fully written before
    // any read. `fill` writes every byte in `[..frame_len]`;
    // `send` then reads them.
    unsafe {
        let frame = core::slice::from_raw_parts_mut(p, frame_len);
        fill(frame);
        let frame_const = core::slice::from_raw_parts(p, frame_len);
        uni_drivers::net::send(frame_const);
    }
}

/// Build and ship a TCP segment whose payload comes from `payload`
/// (a contiguous byte slice). Used by control-path callers (SYN,
/// SYN-ACK, ACK-only, FIN, RST) and by tests.
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
    let dst_mac = match dst_mac::resolve(dst_ip) {
        Some(m) => m,
        None => return, // ARP/NDP miss; TCP retransmit will retry
    };

    let payload_off = payload_offset(local_ip);
    let payload_len = payload.len().min(MSS_MAX);
    let frame_len = payload_off + payload_len;
    // TCP header offset within the frame = ETH + IP. Used by the
    // CSUM-offload hint passed to `submit_tx`.
    let tcp_off = match local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN,
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN,
    } as u16;

    build_and_send_frame(frame_len, tcp_off, |frame| unsafe {
        // Copy payload into the frame's payload slot.
        if payload_len > 0 {
            ptr::copy_nonoverlapping(
                payload.as_ptr(),
                frame.as_mut_ptr().add(payload_off),
                payload_len,
            );
        }
        fill_tcp_frame_headers(
            frame, local_ip, dst_ip, dst_mac,
            src_port, dst_port, seq, ack, flags, window,
            payload_len,
        );
    });
}

/// Build and ship a TCP TSO super-segment whose payload (up to
/// ~16 KiB — one TLS record's worth) is read from a chain
/// cursor. The driver's NIC segments the payload into MSS-sized
/// chunks host-side, fixing up TCP/IP headers per segment.
///
/// Caller must have verified `uni_drivers::net::tso_available()`
/// before reaching this. Falls back to the per-MSS loop in
/// `async_try_send_chain` when not available.
fn send_super_segment_from_cursor(
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
    let dst_mac = match dst_mac::resolve(dst_ip) {
        Some(m) => m,
        None => return,
    };

    let payload_off = payload_offset(local_ip);
    let frame_len = payload_off + payload_len;
    debug_assert!(frame_len <= TSO_FRAME_BUF_LEN);

    // TSO super-segments need a big-pool slot (16 KiB capacity).
    // Falls back to per-MSS when the big pool is full or TSO
    // isn't supported on this driver.
    let Some(mut handle) = uni_drivers::net::acquire_tx_tso_buf() else {
        send_per_mss_fallback(
            local_ip, dst_ip, src_port, dst_port,
            seq, ack, flags, window, cursor, payload_len,
        );
        return;
    };
    let cap = handle.data_cap() as usize;
    debug_assert!(frame_len <= cap);

    let frame = &mut handle.data_mut()[..frame_len];
    // Read the entire super-segment payload directly into the
    // TX-pool slot via the chain cursor — single memcpy across
    // chain → driver TX pool.
    if payload_len > 0 {
        let n = cursor.read(&mut frame[payload_off..payload_off + payload_len]);
        debug_assert_eq!(n, payload_len);
        let _ = n;
    }
    // SAFETY: `frame` is initialised through `frame[payload_off..
    // payload_off + payload_len]` above; the header-fill below
    // writes the rest.
    unsafe {
        fill_tcp_frame_headers(
            frame, local_ip, dst_ip, dst_mac,
            src_port, dst_port, seq, ack, flags, window,
            payload_len,
        );
    }
    // Zero the TCP checksum: with VIRTIO_NET_F_NEEDS_CSUM set,
    // the device computes the per-segment TCP checksum (the
    // partial-checksum convention isn't strictly required —
    // HVF's userspace TCP proxy ignores the field and forwards
    // bytes; vhost-net + real NICs honour the gso fields and
    // synthesise full checksums per segment).
    let tcp_off = match local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN,
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN,
    };
    frame[tcp_off + 16] = 0; // TCP checksum field, big-endian high byte
    frame[tcp_off + 17] = 0; //                              low byte

    let mss = mss_for(local_ip);
    let hdr_len = (payload_off) as u16;
    let csum_start = (tcp_off) as u16;
    uni_drivers::net::submit_tx_tso(
        handle, frame_len, hdr_len, csum_start, mss as u16,
    );
}

/// Try to send a single TCP TSO super-segment whose payload is
/// produced by `fill`. The closure is called with a mutable byte
/// slice into the driver's TX-pool big-slot's payload region
/// (i.e. the bytes after [ETH][IP][TCP] headers); it writes
/// payload bytes there and returns the byte count written.
/// This function fills the L2/L3/L4 headers around the closure's
/// output, calls `submit_tx_tso`, and advances `snd_nxt`.
///
/// The TLS layer uses this to encrypt directly into the TX-pool
/// slot — eliminating the stack-scratch → TX-slot memcpy that
/// the regular `async_try_send_chain` path does. The closure
/// receives access to bytes already in the driver's exclusive-
/// write buffer; the TLS encrypter's chain-to primitive walks
/// the plaintext chain and produces ciphertext directly into
/// those bytes.
///
/// Returns:
///   * `Some(payload_len)` on success — the bytes are in flight.
///   * `None` when no TSO slot is available (TSO not negotiated,
///     big pool full, conn not Established, dst MAC unresolved,
///     stale `gen`). Caller falls back to the regular send path.
pub fn try_send_tso(
    handle: *mut (),
    generation: u16,
    fill: &mut dyn FnMut(&mut [u8]) -> usize,
) -> Option<usize> {
    let (core, slot) = decode_handle(handle)?;
    // SAFETY: per-core ownership; the worker that registered
    // this backend is the one calling here.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return None;
    }
    if c.state != TcpState::Established {
        return None;
    }
    let dst_mac = dst_mac::resolve(c.remote_ip)?;
    let mut handle = uni_drivers::net::acquire_tx_tso_buf()?;

    let payload_off = payload_offset(c.local_ip);
    let cap = handle.data_cap() as usize;
    let max_payload = cap.saturating_sub(payload_off);

    // Hand the post-header region of the slot to the closure.
    // The closure (typically the TLS encrypt-chain-to path)
    // writes ciphertext bytes here and returns the count.
    let payload_len = {
        let region = &mut handle.data_mut()[payload_off..payload_off + max_payload];
        fill(region)
    };
    if payload_len == 0 {
        // Nothing to send — slot returns to the pool via the
        // handle's Drop without a virtio descriptor enqueue.
        return Some(0);
    }
    if payload_len > max_payload {
        // Closure overran (shouldn't happen given the slice we
        // handed in had capacity = max_payload). Defensive.
        return None;
    }

    let frame_len = payload_off + payload_len;
    let frame = &mut handle.data_mut()[..frame_len];

    // Fill ETH + IP + TCP headers in the prefix region.
    // SAFETY: caller verified `c` is exclusively-owned by this
    // worker; the frame slice is a fresh mutable reborrow that
    // doesn't alias with anything else (the closure's earlier
    // payload-region borrow ended above).
    unsafe {
        fill_tcp_frame_headers(
            frame, c.local_ip, c.remote_ip, dst_mac,
            c.local_port, c.remote_port,
            c.snd_nxt, c.rcv_nxt,
            TCP_ACK | TCP_PSH,
            c.rx_free() as u16,
            payload_len,
        );
    }
    // Zero the TCP checksum: NEEDS_CSUM tells the device to
    // compute it per emitted segment. Same convention as
    // `send_super_segment_from_cursor`.
    let tcp_off = match c.local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN,
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN,
    };
    frame[tcp_off + 16] = 0;
    frame[tcp_off + 17] = 0;

    let mss = mss_for(c.local_ip);
    let hdr_len = payload_off as u16;
    let csum_start = tcp_off as u16;
    uni_drivers::net::submit_tx_tso(
        handle, frame_len, hdr_len, csum_start, mss as u16,
    );

    c.snd_nxt = c.snd_nxt.wrapping_add(payload_len as u32);
    Some(payload_len)
}

/// Per-MSS fallback path — used when [`send_super_segment_from_cursor`]
/// can't acquire a TX-pool slot. Loops `send_segment_from_cursor`
/// over the cursor as the original (pre-TSO) path did.
fn send_per_mss_fallback(
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
    let mss = mss_for(local_ip);
    let mut sent = 0usize;
    let mut cur_seq = seq;
    while sent < payload_len {
        let chunk = (payload_len - sent).min(mss);
        send_segment_from_cursor(
            local_ip, dst_ip, src_port, dst_port,
            cur_seq, ack, flags, window, cursor, chunk,
        );
        cur_seq = cur_seq.wrapping_add(chunk as u32);
        sent += chunk;
    }
}

/// Build and ship a TCP segment whose payload is read from a chain
/// cursor. Used by the data-send hot path (`async_try_send_chain`).
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
    let dst_mac = match dst_mac::resolve(dst_ip) {
        Some(m) => m,
        None => return, // ARP/NDP miss; TCP retransmit will retry
    };

    let payload_off = payload_offset(local_ip);
    let payload_len = payload_len.min(MSS_MAX);
    let frame_len = payload_off + payload_len;
    let tcp_off = match local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN,
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN,
    } as u16;

    build_and_send_frame(frame_len, tcp_off, |frame| unsafe {
        // Walk chain bytes straight into the payload slot. This is
        // the "one memcpy, no intermediate buffer" property the
        // IOBuf chain design exists for — and on the direct-fill
        // path the cursor reads into the driver's TX pool slot
        // without further memcpy.
        if payload_len > 0 {
            let dst = core::slice::from_raw_parts_mut(
                frame.as_mut_ptr().add(payload_off),
                payload_len,
            );
            let n = cursor.read(dst);
            debug_assert_eq!(n, payload_len);
            let _ = n;
        }
        fill_tcp_frame_headers(
            frame, local_ip, dst_ip, dst_mac,
            src_port, dst_port, seq, ack, flags, window,
            payload_len,
        );
    });
}

fn send_rst(local_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, seq: u32, ack: u32) {
    send_segment(
        local_ip, dst_ip, src_port, dst_port,
        seq, ack, TCP_RST | TCP_ACK, 0, &[],
    );
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
    // TSO fast path: when the driver advertises TSOv4, hand the
    // whole chain to the driver in a single super-segment. The
    // device does the per-MSS split host-side AND computes per-
    // segment TCP/IP checksums (NEEDS_CSUM), so we save a
    // checksum-compute pass per segment whenever there are 2+
    // segments. The size cap matches the big-pool slot capacity;
    // payloads larger than that fall back to the per-MSS loop
    // (rare for HTTPS — the TLS layer pre-chunks at
    // PLAINTEXT_CHUNK = 16 KiB).
    //
    // The `total > mss` gate keeps single-MSS sends out of the
    // TSO descriptor path. Two reasons:
    //   1. TSO on a single segment is a no-op for the host — it
    //      emits one wire frame regardless. The descriptor-build
    //      cost (TSO+SEG pair vs plain pkt_desc) is pure
    //      overhead.
    //   2. More importantly: it gives `/health` and other small
    //      probe responses a path that doesn't depend on the
    //      driver's TSO descriptor emission being correct. When
    //      we're debugging a new TSO backend (gve in particular,
    //      where serial-port output is gated on GCE) this is
    //      what makes a `/diag-gve` HTTP endpoint reachable on
    //      the same VM that's failing TSO sends for /diagnostics.
    if uni_drivers::net::tso_available()
        && total > mss
        && payload_offset(c.local_ip) + total <= TSO_FRAME_BUF_LEN
    {
        send_super_segment_from_cursor(
            c.local_ip,
            c.remote_ip,
            c.local_port,
            c.remote_port,
            c.snd_nxt,
            c.rcv_nxt,
            TCP_ACK | TCP_PSH,
            c.rx_free() as u16,
            &mut cursor,
            total,
        );
        c.snd_nxt = c.snd_nxt.wrapping_add(total as u32);
    } else {
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
    }

    // Bytes are on the wire — release the cursor's borrow on the
    // chain and drain it. Drops fire in chain order (External
    // callbacks recycle NIC descriptors back to driver pools).
    drop(cursor);
    chain.clear();
    // Both paths (TSO super-segment + per-MSS loop) consume the
    // entire chain — bare-metal NIC TX never blocks under our
    // load model.
    Ok(total)
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

