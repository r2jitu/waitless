// State data: TCP flags, sizing constants, the on-the-wire header
// struct, the per-connection control block (`TcpConnection`), and the
// RFC 6298 retransmission methods that live on it. The actual
// per-core slot pool (`TcpPool`) and the 4-tuple hash live in
// `pool.rs`; the segment-assembly path (and the `send_segment` helper
// these methods call) lives in `send.rs`.

use crate::send::{SegmentMeta, send_segment};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::task::Waker;
use from_bytes::FromBytes;
use iobuf::IOBuf;
use types::IpAddr;

bitflags::bitflags! {
    pub(crate) struct TcpFlags: u8 {
        const FIN = 0x01;
        const SYN = 0x02;
        const RST = 0x04;
        const PSH = 0x08;
        const ACK = 0x10;
    }
}

pub(crate) const TCP_FIN: u8 = TcpFlags::FIN.bits();
pub(crate) const TCP_SYN: u8 = TcpFlags::SYN.bits();
pub(crate) const TCP_RST: u8 = TcpFlags::RST.bits();
pub(crate) const TCP_PSH: u8 = TcpFlags::PSH.bits();
pub(crate) const TCP_ACK: u8 = TcpFlags::ACK.bits();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
pub(crate) struct TcpHeader {
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) data_offset: u8,
    pub(crate) flags: u8,
    pub(crate) window: u16,
    pub(crate) checksum: u16,
    pub(crate) urgent: u16,
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
pub(crate) const SEGMENT_SIZE: u16 = 64;
/// Cap on segments per core. 1023 × 64 = 65472 slots, fits in a u16
/// slot index with `0xFFFF` reserved as the "null" / end-of-free-list
/// sentinel. Hitting this means 65k+ live conns on a single core,
/// which is several orders of magnitude past anything we can
/// realistically service — well before that, the per-core RX-inbox
/// and per-conn handler tasks will have starved out.
pub(crate) const MAX_SEGMENTS: usize = 1023;
pub(crate) const NULL_SLOT: u16 = 0xFFFF;
/// Per-conn RX ring depth. Sized to hold one max-size TLS 1.3
/// record fragment (`MAX_INNER_PLAINTEXT` = 16384 bytes) — when a
/// record arrives faster than the consumer polls `recv()`, the
/// whole fragment lands in the ring contiguously and the eventual
/// `recv()` reads it in one go. The earlier 8 KiB sizing would
/// spill any record over 8 KiB into a second `recv()` round-trip,
/// which mattered for large HTTPS request bodies and (some) H2
/// frames that pack into max-size records.
///
/// Trade: 16 KiB per live conn vs the old 8 KiB. On the
/// "thousands of idle keep-alive clients" shape this doubles
/// per-conn footprint; on the bench shapes we care about (close-
/// conn /health, short-lived TLS handshakes) the rings cycle
/// through the same small set of slots and total heap is bounded
/// by `MAX_SEGMENTS × SEGMENT_SIZE × 16 KiB`, dominated by the
/// other per-slot state.
///
/// `rcv_wnd: u16` still fits — 16384 < 65535. If we ever need to
/// go past 64 KiB we'd need to widen that field.
pub(crate) const RX_RING_BYTES: usize = 16384;
/// IPv4 max TCP segment payload: MTU(1500) - IP(20) - TCP(20) = 1460.
pub(crate) const MSS_V4: usize = 1460;
/// IPv6 max TCP segment payload: MTU(1500) - IPv6(40) - TCP(20) = 1440.
/// Sending a 1460-byte payload over a v6 conn produces a 1534-byte
/// Ethernet frame that the userspace bridge truncates (or drops),
/// silently corrupting any response that needs more than one
/// full-size segment. /health works on v6 because it fits in one
/// short segment; multi-part HTML responses (which need full-size
/// segments after the first chunk's headers) lose data starting at
/// the first 1460-byte payload — observable as Chrome's
/// ERR_SSL_PROTOCOL_ERROR over `https://localhost/`.
pub(crate) const MSS_V6: usize = 1440;
/// Conservative buffer cap that fits both. Used as the stack
/// allocation for `send_segment`'s on-stack TCP segment.
pub(crate) const MSS_MAX: usize = MSS_V4;

/// Pick the MSS for a given local IP family.
pub(crate) fn mss_for(local_ip: IpAddr) -> usize {
    match local_ip {
        IpAddr::V4(_) => MSS_V4,
        IpAddr::V6(_) => MSS_V6,
    }
}

// ─── RFC 6298 retransmission ─────────────────────────────────────────────────
//
// Every unacknowledged outbound byte is kept in a per-conn ring
// (`rtx_buf`) alongside a millisecond RTO deadline. A periodic tick
// (`on_tcp_tick`, driven by the net poll loop) retransmits the oldest
// unacked data once the deadline passes and doubles the RTO each time
// (§5.5 exponential backoff). Before this a lost *outbound* segment
// was never resent — an RFC 9293 MUST violation, and a real
// correctness gap on a lossy path.

/// Per-conn retransmit-ring capacity. Sized to hold a full TCP
/// receive window: `snd_wnd` is a `u16` (no RFC 7323 window scaling
/// negotiated), so the peer can never advertise more than 65535
/// bytes, and the RFC 5681 send path caps in-flight bytes at
/// `min(cwnd, rwnd)`. A 64 KiB ring therefore always covers the
/// whole unacked range `[snd_una, snd_nxt)` — which is what makes
/// `rtx_overflow` from a window that outgrew the ring structurally
/// impossible (the only residual `rtx_overflow` cause is an
/// `ensure_rtx_buf` allocation failure). Boxed + lazy like
/// `rx_ring`, so idle slots stay cheap.
pub(crate) const RTX_BUF_BYTES: usize = 65536;
/// Initial RTO before any RTT measurement (RFC 6298 §2.1), and the
/// floor every computed RTO is clamped up to (§2.4 — round a sub-1 s
/// estimate up to 1 s).
pub(crate) const RTO_INITIAL_MS: u32 = 1000;
/// RTT-estimator gain `K` — RTO = SRTT + K·RTTVAR (RFC 6298 §2.3).
pub(crate) const RTO_K: u32 = 4;
/// RTO ceiling — the §5.5 exponential backoff clamps here. RFC 6298
/// §2.5 requires the bound to be at least 60 s.
pub(crate) const RTO_MAX_MS: u32 = 60_000;
/// Retransmissions of one segment before the connection is declared
/// dead and torn down. With 1+2+4+…+60 s (capped) backoff this is
/// ~100 s of total wait — in line with the RFC 9293 §3.8.3 "R2"
/// lower bound for aborting a broken connection.
pub(crate) const RTX_MAX_RETRIES: u8 = 8;

// ─── Connection-lifecycle timers ─────────────────────────────────────────────
//
// `close()`'s FIN occupies one sequence number but carries no payload,
// so it is not held in the RFC 6298 data ring (`rtx_buf`). A dedicated
// timer (`lifecycle_deadline_ms` + `fin_retx_count`) retransmits the
// FIN in `FinWait1` (active close) and `LastAck` (passive close) until
// the peer acknowledges it or the bounded retry count runs out. Before
// this a single dropped FIN stranded the connection until the peer's
// keepalive fired — invisible on a LAN, an availability bug on a WAN.

/// FIN retransmissions before a half-closed connection (`FinWait1`
/// active close / `LastAck` passive close) is forced shut — the
/// RFC 9293 §3.8.3 "give up on a dead peer" bound. Five retransmits
/// with exponential backoff off the RTO estimate (~63 s total at the
/// 1 s initial RTO) before teardown.
pub(crate) const FIN_RETX_MAX: u8 = 5;
/// Zero-window probes (RFC 9293 §3.8.6.1) before a connection whose
/// peer keeps its receive window shut is aborted — a peer that never
/// reopens its window across this many exponentially-backed-off
/// probes is treated as dead. Matches `RTX_MAX_RETRIES`.
pub(crate) const PERSIST_MAX_PROBES: u8 = 8;
/// `TimeWait` hold time: 2×MSL (RFC 9293 §3.10.7.4) with MSL taken as
/// 30 s. After an active close completes the TCB lingers here so a
/// delayed duplicate from the old 4-tuple cannot be delivered into a
/// new connection that reuses the ports, and so a retransmitted peer
/// FIN still finds a TCB to re-acknowledge.
pub(crate) const TIME_WAIT_MS: u64 = 60_000;

/// One entry in the per-conn retransmit queue — the payload bytes of
/// a single outbound TCP segment plus the RFC 6298 / 9293 bookkeeping
/// needed to retransmit it on RTO expiry. The IOBuf is owned (heap-
/// resident), independent of any NIC-side reference; a future commit
/// will replace this with refcount-shared storage so the same IOBuf
/// is alive in the queue while the wire-DMA is in flight, without an
/// insertion memcpy.
//
// `first_tx_ms` and `tx_count` are read by the RTO path in a follow-up
// commit; allow them as dead until then so this can land as scaffolding.
#[allow(dead_code)]
pub(crate) struct RtxEntry {
    /// Owned IOBuf carrying this segment's payload bytes. `IOBuf::data()`
    /// reads the bytes to retransmit; `narrow` advances the visible
    /// window on a partial-ACK of the head entry.
    pub(crate) iobuf: IOBuf,
    /// First sequence number this entry covers (snd_una when this
    /// was the head of in-flight).
    pub(crate) seq_start: u32,
    /// Payload byte count — `iobuf.data().len()` post-narrow. Caches
    /// the length so the cwnd-paced bytes-in-flight sum is O(1).
    pub(crate) len: u16,
    /// Wall-clock ms of the first transmission of these bytes.
    /// Anchors RFC 6298 RTT sampling for the head-of-queue entry
    /// (subject to Karn's rule via `tx_count`).
    pub(crate) first_tx_ms: u64,
    /// Number of transmissions this entry has been through. >0 means
    /// retransmitted (Karn's rule: don't sample RTT from this entry).
    pub(crate) tx_count: u8,
}

pub struct TcpConnection {
    pub state: TcpState,
    /// Peer's IP — IPv4 or IPv6. Used as the destination of every
    /// outbound segment AND as part of the per-conn lookup key.
    pub(crate) remote_ip: IpAddr,
    /// Our IP that the peer addressed when they SYN'd. Recorded so
    /// outbound segments use the matching pseudo-header (different
    /// for v4 vs v6) and so we reply from whichever of our
    /// addresses the peer expects to see.
    pub(crate) local_ip: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) remote_port: u16,
    pub(crate) snd_nxt: u32,
    pub(crate) snd_una: u32,
    /// Peer's advertised receive window (RFC 9293 SND.WND), bytes —
    /// the far end's free buffer space, and the receiver-side half
    /// of the RFC 5681 send window `min(cwnd, rwnd)`. Refreshed from
    /// `SEG.WND` only when the `snd_wl1`/`snd_wl2` check accepts the
    /// segment. A raw `u16` (no RFC 7323 window scaling), so it
    /// never exceeds 65535.
    pub(crate) snd_wnd: u16,
    /// RFC 9293 SND.WL1 — the `SEG.SEQ` of the segment that last
    /// updated `snd_wnd`. Guards against a reordered segment
    /// installing a stale window.
    pub(crate) snd_wl1: u32,
    /// RFC 9293 SND.WL2 — the `SEG.ACK` of the segment that last
    /// updated `snd_wnd`. With `snd_wl1` it totally orders window
    /// updates, so a retransmitted segment can't regress the window.
    pub(crate) snd_wl2: u32,
    pub(crate) rcv_nxt: u32,
    pub(crate) rcv_wnd: u16,
    /// Per-conn RX ring buffer. Heap-allocated once at
    /// `TcpConnection::alloc_storage` (lazily on first SYN that
    /// lands on a fresh slot) and reused across SYN/close cycles.
    /// `tcp_receive` writes payload bytes here via `deliver_payload`;
    /// `async_recv` drains via `rx_ring_pop`.
    ///
    /// Inline `[u8; RX_RING_BYTES]` would bloat the per-slot
    /// footprint by 8 KiB × every slot in the per-core pool; with
    /// the segmented-pool growth ceiling at MAX_SEGMENTS × SEGMENT_SIZE
    /// that's ~512 MiB worst-case. Boxing the ring keeps idle
    /// segments cheap and only materialises 8 KiB per live conn.
    pub(crate) rx_ring: Option<Box<[u8; RX_RING_BYTES]>>,
    pub(crate) rx_head: u16,
    pub(crate) rx_tail: u16,
    /// Bytes currently in `rx_ring`. Cached so the per-segment
    /// rcv_wnd calc doesn't have to (head - tail) modulo every time.
    pub(crate) rx_used: u16,
    /// Set by `set_chunk_buf_slot` when a parked `RecvChunk` future
    /// wants the next inbound payload as an owned `IOBuf` rather
    /// than copied into a user buffer. While `true`, `tcp_receive`
    /// *moves* the next in-sequence single-part segment's IOBuf
    /// into `pending_chunk` (zero copy) instead of pushing its
    /// bytes through `rx_ring`. Cleared the moment a chunk is
    /// stashed, by `clear_chunk_buf_slot` (cancel-safety), or by a
    /// slot reset. The whole chunk fast path is gated on this flag,
    /// so a conn with no `recv_chunk` consumer behaves exactly as
    /// before.
    pub(crate) chunk_wanted: bool,
    /// The IOBuf handed to a `recv_chunk` consumer, produced by
    /// `tcp_receive`'s zero-copy stash and drained by
    /// `do_recv_chunk`. Holds at most one buffer — the stated
    /// "≤ 1 outstanding IOBuf per TcpStream" invariant, which the
    /// `RecvChunkGuard<'_>` borrow also enforces at the type level.
    /// Only ever stashed when `rx_ring` is empty, so a later ring
    /// push can never make `pending_chunk` the *newer* bytes:
    /// `do_recv_chunk` drains it strictly before the ring.
    pub(crate) pending_chunk: Option<IOBuf>,
    pub(crate) listener_port: u16,
    pub(crate) accepted: bool,
    /// Incremented every time `free_connection` resets this slot, so
    /// a stale async handle that survived a close+reuse sees a
    /// generation mismatch on its next hook call and short-circuits
    /// to the "closed" path. Preserved across reset — `new()` does
    /// NOT reset it; `free_connection` bumps it explicitly.
    pub(crate) generation: u16,
    /// Parked `TcpRecv` waker. Set by `register_recv_waker` on the
    /// owning core; woken when data lands in the ring or the
    /// peer closes. Per-core ownership — no lock needed.
    pub(crate) recv_waker: Option<Waker>,
    /// Parked `TcpSendChain` waker. Set by `register_send_waker` when a
    /// send stalls on a closed window (`min(cwnd, rwnd)` fully
    /// consumed); woken by `tcp_receive` when an ACK reopens the
    /// window, and by `free_connection` on teardown. Per-core
    /// ownership — no lock needed.
    pub(crate) send_waker: Option<Waker>,
    /// RFC 6298 retransmit ring — the unacknowledged outbound bytes,
    /// mirroring the wire range `[snd_una, snd_nxt)`. Heap-boxed and
    /// lazily allocated on the first buffered send, then reused across
    /// SYN/close cycles like `rx_ring`. `None` until the conn first
    /// sends data.
    pub(crate) rtx_buf: Option<Box<[u8; RTX_BUF_BYTES]>>,
    /// Ring index of the byte at `snd_una`.
    pub(crate) rtx_head: u16,
    /// Bytes currently buffered. Equals `snd_nxt - snd_una` while
    /// retransmit coverage holds; see `rtx_overflow`.
    pub(crate) rtx_len: u16,
    /// Set when `rtx_buf` failed to allocate: the ring cannot cover
    /// `[snd_una, snd_nxt)`, so the RTO timer is held off until the
    /// peer's ACKs drain the window back to empty, at which point
    /// `rtx_on_ack` clears this and coverage resumes. The unacked
    /// window outgrowing the ring is no longer a cause — the RFC 5681
    /// send window bounds in-flight bytes at `min(cwnd, rwnd)`, which
    /// the 64 KiB ring always holds; an `ensure_rtx_buf` allocation
    /// failure is the sole residual trigger.
    pub(crate) rtx_overflow: bool,
    /// IOBuf-backed retransmit queue — the new path that replaces
    /// `rtx_buf`. Each entry holds one outbound segment's payload as
    /// an owned IOBuf; the queue mirrors the wire range
    /// `[snd_una, snd_nxt)` one segment at a time, instead of one
    /// flat 64 KiB ring. Allocation is preserved across SYN/close
    /// cycles via `reset_preserving` — the entries drop (returning
    /// their IOBufs) but the deque's capacity stays.
    pub(crate) rtx_queue: VecDeque<RtxEntry>,
    /// Cached sum of `entry.len` across `rtx_queue` — the
    /// bytes-in-flight count the cwnd-paced send window reads. O(1)
    /// per send/ACK instead of summing the queue.
    pub(crate) rtx_bytes_in_flight: u32,
    /// Set when a `rtx_queue` push failed to grow the deque — the OOM
    /// equivalent of the old `rtx_overflow` flag. Coverage is
    /// suspended until ACKs drain the in-flight window; `rtx_on_ack`
    /// clears this once `snd_una == snd_nxt`. The "window outgrew
    /// ring" half of `rtx_overflow` is structurally impossible for the
    /// queue (no fixed capacity), so this flag is OOM-only.
    pub(crate) rtx_alloc_failed: bool,
    /// Current retransmission timeout, milliseconds. Doubles on each
    /// RTO expiry (§5.5); re-initialised when new data is ACK'd.
    pub(crate) rto_ms: u32,
    /// Absolute deadline (`kernel_core::clock::now_ms`) at which the
    /// oldest unacked segment is retransmitted. 0 = timer disarmed.
    pub(crate) rtx_deadline_ms: u64,
    /// Consecutive RTO expiries for the oldest segment without an
    /// intervening ACK — the §5.5 backoff exponent, and the
    /// give-up counter (`RTX_MAX_RETRIES`).
    pub(crate) rtx_backoff: u8,
    /// RFC 6298 §2 smoothed round-trip time, milliseconds. 0 until
    /// the first measurement (see `rtt_seeded`).
    pub(crate) srtt_ms: u32,
    /// RFC 6298 §2 round-trip-time variation, milliseconds.
    pub(crate) rttvar_ms: u32,
    /// False until `sample_rtt` has folded in a first measurement —
    /// selects the §2.2 (seed) vs §2.3 (EWMA) update.
    pub(crate) rtt_seeded: bool,
    /// RTT-sample anchor: the send timestamp and the sequence number
    /// just past the timed bytes. At most one sample is outstanding
    /// per RTT (RFC 6298 §3); the ACK covering `rtt_anchor_seq`
    /// yields the measurement `R`.
    pub(crate) rtt_anchor_ms: u64,
    pub(crate) rtt_anchor_seq: u32,
    /// True while an RTT sample is outstanding. Cleared when the
    /// sample is taken, and on any retransmission — Karn's algorithm
    /// forbids deriving an RTT from a segment that was retransmitted.
    pub(crate) rtt_anchor_active: bool,
    /// Absolute deadline (`kernel_core::clock::now_ms`) for the next
    /// connection-lifecycle timer action — the FIN retransmit in
    /// `FinWait1` (active close) and `LastAck` (passive close). 0 =
    /// disarmed. Separate from `rtx_deadline_ms` (RFC 6298 data
    /// retransmission): a connection closing with still-unacked data
    /// has both timers armed at once.
    pub(crate) lifecycle_deadline_ms: u64,
    /// Consecutive FIN retransmissions with no acknowledgement — the
    /// exponential-backoff exponent and the `FIN_RETX_MAX` give-up
    /// counter. Meaningful only while `lifecycle_deadline_ms` is armed
    /// in `FinWait1` / `LastAck`.
    pub(crate) fin_retx_count: u8,
    /// Absolute deadline (`kernel_core::clock::now_ms`) for the next
    /// RFC 9293 §3.8.6.1 zero-window probe. Armed by
    /// `async_try_send_chain` when a send is blocked by a zero
    /// advertised window; disarmed when an ACK reopens the window.
    /// 0 = disarmed.
    pub(crate) persist_deadline_ms: u64,
    /// Consecutive zero-window probes with no window reopening — the
    /// exponential-backoff exponent and the `PERSIST_MAX_PROBES`
    /// give-up counter.
    pub(crate) persist_backoff: u8,
    /// RFC 5681 congestion window, bytes — the controller's estimate
    /// of how much unacknowledged data the path will accept. Grows on
    /// ACKs (slow start, then congestion avoidance) and collapses to
    /// one segment on an RTO. 0 until `congestion_init` runs at the
    /// SYN. The send path paces against it: `usable_window()` caps
    /// in-flight bytes at `min(cwnd, rwnd)`.
    pub(crate) cwnd: u32,
    /// RFC 5681 slow-start threshold, bytes. While `cwnd < ssthresh`
    /// the controller is in slow start (exponential growth); at or
    /// above it, congestion avoidance (linear). Starts effectively
    /// infinite and drops to half the flight size on loss.
    pub(crate) ssthresh: u32,
    /// Consecutive duplicate ACKs observed (RFC 5681 §3.2). The third
    /// triggers fast retransmit; further duplicates while in fast
    /// recovery inflate `cwnd`. Reset by any ACK of new data.
    pub(crate) dup_acks: u8,
    /// True between the fast-retransmit trigger and the recovering
    /// ACK — RFC 5681 §3.2 fast recovery. While set, extra duplicate
    /// ACKs inflate `cwnd`; the first new-data ACK deflates it back
    /// to `ssthresh` and clears this.
    pub(crate) in_fast_recovery: bool,
    /// Free-list link. When this slot is on the free list (state ==
    /// Closed AND the slot has been returned to the pool), this
    /// holds the index of the next free slot, or `NULL_SLOT` for
    /// end-of-list. Untouched while the slot is live; on `free` the
    /// pool overwrites it; on `alloc` the pool reads it once.
    pub(crate) next_free: u16,

    /// This slot's own index in the per-core pool. Stamped once at
    /// segment-init time (`TcpPool::grow_one`) and never mutated.
    /// Lets per-conn methods that arm a timer (`arm_for_tick`) push
    /// onto the per-core armed-list without needing a separate
    /// `(core, slot)` parameter at every call site. Preserved across
    /// reset (`free_connection` and the alloc path both leave it
    /// alone — `TcpConnection::new()` defaults it to 0 but it's
    /// overwritten the moment a segment is published).
    pub(crate) slot_index: u16,

    /// Intrusive next-link in the per-core "armed timer" list. The
    /// list contains slots whose `rtx_deadline_ms` /
    /// `persist_deadline_ms` / `lifecycle_deadline_ms` is non-zero
    /// (eligible for `on_tcp_tick`'s timer service); `on_tcp_tick`
    /// walks the list instead of scanning the full pool. `NULL_SLOT`
    /// = end-of-list. Meaningful only while `tick_in_list == true`;
    /// junk otherwise.
    pub(crate) tick_next: u16,

    /// `true` while this slot is linked into the per-core armed
    /// list. Membership guard so repeated `arm_for_tick` calls don't
    /// double-link. Cleared by `on_tcp_tick` when the slot's
    /// deadlines are all zero (lazy unlink) and on `free_connection`
    /// reset.
    pub(crate) tick_in_list: bool,
}

impl TcpConnection {
    pub(crate) const fn new() -> Self {
        TcpConnection {
            state: TcpState::Closed,
            remote_ip: IpAddr::V4_ANY,
            local_ip: IpAddr::V4_ANY,
            local_port: 0,
            remote_port: 0,
            snd_nxt: 0,
            snd_una: 0,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            rcv_nxt: 0,
            rcv_wnd: RX_RING_BYTES as u16,
            rx_ring: None,
            rx_head: 0,
            rx_tail: 0,
            rx_used: 0,
            chunk_wanted: false,
            pending_chunk: None,
            listener_port: 0,
            accepted: false,
            generation: 0,
            recv_waker: None,
            send_waker: None,
            rtx_buf: None,
            rtx_head: 0,
            rtx_len: 0,
            rtx_overflow: false,
            rtx_queue: VecDeque::new(),
            rtx_bytes_in_flight: 0,
            rtx_alloc_failed: false,
            rto_ms: RTO_INITIAL_MS,
            rtx_deadline_ms: 0,
            rtx_backoff: 0,
            srtt_ms: 0,
            rttvar_ms: 0,
            rtt_seeded: false,
            rtt_anchor_ms: 0,
            rtt_anchor_seq: 0,
            rtt_anchor_active: false,
            lifecycle_deadline_ms: 0,
            fin_retx_count: 0,
            persist_deadline_ms: 0,
            persist_backoff: 0,
            cwnd: 0,
            ssthresh: 0,
            dup_acks: 0,
            in_fast_recovery: false,
            next_free: NULL_SLOT,
            slot_index: 0,
            tick_next: NULL_SLOT,
            tick_in_list: false,
        }
    }

    /// Reset to a fresh `TcpConnection` while preserving the
    /// per-slot identity (`slot_index`), the bumped generation
    /// counter, and the lazily-allocated per-conn heap buffers
    /// (`rx_ring`, `rtx_buf`). Re-allocating the rings on every
    /// reset would cost a `Box::new([0; …])` per accept on the
    /// close-conn /health hot path — preserving them across the
    /// SYN/close cycle keeps the steady-state hot path heap-free.
    /// Used by `alloc_connection` and `free_connection`; both call
    /// sites used to inline the same `let preserved_… = …; *c =
    /// new(); restore` block.
    pub(crate) fn reset_preserving(&mut self, next_gen: u16) {
        let ring = self.rx_ring.take();
        let rtx = self.rtx_buf.take();
        // Drop the entries (their IOBufs return to the heap) but keep
        // the deque's backing allocation across the SYN/close cycle —
        // same "reuse capacity, lose contents" shape as `rx_ring` and
        // `rtx_buf`. `VecDeque::clear` does exactly this.
        let mut rtx_queue = core::mem::take(&mut self.rtx_queue);
        rtx_queue.clear();
        let slot = self.slot_index;
        *self = TcpConnection::new();
        self.generation = next_gen;
        self.rx_ring = ring;
        self.rtx_buf = rtx;
        self.rtx_queue = rtx_queue;
        self.slot_index = slot;
    }

    /// Link into the per-core armed-timer list; see
    /// [`pool::register_armed_slot`].
    #[inline]
    pub(crate) fn arm_for_tick(&mut self) {
        crate::pool::register_armed_slot(self);
    }

    /// Lazy-allocate the per-conn RX ring on the first SYN that
    /// lands on this slot. Subsequent close+reuse cycles keep the
    /// allocation (the pool's free-list bumps `generation` but
    /// doesn't touch `rx_ring`); see `free_connection` for the
    /// reset-preserve dance.
    pub(crate) fn ensure_rx_ring(&mut self) -> bool {
        if self.rx_ring.is_some() {
            return true;
        }
        // The ring is reused across SYN/close cycles. Box::new
        // on a [u8; 8192] allocates 8 KiB on the global heap;
        // OOM at SYN time refuses the connection — same admission-
        // gate behaviour the previous `VecDeque<IOBuf>` design had.
        let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        if v.try_reserve_exact(RX_RING_BYTES).is_err() {
            return false;
        }
        v.resize(RX_RING_BYTES, 0);
        let boxed: Box<[u8]> = v.into_boxed_slice();
        // SAFETY: we just resized to RX_RING_BYTES, so the slice
        // length matches the array's. into_boxed_slice() returns a
        // Box<[u8]>; we cast to Box<[u8; RX_RING_BYTES]>.
        let ptr = Box::into_raw(boxed) as *mut [u8; RX_RING_BYTES];
        self.rx_ring = Some(unsafe { Box::from_raw(ptr) });
        true
    }

    #[inline]
    pub(crate) fn rx_used(&self) -> usize {
        self.rx_used as usize
    }

    #[inline]
    pub(crate) fn rx_free(&self) -> usize {
        // -1 reserves one slot — keeps head==tail unambiguous as
        // "empty" without forcing a separate "full" flag. Matches
        // the historic behaviour of the IOBuf-list version.
        (RX_RING_BYTES - 1).saturating_sub(self.rx_used as usize)
    }

    /// Write `payload` bytes into the conn's RX ring. Truncates to
    /// the window's free space; the trimmed suffix is dropped (the
    /// peer will retransmit once `rcv_wnd` opens).
    pub(crate) fn rx_ring_push(&mut self, payload: &[u8]) -> usize {
        if payload.is_empty() {
            return 0;
        }
        let free = self.rx_free();
        if free == 0 {
            return 0;
        }
        let n = payload.len().min(free);
        let ring = match self.rx_ring.as_mut() {
            Some(r) => r,
            None => return 0,
        };
        let tail = self.rx_tail as usize;
        if tail + n <= RX_RING_BYTES {
            ring[tail..tail + n].copy_from_slice(&payload[..n]);
        } else {
            let first = RX_RING_BYTES - tail;
            ring[tail..].copy_from_slice(&payload[..first]);
            ring[..n - first].copy_from_slice(&payload[first..n]);
        }
        self.rx_tail = ((tail + n) % RX_RING_BYTES) as u16;
        self.rx_used += n as u16;
        n
    }

    /// Deliver an in-sequence TCP payload to the consumer by
    /// pushing it into the per-conn `rx_ring`; the next `recv` /
    /// `recv_chunk` drains the ring (or, for `recv_chunk` on a
    /// `chunk_wanted` conn, `tcp_receive` stashes the device buffer
    /// into `pending_chunk` before this is called). Returns the
    /// byte count the ring absorbed — `rcv_nxt` advances by this
    /// much, and the segment trim happens at the caller.
    pub(crate) fn deliver_payload(&mut self, payload: &[u8]) -> usize {
        self.rx_ring_push(payload)
    }

    /// Drain bytes from the ring into `out`. Returns the number
    /// of bytes written, capped at `min(rx_used, out.len())` —
    /// any excess stays in the ring for the next `recv` call.
    pub(crate) fn rx_pop(&mut self, out: &mut [u8]) -> usize {
        if out.is_empty() || self.rx_used == 0 {
            return 0;
        }
        let ring = match self.rx_ring.as_mut() {
            Some(r) => r,
            None => return 0,
        };
        let take = out.len().min(self.rx_used as usize);
        let head = self.rx_head as usize;
        if head + take <= RX_RING_BYTES {
            out[..take].copy_from_slice(&ring[head..head + take]);
        } else {
            let first = RX_RING_BYTES - head;
            out[..first].copy_from_slice(&ring[head..]);
            out[first..take].copy_from_slice(&ring[..take - first]);
        }
        self.rx_head = ((head + take) % RX_RING_BYTES) as u16;
        self.rx_used -= take as u16;
        // Draining the ring reopened the receive window. If the peer
        // is SWS-stalled on the old sub-MSS window, tell it now —
        // otherwise it waits for its persist timer.
        self.maybe_send_window_update();
        take
    }

    /// Receiver-side silly-window-syndrome avoidance (RFC 1122
    /// §4.2.2.16 / RFC 813).
    ///
    /// `rcv_wnd` — the window last advertised to the peer — is
    /// normally refreshed on every ACK we send in response to an
    /// inbound segment (see the `rcv_wnd = rx_free()` in
    /// `tcp_receive`). But a peer that fills our `rx_ring`, sees the
    /// resulting sub-MSS window, and then — correctly, under its own
    /// sender-side SWS-avoidance — stops sending leaves us with no
    /// inbound segment to ACK. Once the application drains the ring
    /// the window has reopened, but the peer is never told: it
    /// stalls until its own persist timer fires. Against QEMU's
    /// SLIRP that timer is ~5 s, which collapsed `upload_32k` to
    /// ~3 req/s (a 32 KiB upload overruns the 16 KiB ring, so every
    /// upload past 16 KiB ate one persist-timer stall).
    ///
    /// Fix: when a drain lifts the window back across the one-MSS
    /// boundary, send a standalone window-update ACK. The
    /// `rcv_wnd < mss` guard fires this at most once per ring-full
    /// episode — in steady flow `rcv_wnd` stays well above an MSS
    /// (kept fresh by data-triggered ACKs) so this is a no-op.
    fn maybe_send_window_update(&mut self) {
        if self.state != TcpState::Established {
            return;
        }
        let mss = mss_for(self.local_ip) as u16;
        let free = self.rx_free() as u16;
        // Only the stall case: the last window we advertised was too
        // small for the peer to send a full segment (it may be
        // SWS-stalled), and the drain has now opened at least an MSS
        // of room — enough that advertising it actually unblocks the
        // peer.
        if self.rcv_wnd < mss && free >= mss {
            self.rcv_wnd = free;
            send_segment(
                &SegmentMeta {
                    local_ip: self.local_ip,
                    dst_ip: self.remote_ip,
                    src_port: self.local_port,
                    dst_port: self.remote_port,
                    seq: self.snd_nxt,
                    ack: self.rcv_nxt,
                    flags: TCP_ACK,
                    window: free,
                },
                &[],
            );
        }
    }

    // ─── RFC 6298 retransmission ─────────────────────────────────────────

    /// Push one outbound segment's payload + bookkeeping onto the
    /// per-conn retransmit queue. `iobuf` is `into_owned()`'d at
    /// insertion so the queue's storage is heap-resident and
    /// independent of any NIC-side reference. Returns `false` on a
    /// `try_reserve` failure — caller then suspends coverage via
    /// `rtx_alloc_failed = true` (the OOM equivalent of the old
    /// `rtx_overflow` flag). Arms the RTO timer if the queue was
    /// empty before this push (RFC 6298 §5.1) and seeds the RTT
    /// anchor (§3) if no sample is outstanding.
    ///
    /// Currently dead code — wired into the send path in a follow-up
    /// commit. The accompanying unit tests exercise push/ack/narrow
    /// on a fresh `TcpConnection` to lock in the queue's behaviour
    /// before the send path starts driving it.
    #[allow(dead_code)]
    pub(crate) fn rtx_push(
        &mut self,
        iobuf: IOBuf,
        seq_start: u32,
        len: u16,
        now_ms: u64,
    ) -> bool {
        if self.rtx_queue.try_reserve(1).is_err() {
            self.rtx_alloc_failed = true;
            return false;
        }
        let was_empty = self.rtx_queue.is_empty();
        self.rtx_queue.push_back(RtxEntry {
            iobuf: iobuf.into_owned(),
            seq_start,
            len,
            first_tx_ms: now_ms,
            tx_count: 1,
        });
        self.rtx_bytes_in_flight = self.rtx_bytes_in_flight.saturating_add(len as u32);
        if was_empty && self.rtx_deadline_ms == 0 {
            self.arm_rtx();
        }
        if !self.rtt_anchor_active {
            self.rtt_anchor_active = true;
            self.rtt_anchor_seq = seq_start.wrapping_add(len as u32);
            self.rtt_anchor_ms = now_ms;
        }
        true
    }

    /// Fold an inbound ACK of `ack_num` into the retransmit queue.
    /// Pops fully-acked entries from the head and narrows a
    /// partially-acked head entry forward by the consumed prefix.
    /// Returns the byte count this ACK retired from the queue.
    /// Does NOT itself touch `snd_una`, the RTO deadline, or the
    /// congestion controller — the caller folds those in.
    ///
    /// Currently dead code — wired into the ACK path in a follow-up
    /// commit.
    #[allow(dead_code)]
    pub(crate) fn rtx_ack(&mut self, ack_num: u32, _now_ms: u64) -> usize {
        let mut acked = 0usize;
        while let Some(head) = self.rtx_queue.front_mut() {
            let head_end = head.seq_start.wrapping_add(head.len as u32);
            // Fully acked: `ack_num` covers the whole entry.
            if !seq_lt(ack_num, head_end) {
                acked += head.len as usize;
                self.rtx_bytes_in_flight =
                    self.rtx_bytes_in_flight.saturating_sub(head.len as u32);
                self.rtx_queue.pop_front();
                continue;
            }
            // Partial ack: `ack_num` is strictly inside the head entry
            // (we already know `ack_num < head_end`; check it's also
            // strictly past `seq_start`).
            if seq_lt(head.seq_start, ack_num) {
                let consumed = ack_num.wrapping_sub(head.seq_start) as usize;
                // `consume` advances the IOBuf's visible window past
                // the acked prefix — zero copy, just an offset bump.
                if head.iobuf.consume(consumed).is_ok() {
                    head.seq_start = ack_num;
                    head.len = head.len.saturating_sub(consumed as u16);
                    self.rtx_bytes_in_flight =
                        self.rtx_bytes_in_flight.saturating_sub(consumed as u32);
                    acked += consumed;
                }
            }
            break;
        }
        acked
    }

    /// Mutable accessor for the head of the retransmit queue —
    /// used by the RTO path to reconstruct the retransmitted segment
    /// from the existing IOBuf bytes (zero-copy retransmit) and to
    /// bump `tx_count` for Karn's rule.
    ///
    /// Currently dead code — wired into the RTO path in a follow-up
    /// commit.
    #[allow(dead_code)]
    pub(crate) fn rtx_head_for_retx(&mut self) -> Option<&mut RtxEntry> {
        self.rtx_queue.front_mut()
    }

    /// Lazy-allocate the per-conn retransmit ring on the first
    /// buffered send. Reused across SYN/close cycles like `rx_ring`
    /// (the pool free-list dance preserves it). Returns `false` on
    /// OOM — the caller then suspends retransmit coverage.
    pub(crate) fn ensure_rtx_buf(&mut self) -> bool {
        if self.rtx_buf.is_some() {
            return true;
        }
        let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        if v.try_reserve_exact(RTX_BUF_BYTES).is_err() {
            return false;
        }
        v.resize(RTX_BUF_BYTES, 0);
        let boxed: Box<[u8]> = v.into_boxed_slice();
        // SAFETY: just resized to RTX_BUF_BYTES, so the slice length
        // matches the array type we cast the Box to.
        let ptr = Box::into_raw(boxed) as *mut [u8; RTX_BUF_BYTES];
        self.rtx_buf = Some(unsafe { Box::from_raw(ptr) });
        true
    }

    /// Arm the retransmission timer `rto_ms` ahead of now.
    pub(crate) fn arm_rtx(&mut self) {
        self.rtx_deadline_ms = kernel_core::clock::now_ms() + self.rto_ms as u64;
        self.arm_for_tick();
    }

    /// Fold a round-trip-time measurement `r` (milliseconds) into the
    /// RFC 6298 §2 estimator. §2.2 seeds SRTT/RTTVAR from the first
    /// sample; §2.3 is the EWMA thereafter — RTTVAR is updated first,
    /// against the *old* SRTT (alpha = 1/8, beta = 1/4).
    pub(crate) fn sample_rtt(&mut self, r: u32) {
        // §2.4: a measurement below the clock granularity (G = 1 ms)
        // is floored at G.
        let r = r.max(1);
        if !self.rtt_seeded {
            self.srtt_ms = r;
            self.rttvar_ms = r / 2;
            self.rtt_seeded = true;
        } else {
            let delta = self.srtt_ms.abs_diff(r);
            // RTTVAR ← (1 - 1/4)·RTTVAR + 1/4·|SRTT - R|
            self.rttvar_ms = self.rttvar_ms - (self.rttvar_ms >> 2) + (delta >> 2);
            // SRTT ← (1 - 1/8)·SRTT + 1/8·R
            self.srtt_ms = self.srtt_ms - (self.srtt_ms >> 3) + (r >> 3);
        }
    }

    /// The RTO implied by the current estimator state (RFC 6298
    /// §2.2 / §2.3): `SRTT + max(G, K·RTTVAR)`, clamped to the
    /// [1 s, 60 s] bounds (§2.4 / §2.5). Before any measurement this
    /// is the §2.1 initial 1 s.
    pub(crate) fn estimated_rto(&self) -> u32 {
        if !self.rtt_seeded {
            return RTO_INITIAL_MS;
        }
        let spread = 1u32.max(self.rttvar_ms.saturating_mul(RTO_K));
        self.srtt_ms
            .saturating_add(spread)
            .clamp(RTO_INITIAL_MS, RTO_MAX_MS)
    }

    /// Shared core of the two retransmit-retain entry points
    /// (`rtx_on_data_sent` for the chain path, `rtx_on_data_sent_slice`
    /// for the TSO path). Reserves `total` bytes at the tail of the
    /// retransmit ring and invokes `write` with each (possibly
    /// wrapped) destination slice in order — the caller fills them
    /// from a chain cursor or a contiguous slice. Handles the
    /// allocation guard, the ring wrap, `rtx_len`, the RFC 6298 §5.1
    /// RTO timer, and the §3 RTT anchor.
    fn rtx_retain(&mut self, total: usize, mut write: impl FnMut(&mut [u8])) {
        if total == 0 || self.rtx_overflow {
            return; // nothing to retain, or coverage already suspended
        }
        if !self.ensure_rtx_buf() {
            // The retransmit ring could not be allocated. Suspend
            // retransmit coverage until `snd_una` catches `snd_nxt`;
            // `rtx_on_ack` clears the flag once the window drains.
            // Heap exhaustion — genuinely unexpected, so trace it.
            crate::diag::COUNTERS.rtx_buf_oom.bump();
            self.rtx_overflow = true;
            self.rtx_head = 0;
            self.rtx_len = 0;
            self.rtx_deadline_ms = 0;
            return;
        }
        // A window outgrowing the ring is structurally impossible: the
        // RFC 5681 send path caps in-flight bytes at `min(cwnd, rwnd)`,
        // `rwnd` is a `u16` (no window scaling), and `RTX_BUF_BYTES` is
        // 64 KiB — so `rtx_len + total` (the post-send flight size)
        // never exceeds the ring. Assert it rather than branch on it.
        debug_assert!(
            self.rtx_len as usize + total <= RTX_BUF_BYTES,
            "in-flight bytes outgrew the retransmit ring — the send \
             window should have bounded them at min(cwnd, rwnd)",
        );
        let tail = (self.rtx_head as usize + self.rtx_len as usize) % RTX_BUF_BYTES;
        let buf = self.rtx_buf.as_mut().expect("ensure_rtx_buf succeeded");
        if tail + total <= RTX_BUF_BYTES {
            write(&mut buf[tail..tail + total]);
        } else {
            let first = RTX_BUF_BYTES - tail;
            write(&mut buf[tail..]);
            write(&mut buf[..total - first]);
        }
        self.rtx_len += total as u16;
        // §5.1: start the timer if it is not already running.
        if self.rtx_deadline_ms == 0 {
            self.arm_rtx();
        }
        // RFC 6298 §3: take at most one RTT sample per RTT. Anchor on
        // the sequence number just past this send (`snd_nxt` already
        // advanced); the ACK covering it yields the measurement.
        if !self.rtt_anchor_active {
            self.rtt_anchor_active = true;
            self.rtt_anchor_seq = self.snd_nxt;
            self.rtt_anchor_ms = kernel_core::clock::now_ms();
        }
    }

    /// Retain the `total` just-sent bytes — read from a fresh cursor
    /// over the chain `async_try_send_chain` already transmitted — so
    /// the RTO timer can retransmit them, and start the timer if it
    /// is not already running (RFC 6298 §5.1).
    pub(crate) fn rtx_on_data_sent(&mut self, total: usize, cur: &mut iobuf::Cursor<'_>) {
        self.rtx_retain(total, |dst| {
            cur.read(dst);
        });
    }

    /// Retain just-sent bytes handed in as a contiguous slice — the
    /// TSO fast path's entry point. `try_send_tso` seals ciphertext
    /// directly into a driver TX-pool slot; this copies that slot's
    /// payload into the retransmit ring before the slot recycles, so
    /// a TSO segment is covered by the RTO timer exactly like a
    /// chain-sent one.
    pub(crate) fn rtx_on_data_sent_slice(&mut self, bytes: &[u8]) {
        let mut off = 0usize;
        self.rtx_retain(bytes.len(), |dst| {
            dst.copy_from_slice(&bytes[off..off + dst.len()]);
            off += dst.len();
        });
    }

    /// Fold an ACK into the retransmission state: drop acknowledged
    /// bytes from the ring and re-arm or stop the timer (RFC 6298
    /// §5.2 / §5.3). `old_una` is `snd_una` from *before* the caller
    /// advanced it for this ACK.
    pub(crate) fn rtx_on_ack(&mut self, old_una: u32) {
        // Resume coverage once the window has fully drained — when
        // `rtx_overflow` is set the ring (failed to allocate) cannot
        // be trusted, so wait for an empty window before re-engaging.
        if self.rtx_overflow {
            if self.snd_una == self.snd_nxt {
                self.rtx_overflow = false;
                self.rtx_backoff = 0;
                self.rto_ms = RTO_INITIAL_MS;
            }
            return;
        }
        let acked = self.snd_una.wrapping_sub(old_una) as usize;
        if acked == 0 {
            return; // not new data — leave the timer untouched
        }
        // Data bytes this ACK retires from the retransmit ring.
        // `acked` is the raw sequence advance, which also counts the
        // SYN / FIN phantom bytes — neither is held in `rtx_buf`, so
        // clamping to `rtx_len` strips them.
        let drop = acked.min(self.rtx_len as usize);
        // RFC 5681 §2 / §3.1: the congestion window opens only for an
        // ACK that "cumulatively acknowledges new data" — the SYN and
        // FIN flag bytes do not count. Skipping the update when no
        // data was acked keeps the 3-way handshake ACK (which acks
        // only the SYN) from inflating the initial window.
        if drop > 0 {
            self.cwnd_on_ack(drop as u32);
        }
        // RFC 6298 §3 (Karn): if this ACK covers the anchored byte and
        // no retransmission has invalidated the sample, fold the
        // round-trip time into the estimator.
        if self.rtt_anchor_active && !seq_lt(self.snd_una, self.rtt_anchor_seq) {
            let elapsed = kernel_core::clock::now_ms().saturating_sub(self.rtt_anchor_ms);
            self.sample_rtt(elapsed.min(u32::MAX as u64) as u32);
            self.rtt_anchor_active = false;
        }
        self.rtx_head = ((self.rtx_head as usize + drop) % RTX_BUF_BYTES) as u16;
        self.rtx_len -= drop as u16;
        // New data acknowledged: the peer is making progress, so clear
        // the §5.5 backoff and reset the RTO to the current estimate
        // (RFC 6298 §5.7 — a backed-off RTO holds only until a
        // successful round trip restores the estimator's value).
        self.rtx_backoff = 0;
        self.rto_ms = self.estimated_rto();
        if self.rtx_len == 0 {
            // §5.2: everything outstanding is ACK'd — stop the timer.
            self.rtx_deadline_ms = 0;
        } else {
            // §5.3: some (not all) ACK'd — restart the timer.
            self.arm_rtx();
        }
    }

    /// Re-send up to one MSS of unacknowledged data starting at
    /// `snd_una`. Shared by the RFC 6298 RTO path and RFC 5681 fast
    /// retransmit; the caller owns the congestion-window adjustment
    /// and the RTO-timer bookkeeping. No-op when nothing is buffered.
    fn retransmit_oldest_segment(&mut self) {
        let n = (self.rtx_len as usize).min(mss_for(self.local_ip));
        if n == 0 {
            return;
        }
        // Copy the (≤ MSS) bytes out of the ring into a contiguous
        // scratch buffer — the ring segment may wrap, and `send_segment`
        // takes a flat slice. Off the steady-state path (only fires on
        // actual loss), so the stack copy is not a hot-path cost.
        let mut scratch = [0u8; MSS_MAX];
        {
            let Some(buf) = self.rtx_buf.as_ref() else {
                return;
            };
            let head = self.rtx_head as usize;
            if head + n <= RTX_BUF_BYTES {
                scratch[..n].copy_from_slice(&buf[head..head + n]);
            } else {
                let first = RTX_BUF_BYTES - head;
                scratch[..first].copy_from_slice(&buf[head..]);
                scratch[first..n].copy_from_slice(&buf[..n - first]);
            }
        }
        send_segment(
            &SegmentMeta {
                local_ip: self.local_ip,
                dst_ip: self.remote_ip,
                src_port: self.local_port,
                dst_port: self.remote_port,
                seq: self.snd_una,
                ack: self.rcv_nxt,
                flags: TCP_ACK | TCP_PSH,
                window: self.rx_free() as u16,
            },
            &scratch[..n],
        );
        // RFC 6298 §3 (Karn's algorithm): the outstanding RTT sample
        // is now ambiguous — a later ACK could be for either the
        // original transmission or this one — so discard it.
        self.rtt_anchor_active = false;
    }

    /// Retransmit the oldest unacked segment on RTO expiry (RFC 6298
    /// §5.4-§5.6): re-send up to one MSS from `snd_una`, double the
    /// RTO (§5.5), and re-arm the timer. Called by `on_tcp_tick` when
    /// the deadline has passed.
    pub(crate) fn retransmit_oldest(&mut self, now: u64) {
        if self.rtx_len == 0 {
            self.rtx_deadline_ms = 0; // nothing to retransmit
            return;
        }
        // RFC 5681 §3.1: the timeout is a congestion signal — halve
        // ssthresh (first RTO of the episode) and collapse cwnd back
        // to one segment. Done before the `rtx_backoff` bump below so
        // `rtx_backoff == 0` still marks that first timeout.
        self.congestion_on_rto();
        self.retransmit_oldest_segment();
        // §5.5: back the RTO off exponentially, capped at the ceiling.
        self.rtx_backoff = self.rtx_backoff.saturating_add(1);
        self.rto_ms = self.rto_ms.saturating_mul(2).min(RTO_MAX_MS);
        self.rtx_deadline_ms = now + self.rto_ms as u64;
        self.arm_for_tick();
    }

    // ─── Connection-lifecycle timers ─────────────────────────────────────

    /// Arm (or re-arm) the FIN-retransmit timer. The interval backs
    /// off exponentially with `fin_retx_count` (RFC 6298 §5.5-style)
    /// off the connection's RTO estimate, capped at `RTO_MAX_MS`.
    pub(crate) fn arm_fin_timer(&mut self, now: u64) {
        let interval = ((self.estimated_rto() as u64) << self.fin_retx_count.min(16))
            .min(RTO_MAX_MS as u64);
        self.lifecycle_deadline_ms = now + interval;
        self.arm_for_tick();
    }

    /// Retransmit the connection's FIN (`FinWait1` / `LastAck`) and
    /// re-arm the timer with one more step of backoff. The FIN
    /// occupies sequence number `snd_nxt - 1` — `close()` advanced
    /// `snd_nxt` past it when the FIN was first sent. Called by
    /// `on_tcp_tick` once the lifecycle deadline has passed.
    pub(crate) fn retransmit_fin(&mut self, now: u64) {
        send_segment(
            &SegmentMeta {
                local_ip: self.local_ip,
                dst_ip: self.remote_ip,
                src_port: self.local_port,
                dst_port: self.remote_port,
                seq: self.snd_nxt.wrapping_sub(1),
                ack: self.rcv_nxt,
                flags: TCP_FIN | TCP_ACK,
                window: self.rx_free() as u16,
            },
            &[],
        );
        self.fin_retx_count = self.fin_retx_count.saturating_add(1);
        self.arm_fin_timer(now);
    }

    /// Arm the `TimeWait` 2×MSL drop timer — `on_tcp_tick` frees the
    /// connection once this deadline passes. Reuses the lifecycle
    /// deadline field; in `TimeWait` the tick reads it as a drop
    /// deadline rather than a FIN-retransmit deadline.
    pub(crate) fn arm_time_wait(&mut self, now: u64) {
        self.lifecycle_deadline_ms = now + TIME_WAIT_MS;
        self.arm_for_tick();
    }

    // ─── RFC 9293 §3.8.6.1 zero-window probing ───────────────────────────
    //
    // A peer that advertises a zero receive window stalls the send
    // path. The peer reopens the window with a bare window-update ACK
    // — but that ACK carries no data, so it is not itself
    // retransmitted, and a single lost window-update would otherwise
    // deadlock the connection. The persist timer breaks the deadlock:
    // it periodically probes the shut window until the peer answers.

    /// Arm (or re-arm) the zero-window persist timer. The interval
    /// backs off exponentially with `persist_backoff` off the RTO
    /// estimate, capped at `RTO_MAX_MS` — the same shape as
    /// `arm_fin_timer`.
    pub(crate) fn arm_persist(&mut self, now: u64) {
        let interval = ((self.estimated_rto() as u64) << self.persist_backoff.min(16))
            .min(RTO_MAX_MS as u64);
        self.persist_deadline_ms = now + interval;
        self.arm_for_tick();
    }

    /// Send a zero-window probe and re-arm the persist timer with one
    /// more step of backoff. The probe is a bare ACK at `snd_una - 1`
    /// — one sequence number below the peer's `rcv_nxt`, so the
    /// segment is "unacceptable" and the peer is obliged to answer
    /// with an ACK (RFC 9293 §3.10.7.4), which re-advertises its
    /// receive window. The probe is the Linux `tcp_xmit_probe_skb`
    /// mechanism: a non-data segment, so it needs no access to the
    /// queued send data.
    pub(crate) fn send_window_probe(&mut self, now: u64) {
        crate::diag::COUNTERS.persist_probes.bump();
        send_segment(
            &SegmentMeta {
                local_ip: self.local_ip,
                dst_ip: self.remote_ip,
                src_port: self.local_port,
                dst_port: self.remote_port,
                seq: self.snd_una.wrapping_sub(1),
                ack: self.rcv_nxt,
                flags: TCP_ACK,
                window: self.rx_free() as u16,
            },
            &[],
        );
        self.persist_backoff = self.persist_backoff.saturating_add(1);
        self.arm_persist(now);
    }

    // ─── RFC 5681 congestion control ─────────────────────────────────────

    /// Initialise the congestion window at connection start.
    /// RFC 6928: the initial window is `min(10·SMSS, max(2·SMSS,
    /// 14600))` — for our SMSS (1440/1460 B) that works out to
    /// 10·SMSS, the initial window Linux has defaulted to since
    /// 2013. (RFC 5681 §3.1's older 3·SMSS is the lower bound
    /// RFC 6928 raised: a larger IW saves a fresh connection several
    /// slow-start round-trips on the first response.) `ssthresh`
    /// starts effectively infinite so the connection opens in slow
    /// start.
    pub(crate) fn congestion_init(&mut self) {
        let smss = mss_for(self.local_ip) as u32;
        self.cwnd = (10 * smss).min((2 * smss).max(14600));
        self.ssthresh = u32::MAX;
    }

    /// Bytes sent but not yet acknowledged — the wire range
    /// `[snd_una, snd_nxt)`, RFC 9293's "FlightSize". 32-bit
    /// wrap-around subtraction.
    #[inline]
    pub(crate) fn flight(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }

    /// RFC 5681 §4 usable window: how many further bytes the send
    /// path may put in flight right now. The send window is
    /// `min(cwnd, rwnd)`; the bytes already in flight are subtracted.
    /// `saturating_sub` floors the result at 0 — a peer that shrinks
    /// its advertised window below the current flight size (RFC 9293
    /// §3.8.6.2.1 says SHOULD NOT, but it is legal) simply closes the
    /// send window until ACKs drain the excess.
    #[inline]
    pub(crate) fn usable_window(&self) -> u32 {
        self.cwnd
            .min(self.snd_wnd as u32)
            .saturating_sub(self.flight())
    }

    /// Fold an ACK of `acked` new bytes into the congestion window
    /// (RFC 5681 §3.1). Slow start (`cwnd < ssthresh`) opens the
    /// window by one SMSS per ACK — exponential per RTT. Congestion
    /// avoidance adds `SMSS·SMSS/cwnd` per ACK, the standard
    /// approximation of one SMSS per RTT — linear.
    pub(crate) fn cwnd_on_ack(&mut self, acked: u32) {
        let smss = mss_for(self.local_ip) as u32;
        if self.cwnd < self.ssthresh {
            // Slow start: one SMSS per ACK, capped at the bytes the
            // ACK actually covers (RFC 5681's `min(N, SMSS)`).
            self.cwnd = self.cwnd.saturating_add(acked.min(smss));
        } else {
            // Congestion avoidance: ~one SMSS per RTT. `max(1)` keeps
            // the window opening when integer division would floor
            // the increment to zero.
            let inc = ((smss as u64 * smss as u64) / self.cwnd.max(1) as u64) as u32;
            self.cwnd = self.cwnd.saturating_add(inc.max(1));
        }
    }

    /// Fold an RTO expiry into the congestion window (RFC 5681 §3.1):
    /// the first timeout of a loss episode drops `ssthresh` to half
    /// the flight size, and every timeout collapses `cwnd` to one
    /// segment — the connection re-enters slow start. Called by
    /// `retransmit_oldest` before it bumps `rtx_backoff`, so
    /// `rtx_backoff == 0` marks that first timeout.
    pub(crate) fn congestion_on_rto(&mut self) {
        let smss = mss_for(self.local_ip) as u32;
        if self.rtx_backoff == 0 {
            self.ssthresh = (self.flight() / 2).max(2 * smss);
        }
        self.cwnd = smss;
    }

    /// RFC 5681 §3.2 fast retransmit: the third duplicate ACK is
    /// taken as a loss signal without waiting for the RTO. Halve
    /// `ssthresh` against the flight size, re-send the segment the
    /// duplicates are missing, and inflate `cwnd` to
    /// `ssthresh + 3·SMSS` — each of the three duplicate ACKs implies
    /// a segment that has left the network.
    fn fast_retransmit(&mut self) {
        let smss = mss_for(self.local_ip) as u32;
        self.ssthresh = (self.flight() / 2).max(2 * smss);
        self.retransmit_oldest_segment();
        self.cwnd = self.ssthresh.saturating_add(3 * smss);
    }

    /// Fold a duplicate ACK into the RFC 5681 §3.2 fast-retransmit /
    /// fast-recovery state. The third duplicate triggers fast
    /// retransmit and entry into fast recovery; each further
    /// duplicate while in recovery inflates `cwnd` by one SMSS (the
    /// segment it implies has left the network).
    pub(crate) fn on_dup_ack(&mut self) {
        let smss = mss_for(self.local_ip) as u32;
        self.dup_acks = self.dup_acks.saturating_add(1);
        if self.dup_acks == 3 {
            self.fast_retransmit();
            self.in_fast_recovery = true;
        } else if self.dup_acks > 3 && self.in_fast_recovery {
            // §3.2 step 4: inflate for the additional duplicate.
            self.cwnd = self.cwnd.saturating_add(smss);
        }
    }

    /// Fold an ACK of new data into the fast-recovery state. It ends
    /// any duplicate-ACK run; if the connection was in fast recovery
    /// it deflates `cwnd` back to `ssthresh` and exits recovery
    /// (RFC 5681 §3.2 step 6).
    pub(crate) fn on_new_data_ack(&mut self) {
        self.dup_acks = 0;
        if self.in_fast_recovery {
            self.cwnd = self.ssthresh;
            self.in_fast_recovery = false;
        }
    }
}

/// 32-bit sequence-number "less than" using wrap-around arithmetic
/// (RFC 1323): treat the 32-bit difference as a signed i32. Shared
/// across receive/state — kept here next to `TcpConnection` so it
/// lives with the rest of the per-conn sequence-arithmetic helpers.
#[inline]
pub(crate) fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

