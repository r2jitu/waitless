// net/tcp.rs — TCP state machine, per-core connection pool, ring buffers.
//
// Connections are partitioned across cores. Each core owns a slice of
// the global pool. The flow hash (in net/lib.rs) routes packets to the
// owning core. All connection operations are core-local — no locks.

#![cfg_attr(not(test), no_std)]

extern crate alloc;
extern crate bitflags;
extern crate kernel_core;
extern crate net_dst_mac as dst_mac;
extern crate net_ethernet as ethernet;
extern crate net_from_bytes as from_bytes;
extern crate net_ipv4 as ipv4;
extern crate net_ipv6 as ipv6;
extern crate net_ipv6_send as ipv6_send;
extern crate net_types as types;
extern crate nic;
extern crate uni_runtime;

use alloc::boxed::Box;
use core::ptr;
use core::task::Waker;
use from_bytes::FromBytes;
use types::{IpAddr, MacAddr, htonl, htons, ntohl, ntohs, tcp_checksum_any, tcp_pseudo_partial};
use uni_iobuf::{Chain, IOBuf, OwnedIOBuf};

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
const RX_RING_BYTES: usize = 16384;
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

// ─── RFC 6298 retransmission ─────────────────────────────────────────────────
//
// Every unacknowledged outbound byte is kept in a per-conn ring
// (`rtx_buf`) alongside a millisecond RTO deadline. A periodic tick
// (`on_rtx_tick`, driven by the net poll loop) retransmits the oldest
// unacked data once the deadline passes and doubles the RTO each time
// (§5.5 exponential backoff). Before this a lost *outbound* segment
// was never resent — an RFC 9293 MUST violation, and a real
// correctness gap on a lossy path.

/// Per-conn retransmit-ring capacity. Sized to hold one maximum TLS
/// 1.3 record's ciphertext (16384-byte plaintext chunk + AEAD
/// envelope) with margin — the largest single `async_try_send_chain`
/// the server issues. An unacked window that outgrows this suspends
/// retransmit coverage (`rtx_overflow`) until the peer's ACKs drain
/// it; that is strictly better than the pre-RFC-6298 "retransmit
/// nothing" and disappears once RFC 5681 `cwnd` bounds the in-flight
/// window. Boxed + lazy like `rx_ring`, so idle slots stay cheap.
const RTX_BUF_BYTES: usize = 17408;
/// Initial RTO before any RTT measurement (RFC 6298 §2.1), and the
/// floor every computed RTO is clamped up to (§2.4 — round a sub-1 s
/// estimate up to 1 s).
const RTO_INITIAL_MS: u32 = 1000;
/// RTT-estimator gain `K` — RTO = SRTT + K·RTTVAR (RFC 6298 §2.3).
const RTO_K: u32 = 4;
/// RTO ceiling — the §5.5 exponential backoff clamps here. RFC 6298
/// §2.5 requires the bound to be at least 60 s.
const RTO_MAX_MS: u32 = 60_000;
/// Retransmissions of one segment before the connection is declared
/// dead and torn down. With 1+2+4+…+60 s (capped) backoff this is
/// ~100 s of total wait — in line with the RFC 9293 §3.8.3 "R2"
/// lower bound for aborting a broken connection.
const RTX_MAX_RETRIES: u8 = 8;

/// Active `TcpRecv` future's destination buffer. The future
/// registers this pointer + capacity when it parks, so a subsequent
/// `tcp_receive` can copy payload bytes straight into the user buf
/// — skipping the per-conn ring. Cleared by the future's `Drop`
/// (cancel safety) and by `deliver_payload` after writing.
#[derive(Clone, Copy)]
struct RecvBufSlot {
    ptr: *mut u8,
    cap: u16,
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
    /// Per-conn RX ring buffer. Heap-allocated once at
    /// `TcpConnection::alloc_storage` (lazily on first SYN that
    /// lands on a fresh slot) and reused across SYN/close cycles.
    /// `tcp_receive` writes payload bytes here via `deliver_payload`
    /// (when there's no active recv slot to direct-copy into) or
    /// when direct-copy doesn't consume the entire segment.
    /// `async_recv` drains via `rx_ring_pop`.
    ///
    /// Inline `[u8; RX_RING_BYTES]` would bloat the per-slot
    /// footprint by 8 KiB × every slot in the per-core pool; with
    /// the segmented-pool growth ceiling at MAX_SEGMENTS × SEGMENT_SIZE
    /// that's ~512 MiB worst-case. Boxing the ring keeps idle
    /// segments cheap and only materialises 8 KiB per live conn.
    rx_ring: Option<Box<[u8; RX_RING_BYTES]>>,
    rx_head: u16,
    rx_tail: u16,
    /// Bytes currently in `rx_ring`. Cached so the per-segment
    /// rcv_wnd calc doesn't have to (head - tail) modulo every time.
    rx_used: u16,
    /// Bytes `deliver_payload` wrote directly into a parked
    /// `TcpRecv`'s user buf via `recv_buf_slot`. Read + cleared by
    /// `async_recv` on the very next poll (the conn knows the next
    /// poll's `buf` is the same one whose pointer we already wrote
    /// to, because `TcpRecv::poll` doesn't change the buf between
    /// register and pop). Stored separately from `rx_ring` so the
    /// fast-path bypass doesn't have to memmove anything.
    direct_bytes: u16,
    /// User buf registered by a parked `TcpRecv` future for the
    /// direct-copy fast path. Cleared by either:
    ///   * `TcpRecv::Drop` (the future was dropped / cancelled
    ///     before resolving) — prevents `deliver_payload` from
    ///     writing into freed user memory.
    ///   * `deliver_payload` itself, after it consumes the slot.
    recv_buf_slot: Option<RecvBufSlot>,
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
    chunk_wanted: bool,
    /// The IOBuf handed to a `recv_chunk` consumer, produced by
    /// `tcp_receive`'s zero-copy stash and drained by
    /// `do_recv_chunk`. Holds at most one buffer — the stated
    /// "≤ 1 outstanding IOBuf per TcpStream" invariant, which the
    /// `RecvChunkGuard<'_>` borrow also enforces at the type level.
    /// Only ever stashed when `rx_ring` is empty, so a later ring
    /// push can never make `pending_chunk` the *newer* bytes:
    /// `do_recv_chunk` drains it strictly before the ring.
    pending_chunk: Option<IOBuf>,
    listener_port: u16,
    accepted: bool,
    /// Incremented every time `free_connection` resets this slot, so
    /// a stale async handle that survived a close+reuse sees a
    /// generation mismatch on its next hook call and short-circuits
    /// to the "closed" path. Preserved across reset — `new()` does
    /// NOT reset it; `free_connection` bumps it explicitly.
    generation: u16,
    /// Parked `TcpRecv` waker. Set by `register_recv_waker` on the
    /// owning core; woken when data lands in the ring or the
    /// peer closes. Per-core ownership — no lock needed.
    recv_waker: Option<Waker>,
    /// RFC 6298 retransmit ring — the unacknowledged outbound bytes,
    /// mirroring the wire range `[snd_una, snd_nxt)`. Heap-boxed and
    /// lazily allocated on the first buffered send, then reused across
    /// SYN/close cycles like `rx_ring`. `None` until the conn first
    /// sends data.
    rtx_buf: Option<Box<[u8; RTX_BUF_BYTES]>>,
    /// Ring index of the byte at `snd_una`.
    rtx_head: u16,
    /// Bytes currently buffered. Equals `snd_nxt - snd_una` while
    /// retransmit coverage holds; see `rtx_overflow`.
    rtx_len: u16,
    /// Set when the unacked window outgrew `rtx_buf` (or the buffer
    /// failed to allocate): the ring no longer covers `[snd_una,
    /// snd_nxt)`, so the RTO timer is held off until the peer's ACKs
    /// drain the window back to empty, at which point coverage
    /// resumes. Never *worse* than the pre-RFC-6298 behaviour.
    rtx_overflow: bool,
    /// Current retransmission timeout, milliseconds. Doubles on each
    /// RTO expiry (§5.5); re-initialised when new data is ACK'd.
    rto_ms: u32,
    /// Absolute deadline (`kernel_core::clock::now_ms`) at which the
    /// oldest unacked segment is retransmitted. 0 = timer disarmed.
    rtx_deadline_ms: u64,
    /// Consecutive RTO expiries for the oldest segment without an
    /// intervening ACK — the §5.5 backoff exponent, and the
    /// give-up counter (`RTX_MAX_RETRIES`).
    rtx_backoff: u8,
    /// RFC 6298 §2 smoothed round-trip time, milliseconds. 0 until
    /// the first measurement (see `rtt_seeded`).
    srtt_ms: u32,
    /// RFC 6298 §2 round-trip-time variation, milliseconds.
    rttvar_ms: u32,
    /// False until `sample_rtt` has folded in a first measurement —
    /// selects the §2.2 (seed) vs §2.3 (EWMA) update.
    rtt_seeded: bool,
    /// RTT-sample anchor: the send timestamp and the sequence number
    /// just past the timed bytes. At most one sample is outstanding
    /// per RTT (RFC 6298 §3); the ACK covering `rtt_anchor_seq`
    /// yields the measurement `R`.
    rtt_anchor_ms: u64,
    rtt_anchor_seq: u32,
    /// True while an RTT sample is outstanding. Cleared when the
    /// sample is taken, and on any retransmission — Karn's algorithm
    /// forbids deriving an RTT from a segment that was retransmitted.
    rtt_anchor_active: bool,
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
            rcv_wnd: RX_RING_BYTES as u16,
            rx_ring: None,
            rx_head: 0,
            rx_tail: 0,
            rx_used: 0,
            direct_bytes: 0,
            recv_buf_slot: None,
            chunk_wanted: false,
            pending_chunk: None,
            listener_port: 0,
            accepted: false,
            generation: 0,
            recv_waker: None,
            rtx_buf: None,
            rtx_head: 0,
            rtx_len: 0,
            rtx_overflow: false,
            rto_ms: RTO_INITIAL_MS,
            rtx_deadline_ms: 0,
            rtx_backoff: 0,
            srtt_ms: 0,
            rttvar_ms: 0,
            rtt_seeded: false,
            rtt_anchor_ms: 0,
            rtt_anchor_seq: 0,
            rtt_anchor_active: false,
            next_free: NULL_SLOT,
        }
    }

    /// Lazy-allocate the per-conn RX ring on the first SYN that
    /// lands on this slot. Subsequent close+reuse cycles keep the
    /// allocation (the pool's free-list bumps `generation` but
    /// doesn't touch `rx_ring`); see `free_connection` for the
    /// reset-preserve dance.
    fn ensure_rx_ring(&mut self) -> bool {
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
    fn rx_used(&self) -> usize {
        self.rx_used as usize
    }

    #[inline]
    fn rx_free(&self) -> usize {
        // -1 reserves one slot — keeps head==tail unambiguous as
        // "empty" without forcing a separate "full" flag. Matches
        // the historic behaviour of the IOBuf-list version.
        (RX_RING_BYTES - 1).saturating_sub(self.rx_used as usize)
    }

    /// Write `payload` bytes into the conn's RX ring. Truncates to
    /// the window's free space; the trimmed suffix is dropped (the
    /// peer will retransmit once `rcv_wnd` opens).
    fn rx_ring_push(&mut self, payload: &[u8]) -> usize {
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

    /// Deliver an in-sequence TCP payload to the consumer. Fast
    /// path: if a `TcpRecv` future has registered a destination
    /// slot, copy as many bytes as fit straight into the user buf
    /// (one memcpy, no ring round-trip). Slow path: fall through
    /// to the ring. Returns total bytes consumed (direct + ring) —
    /// `rcv_nxt` advances by this much, and the segment trim happens
    /// at the caller.
    fn deliver_payload(&mut self, payload: &[u8]) -> usize {
        let mut written = 0;
        if let Some(slot) = self.recv_buf_slot.take() {
            let cap = slot.cap as usize;
            let take = payload.len().min(cap);
            if take > 0 {
                // SAFETY: `slot.ptr` was registered by `TcpRecv::poll`
                // on this core; the future's `Drop` clears it (so
                // it can't be dangling here). `slot.cap` is the
                // length of the user buf. Both `slot.ptr` and
                // `payload` are non-overlapping (separate
                // allocations).
                unsafe {
                    ptr::copy_nonoverlapping(payload.as_ptr(), slot.ptr, take);
                }
                self.direct_bytes = take as u16;
                written += take;
            }
        }
        if written < payload.len() {
            written += self.rx_ring_push(&payload[written..]);
        }
        written
    }

    /// Drain bytes from the ring (and any pending `direct_bytes`)
    /// into `out`. `out` is the recv-future's user buf; if
    /// `direct_bytes > 0` those bytes were already written there
    /// by `deliver_payload` and we just need to consume them
    /// counter-wise.
    fn rx_pop(&mut self, out: &mut [u8]) -> usize {
        let mut written = 0;
        // Direct-copy bytes — already in `out` (same pointer),
        // just claim them.
        if self.direct_bytes > 0 {
            let n = (self.direct_bytes as usize).min(out.len());
            written = n;
            self.direct_bytes -= n as u16;
            // If the user buf was smaller than direct_bytes (which
            // would only happen if poll didn't pass through the
            // same buf — shouldn't, but be defensive), the rest is
            // lost. Don't try to recover; this is the cancel-safety
            // invariant.
        }
        if written >= out.len() {
            return written;
        }
        if self.rx_used == 0 {
            return written;
        }
        let ring = match self.rx_ring.as_mut() {
            Some(r) => r,
            None => return written,
        };
        let want = out.len() - written;
        let take = want.min(self.rx_used as usize);
        let head = self.rx_head as usize;
        if head + take <= RX_RING_BYTES {
            out[written..written + take].copy_from_slice(&ring[head..head + take]);
        } else {
            let first = RX_RING_BYTES - head;
            out[written..written + first].copy_from_slice(&ring[head..]);
            out[written + first..written + take].copy_from_slice(&ring[..take - first]);
        }
        self.rx_head = ((head + take) % RX_RING_BYTES) as u16;
        self.rx_used -= take as u16;
        // Draining the ring reopened the receive window. If the peer
        // is SWS-stalled on the old sub-MSS window, tell it now —
        // otherwise it waits for its persist timer.
        self.maybe_send_window_update();
        written + take
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
                self.local_ip,
                self.remote_ip,
                self.local_port,
                self.remote_port,
                self.snd_nxt,
                self.rcv_nxt,
                TCP_ACK,
                free,
                &[],
            );
        }
    }

    // ─── RFC 6298 retransmission ─────────────────────────────────────────

    /// Lazy-allocate the per-conn retransmit ring on the first
    /// buffered send. Reused across SYN/close cycles like `rx_ring`
    /// (the pool free-list dance preserves it). Returns `false` on
    /// OOM — the caller then suspends retransmit coverage.
    fn ensure_rtx_buf(&mut self) -> bool {
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
    fn arm_rtx(&mut self) {
        self.rtx_deadline_ms = kernel_core::clock::now_ms() + self.rto_ms as u64;
    }

    /// Fold a round-trip-time measurement `r` (milliseconds) into the
    /// RFC 6298 §2 estimator. §2.2 seeds SRTT/RTTVAR from the first
    /// sample; §2.3 is the EWMA thereafter — RTTVAR is updated first,
    /// against the *old* SRTT (alpha = 1/8, beta = 1/4).
    fn sample_rtt(&mut self, r: u32) {
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
    fn estimated_rto(&self) -> u32 {
        if !self.rtt_seeded {
            return RTO_INITIAL_MS;
        }
        let spread = 1u32.max(self.rttvar_ms.saturating_mul(RTO_K));
        self.srtt_ms
            .saturating_add(spread)
            .clamp(RTO_INITIAL_MS, RTO_MAX_MS)
    }

    /// Retain the `total` just-sent bytes — read from a fresh cursor
    /// over the chain `async_try_send_chain` already transmitted — so
    /// the RTO timer can retransmit them, and start the timer if it
    /// is not already running (RFC 6298 §5.1).
    fn rtx_on_data_sent(&mut self, total: usize, cur: &mut uni_iobuf::Cursor<'_>) {
        if total == 0 || self.rtx_overflow {
            return; // nothing to retain, or coverage already suspended
        }
        if !self.ensure_rtx_buf() || self.rtx_len as usize + total > RTX_BUF_BYTES {
            // OOM, or the unacked window outgrew the ring. Drop
            // retransmit coverage until snd_una catches snd_nxt;
            // `rtx_on_ack` clears the flag once the window drains.
            self.rtx_overflow = true;
            self.rtx_head = 0;
            self.rtx_len = 0;
            self.rtx_deadline_ms = 0;
            return;
        }
        let tail = (self.rtx_head as usize + self.rtx_len as usize) % RTX_BUF_BYTES;
        let buf = self.rtx_buf.as_mut().expect("ensure_rtx_buf succeeded");
        if tail + total <= RTX_BUF_BYTES {
            cur.read(&mut buf[tail..tail + total]);
        } else {
            let first = RTX_BUF_BYTES - tail;
            cur.read(&mut buf[tail..]);
            cur.read(&mut buf[..total - first]);
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

    /// Fold an ACK into the retransmission state: drop acknowledged
    /// bytes from the ring and re-arm or stop the timer (RFC 6298
    /// §5.2 / §5.3). `old_una` is `snd_una` from *before* the caller
    /// advanced it for this ACK.
    fn rtx_on_ack(&mut self, old_una: u32) {
        // Resume coverage once an overflowed window has fully drained.
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
        // RFC 6298 §3 (Karn): if this ACK covers the anchored byte and
        // no retransmission has invalidated the sample, fold the
        // round-trip time into the estimator.
        if self.rtt_anchor_active && !seq_lt(self.snd_una, self.rtt_anchor_seq) {
            let elapsed = kernel_core::clock::now_ms().saturating_sub(self.rtt_anchor_ms);
            self.sample_rtt(elapsed.min(u32::MAX as u64) as u32);
            self.rtt_anchor_active = false;
        }
        let drop = acked.min(self.rtx_len as usize);
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

    /// Retransmit the oldest unacked segment (RFC 6298 §5.4-§5.6):
    /// re-send up to one MSS from `snd_una`, double the RTO (§5.5),
    /// and re-arm the timer. Called by `on_rtx_tick` when the
    /// deadline has passed.
    fn retransmit_oldest(&mut self, now: u64) {
        let n = (self.rtx_len as usize).min(mss_for(self.local_ip));
        if n == 0 {
            self.rtx_deadline_ms = 0; // nothing to retransmit
            return;
        }
        // Copy the (≤ MSS) bytes out of the ring into a contiguous
        // scratch buffer — the ring segment may wrap, and `send_segment`
        // takes a flat slice. Off the steady-state path (only fires on
        // actual loss), so the stack copy is not a hot-path cost.
        let mut scratch = [0u8; MSS_MAX];
        {
            let Some(buf) = self.rtx_buf.as_ref() else {
                self.rtx_deadline_ms = 0;
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
            self.local_ip,
            self.remote_ip,
            self.local_port,
            self.remote_port,
            self.snd_una,
            self.rcv_nxt,
            TCP_ACK | TCP_PSH,
            self.rx_free() as u16,
            &scratch[..n],
        );
        // RFC 6298 §3 (Karn's algorithm): the outstanding RTT sample
        // is now ambiguous — a later ACK could be for either the
        // original transmission or this one — so discard it.
        self.rtt_anchor_active = false;
        // §5.5: back the RTO off exponentially, capped at the ceiling.
        self.rtx_backoff = self.rtx_backoff.saturating_add(1);
        self.rto_ms = self.rto_ms.saturating_mul(2).min(RTO_MAX_MS);
        self.rtx_deadline_ms = now + self.rto_ms as u64;
    }
}

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

static POOLS: kernel_core::percpu::PerWorker<TcpPool> = kernel_core::percpu::PerWorker::new();

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

static TCP_HASH: kernel_core::percpu::PerWorker<TcpHashCore> =
    kernel_core::percpu::PerWorker::new();

/// Count of SYN (no-ACK) packets we see reach `tcp_receive` —
/// diagnostic: compare against the bench client's SYN-sent count
/// to detect ingress-side drops below the TCP stack (driver/NIC).
pub static TCP_SYN_RX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Count of SYN-ACK segments we emit via `send_segment` in
/// response to a SYN. Compare against bench-client SYN-ACK
/// received to distinguish egress (fabric/strand) drops.
pub static TCP_SYNACK_TX: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// RX item H verification counters. `do_recv_chunk` resolves a
/// `recv_chunk` call by one of two paths:
///   * the zero-copy **stash** — a device RX buffer `tcp_receive`
///     moved straight into `pending_chunk`, surfaced as an
///     `External` IOBuf with no copy;
///   * the **ring-drain** fallback — the per-conn `rx_ring` copied
///     into a fresh `Heap` IOBuf.
/// `stash / (stash + ring_drain)` is the live measure of how often
/// the streaming-body `recv_chunk` path is actually zero-copy — the
/// signal item H's HVF-vs-GCE divergence needs to settle (item H
/// won +13.6% on HVF but was flat on GCE; the hypothesis is that
/// GCE segment bursts keep the ring non-empty so the fallback
/// dominates — these counters confirm or refute it). Surfaced via
/// `/stats` as `rx_chunk_stash_hits` / `rx_chunk_ring_drain`.
pub static RX_CHUNK_STASH_HITS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static RX_CHUNK_RING_DRAIN: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

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
        if k == 0 {
            return None;
        }
        if k == key {
            return Some(slots[idx] as usize);
        }
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
fn conn_ptr(core: u32, slot: usize) -> *mut TcpConnection {
    POOLS.at(core).slot_ptr(slot as u16)
}

/// Snapshot of `core`'s pool capacity — number of slots that have
/// been materialized so far. Linear-scan callers walk `0..pool_capacity(core)`.
#[inline]
fn pool_capacity(core: u32) -> usize {
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
fn tcp_linear_find(core: u32, src_ip: IpAddr, src_port: u16, dst_port: u16) -> Option<usize> {
    let cap = pool_capacity(core);
    for i in 0..cap {
        // SAFETY: per-core ownership — only the owning core scans.
        let c = unsafe { &*conn_ptr(core, i) };
        if c.state != TcpState::Closed
            && c.state != TcpState::Listen
            && c.remote_ip == src_ip
            && c.local_port == dst_port
            && c.remote_port == src_port
        {
            return Some(i);
        }
    }
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
fn next_seq() -> u32 {
    let mut buf = [0u8; 4];
    kernel_core::rng::fill_bytes(&mut buf);
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
        // async handle observes the bump on its next hook call. Also
        // preserve the 8 KiB RX ring allocation — `free_connection`
        // already kept it across the close cycle, but the `*c =
        // TcpConnection::new()` reset would drop it without this
        // hand-off, costing one heap free + one re-allocation per
        // close-conn /health cycle on the bench hot path.
        let preserved_gen = c.generation;
        let preserved_ring = c.rx_ring.take();
        let preserved_rtx = c.rtx_buf.take();
        *c = TcpConnection::new();
        c.generation = preserved_gen;
        c.rx_ring = preserved_ring;
        c.rtx_buf = preserved_rtx;
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
    // Preserve the 8 KiB heap-allocated RX ring across reuse — re-
    // allocating it on every SYN would cost a `Box::new([0; 8192])`
    // per accept on the close-conn /health hot path. The next SYN's
    // `ensure_rx_ring` short-circuits when `rx_ring.is_some()`.
    let preserved_ring = c.rx_ring.take();
    let preserved_rtx = c.rtx_buf.take();
    *c = TcpConnection::new();
    c.generation = next_gen;
    c.rx_ring = preserved_ring;
    c.rtx_buf = preserved_rtx;
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
const IPV4_HDR_LEN: usize = ipv4::HEADER_LEN; // 20
const IPV6_HDR_LEN: usize = ipv6::HEADER_LEN; // 40
const TCP_HDR_LEN: usize = 20;
const FRAME_BUF_LEN: usize = ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN + MSS_V4;
/// Per-conn-state cap on TSO super-segments: the maximum bytes we
/// hand to `submit_tx_tso` in one frame. Sized to cover one TLS
/// 1.3 record (16384 plaintext + 22-byte envelope) plus the
/// L2/L3/L4 headers. The driver's TX-pool slots are sized to
/// match (`MAX_ETH_FRAME` in uni-driver-virtio-net).
const TSO_FRAME_BUF_LEN: usize = ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN + 16384 + 24;

/// Compute the TCP-payload offset within a frame buffer for `local_ip`'s family.
#[inline]
fn payload_offset(local_ip: IpAddr) -> usize {
    match local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN, // 54
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN, // 74
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
    let tcp_hdr = unsafe { &mut *(frame.as_mut_ptr().add(tcp_off) as *mut TcpHeader) };
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
    tcp_hdr.checksum = if nic::csum_tx_offload() {
        match nic::csum_stamp_convention() {
            nic::CsumStampConvention::PseudoHeaderPartial => {
                tcp_pseudo_partial(local_ip, dst_ip, types::proto::TCP, tcp_seg_len)
            }
            nic::CsumStampConvention::Zero => 0,
        }
    } else {
        unsafe {
            tcp_checksum_any(
                local_ip,
                dst_ip,
                types::proto::TCP,
                frame.as_ptr().add(tcp_off),
                tcp_seg_len,
            )
        }
    };

    // ── IP header (family-dispatched) ────────────────────────────────
    let ip_total = (tcp_off - ETH_HDR_LEN + tcp_seg_len) as u16;
    match (local_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            ipv4::fill_header(
                &mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN],
                s,
                d,
                types::proto::TCP,
                ip_total,
            );
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            ipv6::fill_header(
                &mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV6_HDR_LEN],
                &s,
                &d,
                types::proto::TCP,
                64,
                tcp_seg_len as u16,
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
    let csum = if csum_tcp_off != 0 && nic::csum_tx_offload() {
        // 16 = byte offset of the TCP `checksum` field within
        // the TCP header.
        nic::CsumOffload {
            start: csum_tcp_off,
            offset: 16,
        }
    } else {
        nic::CsumOffload::NONE
    };
    if let Some(mut handle) = nic::acquire_tx_buf() {
        let cap = handle.data_cap as usize;
        debug_assert!(frame_len <= cap);
        // SAFETY: the handle's `data_mut()` returns a slice of
        // `data_cap` writable bytes; we narrow to `frame_len`
        // for the closure but the underlying buffer covers the
        // full slot.
        fill(&mut handle.data_mut()[..frame_len]);
        nic::submit_tx(handle, frame_len, csum);
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
        nic::send(frame_const);
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
            frame,
            local_ip,
            dst_ip,
            dst_mac,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
            payload_len,
        );
    });
}

/// Build and ship a TCP TSO super-segment whose payload (up to
/// ~16 KiB — one TLS record's worth) is read from a chain
/// cursor. The driver's NIC segments the payload into MSS-sized
/// chunks host-side, fixing up TCP/IP headers per segment.
///
/// Caller must have verified `nic::tso_available()`
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
    let Some(mut handle) = nic::acquire_tx_tso_buf() else {
        send_per_mss_fallback(
            local_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
            cursor,
            payload_len,
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
            frame,
            local_ip,
            dst_ip,
            dst_mac,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
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
    nic::submit_tx_tso(handle, frame_len, hdr_len, csum_start, mss as u16);
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
    min_payload: usize,
    fill: &mut dyn FnMut(&mut [u8]) -> Result<usize, ()>,
) -> Option<Result<usize, ()>> {
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
    // TSO is only correct when the device will emit multiple
    // segments — gve hardware silently drops sub-MSS TSO frames
    // (the frame goes through `submit_tx_tso` and the device
    // never delivers it on the wire). The same gate as
    // `async_try_send_chain`'s `total > mss` check, but applied
    // to the pre-fill estimate so we don't run the encrypt
    // closure for a single-segment send. Caller falls back to
    // its scratch path on `None`.
    let mss = mss_for(c.local_ip);
    if min_payload <= mss {
        return None;
    }
    let dst_mac = dst_mac::resolve(c.remote_ip)?;
    let mut handle = nic::acquire_tx_tso_buf()?;

    let payload_off = payload_offset(c.local_ip);
    let cap = handle.data_cap() as usize;
    let max_payload = cap.saturating_sub(payload_off);

    // Hand the post-header region of the slot to the closure.
    // The closure (typically the TLS encrypt-chain path) writes
    // ciphertext bytes here and returns the count, or `Err(())`
    // on a fatal failure (TLS seal error).
    let payload_len = {
        let region = &mut handle.data_mut()[payload_off..payload_off + max_payload];
        match fill(region) {
            Ok(n) => n,
            Err(()) => {
                // Slot returns to the pool via handle's Drop
                // without a virtio descriptor enqueue.
                return Some(Err(()));
            }
        }
    };
    if payload_len == 0 {
        // Nothing to send — slot returns to the pool via the
        // handle's Drop without a virtio descriptor enqueue.
        return Some(Ok(0));
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
            frame,
            c.local_ip,
            c.remote_ip,
            dst_mac,
            c.local_port,
            c.remote_port,
            c.snd_nxt,
            c.rcv_nxt,
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

    let hdr_len = payload_off as u16;
    let csum_start = tcp_off as u16;
    nic::submit_tx_tso(handle, frame_len, hdr_len, csum_start, mss as u16);

    c.snd_nxt = c.snd_nxt.wrapping_add(payload_len as u32);
    Some(Ok(payload_len))
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
            local_ip, dst_ip, src_port, dst_port, cur_seq, ack, flags, window, cursor, chunk,
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
            let dst =
                core::slice::from_raw_parts_mut(frame.as_mut_ptr().add(payload_off), payload_len);
            let n = cursor.read(dst);
            debug_assert_eq!(n, payload_len);
            let _ = n;
        }
        fill_tcp_frame_headers(
            frame,
            local_ip,
            dst_ip,
            dst_mac,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
            payload_len,
        );
    });
}

fn send_rst(local_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, seq: u32, ack: u32) {
    send_segment(
        local_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        TCP_RST | TCP_ACK,
        0,
        &[],
    );
}

/// Process an incoming TCP packet. Called on the owning core (via flow hash).
/// `src_ip` and `dst_ip` are family-tagged so v4 and v6 connections
/// share the same TCB pool, hash table, and dispatch path.
///
/// `segment` is an owned `Chain<OwnedIOBuf>` covering exactly the TCP
/// segment — header + payload — with the eth/IP headers and any
/// ethernet trailing padding already narrowed off by the caller
/// (`net::net_receive_frame`, RX item D). It is a one-part chain
/// today; a hardware-coalesced super-segment (RX item I) would
/// arrive multi-part, so the payload walk below iterates every part.
///
/// The chain — and the device RX buffer(s) it owns — drops at
/// return; that drop reposts the buffer(s) to the NIC / pool.
/// Payload bytes are copied out before then: into a parked
/// `TcpRecv`'s direct-copy slot, with the rest into the per-conn
/// ring. RX item D keeps the ring a `Box<[u8; 16384]>` — this commit
/// is plumbing, the copy count is unchanged, only the input is now
/// IOBuf-typed.
pub fn tcp_receive(src_ip: IpAddr, dst_ip: IpAddr, mut segment: Chain<OwnedIOBuf>) {
    // The TCP header is contiguous in the first chain part: a frame's
    // L2/L3/L4 headers all land in the device's first RX buffer, and
    // the caller narrowed the chain to start exactly at the TCP header.
    let Some(first) = segment.iter().next() else {
        return;
    };
    let hdr = match TcpHeader::try_ref_from(first.data()) {
        Some(h) => h,
        None => return,
    };
    let src_port = ntohs(hdr.src_port);
    let dst_port = ntohs(hdr.dst_port);
    let seq = ntohl(hdr.seq);
    let ack = ntohl(hdr.ack);
    let flags = hdr.flags;
    let data_offset = ((hdr.data_offset >> 4) as usize) * 4;
    let payload_len = segment.total_len().saturating_sub(data_offset);

    // Determine which core owns this packet.
    let core = kernel_core::cpu_id();

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
        TCP_SYN_RX.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        // Single pool walk: find the `Listen` slot for `dst_port`,
        // and also spot any existing connection already on this
        // exact 4-tuple. A SYN on a live 4-tuple is the peer
        // (re)starting — a retransmitted SYN whose SYN-ACK was
        // lost, or a fresh connection on a reused ephemeral port.
        // Free that stale twin before allocating, so the pool
        // never holds two connections for one 4-tuple.
        //
        // Without this, a retransmitted SYN `alloc_connection`s a
        // fresh slot and orphans the previous `SynReceived`
        // connection. Nothing reclaims an orphaned `SynReceived`:
        // the stack has no RTO timer, and `alloc_connection`'s
        // pool-exhaustion reclaim scans only closing states. The
        // orphan would leak until its 4-tuple is reused — which is
        // exactly when this scan catches it.
        //
        // An `Established` match is left intact — a live
        // connection, not a stale duplicate.
        let mut listener_idx = None;
        let mut stale_idx = None;
        {
            let cap = pool_capacity(core);
            for i in 0..cap {
                let c = unsafe { &*conn_ptr(core, i) };
                if listener_idx.is_none() && c.state == TcpState::Listen && c.local_port == dst_port
                {
                    listener_idx = Some(i);
                } else if stale_idx.is_none()
                    && c.state != TcpState::Closed
                    && c.state != TcpState::Listen
                    && c.state != TcpState::Established
                    && c.remote_ip == src_ip
                    && c.local_port == dst_port
                    && c.remote_port == src_port
                {
                    stale_idx = Some(i);
                }
                if listener_idx.is_some() && stale_idx.is_some() {
                    break;
                }
            }
        }

        if listener_idx.is_none() {
            send_rst(dst_ip, src_ip, dst_port, src_port, 0, seq + 1);
            return;
        }

        // Drop the stale 4-tuple twin (if any) before allocating, so
        // the pool never holds two connections for one 4-tuple.
        if let Some(s) = stale_idx {
            free_connection(core, s);
        }

        // Allocate new connection on this core
        let slot = match alloc_connection(core) {
            Some(i) => i,
            None => return,
        };

        {
            let c = unsafe { &mut *conn_ptr(core, slot) };
            // Allocate the per-conn RX ring on first use (preserved
            // across reuse; see `free_connection`). OOM here refuses
            // the connection rather than proceeding with a missing
            // ring that would silently drop every payload byte.
            if !c.ensure_rx_ring() {
                send_rst(dst_ip, src_ip, dst_port, src_port, 0, seq + 1);
                free_connection(core, slot);
                return;
            }
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

            // Ring cursors — reset on every SYN so a slot reused from
            // the free list starts empty.
            c.rx_head = 0;
            c.rx_tail = 0;
            c.rx_used = 0;
            c.direct_bytes = 0;
            c.recv_buf_slot = None;
            c.chunk_wanted = false;
            c.pending_chunk = None;
        }

        // Publish this 4-tuple to the per-core hash index so the
        // subsequent ACK + data segments land in `tcp_hash_find`
        // with one probe instead of a 128-slot linear scan.
        let key = tcp_hash_key(src_ip, src_port, dst_port);
        tcp_hash_insert(core, key, slot);

        // Send SYN+ACK
        {
            let c = unsafe { &*conn_ptr(core, slot) };
            send_segment(
                dst_ip,
                src_ip,
                dst_port,
                src_port,
                c.snd_nxt,
                c.rcv_nxt,
                TCP_SYN | TCP_ACK,
                RX_RING_BYTES as u16,
                &[],
            );
            TCP_SYNACK_TX.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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
    //
    // On a hash miss, fall back to a linear pool scan: the hash is
    // a fixed 256 entries and overflows once the pool grows past
    // that, at which point `tcp_hash_insert` silently drops entries
    // (see `tcp_linear_find`). The fallback keeps an overflowed
    // connection correct — found, just slower — instead of dropping
    // every one of its segments.
    let key = tcp_hash_key(src_ip, src_port, dst_port);
    let slot = match tcp_hash_find(core, key) {
        Some(s) => s,
        None => match tcp_linear_find(core, src_ip, src_port, dst_port) {
            Some(s) => s,
            None => return,
        },
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
        // `snd_una` before this ACK advances it — `rtx_on_ack` needs
        // the delta to drop acknowledged bytes from the retransmit
        // ring (RFC 6298 §5.2 / §5.3).
        let old_una = c.snd_una;
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
        // RFC 6298 §5.2 / §5.3: drop acknowledged bytes from the
        // retransmit ring and re-arm or stop the RTO timer. (The
        // `LastAck` branch above already `return`ed — the connection
        // is gone, so it is correctly skipped here.)
        c.rtx_on_ack(old_una);
    }

    // Process data
    if payload_len > 0
        && (c.state == TcpState::Established
            || c.state == TcpState::FinWait1
            || c.state == TcpState::FinWait2)
    {
        if seq == c.rcv_nxt {
            // A parked `recv_chunk` consumer wants the payload as an
            // owned IOBuf. When the ring is empty and no direct-copy
            // `recv` slot is registered, *move* a single-part
            // segment's device buffer straight into `pending_chunk`
            // — zero copy, no `rx_ring` round-trip. Multi-part chains
            // (item I's coalesced super-segments) and the ring-non-
            // empty case fall through to the copy path, which keeps
            // stream order: `pending_chunk` is only ever stashed when
            // the ring is empty, so it holds the *oldest* unread
            // bytes and `do_recv_chunk` drains it strictly first.
            //
            // `chunk_wanted` is false unless a `recv_chunk` future is
            // parked, so a conn with only `recv` consumers never
            // takes this branch — the copy path below is byte-
            // identical to the pre-item-F behaviour.
            let pushed = if c.chunk_wanted
                && c.pending_chunk.is_none()
                && c.rx_used == 0
                && c.recv_buf_slot.is_none()
                && segment.part_count() == 1
            {
                let mut part = segment.pop_front().expect("part_count() == 1");
                match part.narrow(data_offset, payload_len) {
                    Ok(()) => {
                        c.pending_chunk = Some(IOBuf::from(part));
                        c.chunk_wanted = false;
                        payload_len
                    }
                    // Unreachable for a single-part chain — the window
                    // always covers `[data_offset, +payload_len)`. On
                    // the impossible error drop the buffer and let the
                    // peer retransmit rather than desync `rcv_nxt`.
                    Err(_) => 0,
                }
            } else {
                // Walk the chain: skip the `data_offset`-byte TCP
                // header, then deliver each part's payload bytes.
                // `deliver_payload` direct-copies into a parked
                // `TcpRecv`'s user buf when one is registered
                // (consuming the slot on the first call), with the
                // rest into the per-conn ring. One part today — one
                // `deliver_payload` call over `data()[data_offset..]`;
                // item I's coalesced super-segments arrive multi-part.
                // All synchronous on this core, so the chain's device
                // buffers are still owned at return.
                let mut pushed = 0usize;
                let mut skip = data_offset;
                for part in segment.iter() {
                    let bytes = part.data();
                    if skip >= bytes.len() {
                        skip -= bytes.len();
                        continue;
                    }
                    pushed += c.deliver_payload(&bytes[skip..]);
                    skip = 0;
                }
                pushed
            };
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
            send_segment(
                dst_ip,
                src_ip,
                dst_port,
                src_port,
                c.snd_nxt,
                c.rcv_nxt,
                TCP_ACK,
                c.rx_free() as u16,
                &[],
            );
        } else if seq_lt(seq, c.rcv_nxt) {
            // Duplicate/retransmitted segment — send ACK immediately so the
            // sender knows we already have this data (fast retransmit signal).
            send_segment(
                dst_ip,
                src_ip,
                dst_port,
                src_port,
                c.snd_nxt,
                c.rcv_nxt,
                TCP_ACK,
                c.rx_free() as u16,
                &[],
            );
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
        send_segment(
            dst_ip,
            src_ip,
            dst_port,
            src_port,
            c.snd_nxt,
            c.rcv_nxt,
            TCP_ACK,
            c.rx_free() as u16,
            &[],
        );

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

/// Drive the RFC 6298 retransmission timers for the current core's
/// connection pool. Called from the net poll loop (`sched::poll`) at
/// a coarse cadence: every connection whose RTO deadline has passed
/// gets its oldest unacked segment retransmitted, or is torn down
/// once it has been retransmitted `RTX_MAX_RETRIES` times with no
/// intervening progress (RFC 9293 §3.8.3 — give up on a dead peer).
pub fn on_rtx_tick() {
    let core = kernel_core::cpu_id();
    let now = kernel_core::clock::now_ms();
    let cap = pool_capacity(core);
    for i in 0..cap {
        // SAFETY: per-core ownership — only this core touches its pool.
        let c = unsafe { &mut *conn_ptr(core, i) };
        if c.rtx_deadline_ms == 0 || now < c.rtx_deadline_ms {
            continue;
        }
        if c.rtx_backoff >= RTX_MAX_RETRIES {
            free_connection(core, i);
            continue;
        }
        c.retransmit_oldest(now);
    }
}

/// True if any connection on the current core has an armed RTO timer.
/// The event loop consults this before going fully idle so a core
/// with a pending retransmission does not sleep past the deadline.
pub fn has_armed_rtx_timers() -> bool {
    let core = kernel_core::cpu_id();
    let cap = pool_capacity(core);
    for i in 0..cap {
        // SAFETY: per-core ownership.
        let c = unsafe { &*conn_ptr(core, i) };
        if c.rtx_deadline_ms != 0 {
            return true;
        }
    }
    false
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
    let n = kernel_core::percpu::num_cores();
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
    accept_on_port_core(kernel_core::cpu_id(), port)
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
    // `direct_bytes > 0` covers the case where `deliver_payload`
    // wrote bytes straight into the parked `TcpRecv`'s user buf
    // and bypassed the ring entirely — `rx_used` is 0 in that
    // shape, but the future still has bytes to claim.
    // `pending_chunk` is the `recv_chunk` analogue: a zero-copy
    // IOBuf stashed by `tcp_receive` that `do_recv_chunk` will
    // hand out — also readable with `rx_used == 0`.
    if c.rx_used() > 0 || c.direct_bytes > 0 || c.pending_chunk.is_some() {
        return true;
    }
    matches!(
        c.state,
        TcpState::Closed | TcpState::CloseWait | TcpState::LastAck | TcpState::TimeWait
    )
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
                c.local_ip,
                c.remote_ip,
                c.local_port,
                c.remote_port,
                c.snd_nxt,
                c.rcv_nxt,
                TCP_FIN | TCP_ACK,
                win,
                &[],
            );
            c.snd_nxt = c.snd_nxt.wrapping_add(1);
            c.state = TcpState::FinWait1;
        }
        TcpState::CloseWait => {
            send_segment(
                c.local_ip,
                c.remote_ip,
                c.local_port,
                c.remote_port,
                c.snd_nxt,
                c.rcv_nxt,
                TCP_FIN | TCP_ACK,
                win,
                &[],
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
    let n = kernel_core::percpu::num_cores();
    for core in 0..n {
        let cap = pool_capacity(core);
        for slot in 0..cap {
            // SAFETY: see fn-level comment — APs have left the
            // eventloop; only BSP runs this and it owns its own
            // slots, with read-only access to AP slots.
            let c = unsafe { &mut *conn_ptr(core, slot) };
            if c.state != TcpState::Closed && c.state != TcpState::Listen {
                send_rst(
                    c.local_ip,
                    c.remote_ip,
                    c.local_port,
                    c.remote_port,
                    c.snd_nxt,
                    c.rcv_nxt,
                );
                free_connection(core, slot);
            }
            // Release the per-conn RX ring and retransmit ring at
            // shutdown — `free_connection` preserves both across normal
            // close+reuse (the next SYN re-uses the allocations), but at
            // process shutdown there are no more SYNs, and the preserved
            // blocks would show up in `HEAP_LEAK_CHECK` as residual heap
            // the cooldown didn't reclaim. Drop here so the leak-check
            // delta returns to zero.
            // SAFETY: same per-fn invariant as above; the slot is in
            // Closed (post-`free_connection`) or Listen state, neither
            // of which observes the rings.
            let c = unsafe { &mut *conn_ptr(core, slot) };
            c.rx_ring = None;
            c.rtx_buf = None;
        }
    }
    // The caller (`net::bare_shutdown_all`) flushes the NIC TX
    // staging + kick after this returns — this teardown path
    // deliberately leaves that flush to the caller.
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
        None => {
            waker.wake_by_ref();
            return;
        }
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

/// Register the `&mut buf` of a parked `TcpRecv` future as the
/// direct-copy destination for the next inbound TCP payload. Called
/// from `TcpRecv::poll` before parking; `deliver_payload` reads this
/// slot, writes up to `cap` bytes straight into `ptr`, increments
/// `direct_bytes`, and clears the slot.
///
/// Stale `generation` is a no-op — the future will see the closed
/// state via `is_readable_or_closed` and resolve through `do_recv`.
pub fn set_recv_buf_slot(handle: *mut (), generation: u16, ptr: *mut u8, cap: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return;
    }
    c.recv_buf_slot = Some(RecvBufSlot { ptr, cap });
}

/// Drop the registered direct-copy slot. Called from `TcpRecv::Drop`
/// (cancel-safety: future was dropped before waker fired) and from
/// `TcpRecv::poll` after resolving Ready. Stale `generation` is a
/// no-op — the conn slot is already reused for someone else and
/// the new owner's `set_recv_buf_slot` writes will dominate.
pub fn clear_recv_buf_slot(handle: *mut (), generation: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return;
    }
    c.recv_buf_slot = None;
}

/// Register intent to receive the next inbound payload as an owned
/// `IOBuf` (zero copy) rather than copied into a user buffer.
/// Called from `RecvChunk::poll` before parking; `tcp_receive`
/// then moves the next in-sequence single-part segment straight
/// into `pending_chunk` instead of pushing it through `rx_ring`.
///
/// Unlike `set_recv_buf_slot` this carries no pointer — the
/// consumer wants the transport's buffer, not a destination to
/// copy into — so it is just a one-bit "deliver-as-IOBuf" request.
/// Stale `generation` is a no-op; the future resolves to closed
/// via `is_readable_or_closed` + `do_recv_chunk`.
pub fn set_chunk_buf_slot(handle: *mut (), generation: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return;
    }
    c.chunk_wanted = true;
}

/// Drop the chunk-delivery request. Called from `RecvChunk::Drop`
/// (cancel-safety: the future was dropped before resolving) and
/// from `RecvChunk::poll` after resolving Ready. Does NOT discard
/// an already-stashed `pending_chunk` — that IOBuf is still owed to
/// whoever the slot belongs to and is cleared on slot reset. Stale
/// `generation` is a no-op.
pub fn clear_chunk_buf_slot(handle: *mut (), generation: u16) {
    let (core, slot) = match decode_handle(handle) {
        Some(v) => v,
        None => return,
    };
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return;
    }
    c.chunk_wanted = false;
}

/// Async `RecvChunk` consume hook — the `recv_chunk` analogue of
/// `async_recv`. Surfaces the next chunk of inbound data as an
/// owned `IOBuf`:
///
///   * `pending_chunk` — a device buffer `tcp_receive` stashed
///     zero-copy. Returned as-is (an `External` IOBuf): the guard
///     reads it in place and `into_owned()` keeps it zero-copy.
///   * otherwise, if `rx_ring` holds bytes, they are drained into
///     a fresh `Heap` IOBuf. `pending_chunk` is only ever stashed
///     while the ring is empty, so draining it first then the ring
///     preserves stream order.
///   * `None` — no data: EOF / peer close / stale `generation`,
///     observed by the caller as the end of the body.
pub fn do_recv_chunk(handle: *mut (), generation: u16) -> Option<IOBuf> {
    let (core, slot) = decode_handle(handle)?;
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return None;
    }
    if let Some(iobuf) = c.pending_chunk.take() {
        // Zero-copy stash: the device RX buffer is surfaced as-is.
        RX_CHUNK_STASH_HITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return Some(iobuf);
    }
    let n = c.rx_used();
    if n == 0 {
        return None;
    }
    // Drain the ring into an owned heap buffer. `rx_pop` also runs
    // the SWS window-update check, so a chunk read reopens the
    // receive window exactly as a `recv` read does.
    let mut v = alloc::vec::Vec::new();
    if v.try_reserve_exact(n).is_err() {
        return None;
    }
    v.resize(n, 0);
    let got = c.rx_pop(&mut v);
    v.truncate(got);
    // Ring-drain fallback: one memcpy (rx_ring → Heap IOBuf). Not
    // zero-copy — `into_owned()` on this is free, but the bytes
    // already moved through the ring.
    RX_CHUNK_RING_DRAIN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Some(IOBuf::from(v))
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
    if nic::tso_available()
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
    // chain.
    drop(cursor);
    // RFC 6298: retain the just-sent bytes so the RTO timer can
    // retransmit them if their ACK never arrives, and start the
    // timer if it is not already running. A fresh cursor re-walks
    // the still-intact chain (one extra copy into `rtx_buf`); the
    // chain is dropped immediately after.
    {
        let mut rtx_cursor = chain.cursor();
        c.rtx_on_data_sent(total, &mut rtx_cursor);
    }
    // Drops fire in chain order (External callbacks recycle NIC
    // descriptors back to driver pools).
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
        None => {
            waker.wake_by_ref();
            return;
        }
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
}

pub fn clear_send_waker(_handle: *mut (), _generation: u16) {
    // No-op on bare-metal — no send-waker state to clear.
}

// ── Host-native TCP conformance harness ─────────────────────────────────────
//
// packetdrill-style: drive scripted TCP segments into `tcp_receive`
// against a mock `NicOps` that captures every transmitted frame into a
// `Vec`, then assert on the captured output. `tcp_receive` is the real
// RX entry point and the send path is the real TX code — only the NIC
// underneath is mocked.
//
// `tcp.rs`'s per-core pools (`POOLS`, `TCP_HASH`) and the NIC-ops slot
// are process-global, so the scenarios cannot run concurrently:
// `TEST_LOCK` serialises them, and each uses a distinct 4-tuple so
// connection-pool state never bleeds between tests.
#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::NonNull;
    use std::sync::{Mutex, Once};
    use types::Ipv4Addr;
    use uni_iobuf::IOBufDropFn;
    use uni_net_driver::{CsumStampConvention, NicOps, set_active_ops};

    const SERVER_IP: [u8; 4] = [10, 0, 0, 1];
    const CLIENT_IP: [u8; 4] = [10, 0, 0, 2];
    const SERVER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x00, 0x01];

    // ---- mock NIC: capture every transmitted frame ------------------------

    static TX: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

    fn mock_send(frame: &[u8]) {
        TX.lock().unwrap().push(frame.to_vec());
    }
    fn mock_get_mac(out: *mut u8) {
        // SAFETY: the NIC-dispatch contract guarantees `out` addresses
        // six writable bytes.
        unsafe { core::ptr::copy_nonoverlapping(SERVER_MAC.as_ptr(), out, 6) };
    }
    fn yes() -> bool {
        true
    }
    fn no() -> bool {
        false
    }
    fn unit() {}
    fn no_poll(_: fn(Chain<OwnedIOBuf>)) -> usize {
        0
    }
    fn no_poll_qp(_: usize, _: fn(Chain<OwnedIOBuf>)) -> usize {
        0
    }
    fn one_qp() -> u16 {
        1
    }

    // `acquire_tx_buf` / TSO left `None` and the capabilities `false`,
    // so every transmit funnels through `send(&[u8])` — the one path
    // the capture hook covers. `csum_tx_offload = false` makes `tcp.rs`
    // compute and stamp the full TCP checksum, so captured frames are
    // wire-complete.
    static MOCK_OPS: NicOps = NicOps {
        name: "mock",
        probe: yes,
        send: mock_send,
        acquire_tx_buf: None,
        submit_tx: None,
        tso_available: no,
        csum_tx_offload: no,
        csum_stamp_convention: || CsumStampConvention::PseudoHeaderPartial,
        acquire_tx_tso_buf: None,
        submit_tx_tso: None,
        udp_gso_available: no,
        acquire_tx_udp_gso_buf: None,
        submit_tx_udp_gso: None,
        poll_rx: no_poll,
        poll_qp: no_poll_qp,
        get_mac: mock_get_mac,
        num_queue_pairs: one_qp,
        enable_irq: unit,
        enable_deferred_tx_kick: unit,
        flush_tx_staging: unit,
        flush_tx_kick_if_dirty: no,
        poke_interrupt_status: unit,
        idle: None,
        diag: None,
    };

    // ---- one-time bring-up + per-test serialisation -----------------------

    static SETUP: Once = Once::new();
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Lock out the other scenarios, run global bring-up once, and
    /// start with an empty TX capture. The returned guard serialises
    /// the test for as long as it is held.
    fn harness() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        SETUP.call_once(|| {
            uni_worker::set_num_workers(1);
            super::init(); // TCP per-core pools
            ipv4::init(); // per-core IP-ID counter (the TX path stamps it)
            ethernet::set_our_mac(SERVER_MAC);
            set_active_ops(&MOCK_OPS);
        });
        TX.lock().unwrap().clear();
        // Start every scenario at t=0 so a timer-driven test never
        // inherits clock advanced by an earlier one.
        kernel_core::clock::mock::reset();
        guard
    }

    /// Snapshot the captured frames.
    fn tx() -> Vec<Vec<u8>> {
        TX.lock().unwrap().clone()
    }

    /// Drop the captured frames — used to open a fresh assertion
    /// window mid-scenario (e.g. after the handshake).
    fn clear_tx() {
        TX.lock().unwrap().clear();
    }

    // ---- scripted segment construction / parsing --------------------------

    /// A scripted inbound TCP segment. `tcp_receive` is handed the
    /// chain already narrowed to the TCP header, so the harness builds
    /// no Ethernet/IP for the inbound direction.
    struct Seg {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        payload: Vec<u8>,
    }

    impl Seg {
        fn encode(&self) -> Vec<u8> {
            let mut b = Vec::with_capacity(TCP_HDR_LEN + self.payload.len());
            b.extend_from_slice(&self.src_port.to_be_bytes());
            b.extend_from_slice(&self.dst_port.to_be_bytes());
            b.extend_from_slice(&self.seq.to_be_bytes());
            b.extend_from_slice(&self.ack.to_be_bytes());
            b.push(5 << 4); // data offset = 5 32-bit words (a 20-byte header)
            b.push(self.flags);
            b.extend_from_slice(&self.window.to_be_bytes());
            b.extend_from_slice(&[0, 0]); // checksum — tcp_receive does not verify it
            b.extend_from_slice(&[0, 0]); // urgent pointer
            b.extend_from_slice(&self.payload);
            b
        }
    }

    /// Drop callback for `make_chain` — reclaims the `Box<[u8]>` whose
    /// region was handed to `wrap_owned`.
    ///
    /// SAFETY: `base`/`cap` are the `(ptr, len)` of a `Box::<[u8]>`,
    /// reclaimed exactly once here.
    unsafe fn free_box(base: NonNull<u8>, cap: u32, _ctx: *mut ()) {
        let slice = core::ptr::slice_from_raw_parts_mut(base.as_ptr(), cap as usize);
        drop(unsafe { alloc::boxed::Box::from_raw(slice) });
    }

    /// Wrap `bytes` in a single-part `Chain<OwnedIOBuf>` — the shape
    /// `tcp_receive` consumes.
    fn make_chain(bytes: &[u8]) -> Chain<OwnedIOBuf> {
        let boxed: alloc::boxed::Box<[u8]> = bytes.to_vec().into_boxed_slice();
        let cap = boxed.len() as u32;
        let raw = alloc::boxed::Box::into_raw(boxed);
        // SAFETY: `raw` is a non-null `cap`-byte region; `free_box`
        // reclaims it exactly once; offset 0 + len cap fits capacity.
        let buf = unsafe {
            OwnedIOBuf::wrap_owned(
                NonNull::new_unchecked(raw as *mut u8),
                cap,
                0,
                cap,
                free_box as IOBufDropFn,
                core::ptr::null_mut(),
            )
        };
        Chain::from(buf)
    }

    fn v4(o: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(o[0], o[1], o[2], o[3]))
    }

    /// Drive one scripted segment from `CLIENT_IP` to `SERVER_IP`.
    fn deliver(seg: &Seg) {
        tcp_receive(v4(CLIENT_IP), v4(SERVER_IP), make_chain(&seg.encode()));
    }

    /// Host-order view of a captured frame's TCP header. Returned by
    /// value so callers never hold a reference into the `repr(packed)`
    /// `TcpHeader`.
    struct TcpView {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
    }

    /// Parse the TCP header out of a captured `[Eth | IPv4 | TCP]`
    /// frame (Ethernet 14 + IPv4 20 = offset 34).
    fn tcp_hdr(frame: &[u8]) -> TcpView {
        assert!(
            frame.len() >= 34 + TCP_HDR_LEN,
            "captured frame is {} bytes — too short for Eth+IPv4+TCP",
            frame.len()
        );
        let h = TcpHeader::try_ref_from(&frame[34..]).expect("captured frame has a TCP header");
        TcpView {
            src_port: ntohs(h.src_port),
            dst_port: ntohs(h.dst_port),
            seq: ntohl(h.seq),
            ack: ntohl(h.ack),
            flags: h.flags,
        }
    }

    // ---- scenarios --------------------------------------------------------

    /// A bare SYN to a listening port is answered with a SYN|ACK that
    /// acknowledges the client's ISN + 1.
    #[test]
    fn syn_elicits_syn_ack() {
        let _g = harness();
        const SP: u16 = 9101;
        const CP: u16 = 50101;
        const CLIENT_ISN: u32 = 0x1000;
        super::listen_on_core(0, SP);

        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: CLIENT_ISN,
            ack: 0,
            flags: TCP_SYN,
            window: 65535,
            payload: Vec::new(),
        });

        let frames = tx();
        assert_eq!(frames.len(), 1, "a SYN must elicit exactly one frame");
        let h = tcp_hdr(&frames[0]);
        assert_eq!(h.flags, TCP_SYN | TCP_ACK, "the reply must be SYN|ACK");
        assert_eq!(h.src_port, SP, "reply source port = the listening port");
        assert_eq!(h.dst_port, CP, "reply dest port = the client's port");
        assert_eq!(
            h.ack,
            CLIENT_ISN.wrapping_add(1),
            "SYN|ACK must acknowledge the client ISN + 1",
        );
    }

    /// Once the three-way handshake completes, an in-order data
    /// segment is acknowledged with `ack` advanced past the bytes.
    #[test]
    fn established_data_is_acked() {
        let _g = harness();
        const SP: u16 = 9102;
        const CP: u16 = 50102;
        const CLIENT_ISN: u32 = 0x2000;
        super::listen_on_core(0, SP);

        let server_isn = handshake(SP, CP, CLIENT_ISN);

        clear_tx();
        let body = b"hello!";
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: CLIENT_ISN.wrapping_add(1),
            ack: server_isn.wrapping_add(1),
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            payload: body.to_vec(),
        });

        let frames = tx();
        assert!(!frames.is_empty(), "in-order data must elicit an ACK");
        let last = tcp_hdr(frames.last().unwrap());
        assert_ne!(last.flags & TCP_ACK, 0, "the reply must carry ACK");
        assert_eq!(
            last.ack,
            CLIENT_ISN.wrapping_add(1 + body.len() as u32),
            "ACK must cover the delivered payload",
        );
    }

    /// A FIN on an established connection is acknowledged, with `ack`
    /// advanced one sequence number past the FIN.
    #[test]
    fn fin_is_acked() {
        let _g = harness();
        const SP: u16 = 9103;
        const CP: u16 = 50103;
        const CLIENT_ISN: u32 = 0x3000;
        super::listen_on_core(0, SP);

        let server_isn = handshake(SP, CP, CLIENT_ISN);

        clear_tx();
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: CLIENT_ISN.wrapping_add(1),
            ack: server_isn.wrapping_add(1),
            flags: TCP_FIN | TCP_ACK,
            window: 65535,
            payload: Vec::new(),
        });

        let frames = tx();
        assert!(!frames.is_empty(), "a FIN must elicit an ACK");
        let last = tcp_hdr(frames.last().unwrap());
        assert_ne!(last.flags & TCP_ACK, 0, "the reply must carry ACK");
        assert_eq!(
            last.ack,
            CLIENT_ISN.wrapping_add(2),
            "ACK must cover the FIN — one sequence number past the handshake",
        );
    }

    // ---- receiver-side scenarios — no new feature, pure coverage ----------

    /// A retransmitted SYN on a 4-tuple already in `SynReceived` (the
    /// peer never saw our SYN|ACK) must free the orphaned half-open
    /// twin and answer with a fresh SYN|ACK — never leak a second
    /// slot for one 4-tuple. Exercises the stale-twin cleanup in
    /// `tcp_receive`'s SYN handler.
    #[test]
    fn retransmitted_syn_replaces_the_stale_twin() {
        let _g = harness();
        const SP: u16 = 9104;
        const CP: u16 = 50104;
        const CLIENT_ISN: u32 = 0x4000;
        super::listen_on_core(0, SP);

        let syn = Seg {
            src_port: CP,
            dst_port: SP,
            seq: CLIENT_ISN,
            ack: 0,
            flags: TCP_SYN,
            window: 65535,
            payload: Vec::new(),
        };

        // First SYN → SYN|ACK; the connection is now `SynReceived`.
        deliver(&syn);
        assert_eq!(tcp_hdr(&tx()[0]).flags, TCP_SYN | TCP_ACK);

        // The peer never saw that SYN|ACK and retransmits its SYN.
        clear_tx();
        deliver(&syn);
        let frames = tx();
        assert_eq!(
            frames.len(),
            1,
            "a retransmitted SYN must elicit exactly one fresh SYN|ACK",
        );
        let second = tcp_hdr(&frames[0]);
        assert_eq!(
            second.flags,
            TCP_SYN | TCP_ACK,
            "the retransmit reply must itself be SYN|ACK",
        );
        assert_eq!(
            second.ack,
            CLIENT_ISN.wrapping_add(1),
            "the fresh SYN|ACK still acknowledges the client ISN + 1",
        );

        // The connection from the *second* SYN|ACK is the live one —
        // complete its handshake and prove it delivers data.
        let server_isn = second.seq;
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: CLIENT_ISN.wrapping_add(1),
            ack: server_isn.wrapping_add(1),
            flags: TCP_ACK,
            window: 65535,
            payload: Vec::new(),
        });
        clear_tx();
        let body = b"twin-ok";
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: CLIENT_ISN.wrapping_add(1),
            ack: server_isn.wrapping_add(1),
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            payload: body.to_vec(),
        });
        assert_eq!(
            tcp_hdr(tx().last().unwrap()).ack,
            CLIENT_ISN.wrapping_add(1 + body.len() as u32),
            "the post-retransmit connection delivers data correctly",
        );
    }

    /// A duplicate segment wholly below `rcv_nxt` (the peer never saw
    /// our ACK and retransmitted) elicits an immediate bare ACK still
    /// pointing at `rcv_nxt` — the fast-retransmit signal, with no
    /// data re-counted.
    #[test]
    fn duplicate_data_elicits_an_immediate_dup_ack() {
        let _g = harness();
        const SP: u16 = 9105;
        const CP: u16 = 50105;
        const CLIENT_ISN: u32 = 0x5000;
        super::listen_on_core(0, SP);
        let server_isn = handshake(SP, CP, CLIENT_ISN);
        let rcv_nxt = CLIENT_ISN.wrapping_add(1);

        let body = b"first-copy";
        let seg = Seg {
            src_port: CP,
            dst_port: SP,
            seq: rcv_nxt,
            ack: server_isn.wrapping_add(1),
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            payload: body.to_vec(),
        };
        // One in-order delivery advances rcv_nxt past the segment.
        deliver(&seg);
        let advanced = rcv_nxt.wrapping_add(body.len() as u32);

        // The same bytes arrive again — a pure duplicate.
        clear_tx();
        deliver(&seg);
        let frames = tx();
        assert_eq!(
            frames.len(),
            1,
            "a duplicate segment must elicit exactly one ACK",
        );
        let h = tcp_hdr(&frames[0]);
        assert_ne!(h.flags & TCP_ACK, 0, "the reply must carry ACK");
        assert_eq!(
            h.flags & (TCP_SYN | TCP_FIN | TCP_RST),
            0,
            "a dup-ACK is a bare ACK — no other control flags",
        );
        assert_eq!(
            h.ack, advanced,
            "the dup-ACK still points at rcv_nxt — duplicate bytes are not re-counted",
        );
    }

    /// An out-of-order segment (a gap before it) is silently dropped:
    /// the stack has no reassembly queue (SACK is deferred), so the
    /// bytes are neither buffered nor acknowledged. Pinned so a future
    /// reassembly feature has to update this deliberately.
    #[test]
    fn out_of_order_segment_is_not_buffered() {
        let _g = harness();
        const SP: u16 = 9106;
        const CP: u16 = 50106;
        const CLIENT_ISN: u32 = 0x6000;
        super::listen_on_core(0, SP);
        let server_isn = handshake(SP, CP, CLIENT_ISN);
        let rcv_nxt = CLIENT_ISN.wrapping_add(1);

        // A segment 100 bytes past rcv_nxt — there is a gap before it.
        clear_tx();
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: rcv_nxt.wrapping_add(100),
            ack: server_isn.wrapping_add(1),
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            payload: vec![0xAB; 10],
        });
        assert!(
            tx().is_empty(),
            "an out-of-order segment is silently dropped — no reassembly queue",
        );

        // The gap-filling in-order segment is accepted at the
        // *original* rcv_nxt; the 10 out-of-order bytes were dropped.
        clear_tx();
        let body = b"in-order";
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: rcv_nxt,
            ack: server_isn.wrapping_add(1),
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            payload: body.to_vec(),
        });
        assert_eq!(
            tcp_hdr(tx().last().unwrap()).ack,
            rcv_nxt.wrapping_add(body.len() as u32),
            "ACK covers only the in-order bytes — the out-of-order segment was not reassembled",
        );
    }

    /// RFC 5961 §3.2: a RST exactly at `rcv_nxt` is accepted and tears
    /// the connection down — a follow-up segment then finds no TCB.
    #[test]
    fn rst_at_rcv_nxt_tears_down_the_connection() {
        let _g = harness();
        const SP: u16 = 9107;
        const CP: u16 = 50107;
        const CLIENT_ISN: u32 = 0x7000;
        super::listen_on_core(0, SP);
        let server_isn = handshake(SP, CP, CLIENT_ISN);
        let rcv_nxt = CLIENT_ISN.wrapping_add(1);

        clear_tx();
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: rcv_nxt,
            ack: 0,
            flags: TCP_RST,
            window: 0,
            payload: Vec::new(),
        });
        assert!(tx().is_empty(), "an accepted RST elicits no reply");

        // The TCB is gone: follow-up data finds nothing and is dropped
        // without an ACK.
        clear_tx();
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: rcv_nxt,
            ack: server_isn.wrapping_add(1),
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            payload: b"after-rst".to_vec(),
        });
        assert!(
            tx().is_empty(),
            "data on a reset connection finds no TCB — silently dropped",
        );
    }

    /// RFC 5961 §3.2: a RST whose seq is *not* exactly `rcv_nxt` is a
    /// blind-reset candidate — dropped, and the connection survives.
    #[test]
    fn rst_off_rcv_nxt_is_ignored() {
        let _g = harness();
        const SP: u16 = 9108;
        const CP: u16 = 50108;
        const CLIENT_ISN: u32 = 0x8000;
        super::listen_on_core(0, SP);
        let server_isn = handshake(SP, CP, CLIENT_ISN);
        let rcv_nxt = CLIENT_ISN.wrapping_add(1);

        clear_tx();
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: rcv_nxt.wrapping_add(9999),
            ack: 0,
            flags: TCP_RST,
            window: 0,
            payload: Vec::new(),
        });
        assert!(tx().is_empty(), "an off-sequence RST elicits no reply");

        // The connection is still alive — in-order data is still ACK'd.
        clear_tx();
        let body = b"still-here";
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: rcv_nxt,
            ack: server_isn.wrapping_add(1),
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            payload: body.to_vec(),
        });
        assert_eq!(
            tcp_hdr(tx().last().unwrap()).ack,
            rcv_nxt.wrapping_add(body.len() as u32),
            "the connection survived the off-sequence RST and still delivers data",
        );
    }

    /// RFC 6298: an outbound data segment whose ACK never arrives is
    /// retransmitted once the RTO elapses, and the RTO doubles on each
    /// successive expiry (§5.5 exponential backoff). Drives the real
    /// send path, withholds the ACK, and advances the mock clock.
    #[test]
    fn rto_retransmits_unacked_data_with_backoff() {
        let _g = harness();
        const SP: u16 = 9109;
        const CP: u16 = 50109;
        const CLIENT_ISN: u32 = 0x9000;
        super::listen_on_core(0, SP);
        let server_isn = handshake(SP, CP, CLIENT_ISN);

        // The server sends a response; its ACK will be withheld.
        let (handle, generation) = conn_handle(CP, SP);
        clear_tx();
        let body = b"unacked-response-body";
        let mut chain = uni_iobuf::IOBufChain::from(body.to_vec());
        let sent = super::async_try_send_chain(handle, generation, &mut chain)
            .expect("an established connection accepts the send");
        assert_eq!(sent, body.len(), "the whole body is handed to the wire");
        let first = tcp_hdr(&tx()[0]);
        assert_eq!(
            first.seq,
            server_isn.wrapping_add(1),
            "data is sent starting at snd_una",
        );

        // Before the RTO elapses the tick does nothing.
        clear_tx();
        kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 - 1);
        super::on_rtx_tick();
        assert!(tx().is_empty(), "no retransmit before the RTO elapses");

        // Crossing the RTO retransmits the segment verbatim.
        kernel_core::clock::mock::advance(2);
        super::on_rtx_tick();
        let rtx = tx();
        assert_eq!(rtx.len(), 1, "exactly one retransmit fires at the RTO");
        let r = tcp_hdr(&rtx[0]);
        assert_eq!(r.seq, first.seq, "the retransmit re-sends from snd_una");
        assert_eq!(
            &rtx[0][34 + TCP_HDR_LEN..],
            body,
            "the retransmit carries the original payload bytes",
        );

        // §5.5: the RTO has doubled. One RTO of further wait — enough
        // the first time — is now not enough for the second expiry.
        clear_tx();
        kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64);
        super::on_rtx_tick();
        assert!(
            tx().is_empty(),
            "the backed-off (2x) RTO has not elapsed after only one RTO of wait",
        );
        kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64);
        super::on_rtx_tick();
        assert_eq!(
            tx().len(),
            1,
            "the second retransmit fires only after the doubled RTO",
        );
    }

    /// RFC 6298 §5.3: an ACK that covers the outstanding data stops
    /// the RTO timer — no spurious retransmit afterwards.
    #[test]
    fn ack_stops_the_retransmission_timer() {
        let _g = harness();
        const SP: u16 = 9110;
        const CP: u16 = 50110;
        const CLIENT_ISN: u32 = 0xA000;
        super::listen_on_core(0, SP);
        let server_isn = handshake(SP, CP, CLIENT_ISN);

        let (handle, generation) = conn_handle(CP, SP);
        clear_tx();
        let body = b"acked-response";
        let mut chain = uni_iobuf::IOBufChain::from(body.to_vec());
        super::async_try_send_chain(handle, generation, &mut chain)
            .expect("an established connection accepts the send");

        // The client acknowledges the whole response.
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: CLIENT_ISN.wrapping_add(1),
            ack: server_isn.wrapping_add(1 + body.len() as u32),
            flags: TCP_ACK,
            window: 65535,
            payload: Vec::new(),
        });

        // The timer is disarmed: even far past the original RTO the
        // tick produces nothing.
        clear_tx();
        kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 * 4);
        super::on_rtx_tick();
        assert!(
            tx().is_empty(),
            "fully-acknowledged data is never retransmitted",
        );
    }

    /// RFC 6298 §2: the RTT estimator seeds SRTT/RTTVAR from the first
    /// measurement (§2.2) and tracks with the EWMA thereafter (§2.3);
    /// the RTO follows `SRTT + 4·RTTVAR`, clamped to the 1 s floor.
    #[test]
    fn rtt_estimator_tracks_rfc6298() {
        // The estimator math is pure — exercise it on a bare TCB.
        let mut c = TcpConnection::new();

        // §2.1: before any measurement the RTO is the 1 s initial value.
        assert_eq!(c.estimated_rto(), RTO_INITIAL_MS);

        // §2.2: first sample R → SRTT = R, RTTVAR = R/2.
        c.sample_rtt(400);
        assert_eq!(c.srtt_ms, 400, "SRTT seeds to the first sample");
        assert_eq!(c.rttvar_ms, 200, "RTTVAR seeds to R/2");
        // RTO = SRTT + 4·RTTVAR = 400 + 800 = 1200.
        assert_eq!(c.estimated_rto(), 1200);

        // §2.3: a second sample folds in (alpha = 1/8, beta = 1/4) —
        // RTTVAR is updated first, against the *old* SRTT.
        c.sample_rtt(440);
        // RTTVAR = 200 - 200/4 + |400-440|/4 = 150 + 10 = 160.
        assert_eq!(c.rttvar_ms, 160);
        // SRTT  = 400 - 400/8 + 440/8 = 350 + 55 = 405.
        assert_eq!(c.srtt_ms, 405);
        assert_eq!(c.estimated_rto(), 405 + 4 * 160);

        // §2.4: a steady low RTT drives the estimate below 1 s, where
        // it is clamped up to the floor.
        for _ in 0..60 {
            c.sample_rtt(20);
        }
        assert_eq!(
            c.estimated_rto(),
            RTO_INITIAL_MS,
            "a low, steady RTT clamps the RTO at the 1 s floor",
        );
    }

    /// Locate the live (non-listener) connection for a client/server
    /// port pair and return its `(handle, generation)` so a scenario
    /// can drive the real send path (`async_try_send_chain`).
    fn conn_handle(client_port: u16, server_port: u16) -> (*mut (), u16) {
        let core = 0u32;
        let cap = pool_capacity(core);
        for i in 0..cap {
            // SAFETY: single worker, test-serialised by TEST_LOCK.
            let c = unsafe { &*conn_ptr(core, i) };
            if c.state != TcpState::Closed
                && c.state != TcpState::Listen
                && c.local_port == server_port
                && c.remote_port == client_port
            {
                return (encode_handle(core, i), c.generation);
            }
        }
        panic!("no live connection for ports {client_port} -> {server_port}");
    }

    /// Drive a full three-way handshake on `(server_port, client_port)`
    /// and return the server's chosen ISN (read from the SYN|ACK).
    fn handshake(server_port: u16, client_port: u16, client_isn: u32) -> u32 {
        deliver(&Seg {
            src_port: client_port,
            dst_port: server_port,
            seq: client_isn,
            ack: 0,
            flags: TCP_SYN,
            window: 65535,
            payload: Vec::new(),
        });
        let server_isn = tcp_hdr(&tx()[0]).seq;
        deliver(&Seg {
            src_port: client_port,
            dst_port: server_port,
            seq: client_isn.wrapping_add(1),
            ack: server_isn.wrapping_add(1),
            flags: TCP_ACK,
            window: 65535,
            payload: Vec::new(),
        });
        server_isn
    }
}
