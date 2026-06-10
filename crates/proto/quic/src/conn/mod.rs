// crates/proto/quic/src/conn/mod.rs — QUIC server-side connection state
// machine (RFC 9000 + RFC 9001).
//
// One `Connection` per client. Holds: per-direction packet
// protection keys (Initial / Handshake / 1-RTT), per-PN-space
// packet number state, ACK tracking, the TLS handshake driver
// (`QuicTls`), and outbound packet assembly buffers.
//
// Sans-io: caller (the UDP reactor in `endpoint.rs`) feeds
// inbound datagrams via `process_datagram`, drains outbound
// packets via `pop_packet_owned` (returns a `DatagramBuf` —
// either a heap Vec or a wrapper around a driver TX-pool slot
// the encoder wrote into directly). No allocation on the
// steady-state hot path when the driver TX pool has slots;
// the only `Vec` growth is the per-level CRYPTO byte queue
// inside `QuicTls`.
//
// Per the architectural decisions (per-core conn pool, no
// cross-core access, one async task per conn): no Arc, no
// Mutex. The connection is owned by a single task on a single
// core and the task `.await`s on UDP recv → `process_datagram`
// → outbound flush → repeat.
//
// Scope (this commit — server-side handshake MVP):
//   * Initial-packet decode + reply (ServerHello in Initial,
//     EE/Cert/CV/Finished in Handshake)
//   * Handshake-packet decode + reply (ACKs)
//   * Client Finished verification → Established
//   * HANDSHAKE_DONE emission in 1-RTT
//   * Delayed/piggybacked 1-RTT ACK (RFC 9000 §13.2.1) carrying
//     multi-range ACK frames built from a received-PN range set
//   * Coalesced packets (Initial+Handshake in one datagram —
//     standard rustls / quinn client behavior)
//
// Out of scope (see docs/conformance-roadmap.md for the live list):
//   * 0-RTT / early data
//   * Stateless reset
//   * CID rotation (NEW/RETIRE_CONNECTION_ID) + WE-initiated
//     PATH_CHALLENGE on a migrated path (we answer the peer's, and
//     auth-gate the TX-address follow, but don't probe a new path
//     ourselves)
//   * Per-stream abort: generating RESET_STREAM / honoring STOP_SENDING
//     (both are parsed past today, not acted on)
//
// (Loss detection + RFC 9002 retransmission, the stream layer, NewReno/
// CUBIC congestion control, pacing, key update, and connection close all
// landed since this header was first written.)
//
// Module layout (under `conn/`):
//
//   mod.rs    — public types (`ConnError`, `ConnState`,
//               `ConnectionId`, `DatagramBuf`), the `Connection`
//               struct definition + constructor, basic accessors,
//               stream API, and shared bookkeeping types
//               (`SpaceState`, `SentPacket`).
//   keys.rs   — `DirKeys` (per-direction packet protection cipher
//               cache) + key-derivation hooks (`rotate_recv_keys`,
//               `advance_tls`).
//   rx.rs     — inbound packet processing: `process_datagram`,
//               per-level `process_*` packet handlers, header /
//               AEAD unprotect, frame dispatch.
//   tx.rs     — outbound packet assembly: `flush_outbound`,
//               per-level `encode_*_packet`, AEAD seal + HP
//               protect, anti-amplification, CONNECTION_CLOSE.
//   loss.rs   — RFC 9002 loss detection + RTT estimation:
//               `process_ack`, `detect_loss`, `update_rtt`,
//               `record_sent_packet`, PTO timer + probe.

use alloc::vec::Vec;

use crate::tls::{QuicTls, QuicTlsError};
use core::mem::ManuallyDrop;

pub(super) mod keys;
pub(super) mod loss;
pub(super) mod rx;
pub(super) mod tx;

#[cfg(test)]
mod cfg;

// Sibling submodules (`rx`, `tx`, `loss`) reach `DirKeys` via
// `super::DirKeys`; this brings it into the `conn` module path so
// the struct's storage on `Connection` (and the test-module
// references) resolve.
use keys::DirKeys;

// ============================================================================
// Aggregate receive-buffer budget (admission control, the #75 residual)
// ============================================================================
//
// Per-conn receive flow control caps EACH connection's buffered (received-
// but-undrained) bytes at the connection MAX_DATA window (8 MiB). The
// per-worker conn-admission heap gate (inbox.rs) sheds NEW connections under
// memory pressure. Neither bounds the AGGREGATE of already-established
// connections each filling their window: 8192 conns × 8 MiB = 64 GiB ≫ heap.
//
// This is the global byte budget that closes that: one relaxed counter of
// buffered recv bytes summed across all live QUIC connections. When it
// exceeds `AGGREGATE_RECV_BUDGET`, the MAX_DATA grant stops sliding the
// window forward, so peers' connection windows drain toward zero and they
// stop sending (graceful flow-control back-pressure) — instead of growing
// our buffers until the heap gate hard-refuses or OOM. As other connections
// drain, the budget frees and crediting resumes.
//
// One global atomic, not per-worker: recv STREAM frames are not the hottest
// path (per stream-frame, not per packet), the budget is soft, and a global
// counter avoids any per-worker plumbing while still bounding total memory.
use core::sync::atomic::{AtomicU64, Ordering};

/// Global ceiling on bytes buffered (received-but-undrained) across every
/// live QUIC connection. ~256 MiB leaves generous room for a high upload
/// fan-in (32 simultaneous full 8 MiB windows) while bounding total recv
/// memory well under any production heap. Over budget ⇒ MAX_DATA stops
/// sliding ⇒ back-pressure.
pub(crate) const AGGREGATE_RECV_BUDGET: u64 = 256 * 1024 * 1024;

static RECV_BUFFERED: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod recv_budget_tests {
    use super::{
        recv_buffer_over_budget, recv_buffered_add, recv_buffered_now, recv_buffered_sub,
        AGGREGATE_RECV_BUDGET,
    };

    // The counter is a process-global static; one test (not several)
    // so parallel test threads don't race on it. Nothing else in the
    // suite touches `RECV_BUFFERED`, so starting from 0 is sound.
    #[test]
    fn add_sub_threshold_and_saturation() {
        assert_eq!(recv_buffered_now(), 0, "no other test touches the budget");
        // Exactly at budget is NOT over; one past trips.
        recv_buffered_add(AGGREGATE_RECV_BUDGET);
        assert!(!recv_buffer_over_budget(), "exactly at budget is not over");
        recv_buffered_add(1);
        assert!(recv_buffer_over_budget(), "one past budget trips");
        // Release everything; back to 0, not over.
        recv_buffered_sub(AGGREGATE_RECV_BUDGET + 1);
        assert_eq!(recv_buffered_now(), 0);
        assert!(!recv_buffer_over_budget());
        // Over-subtracting floors at 0 (no wrap to u64::MAX).
        recv_buffered_sub(1_000_000);
        assert_eq!(recv_buffered_now(), 0);
    }
}

/// Add `n` newly-buffered recv bytes to the global aggregate.
#[inline]
pub(crate) fn recv_buffered_add(n: u64) {
    RECV_BUFFERED.fetch_add(n, Ordering::Relaxed);
}

/// Remove `n` bytes from the global aggregate (drained by the app, or
/// freed when a connection holding them is dropped). Saturating so a
/// double-subtract can't wrap the counter into a huge value.
#[inline]
pub(crate) fn recv_buffered_sub(n: u64) {
    if n != 0 {
        // `fetch_update` with a saturating floor at 0 — relaxed is fine
        // (soft budget; single-writer-per-conn keeps drift bounded).
        let _ = RECV_BUFFERED.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
            Some(cur.saturating_sub(n))
        });
    }
}

/// Whether the aggregate recv buffer is over budget — the gate read by the
/// MAX_DATA grant.
#[inline]
pub(crate) fn recv_buffer_over_budget() -> bool {
    RECV_BUFFERED.load(Ordering::Relaxed) > AGGREGATE_RECV_BUDGET
}

/// Current aggregate (for `/obs`).
#[inline]
pub(crate) fn recv_buffered_now() -> u64 {
    RECV_BUFFERED.load(Ordering::Relaxed)
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnError {
    /// Malformed packet header / frame, oversize CID, etc.
    Wire,
    /// AEAD-tag mismatch — wrong keys or corruption.
    Decrypt,
    /// TLS handshake refused the inbound CRYPTO bytes.
    Tls,
    /// Caller-supplied output buffer too small.
    OutputTooSmall,
    /// State doesn't permit this operation (e.g. drain outbound
    /// before any inbound).
    BadState,
    /// Unsupported QUIC version (server should respond with
    /// Version Negotiation; out of scope for v1).
    UnsupportedVersion,
}

impl From<QuicTlsError> for ConnError {
    fn from(_: QuicTlsError) -> Self {
        ConnError::Tls
    }
}

// ============================================================================
// Connection ID
// ============================================================================

/// Re-export the canonical SERVER_CID_LEN from `inbox`. The two
/// modules need to agree on this; the source of truth lives next
/// to the slot-encoding helpers (make_local_cid / parse_local_cid).
pub use crate::inbox::SERVER_CID_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionId {
    bytes: [u8; 20],
    len: u8,
}

impl ConnectionId {
    pub fn new(bytes: &[u8]) -> Self {
        let mut buf = [0u8; 20];
        let n = bytes.len().min(20);
        buf[..n].copy_from_slice(&bytes[..n]);
        ConnectionId {
            bytes: buf,
            len: n as u8,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ============================================================================
// Per-PN-space state
// ============================================================================

#[derive(Default)]
pub(super) struct SpaceState {
    /// Next packet number we'll use for an outgoing packet.
    pub(super) next_send_pn: u64,
    /// Largest PN we've successfully decoded inbound. `None` if
    /// nothing received yet.
    pub(super) largest_recv_pn: Option<u64>,
    /// Whether we owe the peer an ACK that hasn't been bundled
    /// into an outbound packet yet.
    pub(super) ack_pending: bool,
    /// Largest packet number the peer has acknowledged in this
    /// space. `None` until the first ACK arrives. Used by RFC 9002
    /// loss detection to compute the packet-threshold cutoff.
    pub(super) largest_acked: Option<u64>,
    /// Per-packet send records, keyed by packet number, for every
    /// outbound packet that hasn't been ACKed or declared lost yet.
    /// RFC 9002 §A.1 names this `sent_packets`. Removed on ACK;
    /// walked by loss detection to find packets that fell behind
    /// `largest_acked - kPacketThreshold`.
    pub(super) sent_packets: SentPackets,
    /// Received packet-number ranges, inclusive `(lo, hi)`, sorted
    /// **descending** by `hi`, disjoint and non-adjacent. Source of
    /// truth for [`Connection::append_ack_frame`]'s First/Additional
    /// ACK Range encoding (RFC 9000 §19.3). In-order receive keeps
    /// this a single range; only loss/reorder splits it. We never
    /// trim acknowledged PNs off the bottom (no ACK-of-ACK GC) — the
    /// lone bottom range's `first_range` just grows as a varint, and
    /// re-reporting it is idempotent for the peer.
    pub(super) recv_ranges: Vec<(u64, u64)>,
}

/// Cap on tracked received-PN ranges per space. Bounds the ACK
/// frame size and memory under pathological reorder/loss; in-order
/// traffic uses one range. When exceeded we drop the lowest range —
/// we simply stop acknowledging those PNs, which is safe (the peer
/// may retransmit them).
pub(super) const MAX_RECV_RANGES: usize = 32;

impl SpaceState {
    /// Record receipt of packet number `pn`: advance `largest_recv_pn`
    /// and merge `pn` into [`recv_ranges`](Self::recv_ranges) so a
    /// delayed/coalesced ACK reports every PN received since the last
    /// one (RFC 9000 §13.2.1). In-order arrival hits the O(1) fast
    /// path (extend the top range); gaps walk the small range list.
    pub(super) fn record_recv_pn(&mut self, pn: u64) {
        self.largest_recv_pn = Some(self.largest_recv_pn.map_or(pn, |x| x.max(pn)));
        let ranges = &mut self.recv_ranges;
        // Insertion point: first range whose `hi` is below `pn`
        // (ranges descending by `hi`). The in-order case breaks at
        // i == 0 immediately.
        let mut i = 0;
        while i < ranges.len() {
            let (lo, hi) = ranges[i];
            if pn > hi {
                break;
            }
            if pn >= lo {
                return; // duplicate — already covered
            }
            i += 1;
        }
        // `ranges[i-1]` (if any) sits above `pn` (hi >= pn, lo > pn);
        // `ranges[i]` (if any) sits below (`hi < pn`).
        let touch_above = i > 0 && ranges[i - 1].0 == pn + 1;
        let touch_below = i < ranges.len() && ranges[i].1 + 1 == pn;
        match (touch_above, touch_below) {
            // `pn` bridges the gap between two ranges → merge them.
            (true, true) => {
                ranges[i - 1].0 = ranges[i].0;
                ranges.remove(i);
            }
            (true, false) => ranges[i - 1].0 = pn,
            (false, true) => ranges[i].1 = pn,
            (false, false) => {
                if ranges.len() < MAX_RECV_RANGES {
                    ranges.insert(i, (pn, pn));
                } else if i < ranges.len() {
                    // Table full: drop the lowest range to make room
                    // for this higher one. (If `pn` is below every
                    // tracked range we simply drop it — safe.)
                    ranges.pop();
                    ranges.insert(i.min(ranges.len()), (pn, pn));
                }
            }
        }
    }
}

/// One in-flight send. Stored per-PN per-space until the peer
/// acknowledges or loss detection declares it lost. RFC 9002 §A.1
/// calls this `SentPacketInfo`. We track only the metadata that
/// matters to current loss detection / RTT estimation; frame
/// retransmission state lives on the streams + handshake queues.
#[derive(Clone, Debug)]
pub(super) struct SentPacket {
    /// Microseconds-since-boot when we sealed and queued this packet.
    /// `now() - time_sent_us` on ACK = RTT sample (RFC 9002 §5.1).
    pub(super) time_sent_us: u64,
    /// `true` if the packet contains any frame other than ACK / PADDING /
    /// CONNECTION_CLOSE — i.e. one the peer must acknowledge. Non-
    /// eliciting packets are not subject to PTO and are not RTT
    /// samples even when later "acknowledged" implicitly.
    pub(super) ack_eliciting: bool,
    /// `true` if the packet counts against congestion-control bytes-
    /// in-flight. RFC 9002 §2: a packet is in flight iff it's ack-
    /// eliciting, or contains PADDING. We piggyback on `ack_eliciting`
    /// for the simple cases — both flags currently coincide for our
    /// stack (we don't pad-only) but keep them split for clarity.
    /// Read by `detect_loss` / `process_ack` to drive `bytes_in_flight`.
    pub(super) in_flight: bool,
    /// On-the-wire byte count of the sealed packet. Drives
    /// `bytes_in_flight` (the cwnd gate) on send/ack/loss.
    pub(super) byte_count: u32,
    /// STREAM frames this packet carried, retained for retransmission
    /// (RFC 9002 §6 / RFC 9000 §13.3). On loss these move to
    /// `Connection::retx_queue` to be re-sent; on ACK the packet (and
    /// these copies) are dropped. Empty for non-data packets (ACK-only,
    /// PING probes, CRYPTO). The retained bytes are bounded by
    /// bytes-in-flight (≤ cwnd), so this can't grow without bound.
    pub(super) stream_frames: alloc::vec::Vec<StreamRetx>,
    /// CRYPTO frames this packet carried, retained for retransmission
    /// (RFC 9002 §6.2 / RFC 9000 §13.3). On loss these move to
    /// `Connection::crypto_retx_queue` and are re-emitted at their
    /// original offset in the same packet-number space; on ACK the
    /// packet (and these copies) are dropped. Empty for non-CRYPTO
    /// packets. A handshake flight is bounded, so this can't grow
    /// without bound.
    pub(super) crypto_frames: alloc::vec::Vec<CryptoRetx>,
}

/// One CRYPTO frame's retransmittable contents — the packet-number
/// space it belongs to (Initial vs Handshake have independent CRYPTO
/// streams and offsets), the offset in that stream, and a copy of the
/// fragment bytes. Held in a [`SentPacket`] until acked (dropped) or
/// lost (moved to [`Connection::crypto_retx_queue`] and re-emitted at
/// `offset`). Each fragment is ≤ one packet's CRYPTO payload, so
/// re-emitting fits one packet.
#[derive(Clone, Debug)]
pub(super) struct CryptoRetx {
    pub(super) level: crate::tls::CryptoLevel,
    pub(super) offset: u64,
    pub(super) data: alloc::vec::Vec<u8>,
}

/// One STREAM frame's retransmittable contents — the offset, FIN bit,
/// and a copy of the data bytes. Held in a [`SentPacket`] until the
/// packet is acked (then dropped) or declared lost (then moved to
/// [`Connection::retx_queue`] and re-emitted). Each copy is ≤ one
/// packet's STREAM payload (~1100 B), so re-emitting fits one packet.
#[derive(Clone, Debug)]
pub(super) struct StreamRetx {
    pub(super) sid: u64,
    pub(super) offset: u64,
    pub(super) fin: bool,
    pub(super) data: alloc::vec::Vec<u8>,
}

/// Per-space record of sent-but-unresolved packets (RFC 9002 §A.1
/// `sent_packets`). Packet numbers are monotonic and contiguous within a
/// space, so instead of a `BTreeMap<pn, _>` (a heap node + `O(log n)` per
/// op) this is a ring of slots indexed by `pn - base_pn`: `O(1)` insert
/// (push_back), `O(1)` lookup/remove by pn, alloc-free amortized (the
/// `VecDeque` reuses its buffer). A removed PN leaves a `None` hole for an
/// out-of-order ACK/loss; the hole is reclaimed (and `base_pn` advanced)
/// once it reaches the front. Length is bounded by the in-flight PN span
/// (≈ cwnd), exactly like the map it replaces. The ACK path removes a
/// whole range in `O(range)` instead of `O(range·log n)`.
#[derive(Default, Debug)]
pub(super) struct SentPackets {
    base_pn: u64,
    slots: alloc::collections::VecDeque<Option<SentPacket>>,
    /// Count of live (`Some`) slots — `O(1)` `len`/`is_empty`.
    live: usize,
}

impl SentPackets {
    /// Record a freshly-sent packet. PNs arrive monotonically; the common
    /// case is `idx == slots.len()` (a plain push_back). A skipped PN
    /// (never happens — PNs are contiguous per space) pads with holes.
    pub(super) fn insert(&mut self, pn: u64, pkt: SentPacket) {
        if self.slots.is_empty() {
            self.base_pn = pn;
        }
        debug_assert!(pn >= self.base_pn, "sent_packets: pn < base_pn");
        if pn < self.base_pn {
            return; // guard against underflow; unreachable in practice
        }
        let idx = (pn - self.base_pn) as usize;
        while self.slots.len() <= idx {
            self.slots.push_back(None);
        }
        if self.slots[idx].is_none() {
            self.live += 1;
        }
        self.slots[idx] = Some(pkt);
    }

    /// Remove and return the packet with number `pn` (if still tracked),
    /// then reclaim any leading resolved holes so `base_pn` tracks the
    /// oldest unresolved PN and the deque stays bounded.
    pub(super) fn remove(&mut self, pn: u64) -> Option<SentPacket> {
        if pn < self.base_pn {
            return None;
        }
        let idx = (pn - self.base_pn) as usize;
        let taken = self.slots.get_mut(idx).and_then(|s| s.take());
        if taken.is_some() {
            self.live -= 1;
        }
        while matches!(self.slots.front(), Some(None)) {
            self.slots.pop_front();
            self.base_pn += 1;
        }
        taken
    }

    /// Iterate `(pn, &SentPacket)` over live packets in ascending PN order
    /// (matches the old `BTreeMap::iter`, on which loss detection relies to
    /// break at the first PN ≥ `largest_acked`).
    pub(super) fn iter(&self) -> impl Iterator<Item = (u64, &SentPacket)> + '_ {
        let base = self.base_pn;
        self.slots
            .iter()
            .enumerate()
            .filter_map(move |(i, s)| s.as_ref().map(|p| (base + i as u64, p)))
    }

    /// Iterate `&SentPacket` over live packets (order-agnostic callers —
    /// e.g. `discard_sent_packets` summing in-flight bytes).
    pub(super) fn values(&self) -> impl Iterator<Item = &SentPacket> + '_ {
        self.slots.iter().filter_map(|s| s.as_ref())
    }

    pub(super) fn len(&self) -> usize {
        self.live
    }

    pub(super) fn is_empty(&self) -> bool {
        self.live == 0
    }

    pub(super) fn clear(&mut self) {
        self.slots.clear();
        self.live = 0;
        self.base_pn = 0;
    }
}

/// Pop every PN in `[low, high]` (inclusive) from `sent_packets`,
/// stashing the entry whose PN equals `target_pn` (the ACK's
/// `largest_acknowledged`) into `largest_out` so the caller can use
/// it for an RTT sample. Inclusive both ends; safe when the range
/// is sparse (most PNs have already been removed by previous ACKs).
pub(super) fn ack_remove_range(
    space: &mut SpaceState,
    low: u64,
    high: u64,
    target_pn: u64,
    largest_out: &mut Option<SentPacket>,
    acked_in_flight_bytes: &mut u32,
) {
    if low > high {
        return;
    }
    // Drain via BTreeMap::remove since the range is typically
    // tight (a few packets at a time); for large ranges the
    // explicit loop is still O((high-low) * log n) which is fine.
    let mut pn = high;
    loop {
        if let Some(pkt) = space.sent_packets.remove(pn) {
            // Release its congestion-control bytes-in-flight (RFC 9002
            // §7.8 OnPacketAcked); accumulated for the caller's `on_ack`.
            if pkt.in_flight {
                *acked_in_flight_bytes = acked_in_flight_bytes.saturating_add(pkt.byte_count);
            }
            if pn == target_pn {
                *largest_out = Some(pkt);
            }
        }
        if pn == low {
            break;
        }
        pn = pn.wrapping_sub(1);
    }
}

// ============================================================================
// Connection
// ============================================================================

/// QUIC v1 connection lifecycle (server side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// Created but no Initial received yet (transient — only
    /// observable to internal callers between `new` and the
    /// first `process_datagram`).
    PreHandshake,
    /// Handshake in progress (Initial / Handshake records flowing).
    Connecting,
    /// Handshake complete; server has emitted HANDSHAKE_DONE.
    Established,
    /// Fatal protocol error; future operations are no-ops.
    Failed,
}

/// Outbound datagram buffer. Either heap-allocated (the
/// `Heap` variant — fallback for backends that don't expose
/// the SG TX surface, or when the driver pool is full) or
/// backed by a driver TX-pool slot (the `TxSlot` variant —
/// the zero-copy hot path: encoder writes packet bytes
/// directly into the slot's `data` region, the bare-metal UDP
/// backend fills the L2/L3/L4 headers in the headroom in place
/// and submits the slot's descriptor without memcpy'ing the
/// payload).
///
/// The encoder reads/writes via [`vec_mut`](Self::vec_mut),
/// which returns a `&mut Vec<u8>` regardless of variant. For
/// `TxSlot`, that Vec is a `ManuallyDrop<Vec<u8>>` whose
/// allocation is the driver-owned slot's `data` field — `push`
/// / `extend_from_slice` write straight into the slot. The
/// encoder's max write (≤ ~1300 B for handshake-coalesced
/// datagrams, ≤ ~1100 B for 1-RTT under PACKET_BODY_BUDGET)
/// stays under the slot's 1514 B capacity, so Vec never
/// reallocates and the ManuallyDrop wrapping never lets it
/// dealloc the driver-owned memory.
///
/// SAFETY contract for `TxSlot::vec`:
///   * `vec.as_mut_ptr()` == `handle.data_ptr` (set at
///     construction in `take_datagram_buf`).
///   * `vec.capacity()` == `handle.data_cap` (1514 today).
///   * No code path on the Vec calls `reserve`, `with_capacity`,
///     `set_len(>cap)`, or any other realloc-triggering method.
///     Audited per-encoder-fn at the time of writing
///     (`out.push`, `out.extend_from_slice`, `out.truncate`,
///     `out.split_at_mut`, slice indexing — never `reserve`).
pub enum DatagramBuf {
    /// Heap-allocated Vec. Used as fallback when
    /// [`executor::reactor::acquire_tx_buf`] returns `None`.
    Heap(Vec<u8>),
    /// Vec wrapping a driver TX-pool slot. The handle's `Drop`
    /// returns the slot to the pool if the buf is dropped
    /// without going through [`Self::into_tx_handle`]; once
    /// `into_tx_handle` extracts the handle for submission, the
    /// slot stays in-flight until the device signals descriptor
    /// completion via the driver's `tx_drain`.
    TxSlot {
        handle: nic_api::TxBufHandle,
        vec: ManuallyDrop<Vec<u8>>,
    },
    /// Big-pool slot holding N back-to-back QUIC packets (each
    /// `gso_size` bytes) for hardware UDP segmentation. The encoder
    /// seals N packets in place; `ship_datagram` hands the driver one
    /// segmentation descriptor and the device splits it into N UDP
    /// datagrams. Same `ManuallyDrop`-over-driver-slot contract as
    /// `TxSlot`, but the slot is from the TSO/GSO big pool (≈16-20 KiB)
    /// and submitted via `submit_tx_udp_gso`, not `submit_tx`.
    GsoSlot {
        handle: nic_api::TxUdpGsoBufHandle,
        vec: ManuallyDrop<Vec<u8>>,
        gso_size: u16,
    },
}

impl DatagramBuf {
    /// Mutable access to the inner Vec — the encoder's write
    /// surface. For TxSlot, dereferences through ManuallyDrop;
    /// the resulting `&mut Vec<u8>` IS a real Vec from the
    /// encoder's perspective.
    pub fn vec_mut(&mut self) -> &mut Vec<u8> {
        match self {
            DatagramBuf::Heap(v) => v,
            DatagramBuf::TxSlot { vec, .. } => vec,
            DatagramBuf::GsoSlot { vec, .. } => vec,
        }
    }

    /// Read-only access to the inner Vec.
    pub fn vec(&self) -> &Vec<u8> {
        match self {
            DatagramBuf::Heap(v) => v,
            DatagramBuf::TxSlot { vec, .. } => vec,
            DatagramBuf::GsoSlot { vec, .. } => vec,
        }
    }

    /// Bytes currently written (= `vec().len()`). Includes the
    /// L2/L3/L4 headroom prefix the encoder pre-fills via
    /// [`Connection::take_datagram_buf`].
    pub fn len(&self) -> usize {
        self.vec().len()
    }

    /// True iff no bytes have been written (headroom not yet
    /// reserved either).
    pub fn is_empty(&self) -> bool {
        self.vec().is_empty()
    }

    /// Whether this buf is backed by a driver TX-pool slot.
    /// `true` iff [`Self::into_tx_handle`] would succeed.
    pub fn is_tx_slot(&self) -> bool {
        matches!(self, DatagramBuf::TxSlot { .. })
    }

    /// Whether this buf is a UDP-GSO big-pool super-packet.
    pub fn is_gso_slot(&self) -> bool {
        matches!(self, DatagramBuf::GsoSlot { .. })
    }

    /// Consume a `GsoSlot` and return its handle + frame_len + gso_size
    /// for `submit_tx_udp_gso`. Returns the buf back via `Err(self)`
    /// for non-GSO variants. Same reallocation tripwire as
    /// [`Self::into_tx_handle`].
    pub fn into_gso_handle(self) -> Result<(nic_api::TxUdpGsoBufHandle, usize, u16), Self> {
        match self {
            DatagramBuf::GsoSlot {
                handle,
                vec,
                gso_size,
            } => {
                let len = vec.len();
                assert!(
                    core::ptr::eq(vec.as_ptr(), handle.0.data_ptr as *const u8),
                    "QUIC GSO datagram reallocated off its {}-byte driver slot",
                    handle.0.data_cap,
                );
                let _ = vec;
                Ok((handle, len, gso_size))
            }
            other => Err(other),
        }
    }

    /// Consume the buf and return its TxBufHandle + frame_len
    /// for submission. Only succeeds for the `TxSlot` variant;
    /// `Heap`-variant returns the buf back via `Err(self)` so
    /// the caller can fall back to a slice-shaped send.
    pub fn into_tx_handle(self) -> Result<(nic_api::TxBufHandle, usize), Self> {
        match self {
            DatagramBuf::TxSlot { handle, vec } => {
                let len = vec.len();
                // Tripwire. If the encoder ever overran the slot,
                // the `Vec` reallocated and `as_ptr()` no longer
                // points at the driver slot — which means the slot
                // pointer was already freed through the heap
                // allocator (heap corruption). Fail-stop loudly
                // here, naming the cause, rather than let a later
                // unrelated `talc::free` fault on the damage. The
                // `data_cap` gate in `take_datagram_buf` plus the
                // encoder's `MAX_QUIC_DATAGRAM` budget make this
                // unreachable in correct code — it is a guard
                // against a future regression, not a live path.
                assert!(
                    core::ptr::eq(vec.as_ptr(), handle.data_ptr as *const u8),
                    "QUIC TX datagram reallocated off its {}-byte driver \
                     slot — the encoder overran the TX-pool buffer",
                    handle.data_cap,
                );
                // `vec` is `ManuallyDrop<Vec<u8>>` wrapping the
                // driver-owned slot. Dropping the wrapper is a
                // no-op (it doesn't dealloc the slot), so the
                // pattern just falls out of scope here. The
                // handle moves out for submission; the driver
                // releases the slot via the handle's `Drop` after
                // the device signals descriptor completion.
                let _ = vec;
                Ok((handle, len))
            }
            other => Err(other),
        }
    }

    /// Recycle this buf back to the conn's outbound_pool. For
    /// `TxSlot`, the slot is implicitly returned by handle's
    /// `Drop` — nothing to recycle on the pool side. For `Heap`,
    /// `clear()` and return the Vec to the pool.
    pub(crate) fn recycle_into(self, pool: &mut Vec<Vec<u8>>, pool_max: usize) {
        match self {
            DatagramBuf::Heap(mut v) => {
                if pool.len() < pool_max {
                    v.clear();
                    pool.push(v);
                }
            }
            DatagramBuf::TxSlot { .. } => {
                // Drop fires `handle.Drop` → `release_fn` → slot
                // back to pool.
            }
            DatagramBuf::GsoSlot { .. } => {
                // Big-pool slot; handle's `Drop` returns it (or the
                // device's PKT completion frees it once submitted).
            }
        }
    }
}

/// The largest QUIC datagram — L2/L3/L4 headroom prefix **plus**
/// wire bytes — the encoder is permitted to produce. It does two
/// jobs:
///
///   * **Protocol.** Keeps every datagram within the conservative
///     1200-byte QUIC path-MTU floor (RFC 9000 §14.1) plus the
///     62-byte headroom, so the server's handshake flight is never
///     IP-fragmented.
///   * **Memory safety.** A [`DatagramBuf::TxSlot`] wraps a
///     driver-owned TX-pool slot in a `Vec` that MUST NOT
///     reallocate — a realloc frees the slot pointer (NIC DMA
///     memory, not a heap allocation) through the global allocator
///     and corrupts the heap. [`Connection::take_datagram_buf`]
///     only takes the zero-copy `TxSlot` path when the slot's
///     capacity is at least this value, so a bounded encode can
///     never grow the `Vec` past the slot.
///
/// Sized above the encoder's true worst case (~1200 B for a 1-RTT
/// packet; ~1100 B for an Initial + first-Handshake-fragment
/// datagram) with margin. Both shipping drivers' TX slots clear it
/// comfortably — gve 2048 B, virtio-net 1514 B.
pub(super) const MAX_QUIC_DATAGRAM: usize = 1400;

/// Maximum Handshake-level CRYPTO bytes packed into a single
/// Handshake packet. The server flight (EncryptedExtensions +
/// Certificate + CertificateVerify + Finished) exceeds one packet
/// for any real leaf+intermediate cert chain, so `flush_outbound`
/// fragments the Handshake CRYPTO stream across several packets,
/// each carrying at most this many bytes. Chosen so a Handshake
/// packet — even coalesced behind an Initial in the first datagram
/// — stays under [`MAX_QUIC_DATAGRAM`]. A small fixed-size drain
/// buffer (`[0u8; HS_CRYPTO_BUDGET]`) makes an oversized handshake
/// packet structurally unrepresentable.
pub(super) const HS_CRYPTO_BUDGET: usize = 768;

pub struct Connection {
    pub(super) state: ConnState,

    /// Our chosen connection ID. Sent as SCID on the server's
    /// Initial reply; clients use it as DCID on subsequent
    /// packets to us. Per-core conn pool indexes by this.
    pub(super) local_cid: ConnectionId,

    /// Client's chosen connection ID. Sent as SCID on their
    /// Initial; we use as DCID on outgoing packets to them.
    pub(super) peer_cid: ConnectionId,

    /// The DCID the client picked for its very first Initial.
    /// Only used to seed Initial-packet protection keys
    /// (RFC 9001 §5.2). Discarded once Initial keys are derived.
    pub(super) initial_dcid: ConnectionId,

    pub(super) initial_send: Option<DirKeys>,
    pub(super) initial_recv: Option<DirKeys>,
    pub(super) handshake_send: Option<DirKeys>,
    pub(super) handshake_recv: Option<DirKeys>,
    pub(super) application_send: Option<DirKeys>,
    pub(super) application_recv: Option<DirKeys>,
    /// Sticky flag set once we've discarded our Initial keys per
    /// RFC 9001 §4.9.1 (first received Handshake packet). Without
    /// this flag, `process_initial`'s `initial_recv.is_none()`
    /// branch would helpfully re-derive Initial keys from a stale
    /// retransmit's DCID — letting it decrypt + dispatch frames
    /// from a peer that has long moved past Initial. The flag
    /// gates the derive arm so straggler Initials fall through to
    /// the late-drop counter instead.
    pub(super) initial_keys_discarded: bool,
    /// Mirror of `initial_keys_discarded` for Handshake keys —
    /// set when the TLS handshake reaches Established (RFC 9001
    /// §4.9.2). Gates `process_handshake_pkt` against late
    /// retransmits.
    pub(super) handshake_keys_discarded: bool,
    /// When true, the per-core egress owner (docs/tx-backpressure.md stage 3)
    /// drives steady-state 1-RTT packet emission build-at-drain — so `flush`
    /// must NOT also build per-packet 1-RTT into `outbound` (that would
    /// double-send). Set by the conn task iff this conn registered with the
    /// owner. False — the eager/heap build path — is NOT dead code: it is
    /// the live fallback when the embedding app never enabled the egress
    /// scheduler (tests, other apps) and when `egress::register` finds this
    /// core's flow table full (the 1025th concurrent conn on a core ships
    /// inline). The handshake + GSO paths build into `outbound` regardless
    /// (the owner ships those).
    pub(super) tx_owner_driven: bool,
    /// 0-RTT (early-data) packet-protection keys for *receiving*.
    /// `Some` only on a resumed handshake whose PSK validated;
    /// derived from `QuicTls::client_early_traffic_secret` once the
    /// CH has been parsed. The server never sends 0-RTT, so there's
    /// no `early_send` counterpart.
    pub(super) early_recv: Option<DirKeys>,
    /// 0-RTT packets that arrived before we'd derived `early_recv`
    /// — typically because they were coalesced with (or arrived
    /// before) the LAST fragment of a multi-packet ClientHello.
    /// Drained and replayed by `advance_tls` the moment
    /// `early_recv` becomes available; cleared (without replay)
    /// once the handshake reaches Established without resumption,
    /// since at that point we'll never be able to decrypt them.
    /// Capped to avoid an unbounded memory footprint from a
    /// flood-attempting peer.
    pub(super) pending_zero_rtt: Vec<Vec<u8>>,

    // ── 1-RTT key update state (RFC 9001 §6) ──────────────────────
    //
    // `application_recv` above holds the keys for the CURRENT recv
    // key phase (the bit value the peer used on packets we've
    // successfully opened). The next-phase recv keys are
    // pre-derived eagerly so that when the peer toggles its
    // KEY_PHASE bit we can trial-decrypt without HKDF on the hot
    // path — Chrome/Firefox routinely do a key update after some
    // traffic volume. The previous-phase keys are retained for one
    // rotation to absorb reordered packets that arrived after the
    // peer's KU but were sent before it.
    pub(super) application_recv_prev: Option<DirKeys>,
    pub(super) application_recv_next: Option<DirKeys>,
    /// Latest CLIENT application-traffic secret. Updated on each
    /// successful key update — `next_traffic_secret(client_ap)` is
    /// then ready to feed `derive_aes128_keys` for the
    /// post-rotation `application_recv_next`.
    pub(super) client_app_secret: Option<[u8; 32]>,
    /// Peer's current KEY_PHASE bit value (0 or 1). Toggled when
    /// we successfully open a packet with `application_recv_next`.
    pub(super) recv_key_phase: u8,
    /// Latest SERVER application-traffic secret — the send-side mirror
    /// of `client_app_secret`. `next_traffic_secret(server_ap)` derives
    /// the next-generation send keys when we respond to a peer-initiated
    /// key update (RFC 9001 §6.1).
    pub(super) server_app_secret: Option<[u8; 32]>,
    /// Our current KEY_PHASE bit value (0 or 1) stamped on the 1-RTT
    /// short header. Toggled in lock-step with `recv_key_phase` when we
    /// respond to a peer key update by rotating our send keys, so
    /// subsequent packets are protected with — and labelled as — the new
    /// generation (RFC 9001 §6.1: "the recipient also updates its
    /// sending keys").
    pub(super) send_key_phase: u8,

    pub(super) initial_space: SpaceState,
    pub(super) handshake_space: SpaceState,
    pub(super) application_space: SpaceState,

    /// Delayed-ACK state for the AppData (1-RTT) space (RFC 9000 §13.2.1).
    /// We don't emit a standalone ACK-only packet for every received
    /// 1-RTT packet; instead a pending ACK piggybacks the next outbound
    /// packet (e.g. a /health response — so its request's ACK costs no
    /// extra packet), and we only force a standalone ACK once two
    /// ack-eliciting packets have arrived since our last ACK (keeps an
    /// uploader's cwnd clocked) or `max_ack_delay` elapses. Count of
    /// ack-eliciting 1-RTT packets received since our last 1-RTT ACK;
    /// reset to 0 when we emit one.
    pub(super) app_ack_eliciting_since_ack: u32,
    /// Receive time (µs) of the first ack-eliciting 1-RTT packet not yet
    /// acknowledged (0 = none) — the `max_ack_delay` timer base.
    pub(super) app_first_unacked_us: u64,

    pub(super) tls: QuicTls,

    /// Whether we've already emitted HANDSHAKE_DONE in 1-RTT.
    pub(super) handshake_done_sent: bool,

    // ── Stream-credit (MAX_STREAMS) replenishment ─────────────────
    //
    // RFC 9000 §4.6 + §19.11: the peer can only open up to
    // `peer_max_streams_*_advertised` cumulative streams of the
    // matching type. Once they've used the credit, they MUST wait
    // for a MAX_STREAMS frame from us bumping the limit. Without
    // replenishment a long-lived browser conn that keeps refreshing
    // will eventually wedge — exactly the symptom the user
    // reproduced after ~99 refreshes against the old 100-stream
    // initial limit.
    //
    // We track:
    //   * the highest sid the peer has actually opened (per type),
    //   * the max-streams limit we've already advertised (per
    //     type, initially the transport-parameter value).
    // When the peer's count gets within `STREAM_CREDIT_REFILL_AT`
    // of the advertised cap, `flush_outbound` emits MAX_STREAMS
    // raising the cap by `STREAM_CREDIT_WINDOW`.
    //
    // Stream IDs encode (type, count): bidi-client sids are
    // 0,4,8,..., so `(sid >> 2) + 1` is the count of bidi streams
    // the peer has opened so far.
    pub(super) peer_bidi_streams_opened: u64,
    pub(super) peer_uni_streams_opened: u64,
    pub(super) peer_max_streams_bidi_advertised: u64,
    pub(super) peer_max_streams_uni_advertised: u64,

    // ── Connection-level receive flow control (RFC 9000 §4.1) ─────
    //
    // The peer may send at most `max_data_advertised` cumulative bytes
    // across all streams. `data_consumed` counts bytes the app has
    // actually drained (stream_recv + discard_recv); the MAX_DATA
    // pull-emission in `encode_app_packet` slides the limit forward as
    // it advances, so uploads aren't capped at the initial 1 MiB
    // `initial_max_data`. Per-stream limits live on each `RecvStream`
    // (`recv_max`); this is the conn-wide ceiling stacked above them.
    /// Cumulative bytes the app has drained across all streams.
    pub(super) data_consumed: u64,
    /// Largest cumulative byte total we've granted the peer (last
    /// MAX_DATA). Monotonic; starts at `initial_max_data` (1 MiB).
    pub(super) max_data_advertised: u64,
    /// Cumulative bytes the peer has SENT across all streams — the sum
    /// of every stream's `recv_high`. Enforced against
    /// `max_data_advertised` so a peer that ignores the connection
    /// window can't grow our receive buffers without bound
    /// (RFC 9000 §4.1). Monotonic.
    pub(super) data_received: u64,
    /// Set when the peer signals it's stalled on the connection window
    /// (DATA_BLOCKED) or a stream window (STREAM_DATA_BLOCKED). Forces
    /// the next 1-RTT packet to re-advertise the *current* MAX_DATA /
    /// MAX_STREAM_DATA even if the consume-threshold isn't crossed —
    /// this recovers a MAX_* the peer lost (we don't retransmit them),
    /// so an upload can't wedge at a window edge after the app has
    /// already caught up. Cleared once re-advertised.
    pub(super) force_max_data: bool,
    pub(super) force_max_stream_data: bool,
    /// As above, for MAX_STREAMS: set on an inbound STREAMS_BLOCKED so
    /// the next packet re-advertises the *current* stream limit even
    /// when the replenish threshold isn't crossed — recovering a
    /// MAX_STREAMS the peer lost (otherwise a peer blocked on stream
    /// creation stays wedged, since the level-trigger needs the peer to
    /// open more streams, which it can't). Cleared once re-advertised.
    pub(super) force_max_streams_bidi: bool,
    pub(super) force_max_streams_uni: bool,
    /// 8 bytes from a received PATH_CHALLENGE awaiting echo in a
    /// PATH_RESPONSE (RFC 9000 §8.2.2 — a MUST). Set by the RX frame
    /// dispatch, drained by the next 1-RTT flush. Only the most recent
    /// is kept; a fresh challenge supersedes an unsent one.
    pub(super) pending_path_response: Option<[u8; 8]>,

    // ── Anti-amplification (RFC 9000 §8.1) ────────────────────────
    //
    // Until the peer's address is validated, we MUST NOT send more
    // than 3 × the bytes we've received from them. Without this an
    // attacker could spoof a victim's source IP, send a small Initial,
    // and we'd reply with a several-KB server flight (cert + EE +
    // CV + Finished) — amplification in the worst case ~30×.
    //
    // Validation is triggered by receipt of a Handshake-encrypted
    // packet (the peer must have decoded our ServerHello to derive
    // Handshake keys, proving they own the source address).
    /// Cumulative bytes received from peer before path was validated.
    /// Frozen once `path_validated` flips to true.
    pub(super) bytes_received_pre_validation: u64,
    /// Cumulative bytes we've sent before path was validated.
    /// Frozen once `path_validated` flips to true.
    pub(super) bytes_sent_pre_validation: u64,
    /// `true` once the peer has proven they hold the source
    /// address (received a Handshake packet from them).
    pub(super) path_validated: bool,
    /// Count of 1-RTT packets we've successfully AEAD-opened. Bumped
    /// only *after* a packet authenticates, so it cannot advance on a
    /// forged/spoofed datagram. The conn task gates connection
    /// migration (following the peer's source address for TX) on this
    /// advancing — RFC 9000 §9.3: an endpoint MUST NOT change the
    /// address it sends to based on an unauthenticated packet, or an
    /// off-path attacker who knows the (cleartext) DCID could redirect
    /// our traffic by spoofing the source address.
    pub(super) authenticated_pkts: u64,

    // ── RTT estimator (RFC 9002 §5) ───────────────────────────────
    //
    // All in microseconds. Updated each time an ACK arrives that
    // names a previously-sent ack-eliciting packet from any space.
    // We use `latest_rtt - peer_ack_delay` (clamped to non-negative)
    // as the per-sample input to the SRTT/RTTvar EWMA. A `None`
    // `smoothed_rtt_us` means we haven't received the first sample
    // yet; PTO falls back to `kInitialRtt = 333_000` until then
    // (RFC 9002 §6.2.2).
    /// Most recent RTT sample (`now - time_sent`).
    pub(super) latest_rtt_us: Option<u64>,
    /// Smallest RTT sample observed so far. Used to clamp
    /// `peer_ack_delay` when we apply it (RFC 9002 §5.2).
    pub(super) min_rtt_us: Option<u64>,
    /// Smoothed RTT estimate. EWMA: `7/8 * SRTT + 1/8 * latest`.
    pub(super) smoothed_rtt_us: Option<u64>,
    /// RTT variation. EWMA: `3/4 * RTTvar + 1/4 * |SRTT - latest|`.
    pub(super) rttvar_us: u64,
    /// Per-space `time_of_last_ack_eliciting_packet_sent`. Indexed
    /// 0=Initial 1=Handshake 2=Application; `None` until we've sent
    /// an ack-eliciting packet in that space. Anchor for the PTO
    /// timer once it's wired up — the PTO deadline is
    /// `last_sent + pto_period`. Tracked here (rather than in
    /// SpaceState) so `pto_deadline_us` can fold across all three
    /// spaces with a single borrow.
    pub(super) time_of_last_ack_eliciting_us: [Option<u64>; 3],
    /// PTO backoff exponent (RFC 9002 §6.2.1): the PTO period is
    /// `base_pto << pto_count`. Incremented each time a PTO probe fires
    /// without intervening progress; reset to 0 when an ACK acknowledges
    /// new data. Without this the timer re-arms at a fixed period and
    /// floods PINGs when the peer is unresponsive (3180 probes / 12 s on
    /// the gve retransmit-storm conn). Capped so the period can't overflow.
    pub(super) pto_count: u32,
    /// Peer's `ack_delay_exponent` (RFC 9000 §18.2): its ACK frames'
    /// `ack_delay` is in `2^exponent` µs units. RFC default 3 until the
    /// client's transport parameters are applied.
    pub(super) peer_ack_delay_exponent: u8,
    /// Peer's `max_ack_delay` in µs (RFC 9000 §18.2): added to our PTO
    /// (RFC 9002 §6.2.1) and the cap on the `ack_delay` we honor in an
    /// RTT sample (§5.3). RFC default 25 ms until the params are applied.
    pub(super) peer_max_ack_delay_us: u64,

    /// Microseconds since boot when this conn last accepted ANY
    /// inbound datagram. Bumped at the end of `process_datagram`
    /// for any datagram that didn't error all the way out. The
    /// conn task races a sleep against this deadline; when the
    /// sleep wins, we've been idle long enough to honor RFC 9000
    /// §10.1 and tear down. `0` = never received (fresh conn);
    /// the listener seeds it via `set_last_recv_now()` immediately
    /// after spawning so the first iteration's deadline is
    /// "creation time + idle".
    pub(super) last_recv_us: u64,

    /// Arrival time (µs, `tls::ticket::now_us`) of the datagram
    /// currently being processed — the conn task sets it from
    /// `Datagram.rx_us` before each `process_datagram`.
    /// `dispatch_frames` copies it onto a freshly-created
    /// `RecvStream` so the request RX→TX latency histogram can be
    /// sampled when the matching response stream FINs. `0` outside
    /// a `process_datagram` call.
    pub(super) cur_rx_us: u64,

    /// Set by `close_with_error` to schedule a CONNECTION_CLOSE
    /// frame on the next `flush_outbound`. `None` means the
    /// connection is in normal operation. RFC 9000 §10.2.1: a close
    /// is emitted at the highest packet number space we have keys
    /// for; subsequent packets in lower spaces are NOT generated
    /// after close. We emit one packet then transition to
    /// `Failed` so the conn task tears down on its next iteration.
    pub(super) close_pending: Option<(u64, alloc::vec::Vec<u8>)>,

    /// Next-byte offset into the OneRtt CRYPTO stream for outbound
    /// post-handshake messages. Bumped on every CRYPTO frame
    /// emitted at 1-RTT level (currently NewSessionTicket; future
    /// KeyUpdate / NEW_TOKEN). Per RFC 8446 §4.6 each post-
    /// handshake message follows the previous in the same stream,
    /// so the offset accumulates rather than resetting per-frame.
    pub(super) one_rtt_crypto_offset: u64,

    /// Next-byte offset into the **Handshake** CRYPTO stream for
    /// the outbound server flight. That flight (EncryptedExtensions,
    /// Certificate, CertificateVerify, Finished) exceeds one packet
    /// for any real leaf+intermediate cert chain, so `flush_outbound`
    /// fragments it across several Handshake packets; each CRYPTO
    /// frame carries its slice's offset in this stream so the peer
    /// reassembles it (RFC 9001 §4.1.3). Mirrors
    /// [`one_rtt_crypto_offset`](Self::one_rtt_crypto_offset).
    pub(super) handshake_crypto_offset: u64,

    /// Outbound packet queue: complete UDP datagrams (including
    /// any header-protected, AEAD-sealed packets) ready to ship.
    /// `pop_packet_owned` drains the front entry; the reactor's
    /// `ship_datagram` dispatches on the variant.
    ///
    /// VecDeque (not Vec) so the front-pop is O(1). Multi-packet
    /// responses queue up to MAX_FLUSH_PACKETS (~32) at a time;
    /// `Vec::remove(0)` would have shifted all of them on each
    /// pop.
    pub(super) outbound: alloc::collections::VecDeque<DatagramBuf>,

    /// Recycle pool for the **`Heap` fallback path** of
    /// [`DatagramBuf`]. Every `Heap` Vec popped via
    /// `pop_packet_owned` and returned via `recycle_packet` lands
    /// here cleared (capacity ≈ 1500 preserved), and
    /// `take_datagram_buf` pulls from it before falling back to a
    /// fresh allocation. Bare-metal builds with a working driver
    /// TX pool rarely touch this — `take_datagram_buf` returns
    /// `TxSlot` first and only falls through to Heap when
    /// `acquire_tx_buf` returns `None` (pool exhaustion, GVE,
    /// native). On native this pool IS the hot path.
    pub(super) outbound_pool: Vec<Vec<u8>>,

    /// Per-stream receive state, keyed by stream ID. Lazily
    /// inserted on the first STREAM frame.
    pub(super) recv_streams: alloc::collections::BTreeMap<u64, crate::streams::RecvStream>,

    /// Per-stream send state, keyed by stream ID. Lazily inserted
    /// the first time the app calls `stream_send` for a stream.
    pub(super) send_streams: alloc::collections::BTreeMap<u64, crate::streams::SendStream>,

    /// Recycle pool for `RecvStream`s. The reaper pushes finished
    /// streams here (after `reset_for_reuse` clears state but
    /// preserves capacity); `get_or_create_recv` pops first
    /// before falling back to a fresh allocation. Capped at
    /// `STREAM_POOL_CAP` so a long-lived conn that processes many
    /// requests doesn't accumulate unbounded reserve.
    pub(super) recv_pool: Vec<crate::streams::RecvStream>,

    /// Recycle pool for `SendStream`s — same shape as `recv_pool`.
    pub(super) send_pool: Vec<crate::streams::SendStream>,

    /// Stream IDs we've seen at least once, in arrival order. The
    /// app's `accept_stream` future drains the head; the listener
    /// is responsible for popping streams it's already accepted.
    pub(super) opened_streams: Vec<u64>,

    /// Ring of recently-reaped client-bidi stream IDs. A late
    /// STREAM-frame retransmit for a sid we've already finished
    /// (response sent + FIN'd, both ends drained) used to:
    ///   1. resurrect a `recv_stream` from the pool,
    ///   2. push the sid back onto `opened_streams`,
    ///
    /// then `reap_finished_streams` would kill the resurrected
    /// recv_stream on the very next flush (because the matching
    /// `send_stream` was still satisfying the reap conditions),
    /// leaving the H3 server blocked forever on `recv(sid)` —
    /// surfaces as `[quic-bug handler_stuck] recv await
    /// state=None`. Linux quinn drives this case routinely via
    /// loss-recovery retransmits; macOS quinn rarely hits it.
    /// Tracking a small ring of "already-handled" sids and
    /// dropping STREAM frames that match (no recv_stream
    /// creation, no opened_streams push, just the byte-ack
    /// bookkeeping) breaks the cycle.
    ///
    /// Cap of 256: a refresh-spamming Chrome session at 20
    /// req/s for 10 s = 200 streams; 256 covers a comfortable
    /// burst without per-conn memory bloat (256 × 8 B = 2 KiB).
    /// Replacement is FIFO via `reaped_idx`.
    pub(super) reaped_streams: [u64; REAPED_STREAMS_CAP],
    pub(super) reaped_idx: usize,

    /// Congestion controller (RFC 9002 §7). Bounds how much
    /// ack-eliciting data may be outstanding (`window()`), so the
    /// server paces to the ACK clock instead of blasting a whole
    /// response at line rate. Fed by `process_ack` (on_ack) and
    /// `detect_loss` (on_loss); read at packetization time to gate
    /// the 1-RTT STREAM-data sweep (see `encode_one_rtt_packet`).
    /// `net_cc::Controller` — NewReno (default) or CUBIC, per
    /// `net_cc::DEFAULT_ALGORITHM`.
    pub(super) cc: net_cc::Controller,
    /// Bytes of ack-eliciting data currently in flight (sealed +
    /// sent, not yet acked or declared lost). Incremented in
    /// `record_sent_packet`, decremented in `process_ack` /
    /// `detect_loss`. The congestion gate is `bytes_in_flight <
    /// cc.window()`.
    pub(super) bytes_in_flight: u32,

    /// Send-side connection-level flow control (RFC 9000 §4.1): the
    /// max total STREAM bytes we may send across all streams, =
    /// peer's `initial_max_data` raised by inbound MAX_DATA frames.
    /// `data_sent` is the running total. Seeded from the peer's
    /// transport params by `apply_peer_flow_control` once Established.
    pub(super) peer_max_data: u64,
    pub(super) data_sent: u64,
    /// Peer's per-stream initial send limits, used to seed a new
    /// `SendStream`'s `peer_max_stream_data` by stream class:
    /// `_bidi` (= the peer's `initial_max_stream_data_bidi_local`) for
    /// client-opened bidi streams (our h3 responses); `_uni` for our
    /// server-opened uni control streams.
    pub(super) peer_initial_max_stream_data_bidi: u64,
    pub(super) peer_initial_max_stream_data_uni: u64,
    /// One-shot guard: whether `apply_peer_flow_control` has parsed and
    /// applied the peer's transport-param flow-control limits.
    pub(super) peer_fc_applied: bool,

    /// STREAM ranges declared lost and awaiting retransmission (RFC 9000
    /// §13.3). `detect_loss` moves a lost packet's `stream_frames` here;
    /// `encode_one_rtt_packet` drains it (highest priority, before fresh
    /// data) so the receiver's gap is filled and the stream can complete.
    pub(super) retx_queue: alloc::collections::VecDeque<StreamRetx>,
    /// Sum of `retx_queue` payload bytes. Folded into the congestion gate
    /// alongside `bytes_in_flight` so total unacked data (in-flight +
    /// awaiting-retransmit) stays ≤ the window — without this, declaring a
    /// packet lost both drops it from `bytes_in_flight` AND queues its
    /// data, re-opening the gate to send fresh data while the retx queue
    /// grows unbounded (heap exhaustion under heavy loss).
    pub(super) retx_bytes: u32,
    /// Staging for the STREAM frames the packet currently being encoded
    /// carries — `record_sent_packet` moves them into the `SentPacket`.
    /// A field (not a return value) so the 6 `record_sent_packet` call
    /// sites that carry no stream data need no signature change.
    pub(super) pending_sent_stream_frames: alloc::vec::Vec<StreamRetx>,

    /// CRYPTO fragments declared lost and awaiting retransmission (RFC
    /// 9002 §6.2). `detect_loss` moves a lost Initial/Handshake packet's
    /// `crypto_frames` here; `flush_outbound` re-emits each at its
    /// original offset before draining fresh handshake CRYPTO, so a lost
    /// handshake packet no longer stalls the handshake (the PTO PING
    /// only forced an ACK, never resent the missing bytes).
    pub(super) crypto_retx_queue: alloc::collections::VecDeque<CryptoRetx>,
    /// Staging for the CRYPTO frame the packet currently being encoded
    /// carries — `record_sent_packet` moves it into the `SentPacket`.
    pub(super) pending_sent_crypto_frames: alloc::vec::Vec<CryptoRetx>,

    /// Egress pacing token bucket (RFC 9002 §7.7). `pace_budget` is send
    /// credit in bytes — it goes negative after a burst and refills at the
    /// paced rate (`pace_rate()`: the srtt-gated `cc.pacing_rate()`, or the
    /// fixed `LOW_RTT_PACE_RATE_BPS` in the ultra-low-RTT regime), capped at
    /// `MAX_PACE_BURST`. The flush tail loop gates 1-RTT data emission on
    /// it; the conn task arms `pace_deadline_us()` to resume when credit
    /// accrues. This bounds the per-flush microburst so GCE's per-VM egress
    /// policer doesn't drop the unpaced cwnd dump — the multi-packet h3
    /// download loss (see reference_gce_h3_burst_loss). `pace_last_us` is
    /// the last refill timestamp; 0 lets the first refill grant a full burst.
    pub(super) pace_budget: i64,
    pub(super) pace_last_us: u64,
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Release any still-buffered (received-but-undrained) bytes from
        // the global aggregate recv budget — their `recv_streams` buffers
        // are freed with this connection. `data_received - data_consumed`
        // is exactly what `recv_buffered_add` charged and `..._sub` hasn't
        // released yet.
        recv_buffered_sub(self.data_received.saturating_sub(self.data_consumed));
        // Bump the counter unconditionally, log only at events
        // verbosity (matches the existing `conns_allocated` event).
        // Pairing those two log lines line-for-line in the serial
        // output is the cheapest way to spot a leaked conn:
        // every `conns_allocated` should have a matching
        // `conns_dropped`.
        crate::quic_event!(
            conns_dropped,
            "local_cid={}",
            crate::endpoint::hex8(self.local_cid.as_slice())
        );
    }
}

/// Cap on the per-conn reaped-streams ring (see
/// `reaped_streams` docstring).
pub(super) const REAPED_STREAMS_CAP: usize = 256;
/// Sentinel for an unused ring slot. Stream IDs are bounded by
/// `2^62 - 1` per RFC 9000 §16, so `u64::MAX` is safely never a
/// real sid.
pub(super) const REAPED_STREAM_EMPTY: u64 = u64::MAX;

/// Cap on the size of each per-conn stream recycle pool. A
/// kept-alive HTTP/3 conn cycles through dozens of streams over
/// its lifetime; 8 reserves enough for a typical pipelined
/// burst (the user's "20-conn refresh" scenario) without
/// stockpiling memory on a long-idle conn.
pub(super) const STREAM_POOL_CAP: usize = 8;

impl Connection {
    /// Create a fresh connection from the client's first Initial
    /// packet. Caller has already parsed enough of the long header
    /// to know it's an Initial (and to dispatch to "new connection"
    /// vs an existing one). We re-parse the full header here for
    /// simplicity; the cost is negligible.
    ///
    /// `local_cid` is the CID the server picked for itself — the
    /// connection pool's key. `seed` is 32 bytes of randomness
    /// for the X25519 ephemeral.
    ///
    /// Per RFC 9000 §7.2, the server's first Initial reply MUST
    /// echo the client-chosen DCID as its DCID (since we haven't
    /// yet told the client our SCID). After that exchange, both
    /// sides settle on the CIDs they advertised.
    pub fn new_server(local_cid: ConnectionId, seed: [u8; 32]) -> Self {
        Connection {
            state: ConnState::PreHandshake,
            local_cid,
            peer_cid: ConnectionId::new(&[]),
            initial_dcid: ConnectionId::new(&[]),
            initial_send: None,
            initial_recv: None,
            early_recv: None,
            pending_zero_rtt: Vec::new(),
            application_recv_prev: None,
            application_recv_next: None,
            client_app_secret: None,
            recv_key_phase: 0,
            server_app_secret: None,
            send_key_phase: 0,
            handshake_send: None,
            handshake_recv: None,
            application_send: None,
            application_recv: None,
            initial_keys_discarded: false,
            handshake_keys_discarded: false,
            tx_owner_driven: false,
            initial_space: SpaceState::default(),
            handshake_space: SpaceState::default(),
            application_space: SpaceState::default(),
            app_ack_eliciting_since_ack: 0,
            app_first_unacked_us: 0,
            tls: QuicTls::new(seed),
            handshake_done_sent: false,
            peer_bidi_streams_opened: 0,
            peer_uni_streams_opened: 0,
            // Must match `transport_params::ServerParams::defaults`'s
            // initial_max_streams_*. Updating one without the other
            // would let the peer either open beyond what we
            // advertised or fail to use credit we already gave.
            peer_max_streams_bidi_advertised: 1024,
            peer_max_streams_uni_advertised: 1024,
            data_consumed: 0,
            // The initial conn-level window we advertise (matches the
            // `initial_max_data` transport param via the shared const).
            max_data_advertised: crate::streams::INITIAL_MAX_DATA,
            data_received: 0,
            force_max_data: false,
            force_max_stream_data: false,
            force_max_streams_bidi: false,
            force_max_streams_uni: false,
            pending_path_response: None,
            bytes_received_pre_validation: 0,
            bytes_sent_pre_validation: 0,
            path_validated: false,
            authenticated_pkts: 0,
            latest_rtt_us: None,
            min_rtt_us: None,
            smoothed_rtt_us: None,
            rttvar_us: 0,
            peer_ack_delay_exponent: 3,
            peer_max_ack_delay_us: 25_000,
            time_of_last_ack_eliciting_us: [None; 3],
            pto_count: 0,
            last_recv_us: 0,
            cur_rx_us: 0,
            close_pending: None,
            one_rtt_crypto_offset: 0,
            handshake_crypto_offset: 0,
            outbound: alloc::collections::VecDeque::new(),
            outbound_pool: Vec::new(),
            recv_streams: alloc::collections::BTreeMap::new(),
            send_streams: alloc::collections::BTreeMap::new(),
            recv_pool: Vec::new(),
            send_pool: Vec::new(),
            opened_streams: Vec::new(),
            reaped_streams: [REAPED_STREAM_EMPTY; REAPED_STREAMS_CAP],
            reaped_idx: 0,
            // Controller (default NewReno) over the QUIC datagram payload size
            // (~1200 B); initial window = IW10 (RFC 9002 §7.2), matching the
            // old implicit burst the loss/PTO machinery already assumed.
            cc: net_cc::Controller::new(MAX_QUIC_DATAGRAM as u32),
            bytes_in_flight: 0,
            peer_max_data: 0,
            data_sent: 0,
            peer_initial_max_stream_data_bidi: 0,
            peer_initial_max_stream_data_uni: 0,
            peer_fc_applied: false,
            retx_queue: alloc::collections::VecDeque::new(),
            crypto_retx_queue: alloc::collections::VecDeque::new(),
            pending_sent_crypto_frames: alloc::vec::Vec::new(),
            retx_bytes: 0,
            pending_sent_stream_frames: alloc::vec::Vec::new(),
            pace_budget: 0,
            pace_last_us: 0,
        }
    }

    /// Stamp the arrival time of the datagram about to be processed.
    /// The conn task calls this with `Datagram.rx_us` before each
    /// `process_datagram`; see the `cur_rx_us` field.
    pub fn set_cur_rx_us(&mut self, rx_us: u64) {
        self.cur_rx_us = rx_us;
    }

    /// Record `sid` in the reaped-streams ring. Called when
    /// `reap_finished_streams` removes a fully-completed stream;
    /// subsequent late STREAM frames for this sid are dropped
    /// instead of resurrecting the stream (see ring docstring).
    pub(super) fn mark_reaped(&mut self, sid: u64) {
        self.reaped_streams[self.reaped_idx] = sid;
        self.reaped_idx = (self.reaped_idx + 1) % REAPED_STREAMS_CAP;
    }

    /// Whether `sid` is in the reaped-streams ring.
    pub(super) fn is_reaped(&self, sid: u64) -> bool {
        self.reaped_streams.contains(&sid)
    }

    /// Get-or-create a SendStream entry for `sid`, drawing from
    /// the recycle pool first so the buffer / VecDeque allocations
    /// inside survive across stream lifecycles. Returns a `&mut`
    /// handle so the caller can immediately write into it.
    pub(super) fn ensure_send_stream(&mut self, sid: u64) -> &mut crate::streams::SendStream {
        let _ss0 = crate::diag::now_cycles();
        if !self.send_streams.contains_key(&sid) {
            // Make sure the peer's send-side flow-control limits are in
            // hand before seeding the new stream's window.
            self.apply_peer_flow_control();
            let mut new_stream = self
                .send_pool
                .pop()
                .unwrap_or_default();
            // Seed the request RX→TX latency timestamp: a request
            // and its response share `sid`, so copy the matching
            // RecvStream's arrival time onto the SendStream. Only a
            // client-bidi request has a RecvStream here — server-
            // initiated streams find none and stay untracked (0).
            new_stream.rx_us = self.recv_streams.get(&sid).map_or(0, |r| r.rx_us);
            // Send-side per-stream flow-control limit (RFC 9000 §4.1),
            // by stream class: a client-opened bidi stream (our h3
            // response) is bounded by the peer's
            // initial_max_stream_data_bidi_local; our server-opened uni
            // control streams by initial_max_stream_data_uni.
            new_stream.peer_max_stream_data = if crate::streams::is_bidirectional(sid) {
                self.peer_initial_max_stream_data_bidi
            } else {
                self.peer_initial_max_stream_data_uni
            };
            self.send_streams.insert(sid, new_stream);
            crate::diag::COUNTERS.send_streams_created.bump();
        }
        crate::diag::COUNTERS
            .stream_setup_cycles
            .add(crate::diag::now_cycles().wrapping_sub(_ss0));
        self.send_streams.get_mut(&sid).unwrap()
    }

    /// Parse the peer's transport parameters (available once the
    /// handshake has processed the client's TLS) and apply the
    /// send-side flow-control limits — `peer_max_data` and the
    /// per-stream-class initial windows. One-shot: a no-op once applied
    /// or while the params aren't available yet (no 1-RTT STREAM data
    /// flows before the handshake completes, so the gate isn't consulted
    /// until after this has run).
    pub(super) fn apply_peer_flow_control(&mut self) {
        if self.peer_fc_applied {
            return;
        }
        if let Some(p) = self
            .tls
            .client_transport_params()
            .and_then(|b| crate::transport_params::parse_client_params(b).ok())
        {
            self.peer_max_data = p.initial_max_data;
            self.peer_initial_max_stream_data_bidi = p.initial_max_stream_data_bidi_local;
            self.peer_initial_max_stream_data_uni = p.initial_max_stream_data_uni;
            // RTT/PTO inputs (RFC 9000 §18.2): how to scale the peer's
            // ACK `ack_delay` fields, and the most it will intentionally
            // delay an ACK. Defaults (3 / 25 ms) until this runs.
            self.peer_ack_delay_exponent = p.ack_delay_exponent;
            self.peer_max_ack_delay_us = p.max_ack_delay_ms.saturating_mul(1_000);
            self.peer_fc_applied = true;
        }
    }

    pub fn state(&self) -> ConnState {
        self.state
    }

    /// Mark the connection terminated. Called from the conn-task
    /// teardown path after a non-error exit (idle timeout, batch
    /// limit reached, …) so that the user handler — which observes
    /// `state() == Failed` to know it can stop awaiting stream
    /// primitives — exits its accept/recv loops and drops its
    /// `Rc<RefCell<Connection>>`. Without this, the handler stays
    /// pinned on `progress.wait()` forever, the Rc never reaches 0,
    /// and the entire `Connection` (with its recv/send pools,
    /// outbound recycle pool, stream BTreeMaps, and reaped-streams
    /// ring) leaks for the rest of process lifetime.
    pub fn mark_terminated(&mut self) {
        self.state = ConnState::Failed;
    }

    pub fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    /// Mark this conn as having received "now", without actually
    /// processing a datagram. Used by the listener to seed the
    /// idle-timeout deadline at conn creation time so a peer that
    /// allocates a slot and then disappears entirely (no further
    /// datagrams) still gets reaped after the idle window.
    pub fn set_last_recv_now(&mut self) {
        self.last_recv_us = tls::ticket::now_us();
    }

    /// Microseconds-since-boot timestamp of the most recent inbound
    /// datagram (or `set_last_recv_now` seed). Pair with
    /// `idle_timeout_us` to compute the close deadline.
    pub fn last_recv_us(&self) -> u64 {
        self.last_recv_us
    }

    /// Effective idle-timeout window for this connection, in
    /// microseconds. RFC 9000 §10.1.2: each endpoint advertises a
    /// `max_idle_timeout` in transport_parameters; the effective
    /// window is `min(local, peer)` — both endpoints close after
    /// that many microseconds without an inbound packet. We
    /// always advertise 30 s; if the peer's value (parsed below)
    /// is smaller and non-zero, use that.
    pub fn idle_timeout_us(&self) -> u64 {
        const OUR_IDLE_MS: u64 = 30_000;
        let peer_ms = self
            .tls
            .client_transport_params()
            .and_then(|bytes| crate::transport_params::parse_client_params(bytes).ok())
            .map(|p| p.max_idle_timeout_ms)
            .unwrap_or(0);
        // RFC 9000 §18.2: a value of 0 means no timeout — treat
        // that as "use the other side's value". Otherwise take min.
        let effective_ms = match (peer_ms, OUR_IDLE_MS) {
            (0, ours) => ours,
            (peer, ours) => peer.min(ours),
        };
        effective_ms.saturating_mul(1_000)
    }

    /// Drop send/recv stream state for any stream where BOTH ends
    /// have FIN'd and all buffers are empty. Without this, every
    /// HTTP/3 request on a long-lived QUIC connection leaks its
    /// stream's `Vec<u8>` buffers forever — a Chrome session that
    /// refreshes a page repeatedly accumulates one leaked stream
    /// per refresh, eventually exhausting the heap.
    ///
    /// "Both done" is locally observable: server-side `fin_sent`
    /// AND `recv.closed` (peer's FIN was seen and the contiguous
    /// data has been consumed). After that, RFC 9000 §3.2 / §3.3
    /// puts the stream in Data Recvd / Data Sent and no further
    /// activity is expected on either side. We don't keep a
    /// "graveyard" set: a late STREAM frame for a reaped sid
    /// would simply re-create an entry. On a healthy connection
    /// that's not expected.
    pub(super) fn reap_finished_streams(&mut self) {
        let _rp0 = crate::diag::now_cycles();
        self.reap_finished_streams_inner();
        crate::diag::COUNTERS
            .reap_cycles
            .add(crate::diag::now_cycles().wrapping_sub(_rp0));
    }

    fn reap_finished_streams_inner(&mut self) {
        // Collect finished sids into a stack buffer instead of a fresh
        // heap `Vec` per call. The steady state is 0-1 finished streams
        // per call (one request completing), so the old `.collect()` was
        // a talc-locked alloc+free on every request's hot path for a
        // ~1-element list. Overflow past the cap is reaped on the next
        // call (this runs per inbound datagram), so nothing leaks.
        const MAX_REAP_PER_CALL: usize = 32;
        let mut candidates = [0u64; MAX_REAP_PER_CALL];
        let mut n = 0usize;
        for (sid, s) in self.send_streams.iter() {
            if n == MAX_REAP_PER_CALL {
                break;
            }
            if !(s.fin_sent() && s.outbound.is_empty()) {
                continue;
            }
            let recv_done = self
                .recv_streams
                .get(sid)
                .is_some_and(|r| r.is_closed() && r.buffer.is_empty());
            if recv_done {
                candidates[n] = *sid;
                n += 1;
            }
        }
        for &sid in &candidates[..n] {
            // Recycle the SendStream / RecvStream into per-conn
            // pools (capped at STREAM_POOL_CAP) so the next
            // stream on this conn reuses their `outbound` /
            // `buffer` allocations instead of growing fresh
            // ones. `reset_for_reuse` clears state but
            // preserves capacity.
            if let Some(mut s) = self.send_streams.remove(&sid)
                && self.send_pool.len() < STREAM_POOL_CAP
            {
                s.reset_for_reuse();
                self.send_pool.push(s);
            }
            if let Some(mut r) = self.recv_streams.remove(&sid)
                && self.recv_pool.len() < STREAM_POOL_CAP
            {
                r.reset_for_reuse();
                self.recv_pool.push(r);
            }
            // Tombstone the sid so a late retransmit's STREAM
            // frame can't resurrect the stream and strand the H3
            // handler in `recv()` (see `reaped_streams` docstring).
            self.mark_reaped(sid);
            crate::diag::COUNTERS.streams_reaped.bump();
        }
    }

    /// Pop the next outbound datagram by ownership, no copy. The
    /// returned `DatagramBuf` is either:
    ///   * `Heap` — a heap-allocated Vec with an `MAX_L2_HEADROOM`-
    ///     byte prefix; caller ships via
    ///     `sock.send_to_with_l2_headroom(&mut vec)`.
    ///   * `TxSlot` — a TxBufHandle wrapping a driver TX-pool
    ///     slot; caller extracts via `into_tx_handle` and ships
    ///     via `sock.send_via_tx_handle(handle, frame_len)` — no
    ///     payload memcpy.
    pub fn pop_packet_owned(&mut self) -> Option<DatagramBuf> {
        self.outbound.pop_front()
    }

    /// Return a previously-popped datagram to the recycle pool.
    /// `Heap` variant: Vec is cleared and pushed back. `TxSlot`
    /// variant: handle's `Drop` returns the slot to the pool —
    /// nothing to do here.
    pub fn recycle_packet(&mut self, buf: DatagramBuf) {
        const POOL_MAX: usize = 16;
        buf.recycle_into(&mut self.outbound_pool, POOL_MAX);
    }

    /// Take a heap-backed datagram buffer for the encoder, recycled
    /// through `outbound_pool`.
    ///
    /// Always heap, never a driver TX slot: packets built here are
    /// DEFERRED through the `outbound` queue (drained later by
    /// `drain_outbound`), and the driver's direct-fill slots require
    /// acquire→submit to be SYNCHRONOUSLY PAIRED — a second acquire
    /// before the first submit returns the SAME un-advanced ring slot,
    /// so two queued packets alias it and the stale one ships with
    /// corrupted ciphertext. GCE-confirmed at 24 ms RTT: ~79 client
    /// "failed to authenticate packet" per transfer → cwnd collapse →
    /// ~0.3 rps; this heap path = 0 auth failures, ~66× throughput.
    /// The heap `DatagramBuf` owns its Vec until ship, so concurrent
    /// queued packets can't alias. The synchronous build-at-drain
    /// owner path uses [`take_datagram_buf_direct`] instead.
    ///
    /// The returned buf has its length pre-set to
    /// `MAX_L2_HEADROOM` (62 bytes) so subsequent encoder writes
    /// (`out.push`, `out.extend_from_slice`) land in the
    /// UDP-payload region. `seal_packet`'s absolute-offset
    /// arithmetic is consistent with the headroom prefix because
    /// the encoder captures `header_start = out.len()` after the
    /// resize.
    pub(super) fn take_datagram_buf(&mut self, fallback_capacity: usize) -> DatagramBuf {
        use nic_api::MAX_L2_HEADROOM;
        let total_capacity = MAX_L2_HEADROOM + fallback_capacity;
        let mut v = match self.outbound_pool.pop() {
            Some(mut v) => {
                v.clear();
                if v.capacity() < total_capacity {
                    v.reserve(total_capacity - v.capacity());
                }
                v
            }
            None => Vec::with_capacity(total_capacity),
        };
        v.resize(MAX_L2_HEADROOM, 0);
        DatagramBuf::Heap(v)
    }

    /// Like [`take_datagram_buf`] but prefers a zero-copy driver TX slot
    /// (the encoder writes packet bytes straight into the slot's data
    /// region; the bare-metal UDP backend fills the L2/L3/L4 headers in
    /// the headroom at submit time — no driver-side memcpy). ONLY safe
    /// when the caller submits the returned datagram SYNCHRONOUSLY
    /// before acquiring another — the per-core egress owner's
    /// build-at-drain loop (acquire→encode→submit paired). Concurrent
    /// un-submitted slots would otherwise alias the same un-advanced
    /// ring position (see [`take_datagram_buf`] for the measured
    /// failure). Falls back to the heap when the pool is full, the
    /// backend doesn't expose the SG TX surface (native), or the slot
    /// can't fit a worst-case datagram.
    pub(crate) fn take_datagram_buf_direct(&mut self, fallback_capacity: usize) -> DatagramBuf {
        use nic_api::MAX_L2_HEADROOM;

        if let Some(handle) = executor::reactor::acquire_tx_buf() {
            // The `TxSlot` datagram wraps the driver slot in a
            // `Vec` that MUST NOT reallocate: a realloc would free
            // `handle.data_ptr` — a NIC TX-pool / DMA address, not
            // a heap allocation — through the global allocator,
            // corrupting the heap. The `Vec`'s capacity is fixed
            // at `data_cap`, so "never reallocate" reduces to
            // "never write past `data_cap`". Only take this path
            // when the slot provably fits the encoder's worst-case
            // datagram (`MAX_QUIC_DATAGRAM`); a smaller slot falls
            // through to the freely-growable heap path. No shipping
            // driver hits the fallback (gve 2048 B, virtio-net
            // 1514 B both clear `MAX_QUIC_DATAGRAM`) — it is a
            // checked guard so a future small-slot driver cannot
            // silently re-introduce the realloc hazard.
            if handle.data_cap as usize >= MAX_QUIC_DATAGRAM {
                // SAFETY:
                //   * `handle.data_ptr` is a valid `*mut u8` over
                //     `data_cap` writable bytes for the handle's
                //     lifetime (the driver's TX-pool slot).
                //   * len 0 ≤ cap; `resize` below initialises
                //     bytes [..MAX_L2_HEADROOM].
                //   * The allocation is NOT heap-managed:
                //     `ManuallyDrop` suppresses `Vec`'s dealloc,
                //     and the `data_cap` gate above guarantees the
                //     encoder never triggers a realloc (which
                //     would have freed `data_ptr` as if it were a
                //     heap block).
                let mut vec: Vec<u8> = unsafe {
                    Vec::from_raw_parts(handle.data_ptr, 0, handle.data_cap as usize)
                };
                // Zero the L2/L3/L4 headroom: the encoder writes
                // past it, but the backend fills the headers there
                // at submit time and may read them for checksum.
                vec.resize(MAX_L2_HEADROOM, 0);
                return DatagramBuf::TxSlot {
                    handle,
                    vec: ManuallyDrop::new(vec),
                };
            }
            // Slot too small for our worst-case datagram — release
            // it (the handle's `Drop` returns it to the pool) and
            // fall through to the heap path below.
            drop(handle);
        }

        self.take_datagram_buf(fallback_capacity)
    }

    /// Acquire a UDP-GSO big-pool slot and wrap it as a `GsoSlot`
    /// datagram, headroom pre-reserved. The GSO flush seals N back-to-
    /// back QUIC packets (each `gso_size` bytes) into it. `None` when
    /// the driver has no hardware UDP segmentation, the big pool is
    /// full, or the slot can't hold ≥2 segments — caller falls back to
    /// the per-datagram path.
    pub(super) fn take_gso_datagram_buf(&mut self, gso_size: u16) -> Option<DatagramBuf> {
        use nic_api::MAX_L2_HEADROOM;
        let handle = executor::reactor::acquire_tx_udp_gso_buf()?;
        let cap = handle.data_cap() as usize;
        if cap < MAX_L2_HEADROOM + 2 * gso_size as usize {
            drop(handle); // too small to be worth a GSO super-packet
            return None;
        }
        // SAFETY:
        //   * `handle.0.data_ptr` is `data_cap` writable bytes for the
        //     handle's lifetime (the driver's TX big-pool slot).
        //   * `ManuallyDrop` suppresses the Vec's dealloc, and the GSO
        //     flush never writes past `cap` (it gates on
        //     `buf.len() + gso_size <= cap`), so the Vec never reallocs
        //     off the driver slot.
        let mut vec: Vec<u8> = unsafe { Vec::from_raw_parts(handle.0.data_ptr, 0, cap) };
        vec.resize(MAX_L2_HEADROOM, 0);
        Some(DatagramBuf::GsoSlot {
            handle,
            vec: ManuallyDrop::new(vec),
            gso_size,
        })
    }

    /// Whether there's an outbound datagram queued. Cheap check
    /// for the reactor's wakeup path.
    pub fn has_outbound(&self) -> bool {
        !self.outbound.is_empty()
    }

    // ── Stream API ─────────────────────────────────────────────

    /// Pop the next stream the peer has opened. Returns `None`
    /// if no new streams are pending. Caller drives `stream_recv`
    /// against the returned ID to consume bytes.
    pub fn pop_accepted_stream(&mut self) -> Option<u64> {
        if self.opened_streams.is_empty() {
            None
        } else {
            Some(self.opened_streams.remove(0))
        }
    }

    /// True if consuming recv data has reopened the flow-control window
    /// enough that a MAX_STREAM_DATA / MAX_DATA frame is now due — i.e.
    /// the same replenishment thresholds `encode_one_rtt_packet` applies.
    /// The handler's recv path flushes when this flips so a
    /// flow-control-blocked uploader gets fresh credit promptly. Without
    /// it the credit waits for the next inbound packet — which a fully
    /// blocked peer won't send — so an upload past one window deadlocks.
    pub(crate) fn recv_credit_due(&self) -> bool {
        if self.force_max_stream_data || self.force_max_data {
            return true;
        }
        // Mirror the encode's window constants (tx.rs).
        const STREAM_DATA_WINDOW: u64 = crate::streams::INITIAL_MAX_STREAM_DATA;
        const MAX_DATA_WINDOW: u64 = crate::streams::INITIAL_MAX_DATA;
        if self
            .max_data_advertised
            .saturating_sub(self.data_consumed)
            <= MAX_DATA_WINDOW / 2
        {
            return true;
        }
        self.recv_streams.values().any(|rs| {
            !rs.is_closed() && rs.recv_max.saturating_sub(rs.consumed()) <= STREAM_DATA_WINDOW / 2
        })
    }

    /// Read up to `out.len()` bytes from the head of stream `sid`'s
    /// recv buffer. Returns `(bytes_copied, eof)`. `eof = true` once
    /// the peer has signaled FIN AND every byte up to it has been
    /// drained.
    pub fn stream_recv(&mut self, sid: u64, out: &mut [u8]) -> (usize, bool) {
        match self.recv_streams.get_mut(&sid) {
            Some(s) => {
                let r = s.drain(out);
                // Count drained bytes toward conn-level flow control so
                // the MAX_DATA pull-emission can slide the window up, and
                // release them from the global aggregate recv budget.
                self.data_consumed += r.0 as u64;
                recv_buffered_sub(r.0 as u64);
                r
            }
            None => (0, false),
        }
    }

    /// Discard any bytes the QUIC layer has buffered for stream
    /// `sid`'s recv side. Used by the HTTP/3 layer for peer
    /// unidirectional streams (QPACK encoder/decoder + control)
    /// where the bytes are uninteresting but the peer keeps
    /// pushing — without this drain the buffer grows for the
    /// lifetime of the connection. Cheap: reuses the existing
    /// `RecvStream::drain` to truncate the buffer head; the Vec
    /// keeps its capacity so subsequent appends don't reallocate.
    pub fn discard_recv(&mut self, sid: u64) {
        if let Some(s) = self.recv_streams.get_mut(&sid) {
            // Drain in 2 KiB chunks until empty.
            let mut sink = [0u8; 2048];
            let mut total = 0u64;
            loop {
                let (n, _eof) = s.drain(&mut sink);
                if n == 0 {
                    break;
                }
                total += n as u64;
            }
            // Discarded bytes are consumed too — credit them at the
            // conn level so a chatty peer uni stream (QPACK encoder)
            // can't exhaust the connection window over a long session,
            // and release them from the global aggregate recv budget.
            self.data_consumed += total;
            recv_buffered_sub(total);
        }
    }

    /// Snapshot a recv stream's interior state for diagnostics.
    /// Returns `None` if the stream doesn't exist (already reaped
    /// or never created). Used by the stuck-handler watchdog.
    pub fn recv_stream_state(&self, sid: u64) -> Option<crate::streams::RecvStreamState> {
        self.recv_streams.get(&sid).map(|s| s.debug_state())
    }

    /// Whether stream `sid` has any buffered bytes ready for the
    /// app to drain.
    pub fn stream_has_buffered(&self, sid: u64) -> bool {
        self.recv_streams
            .get(&sid)
            .map(|s| s.has_buffered())
            .unwrap_or(false)
    }

    /// Append an owned `Vec<u8>` to stream `sid`'s outbound
    /// chunk chain by move. Use this when the caller already
    /// holds a built buffer (e.g. an H3 response payload) so
    /// we don't memcpy the whole thing into the SendStream.
    /// Subsequent `pop_chunk` calls drain from this Vec
    /// directly into the datagram payload region.
    pub fn stream_send_owned(&mut self, sid: u64, data: Vec<u8>) {
        self.ensure_send_stream(sid).write_owned(data);
    }

    /// Append a pre-built [`iobuf::IOBuf`] chunk to stream
    /// `sid`'s outbound chain. Use this when the caller has
    /// already built an IOBuf — typically a heap-allocated
    /// buffer with reserved headroom (so a layer below can
    /// prepend its header in place) plus the payload bytes
    /// already written. The IOBuf moves into the SendStream's
    /// VecDeque; subsequent `pop_chunk` calls read its
    /// `data()` slice straight into the packet's frames buffer.
    pub fn stream_send_iobuf(&mut self, sid: u64, data: iobuf::IOBuf) {
        self.ensure_send_stream(sid).write_iobuf(data);
    }

    /// Mark stream `sid` for FIN. The next outbound STREAM frame
    /// after the buffer drains will carry the FIN flag.
    pub fn stream_close(&mut self, sid: u64) {
        self.ensure_send_stream(sid).close();
    }

    /// Bytes queued on `sid`'s send side but not yet emitted onto the
    /// wire (0 if the send stream doesn't exist). The h3 streaming sink
    /// reads this to backpressure `res.write`. Non-creating — a query
    /// never materialises a send stream.
    pub fn stream_send_buffered(&self, sid: u64) -> usize {
        self.send_streams.get(&sid).map_or(0, |s| s.buffered_len())
    }
}

/// Append a MAX_STREAMS frame to `out` directly. Wraps the
/// stack-buffer-then-extend pattern so the caller doesn't have
/// to thread a tmp buffer in.
pub(super) fn append_max_streams_into(
    out: &mut Vec<u8>,
    max: u64,
    uni: bool,
) -> Result<(), crate::frame::FrameError> {
    let mut tmp = [0u8; 16];
    let n = if uni {
        crate::frame::write_max_streams_uni(max, &mut tmp)?
    } else {
        crate::frame::write_max_streams_bidi(max, &mut tmp)?
    };
    out.extend_from_slice(&tmp[..n]);
    Ok(())
}

/// Append a MAX_DATA frame (conn-level credit). Mirrors
/// [`append_max_streams_into`].
pub(super) fn append_max_data_into(
    out: &mut Vec<u8>,
    max: u64,
) -> Result<(), crate::frame::FrameError> {
    let mut tmp = [0u8; 16];
    let n = crate::frame::write_max_data(max, &mut tmp)?;
    out.extend_from_slice(&tmp[..n]);
    Ok(())
}

/// Append a PATH_RESPONSE frame (RFC 9000 §19.18) echoing the 8 bytes
/// from a received PATH_CHALLENGE: type byte 0x1b + the data.
pub(super) fn append_path_response_into(out: &mut Vec<u8>, data: &[u8; 8]) {
    out.push(crate::frame::ftype::PATH_RESPONSE);
    out.extend_from_slice(data);
}

/// Append a MAX_STREAM_DATA frame (per-stream credit). `sid` + `max`
/// are both varints, so the scratch is sized for two 8-byte varints
/// plus the type byte.
pub(super) fn append_max_stream_data_into(
    out: &mut Vec<u8>,
    sid: u64,
    max: u64,
) -> Result<(), crate::frame::FrameError> {
    let mut tmp = [0u8; 24];
    let n = crate::frame::write_max_stream_data(sid, max, &mut tmp)?;
    out.extend_from_slice(&tmp[..n]);
    Ok(())
}

#[cfg(test)]
mod recv_ranges_tests {
    use super::tx::{MAX_ACK_ADDITIONAL, ack_ranges_from};
    use super::{MAX_RECV_RANGES, SpaceState};
    use alloc::vec::Vec;

    fn space_with(pns: &[u64]) -> SpaceState {
        let mut s = SpaceState::default();
        for &pn in pns {
            s.record_recv_pn(pn);
        }
        s
    }

    /// The range list invariant must hold after every insert:
    /// descending by `hi`, inclusive `lo <= hi`, disjoint and with a
    /// gap of >= 1 PN between consecutive ranges (non-adjacent).
    fn assert_invariant(ranges: &[(u64, u64)]) {
        for &(lo, hi) in ranges {
            assert!(lo <= hi, "range {lo}..={hi} inverted");
        }
        for w in ranges.windows(2) {
            let (hi_lo, _hi_hi) = w[0];
            let (_lo_lo, lo_hi) = w[1];
            assert!(hi_lo > lo_hi + 1, "ranges {:?} adjacent/overlapping", w);
        }
    }

    #[test]
    fn in_order_collapses_to_one_range() {
        let s = space_with(&[0, 1, 2, 3, 4]);
        assert_eq!(s.recv_ranges, &[(0, 4)]);
        assert_eq!(s.largest_recv_pn, Some(4));
        assert_invariant(&s.recv_ranges);
    }

    #[test]
    fn reorder_still_collapses() {
        let s = space_with(&[3, 1, 0, 2, 4]);
        assert_eq!(s.recv_ranges, &[(0, 4)]);
        assert_invariant(&s.recv_ranges);
    }

    #[test]
    fn gap_then_fill_merges() {
        let mut s = space_with(&[0, 1, 3, 4]);
        assert_eq!(s.recv_ranges, &[(3, 4), (0, 1)]); // descending, gap at 2
        assert_invariant(&s.recv_ranges);
        s.record_recv_pn(2); // bridges the gap
        assert_eq!(s.recv_ranges, &[(0, 4)]);
    }

    #[test]
    fn duplicates_are_noops() {
        let s = space_with(&[5, 5, 5, 6, 5]);
        assert_eq!(s.recv_ranges, &[(5, 6)]);
        assert_invariant(&s.recv_ranges);
    }

    #[test]
    fn isolated_high_then_lower_keeps_two_ranges() {
        let mut s = space_with(&[10, 5]);
        assert_eq!(s.recv_ranges, &[(10, 10), (5, 5)]);
        s.record_recv_pn(9); // grows top range down
        assert_eq!(s.recv_ranges, &[(9, 10), (5, 5)]);
        s.record_recv_pn(6); // grows bottom range up
        assert_eq!(s.recv_ranges, &[(9, 10), (5, 6)]);
        assert_invariant(&s.recv_ranges);
    }

    #[test]
    fn range_table_is_capped_dropping_lowest() {
        // Receive every-other PN so each is its own range: 0,2,4,...
        // Far more than the cap. The list must stay bounded and keep
        // the highest ranges.
        let mut s = SpaceState::default();
        for i in 0..(MAX_RECV_RANGES as u64 + 20) {
            s.record_recv_pn(i * 2);
        }
        assert_eq!(s.recv_ranges.len(), MAX_RECV_RANGES);
        // Highest range retained; lowest dropped.
        assert_eq!(s.recv_ranges[0].1, (MAX_RECV_RANGES as u64 + 19) * 2);
        assert_invariant(&s.recv_ranges);
    }

    /// End-to-end: the encoded ACK frame must decode back to exactly
    /// the received ranges (gap math is the subtle part).
    #[test]
    fn encode_decode_roundtrip_with_gaps() {
        // Three disjoint ranges: [0,2], [5,7], [10,12].
        let s = space_with(&[0, 1, 2, 5, 6, 7, 10, 11, 12]);
        assert_eq!(s.recv_ranges, &[(10, 12), (5, 7), (0, 2)]);

        let mut additional = [(0u64, 0u64); MAX_ACK_ADDITIONAL];
        let (largest, first, n_add) =
            ack_ranges_from(&s.recv_ranges, &mut additional).unwrap();
        assert_eq!(largest, 12);
        assert_eq!(first, 2); // 12 - 10

        let mut out = [0u8; 192];
        let n = crate::frame::write_ack(largest, 0, first, &additional[..n_add], &mut out)
            .unwrap();

        // Parse it back and reconstruct the (lo, hi) ranges.
        let frame = crate::frame::parse_frame(&out[..n]).unwrap().0;
        let (largest_dec, first_dec, ranges_iter) = match frame {
            crate::frame::Frame::Ack {
                largest_acknowledged,
                first_ack_range,
                ack_ranges,
                ..
            } => (largest_acknowledged, first_ack_range, ack_ranges),
            _ => panic!("not an ACK frame"),
        };
        let mut decoded: Vec<(u64, u64)> = Vec::new();
        let mut hi = largest_dec;
        let mut lo = hi - first_dec;
        decoded.push((lo, hi));
        for (gap, len) in ranges_iter {
            hi = lo - gap - 2;
            lo = hi - len;
            decoded.push((lo, hi));
        }
        assert_eq!(decoded, s.recv_ranges);
    }

    // ── SentPackets ring ─────────────────────────────────────────────
    use super::{SentPacket, SentPackets};

    fn sp(byte_count: u32) -> SentPacket {
        SentPacket {
            time_sent_us: 1,
            ack_eliciting: true,
            in_flight: true,
            byte_count,
            stream_frames: Vec::new(),
            crypto_frames: Vec::new(),
        }
    }

    fn pns(s: &SentPackets) -> Vec<u64> {
        s.iter().map(|(pn, _)| pn).collect()
    }

    #[test]
    fn ring_insert_len_and_ascending_iter() {
        let mut s = SentPackets::default();
        assert!(s.is_empty());
        for pn in 5..=9 {
            s.insert(pn, sp(pn as u32));
        }
        assert_eq!(s.len(), 5);
        assert_eq!(pns(&s), &[5, 6, 7, 8, 9]); // ascending, starts at base=5
        assert_eq!(s.values().map(|p| p.byte_count).sum::<u32>(), 5 + 6 + 7 + 8 + 9);
    }

    #[test]
    fn ring_in_order_remove_advances_base() {
        let mut s = SentPackets::default();
        for pn in 0..=4 {
            s.insert(pn, sp(1));
        }
        // Remove the front in order; base advances and len shrinks.
        assert!(s.remove(0).is_some());
        assert_eq!(pns(&s), &[1, 2, 3, 4]);
        assert!(s.remove(1).is_some());
        assert_eq!(pns(&s), &[2, 3, 4]);
        assert_eq!(s.len(), 3);
        assert!(s.remove(0).is_none()); // already gone
    }

    #[test]
    fn ring_out_of_order_remove_holes_then_compact() {
        let mut s = SentPackets::default();
        for pn in 0..=5 {
            s.insert(pn, sp(1));
        }
        // Remove a middle PN — leaves a hole, base stays at 0.
        assert!(s.remove(3).is_some());
        assert_eq!(pns(&s), &[0, 1, 2, 4, 5]);
        assert_eq!(s.len(), 5);
        // Remove the front range; compaction must skip the 3-hole and stop
        // at the first live slot (4).
        for pn in 0..=2 {
            assert!(s.remove(pn).is_some());
        }
        assert_eq!(pns(&s), &[4, 5]);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn ring_high_to_low_range_remove_then_reuse() {
        // Mirrors ack_remove_range (removes high..=low descending).
        let mut s = SentPackets::default();
        for pn in 10..=15 {
            s.insert(pn, sp(1));
        }
        let mut pn = 15;
        loop {
            assert!(s.remove(pn).is_some());
            if pn == 10 {
                break;
            }
            pn -= 1;
        }
        assert!(s.is_empty());
        // Reuse after fully draining: a far-higher PN must reset the base,
        // not allocate a giant hole run.
        s.insert(1_000_000, sp(7));
        assert_eq!(s.len(), 1);
        assert_eq!(pns(&s), &[1_000_000]);
        assert!(s.remove(1_000_000).is_some());
        assert!(s.is_empty());
    }
}

