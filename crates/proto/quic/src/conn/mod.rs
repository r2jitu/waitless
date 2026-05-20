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
//   * Single-range ACK frame per outbound packet
//   * Coalesced packets (Initial+Handshake in one datagram —
//     standard rustls / quinn client behavior)
//
// Out of scope (future commits):
//   * Loss detection / retransmission timers (relies on client
//     retransmits today; OK for first interop check)
//   * Stream layer (STREAM frames, app data)
//   * 0-RTT / early data
//   * Connection migration / path validation
//   * Stateless reset
//   * Connection close protocol (we drop on error rather than
//     emit CONNECTION_CLOSE for now)
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

#![allow(dead_code)]

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
    pub(super) sent_packets: alloc::collections::BTreeMap<u64, SentPacket>,
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
    /// stack (we don't pad-only) but keep them split for clarity and
    /// to ease future congestion-control work.
    pub(super) in_flight: bool,
    /// On-the-wire byte count of the sealed packet. Drives bytes-
    /// in-flight; not used yet but recorded for the eventual
    /// congestion controller.
    pub(super) byte_count: u32,
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
) {
    if low > high {
        return;
    }
    // Drain via BTreeMap::remove since the range is typically
    // tight (a few packets at a time); for large ranges the
    // explicit loop is still O((high-low) * log n) which is fine.
    let mut pn = high;
    loop {
        if let Some(pkt) = space.sent_packets.remove(&pn)
            && pn == target_pn
        {
            *largest_out = Some(pkt);
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
        }
    }

    /// Read-only access to the inner Vec.
    pub fn vec(&self) -> &Vec<u8> {
        match self {
            DatagramBuf::Heap(v) => v,
            DatagramBuf::TxSlot { vec, .. } => vec,
        }
    }

    /// Bytes currently written (= `vec().len()`). Includes the
    /// L2/L3/L4 headroom prefix the encoder pre-fills via
    /// [`Connection::take_datagram_buf`].
    pub fn len(&self) -> usize {
        self.vec().len()
    }

    /// Whether this buf is backed by a driver TX-pool slot.
    /// `true` iff [`Self::into_tx_handle`] would succeed.
    pub fn is_tx_slot(&self) -> bool {
        matches!(self, DatagramBuf::TxSlot { .. })
    }

    /// Consume the buf and return its TxBufHandle + frame_len
    /// for submission. Only succeeds for the `TxSlot` variant;
    /// `Heap`-variant returns the buf back via `Err(self)` so
    /// the caller can fall back to a slice-shaped send.
    pub fn into_tx_handle(self) -> Result<(nic_api::TxBufHandle, usize), Self> {
        match self {
            DatagramBuf::TxSlot { handle, vec } => {
                let len = vec.len();
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
        }
    }
}

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
    /// We never initiate KU ourselves on the send side; our own
    /// send packets stay at KP=0 for now.
    pub(super) recv_key_phase: u8,

    pub(super) initial_space: SpaceState,
    pub(super) handshake_space: SpaceState,
    pub(super) application_space: SpaceState,

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
    /// surfaces as `[quic-drop other_wire] stuck recv await
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
}

impl Drop for Connection {
    fn drop(&mut self) {
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
            handshake_send: None,
            handshake_recv: None,
            application_send: None,
            application_recv: None,
            initial_keys_discarded: false,
            handshake_keys_discarded: false,
            initial_space: SpaceState::default(),
            handshake_space: SpaceState::default(),
            application_space: SpaceState::default(),
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
            bytes_received_pre_validation: 0,
            bytes_sent_pre_validation: 0,
            path_validated: false,
            latest_rtt_us: None,
            min_rtt_us: None,
            smoothed_rtt_us: None,
            rttvar_us: 0,
            time_of_last_ack_eliciting_us: [None; 3],
            last_recv_us: 0,
            close_pending: None,
            one_rtt_crypto_offset: 0,
            outbound: alloc::collections::VecDeque::new(),
            outbound_pool: Vec::new(),
            recv_streams: alloc::collections::BTreeMap::new(),
            send_streams: alloc::collections::BTreeMap::new(),
            recv_pool: Vec::new(),
            send_pool: Vec::new(),
            opened_streams: Vec::new(),
            reaped_streams: [REAPED_STREAM_EMPTY; REAPED_STREAMS_CAP],
            reaped_idx: 0,
        }
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
        if !self.send_streams.contains_key(&sid) {
            let new_stream = self
                .send_pool
                .pop()
                .unwrap_or_default();
            self.send_streams.insert(sid, new_stream);
            crate::diag::bump(&crate::diag::COUNTERS.send_streams_created);
        }
        self.send_streams.get_mut(&sid).unwrap()
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
        let candidates: Vec<u64> = self
            .send_streams
            .iter()
            .filter_map(|(sid, s)| {
                if !(s.fin_sent() && s.outbound.is_empty()) {
                    return None;
                }
                let recv_done = self
                    .recv_streams
                    .get(sid)
                    .is_some_and(|r| r.is_closed() && r.buffer.is_empty());
                if recv_done { Some(*sid) } else { None }
            })
            .collect();
        for sid in candidates {
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
            crate::diag::bump(&crate::diag::COUNTERS.streams_reaped);
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

    /// Take a datagram-sized buffer for the encoder. Tries the
    /// driver's TX pool first (zero-copy hot path: encoder
    /// writes packet bytes directly into a slot's `data` region,
    /// and the bare-metal UDP backend fills the L2/L3/L4 headers
    /// in the headroom in place at submit time). Falls back to a
    /// heap-allocated `Vec` when the pool is full, the backend
    /// doesn't expose the SG TX surface (native), or the driver
    /// doesn't (GVE today).
    ///
    /// The returned buf has its length pre-set to
    /// `MAX_L2_HEADROOM` (62 bytes) so subsequent encoder writes
    /// (`out.push`, `out.extend_from_slice`) land in the
    /// UDP-payload region. `seal_packet`'s absolute-offset
    /// arithmetic is consistent with the headroom prefix because
    /// the encoder captures `header_start = out.len()` after the
    /// resize.
    pub(super) fn take_datagram_buf(&mut self, fallback_capacity: usize) -> DatagramBuf {
        use executor::reactor::MAX_L2_HEADROOM;

        // Hot path: acquire a slot from the driver's TX pool.
        if let Some(handle) = executor::reactor::acquire_tx_buf() {
            // Wrap the slot's data region as a Vec via raw
            // construction. Capacity == handle.data_cap (1514 B);
            // the encoder won't push beyond that for any single
            // QUIC datagram (PACKET_BODY_BUDGET keeps 1-RTT
            // packets ~1100 B; handshake-coalesced datagrams stay
            // well under 1300 B).
            //
            // SAFETY:
            //   * `handle.data_ptr` is a valid `*mut u8` to a
            //     writable region of `data_cap` bytes for the
            //     handle's lifetime (driver's TX-pool slot).
            //   * len = MAX_L2_HEADROOM ≤ data_cap; the trailing
            //     bytes are zero-padded (slot was zeroed at boot
            //     and never written past `len` by anyone before).
            //     Wait — the slot's `data` field is reused across
            //     conn lifetimes, so the trailing bytes may hold
            //     stale ciphertext from a previous TX. We
            //     explicitly zero the headroom prefix below so
            //     bytes [..MAX_L2_HEADROOM] are clean before the
            //     encoder writes; the bytes past `len` are not
            //     read until the encoder writes them via push /
            //     extend_from_slice (which initialises before
            //     read).
            //   * The Vec's allocation (`handle.data_ptr`) is NOT
            //     allocator-managed; ManuallyDrop suppresses
            //     Vec::Drop's dealloc.
            let mut vec: Vec<u8> =
                unsafe { Vec::from_raw_parts(handle.data_ptr, 0, handle.data_cap as usize) };
            // Zero-fill the headroom; the encoder doesn't read it
            // (writes start at vec.len()), but the backend fills
            // headers there at submit time and may read for
            // checksumming. Use resize to grow `len`.
            vec.resize(MAX_L2_HEADROOM, 0);
            let _ = fallback_capacity; // matched signature; unused on this path
            return DatagramBuf::TxSlot {
                handle,
                vec: ManuallyDrop::new(vec),
            };
        }

        // Fallback: heap-allocated Vec, recycled through
        // `outbound_pool`.
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

    /// Read up to `out.len()` bytes from the head of stream `sid`'s
    /// recv buffer. Returns `(bytes_copied, eof)`. `eof = true` once
    /// the peer has signaled FIN AND every byte up to it has been
    /// drained.
    pub fn stream_recv(&mut self, sid: u64, out: &mut [u8]) -> (usize, bool) {
        match self.recv_streams.get_mut(&sid) {
            Some(s) => s.drain(out),
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
            loop {
                let (n, _eof) = s.drain(&mut sink);
                if n == 0 {
                    break;
                }
            }
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
    /// Subsequent `pop_chunk_into` calls drain from this Vec
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
    /// VecDeque; subsequent `pop_chunk_into` calls drain its
    /// `data()` slice straight into the packet's frames buffer.
    pub fn stream_send_iobuf(&mut self, sid: u64, data: iobuf::IOBuf) {
        self.ensure_send_stream(sid).write_iobuf(data);
    }

    /// Mark stream `sid` for FIN. The next outbound STREAM frame
    /// after the buffer drains will carry the FIN flag.
    pub fn stream_close(&mut self, sid: u64) {
        self.ensure_send_stream(sid).close();
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

