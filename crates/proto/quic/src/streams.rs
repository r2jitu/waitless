// crates/proto/quic/src/streams.rs — per-stream state for 1-RTT data.
//
// Receive side: per-stream byte queue + offset reassembly + FIN
// flag. Send side: per-stream outbound byte queue + sent-offset
// counter + close-flag.
//
// Sans-io: the connection state machine drives `recv_stream_frame`
// when a STREAM frame arrives and `pop_send_chunks` when the
// outbound packet builder needs frames to ship. No allocator
// activity on the steady-state hot path beyond queue growth on
// recv and one Vec allocation per outbound packet from the
// connection layer.
//
// Scope (HTTP/3 MVP):
//   * Bidirectional client-initiated streams (ID & 0b11 == 0b00)
//     — these carry HTTP/3 request/response data.
//   * Unidirectional client-initiated streams (ID & 0b11 == 0b10)
//     — H3 control / QPACK encoder / decoder streams. Same
//     reassembly logic; the only difference is "no send half."
//   * Server-initiated streams (ID & 0b11 == 0b01 / 0b11) — H3
//     control + QPACK streams the server opens. Created via
//     `open_uni`.
//   * Out-of-order arrival WITHIN a stream (loss → retransmit, or
//     reordering on the wire) is handled by buffering frames whose
//     offset > the current recv offset until the gap fills. The
//     out-of-order buffer is bounded by the receive flow-control
//     window (`recv_max`), enforced in `conn::rx` BEFORE ingest —
//     the peer can't send past the window it was granted, so
//     out-of-order data can't exceed one window. (An earlier fixed
//     16 KiB cap silently dropped in-window frames whose packets we
//     still ACK'd, leaving an unfillable gap that wedged the recv
//     handler on any upload reordered past 16 KiB.)
//
// Receive flow control IS implemented: each stream advertises
// `recv_max` (starts at the initial transport-param limit) and the
// 1-RTT TX path slides it forward via MAX_STREAM_DATA as the app
// drains, with MAX_DATA covering the conn-level ceiling — so an
// upload runs past the initial window. See `consumed` / `recv_max`
// here and the pull-emission in `Connection::encode_app_packet`.
//
// Out of scope (not needed for MVP):
//   * RESET_STREAM / STOP_SENDING (we'd close the conn on stream
//     errors instead — fine for HTTP/3 GET/POST).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Initial per-stream receive limit we advertise (= the
/// `initial_max_stream_data_*` transport params in
/// `transport_params::ServerParams::defaults`). A fresh `RecvStream`
/// starts crediting the peer this many bytes; the limit then slides
/// forward as the app consumes (MAX_STREAM_DATA emission in
/// `Connection::encode_app_packet`). The transport-param defaults seed
/// from this single value.
pub(crate) const INITIAL_MAX_STREAM_DATA: u64 = 2 << 20;

/// Initial connection-level receive limit (summed across all streams)
/// we advertise (= `initial_max_data` in
/// `transport_params::ServerParams::defaults`). The conn-level analog of
/// [`INITIAL_MAX_STREAM_DATA`]: it slides forward as the app consumes
/// (MAX_DATA emission in `Connection::encode_app_packet`). Single source
/// for the advertised value, the encode-side replenish window, and the
/// recv-credit gate — they must agree or the peer sees a window go
/// backwards (FLOW_CONTROL_ERROR) or an upload deadlocks.
pub(crate) const INITIAL_MAX_DATA: u64 = 8 << 20;

/// QUIC stream type bits (RFC 9000 §2.1).
pub mod stream_type {
    /// `bit 0 == 0` → client-initiated.
    pub const CLIENT_INITIATED: u64 = 0;
    /// `bit 0 == 1` → server-initiated.
    pub const SERVER_INITIATED: u64 = 0b01;
    /// `bit 1 == 0` → bidirectional.
    pub const BIDIRECTIONAL: u64 = 0;
    /// `bit 1 == 1` → unidirectional.
    pub const UNIDIRECTIONAL: u64 = 0b10;
}

pub fn is_client_initiated(id: u64) -> bool {
    id & 0b01 == 0
}
pub fn is_bidirectional(id: u64) -> bool {
    id & 0b10 == 0
}

/// Snapshot of `RecvStream` interior state for the stuck-handler
/// watchdog. Serialisable to a log line so a stalled `conn.recv`
/// can report exactly what the stream looks like.
#[derive(Debug, Clone, Copy)]
pub struct RecvStreamState {
    pub offset: u64,
    pub fin_offset: Option<u64>,
    pub closed: bool,
    pub buffer_len: usize,
    pub gap_entries: usize,
}

/// Receive-side stream lifecycle. Replaces the previous bool-pile
/// (`closed: bool` + `fin_offset: Option<u64>`) with three
/// mutually-exclusive variants — invalid combinations like
/// "closed without fin_offset" are now unrepresentable, and the
/// FIN-arrives-on-stale-frame bug from earlier in the session
/// becomes a missing match arm at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    /// No FIN seen yet; data may still arrive.
    Open,
    /// FIN seen at `fin_offset` but `self.offset < fin_offset`
    /// (we still need data to fill the gap before EOF).
    FinSeen { fin_offset: u64 },
    /// FIN seen AND `self.offset >= fin_offset`. No more data
    /// will arrive; once `buffer` drains, drain returns eof.
    Closed { fin_offset: u64 },
}

pub struct RecvStream {
    /// Bytes consecutively received and not yet drained by the app.
    /// Pop-front semantics from the dispatch path; the recv API
    /// drains the head into the caller's buffer.
    pub buffer: Vec<u8>,
    /// Highest contiguous offset ingested. Equals the cumulative
    /// length of bytes that have ever been added to `buffer`
    /// (including drained bytes).
    pub offset: u64,
    /// Out-of-order frames staged by their starting offset. Cleared
    /// as `offset` advances and adjacent ranges fold in.
    pub gap_buffer: BTreeMap<u64, Vec<u8>>,
    /// Lifecycle state — replaces `closed: bool` + `fin_offset`.
    pub state: RecvState,
    /// Arrival time (µs) of the datagram that opened this stream —
    /// copied from `Connection::cur_rx_us` by `dispatch_frames`.
    /// `ensure_send_stream` carries it onto the matching `SendStream`
    /// so the request RX→TX latency can be sampled at response FIN.
    pub rx_us: u64,
    /// Largest byte offset the peer is currently allowed to send on
    /// this stream — the value of the last MAX_STREAM_DATA we
    /// advertised. Starts at [`INITIAL_MAX_STREAM_DATA`] and is raised
    /// reactively as the app drains the buffer, so an upload can run
    /// past the initial window. See the pull-emission in
    /// `Connection::encode_app_packet`.
    pub recv_max: u64,
    /// Largest byte offset+len ever received on this stream — the
    /// receive-flow-control high-water mark, counting out-of-order
    /// frames too. Used to enforce `recv_max` (RFC 9000 §4.1) and to
    /// compute this stream's contribution to the connection-level
    /// received total. Monotonic.
    pub recv_high: u64,
}

impl Default for RecvStream {
    fn default() -> Self {
        RecvStream {
            buffer: Vec::new(),
            offset: 0,
            gap_buffer: BTreeMap::new(),
            state: RecvState::Open,
            rx_us: 0,
            recv_max: INITIAL_MAX_STREAM_DATA,
            recv_high: 0,
        }
    }
}

impl RecvStream {
    /// Reset to a clean state for reuse. Clears all per-stream
    /// data but preserves the `buffer` and `gap_buffer`
    /// allocations — the next stream that recycles this
    /// `RecvStream` from the per-conn pool gets an empty Vec
    /// with non-zero capacity, so its first
    /// `buffer.extend_from_slice` doesn't trigger a fresh
    /// allocation. Saves one heap alloc per request stream on
    /// the H3 hot path.
    pub fn reset_for_reuse(&mut self) {
        self.buffer.clear();
        self.offset = 0;
        self.gap_buffer.clear();
        self.state = RecvState::Open;
        self.rx_us = 0;
        self.recv_max = INITIAL_MAX_STREAM_DATA;
        self.recv_high = 0;
    }

    /// Snapshot of internal state for diagnostics. Used by the
    /// stuck-handler watchdog so a stalled `conn.recv` await can
    /// report what the stream actually looks like instead of
    /// guessing.
    pub fn debug_state(&self) -> RecvStreamState {
        RecvStreamState {
            offset: self.offset,
            fin_offset: self.fin_offset(),
            closed: self.is_closed(),
            buffer_len: self.buffer.len(),
            gap_entries: self.gap_buffer.len(),
        }
    }

    /// `Some(fin_offset)` once we've seen a FIN-bearing frame.
    /// Derived from `state` so the bool-pile invariant
    /// (`closed && fin_offset.is_some()`) is enforced by the
    /// type system.
    pub fn fin_offset(&self) -> Option<u64> {
        match self.state {
            RecvState::Open => None,
            RecvState::FinSeen { fin_offset } | RecvState::Closed { fin_offset } => {
                Some(fin_offset)
            }
        }
    }

    /// `true` once FIN has been seen AND `offset >= fin_offset`.
    /// Equivalent to `matches!(state, RecvState::Closed { .. })`.
    pub fn is_closed(&self) -> bool {
        matches!(self.state, RecvState::Closed { .. })
    }

    /// Bytes the app has drained off this stream = contiguous bytes
    /// received (`offset`) minus those still sitting in `buffer`.
    /// Drives reactive MAX_STREAM_DATA crediting: as this advances the
    /// advertised `recv_max` slides forward to keep the peer's window
    /// open.
    pub fn consumed(&self) -> u64 {
        self.offset - self.buffer.len() as u64
    }

    /// Record a FIN at `end` and re-evaluate whether the stream
    /// is now `Closed`. Called from both the contiguous and
    /// stale-frame branches in `ingest`. Centralising the state
    /// transition is the whole point of this refactor — the
    /// FIN-only-stale bug existed because two branches each had
    /// half the logic.
    fn record_fin(&mut self, end: u64) {
        let fin_offset = match self.state {
            RecvState::Open => end,
            RecvState::FinSeen { fin_offset } | RecvState::Closed { fin_offset } => {
                fin_offset.max(end)
            }
        };
        self.state = if self.offset >= fin_offset {
            RecvState::Closed { fin_offset }
        } else {
            RecvState::FinSeen { fin_offset }
        };
    }

    /// Re-check whether the offset has caught up to an
    /// already-recorded FIN. Called after `offset` advances
    /// (contiguous append + gap fold-in). No-op when not in
    /// `FinSeen`.
    fn maybe_close(&mut self) {
        if let RecvState::FinSeen { fin_offset } = self.state
            && self.offset >= fin_offset
        {
            self.state = RecvState::Closed { fin_offset };
        }
    }

    /// Ingest a STREAM frame's `(offset, data, fin)` triple.
    /// Returns `true` if this frame contributed any new contiguous
    /// bytes (caller may want to wake the recv future).
    pub fn ingest(&mut self, frame_offset: u64, data: &[u8], fin: bool) -> bool {
        let mut produced = false;
        // Frame entirely below current offset → already-seen
        // retransmit, OR a FIN-only frame at the current offset
        // with length 0 (Chrome routinely sends HEADERS without
        // FIN and then a separate FIN-only frame at offset ==
        // self.offset, len = 0). Either way we still must record
        // the FIN if present — `record_fin` handles the
        // FinSeen → Closed promotion.
        if frame_offset + data.len() as u64 <= self.offset {
            if fin {
                self.record_fin(frame_offset + data.len() as u64);
            }
            return false;
        }

        // Trim leading bytes that overlap already-received data.
        let skip = self.offset.saturating_sub(frame_offset);
        let frame_offset = frame_offset + skip;
        let data = &data[skip as usize..];

        if frame_offset == self.offset {
            // Contiguous: append directly.
            self.buffer.extend_from_slice(data);
            self.offset += data.len() as u64;
            produced = !data.is_empty();
            // Try to fold any waiting gap entries in.
            while let Some((&next_off, _)) = self.gap_buffer.iter().next() {
                if next_off > self.offset {
                    break;
                }
                let v = self.gap_buffer.remove(&next_off).unwrap();
                let skip = self.offset.saturating_sub(next_off);
                if (skip as usize) < v.len() {
                    let tail = &v[skip as usize..];
                    self.buffer.extend_from_slice(tail);
                    self.offset += tail.len() as u64;
                    produced = true;
                }
            }
        } else if !data.is_empty() {
            // Out of order — stash until the gap fills, bounded by the
            // receive flow-control window (`recv_max`, enforced in
            // `conn::rx` BEFORE this call: the peer can't send past its
            // granted window, so `gap_buffer` holds ≤ one window).
            //
            // Keep the LONGEST range staged at a given start offset. A
            // re-fragmented retransmit can deliver a SHORTER frame at
            // the same offset; blindly overwriting a longer staged
            // entry would drop its tail — and `conn::rx` already
            // advanced `recv_high` past that tail and ACK'd the packet,
            // so the peer never resends it (unfillable hole → handler
            // wedge, the same dropped-but-acked class as the old fixed
            // gap cap). Stream bytes are immutable per offset, so the
            // longer entry is always a superset — keeping it is never
            // lossy; an equal/shorter duplicate is a no-op.
            let keep = match self.gap_buffer.get(&frame_offset) {
                Some(existing) => existing.len() < data.len(),
                None => true,
            };
            if keep {
                self.gap_buffer.insert(frame_offset, data.to_vec());
            }
        }
        if fin {
            self.record_fin(frame_offset + data.len() as u64);
        } else {
            // Even without a new FIN this frame, our `offset`
            // may have caught up to a previously-seen one.
            self.maybe_close();
        }
        produced
    }

    /// Drain up to `out.len()` bytes from the head of the in-order
    /// buffer. Returns `(bytes_copied, fin_seen_after_drain)` —
    /// `fin_seen_after_drain` is true if FIN has been observed AND
    /// the buffer is now empty (no more data ever).
    pub fn drain(&mut self, out: &mut [u8]) -> (usize, bool) {
        let n = out.len().min(self.buffer.len());
        out[..n].copy_from_slice(&self.buffer[..n]);
        self.buffer.drain(..n);
        let eof = self.is_closed() && self.buffer.is_empty();
        (n, eof)
    }

    pub fn has_buffered(&self) -> bool {
        !self.buffer.is_empty()
    }
}

/// Send-side stream lifecycle. Replaces the
/// (`close_after_drain`, `fin_sent`) bool pair with three
/// mutually-exclusive variants. The two valid states under the
/// old encoding were Open (FF), Closing (TF), FinSent (TT) —
/// the (FT) combination ("fin sent without ever calling close")
/// was unreachable but representable. Now it's not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    /// Accepting writes. `close()` transitions to `Closing`.
    Open,
    /// `close()` was called; we'll emit FIN on the next pop_chunk
    /// after `outbound` drains.
    Closing,
    /// FIN frame has been emitted. No further STREAM frames; no
    /// further writes accepted (write becomes a no-op rather than
    /// panicking — the caller may have a pending write that
    /// raced the close).
    FinSent,
}

/// Per-stream send state. The connection layer drives
/// `pop_chunk` on each outbound 1-RTT packet build.
///
/// Outbound bytes are held as a chain of [`iobuf::IOBuf`]
/// chunks — static-borrowed, heap-owned, or (in future) shared
/// with refcount. `head_consumed` tracks how many bytes of the
/// FRONT chunk have already been emitted in prior pop_chunk
/// calls; only the head needs a cursor (later chunks are
/// untouched until they reach the front). Once the head is
/// fully consumed it's `pop_front`'d and the cursor resets to 0.
///
/// Migrating off `Cow<'static, [u8]>`: the previous `Bytes`
/// alias mapped 1:1 to Cow's two variants. IOBuf is a strict
/// superset — same two cases (Static / Heap), plus per-chunk
/// headroom/tailroom that lower layers (TLS record header /
/// AEAD tag, future per-packet QUIC header prepend) can write
/// into without re-allocating. SendStream itself doesn't read
/// the headroom; it just passes the IOBuf along.
pub struct SendStream {
    /// Outbound chunks, FIFO. Empty payloads are not pushed.
    pub outbound: alloc::collections::VecDeque<iobuf::IOBuf>,
    /// Bytes already emitted from the head chunk's front.
    /// `0..head_consumed` of `outbound[0]` is "drained";
    /// `head_consumed..` is the remaining bytes. Reset to 0
    /// each time we pop_front.
    pub head_consumed: usize,
    /// Offset of the next byte to send. Increments by chunk size
    /// per `pop_chunk` call.
    pub send_offset: u64,
    /// Lifecycle — replaces (`close_after_drain`, `fin_sent`).
    pub state: SendState,
    /// Arrival time (µs) of the request this stream answers, seeded
    /// by `ensure_send_stream` from the matching `RecvStream`. `0`
    /// for an untracked stream (server-initiated, or no matching
    /// request). When non-zero, `enter_fin_sent` records the RX→TX
    /// request latency; cleared to `0` after recording so the
    /// sample fires at most once.
    pub rx_us: u64,
    /// Send-side flow-control limit (RFC 9000 §4.1): the highest
    /// stream offset the peer has authorized us to send, = the peer's
    /// per-stream-class initial limit raised by inbound MAX_STREAM_DATA.
    /// Seeded by `ensure_send_stream`; `send_offset` may not exceed it.
    /// `0` until seeded (no data flows before the handshake completes).
    pub peer_max_stream_data: u64,
}

impl Default for SendStream {
    fn default() -> Self {
        SendStream {
            outbound: alloc::collections::VecDeque::new(),
            head_consumed: 0,
            send_offset: 0,
            state: SendState::Open,
            rx_us: 0,
            peer_max_stream_data: 0,
        }
    }
}

impl SendStream {
    /// Reset to a clean state for reuse. Drains any pending
    /// `outbound` IOBufs (drops them) but preserves the
    /// `VecDeque`'s allocation — the next stream that recycles
    /// this `SendStream` from the per-conn pool gets an empty
    /// chain with non-zero capacity, so its first `push_back`
    /// doesn't trigger a fresh allocation. Saves one heap alloc
    /// per request stream on the H3 hot path.
    pub fn reset_for_reuse(&mut self) {
        self.outbound.clear();
        self.head_consumed = 0;
        self.send_offset = 0;
        self.state = SendState::Open;
        self.rx_us = 0;
        self.peer_max_stream_data = 0;
    }

    /// Convenience predicate (FIN was emitted) — kept for the
    /// reaper, which uses it as half of the "both sides done"
    /// gate.
    pub fn fin_sent(&self) -> bool {
        matches!(self.state, SendState::FinSent)
    }

    /// Transition to `FinSent` — the response is fully encoded — and,
    /// when this is a tracked request stream, record the request
    /// RX→TX latency into `REQUEST_LATENCY`. `rx_us` is seeded by
    /// `ensure_send_stream` from the matching `RecvStream`'s arrival
    /// time (non-zero only for a client-bidi request); it is cleared
    /// after recording so the sample fires at most once.
    fn enter_fin_sent(&mut self) {
        self.state = SendState::FinSent;
        if self.rx_us != 0 {
            let lat_us = tls::ticket::now_us().saturating_sub(self.rx_us);
            crate::diag::REQUEST_LATENCY.record(lat_us);
            self.rx_us = 0;
        }
    }

    /// Canonical append. Takes any pre-built [`IOBuf`] (static
    /// borrow, heap-owned, with or without reserved
    /// headroom/tailroom) and queues it.
    pub fn write_iobuf(&mut self, data: iobuf::IOBuf) {
        if matches!(self.state, SendState::FinSent) || data.is_empty() {
            return;
        }
        self.outbound.push_back(data);
    }

    /// Append an owned `Vec<u8>` by move. `Vec → Box<[u8]>`
    /// transfers the allocation without a copy when len ==
    /// capacity (typical for `Vec::with_capacity` + extend
    /// flows); otherwise `into_boxed_slice` may shrink-realloc.
    pub fn write_owned(&mut self, data: Vec<u8>) {
        self.write_iobuf(iobuf::IOBuf::from(data));
    }

    /// Bytes queued but not yet emitted onto the wire — the sum of the
    /// `outbound` chunk lengths minus the head bytes already sent. The
    /// h3 streaming sink reads this to backpressure `res.write`: once it
    /// exceeds a cap, the handler parks until the connection drains the
    /// chain (peer ACK / window grant), bounding the send buffer to
    /// `O(cap)` rather than `O(response)`.
    pub fn buffered_len(&self) -> usize {
        let total: usize = self.outbound.iter().map(|c| c.data().len()).sum();
        total.saturating_sub(self.head_consumed)
    }

    pub fn close(&mut self) {
        match self.state {
            SendState::Open => self.state = SendState::Closing,
            // Already closing or FIN'd — close is idempotent.
            SendState::Closing | SendState::FinSent => {}
        }
    }

    /// `true` if no bytes are queued AND no close is pending.
    /// Used by `has_pending_one_rtt_data` and the reaper.
    pub fn outbound_is_empty(&self) -> bool {
        self.outbound.is_empty()
    }

    /// How many bytes of the head chunk are still un-emitted.
    /// 0 if no chunks remain.
    fn head_remaining_len(&self) -> usize {
        self.outbound
            .front()
            .map(|b| b.len() - self.head_consumed)
            .unwrap_or(0)
    }

    /// Advance the head cursor by `n` bytes. Pops the head and
    /// resets the cursor when fully drained.
    fn advance_head(&mut self, n: usize) {
        self.head_consumed += n;
        if let Some(head) = self.outbound.front()
            && self.head_consumed == head.len()
        {
            self.outbound.pop_front();
            self.head_consumed = 0;
        }
    }

    /// Pop up to `max_bytes` from the front of the chunk chain as a
    /// refcount-shared [`IOBuf`] view, returning `(offset, view, fin)`.
    /// The view is what the encode path retains as a `StreamRetx` for
    /// retransmission (RFC 9002 §6) — a `clone_shared` + `narrow` of
    /// the queued chunk's storage, NOT a heap copy, so the TX path's
    /// only per-byte pass is the encode write into the packet buffer.
    /// The head chunk is promoted to `Shared` in place on first touch
    /// (Heap/External Arc-wrap with no byte copy; an External — pooled
    /// framing buffer — simply defers its pool-recycle drop until the
    /// last retained view is ACKed, ≤ 1 RTT). A `Closing` stream with
    /// empty `outbound` yields a zero-length FIN.
    pub fn pop_chunk(&mut self, max_bytes: usize) -> Option<(u64, iobuf::IOBuf, bool)> {
        match self.state {
            SendState::FinSent => return None,
            SendState::Open if self.outbound.is_empty() => return None,
            _ => {}
        }
        let offset = self.send_offset;
        if self.outbound.is_empty() {
            // Closing with empty outbound → zero-byte FIN. An empty
            // Vec-backed IOBuf allocates nothing.
            self.enter_fin_sent();
            return Some((offset, iobuf::IOBuf::from(Vec::new()), true));
        }
        let head_remaining = self.head_remaining_len();
        let n = head_remaining.min(max_bytes);
        let view = {
            let head = self.outbound.front_mut().unwrap();
            let mut v = match head.clone_shared() {
                Ok(v) => v,
                Err(_) => {
                    // First slice off a Heap/External chunk: promote to
                    // Shared in place (Arc wrap, no byte copy). Static
                    // and already-Shared chunks took the Ok arm.
                    let taken = core::mem::replace(head, iobuf::IOBuf::from(Vec::new()));
                    *head = taken.share();
                    head.clone_shared().ok()? // infallible post-promote
                }
            };
            // Narrow to this slice of the chunk's visible window. In
            // bounds by construction (`n ≤ head_remaining`); the
            // defensive `ok()?` mirrors the crate's panic-free style.
            v.narrow(self.head_consumed, n).ok()?;
            v
        };
        self.advance_head(n);
        self.send_offset += n as u64;
        let fin = matches!(self.state, SendState::Closing) && self.outbound.is_empty();
        if fin {
            self.enter_fin_sent();
        }
        Some((offset, view, fin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_in_order_no_fin() {
        let mut s = RecvStream::default();
        assert!(s.ingest(0, b"hello", false));
        assert!(s.ingest(5, b" world", false));
        let mut out = [0u8; 16];
        let (n, eof) = s.drain(&mut out);
        assert_eq!(n, 11);
        assert_eq!(&out[..n], b"hello world");
        assert!(!eof);
    }

    #[test]
    fn recv_out_of_order_then_gap_fills() {
        let mut s = RecvStream::default();
        // Late frame at offset 5 arrives before the offset-0 frame.
        assert!(!s.ingest(5, b"world", false));
        assert!(s.ingest(0, b"hello", false));
        let mut out = [0u8; 16];
        let (n, _) = s.drain(&mut out);
        assert_eq!(&out[..n], b"helloworld");
    }

    /// Regression: out-of-order data spanning more than the old
    /// fixed 16 KiB gap budget must still buffer and fold in once the
    /// leading gap fills — never silently drop. The old cap dropped
    /// in-window frames whose packets `conn::rx` had already
    /// processed (and would ACK), so the peer never retransmitted
    /// them, leaving an unfillable gap that wedged the recv handler
    /// (`handler_stuck`) on any upload reordered past 16 KiB. The
    /// reorder bound is now the flow-control window (`recv_max`),
    /// enforced upstream in `conn::rx`.
    #[test]
    fn recv_out_of_order_past_16k_then_fills() {
        let mut s = RecvStream::default();
        // 32 KiB of body, default recv_max (2 MiB) covers it. Deliver
        // the *tail* first (offset 1 KiB .. 32 KiB), in 1 KiB frames,
        // newest-offset-first so >16 KiB sits out of order at once —
        // the exact shape the old 16 KiB cap dropped.
        let chunk = [0xABu8; 1024];
        let mut off = 31 * 1024u64;
        loop {
            assert!(!s.ingest(off, &chunk, false)); // gap → no contiguous bytes yet
            if off == 1024 {
                break;
            }
            off -= 1024;
        }
        // Nothing contiguous drains while the head [0, 1 KiB) is missing.
        let mut out = [0u8; 64 * 1024];
        assert_eq!(s.drain(&mut out).0, 0);
        // Head arrives → the whole 32 KiB folds in (no dropped frame).
        assert!(s.ingest(0, &chunk, false));
        let (n, _) = s.drain(&mut out);
        assert_eq!(n, 32 * 1024, "all 32 KiB present — nothing dropped");
        assert!(out[..n].iter().all(|&b| b == 0xAB));
    }

    /// Regression: a shorter re-fragmented retransmit at the SAME start
    /// offset as a longer staged out-of-order frame must NOT evict the
    /// longer entry's tail. `conn::rx` has already counted that tail in
    /// `recv_high` and ACK'd its packet, so dropping it leaves an
    /// unfillable hole (the dropped-but-acked wedge). `ingest` keeps the
    /// longest range at a given offset.
    #[test]
    fn recv_overlapping_shorter_frame_keeps_longer() {
        let mut s = RecvStream::default();
        // Stage [10, 60) out of order (50 bytes).
        assert!(!s.ingest(10, &[0xAA; 50], false));
        // A shorter retransmit at the same offset [10, 30) arrives later.
        assert!(!s.ingest(10, &[0xAA; 20], false));
        // Fill the head gap [0, 10) → everything folds in.
        assert!(s.ingest(0, &[0xBB; 10], false));
        let mut out = [0u8; 128];
        let (n, _) = s.drain(&mut out);
        assert_eq!(n, 60, "head 10 + full 50-byte staged range; tail not dropped");
        assert!(out[..10].iter().all(|&b| b == 0xBB));
        assert!(out[10..60].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn recv_fin_makes_drain_signal_eof() {
        let mut s = RecvStream::default();
        s.ingest(0, b"hi", true);
        let mut out = [0u8; 8];
        let (n, eof) = s.drain(&mut out);
        assert_eq!(&out[..n], b"hi");
        assert!(eof);
    }

    /// Regression: Chrome (and other HTTP/3 clients) routinely
    /// send HEADERS without FIN, then a separate FIN-only STREAM
    /// frame at offset == current offset, length 0. Previously
    /// the stale-frame early return set `fin_offset` but skipped
    /// the `closed` update, and `drain()` would never report eof
    /// — wedging any handler awaiting the request body.
    #[test]
    fn recv_fin_only_frame_after_data_signals_eof() {
        let mut s = RecvStream::default();
        s.ingest(0, b"GET /", false);
        let mut out = [0u8; 8];
        let (n, eof) = s.drain(&mut out);
        assert_eq!(&out[..n], b"GET /");
        assert!(!eof);
        s.ingest(5, b"", true);
        let (n2, eof2) = s.drain(&mut out);
        assert_eq!(n2, 0);
        assert!(eof2);
    }

    // ── Exhaustive RecvStream state-transition coverage ─────────
    //
    // The bugs we've shipped to production were each one missed
    // (state, input) transition. The tests below cover every
    // legal combination of frame placement vs current `offset` /
    // `fin_offset`, asserting the same invariant at the end:
    //
    //   "drain() returns eof=true iff the peer has signalled FIN
    //    AND every byte up to fin_offset has been delivered to
    //    the app."
    //
    // If a future change re-introduces the FIN-skip-closed bug
    // (or any cousin), the matching test below fails immediately.

    fn drain_all(s: &mut RecvStream) -> (alloc::vec::Vec<u8>, bool) {
        let mut out = [0u8; 4096];
        let mut collected = alloc::vec::Vec::new();
        loop {
            let (n, eof) = s.drain(&mut out);
            collected.extend_from_slice(&out[..n]);
            if n == 0 {
                return (collected, eof);
            }
            if eof {
                return (collected, eof);
            }
        }
    }

    #[test]
    fn recv_fin_with_data_in_one_frame() {
        let mut s = RecvStream::default();
        s.ingest(0, b"hello", true);
        let (data, eof) = drain_all(&mut s);
        assert_eq!(&data[..], b"hello");
        assert!(eof);
    }

    #[test]
    fn recv_data_then_fin_only_at_boundary() {
        // Most common Chrome HTTP/3 GET pattern.
        let mut s = RecvStream::default();
        s.ingest(0, b"hello", false);
        s.ingest(5, b"", true);
        let (data, eof) = drain_all(&mut s);
        assert_eq!(&data[..], b"hello");
        assert!(eof);
    }

    #[test]
    fn recv_drain_then_fin_only_at_boundary() {
        // Same as above but app drains between ingests.
        let mut s = RecvStream::default();
        s.ingest(0, b"hello", false);
        let mut out = [0u8; 16];
        s.drain(&mut out);
        s.ingest(5, b"", true);
        let (_, eof) = s.drain(&mut out);
        assert!(eof);
    }

    #[test]
    fn recv_retransmit_of_fin_bearing_frame() {
        // Peer retransmits same data+FIN frame (same offset/len/fin).
        // `closed` must end up true; idempotent.
        let mut s = RecvStream::default();
        s.ingest(0, b"hello", true);
        s.ingest(0, b"hello", true);
        let (data, eof) = drain_all(&mut s);
        assert_eq!(&data[..], b"hello");
        assert!(eof);
    }

    #[test]
    fn recv_partial_overlap_carrying_fin() {
        // FIN frame partially overlaps already-received data.
        let mut s = RecvStream::default();
        s.ingest(0, b"hello", false);
        // overlap: first 3 bytes already seen, last 4 are new+FIN.
        s.ingest(2, b"llo wo", true); // 2..8
        let (data, eof) = drain_all(&mut s);
        assert_eq!(&data[..], b"hello wo");
        assert!(eof);
    }

    #[test]
    fn recv_out_of_order_then_fill_with_fin() {
        // FIN frame arrives first (gap-buffered), data fills gap.
        let mut s = RecvStream::default();
        s.ingest(5, b"world", true); // gap-buffered, fin_offset=10
        let (n, eof) = s.drain(&mut [0u8; 16]);
        assert_eq!(n, 0);
        assert!(!eof);
        s.ingest(0, b"hello", false);
        let (data, eof) = drain_all(&mut s);
        assert_eq!(&data[..], b"helloworld");
        assert!(eof);
    }

    #[test]
    fn recv_out_of_order_then_fill_then_fin_only() {
        let mut s = RecvStream::default();
        s.ingest(5, b"world", false); // gap-buffered
        s.ingest(0, b"hello", false); // fold-in → offset=10
        s.ingest(10, b"", true); // FIN at boundary
        let (data, eof) = drain_all(&mut s);
        assert_eq!(&data[..], b"helloworld");
        assert!(eof);
    }

    #[test]
    fn recv_fin_arrives_before_any_data() {
        // FIN-only frame at offset 0, no data yet sent.
        let mut s = RecvStream::default();
        s.ingest(0, b"", true);
        let (n, eof) = s.drain(&mut [0u8; 8]);
        assert_eq!(n, 0);
        assert!(eof);
    }

    #[test]
    fn recv_drain_eof_is_idempotent() {
        // Calling drain after eof keeps returning eof=true.
        let mut s = RecvStream::default();
        s.ingest(0, b"x", true);
        let mut out = [0u8; 4];
        let (_, eof1) = s.drain(&mut out);
        assert!(eof1);
        let (n2, eof2) = s.drain(&mut out);
        assert_eq!(n2, 0);
        assert!(eof2);
    }

    #[test]
    fn recv_fin_in_stale_retransmit() {
        // Peer drops the FIN bit on first send, sets it on retx
        // (legal — sender state machine may decide at retx time).
        let mut s = RecvStream::default();
        s.ingest(0, b"hello", false);
        let mut out = [0u8; 8];
        s.drain(&mut out);
        // Retx of same range, this time with FIN.
        s.ingest(0, b"hello", true);
        let (_, eof) = s.drain(&mut out);
        assert!(eof);
    }

    #[test]
    fn recv_eof_only_after_buffer_drained() {
        // Until the app has actually consumed the bytes,
        // eof must remain false.
        let mut s = RecvStream::default();
        s.ingest(0, b"hello", true);
        let mut out = [0u8; 3];
        let (n, eof) = s.drain(&mut out);
        assert_eq!(n, 3);
        assert!(!eof, "buffer not yet drained");
        let (n2, eof2) = s.drain(&mut out);
        assert_eq!(n2, 2);
        assert!(eof2);
    }

    #[test]
    fn send_chunks_and_fin_on_close() {
        let mut s = SendStream::default();
        s.write_owned(b"hello".to_vec());
        s.close();
        let (off, c, fin) = s.pop_chunk(1024).unwrap();
        assert_eq!(off, 0);
        assert_eq!(c.data(), b"hello");
        assert!(fin);
        // After fin, no further chunks.
        assert!(s.pop_chunk(1024).is_none());
    }

    #[test]
    fn send_pops_in_chunks() {
        let mut s = SendStream::default();
        s.write_owned(b"abcdefghij".to_vec());
        let (off1, c1, fin1) = s.pop_chunk(4).unwrap();
        assert_eq!(off1, 0);
        assert_eq!(c1.data(), b"abcd");
        assert!(!fin1);
        let (off2, c2, _) = s.pop_chunk(4).unwrap();
        assert_eq!(off2, 4);
        assert_eq!(c2.data(), b"efgh");
    }

    /// `buffered_len` reports the un-emitted byte count
    /// (`sum(outbound lens) - head_consumed`) that the h2/h3 streaming
    /// sinks read to backpressure `res.write`. This pins its accounting
    /// across writes + (partial and full) pops: if it ever over-reports
    /// the send-buffer cap parks the handler forever, and if it
    /// under-reports the buffer grows unbounded (OOM). Guards both.
    #[test]
    fn send_buffered_len_tracks_writes_and_pops() {
        let mut s = SendStream::default();
        assert_eq!(s.buffered_len(), 0);
        s.write_owned(b"abcdefghij".to_vec()); // 10
        s.write_owned(b"klmno".to_vec()); // +5 = 15
        assert_eq!(s.buffered_len(), 15);
        // Partial pop of the head chunk (4 of the first 10).
        s.pop_chunk(4).unwrap();
        assert_eq!(s.buffered_len(), 11);
        // Pop the rest of the head chunk (6) → first chunk retires.
        s.pop_chunk(6).unwrap();
        assert_eq!(s.buffered_len(), 5);
        // Drain the tail chunk fully.
        s.pop_chunk(100).unwrap();
        assert_eq!(s.buffered_len(), 0);
        // A fresh write counts again, and `reset_for_reuse` clears it.
        s.write_owned(b"xyz".to_vec());
        assert_eq!(s.buffered_len(), 3);
        s.reset_for_reuse();
        assert_eq!(s.buffered_len(), 0);
    }
}
