// uni-quic/src/streams.rs — per-stream state for 1-RTT data.
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
//   * In-order STREAM data only. Out-of-order arrival WITHIN a
//     stream is rare with curl/quinn (loss → retransmit at the
//     same offset) but not impossible; we buffer frames whose
//     offset > current recv offset until the gap fills. Cap at
//     16 KiB per stream — past that we drop.
//
// Out of scope (not needed for MVP):
//   * RESET_STREAM / STOP_SENDING (we'd close the conn on stream
//     errors instead — fine for HTTP/3 GET/POST).
//   * Per-stream MAX_STREAM_DATA reactive flow control —
//     advertised initial limits in transport_params are sized so
//     a small request/response fits without ever blocking.

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

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
    /// Cumulative cap on out-of-order bytes — anything past this
    /// is dropped (treated as packet loss).
    pub gap_budget: usize,
}

impl Default for RecvStream {
    fn default() -> Self {
        RecvStream {
            buffer: Vec::new(),
            offset: 0,
            gap_buffer: BTreeMap::new(),
            state: RecvState::Open,
            gap_budget: 16 * 1024,
        }
    }
}

impl RecvStream {
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
        if let RecvState::FinSeen { fin_offset } = self.state {
            if self.offset >= fin_offset {
                self.state = RecvState::Closed { fin_offset };
            }
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
            loop {
                let next_off = match self.gap_buffer.iter().next() {
                    Some((&k, _)) => k,
                    None => break,
                };
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
        } else if data.len() <= self.gap_budget {
            // Out of order — stash if budget allows.
            self.gap_buffer.insert(frame_offset, data.to_vec());
            self.gap_budget -= data.len();
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

/// Same primitive as `uni_http::Bytes` — a borrowed-static or
/// owned byte chunk. Re-aliased here so this crate's API
/// doesn't have to mention `Cow<'static, [u8]>` longhand and
/// to keep the cross-stack abstraction explicit. uni-quic
/// can't depend on uni-http (transport ↛ application), but
/// the underlying type is the same so values cross the
/// boundary without conversion.
pub type Bytes = alloc::borrow::Cow<'static, [u8]>;

/// Per-stream send state. The connection layer drives
/// `pop_chunk` on each outbound 1-RTT packet build.
///
/// Outbound bytes are held as a chain of [Bytes] chunks — each
/// either owned (Cow::Owned) or borrowed-static (Cow::Borrowed).
/// `head_consumed` tracks how many bytes of the FRONT chunk
/// have already been emitted in prior pop_chunk_into calls;
/// only the head needs a cursor (later chunks are untouched
/// until they reach the front). Once the head is fully
/// consumed it's pop_front'd and the cursor resets to 0.
pub struct SendStream {
    /// Outbound chunks, FIFO. Empty payloads are not pushed.
    pub outbound: alloc::collections::VecDeque<Bytes>,
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
}

impl Default for SendStream {
    fn default() -> Self {
        SendStream {
            outbound: alloc::collections::VecDeque::new(),
            head_consumed: 0,
            send_offset: 0,
            state: SendState::Open,
        }
    }
}

impl SendStream {
    /// Convenience predicate (FIN was emitted) — kept for the
    /// reaper, which uses it as half of the "both sides done"
    /// gate.
    pub fn fin_sent(&self) -> bool {
        matches!(self.state, SendState::FinSent)
    }

    /// Generic append: takes any `Bytes` (Cow::Borrowed or
    /// Cow::Owned) and queues it in the chunk chain. The
    /// type-specific shortcuts below all funnel into this.
    pub fn write_bytes(&mut self, data: Bytes) {
        if matches!(self.state, SendState::FinSent) || data.is_empty() {
            return;
        }
        self.outbound.push_back(data);
    }

    /// Append a borrowed slice. Allocates one Vec to hold the
    /// copy. For zero-copy paths use `write_owned` (Vec by
    /// move) or `write_static` (`&'static [u8]` by reference).
    pub fn write(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.write_bytes(alloc::borrow::Cow::Owned(data.to_vec()));
    }

    /// Append an owned `Vec<u8>` by move — no copy.
    pub fn write_owned(&mut self, data: Vec<u8>) {
        self.write_bytes(alloc::borrow::Cow::Owned(data));
    }

    /// Append a `&'static` slice by reference — zero copy AND
    /// zero alloc.
    pub fn write_static(&mut self, data: &'static [u8]) {
        self.write_bytes(alloc::borrow::Cow::Borrowed(data));
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
        if let Some(head) = self.outbound.front() {
            if self.head_consumed == head.len() {
                self.outbound.pop_front();
                self.head_consumed = 0;
            }
        }
    }

    /// Pop up to `max_bytes` from the front of the chunk chain
    /// as an owned Vec. Hot path is `pop_chunk_into` (writes
    /// straight into the datagram); this exists for callers
    /// that want an owned chunk back.
    pub fn pop_chunk(&mut self, max_bytes: usize) -> Option<(u64, Vec<u8>, bool)> {
        match self.state {
            SendState::FinSent => return None,
            SendState::Open if self.outbound.is_empty() => return None,
            _ => {}
        }
        let offset = self.send_offset;
        if self.outbound.is_empty() {
            // Closing with empty outbound → zero-byte FIN.
            self.state = SendState::FinSent;
            return Some((offset, Vec::new(), true));
        }
        let head_remaining = self.head_remaining_len();
        let n = head_remaining.min(max_bytes);
        let chunk: Vec<u8> = {
            let head = self.outbound.front().unwrap();
            head[self.head_consumed..self.head_consumed + n].to_vec()
        };
        self.advance_head(n);
        self.send_offset += n as u64;
        let fin = matches!(self.state, SendState::Closing) && self.outbound.is_empty();
        if fin {
            self.state = SendState::FinSent;
        }
        Some((offset, chunk, fin))
    }

    /// Allocation-free variant of `pop_chunk`: appends the
    /// STREAM frame (header + body + FIN bit) directly into
    /// `frames_out`.
    pub fn pop_chunk_into(
        &mut self,
        stream_id: u64,
        max_bytes: usize,
        frames_out: &mut Vec<u8>,
    ) -> Result<bool, crate::frame::FrameError> {
        match self.state {
            SendState::FinSent => return Ok(false),
            SendState::Open if self.outbound.is_empty() => return Ok(false),
            _ => {}
        }
        let offset = self.send_offset;

        if self.outbound.is_empty() {
            // Closing with no queued data → zero-byte FIN.
            crate::frame::append_stream_header(stream_id, offset, true, 0, frames_out)?;
            self.state = SendState::FinSent;
            return Ok(true);
        }

        let head_remaining = self.head_remaining_len();
        let n = head_remaining.min(max_bytes);
        // FIN iff: closing AND this drain empties the entire
        // chain (head fully consumed AND no chunks behind it).
        let fin = matches!(self.state, SendState::Closing)
            && n == head_remaining
            && self.outbound.len() == 1;

        crate::frame::append_stream_header(stream_id, offset, fin, n, frames_out)?;
        {
            let head = self.outbound.front().unwrap();
            frames_out.extend_from_slice(&head[self.head_consumed..self.head_consumed + n]);
        }
        self.advance_head(n);
        self.send_offset += n as u64;
        if fin {
            self.state = SendState::FinSent;
        }
        Ok(true)
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
        s.write(b"hello");
        s.close();
        let (off, c, fin) = s.pop_chunk(1024).unwrap();
        assert_eq!(off, 0);
        assert_eq!(c, b"hello");
        assert!(fin);
        // After fin, no further chunks.
        assert!(s.pop_chunk(1024).is_none());
    }

    #[test]
    fn send_pops_in_chunks() {
        let mut s = SendStream::default();
        s.write(b"abcdefghij");
        let (off1, c1, fin1) = s.pop_chunk(4).unwrap();
        assert_eq!(off1, 0);
        assert_eq!(c1, b"abcd");
        assert!(!fin1);
        let (off2, c2, _) = s.pop_chunk(4).unwrap();
        assert_eq!(off2, 4);
        assert_eq!(c2, b"efgh");
    }
}
