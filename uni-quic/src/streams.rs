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

/// Per-stream receive state. Keeps a contiguous in-order byte
/// buffer + an offset map for any out-of-order tail.
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
    /// Set when a STREAM frame with FIN has been seen. Combined
    /// with `offset >= fin_offset` to determine "all data has been
    /// delivered."
    pub fin_offset: Option<u64>,
    /// `true` once the app has consumed everything up to fin_offset.
    pub closed: bool,
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
            fin_offset: None,
            closed: false,
            gap_budget: 16 * 1024,
        }
    }
}

impl RecvStream {
    /// Ingest a STREAM frame's `(offset, data, fin)` triple.
    /// Returns `true` if this frame contributed any new contiguous
    /// bytes (caller may want to wake the recv future).
    pub fn ingest(&mut self, frame_offset: u64, data: &[u8], fin: bool) -> bool {
        let mut produced = false;
        // Frame entirely below current offset → already-seen
        // retransmit, OR a FIN-only frame at the current offset
        // with length 0 (Chrome routinely sends HEADERS without
        // FIN and then a separate FIN-only frame; the inequality
        // is non-strict so a 0-length FIN at offset==self.offset
        // hits this branch). We still need to record the FIN and
        // — critically — set `closed` if it's now reached, since
        // the early-return below would otherwise skip the
        // closed-update at the bottom and `drain()` would never
        // report eof, hanging any reader awaiting the FIN.
        if frame_offset + data.len() as u64 <= self.offset {
            if fin {
                let end = frame_offset + data.len() as u64;
                self.fin_offset = Some(self.fin_offset.map_or(end, |x| x.max(end)));
                if let Some(f) = self.fin_offset {
                    if self.offset >= f {
                        self.closed = true;
                    }
                }
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
            let end = frame_offset + data.len() as u64;
            self.fin_offset = Some(self.fin_offset.map_or(end, |x| x.max(end)));
        }
        if let Some(f) = self.fin_offset {
            if self.offset >= f {
                self.closed = true;
            }
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
        let eof =
            self.fin_offset.is_some() && self.buffer.is_empty() && self.closed;
        (n, eof)
    }

    pub fn has_buffered(&self) -> bool {
        !self.buffer.is_empty()
    }
}

/// Per-stream send state. The connection layer drives
/// `pop_chunk` on each outbound 1-RTT packet build.
pub struct SendStream {
    /// Byte buffer waiting to ship. `pop_chunk` slices off the
    /// front into a STREAM frame body.
    pub outbound: Vec<u8>,
    /// Offset of the next byte to send. Increments by chunk size
    /// per `pop_chunk` call.
    pub send_offset: u64,
    /// Set by `close()` — once the buffer is empty we'll emit
    /// FIN on the final STREAM frame.
    pub close_after_drain: bool,
    /// `true` once a STREAM frame with FIN has been emitted; no
    /// further STREAM frames go out for this stream.
    pub fin_sent: bool,
}

impl Default for SendStream {
    fn default() -> Self {
        SendStream {
            outbound: Vec::new(),
            send_offset: 0,
            close_after_drain: false,
            fin_sent: false,
        }
    }
}

impl SendStream {
    pub fn write(&mut self, data: &[u8]) {
        self.outbound.extend_from_slice(data);
    }
    pub fn close(&mut self) {
        self.close_after_drain = true;
    }
    /// Pop up to `max_bytes` from the front. Returns
    /// `(offset, data, fin)`. `fin` is `true` only if `close()`
    /// was called and we just popped the final byte.
    pub fn pop_chunk(&mut self, max_bytes: usize) -> Option<(u64, Vec<u8>, bool)> {
        if self.fin_sent {
            return None;
        }
        if self.outbound.is_empty() && !self.close_after_drain {
            return None;
        }
        let n = self.outbound.len().min(max_bytes);
        let chunk: Vec<u8> = self.outbound.drain(..n).collect();
        let offset = self.send_offset;
        self.send_offset += n as u64;
        let fin = self.close_after_drain && self.outbound.is_empty();
        if fin {
            self.fin_sent = true;
        }
        Some((offset, chunk, fin))
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
        // First frame: data, no FIN.
        s.ingest(0, b"GET /", false);
        let mut out = [0u8; 8];
        let (n, eof) = s.drain(&mut out);
        assert_eq!(&out[..n], b"GET /");
        assert!(!eof);
        // Second frame: empty, FIN at offset == current offset.
        s.ingest(5, b"", true);
        let (n2, eof2) = s.drain(&mut out);
        assert_eq!(n2, 0);
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
