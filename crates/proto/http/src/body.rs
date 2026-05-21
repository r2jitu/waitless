// Streaming request-body reader.
//
// Hands the handler bytes the request declared via Content-Length,
// drawn first from any prebuf bytes that rode in with the headers
// and then from the transport stream's own `recv_chunk` path —
// both surfaced zero-copy through `BodyChunkGuard`.

use core::marker::PhantomData;

use iobuf::IOBuf;

use crate::stream::HttpStream;

/// Streaming reader for the request body.
///
/// Bytes are exposed via [`chunk`](Self::chunk) as a
/// [`BodyChunkGuard`] — a zero-copy view over whichever buffer
/// currently holds them:
///   * the per-connection parse buffer (`prebuf`) — body bytes that
///     arrived in the same TCP/TLS read that delivered the headers;
///   * the transport's own buffer past the prebuf — surfaced by
///     [`HttpStream::recv_chunk`] with no intermediate copy (an
///     `ExternalOwned` NIC RX buffer on bare-metal TCP, a
///     `Borrowed` view into the TLS plaintext window for HTTPS).
///
/// Before RX item H the past-prebuf bytes were copied through a
/// 4 KiB `refill` scratch field; `recv_chunk` removes that copy, so
/// the field is gone — small bodies are served straight from the
/// prebuf, large ones straight from the transport buffer.
///
/// The reader knows the total body length (from the request's
/// `Content-Length`) and stops handing out bytes after exactly
/// that many have been delivered, so the underlying transport
/// stream is left positioned at the start of the next pipelined
/// request.
///
/// If the handler returns without consuming all bytes,
/// `serve_conn` calls [`discard`](Self::discard) before sending the
/// response so the keep-alive contract holds. Handlers that
/// intentionally want to abort a large unwanted upload should
/// return a response with `Connection: close` set; `serve_conn`
/// then skips the drain and tears down the conn.
pub struct BodyReader<'a, S: HttpStream> {
    stream: &'a mut S,
    /// Bytes from `serve_conn`'s parse buffer that belong to the
    /// body — already received from the wire by the time the
    /// handler runs.
    prebuf: &'a [u8],
    prebuf_consumed: usize,
    /// Total body length declared by the request's Content-Length.
    total: usize,
    /// Bytes already handed to the handler via `chunk`.
    delivered: usize,
}

impl<'a, S: HttpStream> BodyReader<'a, S> {
    /// Construct a reader against `stream`, with `prebuf` carrying
    /// any body bytes already received during the parse step.
    /// `total` is the declared body length; the reader delivers
    /// exactly that many bytes (possibly fewer on EOF) and refuses
    /// to read past it into the next pipelined request.
    pub fn new(stream: &'a mut S, prebuf: &'a [u8], total: usize) -> Self {
        // Trim `prebuf` to at most `total` so the reader never
        // reaches into post-body bytes (next pipelined request).
        let prebuf_avail = prebuf.len().min(total);
        BodyReader {
            stream,
            prebuf: &prebuf[..prebuf_avail],
            prebuf_consumed: 0,
            total,
            delivered: 0,
        }
    }

    /// Total body length (Content-Length).
    pub fn len(&self) -> usize {
        self.total
    }

    /// Bytes still to be delivered.
    pub fn remaining(&self) -> usize {
        self.total - self.delivered
    }

    /// True once the body is fully consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Get the next chunk of body bytes as a [`BodyChunkGuard`].
    ///
    /// `None` signals end-of-body — either the expected "all
    /// `Content-Length` bytes delivered" end state (the caller
    /// stops) or "transport EOF / close before `Content-Length` was
    /// reached." Distinguish the two via [`remaining`](Self::remaining):
    /// a clean end leaves it at 0.
    ///
    /// Two byte sources, both surfaced zero-copy:
    ///   * **Prebuf** — body bytes that rode in with the request
    ///     headers. The guard wraps a `Borrowed` `IOBuf` over
    ///     `serve_conn`'s parse buffer.
    ///   * **Past the prebuf** — pulled from the transport via
    ///     [`HttpStream::recv_chunk`]; the guard wraps whatever that
    ///     surfaced (an `ExternalOwned` NIC RX buffer for bare-metal
    ///     TCP, a `Borrowed` view into the TLS plaintext window).
    ///
    /// The returned guard borrows `&mut self` for its whole life, so
    /// the transport buffer it views cannot be re-read — hence
    /// overwritten — while the handler still holds the chunk. That
    /// is the item-F/G borrow-safety property, one layer up.
    ///
    /// A single `recv_chunk` chunk is delivered whole; the rare case
    /// where one straddles the `Content-Length` boundary — reachable
    /// only when a client pipelines a follow-up request into the
    /// tail segment of a body that overflowed the 16 KiB parse
    /// buffer — has its delivered slice capped at the remaining body
    /// length, and the straddling bytes are dropped. The server has
    /// no streaming header parser yet (Phase 4), so post-large-body
    /// pipelining is out of scope; the cap is what keeps the handler
    /// and the `delivered` accounting correct regardless.
    pub async fn chunk(&mut self) -> Option<BodyChunkGuard<'_>> {
        if self.delivered >= self.total {
            return None;
        }
        let want_max = self.total - self.delivered;

        // 1. Drain prebuf first — zero-copy, the bytes already sit
        //    in serve_conn's parse buffer.
        if self.prebuf_consumed < self.prebuf.len() {
            let start = self.prebuf_consumed;
            let avail = self.prebuf.len() - start;
            let take = avail.min(want_max);
            self.prebuf_consumed += take;
            self.delivered += take;
            let slice = &self.prebuf[start..start + take];
            // SAFETY: `IOBuf::borrow` needs the region valid,
            // unaliased, and unmutated for the IOBuf's whole life.
            //  * `slice` points into `serve_conn`'s parse buffer; it
            //    is `take` bytes, in-bounds, and — a slice pointer —
            //    non-null and aligned.
            //  * The returned `BodyChunkGuard` carries the
            //    `&mut self` borrow for its whole life, so the
            //    handler cannot return — and `serve_conn` cannot
            //    resume to mutate the parse buffer — while the guard
            //    is live.
            //  * The `Borrowed` IOBuf is owned by the guard and
            //    drops with it; no drop callback (the bytes are
            //    borrowed, not owned).
            let iobuf = unsafe {
                IOBuf::borrow(
                    core::ptr::NonNull::new_unchecked(slice.as_ptr() as *mut u8),
                    take as u32,
                    0,
                    take as u32,
                )
            };
            return Some(BodyChunkGuard {
                src: ChunkSource::Prebuf(iobuf, PhantomData),
            });
        }

        // 2. Past the prebuf — pull a zero-copy chunk straight from
        //    the transport. `recv_chunk` surfaces the transport's
        //    own buffer (NIC RX buffer / TLS plaintext window).
        //    `None` means peer close / EOF, or a transport with no
        //    chunk path (NullStream / HTTP/3, whose whole body is
        //    always in the prebuf — this branch is unreachable for
        //    it). `take` caps the delivery at the remaining body
        //    length; see the straddle note above.
        let guard = self.stream.recv_chunk().await?;
        let take = guard.data().len().min(want_max);
        if take == 0 {
            return None;
        }
        self.delivered += take;
        Some(BodyChunkGuard {
            src: ChunkSource::Stream { guard, len: take },
        })
    }

    /// Drain the rest of the body, dropping every byte. Returns
    /// `Err` if the transport closed before delivering all
    /// `Content-Length` bytes — caller's contract is to tear the
    /// connection down in that case.
    pub async fn discard(&mut self) -> Result<(), ()> {
        while self.delivered < self.total {
            match self.chunk().await {
                Some(g) if !g.data().is_empty() => {}
                // `None` (or a chunk that came back empty) before
                // `delivered` reached `total` — the transport
                // closed mid-body.
                _ => return Err(()),
            }
        }
        Ok(())
    }
}

/// A single contiguous chunk of request-body bytes, handed to the
/// handler by [`BodyReader::chunk`].
///
/// The guard borrows the `BodyReader` — hence the transport's
/// buffer — for its whole life: read the bytes in place with
/// [`data`](Self::data) (zero copy), or call
/// [`into_owned`](Self::into_owned) to lift them into an owned
/// [`IOBuf`] that can outlive the guard (e.g. a proxy forwarding
/// the chunk into an outbound `send`).
///
/// Single-part by design: `BodyReader` delivers one contiguous run
/// of bytes per `chunk` call. Multi-part RX delivery is a separate
/// RX-path item; this API stays frozen single-part.
pub struct BodyChunkGuard<'a> {
    src: ChunkSource<'a>,
}

/// Which buffer a [`BodyChunkGuard`]'s bytes live in. Private — the
/// source is an implementation detail; handlers see only `data()` /
/// `into_owned()`.
enum ChunkSource<'a> {
    /// Body bytes that arrived in the same read as the request
    /// headers: a `Borrowed` `IOBuf` over `serve_conn`'s parse
    /// buffer. `data()` is zero copy; `into_owned()` copies to
    /// `Heap`. The `PhantomData` ties the borrow to the
    /// `&'a mut BodyReader` that `chunk` took — the parse buffer
    /// must not be mutated while the chunk is live.
    Prebuf(IOBuf, PhantomData<&'a mut ()>),
    /// Body bytes past the prebuf: the transport's own buffer, held
    /// behind the [`RecvChunkGuard`](waitless::runtime::RecvChunkGuard)
    /// that `stream.recv_chunk()` surfaced (which already carries
    /// the `&'a mut` borrow). `len` is the delivered byte count —
    /// equal to the surfaced chunk length except when a chunk
    /// straddles the `Content-Length` boundary, where it is capped.
    Stream {
        guard: waitless::runtime::RecvChunkGuard<'a>,
        len: usize,
    },
}

impl<'a> BodyChunkGuard<'a> {
    /// The chunk's body bytes, read in place. Zero copy.
    pub fn data(&self) -> &[u8] {
        match &self.src {
            ChunkSource::Prebuf(buf, _) => buf.data(),
            ChunkSource::Stream { guard, len } => &guard.data()[..*len],
        }
    }

    /// Take owned possession of the chunk's bytes.
    ///
    /// Zero copy when the bytes already sit in an owned buffer — the
    /// `ExternalOwned` NIC RX buffer on the bare-metal TCP path. One
    /// memcpy when they are a borrowed view: the parse-buffer prebuf
    /// (copied to `Heap`), or the TLS plaintext window. The escape
    /// hatch for holding the bytes past the guard's borrow.
    pub fn into_owned(self) -> IOBuf {
        match self.src {
            ChunkSource::Prebuf(buf, _) => buf.into_owned(),
            ChunkSource::Stream { guard, len } => {
                // Common case — the whole surfaced chunk is body
                // bytes: hand the guard's IOBuf straight on
                // (`into_owned` is zero copy for an owned source).
                if len == guard.data().len() {
                    guard.into_owned()
                } else {
                    // Straddle case (`len` capped below the chunk
                    // length): only `len` bytes belong to this
                    // body. Copy that prefix into a fresh `Heap`
                    // IOBuf so the owned buffer never carries bytes
                    // past the `Content-Length` boundary.
                    IOBuf::from(guard.data()[..len].to_vec())
                }
            }
        }
    }
}

/// Item H — `BodyReader::chunk` returns a `BodyChunkGuard`. These
/// tests pin the two prebuf-side chunk sources (in-place `data()`
/// and the `into_owned()` heap copy), the prebuf trim to
/// `Content-Length`, and the `NullStream` (HTTP/3-style pre-buffered
/// body) case where `recv_chunk` has no chunk path. The
/// transport-`recv_chunk` source needs a live backend and is
/// exercised by `test_hvf` instead.
#[cfg(test)]
mod body_reader_tests {
    use super::BodyReader;
    use crate::stream::NullStream;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    /// Minimal executor: every future these tests build resolves on
    /// the first poll — the prebuf path returns without awaiting,
    /// and `NullStream::recv_chunk` (the inherited `-> None` default)
    /// is itself non-suspending — so a single poll with a no-op
    /// waker drives any of them to completion.
    fn block_on<F: Future>(fut: F) -> F::Output {
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = fut;
        // SAFETY: `fut` is a local that is not moved again before
        // the poll below.
        let fut = unsafe { Pin::new_unchecked(&mut fut) };
        match fut.poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("test future pended unexpectedly"),
        }
    }

    /// A body whose bytes all rode in with the headers is served
    /// from the prebuf in one chunk; the next `chunk` is `None`.
    #[test]
    fn serves_prebuf_then_none() {
        let mut s = NullStream;
        let prebuf = b"PINGPONG-body";
        let mut br = BodyReader::new(&mut s, prebuf, prebuf.len());
        let g = block_on(br.chunk()).expect("prebuf chunk");
        assert_eq!(g.data(), prebuf);
        drop(g);
        assert!(block_on(br.chunk()).is_none(), "body fully delivered");
        assert_eq!(br.remaining(), 0);
    }

    /// `into_owned` on a prebuf chunk materialises a heap copy that
    /// outlives the guard and preserves the bytes.
    #[test]
    fn prebuf_chunk_into_owned_copies() {
        let mut s = NullStream;
        let prebuf = b"materialise-me";
        let mut br = BodyReader::new(&mut s, prebuf, prebuf.len());
        let owned = block_on(br.chunk()).unwrap().into_owned();
        assert_eq!(owned.data(), prebuf);
    }

    /// The prebuf is trimmed to `total`: a parse buffer that also
    /// carries the start of the next pipelined request never leaks
    /// post-body bytes into the chunk.
    #[test]
    fn prebuf_trimmed_to_content_length() {
        let mut s = NullStream;
        // 4 body bytes followed by the next request's bytes.
        let raw = b"BODYGET / HTTP/1.1\r\n";
        let mut br = BodyReader::new(&mut s, raw, 4);
        let g = block_on(br.chunk()).unwrap();
        assert_eq!(g.data(), b"BODY");
        drop(g);
        assert!(block_on(br.chunk()).is_none());
    }

    /// When the declared body is longer than the prebuf and the
    /// stream has no chunk path (`NullStream` — the HTTP/3-style
    /// pre-buffered case), `chunk` returns `None` past the prebuf:
    /// EOF before `Content-Length`, surfaced via `remaining()`.
    #[test]
    fn nullstream_past_prebuf_is_eof() {
        let mut s = NullStream;
        let prebuf = b"HALF";
        let mut br = BodyReader::new(&mut s, prebuf, 100);
        let g = block_on(br.chunk()).unwrap();
        assert_eq!(g.data(), prebuf);
        drop(g);
        assert!(
            block_on(br.chunk()).is_none(),
            "NullStream recv_chunk -> None"
        );
        assert_eq!(br.remaining(), 96);
    }
}
