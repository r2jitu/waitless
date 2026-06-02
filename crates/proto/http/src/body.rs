// Streaming request-body reader.
//
// Hands the handler the bytes the request declared via Content-Length,
// drawn first from any prebuf bytes that rode in with the headers and
// then from the transport, surfaced through a **transport-erased**
// [`BodySource`] (`&mut dyn`). That erasure is what keeps `BodyReader`
// — and therefore the handler signature — free of any stream type
// parameter: one `(&Request, &mut BodyReader<'_>)` handler serves
// HTTP/1.1, HTTP/2, and HTTP/3 alike.

use core::marker::PhantomData;

use iobuf::IOBuf;

use crate::stream::BodySource;

/// Streaming reader for the request body.
///
/// Bytes are exposed via [`chunk`](Self::chunk) as a
/// [`BodyChunkGuard`] — a zero-copy view over whichever buffer
/// currently holds them:
///   * the per-connection parse buffer (`prebuf`) — body bytes that
///     arrived in the same TCP/TLS read that delivered the headers;
///   * the transport's own buffer past the prebuf — surfaced by the
///     [`BodySource`] with no intermediate copy of the *bytes* (an
///     owned `External` NIC RX buffer on bare-metal TCP, an
///     `Owned(Shared)` view of the TLS plaintext window for HTTPS).
///
/// The reader knows the total body length (from the request's
/// `Content-Length`) and stops handing out bytes after exactly that
/// many have been delivered, so the underlying transport is left
/// positioned at the start of the next pipelined request.
///
/// `source` is `None` for transports that buffer the whole body before
/// dispatch (HTTP/2 and HTTP/3 reassemble it first): the body is then
/// entirely in `prebuf` and the reader never touches the transport.
///
/// If the handler returns without consuming all bytes, the serve loop
/// calls [`discard`](Self::discard) before sending the response so the
/// keep-alive contract holds.
pub struct BodyReader<'a> {
    /// Transport-erased source for body bytes past the prebuf. `None`
    /// for fully-buffered transports (h2/h3).
    source: Option<&'a mut dyn BodySource>,
    /// Bytes from the serve loop's parse buffer that belong to the
    /// body — already received from the wire by the time the handler
    /// runs.
    prebuf: &'a [u8],
    prebuf_consumed: usize,
    /// Total body length declared by the request's Content-Length.
    total: usize,
    /// Bytes already handed to the handler via `chunk`.
    delivered: usize,
    /// Post-body residue captured when a transport chunk straddled the
    /// `Content-Length` boundary. The serve loop retrieves this via
    /// [`into_leftover`](Self::into_leftover) and threads it into the
    /// next outer-iteration carry so the next pipelined request's HEAD
    /// bytes aren't dropped.
    leftover: Option<IOBuf>,
}

impl<'a> BodyReader<'a> {
    /// Construct a reader with `prebuf` carrying any body bytes already
    /// received during the parse step, and `source` for bytes past it
    /// (`None` when the whole body is already in `prebuf`). `total` is
    /// the declared body length; the reader delivers exactly that many
    /// bytes (possibly fewer on EOF) and refuses to read past it into
    /// the next pipelined request.
    pub fn new(source: Option<&'a mut dyn BodySource>, prebuf: &'a [u8], total: usize) -> Self {
        // Trim `prebuf` to at most `total` so the reader never reaches
        // into post-body bytes (next pipelined request).
        let prebuf_avail = prebuf.len().min(total);
        BodyReader {
            source,
            prebuf: &prebuf[..prebuf_avail],
            prebuf_consumed: 0,
            total,
            delivered: 0,
            leftover: None,
        }
    }

    /// Consume the reader and return any post-body residue captured
    /// from a straddling transport chunk. The serve loop calls this
    /// after the handler returns and threads the result into its
    /// `carry` slot.
    pub fn into_leftover(self) -> Option<IOBuf> {
        self.leftover
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
    /// `Content-Length` bytes delivered" end state (the caller stops)
    /// or "transport EOF / close before `Content-Length` was reached."
    /// Distinguish the two via [`remaining`](Self::remaining): a clean
    /// end leaves it at 0.
    ///
    /// Two byte sources:
    ///   * **Prebuf** — body bytes that rode in with the headers; the
    ///     guard wraps a `Borrowed` `IOBuf` over the serve loop's parse
    ///     buffer (zero copy).
    ///   * **Past the prebuf** — pulled from the [`BodySource`] as an
    ///     owned `IOBuf` (the body bytes themselves are zero-copy — the
    ///     `IOBuf` owns the device buffer). When that chunk straddles
    ///     the `Content-Length` boundary (a follow-up pipelined request
    ///     packed into the body tail), it's split: the body-side bytes
    ///     are copied to a heap `IOBuf` and the residue is stashed in
    ///     `leftover` (zero-copy via `into_remainder`) for the serve
    ///     loop to carry forward.
    pub async fn chunk(&mut self) -> Option<BodyChunkGuard<'_>> {
        if self.delivered >= self.total {
            return None;
        }
        let want_max = self.total - self.delivered;

        // 1. Drain prebuf first — zero-copy, the bytes already sit in
        //    the serve loop's parse buffer.
        if self.prebuf_consumed < self.prebuf.len() {
            let start = self.prebuf_consumed;
            let avail = self.prebuf.len() - start;
            let take = avail.min(want_max);
            self.prebuf_consumed += take;
            self.delivered += take;
            let slice = &self.prebuf[start..start + take];
            // SAFETY: `IOBuf::borrow` needs the region valid,
            // unaliased, and unmutated for the IOBuf's whole life.
            //  * `slice` points into the serve loop's parse buffer; it
            //    is `take` bytes, in-bounds, non-null, aligned.
            //  * The returned `BodyChunkGuard` carries the `&mut self`
            //    borrow for its whole life, so the parse buffer can't
            //    be mutated while the guard is live.
            //  * The `Borrowed` IOBuf is owned by the guard and drops
            //    with it; no drop callback (the bytes are borrowed).
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

        // 2. Past the prebuf — pull from the transport-erased source.
        //    `None` source (h2/h3 buffered body) or peer EOF ends here.
        let chunk: Option<IOBuf> = match self.source.as_deref_mut() {
            Some(src) => src.next_chunk().await,
            None => return None,
        };
        let iobuf = chunk?;
        let avail = iobuf.data().len();
        let take = avail.min(want_max);
        if take == 0 {
            return None;
        }
        self.delivered += take;
        if take == avail {
            // No straddle — the whole chunk is body.
            Some(BodyChunkGuard {
                src: ChunkSource::Owned(iobuf),
            })
        } else {
            // Straddle — body-side bytes copied; residue stashed
            // zero-copy via `into_remainder` for the serve loop.
            use alloc::vec::Vec;
            let body_bytes: Vec<u8> = iobuf.data()[..take].to_vec();
            self.leftover = iobuf.into_remainder(take).expect("take <= data().len()");
            Some(BodyChunkGuard {
                src: ChunkSource::Owned(IOBuf::from(body_bytes)),
            })
        }
    }

    /// Drain the rest of the body, dropping every byte. Returns `Err`
    /// if the transport closed before delivering all `Content-Length`
    /// bytes — caller's contract is to tear the connection down.
    pub async fn discard(&mut self) -> Result<(), ()> {
        while self.delivered < self.total {
            match self.chunk().await {
                Some(g) if !g.data().is_empty() => {}
                // `None` (or an empty chunk) before `delivered` reached
                // `total` — the transport closed mid-body.
                _ => return Err(()),
            }
        }
        Ok(())
    }
}

/// A single contiguous chunk of request-body bytes, handed to the
/// handler by [`BodyReader::chunk`].
///
/// The guard borrows the `BodyReader` for its whole life: read the
/// bytes in place with [`data`](Self::data) (zero copy), or call
/// [`into_owned`](Self::into_owned) to lift them into an owned
/// [`IOBuf`] that can outlive the guard.
pub struct BodyChunkGuard<'a> {
    src: ChunkSource<'a>,
}

/// Which buffer a [`BodyChunkGuard`]'s bytes live in. Private — the
/// source is an implementation detail; handlers see only `data()` /
/// `into_owned()`.
enum ChunkSource<'a> {
    /// Body bytes that arrived in the same read as the request
    /// headers: a `Borrowed` `IOBuf` over the serve loop's parse
    /// buffer. `data()` is zero copy; `into_owned()` copies to `Heap`.
    /// The `PhantomData` ties the borrow to the `&'a mut BodyReader`
    /// `chunk` took.
    Prebuf(IOBuf, PhantomData<&'a mut ()>),
    /// Body bytes pulled from the transport source (or copied out of a
    /// straddling chunk): an owned `IOBuf`. `data()` is zero copy;
    /// `into_owned()` is a move.
    Owned(IOBuf),
}

impl<'a> BodyChunkGuard<'a> {
    /// The chunk's body bytes, read in place. Zero copy.
    pub fn data(&self) -> &[u8] {
        match &self.src {
            ChunkSource::Prebuf(buf, _) => buf.data(),
            ChunkSource::Owned(buf) => buf.data(),
        }
    }

    /// Take owned possession of the chunk's bytes.
    ///
    /// Zero copy when the bytes already sit in an owned buffer (the
    /// transport-source path); one memcpy for the borrowed prebuf view.
    pub fn into_owned(self) -> IOBuf {
        match self.src {
            ChunkSource::Prebuf(buf, _) => buf.into_owned(),
            ChunkSource::Owned(buf) => buf,
        }
    }
}

/// These tests pin the prebuf-side chunk sources (in-place `data()`
/// and the `into_owned()` heap copy), the prebuf trim to
/// `Content-Length`, and the `None`-source (fully-buffered) case where
/// there's no transport to pull from. The live-transport source needs a
/// backend and is exercised by `test_hvf`.
#[cfg(test)]
mod body_reader_tests {
    use super::BodyReader;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    /// Minimal executor: every future these tests build resolves on the
    /// first poll — the prebuf path returns without awaiting, and a
    /// `None` source never awaits — so a single poll with a no-op waker
    /// drives any of them to completion.
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

    /// A body whose bytes all rode in with the headers is served from
    /// the prebuf in one chunk; the next `chunk` is `None`.
    #[test]
    fn serves_prebuf_then_none() {
        let prebuf = b"PINGPONG-body";
        let mut br = BodyReader::new(None, prebuf, prebuf.len());
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
        let prebuf = b"materialise-me";
        let mut br = BodyReader::new(None, prebuf, prebuf.len());
        let owned = block_on(br.chunk()).unwrap().into_owned();
        assert_eq!(owned.data(), prebuf);
    }

    /// The prebuf is trimmed to `total`: a parse buffer that also
    /// carries the start of the next pipelined request never leaks
    /// post-body bytes into the chunk.
    #[test]
    fn prebuf_trimmed_to_content_length() {
        // 4 body bytes followed by the next request's bytes.
        let raw = b"BODYGET / HTTP/1.1\r\n";
        let mut br = BodyReader::new(None, raw, 4);
        let g = block_on(br.chunk()).unwrap();
        assert_eq!(g.data(), b"BODY");
        drop(g);
        assert!(block_on(br.chunk()).is_none());
    }

    /// When the declared body is longer than the prebuf and there's no
    /// transport source (the HTTP/2/3 fully-buffered case), `chunk`
    /// returns `None` past the prebuf: EOF before `Content-Length`,
    /// surfaced via `remaining()`.
    #[test]
    fn buffered_past_prebuf_is_eof() {
        let prebuf = b"HALF";
        let mut br = BodyReader::new(None, prebuf, 100);
        let g = block_on(br.chunk()).unwrap();
        assert_eq!(g.data(), prebuf);
        drop(g);
        assert!(block_on(br.chunk()).is_none(), "no source -> None past prebuf");
        assert_eq!(br.remaining(), 96);
    }
}
