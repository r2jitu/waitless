// HTTP/1.1 server. Cooperative non-blocking: the kernel event loop
// accepts, reads, parses, dispatches, and writes back.
//
// Per-core listener + connection set; routes are shared read-only.
// This crate is TLS-agnostic: HTTPS lives in `tls`, which
// defines its own `HttpStream` impl (TLS over TCP) and calls
// `serve_conn` to drive the same request/response machinery.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

// Re-export the shared IOBuf primitive so `http::IOBuf` /
// `http::IOBufChain` keep working at every existing call
// site. The crate moved out so `quic` (transport, can't
// depend on `http`) can use the same type without crossing
// the transport↛app dependency boundary.
pub use iobuf::{Cursor as IOBufCursor, IOBuf, IOBufChain, IOBufError, IOBufWriter, OwnedIOBuf};

mod body;
pub mod diag;
mod request;
mod response;
mod server;
mod stream;
mod streaming;

pub use body::{BodyChunkGuard, BodyReader};
pub use request::{Header, Method, Request, RequestHead};
pub use response::{Bytes, MAX_EXTRA_HEADERS, Response, bytes_owned, bytes_static};
pub use server::{listen, serve_conn};
pub use stream::{BodySource, HttpStream, ResponseSink};

/// Allocate an IOBuf for a response body part with `cap` bytes
/// of usable payload capacity. The returned IOBuf's visible
/// payload (`buf.data()`) starts empty and grows up to `cap`
/// bytes via [`IOBuf::append_slice`] / [`IOBuf::writer`] /
/// [`IOBuf::extend_uninit`].
///
/// No headroom or tailroom is reserved — every framing layer in
/// the stack prepends its header as a *separate* IOBuf
/// (`push_front` onto the response chain) rather than writing
/// into a body part's reserved space:
///   * HTTP/1.1: response head IOBuf goes in front of the body
///     parts (see `serve_conn`'s `out_chain`).
///   * TLS: encrypts the chain into a fresh record buffer.
///   * HTTP/3: HEADERS/DATA frame headers are wrapped in a
///     separate IOBuf the H3 framer pushes ahead of body parts.
///
/// So body IOBufs only need to hold their own bytes.
///
/// One per-request heap allocation (typically a few-KiB
/// `Box<[u8]>`). The bytes are uninitialised — the IOBuf API's
/// write-before-read entry points (`append_slice`, `writer`,
/// `extend_uninit`, `prepend` consuming from headroom into the
/// visible window) ensure no uninit byte ever becomes visible
/// via `data()`. Caller doesn't need to think about this.
///
/// Apps:
///
/// ```ignore
/// async fn page(_req: &Request) -> Response {
///     let mut body = http::body_iobuf(12 * 1024);
///     {
///         let mut w = body.writer();
///         // render content
///     }
///     Response::ok(b"text/html", body)
/// }
/// ```
pub fn body_iobuf(cap: usize) -> IOBuf {
    // SAFETY: visible payload starts empty; the public IOBuf
    // mutation entry points used to grow it (append_slice /
    // writer / extend_uninit / prepend) all write before
    // exposing bytes through `data()`.
    unsafe { IOBuf::new_with_reserved_uninit(0, cap, 0) }
}
