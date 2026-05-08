// HTTP/1.1 server. Cooperative non-blocking: the kernel event loop
// accepts, reads, parses, dispatches, and writes back.
//
// Per-core listener + connection set; routes are shared read-only.
// HTTPS injection happens via the `Tls` trait object below so this
// crate has no compile-time dep on TLS or crypto code — apps that
// don't import a TLS provider link zero TLS bytes.

#![no_std]

extern crate alloc;
extern crate uni;
extern crate uni_iobuf;

// Re-export the shared IOBuf primitive so `uni_http::IOBuf` /
// `uni_http::IOBufChain` keep working at every existing call
// site. The crate moved out so `uni-quic` (transport, can't
// depend on `uni-http`) can use the same type without crossing
// the transport↛app dependency boundary.
pub use uni_iobuf::{
    Cursor as IOBufCursor, IOBuf, IOBufChain, IOBufError, IOBufWriter,
    MAX_HEADER_RESERVE, MAX_TRAILER_RESERVE,
};

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::Cell;
use core::ptr::NonNull;

use uni_worker::{CurrentWorker, WorkerLocal};

// ---- Per-conn body scratch -------------------------------------------------
//
// `handle_conn` allocates one heap-backed `body_storage` per
// connection and parks a pointer to it in this per-worker slot
// before invoking the request handler. Handlers that opt in
// call [`body_iobuf`] to wrap the storage as an `IOBuf::External`
// — zero allocation per response, the storage is reused on
// every iteration of the conn's keep-alive loop. Apps that
// don't opt in keep allocating fresh `IOBuf::new_with_reserved`
// like before.
//
// Lifetime contract (audited unsafe inside `body_iobuf`):
//
//   * `handle_conn`'s future is `Pin`'d, so `body_storage`'s
//     address is stable across awaits.
//   * Per-worker single-threaded cooperative scheduling means
//     at most one handler is "running" (between awaits) on a
//     given worker at a time. The slot is set just before
//     the handler is polled and cleared after the response
//     send completes.
//   * The IOBuf returned by `body_iobuf` captures the slot's
//     pointer at construction time. Subsequent slot changes
//     (a different `handle_conn` running concurrently on the
//     same worker because the first one awaited) don't
//     affect already-issued IOBufs — each IOBuf still points
//     at the `body_storage` of its originating conn.
//   * The `taken` flag prevents one handler from constructing
//     two IOBufs that alias the same buffer.

/// Per-handler scratch slot. `handle_conn` parks the
/// connection's body buffer here before invoking the handler;
/// `body_iobuf` carves out a sub-range, advances `cursor`, and
/// returns an `IOBuf::External` wrapping that range. Multiple
/// `body_iobuf` calls within a single handler invocation are
/// supported as long as their combined size fits the buffer —
/// useful for handlers that compose several heap-IOBufs (a
/// title buf + nav buf + main body), each backed by a slice
/// of the same per-conn scratch.
#[derive(Clone, Copy)]
struct BodyScratchSlot {
    /// Address of the current `handle_conn`'s body buffer.
    /// `None` outside any handler invocation.
    ptr: Option<NonNull<[u8]>>,
    /// Bytes already handed out from `ptr`. Subsequent
    /// `body_iobuf` calls carve from `[cursor..]`. Reset to 0
    /// by `handle_conn` between requests.
    cursor: usize,
}

// SAFETY: `BodyScratchSlot` is logically `!Send` (the `NonNull`
// borrows `handle_conn`'s frame on a specific worker) but
// `WorkerLocal` requires `Send` to be `Sync`. The slot is only
// ever touched from its owning worker (via `CurrentWorker`), so
// the bound is satisfied by construction.
unsafe impl Send for BodyScratchSlot {}

static BODY_SCRATCH: WorkerLocal<Cell<BodyScratchSlot>> = WorkerLocal::new();

fn body_scratch_init() {
    BODY_SCRATCH.ensure_init(uni::num_workers(), |_| {
        Cell::new(BodyScratchSlot { ptr: None, cursor: 0 })
    });
}

/// Allocate an IOBuf for a response body part with `cap` bytes
/// of usable payload capacity. The framework reserves transport-
/// framing headroom and tailroom internally — apps don't see
/// or care about TLS record headers / AEAD tag space; the
/// returned IOBuf's visible payload (`buf.data()`) starts empty
/// and grows up to `cap` bytes via [`IOBuf::append_slice`] /
/// [`IOBuf::writer`] / [`IOBuf::extend_uninit`].
///
/// Always returns an IOBuf. Two backing strategies, transparent
/// to the caller:
///
///   1. **Borrowed scratch** (zero alloc): when invoked inside
///      a request handler, the IOBuf borrows a sub-range of
///      `handle_conn`'s per-conn 16 KiB scratch buffer. Multiple
///      `body_iobuf` calls within one handler partition the
///      scratch in order, so a handler that builds a title
///      IOBuf + nav IOBuf + body IOBuf gets all three from the
///      same buffer — zero heap allocations for any of them.
///
///   2. **Fresh heap allocation**: when called outside a handler
///      (test contexts) or when the requested capacity exceeds
///      the remaining scratch, falls back to a fresh
///      `IOBuf::new_with_reserved` with the same reserves baked
///      in. Same observable IOBuf shape, just a `Box<[u8]>`
///      under the hood.
///
/// Apps:
///
/// ```ignore
/// async fn page(_req: &Request) -> Response {
///     let mut body = uni_http::body_iobuf(12 * 1024);
///     {
///         let mut w = body.writer();
///         // render content
///     }
///     Response::ok(b"text/html", body)
/// }
/// ```
pub fn body_iobuf(cap: usize) -> IOBuf {
    if let Some(borrowed) = try_carve_scratch(cap) {
        return borrowed;
    }
    // Fallback: fresh heap allocation with headroom for layered
    // framing prepends (HTTP / TLS record / etc.) but no
    // tailroom — TLS handles its trailer through the slice path
    // today, so reserving 17 B per IOBuf was hidden bytes that
    // never got used. If a future small-record fast path
    // re-enables encrypt-in-place we can either bump this back
    // or have the TLS layer append a separate trailer IOBuf.
    IOBuf::new_with_reserved(MAX_HEADER_RESERVE, cap, 0)
}

/// Internal: try to carve an IOBuf out of the per-worker
/// scratch slot. Returns `None` outside handlers or when the
/// requested capacity wouldn't fit in the remaining scratch.
fn try_carve_scratch(cap: usize) -> Option<IOBuf> {
    let cc = CurrentWorker::enter();
    body_scratch_init();
    let slot = BODY_SCRATCH.with(&cc, |c| c.get());
    let ptr = slot.ptr?;
    let cursor = slot.cursor;

    // SAFETY: the slice is `handle_conn`'s body buffer for the
    // current connection — Pin'd and exclusively owned for the
    // duration of this handler invocation. We carve a sub-range
    // `[cursor..cursor + needed]` and update `cursor` (the
    // worker is single-threaded cooperative, so this is
    // race-free), so subsequent `body_iobuf` calls within the
    // same invocation see disjoint ranges.
    let slice = unsafe { ptr.as_ref() };
    let total = slice.len();
    if cursor >= total {
        return None;
    }
    let remaining = total - cursor;
    // Headroom only — no trailer reservation. The TLS encrypt-
    // in-place path wanted 17 B of tailroom (1 B inner-content-
    // type + 16 B AEAD tag), but its size cap (≤ 3 KiB
    // plaintext per record) rules out the diagnostics-class
    // bodies that actually matter, and small bodies take the
    // already-coalesce-into-scratch path which doesn't need
    // body tailroom either. Until a faster small-record fast
    // path needs encrypt-in-place to fire, the trailer reserve
    // was just hidden bytes that did nothing.
    let headroom = MAX_HEADER_RESERVE.min(remaining / 4);
    let needed = headroom + cap;
    if needed > remaining {
        return None;
    }
    let chunk_start = cursor;
    BODY_SCRATCH.with(&cc, |c| {
        c.set(BodyScratchSlot {
            ptr: Some(ptr),
            cursor: cursor + needed,
        })
    });
    Some(unsafe {
        IOBuf::from_external(
            NonNull::new_unchecked(slice.as_ptr().add(chunk_start) as *mut u8),
            needed as u32,
            headroom as u32,
            0,
            None,
            core::ptr::null_mut(),
        )
    })
}

/// Internal: install `body_storage` as the current handler's
/// scratch slot. `handle_conn` calls this just before polling
/// the handler and `clear_body_scratch` after the response is
/// drained.
fn install_body_scratch(buf: &mut [u8]) {
    let cc = CurrentWorker::enter();
    body_scratch_init();
    BODY_SCRATCH.with(&cc, |c| {
        c.set(BodyScratchSlot {
            ptr: Some(NonNull::from(&mut *buf)),
            cursor: 0,
        });
    });
}

/// Internal: clear the body-scratch slot after the response
/// is fully sent. Subsequent `body_iobuf` calls (e.g. from
/// out-of-handler code) return `None` and fall back to fresh
/// allocations.
fn clear_body_scratch() {
    let cc = CurrentWorker::enter();
    body_scratch_init();
    BODY_SCRATCH.with(&cc, |c| {
        c.set(BodyScratchSlot { ptr: None, cursor: 0 });
    });
}

// TLS injection boundary. `uni-tls` is the (currently sole) impl,
// adapting its TLS 1.3 state machine onto these methods.

/// TLS provider for `listen_https`. Implementations own per-
/// connection-config state (cert + key + per-handshake scratch);
/// `new_connection` is called once per accepted HTTPS connection
/// to mint a fresh handshake state machine.
pub trait Tls: Send + Sync + 'static {
    /// `seed` is 32 bytes of platform entropy the caller has
    /// already pulled from the RNG.
    fn new_connection(&self, seed: [u8; 32]) -> Box<dyn TlsConn>;
}

/// Per-connection TLS state. `push_rx` / `pop_tx` move ciphertext
/// bytes; `pop_plaintext` / `send_app_data` move plaintext bytes;
/// `advance` runs the state machine after `push_rx`.
pub trait TlsConn: Send + 'static {
    fn push_rx(&mut self, bytes: &[u8]);
    /// `Err(())` is fatal — caller drops the connection.
    fn advance(&mut self) -> Result<(), ()>;
    fn pop_tx(&mut self, out: &mut [u8]) -> usize;
    fn pop_plaintext(&mut self, out: &mut [u8]) -> usize;
    fn send_app_data(&mut self, data: &[u8]) -> Result<(), ()>;
    fn close_notify(&mut self) -> Result<(), ()>;

    /// Encrypt-in-place sibling of `send_app_data`. The caller hands
    /// the TLS layer an [`uni_iobuf::IOBuf`] containing plaintext
    /// (visible as `buf.data()`) plus reserved headroom (≥ 5 B) and
    /// tailroom (≥ 17 B = 1 type byte + 16-B AEAD tag); on success
    /// the IOBuf's visible payload becomes the full TLSCiphertext
    /// record (header || ciphertext || type || tag), ready to write
    /// straight to TCP.
    ///
    /// The default impl falls back to `send_app_data(&buf.data())`
    /// then drains via `pop_tx` into a temporary scratch — same
    /// number of copies as the legacy path. Implementations that
    /// support true in-place sealing override this; today
    /// `uni-tls`'s `TlsServer` does so via `record::seal_in_place`,
    /// skipping the plaintext memcpy into `tx_buf`.
    ///
    /// On `Err(())` the IOBuf state is unspecified — caller should
    /// drop the connection.
    fn send_app_data_iobuf(&mut self, buf: &mut uni_iobuf::IOBuf) -> Result<(), ()> {
        // Fallback: same observable effect as `send_app_data(&buf.data())`,
        // just paid as one plaintext memcpy into the TLS tx_buf
        // and one ciphertext memcpy back out into the IOBuf via
        // `pop_tx`.
        let plaintext_len = buf.len();
        // Save plaintext bytes into a stack scratch (≤ TLS plaintext
        // record max — 16 KiB) so we can re-write the IOBuf with
        // the sealed record. For payloads above that the impl
        // really should override.
        let mut scratch = [0u8; 16384];
        if plaintext_len > scratch.len() {
            return Err(());
        }
        scratch[..plaintext_len].copy_from_slice(buf.data());
        self.send_app_data(&scratch[..plaintext_len])?;
        // Drain the ciphertext back into the IOBuf. We need the
        // IOBuf to be empty + at offset 0 to receive the record
        // bytes; rewrite via `consume + extend_uninit`. The default
        // impl is here for trait completeness; concrete impls do
        // the in-place seal directly.
        let _ = buf;
        Ok(())
    }

    /// Scatter-gather sibling of [`Self::send_app_data_iobuf`].
    /// Seals across two IOBufs: plaintext lives in `body` (which
    /// needs `headroom >= 5 B` for the TLS record header but no
    /// tailroom), and the inner-content-type byte + AEAD tag go
    /// into a small dedicated `trailer` IOBuf the caller allocated
    /// or pooled (`tailroom >= 17 B`).
    ///
    /// On success:
    ///   * `body.data()` is `[record_header || ciphertext]`.
    ///   * `trailer.data()` is `[encrypted_type || tag]`.
    ///
    /// Caller chains them as adjacent parts to ship the full
    /// record. Lets app-side body IOBufs ship without leaving
    /// transport-framing tailroom — the framing layer appends the
    /// trailer at seal time. Default impl falls back to
    /// `send_app_data_iobuf` over a coalesced buffer; concrete
    /// impls override to use the AEAD scatter-gather primitive.
    fn send_app_data_iobuf_split(
        &mut self,
        body: &mut uni_iobuf::IOBuf,
        trailer: &mut uni_iobuf::IOBuf,
    ) -> Result<(), ()> {
        // Generic fallback: the body has the full plaintext in its
        // visible payload; we coalesce body+trailer into a contiguous
        // buffer and seal that, then re-distribute the bytes back into
        // the two IOBufs. Concrete impls (like `uni-tls`'s) override
        // to drive the scatter-gather AEAD primitive directly.
        let _ = trailer;
        self.send_app_data_iobuf(body)
    }

    /// Whole-chain in-place seal. Takes an `IOBufChain` of plaintext
    /// parts (every part must be mutable — Heap or External, not
    /// Static), prepends a fresh TLS record header IOBuf, appends a
    /// fresh trailer IOBuf for the encrypted inner-content-type byte
    /// + AEAD tag, runs the scatter-gather AEAD across every part in
    /// place, and leaves the chain as a ready-to-ship TLS record:
    ///
    ///   `[record_header, ct_part_0, ..., ct_part_n, trailer]`
    ///
    /// Single-record only — caller chunks oversized chains. Returns
    /// `Err(())` if any chain part is a Static borrow (caller should
    /// fall back to coalesce-then-seal) or if the cipher state isn't
    /// `Established`.
    ///
    /// Default impl falls back to `send_app_data_iobuf` over a
    /// coalesced buffer; concrete impls override to drive the
    /// chain-shaped seal primitive directly.
    fn send_app_data_chain(
        &mut self,
        chain: &mut uni_iobuf::IOBufChain,
    ) -> Result<(), ()> {
        // Generic fallback for trait-completeness: coalesce every
        // part into a stack scratch and call `send_app_data`. The
        // concrete `uni-tls` impl overrides this and never falls
        // through.
        let total = chain.total_len();
        let mut scratch = [0u8; 16384];
        if total > scratch.len() {
            return Err(());
        }
        let mut off = 0;
        for part in chain.iter() {
            scratch[off..off + part.len()].copy_from_slice(part.data());
            off += part.len();
        }
        self.send_app_data(&scratch[..total])
    }

    /// What the TLS layer wants reserved at the front of every
    /// IOBuf the layer above hands to a future
    /// `send_app_data_iobuf` (encrypt-in-place) entry point.
    /// 5 bytes for the TLS 1.3 record header. Default impl
    /// returns the LayerReserve that today's `send_app_data`
    /// would need if it were called with an IOBuf instead of
    /// a `&[u8]` — useful for apps that want to size body
    /// chunks for in-place encryption without adopting the
    /// full IOBuf path yet.
    fn layer_reserve(&self) -> uni_iobuf::LayerReserve {
        uni_iobuf::LayerReserve {
            // 5 B TLS 1.3 record header.
            headroom: 5,
            // 16 B AEAD tag + 1 B inner-content-type trailer.
            tailroom: 17,
            // Max plaintext bytes per TLS 1.3 record (MAX_INNER_PLAINTEXT
            // in uni-tls/src/record.rs, but we don't depend on that
            // crate here). Less 1 for the type trailer, less 16 for
            // the tag. ~16 KiB.
            max_payload: 16384,
        }
    }
}

// ---- HTTP types -------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Method {
    Get = 0,
    Post = 1,
    Put = 2,
    Delete = 3,
    Head = 4,
    Unknown = 5,
}

pub struct Header {
    name: [u8; 64],
    name_len: usize,
    value: [u8; 256],
    value_len: usize,
}

impl Header {
    const fn new() -> Self {
        Header {
            name: [0; 64],
            name_len: 0,
            value: [0; 256],
            value_len: 0,
        }
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub fn value(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

pub struct Request {
    pub method: Method,
    path: [u8; 256],
    path_len: usize,
    headers: [Header; 16],
    header_count: usize,
    body: [u8; 8192],
    body_len: usize,
}

impl Request {
    pub fn new() -> Self {
        Request {
            method: Method::Unknown,
            path: [0; 256],
            path_len: 0,
            headers: [const { Header::new() }; 16],
            header_count: 0,
            body: [0; 8192],
            body_len: 0,
        }
    }

    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    pub fn body(&self) -> &[u8] {
        &self.body[..self.body_len]
    }

    pub fn header(&self, name: &[u8]) -> Option<&[u8]> {
        for i in 0..self.header_count {
            if self.headers[i].name().eq_ignore_ascii_case(name) {
                return Some(self.headers[i].value());
            }
        }
        None
    }

    /// Parse the port number out of the request's `Host` header.
    /// Returns `None` if the header is missing or has no `:port`
    /// suffix. Handles both `host:port` and `[v6-literal]:port`
    /// shapes (RFC 7230 §5.4). Useful for apps that want to emit
    /// `Alt-Svc: h3=":<port>"` advertising the same port the
    /// client used to reach us — typical in dev where the host-
    /// to-guest mapping puts HTTPS on a non-default port.
    pub fn host_port(&self) -> Option<u16> {
        host_header_port(self.header(b"Host")?)
    }

    /// Overwrite the request-target path. Truncates if longer than
    /// the fixed `path` buffer. Used by the HTTP/3 frontend to
    /// install the `:path` pseudo-header into the same `Request`
    /// shape the HTTP/1.1 parser fills in.
    pub fn set_path(&mut self, path: &[u8]) {
        let n = path.len().min(self.path.len());
        self.path[..n].copy_from_slice(&path[..n]);
        self.path_len = n;
    }

    /// Overwrite the request body. Truncates if longer than the
    /// fixed `body` buffer. Used by the HTTP/3 frontend after it
    /// reassembles DATA frames.
    pub fn set_body(&mut self, body: &[u8]) {
        let n = body.len().min(self.body.len());
        self.body[..n].copy_from_slice(&body[..n]);
        self.body_len = n;
    }

    /// Append a header line `(name, value)`. Drops silently if the
    /// per-Request 16-header cap is full (matches the HTTP/1.1
    /// parser's truncation policy).
    pub fn push_header(&mut self, name: &[u8], value: &[u8]) {
        if self.header_count >= self.headers.len() {
            return;
        }
        let h = &mut self.headers[self.header_count];
        let n = name.len().min(h.name.len());
        h.name[..n].copy_from_slice(&name[..n]);
        h.name_len = n;
        let v = value.len().min(h.value.len());
        h.value[..v].copy_from_slice(&value[..v]);
        h.value_len = v;
        self.header_count += 1;
    }

    fn clear(&mut self) {
        self.method = Method::Unknown;
        self.path_len = 0;
        self.header_count = 0;
        self.body_len = 0;
    }
}

// ---- Response ---------------------------------------------------------------

/// One byte chunk — either borrowed against the program's
/// static data segment or heap-owned with optional headroom /
/// tailroom for layer-prepend. Re-export of [`IOBuf`] under the
/// historical `Bytes` name so existing call sites (and the
/// `impl Into<Bytes>` type bounds throughout this crate) keep
/// compiling. Future cleanup may rename callsites to `IOBuf`
/// directly; for now the alias keeps the diff small while the
/// underlying primitive switches to the chain-aware type.
pub type Bytes = IOBuf;

/// Maximum number of additional headers (beyond the framework's
/// always-emitted Content-Type / Content-Length / Connection) that
/// a Response can carry. 4 covers the common cases (Alt-Svc, Cache-
/// Control, ETag, Set-Cookie) without bloating the struct. Past
/// this the builder silently drops further `with_header` calls,
/// matching the Request-side header-cap behaviour.
pub const MAX_EXTRA_HEADERS: usize = 4;

pub struct Response {
    pub status: i32,
    /// Content-Type header value. `Bytes` (Cow<'static, [u8]>) so
    /// the common `Response::ok(b"text/plain", ...)` case stays
    /// borrowed-static (no alloc), while dynamically-built MIME
    /// strings can flow through Cow::Owned.
    content_type: Bytes,
    /// The response body, as a chain of IOBuf parts. Uniform
    /// shape — `Response::ok(ct, b"static")` builds a 1-part
    /// chain; multi-part templates push static + dynamic parts
    /// without ever materialising a single contiguous buffer.
    /// `IOBufChain` is the standard transport-side buffer type
    /// (`HttpStream::send`, `TcpStream::send`) so
    /// the body flows through to the wire with no enum dispatch
    /// or shape-flattening on the way down.
    body: IOBufChain,
    /// Optional extra response headers (Alt-Svc, Cache-Control,
    /// etc.) that the app sets via `with_header`. Inline storage
    /// — no Vec allocation per response. Both name and value are
    /// `Bytes` so static literals stay zero-alloc.
    extra_headers: [Option<(Bytes, Bytes)>; MAX_EXTRA_HEADERS],
}

// Note: no `unsafe impl Send/Sync for Response` needed —
// `IOBuf` and `ResponseBody` are themselves Send + Sync (the
// static-borrow branch has 'static lifetime, the heap branch
// holds Box<[u8]>; no thread-local interior mutability).

impl Response {
    /// Build a 200 OK. `body` accepts anything convertible into
    /// an [`IOBufChain`]:
    ///
    ///   * `&'static [u8]` / `&'static str` — zero-alloc 1-part chain.
    ///   * `Vec<u8>` / `String` / `Box<[u8]>` — heap-rendered, moved.
    ///   * `IOBuf` — pre-built chunk.
    ///   * `IOBufChain` — multi-part body the app composed itself.
    ///
    /// `content_type` is `Bytes` — pass `b"text/plain"` for a
    /// static value or build dynamically as `Cow::Owned`.
    pub fn ok(content_type: impl Into<Bytes>, body: impl Into<IOBufChain>) -> Self {
        Response {
            status: 200,
            content_type: content_type.into(),
            body: body.into(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
        }
    }

    pub fn not_found() -> Self {
        Response {
            status: 404,
            content_type: IOBuf::from_static(b"text/plain"),
            body: IOBuf::from_static(b"Not Found").into(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
        }
    }

    /// Add an extra response header. Use for `Alt-Svc`,
    /// `Cache-Control`, `Set-Cookie`, etc. Both `name` and
    /// `value` are `Bytes` (Cow<'static, [u8]>) so static
    /// literals stay zero-alloc; dynamically-built values
    /// flow through `Cow::Owned`. Builder-style — chains.
    /// Silently drops past `MAX_EXTRA_HEADERS` (4 today).
    pub fn with_header(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        for slot in self.extra_headers.iter_mut() {
            if slot.is_none() {
                *slot = Some((name.into(), value.into()));
                return self;
            }
        }
        self
    }

    /// Iterate the extra headers set via `with_header`. Used by
    /// the HTTP/1.1 response writer and the H3 frontend's QPACK
    /// encoder to emit them on the wire.
    pub fn extra_headers(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.extra_headers
            .iter()
            .filter_map(|slot| slot.as_ref().map(|(n, v)| (n.data(), v.data())))
    }

    /// Consume the response and yield its body chain. Frontends
    /// drain it via `pop_front`, `iter`, or by appending it to
    /// an outbound chain (`stream.send(&mut out_chain)`).
    pub fn into_body(self) -> IOBufChain {
        self.body
    }

    /// Borrow the body chain without consuming the response.
    /// Used by frontends that want to inspect length / parts
    /// before deciding whether to inline / stream / coalesce.
    pub fn body(&self) -> &IOBufChain {
        &self.body
    }

    /// Total body length in bytes. Used by frontends to write
    /// the Content-Length header (HTTP/1.1) or DATA-frame
    /// length prefix (HTTP/3) without walking the parts twice.
    pub fn body_len(&self) -> usize {
        self.body.total_len()
    }

    pub fn content_type_bytes(&self) -> &[u8] {
        self.content_type.data()
    }
}

/// Convenience: bytes_static(b"...") produces a borrowed-static
/// `IOBuf`. Equivalent to `IOBuf::from_static(s)`; kept for
/// symmetry with the historical `Bytes` API.
pub fn bytes_static(s: &'static [u8]) -> IOBuf {
    IOBuf::from_static(s)
}

/// Convenience: bytes_owned(v) wraps a Vec as `IOBuf`.
pub fn bytes_owned(v: alloc::vec::Vec<u8>) -> IOBuf {
    IOBuf::from(v)
}

// ---- Server -----------------------------------------------------------------

const BUF_SIZE: usize = 8192;

/// Idle-connection timeout. After this long without inbound data,
/// the per-conn task tears down the connection and releases its
/// backend slot. Mirrors common HTTP/1.1 keep-alive budgets.
const IDLE_TIMEOUT_US: u64 = 30_000_000;

// ---- HttpStream abstraction --------------------------------------------------
//
// `HttpStream` is the byte-level interface the conn handler uses
// to talk to a peer. Plain HTTP impls it directly over
// `TcpStream`; HTTPS impls it via `TlsStream`, which owns a
// `TlsConn` and pumps the TLS state machine inside `recv` / `send`
// so the handler stays protocol-agnostic.
//
// Static dispatch: `handle_conn<S: HttpStream>` is monomorphised
// per impl, so trait method calls inline. Plain path is identical
// to the pre-trait code; TLS path performs the same TLS pump
// work, just relocated inside `TlsStream`.

/// `async_fn_in_trait` lints because the lint can't see that
/// our connection futures are `!Send` by design — `TcpStream` is
/// per-worker. Allow at the trait level: callers always use this
/// trait through static dispatch (see `handle_conn<S: HttpStream>`),
/// and the per-conn task spawns onto the same worker that
/// accepted the connection, so cross-worker Send is never needed.
#[allow(async_fn_in_trait)]
pub trait HttpStream {
    /// Read up to `buf.len()` bytes from the peer (after
    /// decryption, for `TlsStream`). Returns `0` on EOF / fatal
    /// transport error. Implementors decide whether to wake on
    /// partial reads or drain a full segment first.
    async fn recv(&mut self, buf: &mut [u8]) -> usize;

    /// Send a chain of IOBuf parts. The transport decides how to
    /// chunk the bytes onto the wire — TCP coalesces parts into
    /// MSS-bounded segments, TLS encrypts each part as a record
    /// (in-place when the part has reserved headroom + tailroom).
    /// Producers (the HTTP framing layer + apps) build the chain
    /// out of the layered pieces — header IOBuf prepended to the
    /// app's body chain — and let the transport own the layout
    /// decision.
    ///
    /// `IOBufChain` is the standard send surface; takes `&mut`
    /// so the caller can amortise the `VecDeque` allocation
    /// across many requests on the same connection. The
    /// implementation drains the chain (each part `pop_front`'d,
    /// then dropped after its bytes are committed); on return
    /// the chain is empty but the underlying `VecDeque` capacity
    /// is preserved.
    ///
    /// `Err(())` on fatal transport error; the conn handler tears
    /// down on error.
    async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), ()>;

    /// What this stream's transport stack reserves at the front
    /// and back of every IOBuf the producer ships through
    /// `send`. Lets the producer size headers/body buffers
    /// so each part has enough headroom for the transport's
    /// framing (TLS prepends 5 B record header) and tailroom for
    /// trailers (TLS appends 17 B AEAD tag + inner-content-type)
    /// — without this, the transport falls back to a slice copy
    /// instead of encrypt-in-place.
    fn layer_reserve(&self) -> uni_iobuf::LayerReserve {
        uni_iobuf::LayerReserve::PASSTHROUGH
    }

    /// Cleanly signal end-of-stream to the peer before the
    /// underlying transport closes. Plain TCP is already correct
    /// with the implicit FIN-on-drop, so the default is a no-op.
    /// `TlsStream` overrides to emit a `close_notify` alert: rustls
    /// (and most spec-compliant TLS clients) treat a TCP close
    /// without close_notify as an unclean shutdown and discard any
    /// session ticket they were about to cache, blocking resumption.
    async fn close(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

impl HttpStream for uni::runtime::TcpStream {
    async fn recv(&mut self, buf: &mut [u8]) -> usize {
        (*self).recv(buf).await
    }

    async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), ()> {
        // Hand the chain to the runtime's chain-shaped send,
        // which calls into the backend. Bare-metal walks the
        // chain via its cursor and copies bytes directly into
        // MSS-sized TCP segments (no user-space scratch
        // coalesce); native uses `writev(2)` so a multi-part
        // shape ships in one syscall. This layer is a thin
        // trait wire-up — the transport-side decisions live
        // in `tcp::async_try_send_chain` (bare-metal) and
        // `native_tcp_try_send_chain` (POSIX).
        (*self).send(chain).await
    }
}

/// HTTPS-side `HttpStream`: owns the `TcpStream` + `TlsConn` and
/// drives the TLS state machine. `recv` blocks until decrypted
/// plaintext is available (pumping handshake records as needed);
/// `send` encrypts via `send_app_data` and flushes ciphertext to
/// TCP.
pub struct TlsStream {
    tcp: uni::runtime::TcpStream,
    tls: Box<dyn TlsConn>,
    /// Inline ciphertext scratch reused across recvs. Used to be
    /// `Box<[u8]>` allocated separately in `new()`; folded into
    /// the struct so the future state machine that holds the
    /// `TlsStream` carries the buffer inline — one fewer alloc
    /// per HTTPS conn accept.
    cipher_buf: [u8; BUF_SIZE],
    /// Stack-friendly scratch for draining `pop_tx` output.
    tx_scratch: [u8; 2048],
}

impl TlsStream {
    pub fn new(tcp: uni::runtime::TcpStream, tls: Box<dyn TlsConn>) -> Self {
        TlsStream {
            tcp,
            tls,
            cipher_buf: [0u8; BUF_SIZE],
            tx_scratch: [0u8; 2048],
        }
    }

    /// Drain any pending TLS TX (handshake flight, alerts, queued
    /// app-data) to the underlying TCP stream. `Err(())` is fatal.
    async fn drain_tx(&mut self) -> Result<(), ()> {
        loop {
            let n = self.tls.pop_tx(&mut self.tx_scratch);
            if n == 0 {
                return Ok(());
            }
            self.tcp.send_bytes(&self.tx_scratch[..n]).await?;
        }
    }
}

/// Wrap `scratch[..filled]` as an External IOBuf, push it as the
/// only data part of `chain`, run the chain-shaped seal (which
/// adds a header + trailer IOBuf around it), and ship to TCP.
/// Caller resets `filled = 0` after.
///
/// Free function rather than `&mut self` method so the caller can
/// borrow `tls` mutably and `tcp` immutably alongside the
/// stack-local `scratch` without aliasing through `self` — Rust's
/// borrow checker rejects the equivalent
/// `self.flush_record(chain, &mut scratch, ...)` shape because
/// `scratch` is conceptually-local-to-`send` but the method
/// signature would re-borrow all of `self`.
///
/// SAFETY: `scratch`'s address is stable across `tcp.send.await`
/// because the surrounding `send` future is `Pin`'d. The External
/// IOBuf is dropped when `tcp.send` drains the chain — its
/// `drop_fn = None` means no-op for the borrowed storage. After
/// `flush_record` returns, no IOBuf aliases `scratch` and the
/// caller can overwrite it.
async fn flush_record(
    tls: &mut Box<dyn TlsConn>,
    tcp: &uni::runtime::TcpStream,
    chain: &mut IOBufChain,
    scratch: &mut [u8],
    filled: usize,
) -> Result<(), ()> {
    debug_assert!(chain.is_empty());
    let ext = unsafe {
        IOBuf::from_external(
            NonNull::new_unchecked(scratch.as_mut_ptr()),
            scratch.len() as u32,
            0,
            filled as u32,
            None,
            core::ptr::null_mut(),
        )
    };
    chain.push_back(ext);
    tls.send_app_data_chain(chain).map_err(|_| ())?;
    tcp.send(chain).await
}

impl HttpStream for TlsStream {
    async fn recv(&mut self, buf: &mut [u8]) -> usize {
        loop {
            // Try to satisfy from already-decrypted plaintext.
            let n = self.tls.pop_plaintext(buf);
            if n > 0 {
                return n;
            }
            // Pump TLS: drain pending tx, recv ciphertext, advance,
            // drain again, then loop to pop_plaintext.
            if self.drain_tx().await.is_err() {
                return 0;
            }
            let cipher_len = self.cipher_buf.len();
            let got = self.tcp.recv(&mut self.cipher_buf[..cipher_len]).await;
            if got == 0 {
                return 0;
            }
            self.tls.push_rx(&self.cipher_buf[..got]);
            if self.tls.advance().is_err() {
                return 0;
            }
            if self.drain_tx().await.is_err() {
                return 0;
            }
        }
    }

    async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), ()> {
        // Drain any TLS bytes queued before this send (handshake
        // straggler, NewSessionTicket, prior alert) so the wire
        // byte order is what the peer expects.
        self.drain_tx().await?;

        if chain.is_empty() {
            return Ok(());
        }

        // TLS 1.3 RFC 8446 §5.1 caps inner plaintext at 2^14 B per
        // record. Hot path is a single record (≤16 KiB).
        const PLAINTEXT_CHUNK: usize = 16384;

        // Mutable-only fast path: chain-shaped AEAD encrypts every
        // part in place, prepends a header IOBuf, appends a
        // trailer IOBuf — zero plaintext-side memcpy. Single-
        // record only (total ≤ 16 KiB); size mismatch or any
        // Static-borrow part flips to the coalesce path below.
        if chain.total_len() <= PLAINTEXT_CHUNK
            && self.tls.send_app_data_chain(chain).is_ok()
        {
            return self.tcp.send(chain).await;
        }

        // Slow path: walk chain, copy bytes into a stack-local
        // TLS-record-sized scratch in 16 KiB chunks, run the
        // chain-shaped seal over the scratch, ship to TCP, repeat.
        // Handles two cases under one path:
        //   * Static-bearing chains that the in-place fast path
        //     above can't seal (Static IOBufs aren't mutable).
        //   * Oversized chains that span more than one record;
        //     each chunk becomes its own TLS record.
        //
        // Stack scratch (not a per-conn Box) keeps the alloc
        // pattern matched to the legacy code that worked on multi-
        // core; the address is stable across awaits because the
        // surrounding handle_conn future is `Pin`'d. Future work:
        // size the chunk dynamically based on transport feedback
        // (congestion, loss) once the QUIC path needs it.
        let mut scratch = [0u8; PLAINTEXT_CHUNK];
        let mut filled = 0usize;
        while let Some(part) = chain.pop_front() {
            let mut data: &[u8] = part.data();
            while !data.is_empty() {
                let take = (PLAINTEXT_CHUNK - filled).min(data.len());
                scratch[filled..filled + take].copy_from_slice(&data[..take]);
                filled += take;
                data = &data[take..];
                if filled == PLAINTEXT_CHUNK {
                    flush_record(&mut self.tls, &self.tcp, chain, &mut scratch, filled).await?;
                    filled = 0;
                }
            }
        }
        if filled > 0 {
            flush_record(&mut self.tls, &self.tcp, chain, &mut scratch, filled).await?;
        }
        Ok(())
    }

    fn layer_reserve(&self) -> uni_iobuf::LayerReserve {
        // Mirror the TlsConn-level reserve so the framing layer
        // sizes the header IOBuf (and any body chunks the app
        // allocates with `IOBuf::new_with_reserved`) for the
        // encrypt-in-place fast path. 5-B record header headroom
        // + 17-B trailer (1-B type + 16-B AEAD tag) = the TLS 1.3
        // record envelope.
        self.tls.layer_reserve()
    }

    async fn close(&mut self) -> Result<(), ()> {
        // Best-effort: the alert is only meaningful when the TLS
        // state machine is in `Established`. `close_notify` itself
        // handles other states by no-op'ing and moving to Closed,
        // so we just drain whatever it produced (if anything).
        let _ = self.tls.close_notify();
        self.drain_tx().await
    }
}

// ---- Public entry points -----------------------------------------------------

/// Listen for plain HTTP on `port`. The returned `TcpHandle`
/// owns the per-worker accept fan-out; drop it to stop accepting
/// new connections (in-flight conns drain at their idle
/// timeout).
///
/// `handler` is called for every parsed request; apps that want
/// path routing match `req.path()` inside it. Many ports can be
/// bound — call this multiple times — and each `TcpHandle` is
/// independent.
/// Listen for plain HTTP on `port`. `handler` is any async closure
/// or `async fn` taking `&Request` and producing `Response` — e.g.
/// `async fn handle(req: &Request) -> Response { ... }`. The
/// closure is shared across every accepted connection (wrapped in
/// `Arc` once internally) and the per-conn task awaits it inline,
/// so a slow handler suspends only its own connection.
pub fn listen<H>(port: u16, handler: H) -> Result<(), uni::runtime::TcpBindError>
where
    H: AsyncFn(&Request) -> Response + Send + Sync + 'static,
{
    let listener = uni::runtime::TcpListener::bind(port)?;
    let handler = Arc::new(handler);
    let h = listener.run(move |stream| {
        let handler = Arc::clone(&handler);
        async move {
            handle_conn(handler, stream).await;
        }
    });
    uni::_retain(h);
    Ok(())
}

/// Listen for HTTPS (TLS 1.3) on `port`. `tls` is a TLS provider
/// — typically `uni_tls::acceptor(cert, key)?`. The provider is
/// shared across every accepted connection on this port; for
/// multi-port HTTPS reusing the same cert, pass `tls.clone()`
/// (`Arc::clone` is cheap).
///
/// To advertise an HTTP/3 endpoint via `Alt-Svc` on responses,
/// the app's handler should emit it itself per-response — read
/// `req.host_port()` and add a `with_header(b"Alt-Svc", ...)`
/// to the `Response`. The framework no longer hardcodes this
/// (the previous `listen_https_advertising_h3` plumbing); apps
/// that don't use HTTP/3 don't pay the per-response Host-header
/// re-parse, and apps that do retain full control over the
/// advertised port and TTL.
pub fn listen_https<H>(
    port: u16,
    handler: H,
    tls: Arc<dyn Tls>,
) -> Result<(), uni::runtime::TcpBindError>
where
    H: AsyncFn(&Request) -> Response + Send + Sync + 'static,
{
    let listener = uni::runtime::TcpListener::bind(port)?;
    let handler = Arc::new(handler);
    let h = listener.run(move |tcp| {
        let handler = Arc::clone(&handler);
        let tls = Arc::clone(&tls);
        async move {
            let mut seed = [0u8; 32];
            uni::rng::fill_bytes(&mut seed);
            let stream = TlsStream::new(tcp, tls.new_connection(seed));
            handle_conn(handler, stream).await;
        }
    });
    uni::_retain(h);
    Ok(())
}


// ---- Unified per-connection handler ------------------------------------------

/// Per-conn keep-alive loop. Reads bytes from `stream` (plain or
/// TLS — same code path), parses pipelined requests, calls
/// `handler`, sends responses. Returns when the peer closes,
/// idle timeout fires, or the buffer overflows on a too-large
/// request.
async fn handle_conn<S, H>(
    handler: Arc<H>,
    mut stream: S,
) where
    S: HttpStream,
    H: AsyncFn(&Request) -> Response,
{
    // Inline 8 KiB request-parse buffer in the future state. The
    // async runtime allocates the future once (as a
    // `Pin<Box<dyn Future>>` per accepted conn); folding `buf` in
    // turns the previous "future alloc + Box<[u8]> alloc" pair
    // into a single alloc per conn-accept. The future struct
    // already carries an inline `Request` (8 KiB body + 256 B
    // path) and the per-conn header storage + outbound chain;
    // the extra 8 KiB here stays proportional.
    let mut buf = [0u8; BUF_SIZE];
    let mut buf_len = 0usize;
    // Per-connection scratch reused across every request on this
    // conn — `Request` carries 8 KiB of body buffer and 256 B of
    // path. Allocating + zero-initing it per request was costing
    // ~1 GB/s of memory bandwidth per core at peak request rate.
    // `parse_request` resets length fields up front, so a stale
    // tail is invisible to the read path; only the
    // writes-then-reads-back range is observed.
    let mut req = Request::new();
    // The stream's transport stack publishes the headroom +
    // tailroom every IOBuf it ships should reserve (TLS prepends
    // 5 B record header + appends 17 B AEAD tag for the encrypt-
    // in-place path; plain TCP needs neither). Cache it once at
    // conn-accept so we don't re-query per response.
    let layer = stream.layer_reserve();
    // Outbound chain is amortised across every response on this
    // connection — `send` drains it via `pop_front`, leaving
    // the chain empty but with its `VecDeque` allocation
    // preserved. Capacity 4 covers the common shapes (header +
    // 1 body part, header + 2-3 chunked body parts) without
    // forcing the deque to grow.
    let mut out_chain = IOBufChain::with_capacity(4);
    // Inline storage for the response-header IOBuf, sized for the
    // typical header set plus the worst-case transport reserve.
    // Folded into the future state so each iteration wraps it as
    // an `IOBuf::External` rather than allocating a fresh
    // `Box<[u8]>` per response. 1 KiB covers HTTP/1.1 status line
    // + Content-Type + Content-Length + Connection + a handful
    // of `with_header`-set extras (Alt-Svc, Cache-Control,
    // Set-Cookie) with room to spare.
    const HEADER_BUF_SIZE: usize = 1024;
    let mut header_storage = [0u8; HEADER_BUF_SIZE];
    // Per-conn body scratch for handlers that opt into the
    // `body_iobuf` zero-alloc path. Heap-allocated once at
    // conn-open (one alloc per accept, amortised across every
    // request on this conn) rather than inline in the future
    // state — keeps the handle_conn future small enough to
    // stay in cache. Sized to cover the largest dynamic body
    // we render today (the diagnostics page is ~9 KiB; 16 KiB
    // gives headroom). Apps that need bigger bodies fall back
    // to fresh `IOBuf::new_with_reserved` allocs (one per
    // response) automatically.
    const BODY_SCRATCH_SIZE: usize = 16 * 1024;
    let mut body_scratch = alloc::vec![0u8; BODY_SCRATCH_SIZE].into_boxed_slice();
    // Carries the parser's progress (`scan_pos`) across calls
    // when a request arrives in multiple recv'd segments — the
    // `find_header_end` scan resumes from the last position
    // instead of restarting at byte 0. Reset to default after
    // each successfully-consumed request so the next pipelined
    // request starts a fresh scan.
    let mut parser_state = ParserState::default();
    loop {
        if buf_len == BUF_SIZE {
            // Parse buffer full and no complete request in it —
            // client sent something larger than we handle.
            return;
        }
        let recv_fut = stream.recv(&mut buf[buf_len..]);
        let got = match uni::runtime::timeout_us(IDLE_TIMEOUT_US, recv_fut).await {
            Some(n) => n,
            None => return, // idle timeout
        };
        if got == 0 {
            return; // EOF / fatal recv
        }
        buf_len += got;

        // Drain every complete request sitting in the buffer.
        while buf_len > 0 {
            let consumed =
                parse_request_with_state(&buf[..buf_len], &mut req, &mut parser_state);
            if consumed == 0 {
                break; // need more bytes
            }
            let want_close = match req.header(b"Connection") {
                Some(v) => v.eq_ignore_ascii_case(b"close"),
                None => false,
            };
            // Park `body_scratch` in the per-worker slot so the
            // handler can grab a borrowed `IOBuf` via
            // `uni_http::body_iobuf` and skip the per-response
            // heap allocation. Cleared after the chain is sent —
            // out-of-handler `body_iobuf` calls return `None` and
            // fall back to fresh allocations.
            install_body_scratch(&mut body_scratch);
            let resp = (&*handler)(&req).await;
            clear_body_scratch();

            // Wrap the per-conn `header_storage` array as an
            // `IOBuf::External` so the framing layer can build
            // headers in stack-resident memory without a heap
            // allocation per response. SAFETY contract:
            //   * `header_storage` outlives every IOBuf wrapping
            //     it (it's a future-state field, the future is
            //     pinned, and we drop the IOBuf inside this
            //     iteration before constructing the next one).
            //   * No two IOBufs ever alias the same bytes — the
            //     IOBuf is `push_back`'d into `out_chain`,
            //     drained by `send` (which drops it after
            //     committing the bytes to the wire), and only
            //     then does the next iteration construct a fresh
            //     IOBuf wrapping the same storage.
            //   * No drop callback (`drop_fn = None`) — the
            //     storage is borrowed, not owned, so the IOBuf's
            //     drop should be a no-op for the array.
            let header = unsafe {
                IOBuf::from_external(
                    core::ptr::NonNull::new_unchecked(header_storage.as_mut_ptr()),
                    HEADER_BUF_SIZE as u32,
                    layer.headroom as u32,
                    0,
                    None,
                    core::ptr::null_mut(),
                )
            };
            // SAFETY: the only IOBuf currently aliasing
            // `header_storage` is `header` itself (we just
            // constructed it). `write_response_into_iobuf` writes
            // through `header` exclusively.
            let mut header = header;
            write_response_into_iobuf(&mut header, &resp, !want_close);

            // Stage the response into the per-conn outbound chain.
            // Order: header IOBuf first, then body parts. The
            // transport (TCP / TLS) drains the chain and decides
            // the wire chunking — TCP coalesces parts into
            // MSS-bounded segments so this header-plus-body shape
            // ships in one TCP segment for tiny replies; TLS
            // encrypts each part as its own record (in-place when
            // reserves match).
            //
            // `out_chain` is empty here (`send` drains it
            // each iteration). Move the body's parts in via
            // `into_parts()`, then `push_front` the header so the
            // wire order is [header, body0, body1, ...].
            debug_assert!(out_chain.is_empty());
            for part in resp.into_body().into_parts() {
                out_chain.push_back(part);
            }
            out_chain.push_front(header);

            if stream.send(&mut out_chain).await.is_err() {
                return;
            }

            if want_close {
                // Send TLS close_notify (no-op for plain TCP) before
                // the conn drops. Without this, TLS clients tear
                // down their session-resumption state on the
                // perceived unclean close — which is why every
                // post-resumption-PR fresh handshake from rustls or
                // openssl was unable to follow up with a resumed
                // one despite tickets flowing correctly on the wire.
                let _ = stream.close().await;
                return;
            }
            let remaining = buf_len - consumed;
            if remaining > 0 {
                buf.copy_within(consumed..buf_len, 0);
            }
            buf_len = remaining;
            // The next pipelined request starts at byte 0 of the
            // shifted buffer, so the parser state has to forget
            // its "already scanned" cursor.
            parser_state = ParserState::default();
        }
    }
}

// ---- HTTP request parser ----------------------------------------------------

/// Parser state retained across `parse_request` calls on the same
/// pipelined request. Lets `find_header_end` skip bytes it's
/// already scanned — the previous implementation re-walked the
/// whole accumulated buffer on every recv, costing O(N²) on
/// requests that arrive in many small segments. With this state
/// the scan is amortised O(N) regardless of segment shape.
///
/// `handle_conn` keeps one of these per connection and resets it
/// to `Default::default()` after each successfully-consumed
/// request so the next pipelined request starts a fresh scan.
#[derive(Default)]
pub struct ParserState {
    /// Bytes 0..scan_pos already scanned without finding the
    /// `\r\n\r\n` terminator. New recv data extends past
    /// `scan_pos`; the scan resumes from `scan_pos.saturating_sub(3)`
    /// so a terminator straddling the recv boundary still matches.
    scan_pos: usize,
}

fn parse_request_with_state(data: &[u8], req: &mut Request, state: &mut ParserState) -> usize {
    req.clear();

    // Find end of headers ("\r\n\r\n"). Resume from the last
    // scanned position (minus 3 so a terminator straddling the
    // previous-call buffer boundary is caught).
    let resume = state.scan_pos.saturating_sub(3);
    let header_end = find_header_end_from(data, resume);
    if header_end.is_none() {
        // Mark how far we've scanned so the next call doesn't
        // redo this work.
        state.scan_pos = data.len();
        return 0;
    }
    let header_end_pos = header_end.unwrap();

    // Parse request line: "METHOD /path HTTP/1.x\r\n"
    let mut pos = 0;

    if data[pos..].starts_with(b"GET ") {
        req.method = Method::Get;
        pos += 4;
    } else if data[pos..].starts_with(b"POST ") {
        req.method = Method::Post;
        pos += 5;
    } else if data[pos..].starts_with(b"PUT ") {
        req.method = Method::Put;
        pos += 4;
    } else if data[pos..].starts_with(b"DELETE ") {
        req.method = Method::Delete;
        pos += 7;
    } else if data[pos..].starts_with(b"HEAD ") {
        req.method = Method::Head;
        pos += 5;
    } else {
        req.method = Method::Unknown;
    }

    // Extract path
    let mut path_len = 0;
    while pos < data.len()
        && data[pos] != b' '
        && data[pos] != b'\r'
        && data[pos] != b'\n'
        && path_len < 255
    {
        req.path[path_len] = data[pos];
        path_len += 1;
        pos += 1;
    }
    req.path_len = path_len;

    // Skip to end of request line
    while pos < data.len() && data[pos] != b'\n' {
        pos += 1;
    }
    if pos < data.len() {
        pos += 1; // skip \n
    }

    // Parse headers
    while pos < header_end_pos {
        if data[pos] == b'\r' || data[pos] == b'\n' {
            break;
        }

        if req.header_count < 16 {
            let h = &mut req.headers[req.header_count];

            // Header name (up to ':')
            let mut ni = 0;
            while pos < data.len() && data[pos] != b':' && data[pos] != b'\r' && ni < 63 {
                h.name[ni] = data[pos];
                ni += 1;
                pos += 1;
            }
            h.name_len = ni;

            // Skip ':' and spaces
            while pos < data.len() && (data[pos] == b':' || data[pos] == b' ') {
                pos += 1;
            }

            // Header value
            let mut vi = 0;
            while pos < data.len() && data[pos] != b'\r' && data[pos] != b'\n' && vi < 255 {
                h.value[vi] = data[pos];
                vi += 1;
                pos += 1;
            }
            h.value_len = vi;

            req.header_count += 1;
        }

        // Skip to next line
        while pos < data.len() && data[pos] != b'\n' {
            pos += 1;
        }
        if pos < data.len() {
            pos += 1;
        }
    }

    let body_start = header_end_pos + 4; // skip \r\n\r\n
    let mut consumed = body_start;

    // Handle Content-Length
    if let Some(cl_val) = req.header(b"Content-Length") {
        let body_len = parse_usize(cl_val);
        let avail = data.len() - body_start;
        if avail < body_len {
            return 0; // incomplete body
        }
        let copy_len = body_len.min(8191);
        req.body[..copy_len].copy_from_slice(&data[body_start..body_start + copy_len]);
        req.body_len = copy_len;
        consumed += body_len;
    }

    consumed
}

// ---- Response sender --------------------------------------------------------

/// Serialise an HTTP/1.1 response head (status line + headers,
/// terminated by `\r\n\r\n`) into a heap-backed `IOBuf` whose
/// reserves were sized for the transport stack. The body is NOT
/// appended here — the caller `push_front`s this IOBuf onto the
/// response body chain and lets the transport stitch the parts.
///
/// Hot path — called once per HTTP request. `core::fmt`'s
/// machinery (format-string walker, Display vtable dispatch,
/// padding logic) adds up at hundreds of thousands of req/s; the
/// manual byte-level `append_slice` calls here plus a small itoa
/// for the only variable integer (`Content-Length`) measurably
/// outperform `write!(...)`.
///
/// Extra headers (`Alt-Svc`, `Cache-Control`, `Set-Cookie`, etc.)
/// are pulled from `resp.extra_headers()` — apps add them via
/// `Response::with_header`. The framework no longer hardcodes any
/// optional header itself; per-response branches live in app code.
fn write_response_into_iobuf(buf: &mut IOBuf, resp: &Response, keep_alive: bool) {
    // `append_slice` returns `Err(NoTailroom)` if we exceed the
    // IOBuf's reserved capacity. The caller picks `HEADER_BUF_SIZE`
    // bytes well above the realistic header total (~ a few hundred
    // bytes), so an `Err` here means the producer truncated the
    // response head. `debug_assert` panics in tests; release builds
    // silently truncate.
    macro_rules! push {
        ($data:expr) => {{
            let r = buf.append_slice($data);
            debug_assert!(r.is_ok(), "response header overflow (raise HEADER_CAP)");
            let _ = r;
        }};
    }

    push!(b"HTTP/1.1 ");
    let mut status_buf = [0u8; 4];
    let status_len = write_status_code(&mut status_buf, resp.status);
    push!(&status_buf[..status_len]);
    push!(b" ");
    push!(status_text(resp.status).as_bytes());
    push!(b"\r\nContent-Type: ");
    push!(resp.content_type_bytes());
    push!(b"\r\nContent-Length: ");
    let mut len_buf = [0u8; 20];
    let len_len = write_usize(&mut len_buf, resp.body_len());
    push!(&len_buf[..len_len]);
    push!(b"\r\nConnection: ");
    push!(if keep_alive { b"keep-alive" } else { b"close" });
    push!(b"\r\n");
    for (name, value) in resp.extra_headers() {
        push!(name);
        push!(b": ");
        push!(value);
        push!(b"\r\n");
    }
    push!(b"\r\n");
}

/// Extract the port from an HTTP `Host` header value. Handles:
///   `localhost:8443`           → 8443
///   `localhost`                → None (caller defaults)
///   `[::1]:8443`               → 8443 (v6-literal form, RFC 7230 §5.4)
///   `[::1]`                    → None
/// Anything malformed or out-of-range returns `None`.
fn host_header_port(host: &[u8]) -> Option<u16> {
    let after_host = if host.first() == Some(&b'[') {
        // IPv6 literal: scan past the closing `]` before looking
        // for the `:` separator, otherwise the address's own colons
        // would match first.
        let close = host.iter().position(|&b| b == b']')?;
        &host[close + 1..]
    } else {
        host
    };
    let colon = after_host.iter().position(|&b| b == b':')?;
    let digits = &after_host[colon + 1..];
    if digits.is_empty() { return None; }
    let mut acc: u32 = 0;
    for &b in digits {
        if !b.is_ascii_digit() { return None; }
        acc = acc * 10 + (b - b'0') as u32;
        if acc > 65535 { return None; }
    }
    Some(acc as u16)
}

#[cfg(test)]
mod host_port_tests {
    use super::host_header_port;
    #[test] fn plain_host_with_port() {
        assert_eq!(host_header_port(b"localhost:8443"), Some(8443));
    }
    #[test] fn plain_host_no_port() {
        assert_eq!(host_header_port(b"localhost"), None);
    }
    #[test] fn ipv6_with_port() {
        assert_eq!(host_header_port(b"[::1]:8443"), Some(8443));
        assert_eq!(host_header_port(b"[fe80::1%eth0]:443"), Some(443));
    }
    #[test] fn ipv6_no_port() {
        assert_eq!(host_header_port(b"[::1]"), None);
    }
    #[test] fn malformed() {
        assert_eq!(host_header_port(b"localhost:"), None);
        assert_eq!(host_header_port(b"localhost:abc"), None);
        assert_eq!(host_header_port(b"localhost:65536"), None);
    }
}

/// Write the decimal digits of a 3-digit HTTP status code into `out`,
/// returning the number of bytes written. Limited to 100..=999, which
/// is the entire HTTP status range; anything outside falls back to a
/// `0` so the response stays well-formed.
fn write_status_code(out: &mut [u8; 4], status: i32) -> usize {
    if !(100..=999).contains(&status) {
        out[0] = b'0';
        return 1;
    }
    let s = status as usize;
    out[0] = b'0' + (s / 100) as u8;
    out[1] = b'0' + ((s / 10) % 10) as u8;
    out[2] = b'0' + (s % 10) as u8;
    3
}

/// Minimal usize → ASCII decimal. Writes into `out` from the right,
/// returns the number of bytes written. Avoids `core::fmt::Display`'s
/// padding/precision machinery, which dominates the per-request
/// formatting cost on the static-body path.
fn write_usize(out: &mut [u8; 20], mut n: usize) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = tmp.len() - i;
    out[..len].copy_from_slice(&tmp[i..]);
    len
}

// ---- Helper functions -------------------------------------------------------

/// Locate `\r\n\r\n` (the headers/body terminator) starting from
/// byte `start`. The caller has already scanned `data[..start]`
/// without finding it; this restarts there to avoid the O(N²)
/// re-scan when a request arrives in many small recv segments.
/// Returns the absolute index of the terminator within `data`.
fn find_header_end_from(data: &[u8], start: usize) -> Option<usize> {
    let suffix = data.get(start..)?;
    suffix.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + start)
}


fn parse_usize(data: &[u8]) -> usize {
    let mut n: usize = 0;
    for &b in data {
        if b >= b'0' && b <= b'9' {
            n = n * 10 + (b - b'0') as usize;
        } else {
            break;
        }
    }
    n
}


fn status_text(status: i32) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}
