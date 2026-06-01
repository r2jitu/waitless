// crates/proto/http2/src/listen.rs — the HTTP/2-over-TLS listener.
//
// `http2::listen` is the TLS/TCP HTTP server. "h2" is, by RFC 7540
// §3.1-3.3, HTTP/2-*over-TLS* (the cleartext variant is "h2c", a
// non-goal here), so the HTTP/2 server is inherently an HTTPS server —
// and, because ALPN mandates an HTTP/1.1 fallback, it necessarily also
// serves h1.1. This module owns the `TlsStream: http::HttpStream`
// adapter, the per-worker conn pool, and the per-connection dispatch:
// drive the TLS handshake, read the negotiated ALPN, then run this
// crate's `serve_conn` (h2) or `http::serve_conn` (h1.1).
//
// Mirrors `proto/http3` (which bundles its QUIC listener with the h3
// protocol): `http`, `http2`, `http3` are each "the server for that
// HTTP version over its transport" — plaintext TCP, TLS/TCP, QUIC/UDP
// respectively.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::mem::ManuallyDrop;
use core::ptr::addr_of_mut;

use worker::{CurrentWorker, WorkerLocal};

use http::{BodyReader, HttpStream, Request, Response};
use iobuf::{IOBuf, IOBufChain};
use tls::record;
use tls::server::{AlpnProtocol, TlsServer};
use tls::TlsServerConfig;

// ---- Public entry point ------------------------------------------------------

/// Error from [`listen`]: either the cert / key pair didn't parse,
/// or the underlying TCP bind failed.
#[derive(Debug)]
pub enum ListenError {
    /// Couldn't parse the cert / key bytes.
    Cert,
    /// `TcpListener::bind` failed (port in use, registry full, …).
    Bind(waitless::runtime::TcpBindError),
}

/// One-call HTTP/2-over-TLS listener. Parses the DER `cert_chain`
/// (leaf first, then intermediates) + `key_der`, binds TCP on `port`,
/// accepts each connection, runs the TLS 1.3 handshake, and serves it
/// with HTTP/2 or HTTP/1.1 depending on the ALPN the client negotiated.
///
/// "h2" means HTTP/2 over TLS; clients that don't offer h2 are served
/// HTTP/1.1 — the mandatory ALPN fallback, and the golden path. The
/// same `handler` serves both versions (it's generic over the byte
/// stream via `http::HttpStream`, so no per-version adapter is needed).
///
/// For HTTP/3 (over QUIC/UDP), call `http3::listen` separately;
/// `Alt-Svc` advertising it is emitted per-response by the app.
pub fn listen<H>(
    port: u16,
    handler: H,
    cert_chain: &'static [&'static [u8]],
    key_der: &'static [u8],
) -> Result<(), ListenError>
where
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, TlsStream>) -> Response
        + Send
        + Sync
        + 'static,
{
    let cfg = TlsServerConfig::from_chain(cert_chain, key_der).ok_or(ListenError::Cert)?;
    let cfg = Arc::new(cfg);
    let pool = TlsConnPool::new();

    let listener = waitless::runtime::TcpListener::bind(port).map_err(ListenError::Bind)?;
    let handler = Arc::new(handler);
    let h = listener.run(move |tcp| {
        let handler = Arc::clone(&handler);
        let cfg = cfg.clone();
        let pool = Arc::clone(&pool);
        async move {
            let mut seed = [0u8; 32];
            waitless::rng::fill_bytes(&mut seed);
            let tls = build_tls_conn(seed, cfg, pool);
            let mut stream = TlsStream::new(tcp, tls);
            // Drive the handshake far enough to learn the ALPN choice,
            // then branch to the matching serve loop. HTTP/1.1 stays the
            // golden path / fallback; "h2" is additive, never replacing
            // it. A failed handshake just drops the connection.
            match stream.drive_handshake().await {
                Ok(AlpnProtocol::H2) => {
                    crate::serve_conn(handler, stream).await;
                }
                Ok(_) => {
                    http::serve_conn(handler, stream).await;
                }
                Err(()) => {}
            }
        }
    });
    waitless::_retain(h);
    Ok(())
}

/// Pop a recycled `Box<TlsConnImpl>` from the per-worker pool
/// (resetting it with the supplied seed) or allocate fresh.
/// Wraps the result in a `PooledTlsConn` whose Drop returns the
/// box to the pool.
fn build_tls_conn(
    seed: [u8; 32],
    cfg: Arc<TlsServerConfig>,
    pool: Arc<TlsConnPool>,
) -> PooledTlsConn {
    let inner = match pool.pop() {
        Some(mut boxed) => {
            boxed.tls.reset(seed);
            boxed
        }
        None => TlsConnImpl::new_box(seed, cfg),
    };
    PooledTlsConn {
        inner: ManuallyDrop::new(inner),
        pool,
    }
}

// ---- Conn-state pool --------------------------------------------------------
//
// Recycles `Box<TlsConnImpl>` instances across accept/close cycles
// instead of paying ~7 chunky heap allocs per accept (TlsConnImpl
// + rx/tx/pt buffers + handshake state). On accept we pop a freed
// instance, `TlsServer::reset` it with a fresh ephemeral seed, and
// reuse its buffers; on close, the wrapper's `Drop` pushes the inner
// box back to the pool.
//
// Per-worker storage. Tier 1 multi-queue assigns each conn task to
// exactly one worker, and that worker owns the conn for its lifetime
// (no migration), so `WorkerLocal<RefCell<Vec<...>>>` gives us
// lock-free pool ops on the steady-state path. The `Arc<TlsConnPool>`
// is shared across the listener and every `PooledTlsConn` it issues;
// when the listener + every live conn drop, the Arc count hits zero,
// the pool drops, and all retained `Box<TlsConnImpl>` go with it.

const POOL_CAP: usize = 16;

pub(crate) struct TlsConnPool {
    slots: WorkerLocal<RefCell<Vec<Box<TlsConnImpl>>>>,
}

// SAFETY: `WorkerLocal<T>` is `Sync` for `T: Send`; `RefCell` is
// `Send`; `Box<TlsConnImpl>` is `Send` (TlsServer is `Send` —
// inner `Box<[u8]>` plus `Send`-friendly key state). The
// `WorkerLocal` access path bounds borrowing to the current
// worker via `CurrentWorker`, so the `RefCell::borrow_mut` inside
// `with` can never race across workers.

impl TlsConnPool {
    fn new() -> Arc<Self> {
        let pool = TlsConnPool {
            slots: WorkerLocal::new(),
        };
        pool.slots.ensure_init(waitless::num_workers(), |_| {
            RefCell::new(Vec::with_capacity(POOL_CAP))
        });
        Arc::new(pool)
    }

    /// Pop an idle `Box<TlsConnImpl>` for this worker, or `None`
    /// if the worker's slot is empty (caller falls back to fresh
    /// alloc).
    fn pop(&self) -> Option<Box<TlsConnImpl>> {
        if !self.slots.is_initialized() {
            return None;
        }
        let cc = CurrentWorker::enter();
        self.slots.with(&cc, |c| c.borrow_mut().pop())
    }

    /// Push an idle `Box<TlsConnImpl>` back to this worker's slot,
    /// or drop it if the slot is full / pool not initialised.
    fn push(&self, boxed: Box<TlsConnImpl>) {
        if !self.slots.is_initialized() {
            return; // Box drops at scope-end
        }
        let cc = CurrentWorker::enter();
        self.slots.with(&cc, |c| {
            let mut v = c.borrow_mut();
            if v.len() < POOL_CAP {
                v.push(boxed);
            }
            // else: pool full — Box drops at scope-end
        });
    }
}

/// Inner per-conn TLS state. Pooled by `TlsConnPool`; the
/// `cfg` Arc is invariant across the pool's lifetime, so `reset`
/// only has to touch the `tls` field.
///
/// `TlsServer` carries its rx/tx/pt buffers inline, so
/// `Box<TlsConnImpl>` is **one** contiguous heap allocation covering
/// the metadata + buffers + the cfg pointer.
pub(crate) struct TlsConnImpl {
    tls: TlsServer,
    cfg: Arc<TlsServerConfig>,
}

impl TlsConnImpl {
    /// Allocate + initialise in place. Wraps
    /// `Box::<MaybeUninit<Self>>::new_uninit()` so the large
    /// `TlsServer` field never round-trips through a stack
    /// temporary — same constraint as `TlsServer::new_box`.
    fn new_box(seed: [u8; 32], cfg: Arc<TlsServerConfig>) -> Box<Self> {
        let mut b = Box::<Self>::new_uninit();
        // SAFETY: `b.as_mut_ptr()` points at uninitialised storage
        // sized for `Self`. We initialise both fields below; on
        // return `assume_init` is sound.
        unsafe {
            let p = b.as_mut_ptr();
            TlsServer::init_in_place(addr_of_mut!((*p).tls), seed);
            addr_of_mut!((*p).cfg).write(cfg);
            b.assume_init()
        }
    }
}

/// Pool-aware wrapper around `Box<TlsConnImpl>`. On drop, takes
/// the inner box out and pushes it back to the pool — the next
/// accept on this worker will pop + reset it instead of paying a
/// fresh allocation.
struct PooledTlsConn {
    inner: ManuallyDrop<Box<TlsConnImpl>>,
    pool: Arc<TlsConnPool>,
}

impl Drop for PooledTlsConn {
    fn drop(&mut self) {
        // SAFETY: ManuallyDrop::take moves the inner Box out
        // exactly once — this is the only access, and `self`
        // drops immediately after, so the `inner` field is
        // never read again.
        let inner = unsafe { ManuallyDrop::take(&mut self.inner) };
        self.pool.push(inner);
    }
}

impl PooledTlsConn {
    /// Consume one owned TCP chunk worth of ciphertext, walking
    /// complete records and dispatching each to the right state
    /// handler. The chunk's bytes are AEAD-decrypted in place by
    /// record-layer `open`; the chunk is then `share()`'d so each
    /// decrypted app-data record can be queued as a refcount-shared
    /// view (see `TlsServer::process_chunk`).
    fn process_chunk(&mut self, chunk: IOBuf) -> Result<(), ()> {
        let inner = &mut **self.inner;
        inner.tls.process_chunk(chunk, &inner.cfg).map_err(|_| ())
    }

    fn pop_tx(&mut self, out: &mut [u8]) -> usize {
        self.inner.tls.pop_tx(out)
    }

    fn has_plaintext(&self) -> bool {
        self.inner.tls.has_plaintext()
    }

    fn is_established(&self) -> bool {
        self.inner.tls.is_established()
    }

    fn is_terminated(&self) -> bool {
        self.inner.tls.is_terminated()
    }

    fn negotiated_alpn(&self) -> AlpnProtocol {
        self.inner.tls.negotiated_alpn()
    }

    fn pop_plaintext(&mut self) -> Option<IOBuf> {
        self.inner.tls.pop_plaintext()
    }

    fn seal_app_data(&mut self, src_chain: &mut IOBufChain, dst: &mut [u8]) -> Result<usize, ()> {
        self.inner.tls.seal_app_data(src_chain, dst).map_err(|_| ())
    }

    fn close_notify(&mut self) -> Result<(), ()> {
        self.inner.tls.close_notify().map_err(|_| ())
    }
}

// ============================================================================
// TLS stream: TCP + TLS state machine as an `HttpStream`.
// ============================================================================

/// Headroom reserved at the front of every record IOBuf for the
/// 5 B TLS 1.3 record header that the seal layer prepends.
const TLS_HEADROOM: usize = record::HEADER_LEN;

/// Tailroom reserved at the back of every record IOBuf for the
/// 1 B inner-content-type byte + 16 B AEAD tag.
const TLS_TAILROOM: usize = 1 + record::TAG_LEN;

/// Plaintext capacity of one TLS 1.3 record (RFC 8446 §5.1: 2^14 B).
/// One less than `MAX_INNER_PLAINTEXT` since the latter includes
/// the one-byte inner-content-type trailer.
const PLAINTEXT_CHUNK: usize = record::MAX_INNER_PLAINTEXT - 1;

/// Total bytes in one TLS record envelope + max plaintext.
/// Sized for the worker scratch and the wire-bytes capacity
/// `seal_app_data` writes into.
const TLS_RECORD_LEN: usize = TLS_HEADROOM + PLAINTEXT_CHUNK + TLS_TAILROOM;

/// HTTPS-side `HttpStream`: owns the `TcpStream` + `PooledTlsConn`
/// and drives the TLS state machine. `recv_chunk` blocks until
/// decrypted plaintext is available (pumping handshake records as
/// needed); `send` encrypts via `seal_app_data` and flushes
/// ciphertext to TCP.
pub struct TlsStream {
    tcp: waitless::runtime::TcpStream,
    tls: PooledTlsConn,
    /// Stack-friendly scratch for draining `pop_tx` output.
    tx_scratch: [u8; 2048],
    /// Lazily-allocated scratch for the TLS record fallback path
    /// (when TSO direct-encrypt isn't available — TX big-pool
    /// full, TSO not negotiated, or dst MAC unresolved). Per-conn
    /// ownership: the buffer is borrowed mutably from `&mut self`
    /// for the entire `send_one_record` call including the
    /// `tcp.send.await`, so no other task on this worker can
    /// alias these bytes even if the send yields under
    /// backpressure. Conns whose sends all take the fast-fast TSO
    /// path never allocate.
    record_scratch: Option<Box<[u8]>>,
}

impl TlsStream {
    fn new(tcp: waitless::runtime::TcpStream, tls: PooledTlsConn) -> Self {
        TlsStream {
            tcp,
            tls,
            tx_scratch: [0u8; 2048],
            record_scratch: None,
        }
    }

    /// Pump the TLS handshake to completion, returning the ALPN protocol
    /// the client negotiated. Drives `pump_rx` until the connection is
    /// `Established` (ALPN is decided at ClientHello, so it's known by
    /// then). `Err(())` if the handshake fails before completing.
    ///
    /// This runs the same `pump_rx` cycles the first `recv_chunk` used
    /// to drive lazily — no extra round trips — but lets `listen`
    /// branch to the HTTP/1.1 or HTTP/2 serve loop *before* the first
    /// application byte is read. Any application data the client
    /// coalesced with its Finished stays queued for the serve loop's
    /// first `recv_chunk`.
    async fn drive_handshake(&mut self) -> Result<AlpnProtocol, ()> {
        loop {
            if self.tls.is_established() {
                return Ok(self.tls.negotiated_alpn());
            }
            if self.tls.is_terminated() {
                return Err(());
            }
            self.pump_rx().await?;
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

    /// One full sans-io RX pump cycle:
    ///   1. Drain any TLS TX bytes left in `tx_buf` from a prior
    ///      step (preserves NST / alert ordering — they must hit
    ///      the wire before we block waiting for more peer bytes).
    ///   2. Read fresh ciphertext from TCP as one chunk.
    ///   3. Take owned possession of the chunk (`into_owned` —
    ///      zero-copy for the NIC-RX buffer) and hand it to
    ///      `process_chunk`, which walks complete records and
    ///      dispatches each to the state-appropriate handler.
    ///      Decryption is in place — the chunk's ciphertext is
    ///      overwritten with plaintext as records are consumed; any
    ///      straddler is copied into the TLS layer's `rx_partial` for
    ///      next chunk. After framing, the chunk is `share()`'d and
    ///      each app-data record is queued as a refcount-shared view.
    ///   4. The chunk's storage (a NIC RX slot) stays alive only as
    ///      long as a queued view references it; it returns to the
    ///      pool once the consumer drains the plaintext.
    ///   5. Drain anything `process_chunk` produced (handshake
    ///      reply, NewSessionTicket, alert, ...).
    ///
    /// One call advances the conn by exactly one chunk's worth of
    /// received bytes. The handshake driver and the app-data RX
    /// loop both bottom out here — there's no separate
    /// "handshake state machine driver" task because the handshake
    /// runs inside the same `recv_chunk` that consumes app data;
    /// once `has_plaintext()` flips true, the handshake is done.
    ///
    /// `Err(())` is fatal (peer closed, decrypt error, or TCP
    /// error). Caller drops the conn.
    async fn pump_rx(&mut self) -> Result<(), ()> {
        self.drain_tx().await?;
        {
            let Some(guard) = self.tcp.recv_chunk().await else {
                return Err(());
            };
            // Take owned possession of the chunk: zero-copy for the
            // NIC-RX `External`/`Heap` buffer the backend surfaces,
            // one copy only for a `Borrowed` view. `process_chunk`
            // then decrypts records in place and `share()`s the chunk
            // so each app-data record's plaintext range can be queued
            // as a refcount-shared view — no staging copy. The chunk's
            // storage (a NIC RX slot) stays alive until the last
            // queued view drops, so the slot returns once the consumer
            // has drained the plaintext via `pop_plaintext`.
            let chunk = guard.into_owned();
            self.tls.process_chunk(chunk)?;
        }
        self.drain_tx().await
    }

    /// Encrypt and ship one TLS 1.3 application_data record. The
    /// TLS layer consumes up to `PLAINTEXT_CHUNK` (16 KiB) bytes
    /// from the front of `src` and leaves the rest for the next
    /// call — multi-record bodies loop in `send`.
    ///
    /// Two paths, both single-pass:
    ///
    ///   * **TSO direct-encrypt**: when the TX big-pool has a
    ///     free slot, seal straight into the slot's payload
    ///     region — no intermediate buffer anywhere on the data
    ///     path.
    ///   * **Per-conn scratch + tcp.send fallback**: TX big-pool
    ///     full / TSO not negotiated / dst MAC unresolved → seal
    ///     into this stream's `record_scratch` (lazily allocated
    ///     on first miss, reused on subsequent misses) and ship
    ///     via the chain-based TCP send. The scratch is owned by
    ///     `&mut self` for the entire call, so the IOBuf wrapping
    ///     it can't be aliased by another conn's send even if
    ///     `tcp.send.await` yields under TX backpressure.
    ///
    /// `Err(())` is fatal — caller drops the conn.
    async fn send_one_record(&mut self, src: &mut IOBufChain) -> Result<(), ()> {
        if src.is_empty() {
            return Ok(());
        }

        // Fast-fast path: TSO direct-encrypt into a TX big-slot.
        // The record is `plaintext + 22 B` (5 hdr + 1 type + 16
        // tag). TCP layer gates TSO on `min_payload` vs MSS so
        // sub-MSS sends bypass the TSO descriptor path (which gve
        // silently drops at <= MSS).
        const TLS13_RECORD_OVERHEAD: usize = TLS_HEADROOM + TLS_TAILROOM;
        let min_payload = src.total_len().min(PLAINTEXT_CHUNK) + TLS13_RECORD_OVERHEAD;
        match self
            .tcp
            .try_send_tso(min_payload, |slot| self.tls.seal_app_data(src, slot))
        {
            Some(Ok(_)) => return Ok(()),
            Some(Err(())) => return Err(()),
            None => {} // TSO unavailable — fall through to scratch path
        }

        // Fallback: per-conn scratch seal + chain-based tcp.send.
        // Destructure self into disjoint field borrows so we can
        // hold &mut record_scratch (for the seal) and &mut tcp
        // (for the send) at the same time without the borrow
        // checker conflating them.
        let Self {
            tcp,
            tls,
            record_scratch,
            ..
        } = self;
        // Lazy first-use alloc of the per-conn TLS record scratch
        // (`TLS_RECORD_LEN` ≈ 16 KB). Under high-concurrency load the
        // heap can be exhausted by the time the Nth conn reaches its
        // first app-data send; `try_reserve_exact` lets us refuse the
        // send gracefully (returns `Err(())` like any other TLS send
        // failure) instead of `arch_shutdown`-ing the unikernel via
        // Rust's default alloc-error handler.
        if record_scratch.is_none() {
            let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            if v.try_reserve_exact(TLS_RECORD_LEN).is_err() {
                return Err(());
            }
            v.resize(TLS_RECORD_LEN, 0);
            *record_scratch = Some(v.into_boxed_slice());
        }
        let scratch = record_scratch.as_mut().expect("just-ensured Some");
        let n = tls.seal_app_data(src, &mut scratch[..]).map_err(|_| ())?;
        // SAFETY: `scratch` is owned by `self` and stays alive
        // across the `tcp.send.await` (we hold `&mut self` for
        // the whole function). No other task on this worker can
        // acquire a reference to `self.record_scratch` — it's
        // per-conn private. The wrapping IOBuf drops at function
        // exit, ending the raw-pointer borrow.
        let mut ship = IOBufChain::new();
        let ptr = unsafe { core::ptr::NonNull::new_unchecked(scratch.as_mut_ptr()) };
        ship.push_back(unsafe { IOBuf::borrow(ptr, TLS_RECORD_LEN as u32, 0, n as u32) });
        tcp.send(&mut ship).await
    }
}

impl HttpStream for TlsStream {
    /// Resolve a `RecvChunkGuard` over an `IOBuf` carrying one
    /// decrypted plaintext record. For a chunk-direct record the
    /// IOBuf is an `Owned(Shared)` view refcount-sharing the recv'd
    /// chunk's storage (so the NIC RX slot is held until this guard —
    /// and any owned tail the consumer carries forward — drops); for
    /// the rare rx_partial straddler it's an `Owned(Heap)` copy.
    /// Either way `into_owned()` on the guard is a no-op.
    ///
    /// Resolves to `Some(guard)` once a record's worth of plaintext
    /// is available, or `None` on peer close / decrypt error / any
    /// fatal TLS error. Handshake records carry no plaintext, so
    /// the first one or two `pump_rx` iterations drive the
    /// handshake to completion before any guard is returned.
    ///
    /// `guard.data()` reads the plaintext in place (zero copy);
    /// `guard.into_owned()` is a no-op (the IOBuf already owns —
    /// `Shared` or `Heap` — its bytes).
    async fn recv_chunk(&mut self) -> Option<waitless::runtime::RecvChunkGuard<'_>> {
        // Drive the conn until a plaintext record is queued.
        // Handshake records produce none, so early iterations just
        // advance the handshake.
        while !self.tls.has_plaintext() {
            if self.pump_rx().await.is_err() {
                return None;
            }
        }
        let iobuf = self.tls.pop_plaintext()?;
        Some(waitless::runtime::RecvChunkGuard::new(iobuf))
    }

    async fn send(&mut self, src: &mut IOBufChain) -> Result<(), ()> {
        // Drain any TLS bytes queued before this send (handshake
        // straggler, NewSessionTicket, prior alert) so the wire
        // byte order is what the peer expects.
        self.drain_tx().await?;

        // `send_one_record` consumes up to one record's plaintext
        // from `src` per call (16 KiB cap inside the TLS layer);
        // loop until the chain is drained. Multi-record bodies
        // (>16 KiB) thus run through the same fast-fast TSO
        // direct-encrypt path per record as single-record sends.
        while !src.is_empty() {
            self.send_one_record(src).await?;
        }
        Ok(())
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
