// crates/proto/tls — TLS 1.3 protocol stack for HTTPS-over-TCP.
//
// Owns the full TLS 1.3 implementation: sans-io primitives that
// were previously split across `//net/tls{,_crypto,_handshake,_record}`,
// plus the TCP-specific record-layer driver and the per-connection
// server state machine. After the //net→//crates/proto/tls merger this is
// one cohesive crate; `//crates/proto/quic` reuses the sans-io modules
// (`schedule`, `aead`, `handshake`) but skips `record` (which is
// TCP-specific) and substitutes its own CRYPTO-frame I/O.
//
// Module layout (flat under `src/`):
//
//   lib.rs       public API: `listen` (HTTPS entry), `TlsStream`
//                  (the `HttpStream` impl), per-conn pool +
//                  per-worker record scratch
//   schedule.rs  TLS 1.3 key schedule, transcript, X25519, HKDF math
//   aead.rs      AES-128-GCM wrapper — the single AEAD shared by
//                  TLS-over-TCP record protection here AND //crates/proto/quic
//                  packet protection (see RFC 9001 §5.3)
//   handshake.rs ClientHello parser, server-flight builders,
//                  signature-content shaper, finished helpers
//   record.rs    TLS record framing (TCP-specific)
//   server.rs    TlsServer connection state machine + state enum
//   handlers.rs  do_client_hello / do_client_finished / do_app_data
//   keys.rs      finished_key derivation + ct_eq_32 + HMAC helpers
//                  (small protocol math used by handlers + ticket)
//   profile.rs   per-stage handshake timing diagnostics
//   ticket.rs    session-resumption ticket envelope
//   trace.rs     diagnostic tracing (cfg(tls_debug))
//
// Public surface (re-exported through this module's root):
//   * `listen(port, handler, cert, key)` — one-call HTTPS server.
//   * `TlsServerConfig` — typed cert + key bundle.
//   * `tls_profile_report` / `tls_profile_reset` — diagnostics.
//   * `TlsError`, `ListenError` — failure modes.
//
// Sans-io modules (`schedule`, `aead`, `handshake`) are also `pub`
// so `//crates/proto/quic` can reach into them without going through the
// TCP-server wrappers. Apps consuming `tls` for HTTPS only
// don't import them directly — the public API hides them behind
// `listen`.

// Stays no_std in production; flips to std only under `--test`
// so the libtest harness has the std it needs.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::mem::ManuallyDrop;
use core::ptr::addr_of_mut;

use worker::{CurrentWorker, WorkerLocal};

use http::{IOBuf, IOBufChain};

// Sans-io TLS primitives (formerly //crates/net:tls{,_crypto,_handshake,_record}).
// Pub because //crates/proto/quic reaches into `schedule`, `aead`, `handshake`
// for the TLS-handshake-over-CRYPTO-frames driver. `record` stays
// pub for symmetry; it's TCP-only but the wider audience doesn't
// pay any cost — LTO drops it from QUIC binaries.
pub mod aead;
pub mod handshake;
pub mod record;
pub mod schedule;

// TLS-over-TCP server state machine. (`//crates/proto/quic` lives in its
// own crate now and depends on this one for the sans-io TLS bits.)
pub mod server;

// Submodules of the server stack. `pub` so `//crates/proto/quic` can reuse
// `keys::{ct_eq_32, derive_finished_key, hmac_sha256}` (RFC 8446
// §4.4.4 finished-key + helpers) and `profile` for the shared
// per-stage timing accumulator.
pub mod handlers;
pub mod keys;
pub mod profile;
pub mod replay;
pub mod ticket;
pub mod trace;

pub use server::TlsServerConfig;

/// Cert / key parse failure. Apps treat this as "TLS not
/// available" and fall back to plain HTTP.
#[derive(Debug)]
pub enum TlsError {
    CertOrKey,
}

/// Force-exercise every TLS primitive that lazily allocates inside
/// its RustCrypto crate so the heap allocations land in
/// `HEAP_BASELINE` at boot rather than being charged to the first
/// request as a per-conn delta. Idempotent.
///
/// `listen` calls this once on entry. Apps that build their own
/// `TlsServerConfig` directly should call it once at boot too.
/// Cost is one ECDSA sign + verify, one AES-128-GCM
/// seal + open, one X25519 keypair + ECDH — single-digit
/// microseconds total on Apple silicon, dwarfed by `getrandom`'s
/// own boot-time work.
///
/// Without this, the first HTTPS / HTTP/3 connection's handshake
/// allocates whichever precomputed scalar / GHASH / Curve25519
/// tables those crates lazy-init on first use, and the post-
/// shutdown leak check picks them up as a +N alloc delta. With it,
/// the leak check can demand `delta == 0`.
pub fn preinit() {
    // ECDSA P-256 sign + verify exercise. Uses an arbitrary 32-byte
    // private scalar so we don't depend on the dev cert at preinit
    // time; the math hits the same precomputed scalar tables the
    // real CertVerify path will use. All-ones is a valid scalar
    // (it's < the group order).
    {
        use p256::ecdsa::{
            Signature, SigningKey, VerifyingKey,
            signature::{Signer, Verifier},
        };
        let scalar = [0xFFu8; 32];
        if let Ok(sk) = SigningKey::from_slice(&scalar) {
            let sig: Signature = sk.sign(b"waitless-tls preinit");
            let vk = VerifyingKey::from(&sk);
            let _ = vk.verify(b"waitless-tls preinit", &sig);
        }
    }

    // AES-128-GCM seal + open exercise. Hits the AES round-key
    // expansion + GHASH H-table init the crate lazily allocates
    // on the first cipher constructor.
    {
        let key = [0u8; aead::KEY_LEN];
        let nonce = [0u8; aead::NONCE_LEN];
        let mut buf = [0u8; 16];
        let tag = aead::seal(&key, &nonce, b"", &mut buf);
        let _ = aead::open(&key, &nonce, b"", &mut buf, &tag);
    }

    // X25519 ECDH exercise. The schedule path uses
    // `x25519_dalek::StaticSecret::from(seed).diffie_hellman(...)`
    // — both operations may populate Curve25519 lazy state.
    {
        use x25519_dalek::{PublicKey, StaticSecret};
        let a = StaticSecret::from([1u8; 32]);
        let b = StaticSecret::from([2u8; 32]);
        let _shared = a.diffie_hellman(&PublicKey::from(&b));
    }
}

// ---- Public HTTPS entry point ------------------------------------------------

/// Error from [`listen`]: either the cert / key pair didn't parse,
/// or the underlying TCP bind failed.
#[derive(Debug)]
pub enum ListenError {
    /// Couldn't parse the cert / key bytes.
    Cert,
    /// `TcpListener::bind` failed (port in use, registry full, …).
    Bind(waitless::runtime::TcpBindError),
}

/// One-call HTTPS listener. Parses `cert_der` + `key_der`, binds
/// TCP on `port`, accepts each connection, wraps it in a
/// `TlsStream`, and drives `http::serve_conn` on top.
///
/// Apps that want to advertise an HTTP/3 endpoint via `Alt-Svc`
/// emit it themselves per-response — read `req.host_port()` and
/// add the header via `Response::with_header(b"Alt-Svc", ...)`.
/// The framework no longer hardcodes this (it used to take an
/// `advertise_h3` flag and the host-header reparse fired on
/// every response); apps that don't care don't pay.
pub fn listen<H>(
    port: u16,
    handler: H,
    cert_der: &'static [u8],
    key_der: &'static [u8],
) -> Result<(), ListenError>
where
    H: for<'a, 'b> AsyncFn(
            &'a http::Request,
            &'a mut http::BodyReader<'b, TlsStream>,
        ) -> http::Response
        + Send
        + Sync
        + 'static,
{
    let cfg = TlsServerConfig::from_dev_cert(cert_der, key_der).ok_or(ListenError::Cert)?;
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
            let stream = TlsStream::new(tcp, tls);
            http::serve_conn(handler, stream).await;
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

// ---- Diagnostic helpers ------------------------------------------------------

/// Format the TLS handshake profile into `out`. Apps can serve
/// this as the body of a debug endpoint (`/tls_profile`) to
/// inspect per-stage handshake timings.
pub fn tls_profile_report(out: &mut [u8]) -> usize {
    profile::report(out)
}

/// Reset the TLS handshake profile accumulators. Useful between
/// benchmark runs.
pub fn tls_profile_reset() {
    profile::reset();
}

// ---- Conn-state pool (item M) -----------------------------------------------
//
// Recycles `Box<TlsConnImpl>` instances across accept/close cycles
// instead of paying ~7 chunky heap allocs per accept (TlsConnImpl
// + 3 × 4 KiB rx/tx/pt buffers + handshake state). On accept we
// pop a freed instance, `TlsServer::reset` it with a fresh ephemeral
// seed, and reuse its buffers; on close, the wrapper's `Drop` pushes
// the inner box back to the pool. Pre-M baseline `tls_handshake_max`
// bench: 7.25 allocs/iter; post-M target: ~0 once steady-state pool
// usage stabilises.
//
// Per-worker storage. Tier 1 multi-queue assigns each conn task to
// exactly one worker, and that worker owns the conn for its lifetime
// (no migration), so `WorkerLocal<RefCell<Vec<...>>>` gives us
// lock-free pool ops on the steady-state path. The `Arc<TlsConnPool>`
// is shared across `TlsImpl` (one per HTTPS listener) and every
// `PooledTlsConn` it issues; when LISTENERS drains and the listener
// + every live conn drop, the Arc count hits zero, the pool drops,
// and all retained `Box<TlsConnImpl>` go with it — no separate
// shutdown-drain hook needed.

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
/// `TlsServer` carries its rx/tx/pt buffers inline (see
/// `server.rs` tunables), so `Box<TlsConnImpl>` is **one**
/// contiguous heap allocation covering the metadata + 12 KB of
/// buffers + the cfg pointer. Fresh-conn allocation count is
/// `1` total — the pre-inline design did 4 (struct + three
/// `Box<[u8]>`).
pub(crate) struct TlsConnImpl {
    tls: server::TlsServer,
    cfg: Arc<TlsServerConfig>,
}

impl TlsConnImpl {
    /// Allocate + initialise in place. Wraps
    /// `Box::<MaybeUninit<Self>>::new_uninit()` so the 12 KB
    /// `TlsServer` field never round-trips through a stack
    /// temporary — same constraint as `TlsServer::new_box` (and
    /// the same fix).
    fn new_box(seed: [u8; 32], cfg: Arc<TlsServerConfig>) -> Box<Self> {
        let mut b = Box::<Self>::new_uninit();
        // SAFETY: `b.as_mut_ptr()` points at uninitialised storage
        // sized for `Self`. We initialise both fields below; on
        // return `assume_init` is sound.
        unsafe {
            let p = b.as_mut_ptr();
            server::TlsServer::init_in_place(addr_of_mut!((*p).tls), seed);
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
    fn push_rx(&mut self, bytes: &[u8]) -> usize {
        self.inner.tls.push_rx(bytes)
    }

    fn advance(&mut self) -> Result<(), ()> {
        // Reborrow split: take an immutable Arc clone of cfg first
        // so the subsequent `&mut self.inner.tls` borrow doesn't
        // conflict with reading `self.inner.cfg`.
        let inner = &mut **self.inner;
        inner.tls.advance(&inner.cfg).map(|_| ()).map_err(|_| ())
    }

    fn pop_tx(&mut self, out: &mut [u8]) -> usize {
        self.inner.tls.pop_tx(out)
    }

    fn pop_plaintext(&mut self, out: &mut [u8]) -> usize {
        self.inner.tls.pop_plaintext(out)
    }

    fn has_plaintext(&self) -> bool {
        self.inner.tls.has_plaintext()
    }

    fn take_plaintext_chunk(&mut self) -> &mut [u8] {
        self.inner.tls.take_plaintext_chunk()
    }

    fn seal_app_data(
        &mut self,
        src_chain: &mut iobuf::IOBufChain,
        dst: &mut [u8],
    ) -> Result<usize, ()> {
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

/// Inline ciphertext scratch in `TlsStream` — sized for one TCP
/// MTU's worth of inbound ciphertext per `recv` call.
const CIPHER_BUF_LEN: usize = 8192;

/// HTTPS-side `HttpStream`: owns the `TcpStream` + `PooledTlsConn`
/// and drives the TLS state machine. `recv` blocks until decrypted
/// plaintext is available (pumping handshake records as needed);
/// `send` encrypts via `seal_app_data` and flushes ciphertext to
/// TCP.
pub struct TlsStream {
    tcp: waitless::runtime::TcpStream,
    tls: PooledTlsConn,
    /// Inline ciphertext scratch reused across recvs. Folded into
    /// the struct so the future state machine that holds the
    /// `TlsStream` carries the buffer inline — one fewer alloc
    /// per HTTPS conn accept.
    cipher_buf: [u8; CIPHER_BUF_LEN],
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
            cipher_buf: [0u8; CIPHER_BUF_LEN],
            tx_scratch: [0u8; 2048],
            record_scratch: None,
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
    ///      `advance` (preserves NST / alert ordering — they must
    ///      hit the wire before we block waiting for more peer
    ///      bytes).
    ///   2. Read fresh ciphertext from TCP.
    ///   3. Hand it to the TLS state machine and `advance`.
    ///   4. Drain anything `advance` produced (handshake reply,
    ///      app data ACK in future versions, etc.).
    ///
    /// One call advances the conn by exactly one wire round-trip's
    /// worth of received bytes. The handshake driver and the
    /// app-data RX loop both bottom out here — there's no separate
    /// "handshake state machine driver" task because the handshake
    /// runs inside the same `recv` that consumes app data; once
    /// `pop_plaintext` starts returning bytes, the handshake is
    /// done.
    ///
    /// `Err(())` is fatal (peer closed, decrypt error, or TCP
    /// error). Caller drops the conn.
    async fn pump_rx(&mut self) -> Result<(), ()> {
        self.drain_tx().await?;
        let got = self.tcp.recv(&mut self.cipher_buf).await;
        if got == 0 {
            return Err(());
        }
        // `push_rx` may accept fewer bytes than offered when the
        // TLS-side rx_buf is near full. Loop, advancing between
        // pushes so the state machine drains parsed records and
        // frees space for the rest of this `cipher_buf` slice.
        // Without this loop, leftover bytes would be silently
        // dropped — bulk uploads that span multiple TCP segments
        // would stall mid-record.
        let mut off = 0usize;
        while off < got {
            let n = self.tls.push_rx(&self.cipher_buf[off..got]);
            self.tls.advance().map_err(|_| ())?;
            if n == 0 {
                // advance() didn't drain anything and the buffer
                // can't accept more — the peer sent a record
                // bigger than rx_buf can hold. Fatal.
                return Err(());
            }
            off += n;
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
        let scratch = record_scratch
            .get_or_insert_with(|| alloc::vec![0u8; TLS_RECORD_LEN].into_boxed_slice());
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

impl http::HttpStream for TlsStream {
    async fn recv(&mut self, buf: &mut [u8]) -> usize {
        loop {
            // Try plaintext first — `pump_rx` may have decrypted
            // app data on a previous iteration, or the TLS state
            // machine may have buffered it from earlier records.
            let n = self.tls.pop_plaintext(buf);
            if n > 0 {
                return n;
            }
            // No plaintext available → pump one wire round-trip
            // through the TLS state machine. Returns Err on TCP
            // close, decrypt error, or other fatal TLS error.
            // Handshake records produce no plaintext, so the
            // first 1-2 iterations of this loop drive the
            // handshake to completion; subsequent iterations are
            // app-data decrypt.
            if self.pump_rx().await.is_err() {
                return 0;
            }
        }
    }

    /// Zero-copy sibling of [`recv`](Self::recv). Where `recv`
    /// copies decrypted plaintext out of the TLS layer's `pt_buf`
    /// into a caller buffer, `recv_chunk` surfaces a
    /// `RecvChunkGuard` over a `Borrowed` `IOBuf` viewing `pt_buf`
    /// *in place* — eliminating step 7 of the TLS RX path table
    /// (the `pt_buf` → user-buf copy). [`BodyReader::chunk`] drives
    /// it for HTTPS request bodies past the prebuf (RX item H).
    ///
    /// Resolves to `Some(guard)` once a record's worth of plaintext
    /// is available, or `None` on peer close / decrypt error / any
    /// fatal TLS error — the same conditions under which `recv`
    /// resolves to `0`. Handshake records carry no plaintext, so
    /// the first one or two `pump_rx` iterations drive the
    /// handshake to completion exactly as in `recv`.
    ///
    /// **`&mut self` is load-bearing, not incidental.** The
    /// returned guard carries that borrow for its whole life (it is
    /// `RecvChunkGuard<'_>` with `'_` tied to `&mut self`), so the
    /// borrow checker forbids a second `recv` / `recv_chunk` —
    /// hence `pump_rx`, hence the AEAD decrypt that overwrites
    /// `pt_buf` — while the guard is live. That is what makes the
    /// `Borrowed`-into-`pt_buf` view sound: the bytes it points at
    /// cannot be rewritten under it. A bare
    /// `recv_chunk() -> Option<IOBuf>` would be borrow-*unsafe*
    /// here — `IOBuf` has no lifetime parameter — which is the
    /// whole reason RX item F chose the guard shape.
    ///
    /// `guard.data()` reads the plaintext in place (zero copy);
    /// `guard.into_owned()` lifts it to an owned `Heap` `IOBuf` at
    /// the cost of one memcpy (the `Borrowed` → `Heap` case — the
    /// TLS path has no `ExternalOwned` plaintext buffer to hand out
    /// for free; closing that last copy is the documented Phase-4
    /// in-place-decrypt follow-up).
    async fn recv_chunk(&mut self) -> Option<waitless::runtime::RecvChunkGuard<'_>> {
        // Drive the conn until `pt_buf` holds decrypted plaintext.
        // Handshake records produce none, so early iterations just
        // advance the handshake — same loop shape as `recv`.
        while !self.tls.has_plaintext() {
            if self.pump_rx().await.is_err() {
                return None;
            }
        }

        // Consume the plaintext window. `take_plaintext_chunk`
        // resets `pt_pos` / `pt_len` *now* (eager, not on guard
        // drop): the guard's `&mut self` borrow means no code can
        // observe the cursors — or re-`pump_rx` `pt_buf` — between
        // here and the guard's drop, so on-drop bookkeeping would
        // be indistinguishable. The cross-crate `RecvChunkGuard`
        // has no `Drop` hook by design (RX item F); eager advance
        // needs none.
        let window: &mut [u8] = self.tls.take_plaintext_chunk();
        let len = window.len() as u32;
        let base = window.as_mut_ptr();

        // SAFETY: `IOBuf::borrow` requires the region stay valid,
        // unaliased, and not mutated from elsewhere for the
        // IOBuf's whole life.
        //  * `base` points into `pt_buf`, an inline array in the
        //    `Box<TlsConnImpl>` owned by `self.tls`; `len` bytes
        //    from it are in-bounds (`take_plaintext_chunk`
        //    sliced them out of `pt_buf`). `base` is a slice
        //    pointer, hence non-null and aligned.
        //  * The returned guard borrows `&mut self` for its whole
        //    life, so `self` — hence the box, `pt_buf`, and these
        //    bytes — can neither move nor be re-`pump_rx`'d (the
        //    sole `pt_buf` writer) while the guard reads them.
        //  * At most one guard exists at a time — the same
        //    `&mut self` borrow — so no second view overlaps.
        //  * The `Borrowed` IOBuf drops with the guard, ending the
        //    borrow before the next `recv` / `recv_chunk` can run.
        let iobuf = unsafe { IOBuf::borrow(core::ptr::NonNull::new_unchecked(base), len, 0, len) };
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
