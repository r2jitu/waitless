// uni-tls — TLS 1.3 protocol stack for HTTPS-over-TCP.
//
// Owns the full TLS 1.3 implementation: sans-io primitives that
// were previously split across `//net/tls{,_crypto,_handshake,_record}`,
// plus the TCP-specific record-layer driver and the per-connection
// server state machine. After the //net→//uni-tls merger this is
// one cohesive crate; `//uni-quic` reuses the sans-io modules
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
//                  TLS-over-TCP record protection here AND //uni-quic
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
// so `//uni-quic` can reach into them without going through the
// TCP-server wrappers. Apps consuming `uni-tls` for HTTPS only
// don't import them directly — the public API hides them behind
// `listen`.

// Stays no_std in production. Under `bazel test`, the
// `tests_need_std` flag flips this crate's `std` feature on so
// libtest's panic=unwind harness can link past the RustCrypto
// deps' no_std requirement.
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::mem::ManuallyDrop;
use core::ptr::addr_of_mut;
#[cfg(target_os = "none")]
use core::ptr::NonNull;

use uni_worker::{CurrentWorker, WorkerLocal};

use uni_http::{IOBuf, IOBufChain};

// Sans-io TLS primitives (formerly //net:tls{,_crypto,_handshake,_record}).
// Pub because //uni-quic reaches into `schedule`, `aead`, `handshake`
// for the TLS-handshake-over-CRYPTO-frames driver. `record` stays
// pub for symmetry; it's TCP-only but the wider audience doesn't
// pay any cost — LTO drops it from QUIC binaries.
pub mod aead;
pub mod handshake;
pub mod record;
pub mod schedule;

// TLS-over-TCP server state machine. (`//uni-quic` lives in its
// own crate now and depends on this one for the sans-io TLS bits.)
pub mod server;

// Submodules of the server stack. `pub` so `//uni-quic` can reuse
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
            signature::{Signer, Verifier},
            Signature, SigningKey, VerifyingKey,
        };
        let scalar = [0xFFu8; 32];
        if let Ok(sk) = SigningKey::from_slice(&scalar) {
            let sig: Signature = sk.sign(b"uni-tls preinit");
            let vk = VerifyingKey::from(&sk);
            let _ = vk.verify(b"uni-tls preinit", &sig);
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
    Bind(uni::runtime::TcpBindError),
}

/// One-call HTTPS listener. Parses `cert_der` + `key_der`, binds
/// TCP on `port`, accepts each connection, wraps it in a
/// `TlsStream`, and drives `uni_http::serve_conn` on top.
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
    H: AsyncFn(&uni_http::Request) -> uni_http::Response + Send + Sync + 'static,
{
    let cfg = TlsServerConfig::from_dev_cert(cert_der, key_der)
        .ok_or(ListenError::Cert)?;
    let cfg = Arc::new(cfg);
    let pool = TlsConnPool::new();

    // Pay the per-worker body-scratch + TLS-record-scratch
    // allocations into HEAP_BASELINE before any traffic arrives.
    uni_http::body_scratch_preinit();
    tls_scratch_preinit();

    let listener = uni::runtime::TcpListener::bind(port).map_err(ListenError::Bind)?;
    let handler = Arc::new(handler);
    let h = listener.run(move |tcp| {
        let handler = Arc::clone(&handler);
        let cfg = cfg.clone();
        let pool = Arc::clone(&pool);
        async move {
            let mut seed = [0u8; 32];
            uni::rng::fill_bytes(&mut seed);
            let tls = build_tls_conn(seed, cfg, pool);
            let stream = TlsStream::new(tcp, tls);
            uni_http::serve_conn(handler, stream).await;
        }
    });
    uni::_retain(h);
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
        let pool = TlsConnPool { slots: WorkerLocal::new() };
        pool.slots.ensure_init(uni::num_workers(), |_| {
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
    fn push_rx(&mut self, bytes: &[u8]) {
        self.inner.tls.push_rx(bytes);
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

    fn seal_app_data(
        &mut self,
        src_chain: &mut uni_iobuf::IOBufChain,
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
    tcp: uni::runtime::TcpStream,
    tls: PooledTlsConn,
    /// Inline ciphertext scratch reused across recvs. Folded into
    /// the struct so the future state machine that holds the
    /// `TlsStream` carries the buffer inline — one fewer alloc
    /// per HTTPS conn accept.
    cipher_buf: [u8; CIPHER_BUF_LEN],
    /// Stack-friendly scratch for draining `pop_tx` output.
    tx_scratch: [u8; 2048],
}

impl TlsStream {
    fn new(tcp: uni::runtime::TcpStream, tls: PooledTlsConn) -> Self {
        TlsStream {
            tcp,
            tls,
            cipher_buf: [0u8; CIPHER_BUF_LEN],
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
        self.tls.push_rx(&self.cipher_buf[..got]);
        self.tls.advance().map_err(|_| ())?;
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
    ///     path. Walks the plaintext chain, ciphertext lands in
    ///     the TX descriptor.
    ///   * **Worker-scratch + tcp.send fallback**: TX big-pool
    ///     full / TSO not negotiated / dst MAC unresolved → seal
    ///     into the per-worker scratch and ship via the chain-
    ///     based TCP send (which TSO's the record into MSS-sized
    ///     segments internally).
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
        let min_payload =
            src.total_len().min(PLAINTEXT_CHUNK) + TLS13_RECORD_OVERHEAD;
        match self
            .tcp
            .try_send_tso(min_payload, |slot| self.tls.seal_app_data(src, slot))
        {
            Some(Ok(_)) => return Ok(()),
            Some(Err(())) => return Err(()),
            None => {} // TSO unavailable — fall through to scratch path
        }

        // Fallback: worker-scratch seal + chain-based tcp.send.
        let mut scratch = take_record_scratch();
        let n = self
            .tls
            .seal_app_data(src, scratch.slot())
            .map_err(|_| ())?;
        let mut ship = IOBufChain::new();
        ship.push_back(scratch.into_iobuf(n));
        self.tcp.send(&mut ship).await
    }
}

impl uni_http::HttpStream for TlsStream {
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

// ============================================================================
// Per-worker TLS record scratch
// ============================================================================
//
// `TlsStream::send` needs ~16 KiB of buffer to stage a wire-ready
// TLS record across the `tcp.send.await` (TLS encrypts into the
// buffer; TCP drains it to the wire). With one scratch per send
// future, scaling to tens of thousands of concurrent TLS conns
// would need 10K × 16 KiB = 160 MiB of inline scratch in the
// per-conn pinned futures. Per-worker scratch instead bounds the
// cost at `num_workers × TLS_RECORD_LEN` (a few dozen KiB).
//
// Aliasing safety on bare-metal: the runtime's
// `async_try_send_chain` resolves synchronously — `tcp.send.await`
// never yields, so no other task on the same worker can observe
// the scratch in-use across an await. Single-task-per-worker plus
// "the await isn't really an await" gives us free exclusion.
//
// On native, `tcp.send.await` CAN yield mid-writev under
// backpressure; another task that wakes on the same worker would
// alias the scratch. We sidestep this by heap-allocating per
// record on native (developer-machine scale, not the 10K-conn
// target) — `take_record_scratch` is cfg-gated.

#[cfg(target_os = "none")]
struct TlsScratch {
    storage: core::cell::UnsafeCell<[u8; TLS_RECORD_LEN]>,
}

// SAFETY: cross-worker access is gated by WorkerLocal indexing;
// only the owning worker can construct a pointer into the slot.
#[cfg(target_os = "none")]
unsafe impl Send for TlsScratch {}

#[cfg(target_os = "none")]
static TLS_SCRATCH: WorkerLocal<TlsScratch> = WorkerLocal::new();

#[cfg(target_os = "none")]
fn tls_scratch_init() {
    TLS_SCRATCH.ensure_init(uni::num_workers(), |_| TlsScratch {
        storage: core::cell::UnsafeCell::new([0u8; TLS_RECORD_LEN]),
    });
}

#[cfg(not(target_os = "none"))]
fn tls_scratch_init() {}

/// Pre-init the per-worker TLS record scratch so the
/// `num_workers × TLS_RECORD_LEN` allocation lands in
/// HEAP_BASELINE rather than being charged to the first request
/// as a leak-check delta. Called from `listen` before any traffic
/// arrives. On native, no-op.
fn tls_scratch_preinit() {
    tls_scratch_init();
}

/// Per-worker TLS record scratch handle. Hands out the raw
/// scratch bytes for the seal pass via [`Self::slot`], then
/// converts to an `IOBuf` wrapping just the wire bytes (`[..n]`)
/// via [`Self::into_iobuf`] for the post-seal `tcp.send.await`.
///
/// Two-stage shape rather than one IOBuf throughout: TLS seal
/// writes `[hdr || ciphertext || type || tag]` starting at byte 0
/// of its destination, so it doesn't actually want the IOBuf
/// headroom/tailroom framing — just a flat `&mut [u8]`. Only the
/// TCP layer below wants an IOBuf, and only for the post-seal
/// wire-byte range.
///
/// Bare-metal contract: only one `RecordScratch` is live on a
/// given worker at a time. `TlsStream::send_one_record` ensures
/// this — it acquires, seals, ships via `tcp.send.await`
/// (synchronous on bare-metal), and lets the wrapping IOBuf drop
/// before the next acquire.
#[cfg(target_os = "none")]
struct RecordScratch {
    ptr: NonNull<u8>,
}

#[cfg(target_os = "none")]
impl RecordScratch {
    fn slot(&mut self) -> &mut [u8] {
        // SAFETY: per-worker storage; `CurrentWorker` is `!Send`
        // so no other worker can produce a pointer into this slot.
        // Within a worker, the acquire → seal → ship → drop
        // pattern (with `tcp.send.await` resolving synchronously)
        // keeps at most one borrow live at a time.
        unsafe {
            core::slice::from_raw_parts_mut(self.ptr.as_ptr(), TLS_RECORD_LEN)
        }
    }
    fn into_iobuf(self, len: usize) -> IOBuf {
        debug_assert!(len <= TLS_RECORD_LEN);
        // SAFETY: same per-worker contract; the Borrowed IOBuf
        // lives until `tcp.send.await` returns and the wrapping
        // chain drops.
        unsafe {
            IOBuf::borrow(self.ptr, TLS_RECORD_LEN as u32, 0, len as u32)
        }
    }
}

#[cfg(target_os = "none")]
fn take_record_scratch() -> RecordScratch {
    let cc = CurrentWorker::enter();
    tls_scratch_init();
    let p = TLS_SCRATCH.with(&cc, |s| s.storage.get());
    RecordScratch {
        ptr: unsafe { NonNull::new_unchecked(p as *mut u8) },
    }
}

#[cfg(not(target_os = "none"))]
struct RecordScratch {
    owned: Box<[u8]>,
}

#[cfg(not(target_os = "none"))]
impl RecordScratch {
    fn slot(&mut self) -> &mut [u8] {
        &mut self.owned[..]
    }
    fn into_iobuf(self, len: usize) -> IOBuf {
        debug_assert!(len <= self.owned.len());
        let mut v = self.owned.into_vec();
        v.truncate(len);
        IOBuf::from(v)
    }
}

#[cfg(not(target_os = "none"))]
fn take_record_scratch() -> RecordScratch {
    RecordScratch {
        owned: alloc::vec![0u8; TLS_RECORD_LEN].into_boxed_slice(),
    }
}
