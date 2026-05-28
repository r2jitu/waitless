// TLS 1.3 server handshake state machine. Sans-io: caller feeds
// inbound bytes via `process_chunk` (one TCP-recv chunk at a time),
// drains outbound TX via `pop_tx`, and pops decrypted plaintext
// records via `pop_plaintext`.
//
// Supports exactly:
//   - TLS 1.3, TLS_AES_128_GCM_SHA256, X25519
//   - ECDSA P-256 + SHA-256 server cert
// No client auth, no resumption, no 0-RTT, no key update, no ALPN.
//
// References: RFC 8446 §2 (flow), §4.1.3 (ServerHello),
// §4.3.1 (EncryptedExtensions), §4.4.2-4 (Certificate chain),
// §5 (Record protocol), §7.1 (Key schedule).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ptr::{self, addr_of_mut};

use iobuf::IOBuf;
use p256::ecdsa::SigningKey;

use crate::handshake::ParseError;
use crate::record::{
    MAX_RECORD_LEN, RecordError, content_type, seal as record_seal,
};
use crate::schedule::{HASH_LEN, KeySchedule, TrafficKey, Transcript, X25519ServerKey};

// File-local aliases. Sibling modules of this crate referenced
// throughout the file body keep their original short names
// (`tls`, `record`) so the body matches the prose in RFC 8446
// without `crate::` clutter.
use crate::record;
use crate::schedule as tls;

// ============================================================================
// Tunables
// ============================================================================

/// Max raw TLS bytes we emit during the server flight
/// (ServerHello + CCS + encrypted {EncExt, Certificate, CertVerify,
/// Finished}) plus a couple of NewSessionTickets and any alerts.
/// A typical self-signed ECDSA P-256 dev cert is ~550 bytes so the
/// flight fits in ~1.5 KB; 4 KB is generous room.
///
/// Application data bypasses `tx_buf` entirely — `seal_app_data`
/// writes the wire-ready record directly into the caller's destination
/// slice. So this constant only has to scale to handshake messages,
/// not to MAX_INNER_PLAINTEXT.
pub const TX_BUF_LEN: usize = 4 * 1024;

/// One full TLS 1.3 record's wire footprint = 5 B header +
/// `MAX_RECORD_LEN` (body + AEAD tag). The `rx_partial` straddle
/// buffer is sized to exactly one record so a single in-flight
/// straddle never overflows it.
pub const MAX_RECORD_TOTAL: usize = record::HEADER_LEN + MAX_RECORD_LEN;

// ============================================================================
// Configuration
// ============================================================================

/// Static server configuration shared across all TLS connections.
/// Must outlive every `TlsServer` that references it.
pub struct TlsServerConfig {
    /// DER-encoded X.509 certificate chain — the leaf first, then any
    /// intermediate CA certificates. Opaque to us; the client's job
    /// is to verify it (or not, in the `curl -k` case). A self-signed
    /// dev cert is a one-element chain; a real CA leaf needs its
    /// issuing intermediate appended or clients reject it.
    pub cert_chain: &'static [&'static [u8]],
    /// Pre-constructed ECDSA P-256 signing key. Built once at config
    /// creation so the handshake hot path doesn't re-derive it on
    /// every connection.
    ///
    /// Why this matters: `SigningKey::from_slice(seed)` internally
    /// runs `PublicKey::from_secret_scalar(&secret_scalar)` to
    /// populate the `verifying_key` field of the returned key (the
    /// `verifying` feature is on by default). That's a full P-256
    /// scalar multiplication (`d*G`) that we'd otherwise pay on
    /// every handshake even though we never look at the verifying
    /// key. Caching the constructed `SigningKey` eliminates that
    /// redundant scalar mult from the critical path — profiling
    /// showed it was ~half of the 346µs the raw `sign()` call took.
    pub signing_key: SigningKey,
}

impl TlsServerConfig {
    /// Build from a DER certificate chain (leaf first, then any
    /// intermediates) and a PKCS#8 ECDSA P-256 private key. The dev
    /// cert is a one-element chain; a Let's Encrypt leaf passes its
    /// issuing intermediate as the second element.
    ///
    /// The key DER from `openssl genpkey -algorithm EC -pkeyopt
    /// ec_paramgen_curve:P-256` is a PKCS#8 `PrivateKeyInfo` wrapping
    /// an RFC 5915 `ECPrivateKey` SEQUENCE, which holds the 32-byte
    /// private scalar.
    ///
    /// Returns `None` if the chain is empty, the PKCS#8 blob isn't
    /// the expected shape, or the extracted scalar isn't a valid
    /// P-256 private key.
    pub fn from_chain(cert_chain: &'static [&'static [u8]], pkcs8_key: &[u8]) -> Option<Self> {
        if cert_chain.is_empty() {
            return None;
        }
        let seed = extract_p256_d_from_pkcs8(pkcs8_key)?;
        let signing_key = SigningKey::from_slice(&seed).ok()?;
        Some(TlsServerConfig {
            cert_chain,
            signing_key,
        })
    }
}

/// Extract the 32-byte private scalar `d` from a PKCS#8 `PrivateKeyInfo`
/// DER encoding of an ECDSA P-256 key (as produced by `openssl genpkey
/// -algorithm EC -pkeyopt ec_paramgen_curve:P-256`).
///
/// The layout is:
/// ```text
///   SEQUENCE
///     INTEGER 0                              (PKCS#8 version)
///     SEQUENCE                               (AlgorithmIdentifier)
///       OID 1.2.840.10045.2.1                (id-ecPublicKey)
///       OID 1.2.840.10045.3.1.7              (prime256v1 = secp256r1)
///     OCTET STRING containing
///       SEQUENCE                             (ECPrivateKey, RFC 5915)
///         INTEGER 1                          (version)
///         OCTET STRING <d>                   (32-byte private scalar)
///         [0] explicit parameters (optional)
///         [1] explicit publicKey  (optional)
/// ```
///
/// We check that the prime256v1 OID appears in the blob, then scan for
/// `02 01 01 04 20` — the ECPrivateKey `version = 1` INTEGER followed
/// by the `OCTET STRING length = 32` header. The 32 bytes right after
/// that header are the private scalar. Deliberately narrow-minded: we
/// only parse our own checked-in dev key, not arbitrary PKCS#8.
fn extract_p256_d_from_pkcs8(blob: &[u8]) -> Option<[u8; 32]> {
    // Sanity-check the prime256v1 OID appears somewhere in the header.
    // Bytes: 06 08 2a 86 48 ce 3d 03 01 07
    //        ^  ^-- length
    //        OID tag
    const P256_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    if blob.len() < P256_OID.len() + 5 + 32 {
        return None;
    }
    let mut found_oid = false;
    for start in 0..=blob.len() - P256_OID.len() {
        if &blob[start..start + P256_OID.len()] == P256_OID {
            found_oid = true;
            break;
        }
    }
    if !found_oid {
        return None;
    }

    // Scan for `02 01 01 04 20` (ECPrivateKey version=1 +
    // 32-byte OCTET STRING header) and take the 32 bytes after.
    const D_HEADER: &[u8] = &[0x02, 0x01, 0x01, 0x04, 0x20];
    for start in 0..=blob.len() - D_HEADER.len() - 32 {
        if &blob[start..start + D_HEADER.len()] == D_HEADER {
            let d_offset = start + D_HEADER.len();
            let mut d = [0u8; 32];
            d.copy_from_slice(&blob[d_offset..d_offset + 32]);
            return Some(d);
        }
    }
    None
}

// ============================================================================
// Error type
// ============================================================================

// `AeadFailed` is reserved: no current code path constructs it — the
// underlying record-layer error is returned wrapped in
// `RecordError(...)` rather than translated. Kept so the trace
// formatter stays exhaustive and future error-translation paths have
// the name they need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    ParseError(ParseError),
    RecordError(RecordError),
    /// Client's ClientHello didn't meet our requirements
    /// (missing TLS 1.3 / X25519 / TLS_AES_128_GCM_SHA256).
    UnsupportedClient,
    /// AEAD tag mismatch on an incoming record.
    AeadFailed,
    /// Output buffer too small to hold the server flight.
    TxBufTooSmall,
    /// Client's Finished didn't match the expected HMAC.
    BadClientFinished,
    /// We received a record in a state that doesn't expect it.
    UnexpectedRecord,
    /// Internal bug: a buffer was too small (shouldn't happen with our
    /// fixed limits, but we return it instead of panicking so fuzzing
    /// input can't crash the server).
    Internal,
}

impl From<ParseError> for HandshakeError {
    fn from(e: ParseError) -> Self {
        HandshakeError::ParseError(e)
    }
}

impl From<RecordError> for HandshakeError {
    fn from(e: RecordError) -> Self {
        HandshakeError::RecordError(e)
    }
}

// ============================================================================
// State
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Before any bytes have arrived.
    WaitClientHello,
    /// Server flight has been generated; the client's Finished record
    /// is expected next. (There's no separate "flushing" state — we
    /// transition as soon as the flight is written to `tx_buf`.)
    WaitClientFinished,
    /// Handshake done; application data can flow.
    Established,
    /// Peer cleanly closed or we sent close_notify.
    Closed,
    /// Fatal error. `error` field in `TlsServer` holds the cause.
    Failed,
}

// ============================================================================
// TlsServer
// ============================================================================

/// TLS 1.3 server connection state.
///
/// The caller owns the TCP socket; this struct owns the TLS state.
/// Typical event-loop glue per connection: hand each recv'd chunk
/// to `process_chunk` (decrypts in place, queues plaintext records),
/// drain `pop_tx` between handshake stages, pop decrypted records
/// via `pop_plaintext` for the app.
///
/// ```ignore
/// // On each tick:
/// let mut chunk = tcp.recv_chunk().await?;
/// tls.process_chunk(chunk.data_mut(), &cfg)?;
/// drop(chunk);   // NIC slot returns; plaintext is in pending_plaintext.
/// loop {
///     let n_tx = tls.pop_tx(&mut tx_tmp);
///     if n_tx > 0 { tcp.send(&tx_tmp[..n_tx]); continue; }
///     if let Some(pt) = tls.pop_plaintext() {
///         app.handle(pt.data());
///         continue;
///     }
///     break;
/// }
/// ```
pub struct TlsServer {
    // State
    pub(crate) state: State,
    /// Set on fatal errors. Not read today (handlers return the
    /// error directly via `Result`); preserved as scaffolding for
    /// the eventual `state()`/`error()` accessor pair when a
    /// caller actually wants to inspect post-mortem.
    pub(crate) error: Option<HandshakeError>,

    // Lazy straddle buffer: holds a partial record carried across
    // chunk boundaries. Empty in steady state (most /health-style
    // workloads are MSS-aligned; no straddle, no allocation).
    // Sized to one full TLS 1.3 record on first use, then kept
    // warm across the conn's life (and across pool recycle via
    // `reset`).
    pub(crate) rx_partial: Option<Box<[u8]>>,
    /// Number of bytes valid in `rx_partial[..]`. `u16` because
    /// `MAX_RECORD_TOTAL < 2^14 + small constant`.
    pub(crate) rx_partial_len: u16,

    // Raw TLS bytes waiting to be sent to peer.
    pub(crate) tx_buf: [u8; TX_BUF_LEN],
    pub(crate) tx_len: usize,
    pub(crate) tx_pos: usize, // how many bytes we've handed out via pop_tx()

    // Decrypted application data records waiting for the app.
    // One owned byte buffer per record; consumer drains from the
    // front via `pop_plaintext` which lifts the head to a Heap
    // `IOBuf` (zero-copy: `IOBuf::from(Vec<u8>)` reuses the
    // allocation). Typical depth is 0 or 1 — the consumer pulls a
    // record, parses, and either replies or asks for the next.
    //
    // Stored as `Vec<u8>` rather than `IOBuf` because `IOBuf` is
    // `!Send` (the `Borrowed` variant propagates a non-Send
    // marker through the enum), and `TlsServer` types end up in a
    // `WorkerLocal` that the type-system demands be `Sync<T:Send>`
    // — even though by construction one TlsConnImpl never crosses
    // worker threads. Vec<u8> sidesteps the constraint without
    // costing a copy.
    pub(crate) pending_plaintext: VecDeque<Vec<u8>>,

    // Key schedule + transcript
    pub(crate) transcript: Transcript,
    pub(crate) schedule: KeySchedule,
    pub(crate) ephemeral: Option<X25519ServerKey>,

    // Traffic keys at each stage. `Option` so we can derive lazily.
    pub(crate) client_hs_tk: Option<TrafficKey>,
    pub(crate) server_hs_tk: Option<TrafficKey>,
    pub(crate) client_ap_tk: Option<TrafficKey>,
    pub(crate) server_ap_tk: Option<TrafficKey>,

    // Server-side handshake traffic secret — needed separately to
    // compute server Finished and then derive the master secret.
    pub(crate) server_hs_secret: Option<[u8; HASH_LEN]>,
    pub(crate) client_hs_secret: Option<[u8; HASH_LEN]>,
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        // TrafficKey / KeySchedule have their own Drop impls that
        // wipe `key` / `iv` / `secret`. The raw handshake-secret
        // arrays in this struct are separately held, so scrub them
        // here before the backing memory is released back to the
        // global allocator. (tx_buf is an inline array; it only
        // holds handshake ciphertext, not secret key material.
        // rx_partial and pending_plaintext IOBufs drop via their
        // own Drop impls.)
        if let Some(mut s) = self.server_hs_secret.take() {
            tls::secure_zero(&mut s);
        }
        if let Some(mut s) = self.client_hs_secret.take() {
            tls::secure_zero(&mut s);
        }
    }
}

impl TlsServer {
    /// Allocate a fresh boxed `TlsServer` and initialise it in
    /// place. `seed` is 32 bytes of entropy for the ephemeral
    /// X25519 keypair (caller supplies from
    /// `kernel_bare::rng::fill_bytes()`).
    ///
    /// Goes through `Box::<MaybeUninit<Self>>::new_uninit()` and
    /// writes each field via raw pointer in `init_in_place` so the
    /// 4 KB `tx_buf` inline array never round-trips through a
    /// stack temporary (the pre-streaming RX design had 12 KB of
    /// inline buffers — `init_in_place` was load-bearing there;
    /// now it's defensive for the still-inline TX side and lets
    /// the construction stay one cohesive primitive).
    pub fn new_box(x25519_seed: [u8; 32]) -> Box<Self> {
        let mut b = Box::<Self>::new_uninit();
        // SAFETY: `b.as_mut_ptr()` returns a valid `*mut TlsServer`
        // pointing at uninitialised storage of `size_of::<Self>()`;
        // `init_in_place` writes every field, after which
        // `assume_init` is sound.
        unsafe {
            Self::init_in_place(b.as_mut_ptr(), x25519_seed);
            b.assume_init()
        }
    }

    /// Write a fully-initialised `TlsServer` into the given
    /// uninitialised pointer.
    ///
    /// Each field is written via `addr_of_mut!` so the compiler
    /// never materialises a struct-shaped stack temporary; the
    /// 4 KB `tx_buf` is zero-filled directly via `write_bytes` on
    /// the heap pointer rather than `[0u8; N]` literals.
    ///
    /// # Safety
    ///
    /// `this` must point at writable, properly-aligned,
    /// uninitialised memory of exactly `size_of::<TlsServer>()`.
    /// On return, every field is initialised — the pointer is
    /// safe to convert via `assume_init` / dereference.
    pub unsafe fn init_in_place(this: *mut Self, x25519_seed: [u8; 32]) {
        // Plain Copy / small fields first.
        unsafe {
            addr_of_mut!((*this).state).write(State::WaitClientHello);
            addr_of_mut!((*this).error).write(None);
            addr_of_mut!((*this).rx_partial).write(None);
            addr_of_mut!((*this).rx_partial_len).write(0);
            addr_of_mut!((*this).tx_len).write(0);
            addr_of_mut!((*this).tx_pos).write(0);

            // tx_buf: zero-fill in place. Writing `[0u8; N]` would
            // construct the array on the stack first; `write_bytes`
            // on the field pointer does it directly on the heap.
            ptr::write_bytes(addr_of_mut!((*this).tx_buf) as *mut u8, 0, TX_BUF_LEN);

            addr_of_mut!((*this).pending_plaintext).write(VecDeque::new());

            // Sub-objects with their own constructors. These return
            // by value but are small (Transcript ≈ SHA-256 state ~
            // 100 B; KeySchedule a similar shape; X25519ServerKey
            // ~ 32 B scalar), so they round-trip a stack temp
            // safely.
            addr_of_mut!((*this).transcript).write(Transcript::new());
            addr_of_mut!((*this).schedule).write(KeySchedule::new_without_psk());
            addr_of_mut!((*this).ephemeral).write(Some(X25519ServerKey::from_seed(x25519_seed)));
            addr_of_mut!((*this).client_hs_tk).write(None);
            addr_of_mut!((*this).server_hs_tk).write(None);
            addr_of_mut!((*this).client_ap_tk).write(None);
            addr_of_mut!((*this).server_ap_tk).write(None);
            addr_of_mut!((*this).server_hs_secret).write(None);
            addr_of_mut!((*this).client_hs_secret).write(None);
        }
    }

    /// Reset this TlsServer for reuse on a fresh connection. The
    /// `rx_partial` straddle buffer (when previously allocated)
    /// stays warm across the reset — its 16 KB box is kept around
    /// so a pooled conn doesn't re-pay the allocation on its first
    /// inbound straddle. The plaintext queue's IOBufs drop here
    /// (any leftover undelivered records from a prior conn — e.g.
    /// a half-closed peer — get freed).
    ///
    /// Observable state matches `TlsServer::new_box(seed)` after
    /// the call: fresh X25519 keypair, all traffic keys cleared,
    /// transcript / key schedule reinitialised, no buffered RX or
    /// plaintext.
    ///
    /// Used by the per-worker conn-state pool: a freed
    /// `Box<TlsConnImpl>` is reset and pushed back; the next accept
    /// pops it instead of allocating fresh.
    pub fn reset(&mut self, x25519_seed: [u8; 32]) {
        // Wipe handshake-secret arrays before clearing — same
        // discipline as our Drop impl. TrafficKey and KeySchedule
        // wipe their own key/iv/secret in their Drop impls when we
        // overwrite them below.
        if let Some(mut s) = self.server_hs_secret.take() {
            tls::secure_zero(&mut s);
        }
        if let Some(mut s) = self.client_hs_secret.take() {
            tls::secure_zero(&mut s);
        }

        self.state = State::WaitClientHello;
        self.error = None;
        // Keep the rx_partial box (if allocated) but mark its
        // content empty — the next straddle reuses the warm slot.
        self.rx_partial_len = 0;
        self.tx_len = 0;
        self.tx_pos = 0;
        self.pending_plaintext.clear();
        self.transcript = Transcript::new();
        self.schedule = KeySchedule::new_without_psk();
        self.ephemeral = Some(X25519ServerKey::from_seed(x25519_seed));
        self.client_hs_tk = None;
        self.server_hs_tk = None;
        self.client_ap_tk = None;
        self.server_ap_tk = None;
        // server_hs_secret / client_hs_secret already cleared above.
    }

    // ── Outward API (caller-driven) ─────────────────────────────────

    /// Drain buffered outgoing TLS bytes into `out`. Returns bytes copied.
    pub fn pop_tx(&mut self, out: &mut [u8]) -> usize {
        let available = self.tx_len - self.tx_pos;
        let n = core::cmp::min(available, out.len());
        out[..n].copy_from_slice(&self.tx_buf[self.tx_pos..self.tx_pos + n]);
        self.tx_pos += n;
        if self.tx_pos == self.tx_len {
            self.tx_len = 0;
            self.tx_pos = 0;
        }
        n
    }

    /// `true` when an undelivered decrypted plaintext record is
    /// queued. A peek; does not consume.
    pub fn has_plaintext(&self) -> bool {
        !self.pending_plaintext.is_empty()
    }

    /// Pop the next decrypted plaintext record as a `Heap` IOBuf.
    /// Returns `None` when the queue is empty. The byte buffer was
    /// owned at AEAD-decrypt time (`do_app_data` copied the
    /// in-place plaintext into a fresh `Vec`), so the NIC RX slot
    /// it came from has long since returned to the pool — callers
    /// can hold the IOBuf indefinitely without back-pressuring the
    /// NIC.
    ///
    /// Zero copy: `IOBuf::from(Vec<u8>)` reuses the existing heap
    /// allocation (`Vec::into_boxed_slice` when `len == capacity`).
    pub fn pop_plaintext(&mut self) -> Option<IOBuf> {
        self.pending_plaintext.pop_front().map(IOBuf::from)
    }

    /// Emit a TLS 1.3 `close_notify` alert record (RFC 8446 §6.1)
    /// into the TX buffer and move the connection to `State::Closed`.
    ///
    /// The alert is `[level=warning(1), description=close_notify(0)]`
    /// — 2 bytes of plaintext wrapped in an `alert`-type record and
    /// encrypted under the current server application traffic key.
    /// After this call, the caller is expected to drain `tx_buf` onto
    /// the wire and then close the underlying TCP connection. No
    /// further `send_app_data` / `advance` calls should be made.
    ///
    /// Silently no-ops if the connection is not in `Established` (we
    /// don't send alerts during a half-complete handshake because
    /// the traffic keys may not exist yet — closing the TCP without
    /// an alert is the conservative thing in that case).
    pub fn close_notify(&mut self) -> Result<(), HandshakeError> {
        if self.state != State::Established {
            // No traffic keys, nothing we can cleanly encrypt.
            // Caller should just close TCP.
            self.state = State::Closed;
            return Ok(());
        }
        let tk = self.server_ap_tk.as_mut().ok_or(HandshakeError::Internal)?;
        let alert_body: [u8; 2] = [1, 0]; // warning(1), close_notify(0)
        let needed = record::HEADER_LEN + alert_body.len() + 1 + record::TAG_LEN;
        if TX_BUF_LEN - self.tx_len < needed {
            // No space for the alert; give up cleanly rather than
            // wedging. Caller will close TCP; peer will see an
            // unexpected eof but at least nothing crashes.
            self.state = State::Closed;
            return Ok(());
        }
        let n = record_seal(
            tk,
            content_type::ALERT,
            &alert_body,
            &mut self.tx_buf[self.tx_len..],
        )?;
        self.tx_len += n;
        crate::diag::COUNTERS.close_notify_sent.bump();
        self.state = State::Closed;
        Ok(())
    }

    /// Read up to one record's worth of plaintext from `src_chain`,
    /// encrypt-while-copying directly into `dst` with the layout
    /// `[5 hdr || N ciphertext || 1 type || 16 tag]` starting at
    /// byte 0, and consume the bytes used from the front of
    /// `src_chain`. Returns the wire byte count.
    ///
    /// Bypasses `tx_buf` entirely — `dst` is the caller's buffer
    /// (TX-slot in the fast-fast path, worker scratch in the
    /// fallback). The TLS layer's `TlsStream::send_one_record`
    /// loops this until the chain is drained.
    pub fn seal_app_data(
        &mut self,
        src_chain: &mut iobuf::IOBufChain,
        dst: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        if self.state != State::Established {
            return Err(HandshakeError::UnexpectedRecord);
        }
        let tk = self.server_ap_tk.as_mut().ok_or(HandshakeError::Internal)?;
        record::seal_chain(tk, content_type::APPLICATION_DATA, src_chain, dst).map_err(|e| e.into())
    }

    /// Consume one inbound TCP chunk: walk record headers in
    /// `cipher` (and any partial record carried over from the
    /// previous chunk), dispatch each complete record to the
    /// state-appropriate handler, and stash any straddler in
    /// `rx_partial` for the next call.
    ///
    /// `cipher` is borrowed mutably because record-layer AEAD
    /// `open` decrypts in place — the chunk's ciphertext bytes are
    /// overwritten with plaintext as records are consumed. The
    /// caller (`TlsStream::pump_rx`) drops the underlying NIC RX
    /// chunk immediately on return, so the scrambled bytes are
    /// never observed again.
    ///
    /// Returns the current state on success. Transitions across
    /// multiple records inside a single chunk are handled by the
    /// per-record dispatch — e.g. a chunk containing
    /// `[middlebox-CCS, ClientFinished, first app_data]` advances
    /// `WaitClientFinished -> Established` between records 2 and 3
    /// and decrypts record 3 with the application traffic key.
    pub fn process_chunk(
        &mut self,
        cipher: &mut [u8],
        config: &TlsServerConfig,
    ) -> Result<State, HandshakeError> {
        let entry_state = self.state;
        let result = self.process_chunk_inner(cipher, config);
        if entry_state != State::Established && self.state == State::Established {
            crate::diag::COUNTERS.handshakes_completed.bump();
        }
        match result {
            Ok(()) => Ok(self.state),
            Err(e) => {
                crate::trace::error(self.state, &e);
                crate::diag::record_handshake_failure(self.state, &e);
                Err(e)
            }
        }
    }

    fn process_chunk_inner(
        &mut self,
        cipher: &mut [u8],
        config: &TlsServerConfig,
    ) -> Result<(), HandshakeError> {
        // Phase 1: complete any partial record carried from the
        // previous chunk. If still incomplete after consuming part
        // of `cipher`, return — wait for more.
        let cursor = self.complete_partial(cipher, config)?;
        if self.rx_partial_len > 0 {
            // Still straddled — `complete_partial` consumed the
            // whole remaining slice into rx_partial.
            debug_assert_eq!(cursor, cipher.len());
            return Ok(());
        }

        // Phase 2: walk `cipher[cursor..]` record-by-record.
        let mut off = cursor;
        while off < cipher.len() {
            // Closed / Failed terminate early — any trailing bytes
            // are dropped on the floor (the conn is being torn
            // down).
            if matches!(self.state, State::Closed | State::Failed) {
                return Ok(());
            }

            let remaining = &cipher[off..];
            if remaining.len() < record::HEADER_LEN {
                // Header straddles into the next chunk.
                self.save_to_partial(remaining)?;
                return Ok(());
            }
            let len_field =
                u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
            let total = record::HEADER_LEN + len_field;
            if total > MAX_RECORD_TOTAL {
                return Err(RecordError::RecordTooLarge.into());
            }
            if remaining.len() < total {
                // Body straddles — stash and wait.
                self.save_to_partial(remaining)?;
                return Ok(());
            }
            // Complete record — dispatch to the state handler.
            self.dispatch_record(&mut cipher[off..off + total], config)?;
            off += total;
        }
        Ok(())
    }

    /// Drain any prior-chunk straddler. Returns the number of
    /// `cipher` bytes consumed (always 0 when `rx_partial_len ==
    /// 0`). On exit either `rx_partial_len == 0` (record dispatched)
    /// or the full remaining `cipher` was absorbed and we're still
    /// short.
    fn complete_partial(
        &mut self,
        cipher: &mut [u8],
        config: &TlsServerConfig,
    ) -> Result<usize, HandshakeError> {
        if self.rx_partial_len == 0 {
            return Ok(0);
        }
        // SAFETY-by-invariant: rx_partial_len > 0 only after
        // save_to_partial allocated rx_partial.
        let partial = self
            .rx_partial
            .as_mut()
            .expect("rx_partial_len > 0 implies allocated");
        let mut have = self.rx_partial_len as usize;
        let mut cursor = 0usize;

        // Bring in enough bytes to read the 5-byte record header.
        if have < record::HEADER_LEN {
            let need = record::HEADER_LEN - have;
            let to_copy = need.min(cipher.len());
            partial[have..have + to_copy].copy_from_slice(&cipher[..to_copy]);
            have += to_copy;
            cursor += to_copy;
            self.rx_partial_len = have as u16;
            if have < record::HEADER_LEN {
                return Ok(cursor); // still short of a full header
            }
        }

        // Now we can compute the expected total record size.
        let len_field = u16::from_be_bytes([partial[3], partial[4]]) as usize;
        let total = record::HEADER_LEN + len_field;
        if total > MAX_RECORD_TOTAL {
            return Err(RecordError::RecordTooLarge.into());
        }
        let need = total - have;
        let available = cipher.len() - cursor;
        let to_copy = need.min(available);
        partial[have..have + to_copy]
            .copy_from_slice(&cipher[cursor..cursor + to_copy]);
        cursor += to_copy;
        have += to_copy;
        self.rx_partial_len = have as u16;

        if have < total {
            // Still short — caller leaves cursor at end of cipher.
            return Ok(cursor);
        }

        // Complete: dispatch the record. Take rx_partial out by
        // value so we can borrow `&mut self` for the dispatcher
        // without aliasing the box; put it back afterward.
        self.rx_partial_len = 0;
        let mut owned = self
            .rx_partial
            .take()
            .expect("present from invariant above");
        let dispatch_result = self.dispatch_record(&mut owned[..total], config);
        self.rx_partial = Some(owned);
        dispatch_result?;
        Ok(cursor)
    }

    /// Lazily allocate `rx_partial` (one max-record-sized box) on
    /// first straddle and stash `bytes` (one partial record's
    /// worth) inside it. The box is kept warm across `reset()` so
    /// pooled conns don't re-pay the allocation.
    ///
    /// OOM is graceful: returns `HandshakeError::Internal`, which
    /// the caller surfaces as a conn-fatal error rather than a
    /// panic — same admission discipline as the per-conn RTX ring.
    fn save_to_partial(&mut self, bytes: &[u8]) -> Result<(), HandshakeError> {
        if bytes.len() > MAX_RECORD_TOTAL {
            // Caller framed a longer-than-max chunk; that's a
            // protocol error we'd have caught above anyway, but
            // defend on the path too.
            return Err(RecordError::RecordTooLarge.into());
        }
        if self.rx_partial.is_none() {
            let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            if v.try_reserve_exact(MAX_RECORD_TOTAL).is_err() {
                return Err(HandshakeError::Internal);
            }
            v.resize(MAX_RECORD_TOTAL, 0);
            self.rx_partial = Some(v.into_boxed_slice());
        }
        let buf = self.rx_partial.as_mut().expect("just-ensured Some");
        buf[..bytes.len()].copy_from_slice(bytes);
        self.rx_partial_len = bytes.len() as u16;
        Ok(())
    }

    /// Dispatch one complete record (already framed by the
    /// orchestrator) to the state-appropriate handler.
    fn dispatch_record(
        &mut self,
        record: &mut [u8],
        config: &TlsServerConfig,
    ) -> Result<(), HandshakeError> {
        match self.state {
            State::WaitClientHello => self.do_client_hello(record, config),
            State::WaitClientFinished => self.do_client_finished(record),
            State::Established => self.do_app_data(record),
            State::Closed | State::Failed => Ok(()),
        }
    }
}

// ============================================================================
// Basic host tests (primitives only)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_p256_d_matches_known_shape() {
        // Hand-assembled PKCS#8 matching the openssl genpkey -algorithm EC
        // -pkeyopt ec_paramgen_curve:P-256 -outform DER output, stripped
        // down to just the parts our extractor checks for:
        //   * the prime256v1 OID (06 08 2a 86 48 ce 3d 03 01 07) somewhere
        //     in the AlgorithmIdentifier
        //   * the ECPrivateKey `version=1` INTEGER followed by a 32-byte
        //     OCTET STRING containing the private scalar (02 01 01 04 20
        //     <32 bytes>)
        let mut blob = [0u8; 64];
        // id-ecPublicKey + prime256v1 OIDs (just the prime256v1 OID is
        // required by our extractor; id-ecPublicKey is a real-blob detail).
        blob[0..10].copy_from_slice(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
        // ECPrivateKey version=1 + OCTET STRING length=32 header.
        blob[10..15].copy_from_slice(&[0x02, 0x01, 0x01, 0x04, 0x20]);
        // Scalar: 32 bytes of 0, 1, 2, ... 31.
        for (i, slot) in blob[15..47].iter_mut().enumerate() {
            *slot = i as u8;
        }
        let d = extract_p256_d_from_pkcs8(&blob).expect("parse");
        let mut expected = [0u8; 32];
        for (i, slot) in expected.iter_mut().enumerate() {
            *slot = i as u8;
        }
        assert_eq!(d, expected);
    }
}
