// TLS 1.3 server handshake state machine. Sans-io: caller feeds bytes
// via `push_rx` / `pop_tx`, drives state with `advance`.
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
use core::ptr::{self, addr_of_mut};

use p256::ecdsa::SigningKey;

use crate::handshake::ParseError;
use crate::record::{RecordError, content_type, seal as record_seal};
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
//
// rx/tx/pt buffers are now inline `[u8; N]` arrays inside `TlsServer`
// (was: three separate `Box<[u8]>` allocations). Inline brings the
// fresh-conn allocation count from 4 → 1: a single
// `Box<TlsConnImpl>` covers the metadata, all three buffers, and the
// shared cfg pointer in one contiguous heap block.
//
// Stack-overflow on the boot path is avoided by `init_in_place`
// below — it writes every field via `addr_of_mut!` without ever
// constructing the 12 KB struct on the stack. `TlsServer::new_box`
// is the only public constructor; struct-literal construction
// (`TlsServer { ... }`) would create the stack temp the comment
// previously warned about, so it's intentionally not exposed.
//
// Sized to fit a typical ClientHello / server flight / HTTP/1.1
// request respectively; 4 KB is generous for all three.

/// Max raw TLS bytes we buffer from the peer before advancing the
/// state machine. TLS 1.3 lets peers send records up to ~16 KiB
/// plaintext + 22 B AEAD/record overhead = 16406 B; production
/// clients (rustls, OpenSSL, Chrome, Safari) routinely fill that
/// for bulk uploads. Sized to one full max-size record so a
/// 32 KiB POST that splits into 2 records can still be processed
/// one-at-a-time: each record fills rx_buf, gets parsed +
/// drained, then the next arrives. Anything bigger than this in
/// a single record will close the connection.
pub const RX_BUF_LEN: usize = 17 * 1024;

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

/// Max decrypted plaintext we buffer for the app between
/// `pop_plaintext` calls. Must fit one full TLS 1.3 record's
/// worth of plaintext (16 KiB max) — `do_app_data` refuses to
/// consume a record whose plaintext exceeds remaining space,
/// so a smaller cap stalls bulk uploads (curl test:
/// >4 KiB POST hung at "0 bytes received" before this bump).
pub const PT_BUF_LEN: usize = 17 * 1024;

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
/// Typical event-loop glue per connection:
///
/// ```ignore
/// // On each tick:
/// let bytes_read = tcp.recv(&mut tmp);
/// tls.push_rx(&tmp[..bytes_read]);
/// loop {
///     let n_tx = tls.pop_tx(&mut tx_tmp);
///     if n_tx > 0 { tcp.send(&tx_tmp[..n_tx]); continue; }
///     let n_pt = tls.pop_plaintext(&mut pt_tmp);
///     if n_pt > 0 { app.handle(&pt_tmp[..n_pt]); continue; }
///     match tls.advance(config) { ... }
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

    // Raw TLS bytes received from peer (may contain partial or
    // multiple records). Inline `[u8; N]` arrays now live with the
    // metadata in a single Box<TlsConnImpl> — the boxed allocation
    // is one heap block per conn, no per-buffer secondary allocs.
    // See `init_in_place` for the stack-temp-avoidance scheme.
    pub(crate) rx_buf: [u8; RX_BUF_LEN],
    pub(crate) rx_len: usize,

    // Raw TLS bytes waiting to be sent to peer.
    pub(crate) tx_buf: [u8; TX_BUF_LEN],
    pub(crate) tx_len: usize,
    pub(crate) tx_pos: usize, // how many bytes we've handed out via pop_tx()

    // Decrypted application data waiting to be consumed by the app.
    pub(crate) pt_buf: [u8; PT_BUF_LEN],
    pub(crate) pt_len: usize,
    pub(crate) pt_pos: usize,

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
        // global allocator. (rx/tx/pt buffers are inline arrays;
        // they hold ciphertext and decrypted request plaintext,
        // not secret key material — no scrub needed before free.)
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
    /// place — single 12 KB heap allocation, no per-buffer
    /// secondary allocs. `seed` is 32 bytes of entropy for the
    /// ephemeral X25519 keypair (caller supplies from
    /// `kernel_bare::rng::fill_bytes()`).
    ///
    /// The struct is too large to round-trip through a stack
    /// temporary (3 × 4 KB inline buffers), so we go through
    /// `Box::<MaybeUninit<Self>>::new_uninit()` and write each
    /// field via raw pointer in `init_in_place`. RVO/NRVO is not
    /// guaranteed across all build configurations and the
    /// pre-inline boot stack was tight enough that the original
    /// design boxed the buffers separately to dodge this exact
    /// problem; the in-place writer makes inlining safe again.
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
    /// never materialises a struct-shaped stack temporary; in
    /// particular the three 4 KB buffers are zero-filled directly
    /// via `write_bytes` on the heap pointer rather than
    /// `[0u8; N]` literals.
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
            addr_of_mut!((*this).rx_len).write(0);
            addr_of_mut!((*this).tx_len).write(0);
            addr_of_mut!((*this).tx_pos).write(0);
            addr_of_mut!((*this).pt_len).write(0);
            addr_of_mut!((*this).pt_pos).write(0);

            // Buffers: zero-fill in place. Writing `[0u8; N]` would
            // construct the array on the stack first; `write_bytes`
            // on the field pointer does it directly on the heap.
            ptr::write_bytes(addr_of_mut!((*this).rx_buf) as *mut u8, 0, RX_BUF_LEN);
            ptr::write_bytes(addr_of_mut!((*this).tx_buf) as *mut u8, 0, TX_BUF_LEN);
            ptr::write_bytes(addr_of_mut!((*this).pt_buf) as *mut u8, 0, PT_BUF_LEN);

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
    /// whole struct (incl. the 12 KB of inline rx/tx/pt buffers)
    /// stays in its existing heap slot — no allocations happen
    /// here. Observable state matches `TlsServer::new_box(seed)`
    /// after the call: buffers are logically empty (length cursors
    /// at 0), fresh X25519 keypair, all traffic keys cleared,
    /// transcript / key schedule reinitialised. The buffer storage
    /// itself isn't touched (see the buffer-secrecy note below).
    ///
    /// Used by the per-worker conn-state pool (item M in
    /// docs/tx-path-optimizations.md): a freed `Box<TlsConnImpl>`
    /// is reset and pushed back to the pool; the next accept pops
    /// it instead of allocating a new TlsServer + 3 buffers.
    ///
    /// Buffer contents are not zeroed — the buffer slots
    /// (`..rx_len`, `..tx_len`, `..pt_len`) are inaccessible via
    /// the API once their length cursors reset to 0, and
    /// application plaintext that lived in `pt_buf` during the
    /// previous conn isn't secret cryptographic material in our
    /// model (the application already saw it). `rx_buf` / `tx_buf`
    /// only ever held ciphertext.
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
        self.rx_len = 0;
        self.tx_len = 0;
        self.tx_pos = 0;
        self.pt_len = 0;
        self.pt_pos = 0;
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

    /// Push raw TLS bytes from the peer into the RX buffer. Returns
    /// the number of bytes accepted (may be less than `data.len()` if
    /// our buffer is temporarily full).
    pub fn push_rx(&mut self, data: &[u8]) -> usize {
        let space = RX_BUF_LEN - self.rx_len;
        let n = core::cmp::min(space, data.len());
        self.rx_buf[self.rx_len..self.rx_len + n].copy_from_slice(&data[..n]);
        self.rx_len += n;
        n
    }

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

    /// Drain decrypted application data into `out`.
    pub fn pop_plaintext(&mut self, out: &mut [u8]) -> usize {
        let available = self.pt_len - self.pt_pos;
        let n = core::cmp::min(available, out.len());
        out[..n].copy_from_slice(&self.pt_buf[self.pt_pos..self.pt_pos + n]);
        self.pt_pos += n;
        if self.pt_pos == self.pt_len {
            self.pt_len = 0;
            self.pt_pos = 0;
        }
        n
    }

    /// `true` when undelivered decrypted plaintext is buffered —
    /// i.e. the next [`pop_plaintext`](Self::pop_plaintext) /
    /// [`take_plaintext_chunk`](Self::take_plaintext_chunk) would
    /// hand back bytes. A peek; does not move the cursor.
    pub fn has_plaintext(&self) -> bool {
        self.pt_pos < self.pt_len
    }

    /// Zero-copy sibling of [`pop_plaintext`](Self::pop_plaintext):
    /// hand back the buffered plaintext window `pt_buf[pt_pos..pt_len]`
    /// *in place* and consume it from the cursors' point of view,
    /// instead of copying it into a caller buffer.
    ///
    /// The plaintext *bytes* in `pt_buf` are untouched — only the
    /// `pt_pos` / `pt_len` cursors reset (matching the full-drain
    /// branch of `pop_plaintext`). So a reader holding the returned
    /// slice keeps seeing valid plaintext until the next
    /// [`advance`](Self::advance) decrypts a fresh record into
    /// `pt_buf`. The caller MUST therefore keep this `TlsServer`
    /// borrowed and un-`advance`d for as long as it reads the
    /// slice: `TlsStream::recv_chunk` does exactly that — the
    /// `RecvChunkGuard` it returns carries the `&mut TlsStream`
    /// borrow, which the borrow checker then forbids `pump_rx`
    /// (the lone `advance` caller) to run under.
    ///
    /// `pt_buf` holds at most one record's plaintext, so the
    /// returned slice is a single contiguous chunk. Returns an
    /// empty slice when nothing is buffered; callers gate on
    /// [`has_plaintext`](Self::has_plaintext).
    pub fn take_plaintext_chunk(&mut self) -> &mut [u8] {
        let lo = self.pt_pos;
        let hi = self.pt_len;
        // Consume the window now (eager): the caller wraps these
        // bytes in a borrow-guarded view, and the next
        // `pop_plaintext` / `take_plaintext_chunk` must not
        // re-deliver them.
        self.pt_pos = 0;
        self.pt_len = 0;
        &mut self.pt_buf[lo..hi]
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

    /// Advance the state machine as far as possible with what's in
    /// `rx_buf`. Returns the current state.
    ///
    /// Loops until no further progress is possible: each state handler
    /// processes at most one record, but a single caller push may have
    /// delivered multiple records across state-transition boundaries
    /// (e.g. ClientChangeCipherSpec + ClientFinished + first
    /// application_data record all arrive in one TCP segment). Without
    /// the loop, the handler that transitions WaitClientFinished →
    /// Established would consume Finished and return, leaving the app
    /// data record stranded in `rx_buf` until the next caller push —
    /// which for a short HTTPS request never comes, wedging the conn.
    pub fn advance(&mut self, config: &TlsServerConfig) -> Result<State, HandshakeError> {
        // State on entry — so a fresh transition to `Established`
        // can be counted exactly once (the doctrine handshake-
        // completed counter), regardless of how many inner steps run.
        let entry_state = self.state;
        loop {
            let before_state = self.state;
            let before_rx = self.rx_len;
            let before_pt = self.pt_len;
            let before_tx = self.tx_len;
            let step_result: Result<(), HandshakeError> = match self.state {
                State::WaitClientHello => self.do_client_hello(config),
                State::WaitClientFinished => self.do_client_finished(),
                State::Established => self.do_app_data(),
                State::Closed | State::Failed => return Ok(self.state),
            };
            if let Err(e) = step_result {
                crate::trace::error(before_state, &e);
                crate::diag::record_handshake_failure(before_state, &e);
                return Err(e);
            }
            let progressed = self.state != before_state
                || self.rx_len != before_rx
                || self.pt_len != before_pt
                || self.tx_len != before_tx;
            if !progressed {
                if entry_state != State::Established && self.state == State::Established {
                    crate::diag::COUNTERS.handshakes_completed.bump();
                }
                return Ok(self.state);
            }
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
