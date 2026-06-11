// TLS 1.3 CLIENT handshake state machine. Sans-io mirror of
// `server.rs`: the caller feeds inbound bytes via `process_chunk`
// (one TCP-recv chunk at a time), drains outbound TX via `pop_tx`,
// and pops decrypted plaintext records via `pop_plaintext`. The
// ClientHello is emitted at construction (`new_box`), so the very
// first `pop_tx` drain already carries the client's first flight.
//
// Supports exactly the shape this crate's server speaks (and any
// RFC-compliant TLS 1.3 server offering the same):
//   - TLS 1.3, TLS_AES_128_GCM_SHA256, X25519
//   - ECDSA P-256 + SHA-256 server certificates
// Server authentication is by SPKI pin (`ServerAuth::PinnedSpki`) —
// a SHA-256 over the leaf certificate's SubjectPublicKeyInfo DER —
// or loudly skipped (`ServerAuth::InsecureSkipVerify`, bench/sim
// only; the Finished check still runs either way since it keys off
// the handshake secret). Full X.509 chain / web-PKI validation is a
// documented non-goal.
//
// Documented non-goals / v1 limits:
//   - HelloRetryRequest: we always offer x25519 (the only group we
//     implement), so a compliant server never needs to retry; an HRR
//     fails cleanly with `ClientHandshakeError::HelloRetryRequest`.
//   - Resumption: NewSessionTicket messages are counted and
//     discarded (`tickets_received`); offering a PSK on a later
//     connection is a follow-up.
//   - KeyUpdate: not supported in either role (see server.rs "no key
//     update"); a server-initiated KEY_UPDATE fails cleanly with
//     `KeyUpdateUnsupported`.
//   - Client certificates: never offered; a CertificateRequest is an
//     `UnexpectedMessage`.
//
// All entropy arrives by value: `new_box(seed, ..)` expands the
// caller's 32-byte seed into the X25519 keypair seed, the ClientHello
// random, and the legacy_session_id via HKDF-Expand-Label with
// distinct local labels — the same `TlsClient` seed reproduces the
// same ClientHello byte-for-byte (deterministic-simulation friendly).
//
// References: RFC 8446 §2 (flow), §4.1.2 (ClientHello), §4.1.3
// (ServerHello), §4.4.2-4 (server auth), §4.6.1 (NewSessionTicket),
// §5 (Record protocol), §7.1 (Key schedule), §D.4 (middlebox compat).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ptr::{self, addr_of_mut};

use iobuf::{IOBuf, OwnedIOBuf};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::handshake::{
    ClientHelloParams, ParseError, build_client_hello, build_finished, encode_handshake,
    msg_type, parse_certificate_leaf, parse_certificate_verify, parse_encrypted_extensions,
    parse_finished, parse_handshake, parse_server_hello, sig_scheme,
    sign_content_server_cert_verify,
};
use crate::keys::{ct_eq_32, derive_finished_key, hmac_sha256};
use crate::record::{
    RecordError, content_type, open as record_open, seal as record_seal,
};
use crate::schedule::{
    HASH_LEN, KeySchedule, TrafficKey, Transcript, X25519ServerKey, hkdf_expand_label,
};

// File-local aliases, mirroring server.rs: sibling modules keep their
// short names so the body reads like the RFC 8446 prose.
use crate::record;
use crate::schedule as tls;

// The client reuses the server's TX-buffer and straddle-buffer
// dimensions — the client flight (ClientHello + CCS + Finished +
// alerts) is strictly smaller than the server's.
use crate::server::{MAX_RECORD_TOTAL, TX_BUF_LEN};

// ============================================================================
// Tunables
// ============================================================================

/// Largest single handshake message we accept from a server.
/// Certificate is the big one: the dev chain is ~600 B, a typical
/// web-PKI leaf+intermediate chain is 4–6 KiB. 16 KiB leaves margin
/// without letting a hostile server balloon the reassembly buffer.
pub const MAX_HS_MSG: usize = 16 * 1024;

/// Cap on the cross-record handshake-message reassembly buffer: one
/// maximum-size in-flight message plus one record's worth of tail.
pub const MAX_HS_BUF: usize = MAX_HS_MSG + MAX_RECORD_TOTAL;

/// Longest ALPN protocol name the client config may offer (and thus
/// the longest selection it can store). "http/1.1" is 8; 32 is roomy.
pub const MAX_ALPN_NAME_LEN: usize = 32;

// ============================================================================
// Configuration
// ============================================================================

/// How the client authenticates the server's certificate.
#[derive(Clone, Copy)]
pub enum ServerAuth {
    /// SHA-256 over the leaf certificate's SubjectPublicKeyInfo DER
    /// (the full TLV — the RFC 7469 pin definition). Compute it from
    /// a cert with [`spki_pin_from_cert_der`]. The pinned P-256 key
    /// then verifies CertificateVerify per RFC 8446 §4.4.3.
    PinnedSpki([u8; 32]),
    /// Skip the pin AND the CertificateVerify signature check. As the
    /// name shouts: NO server authentication — a MITM with any valid
    /// TLS 1.3 stack passes. Bench / deterministic-sim use only. The
    /// Finished check still runs (it keys off the handshake secret),
    /// so accidental key-schedule divergence is still caught.
    InsecureSkipVerify,
}

/// Static client configuration. Mirrors `TlsServerConfig`: built once,
/// passed by reference into `new_box` / `process_chunk`.
pub struct TlsClientConfig {
    /// Server authentication mode.
    pub auth: ServerAuth,
    /// Optional `server_name` (SNI) host bytes, e.g. `b"dev.r2jitu.com"`.
    /// 1–255 bytes when present.
    pub server_name: Option<&'static [u8]>,
    /// ALPN protocols to offer, in preference order. Empty ⇒ no ALPN.
    /// Each name 1–[`MAX_ALPN_NAME_LEN`] bytes.
    pub alpn: &'static [&'static [u8]],
}

// ============================================================================
// Error type
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHandshakeError {
    ParseError(ParseError),
    RecordError(RecordError),
    /// ServerHello (or a later message) didn't meet our requirements:
    /// wrong suite/version/key_share, a session-id echo mismatch, an
    /// unsolicited pre_shared_key, or an ALPN selection we never
    /// offered.
    UnsupportedServer,
    /// The server answered with a HelloRetryRequest. We always offer
    /// x25519 — the only group we implement — so HRR support is a
    /// documented non-goal; surface it distinctly instead of
    /// misparsing the retry.
    HelloRetryRequest,
    /// SPKI pin mismatch on the server's leaf certificate.
    PinMismatch,
    /// The leaf certificate's DER walk or P-256 key extraction failed.
    BadCertificate,
    /// CertificateVerify didn't verify (wrong algorithm, malformed
    /// DER signature, or signature mismatch).
    BadCertificateVerify,
    /// Server Finished verify_data mismatch.
    BadServerFinished,
    /// A record arrived in a state that doesn't expect it.
    UnexpectedRecord,
    /// A handshake message arrived in a state that doesn't expect it.
    UnexpectedMessage,
    /// Server-initiated KeyUpdate — unsupported in v1 (mirrors the
    /// server role, which never sends one). Rejected cleanly.
    KeyUpdateUnsupported,
    /// A handshake message exceeded [`MAX_HS_MSG`] or the reassembly
    /// buffer cap.
    MessageTooLarge,
    /// Output buffer too small to hold the client flight.
    TxBufTooSmall,
    /// The application traffic key sealed its full RFC 8446 §5.5
    /// record budget (see `TrafficKey::SEAL_RECORD_LIMIT`).
    KeyExhausted,
    /// Internal bug surfaced as an error instead of a panic.
    Internal,
}

impl From<ParseError> for ClientHandshakeError {
    fn from(e: ParseError) -> Self {
        ClientHandshakeError::ParseError(e)
    }
}

impl From<RecordError> for ClientHandshakeError {
    fn from(e: RecordError) -> Self {
        ClientHandshakeError::RecordError(e)
    }
}

/// TLS alert descriptions (RFC 8446 §6.2) used by the client's
/// fatal-alert emission.
mod alert {
    pub const UNEXPECTED_MESSAGE: u8 = 10;
    pub const BAD_RECORD_MAC: u8 = 20;
    pub const HANDSHAKE_FAILURE: u8 = 40;
    pub const BAD_CERTIFICATE: u8 = 42;
    pub const DECODE_ERROR: u8 = 50;
    pub const DECRYPT_ERROR: u8 = 51;
    pub const INTERNAL_ERROR: u8 = 80;
}

fn alert_description_for(e: &ClientHandshakeError) -> u8 {
    use ClientHandshakeError as E;
    match e {
        E::PinMismatch | E::BadCertificate => alert::BAD_CERTIFICATE,
        E::BadCertificateVerify | E::BadServerFinished => alert::DECRYPT_ERROR,
        E::RecordError(RecordError::AeadOpenFailed) => alert::BAD_RECORD_MAC,
        E::ParseError(_) | E::RecordError(_) | E::MessageTooLarge => alert::DECODE_ERROR,
        E::HelloRetryRequest | E::UnsupportedServer => alert::HANDSHAKE_FAILURE,
        E::UnexpectedRecord | E::UnexpectedMessage | E::KeyUpdateUnsupported => {
            alert::UNEXPECTED_MESSAGE
        }
        E::TxBufTooSmall | E::KeyExhausted | E::Internal => alert::INTERNAL_ERROR,
    }
}

// ============================================================================
// State
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// ClientHello sent (at construction); ServerHello expected.
    WaitServerHello,
    /// Handshake keys derived; EncryptedExtensions expected.
    WaitEncryptedExtensions,
    /// Certificate expected (fresh handshake — v1 never offers a PSK,
    /// so the server flight always carries the cert).
    WaitCertificate,
    /// CertificateVerify expected.
    WaitCertificateVerify,
    /// Server Finished expected.
    WaitFinished,
    /// Handshake done; application data can flow.
    Established,
    /// Peer cleanly closed or we sent close_notify.
    Closed,
    /// Fatal error. `error` field holds the cause.
    Failed,
}

// ============================================================================
// TlsClient
// ============================================================================

/// TLS 1.3 client connection state.
///
/// The caller owns the TCP socket; this struct owns the TLS state.
/// Typical glue per connection: construct (the ClientHello lands in
/// the TX buffer immediately), drain `pop_tx` onto the wire, hand
/// each recv'd chunk to `process_chunk`, drain `pop_tx` again (the
/// client's second flight / alerts), and once `is_established()`
/// exchange application data via `seal_app_data` / `pop_plaintext`.
pub struct TlsClient {
    // State
    pub(crate) state: State,
    /// Set on fatal errors (also returned from `process_chunk`);
    /// readable post-mortem via [`Self::error`].
    pub(crate) error: Option<ClientHandshakeError>,

    // Lazy straddle buffer for a partial record carried across chunk
    // boundaries — same shape as the server's.
    pub(crate) rx_partial: Option<Box<[u8]>>,
    pub(crate) rx_partial_len: u16,

    // Raw TLS bytes waiting to be sent to the peer.
    pub(crate) tx_buf: [u8; TX_BUF_LEN],
    pub(crate) tx_len: usize,
    pub(crate) tx_pos: usize,

    // Decrypted application data records waiting for the app — the
    // same `OwnedIOBuf` fan-out as the server (see server.rs for the
    // share/narrow rationale).
    pub(crate) pending_plaintext: VecDeque<OwnedIOBuf>,
    pub(crate) app_data_ranges: Vec<(u32, u32)>,

    // Handshake-message reassembly: decrypted HANDSHAKE record bodies
    // append here; complete messages (4-byte header + uint24 body)
    // drain off the front. This is what lets one record carry many
    // messages (RFC-compliant servers coalesce EE..Finished) AND one
    // message straddle records (large Certificate chains) — the
    // record walker stays oblivious. Bounded by `MAX_HS_BUF`.
    pub(crate) hs_buf: Vec<u8>,

    // Key schedule + transcript
    pub(crate) transcript: Transcript,
    pub(crate) schedule: KeySchedule,
    pub(crate) ephemeral: Option<X25519ServerKey>,

    // Seed-derived ClientHello fields. `random` is consumed at
    // construction; `session_id` is re-checked against the
    // ServerHello echo (RFC 8446 §4.1.3).
    pub(crate) random: [u8; 32],
    pub(crate) session_id: [u8; 32],

    // Traffic keys at each stage.
    pub(crate) client_hs_tk: Option<TrafficKey>,
    pub(crate) server_hs_tk: Option<TrafficKey>,
    pub(crate) client_ap_tk: Option<TrafficKey>,
    pub(crate) server_ap_tk: Option<TrafficKey>,

    // Handshake traffic secrets — needed to derive the two Finished
    // keys (server's to verify, ours to send).
    pub(crate) client_hs_secret: Option<[u8; HASH_LEN]>,
    pub(crate) server_hs_secret: Option<[u8; HASH_LEN]>,

    // The pinned leaf's P-256 key, parked between Certificate and
    // CertificateVerify. `None` under `InsecureSkipVerify`.
    pub(crate) server_verify_key: Option<VerifyingKey>,

    // ALPN protocol the server selected (validated against our
    // offer). Empty ⇒ none negotiated.
    pub(crate) negotiated_alpn: [u8; MAX_ALPN_NAME_LEN],
    pub(crate) negotiated_alpn_len: u8,

    // Post-handshake NewSessionTickets seen (counted + discarded —
    // resumption is a follow-up; see module docs).
    pub(crate) tickets_received: u32,
}

impl Drop for TlsClient {
    fn drop(&mut self) {
        // TrafficKey / KeySchedule wipe themselves; the raw
        // handshake-secret arrays are separately held — scrub them
        // here, same discipline as the server.
        if let Some(mut s) = self.server_hs_secret.take() {
            tls::secure_zero(&mut s);
        }
        if let Some(mut s) = self.client_hs_secret.take() {
            tls::secure_zero(&mut s);
        }
    }
}

impl TlsClient {
    /// Allocate a fresh boxed `TlsClient`, expand `seed` into the
    /// per-connection entropy (X25519 keypair, ClientHello random,
    /// legacy_session_id), and emit the ClientHello into the TX
    /// buffer. The caller drains `pop_tx` to put it on the wire.
    ///
    /// Entropy by value, like `TlsServer::new_box`: callers supply 32
    /// bytes (kernel: `kernel_bare::rng::fill_bytes()`); the expansion
    /// is deterministic, so a fixed seed reproduces the connection's
    /// client-side bytes exactly — the deterministic-simulation arc
    /// leans on this.
    ///
    /// Errors only on a malformed `config` (oversized SNI / ALPN
    /// names) — surfaced as `Internal`.
    pub fn new_box(
        seed: [u8; 32],
        config: &TlsClientConfig,
    ) -> Result<Box<Self>, ClientHandshakeError> {
        let mut b = Box::<Self>::new_uninit();
        // SAFETY: `b.as_mut_ptr()` points at uninitialised storage of
        // `size_of::<Self>()`; `init_in_place` writes every field,
        // after which `assume_init` is sound.
        let mut client = unsafe {
            Self::init_in_place(b.as_mut_ptr(), seed);
            b.assume_init()
        };
        client.send_client_hello(config)?;
        Ok(client)
    }

    /// Write a fully-initialised `TlsClient` into the given
    /// uninitialised pointer (same in-place discipline as the server:
    /// the 4 KB `tx_buf` never round-trips through a stack temporary).
    /// The ClientHello is NOT built here — `new_box` follows up with
    /// `send_client_hello` once the struct is live.
    ///
    /// # Safety
    ///
    /// `this` must point at writable, properly-aligned, uninitialised
    /// memory of exactly `size_of::<TlsClient>()`. On return, every
    /// field is initialised.
    pub unsafe fn init_in_place(this: *mut Self, seed: [u8; 32]) {
        // Expand the caller's seed into the three per-connection
        // values via HKDF-Expand-Label with distinct local labels
        // (domain separators for this derivation only — never on the
        // wire). The X25519 seed is secret; random and session_id are
        // public the moment the ClientHello ships.
        let mut x_seed = [0u8; 32];
        let mut random = [0u8; 32];
        let mut session_id = [0u8; 32];
        hkdf_expand_label(&seed, b"waitless cli x25519", &[], &mut x_seed);
        hkdf_expand_label(&seed, b"waitless cli random", &[], &mut random);
        hkdf_expand_label(&seed, b"waitless cli sid", &[], &mut session_id);

        unsafe {
            addr_of_mut!((*this).state).write(State::WaitServerHello);
            addr_of_mut!((*this).error).write(None);
            addr_of_mut!((*this).rx_partial).write(None);
            addr_of_mut!((*this).rx_partial_len).write(0);
            addr_of_mut!((*this).tx_len).write(0);
            addr_of_mut!((*this).tx_pos).write(0);

            // tx_buf: zero-fill in place on the heap.
            ptr::write_bytes(addr_of_mut!((*this).tx_buf) as *mut u8, 0, TX_BUF_LEN);

            addr_of_mut!((*this).pending_plaintext).write(VecDeque::new());
            addr_of_mut!((*this).app_data_ranges).write(Vec::new());
            addr_of_mut!((*this).hs_buf).write(Vec::new());

            addr_of_mut!((*this).transcript).write(Transcript::new());
            addr_of_mut!((*this).schedule).write(KeySchedule::new_without_psk());
            addr_of_mut!((*this).ephemeral).write(Some(X25519ServerKey::from_seed(x_seed)));
            addr_of_mut!((*this).random).write(random);
            addr_of_mut!((*this).session_id).write(session_id);
            addr_of_mut!((*this).client_hs_tk).write(None);
            addr_of_mut!((*this).server_hs_tk).write(None);
            addr_of_mut!((*this).client_ap_tk).write(None);
            addr_of_mut!((*this).server_ap_tk).write(None);
            addr_of_mut!((*this).client_hs_secret).write(None);
            addr_of_mut!((*this).server_hs_secret).write(None);
            addr_of_mut!((*this).server_verify_key).write(None);
            addr_of_mut!((*this).negotiated_alpn).write([0u8; MAX_ALPN_NAME_LEN]);
            addr_of_mut!((*this).negotiated_alpn_len).write(0);
            addr_of_mut!((*this).tickets_received).write(0);
        }
        // The X25519 seed has been folded into the keypair; wipe the
        // stack copy.
        tls::secure_zero(&mut x_seed);
    }

    /// Build the ClientHello (RFC 8446 §4.1.2), update the transcript,
    /// and emit it as a plaintext record into `tx_buf`.
    fn send_client_hello(
        &mut self,
        config: &TlsClientConfig,
    ) -> Result<(), ClientHandshakeError> {
        // Validate config bounds up front so the builder's `None` can
        // only mean an internal sizing bug.
        if config
            .server_name
            .is_some_and(|name| name.is_empty() || name.len() > 255)
        {
            return Err(ClientHandshakeError::Internal);
        }
        for name in config.alpn {
            if name.is_empty() || name.len() > MAX_ALPN_NAME_LEN {
                return Err(ClientHandshakeError::Internal);
            }
        }

        let public = self
            .ephemeral
            .as_ref()
            .ok_or(ClientHandshakeError::Internal)?
            .public_bytes();
        let params = ClientHelloParams {
            random: &self.random,
            legacy_session_id: &self.session_id,
            x25519_pub: &public,
            server_name: config.server_name,
            alpn: config.alpn,
            extras: &[],
        };
        // 1 KiB covers the base ~170 B + max SNI (264) + bounded ALPN.
        let mut ch_body = [0u8; 1024];
        let body_len =
            build_client_hello(&params, &mut ch_body).ok_or(ClientHandshakeError::Internal)?;
        let mut ch_msg = [0u8; 1056];
        let msg_len = encode_handshake(msg_type::CLIENT_HELLO, &ch_body[..body_len], &mut ch_msg)
            .ok_or(ClientHandshakeError::Internal)?;
        let rec_len = record::build_plaintext(
            content_type::HANDSHAKE,
            &ch_msg[..msg_len],
            &mut self.tx_buf[self.tx_len..],
        )?;
        self.tx_len += rec_len;
        self.transcript.update(&ch_msg[..msg_len]);
        Ok(())
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

    /// `true` once the handshake has completed and application data
    /// can flow.
    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    /// `true` when the connection has reached a terminal state.
    pub fn is_terminated(&self) -> bool {
        matches!(self.state, State::Closed | State::Failed)
    }

    /// The fatal error that moved the connection to `Failed`, if any.
    pub fn error(&self) -> Option<ClientHandshakeError> {
        self.error
    }

    /// The ALPN protocol the server selected (always one of the
    /// offered names — enforced during the handshake). `None` when no
    /// ALPN was negotiated.
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        if self.negotiated_alpn_len == 0 {
            None
        } else {
            Some(&self.negotiated_alpn[..self.negotiated_alpn_len as usize])
        }
    }

    /// Post-handshake NewSessionTickets received (counted + discarded
    /// in v1 — see module docs).
    pub fn tickets_received(&self) -> u32 {
        self.tickets_received
    }

    /// `true` when an undelivered decrypted plaintext record is queued.
    pub fn has_plaintext(&self) -> bool {
        !self.pending_plaintext.is_empty()
    }

    /// Pop the next decrypted plaintext record, widened to an `IOBuf`
    /// (zero copy — see the server's `pop_plaintext` for the sharing
    /// story).
    pub fn pop_plaintext(&mut self) -> Option<IOBuf> {
        self.pending_plaintext.pop_front().map(IOBuf::from)
    }

    /// Emit a TLS 1.3 `close_notify` alert (RFC 8446 §6.1) under the
    /// client application traffic key and move to `Closed`. Mirrors
    /// the server's `close_notify` exactly, including the silent
    /// degradation paths.
    pub fn close_notify(&mut self) -> Result<(), ClientHandshakeError> {
        if self.state != State::Established {
            self.state = State::Closed;
            return Ok(());
        }
        let tk = self
            .client_ap_tk
            .as_mut()
            .ok_or(ClientHandshakeError::Internal)?;
        let alert_body: [u8; 2] = [1, 0]; // warning(1), close_notify(0)
        let needed = record::HEADER_LEN + alert_body.len() + 1 + record::TAG_LEN;
        if TX_BUF_LEN - self.tx_len < needed {
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
        self.state = State::Closed;
        Ok(())
    }

    /// Read up to one record's worth of plaintext from `src_chain`,
    /// encrypt-while-copying directly into `dst`, and consume the
    /// bytes used. Returns the wire byte count. Mirror of the
    /// server's `seal_app_data`, sealing under the CLIENT application
    /// traffic key.
    pub fn seal_app_data(
        &mut self,
        src_chain: &mut iobuf::IOBufChain,
        dst: &mut [u8],
    ) -> Result<usize, ClientHandshakeError> {
        if self.state != State::Established {
            return Err(ClientHandshakeError::UnexpectedRecord);
        }
        let tk = self
            .client_ap_tk
            .as_mut()
            .ok_or(ClientHandshakeError::Internal)?;
        if tk.seal_exhausted() {
            return Err(ClientHandshakeError::KeyExhausted);
        }
        record::seal_chain(tk, content_type::APPLICATION_DATA, src_chain, dst)
            .map_err(|e| e.into())
    }

    /// Consume one inbound TCP chunk — the client-side mirror of the
    /// server's orchestrator: walk record headers (completing any
    /// straddler from the previous chunk), dispatch each complete
    /// record, then fan decrypted application-data plaintext out to
    /// `pending_plaintext` as refcount-shared views.
    ///
    /// `process_chunk` loops across state transitions within one
    /// chunk: a single chunk carrying the whole server flight
    /// `[SH, CCS, EE, Cert, CertVerify, Finished]` walks
    /// WaitServerHello → Established and leaves the client's second
    /// flight (CCS + Finished) in the TX buffer.
    ///
    /// On a fatal error the client emits a best-effort fatal alert
    /// into the TX buffer (drain it before closing the TCP
    /// connection) and parks in `State::Failed`.
    pub fn process_chunk(
        &mut self,
        chunk: IOBuf,
        config: &TlsClientConfig,
    ) -> Result<(), ClientHandshakeError> {
        let result = self.process_chunk_inner(chunk, config);
        if let Err(e) = result {
            if !matches!(self.state, State::Closed | State::Failed) {
                self.emit_fatal_alert(alert_description_for(&e));
            }
            self.error = Some(e);
            self.state = State::Failed;
        }
        result
    }

    fn process_chunk_inner(
        &mut self,
        mut chunk: IOBuf,
        config: &TlsClientConfig,
    ) -> Result<(), ClientHandshakeError> {
        // Scratch from any prior chunk must not leak in (its ranges
        // are relative to that chunk's window).
        self.app_data_ranges.clear();

        {
            // Mutable byte window for framing + in-place AEAD. The
            // caller hands us an Owned chunk (test pumps and the
            // future connector glue both construct owned IOBufs), so
            // `data_mut` is safe — same contract as the server's
            // post-pump_rx chunks.
            let cipher = chunk.data_mut().expect("RX chunk is Owned");

            // Phase 1: complete any partial record carried from the
            // previous chunk.
            let cursor = self.complete_partial(cipher, config)?;
            if self.rx_partial_len == 0 {
                // Phase 2: walk `cipher[cursor..]` record-by-record.
                let mut off = cursor;
                while off < cipher.len() {
                    if matches!(self.state, State::Closed | State::Failed) {
                        break;
                    }

                    let remaining = &cipher[off..];
                    if remaining.len() < record::HEADER_LEN {
                        self.save_to_partial(remaining)?;
                        break;
                    }
                    let len_field =
                        u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
                    let total = record::HEADER_LEN + len_field;
                    if total > MAX_RECORD_TOTAL {
                        return Err(RecordError::RecordTooLarge.into());
                    }
                    if remaining.len() < total {
                        self.save_to_partial(remaining)?;
                        break;
                    }
                    self.dispatch_record(&mut cipher[off..off + total], Some(off), config)?;
                    off += total;
                }
            } else {
                debug_assert_eq!(cursor, cipher.len());
            }
        }

        // Phase 3: hand decrypted application-data records out as
        // views into the (now-decrypted) chunk storage — identical to
        // the server's share/narrow fan-out.
        match self.app_data_ranges.len() {
            0 => {}
            1 => {
                let (off, len) = self.app_data_ranges[0];
                let mut owned = OwnedIOBuf::try_from(chunk)
                    .ok()
                    .expect("RX chunk is Owned");
                owned
                    .narrow(off as usize, len as usize)
                    .map_err(|_| ClientHandshakeError::Internal)?;
                if self.pending_plaintext.try_reserve(1).is_err() {
                    return Err(ClientHandshakeError::Internal);
                }
                self.pending_plaintext.push_back(owned);
                self.app_data_ranges.clear();
            }
            _ => {
                let shared = OwnedIOBuf::try_from(chunk)
                    .ok()
                    .expect("RX chunk is Owned")
                    .share();
                for i in 0..self.app_data_ranges.len() {
                    let (off, len) = self.app_data_ranges[i];
                    let mut view = shared
                        .clone_shared()
                        .expect("share()'d chunk is shareable");
                    view.narrow(off as usize, len as usize)
                        .map_err(|_| ClientHandshakeError::Internal)?;
                    if self.pending_plaintext.try_reserve(1).is_err() {
                        return Err(ClientHandshakeError::Internal);
                    }
                    self.pending_plaintext.push_back(view);
                }
                self.app_data_ranges.clear();
            }
        }
        Ok(())
    }

    /// Drain any prior-chunk straddler — byte-for-byte the server's
    /// `complete_partial` logic.
    fn complete_partial(
        &mut self,
        cipher: &mut [u8],
        config: &TlsClientConfig,
    ) -> Result<usize, ClientHandshakeError> {
        if self.rx_partial_len == 0 {
            return Ok(0);
        }
        let partial = self
            .rx_partial
            .as_mut()
            .expect("rx_partial_len > 0 implies allocated");
        let mut have = self.rx_partial_len as usize;
        let mut cursor = 0usize;

        if have < record::HEADER_LEN {
            let need = record::HEADER_LEN - have;
            let to_copy = need.min(cipher.len());
            partial[have..have + to_copy].copy_from_slice(&cipher[..to_copy]);
            have += to_copy;
            cursor += to_copy;
            self.rx_partial_len = have as u16;
            if have < record::HEADER_LEN {
                return Ok(cursor);
            }
        }

        let len_field = u16::from_be_bytes([partial[3], partial[4]]) as usize;
        let total = record::HEADER_LEN + len_field;
        if total > MAX_RECORD_TOTAL {
            return Err(RecordError::RecordTooLarge.into());
        }
        let need = total - have;
        let available = cipher.len() - cursor;
        let to_copy = need.min(available);
        partial[have..have + to_copy].copy_from_slice(&cipher[cursor..cursor + to_copy]);
        cursor += to_copy;
        have += to_copy;
        self.rx_partial_len = have as u16;

        if have < total {
            return Ok(cursor);
        }

        self.rx_partial_len = 0;
        let mut owned = self
            .rx_partial
            .take()
            .expect("present from invariant above");
        // `None`: the straddler's bytes live in the rx_partial box —
        // app-data plaintext copies out instead of sharing the chunk.
        let dispatch_result = self.dispatch_record(&mut owned[..total], None, config);
        self.rx_partial = Some(owned);
        dispatch_result?;
        Ok(cursor)
    }

    /// Lazily allocate `rx_partial` and stash a partial record —
    /// mirror of the server's `save_to_partial`.
    fn save_to_partial(&mut self, bytes: &[u8]) -> Result<(), ClientHandshakeError> {
        if bytes.len() > MAX_RECORD_TOTAL {
            return Err(RecordError::RecordTooLarge.into());
        }
        if self.rx_partial.is_none() {
            let mut v: Vec<u8> = Vec::new();
            if v.try_reserve_exact(MAX_RECORD_TOTAL).is_err() {
                return Err(ClientHandshakeError::Internal);
            }
            v.resize(MAX_RECORD_TOTAL, 0);
            self.rx_partial = Some(v.into_boxed_slice());
        }
        let buf = self.rx_partial.as_mut().expect("just-ensured Some");
        buf[..bytes.len()].copy_from_slice(bytes);
        self.rx_partial_len = bytes.len() as u16;
        Ok(())
    }

    /// Dispatch one complete record. The client routes on the record
    /// TYPE first (plaintext handshake / CCS / alert vs encrypted),
    /// then on state — handshake-message-level transitions happen in
    /// `drain_hs_messages`, which is what lets one record carry many
    /// messages.
    fn dispatch_record(
        &mut self,
        rec: &mut [u8],
        base_off: Option<usize>,
        config: &TlsClientConfig,
    ) -> Result<(), ClientHandshakeError> {
        debug_assert!(
            rec.len() >= record::HEADER_LEN,
            "orchestrator only dispatches framed records",
        );
        if matches!(self.state, State::Closed | State::Failed) {
            return Ok(());
        }
        match rec[0] {
            // Middlebox-compat ChangeCipherSpec: legal at any point
            // mid-handshake per RFC 8446 §D.4 — drop silently.
            content_type::CHANGE_CIPHER_SPEC => Ok(()),
            // Plaintext handshake record — only ServerHello arrives
            // this way; after the SH the server's flight is encrypted.
            content_type::HANDSHAKE => {
                if self.state != State::WaitServerHello {
                    return Err(ClientHandshakeError::UnexpectedRecord);
                }
                let (ct, body, _consumed) = record::parse_plaintext(rec)?;
                debug_assert_eq!(ct, content_type::HANDSHAKE);
                self.append_hs_and_drain(body, config)
            }
            // Plaintext alert (pre-encryption), e.g. handshake_failure
            // from a server that couldn't negotiate. Terminal.
            content_type::ALERT => {
                self.state = State::Closed;
                Ok(())
            }
            // Everything else must be an encrypted record (the record
            // layer enforces opaque_type == application_data).
            _ => self.do_encrypted_record(rec, base_off, config),
        }
    }

    /// Open one encrypted record under the state-appropriate server
    /// traffic key and route its inner content.
    fn do_encrypted_record(
        &mut self,
        rec: &mut [u8],
        base_off: Option<usize>,
        config: &TlsClientConfig,
    ) -> Result<(), ClientHandshakeError> {
        let established = self.state == State::Established;
        // Capture the record's base pointer before `record_open`
        // borrows it — used for the chunk-relative plaintext range.
        let rec_base = rec.as_ptr() as usize;
        let tk = if established {
            self.server_ap_tk.as_mut()
        } else {
            self.server_hs_tk.as_mut()
        }
        .ok_or(ClientHandshakeError::UnexpectedRecord)?;
        let (inner_type, pt, _consumed) = record_open(tk, rec)?;
        match inner_type {
            content_type::HANDSHAKE => {
                // Server-flight messages (pre-Established) or
                // post-handshake messages (NewSessionTicket /
                // KeyUpdate). Copy into the reassembly buffer; the
                // borrow of `rec` ends with `pt`.
                if self.hs_buf.len() + pt.len() > MAX_HS_BUF {
                    return Err(ClientHandshakeError::MessageTooLarge);
                }
                if self.hs_buf.try_reserve(pt.len()).is_err() {
                    return Err(ClientHandshakeError::Internal);
                }
                self.hs_buf.extend_from_slice(pt);
                let _ = pt;
                self.drain_hs_messages(config)
            }
            content_type::APPLICATION_DATA => {
                if !established {
                    return Err(ClientHandshakeError::UnexpectedRecord);
                }
                // Mirror of the server's `do_app_data`: empty records
                // (padding) drop silently; chunk-direct records fan
                // out as shared views, straddlers copy out.
                if pt.is_empty() {
                    return Ok(());
                }
                match base_off {
                    Some(off) => {
                        let pt_off = off + (pt.as_ptr() as usize - rec_base);
                        let pt_len = pt.len();
                        let _ = pt;
                        if self.app_data_ranges.try_reserve(1).is_err() {
                            return Err(ClientHandshakeError::Internal);
                        }
                        self.app_data_ranges.push((pt_off as u32, pt_len as u32));
                    }
                    None => {
                        let mut v: Vec<u8> = Vec::new();
                        if v.try_reserve_exact(pt.len()).is_err() {
                            return Err(ClientHandshakeError::Internal);
                        }
                        v.extend_from_slice(pt);
                        let _ = pt;
                        if self.pending_plaintext.try_reserve(1).is_err() {
                            return Err(ClientHandshakeError::Internal);
                        }
                        self.pending_plaintext.push_back(OwnedIOBuf::from(v));
                    }
                }
                Ok(())
            }
            content_type::ALERT => {
                // close_notify or fatal alert — terminal either way.
                let _ = pt;
                self.state = State::Closed;
                Ok(())
            }
            _ => Err(ClientHandshakeError::UnexpectedRecord),
        }
    }

    /// Append plaintext handshake bytes to the reassembly buffer and
    /// drain complete messages.
    fn append_hs_and_drain(
        &mut self,
        bytes: &[u8],
        config: &TlsClientConfig,
    ) -> Result<(), ClientHandshakeError> {
        if self.hs_buf.len() + bytes.len() > MAX_HS_BUF {
            return Err(ClientHandshakeError::MessageTooLarge);
        }
        if self.hs_buf.try_reserve(bytes.len()).is_err() {
            return Err(ClientHandshakeError::Internal);
        }
        self.hs_buf.extend_from_slice(bytes);
        self.drain_hs_messages(config)
    }

    /// Pop every complete handshake message off the front of `hs_buf`
    /// and dispatch it to the state-appropriate handler. This is the
    /// message-granular half of the "loop across transitions"
    /// discipline: record framing happens in the chunk walker,
    /// message framing here.
    fn drain_hs_messages(
        &mut self,
        config: &TlsClientConfig,
    ) -> Result<(), ClientHandshakeError> {
        // Take the buffer out so handlers can borrow `&mut self`
        // without aliasing the message bytes.
        let buf = core::mem::take(&mut self.hs_buf);
        let mut off = 0usize;
        let mut result = Ok(());
        while buf.len() - off >= 4 {
            let body_len = ((buf[off + 1] as usize) << 16)
                | ((buf[off + 2] as usize) << 8)
                | (buf[off + 3] as usize);
            let total = 4 + body_len;
            if total > MAX_HS_MSG {
                result = Err(ClientHandshakeError::MessageTooLarge);
                break;
            }
            if buf.len() - off < total {
                break; // incomplete — wait for the next record
            }
            let pre_state = self.state;
            if let Err(e) = self.handle_hs_message(&buf[off..off + total], config) {
                result = Err(e);
                break;
            }
            off += total;
            if matches!(self.state, State::Closed | State::Failed) {
                break;
            }
            // RFC 8446 §5.1: a key change (here: server Finished →
            // application keys) must align with a record boundary, so
            // nothing may trail the Finished message inside its
            // record / reassembly run.
            if pre_state != State::Established
                && self.state == State::Established
                && off < buf.len()
            {
                result = Err(ClientHandshakeError::UnexpectedMessage);
                break;
            }
        }
        if result.is_err() {
            // Connection is dead; drop any tail.
            self.hs_buf.clear();
            return result;
        }
        // Keep the unconsumed tail (a partial message straddling
        // records). `drain` shifts the remainder to the front.
        self.hs_buf = buf;
        if off > 0 {
            self.hs_buf.drain(..off);
        }
        result
    }

    /// Dispatch one complete handshake message (header + body) to the
    /// state handler.
    fn handle_hs_message(
        &mut self,
        msg: &[u8],
        config: &TlsClientConfig,
    ) -> Result<(), ClientHandshakeError> {
        let (hs_type, body) = parse_handshake(msg)?;
        match (self.state, hs_type) {
            (State::WaitServerHello, msg_type::SERVER_HELLO) => self.on_server_hello(msg, body),
            (State::WaitEncryptedExtensions, msg_type::ENCRYPTED_EXTENSIONS) => {
                self.on_encrypted_extensions(msg, body, config)
            }
            (State::WaitCertificate, msg_type::CERTIFICATE) => {
                self.on_certificate(msg, body, config)
            }
            (State::WaitCertificateVerify, msg_type::CERTIFICATE_VERIFY) => {
                self.on_certificate_verify(msg, body, config)
            }
            (State::WaitFinished, msg_type::FINISHED) => self.on_server_finished(msg, body),
            (State::Established, msg_type::NEW_SESSION_TICKET) => {
                // Counted + discarded — resumption is a follow-up.
                self.tickets_received = self.tickets_received.saturating_add(1);
                Ok(())
            }
            (State::Established, msg_type::KEY_UPDATE) => {
                // Neither role implements KeyUpdate (tls-backlog
                // TL-2); reject cleanly rather than silently desync
                // the record layer.
                Err(ClientHandshakeError::KeyUpdateUnsupported)
            }
            _ => Err(ClientHandshakeError::UnexpectedMessage),
        }
    }

    // ── Per-message handlers ────────────────────────────────────────

    /// WaitServerHello + SERVER_HELLO: validate, derive the handshake
    /// traffic keys, → WaitEncryptedExtensions.
    fn on_server_hello(
        &mut self,
        msg: &[u8],
        body: &[u8],
    ) -> Result<(), ClientHandshakeError> {
        let sh = parse_server_hello(body)?;
        if sh.is_hello_retry_request {
            return Err(ClientHandshakeError::HelloRetryRequest);
        }
        // We never offered a PSK; a server "accepting" one is broken
        // or hostile (RFC 8446 §4.1.3 — MUST abort).
        if sh.has_pre_shared_key {
            return Err(ClientHandshakeError::UnsupportedServer);
        }
        // RFC 8446 §4.1.3: the echo MUST equal what we sent.
        if sh.legacy_session_id_echo != &self.session_id[..] {
            return Err(ClientHandshakeError::UnsupportedServer);
        }
        let server_pub = sh
            .x25519_server_pub
            .ok_or(ClientHandshakeError::UnsupportedServer)?;

        self.transcript.update(msg);

        // ECDHE + key-schedule handshake stage. Same cascade as the
        // server (`schedule::enter_handshake`), with the client/server
        // traffic-key roles assigned from our side: client_hs seals
        // our Finished, server_hs opens the server flight.
        let ephemeral = self
            .ephemeral
            .take()
            .ok_or(ClientHandshakeError::Internal)?;
        let shared = ephemeral.shared_secret(&server_pub);
        let transcript_h1 = self.transcript.snapshot();
        let hs_secrets = self.schedule.enter_handshake(&shared, &transcript_h1);
        self.client_hs_secret = Some(hs_secrets.client_hs);
        self.server_hs_secret = Some(hs_secrets.server_hs);
        self.client_hs_tk = Some(TrafficKey::from_secret(&hs_secrets.client_hs));
        self.server_hs_tk = Some(TrafficKey::from_secret(&hs_secrets.server_hs));

        self.state = State::WaitEncryptedExtensions;
        Ok(())
    }

    /// WaitEncryptedExtensions + ENCRYPTED_EXTENSIONS: record the ALPN
    /// selection (validated against our offer), → WaitCertificate.
    fn on_encrypted_extensions(
        &mut self,
        msg: &[u8],
        body: &[u8],
        config: &TlsClientConfig,
    ) -> Result<(), ClientHandshakeError> {
        let ee = parse_encrypted_extensions(body)?;
        if let Some(selected) = ee.alpn_protocol {
            // RFC 7301 §3.2: the server MUST select from our offer; a
            // name we never offered is a fatal no_application_protocol
            // class failure.
            if selected.len() > MAX_ALPN_NAME_LEN || !config.alpn.contains(&selected) {
                return Err(ClientHandshakeError::UnsupportedServer);
            }
            self.negotiated_alpn[..selected.len()].copy_from_slice(selected);
            self.negotiated_alpn_len = selected.len() as u8;
        }
        self.transcript.update(msg);
        self.state = State::WaitCertificate;
        Ok(())
    }

    /// WaitCertificate + CERTIFICATE: authenticate the leaf per the
    /// configured mode, → WaitCertificateVerify.
    fn on_certificate(
        &mut self,
        msg: &[u8],
        body: &[u8],
        config: &TlsClientConfig,
    ) -> Result<(), ClientHandshakeError> {
        let leaf = parse_certificate_leaf(body)?;
        match &config.auth {
            ServerAuth::PinnedSpki(pin) => {
                let spki =
                    extract_spki_from_cert_der(leaf).ok_or(ClientHandshakeError::BadCertificate)?;
                let mut hasher = Sha256::new();
                hasher.update(spki);
                let digest: [u8; 32] = hasher.finalize().into();
                if !ct_eq_32(&digest, pin) {
                    return Err(ClientHandshakeError::PinMismatch);
                }
                // Pin matched — lift the pinned P-256 key out of the
                // SPKI for the CertificateVerify check.
                let point =
                    spki_p256_point(spki).ok_or(ClientHandshakeError::BadCertificate)?;
                let vk = VerifyingKey::from_sec1_bytes(point)
                    .map_err(|_| ClientHandshakeError::BadCertificate)?;
                self.server_verify_key = Some(vk);
            }
            ServerAuth::InsecureSkipVerify => {
                // Loudly skipped — see the variant docs.
            }
        }
        self.transcript.update(msg);
        self.state = State::WaitCertificateVerify;
        Ok(())
    }

    /// WaitCertificateVerify + CERTIFICATE_VERIFY: verify the server's
    /// signature over the transcript (RFC 8446 §4.4.3), → WaitFinished.
    fn on_certificate_verify(
        &mut self,
        msg: &[u8],
        body: &[u8],
        config: &TlsClientConfig,
    ) -> Result<(), ClientHandshakeError> {
        let (algorithm, signature_der) = parse_certificate_verify(body)?;
        match (&config.auth, self.server_verify_key.as_ref()) {
            (ServerAuth::InsecureSkipVerify, _) => {
                // Signature check skipped along with the pin.
            }
            (ServerAuth::PinnedSpki(_), Some(vk)) => {
                if algorithm != sig_scheme::ECDSA_SECP256R1_SHA256 {
                    return Err(ClientHandshakeError::BadCertificateVerify);
                }
                // Signed content: 64×0x20 || context string || 0x00 ||
                // Transcript-Hash(CH..Certificate). The transcript has
                // not yet absorbed this CertificateVerify, so a plain
                // snapshot is exactly the §4.4.3 input.
                let transcript_hash = self.transcript.snapshot();
                let mut content = [0u8; 130];
                sign_content_server_cert_verify(&transcript_hash, &mut content);
                let signature = EcdsaSignature::from_der(signature_der)
                    .map_err(|_| ClientHandshakeError::BadCertificateVerify)?;
                vk.verify(&content, &signature)
                    .map_err(|_| ClientHandshakeError::BadCertificateVerify)?;
            }
            (ServerAuth::PinnedSpki(_), None) => {
                // Certificate handler must have parked the key.
                return Err(ClientHandshakeError::Internal);
            }
        }
        self.transcript.update(msg);
        self.state = State::WaitFinished;
        Ok(())
    }

    /// WaitFinished + FINISHED: verify the server's verify_data
    /// (RFC 8446 §4.4.4), derive application keys, emit our CCS +
    /// Finished flight, → Established.
    fn on_server_finished(
        &mut self,
        msg: &[u8],
        body: &[u8],
    ) -> Result<(), ClientHandshakeError> {
        let server_verify = parse_finished(body)?;
        let server_hs_secret = self
            .server_hs_secret
            .as_ref()
            .ok_or(ClientHandshakeError::Internal)?;
        let server_finished_key = derive_finished_key(server_hs_secret);
        // Expected = HMAC(server_finished_key, Transcript-Hash(CH ..
        // CertificateVerify)) — the transcript has not yet absorbed
        // the Finished itself.
        let expected = hmac_sha256(&server_finished_key, &self.transcript.snapshot());
        if !ct_eq_32(server_verify, &expected) {
            return Err(ClientHandshakeError::BadServerFinished);
        }
        self.transcript.update(msg);

        // Application secrets derive from the transcript through the
        // server Finished — the same hash our own Finished HMACs over
        // (RFC 8446 §4.4.4: client verify_data covers CH..server Fin).
        let transcript_h2 = self.transcript.snapshot();
        let app_secrets = self.schedule.enter_application(&transcript_h2);
        self.server_ap_tk = Some(TrafficKey::from_secret(&app_secrets.server_ap));

        // ── Our second flight ───────────────────────────────────────
        // Middlebox-compat CCS immediately before our Finished
        // (RFC 8446 §D.4 — either position is legal; before the
        // second flight is what BoringSSL/rustls interop expects).
        // The server role skips CCS records while waiting for our
        // Finished, so this round-trips with our own server too.
        let ccs: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        if TX_BUF_LEN - self.tx_len < ccs.len() {
            return Err(ClientHandshakeError::TxBufTooSmall);
        }
        self.tx_buf[self.tx_len..self.tx_len + ccs.len()].copy_from_slice(&ccs);
        self.tx_len += ccs.len();

        // Client Finished: HMAC(client_finished_key, transcript
        // through server Finished), sealed under the client handshake
        // traffic key.
        let client_hs_secret = self
            .client_hs_secret
            .as_ref()
            .ok_or(ClientHandshakeError::Internal)?;
        let client_finished_key = derive_finished_key(client_hs_secret);
        let verify_data = hmac_sha256(&client_finished_key, &transcript_h2);
        let mut fin_body = [0u8; HASH_LEN];
        let fin_body_len =
            build_finished(&verify_data, &mut fin_body).ok_or(ClientHandshakeError::Internal)?;
        let mut fin_msg = [0u8; 48];
        let fin_msg_len =
            encode_handshake(msg_type::FINISHED, &fin_body[..fin_body_len], &mut fin_msg)
                .ok_or(ClientHandshakeError::Internal)?;
        {
            let tk = self
                .client_hs_tk
                .as_mut()
                .ok_or(ClientHandshakeError::Internal)?;
            let needed = record::HEADER_LEN + fin_msg_len + 1 + record::TAG_LEN;
            if TX_BUF_LEN - self.tx_len < needed {
                return Err(ClientHandshakeError::TxBufTooSmall);
            }
            let n = record_seal(
                tk,
                content_type::HANDSHAKE,
                &fin_msg[..fin_msg_len],
                &mut self.tx_buf[self.tx_len..],
            )?;
            self.tx_len += n;
        }
        // Transcript through client Finished — the resumption-secret
        // input, kept for parity even though v1 discards tickets.
        self.transcript.update(&fin_msg[..fin_msg_len]);

        self.client_ap_tk = Some(TrafficKey::from_secret(&app_secrets.client_ap));
        self.state = State::Established;
        Ok(())
    }

    /// Best-effort fatal alert into the TX buffer (RFC 8446 §6.2),
    /// under the newest send key we have — or as a plaintext alert
    /// record if the handshake keys don't exist yet. Failures here
    /// are swallowed: the connection is already dying and the TCP
    /// close carries the day.
    fn emit_fatal_alert(&mut self, description: u8) {
        let body: [u8; 2] = [2, description]; // fatal(2)
        let tk = if self.state == State::Established {
            self.client_ap_tk.as_mut()
        } else {
            self.client_hs_tk.as_mut()
        };
        match tk {
            Some(tk) => {
                let needed = record::HEADER_LEN + body.len() + 1 + record::TAG_LEN;
                if TX_BUF_LEN - self.tx_len >= needed
                    && !tk.seal_exhausted()
                    && let Ok(n) = record_seal(
                        tk,
                        content_type::ALERT,
                        &body,
                        &mut self.tx_buf[self.tx_len..],
                    )
                {
                    self.tx_len += n;
                }
            }
            None => {
                if TX_BUF_LEN - self.tx_len >= record::HEADER_LEN + body.len()
                    && let Ok(n) = record::build_plaintext(
                        content_type::ALERT,
                        &body,
                        &mut self.tx_buf[self.tx_len..],
                    )
                {
                    self.tx_len += n;
                }
            }
        }
    }
}

// ============================================================================
// SPKI pinning — minimal X.509 DER walk
// ============================================================================
//
// Just enough DER to locate the SubjectPublicKeyInfo inside a leaf
// certificate — length-checked TLV navigation over the fixed
// TBSCertificate field order (RFC 5280 §4.1):
//
//   Certificate ::= SEQUENCE {
//     tbsCertificate       SEQUENCE {
//       [0] version (optional)  ── skipped if present
//       serialNumber INTEGER    ── skipped
//       signature    SEQUENCE   ┐
//       issuer       SEQUENCE   │ four SEQUENCEs, skipped
//       validity     SEQUENCE   │
//       subject      SEQUENCE   ┘
//       subjectPublicKeyInfo SEQUENCE   ← extracted (full TLV)
//       ... }                   ── ignored
//     ... }                     ── ignored
//
// NOT a general X.509 parser: no names, no extensions, no chains, no
// time checks. The pin (SHA-256 over the full SPKI TLV — the RFC 7469
// definition) plus the CertificateVerify signature is the entire
// authentication story. Every read is bounds-checked; arbitrary input
// returns `None`, never panics (fuzz-smoke below).

/// Read one DER TLV at `pos`: returns `(tag, content_start,
/// content_len)`. Accepts short-form and 1–2 byte long-form lengths
/// (certificates are < 64 KiB); indefinite/longer forms return `None`.
fn der_tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    let tag = *buf.get(pos)?;
    let first_len_byte = *buf.get(pos.checked_add(1)?)?;
    let (len, content_start) = if first_len_byte < 0x80 {
        (first_len_byte as usize, pos.checked_add(2)?)
    } else if first_len_byte == 0x81 {
        (*buf.get(pos + 2)? as usize, pos.checked_add(3)?)
    } else if first_len_byte == 0x82 {
        let hi = *buf.get(pos + 2)? as usize;
        let lo = *buf.get(pos + 3)? as usize;
        ((hi << 8) | lo, pos.checked_add(4)?)
    } else {
        return None; // indefinite / >64 KiB — not a cert we accept
    };
    let end = content_start.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some((tag, content_start, len))
}

/// DER universal tags used by the walk.
const DER_SEQUENCE: u8 = 0x30;
const DER_INTEGER: u8 = 0x02;
const DER_BIT_STRING: u8 = 0x03;
const DER_CTX_0: u8 = 0xA0; // [0] EXPLICIT (the optional version)

/// Walk a DER certificate and return the full SubjectPublicKeyInfo
/// TLV (tag + length + value) as a sub-slice. `None` on any shape we
/// don't recognise.
pub fn extract_spki_from_cert_der(cert: &[u8]) -> Option<&[u8]> {
    // Certificate ::= SEQUENCE { tbsCertificate, .. }
    let (tag, cs, cl) = der_tlv(cert, 0)?;
    if tag != DER_SEQUENCE {
        return None;
    }
    let cert_body = &cert[cs..cs + cl];
    // tbsCertificate ::= SEQUENCE { .. }
    let (tag, ts, tl) = der_tlv(cert_body, 0)?;
    if tag != DER_SEQUENCE {
        return None;
    }
    let tbs = &cert_body[ts..ts + tl];

    let mut pos = 0usize;
    // Optional [0] EXPLICIT version.
    let (tag, s, l) = der_tlv(tbs, pos)?;
    if tag == DER_CTX_0 {
        pos = s + l;
    }
    // serialNumber INTEGER.
    let (tag, s, l) = der_tlv(tbs, pos)?;
    if tag != DER_INTEGER {
        return None;
    }
    pos = s + l;
    // signature, issuer, validity, subject — four SEQUENCEs.
    for _ in 0..4 {
        let (tag, s, l) = der_tlv(tbs, pos)?;
        if tag != DER_SEQUENCE {
            return None;
        }
        pos = s + l;
    }
    // subjectPublicKeyInfo — return the FULL TLV (the RFC 7469 pin
    // input is the complete DER encoding, header included).
    let (tag, s, l) = der_tlv(tbs, pos)?;
    if tag != DER_SEQUENCE {
        return None;
    }
    Some(&tbs[pos..s + l])
}

/// Lift the public-key point out of a SubjectPublicKeyInfo TLV:
/// `SEQUENCE { AlgorithmIdentifier, BIT STRING }` — the BIT STRING's
/// content (after the unused-bits byte, which must be 0) is the SEC1
/// point `p256::ecdsa::VerifyingKey::from_sec1_bytes` consumes.
/// `pub` because the QUIC client role (`//crates/proto/quic`'s
/// `tls.rs`) runs the same pin → verify-key lift over CRYPTO frames.
pub fn spki_p256_point(spki: &[u8]) -> Option<&[u8]> {
    let (tag, s, l) = der_tlv(spki, 0)?;
    if tag != DER_SEQUENCE {
        return None;
    }
    let body = &spki[s..s + l];
    let (tag, as_, al) = der_tlv(body, 0)?;
    if tag != DER_SEQUENCE {
        return None; // AlgorithmIdentifier
    }
    let (tag, bs, bl) = der_tlv(body, as_ + al)?;
    if tag != DER_BIT_STRING || bl < 2 {
        return None;
    }
    let bits = &body[bs..bs + bl];
    if bits[0] != 0 {
        return None; // unused-bits must be 0 for a key
    }
    Some(&bits[1..])
}

/// Compute the SPKI pin for a DER certificate: SHA-256 over the full
/// SubjectPublicKeyInfo TLV (the RFC 7469 definition). Deploys and
/// tests derive the pin for `ServerAuth::PinnedSpki` from the cert
/// they intend to trust (e.g. the dev cert) with this.
pub fn spki_pin_from_cert_der(cert_der: &[u8]) -> Option<[u8; 32]> {
    let spki = extract_spki_from_cert_der(cert_der)?;
    let mut hasher = Sha256::new();
    hasher.update(spki);
    Some(hasher.finalize().into())
}

// ============================================================================
// Tests — loopback against the real TlsServer + negative paths
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{AlpnProtocol, TlsServer, TlsServerConfig};
    use iobuf::IOBufChain;
    use p256::ecdsa::SigningKey;

    // The same dev cert the webserver (and the QUIC tests) use.
    const CERT: &[u8] = include_bytes!("../../../../apps/webserver/dev_certs/dev_cert.der");
    const KEY: &[u8] = include_bytes!("../../../../apps/webserver/dev_certs/dev_key.der");

    const ALPN_OFFER: &[&[u8]] = &[b"h2", b"http/1.1"];

    fn dev_server_config() -> TlsServerConfig {
        TlsServerConfig::from_chain(&[CERT], KEY).expect("dev cert load")
    }

    fn pinned_client_config() -> TlsClientConfig {
        TlsClientConfig {
            auth: ServerAuth::PinnedSpki(spki_pin_from_cert_der(CERT).expect("pin")),
            server_name: Some(b"localhost"),
            alpn: ALPN_OFFER,
        }
    }

    fn chunk_of(bytes: &[u8]) -> IOBuf {
        let mut b = IOBuf::new_with_reserved(0, bytes.len(), 0);
        b.append_slice(bytes).unwrap();
        b
    }

    fn drain_client_tx(c: &mut TlsClient) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = c.pop_tx(&mut buf);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    fn drain_server_tx(s: &mut TlsServer) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = s.pop_tx(&mut buf);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    /// Pump both endpoints until neither has bytes to send, failing
    /// the test on any error. THE loopback structure: each round
    /// drains the client's TX into the server's `process_chunk`, then
    /// the server's TX into the client's, until quiescent.
    fn pump_ok(
        client: &mut TlsClient,
        server: &mut TlsServer,
        ccfg: &TlsClientConfig,
        scfg: &TlsServerConfig,
    ) {
        loop {
            let c2s = drain_client_tx(client);
            if !c2s.is_empty() {
                server.process_chunk(chunk_of(&c2s), scfg).expect("server");
            }
            let s2c = drain_server_tx(server);
            if !s2c.is_empty() {
                client.process_chunk(chunk_of(&s2c), ccfg).expect("client");
            }
            if c2s.is_empty() && s2c.is_empty() {
                break;
            }
        }
    }

    /// Like `pump_ok` but returns the client's first error (the
    /// negative tests drive failures from the client side).
    fn pump_until_client_err(
        client: &mut TlsClient,
        server: &mut TlsServer,
        ccfg: &TlsClientConfig,
        scfg: &TlsServerConfig,
    ) -> ClientHandshakeError {
        loop {
            let c2s = drain_client_tx(client);
            if !c2s.is_empty() {
                // The server may legitimately error after the client
                // aborts (e.g. it can't parse our alert) — ignore.
                let _ = server.process_chunk(chunk_of(&c2s), scfg);
            }
            let s2c = drain_server_tx(server);
            if !s2c.is_empty()
                && let Err(e) = client.process_chunk(chunk_of(&s2c), ccfg)
            {
                return e;
            }
            if c2s.is_empty() && s2c.is_empty() {
                panic!("pump went quiescent without a client error");
            }
        }
    }

    /// Frame a raw TLS byte stream into record-sized lengths.
    fn record_lengths(stream: &[u8]) -> Vec<usize> {
        let mut lens = Vec::new();
        let mut off = 0usize;
        while off + record::HEADER_LEN <= stream.len() {
            let len =
                u16::from_be_bytes([stream[off + 3], stream[off + 4]]) as usize;
            lens.push(record::HEADER_LEN + len);
            off += record::HEADER_LEN + len;
        }
        assert_eq!(off, stream.len(), "stream must frame exactly");
        lens
    }

    /// Round-trip one application-data message through `seal_app_data`
    /// → `process_chunk` → `pop_plaintext` in the given direction.
    fn client_to_server_app_data(
        client: &mut TlsClient,
        server: &mut TlsServer,
        scfg: &TlsServerConfig,
        msg: &[u8],
    ) {
        let mut chain = IOBufChain::new();
        let mut b = IOBuf::new_with_reserved(0, msg.len(), 0);
        b.append_slice(msg).unwrap();
        chain.push_back(b);
        let mut dst = vec![0u8; record::HEADER_LEN + msg.len() + 1 + record::TAG_LEN];
        let n = client.seal_app_data(&mut chain, &mut dst).expect("seal");
        server
            .process_chunk(chunk_of(&dst[..n]), scfg)
            .expect("server opens");
        let pt = server.pop_plaintext().expect("plaintext queued");
        assert_eq!(pt.data(), msg, "byte-exact across the record layer");
    }

    fn server_to_client_app_data(
        server: &mut TlsServer,
        client: &mut TlsClient,
        ccfg: &TlsClientConfig,
        msg: &[u8],
    ) {
        let mut chain = IOBufChain::new();
        let mut b = IOBuf::new_with_reserved(0, msg.len(), 0);
        b.append_slice(msg).unwrap();
        chain.push_back(b);
        let mut dst = vec![0u8; record::HEADER_LEN + msg.len() + 1 + record::TAG_LEN];
        let n = server.seal_app_data(&mut chain, &mut dst).expect("seal");
        client
            .process_chunk(chunk_of(&dst[..n]), ccfg)
            .expect("client opens");
        let pt = client.pop_plaintext().expect("plaintext queued");
        assert_eq!(pt.data(), msg, "byte-exact across the record layer");
    }

    // ── (a) THE loopback ────────────────────────────────────────────

    /// TlsClient vs TlsServer, pure pump: full handshake, ALPN
    /// negotiated on both ends, bidirectional app data byte-exact,
    /// and the server's NewSessionTicket arrival doesn't break the
    /// client.
    #[test]
    fn loopback_handshake_app_data_and_ticket() {
        let scfg = dev_server_config();
        let ccfg = pinned_client_config();
        let mut client = TlsClient::new_box([0x11; 32], &ccfg).expect("client");
        let mut server = TlsServer::new_box([0x22; 32]);

        pump_ok(&mut client, &mut server, &ccfg, &scfg);

        assert!(client.is_established(), "client established");
        assert!(server.is_established(), "server established");
        // ALPN: we offered [h2, http/1.1]; the server prefers h2.
        assert_eq!(client.negotiated_alpn(), Some(&b"h2"[..]));
        assert_eq!(server.negotiated_alpn(), AlpnProtocol::H2);
        // The server issues exactly one ticket after our Finished —
        // the pump already delivered it; counted + discarded.
        assert_eq!(client.tickets_received(), 1);

        // Bidirectional application data.
        client_to_server_app_data(
            &mut client,
            &mut server,
            &scfg,
            b"GET /health HTTP/1.1\r\nHost: waitless\r\n\r\n",
        );
        server_to_client_app_data(
            &mut server,
            &mut client,
            &ccfg,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        );
        // Still healthy after the ticket + data exchange.
        assert!(client.is_established());
        assert!(!client.has_plaintext());
    }

    /// `InsecureSkipVerify` completes the handshake without a pin
    /// (Finished still verified — it keys off the handshake secret).
    #[test]
    fn insecure_skip_verify_handshakes() {
        let scfg = dev_server_config();
        let ccfg = TlsClientConfig {
            auth: ServerAuth::InsecureSkipVerify,
            server_name: None,
            alpn: &[],
        };
        let mut client = TlsClient::new_box([0x33; 32], &ccfg).expect("client");
        let mut server = TlsServer::new_box([0x44; 32]);
        pump_ok(&mut client, &mut server, &ccfg, &scfg);
        assert!(client.is_established());
        assert!(server.is_established());
        // No ALPN offered ⇒ none negotiated, server falls back.
        assert_eq!(client.negotiated_alpn(), None);
        assert_eq!(server.negotiated_alpn(), AlpnProtocol::None);
    }

    // ── (b) Wrong pin ───────────────────────────────────────────────

    #[test]
    fn wrong_pin_aborts_with_pin_error_and_alert() {
        let scfg = dev_server_config();
        let ccfg = TlsClientConfig {
            auth: ServerAuth::PinnedSpki([0u8; 32]), // not the dev cert's pin
            server_name: None,
            alpn: &[],
        };
        let mut client = TlsClient::new_box([0x55; 32], &ccfg).expect("client");
        let mut server = TlsServer::new_box([0x66; 32]);

        let ch = drain_client_tx(&mut client);
        server.process_chunk(chunk_of(&ch), &scfg).expect("server takes CH");
        let flight = drain_server_tx(&mut server);

        let err = client
            .process_chunk(chunk_of(&flight), &ccfg)
            .expect_err("pin must not match");
        assert_eq!(err, ClientHandshakeError::PinMismatch);
        assert!(client.is_terminated());
        assert_eq!(client.error(), Some(ClientHandshakeError::PinMismatch));

        // The client emitted a fatal alert: one encrypted record of
        // exactly 2 alert bytes (+ type byte + tag) under the client
        // handshake key.
        let alert = drain_client_tx(&mut client);
        assert_eq!(alert.len(), record::HEADER_LEN + 2 + 1 + record::TAG_LEN);
        assert_eq!(alert[0], content_type::APPLICATION_DATA, "encrypted record");
    }

    // ── (c) Tampered server Finished ────────────────────────────────

    #[test]
    fn tampered_server_finished_aborts() {
        let scfg = dev_server_config();
        let ccfg = pinned_client_config();
        let mut client = TlsClient::new_box([0x77; 32], &ccfg).expect("client");
        let mut server = TlsServer::new_box([0x88; 32]);

        let ch = drain_client_tx(&mut client);
        server.process_chunk(chunk_of(&ch), &scfg).expect("server takes CH");
        let flight = drain_server_tx(&mut server);

        // Server flight = [SH, CCS, EE, Cert, CertVerify, Finished];
        // the last record is the Finished. Feed everything up to it,
        // confirm the client is parked at WaitFinished, then deliver
        // a tampered Finished record.
        let lens = record_lengths(&flight);
        let fin_len = *lens.last().unwrap();
        let (head, fin) = flight.split_at(flight.len() - fin_len);
        client
            .process_chunk(chunk_of(head), &ccfg)
            .expect("flight minus Finished");
        assert_eq!(client.state, State::WaitFinished);

        let mut bad_fin = fin.to_vec();
        *bad_fin.last_mut().unwrap() ^= 0x01; // flip a tag bit
        let err = client
            .process_chunk(chunk_of(&bad_fin), &ccfg)
            .expect_err("tampered Finished must abort");
        assert_eq!(
            err,
            ClientHandshakeError::RecordError(RecordError::AeadOpenFailed)
        );
        assert!(client.is_terminated());
    }

    // ── (d) Tampered CertificateVerify signature ────────────────────

    /// The server presents the genuine dev cert (pin matches) but
    /// signs CertificateVerify with a DIFFERENT key — exactly the
    /// MITM-with-a-stolen-cert shape §4.4.3 verification exists to
    /// kill. Exercises the actual signature check (unlike a
    /// ciphertext flip, which the AEAD would catch first).
    #[test]
    fn certificate_verify_with_wrong_key_aborts() {
        let evil_scfg = TlsServerConfig {
            cert_chain: &[CERT],
            signing_key: SigningKey::from_slice(&[7u8; 32]).expect("scalar"),
        };
        let ccfg = pinned_client_config();
        let mut client = TlsClient::new_box([0x99; 32], &ccfg).expect("client");
        let mut server = TlsServer::new_box([0xaa; 32]);

        let err = pump_until_client_err(&mut client, &mut server, &ccfg, &evil_scfg);
        assert_eq!(err, ClientHandshakeError::BadCertificateVerify);
        assert!(client.is_terminated());
    }

    // ── (f) Malicious server flights — auth-guard regression ────────
    //
    // Both negative cases need the server to emit a flight the real
    // `TlsServer` never would (an off-list ALPN; a Certificate-less
    // flight). The real server is driven only far enough to derive the
    // shared handshake secret, then the offending encrypted record is
    // hand-sealed under a FRESH `server_hs_tk` (`from_secret` starts at
    // seq 0, matching the client's just-derived receive key) — the same
    // "seal under the server's own key directly" technique
    // `server_key_update_rejected_cleanly` uses.

    /// Drive the CH exchange, then feed the client ONLY the server's
    /// ServerHello so it derives `server_hs_tk` (at seq 0) and parks at
    /// `WaitEncryptedExtensions`. Returns the live client, the real
    /// encrypted EncryptedExtensions record (sealed at server seq 0, so
    /// the client opens it at its own seq 0), and a fresh server
    /// handshake key at seq 0 for sealing forged messages.
    fn client_at_wait_encrypted_extensions(
        client: &mut TlsClient,
        ccfg: &TlsClientConfig,
    ) -> (Vec<u8>, TrafficKey) {
        let scfg = dev_server_config();
        let mut server = TlsServer::new_box([0x5e; 32]);
        let ch = drain_client_tx(client);
        server.process_chunk(chunk_of(&ch), &scfg).expect("server takes CH");
        let flight = drain_server_tx(&mut server);

        // Flight = [SH(plaintext 0x16), CCS(0x14), EE, Cert, CV, Fin].
        // The first record is the ServerHello; the first ENCRYPTED
        // record (0x17) is the EncryptedExtensions.
        let lens = record_lengths(&flight);
        let mut off = 0usize;
        let mut sh: Option<&[u8]> = None;
        let mut ee: Option<&[u8]> = None;
        for len in lens {
            let rec = &flight[off..off + len];
            if rec[0] == content_type::HANDSHAKE && sh.is_none() {
                sh = Some(rec); // plaintext ServerHello
            } else if rec[0] == content_type::APPLICATION_DATA && ee.is_none() {
                ee = Some(rec); // first encrypted record = EE
            }
            off += len;
        }
        let sh = sh.expect("flight carries a plaintext ServerHello");
        let ee = ee.expect("flight carries an encrypted EncryptedExtensions").to_vec();

        // Feed the SH alone: the client derives the handshake keys and
        // advances to WaitEncryptedExtensions.
        client.process_chunk(chunk_of(sh), ccfg).expect("client takes ServerHello");
        assert_eq!(client.state, State::WaitEncryptedExtensions);

        // A fresh receive-side server handshake key at seq 0 — identical
        // to the one the client just derived, so records sealed with it
        // open cleanly.
        let secret = server.server_hs_secret.expect("server derived its hs secret");
        (ee, TrafficKey::from_secret(&secret))
    }

    /// Seal one handshake message into an encrypted record under `tk`,
    /// returning the wire bytes. Advances `tk.seq`.
    fn seal_hs_record(tk: &mut TrafficKey, msg: &[u8]) -> Vec<u8> {
        let mut rec = vec![0u8; record::HEADER_LEN + msg.len() + 1 + record::TAG_LEN];
        let n = record::seal(tk, content_type::HANDSHAKE, msg, &mut rec).expect("seal");
        rec.truncate(n);
        rec
    }

    /// (a) A server that selects an ALPN protocol the client never
    /// offered MUST abort (RFC 7301 §3.2 — the selection must come from
    /// the client's list). The client offers only "h2"; the forged
    /// EncryptedExtensions names "h3". Pins the `config.alpn.contains`
    /// check in `on_encrypted_extensions` (~client.rs:1085); without it
    /// the off-list "h3" would be silently accepted as the negotiated
    /// protocol and the handshake would proceed.
    #[test]
    fn server_selecting_unoffered_alpn_aborts() {
        use crate::handshake::{build_encrypted_extensions, ext_type};
        const OFFER: &[&[u8]] = &[b"h2"]; // the client offers ONLY h2
        let ccfg = TlsClientConfig {
            auth: ServerAuth::PinnedSpki(spki_pin_from_cert_der(CERT).expect("pin")),
            server_name: Some(b"localhost"),
            alpn: OFFER,
        };
        let mut client = TlsClient::new_box([0x5a; 32], &ccfg).expect("client");
        let (_ee, mut hs_tk) = client_at_wait_encrypted_extensions(&mut client, &ccfg);

        // Forge an EncryptedExtensions naming "h3" (never offered).
        // ALPN extension data: u16 list_len || u8 name_len || name.
        let alpn_body: &[u8] = &[0, 3, 2, b'h', b'3'];
        let mut ee_body = [0u8; 64];
        let ee_len = build_encrypted_extensions(
            &[(ext_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, alpn_body)],
            &mut ee_body,
        )
        .expect("EE body");
        let mut ee_msg = [0u8; 80];
        let ee_msg_len = encode_handshake(
            msg_type::ENCRYPTED_EXTENSIONS,
            &ee_body[..ee_len],
            &mut ee_msg,
        )
        .expect("EE msg");
        let rec = seal_hs_record(&mut hs_tk, &ee_msg[..ee_msg_len]);

        let err = client
            .process_chunk(chunk_of(&rec), &ccfg)
            .expect_err("an off-list ALPN selection must abort");
        assert_eq!(err, ClientHandshakeError::UnsupportedServer);
        assert!(client.is_terminated(), "the client is in a terminal state");
        assert!(!client.is_established(), "it never reaches Established");
        assert_eq!(client.error(), Some(ClientHandshakeError::UnsupportedServer));
    }

    /// (b) A server flight that OMITS Certificate + CertificateVerify
    /// (jumps EncryptedExtensions → Finished) under `PinnedSpki` MUST
    /// abort: the Finished arrives while the client is at
    /// `WaitCertificate`, so it falls through to the `UnexpectedMessage`
    /// arm (~client.rs:1020). Pins the strict state-ordered dispatch in
    /// `handle_hs_message`; without it a pinned client could be talked
    /// past authentication — established with NO certificate ever
    /// verified.
    #[test]
    fn server_omitting_certificate_aborts() {
        use crate::handshake::build_finished;
        let ccfg = pinned_client_config();
        let mut client = TlsClient::new_box([0x5b; 32], &ccfg).expect("client");
        let (ee, mut hs_tk) = client_at_wait_encrypted_extensions(&mut client, &ccfg);

        // Deliver the genuine EncryptedExtensions (opens at the client's
        // seq 0) → WaitCertificate. Advance our forging key past the seq
        // the EE consumed so the next record we seal lines up at the
        // client's seq 1.
        client.process_chunk(chunk_of(&ee), &ccfg).expect("client takes EE");
        assert_eq!(client.state, State::WaitCertificate);
        let _ = seal_hs_record(&mut hs_tk, &[]); // burn seq 0 (EE's slot)

        // Now jump straight to Finished — no Certificate, no
        // CertificateVerify. The body is arbitrary: the client rejects
        // on the (state, type) mismatch before ever checking verify_data.
        let mut fin_body = [0u8; HASH_LEN];
        let fin_body_len = build_finished(&[0u8; HASH_LEN], &mut fin_body).expect("finished body");
        let mut fin_msg = [0u8; 48];
        let fin_msg_len =
            encode_handshake(msg_type::FINISHED, &fin_body[..fin_body_len], &mut fin_msg)
                .expect("finished msg");
        let rec = seal_hs_record(&mut hs_tk, &fin_msg[..fin_msg_len]);

        let err = client
            .process_chunk(chunk_of(&rec), &ccfg)
            .expect_err("a Certificate-less flight must abort");
        assert_eq!(err, ClientHandshakeError::UnexpectedMessage);
        assert!(client.is_terminated(), "the client is in a terminal state");
        assert!(!client.is_established(), "it never reaches Established");
        assert_eq!(client.error(), Some(ClientHandshakeError::UnexpectedMessage));
    }

    // ── (e) HelloRetryRequest ───────────────────────────────────────

    #[test]
    fn hello_retry_request_fails_with_distinct_error() {
        let ccfg = pinned_client_config();
        let mut client = TlsClient::new_box([0xbb; 32], &ccfg).expect("client");
        let _ = drain_client_tx(&mut client); // CH onto the floor

        // Hand-craft an HRR-shaped ServerHello record. The builder
        // happily writes the sentinel random; the client must flag it
        // before looking at anything else.
        let mut sh_body = [0u8; 256];
        let n = crate::handshake::build_server_hello(
            &crate::handshake::HELLO_RETRY_REQUEST_RANDOM,
            &[],
            &[0u8; 32],
            None,
            &mut sh_body,
        )
        .unwrap();
        let mut sh_msg = [0u8; 280];
        let m = encode_handshake(msg_type::SERVER_HELLO, &sh_body[..n], &mut sh_msg).unwrap();
        let mut rec = [0u8; 300];
        let r = record::build_plaintext(content_type::HANDSHAKE, &sh_msg[..m], &mut rec).unwrap();

        let err = client
            .process_chunk(chunk_of(&rec[..r]), &ccfg)
            .expect_err("HRR is a clean, distinct failure");
        assert_eq!(err, ClientHandshakeError::HelloRetryRequest);
        assert!(client.is_terminated());
    }

    // ── (g) SPKI pin helper ─────────────────────────────────────────

    #[test]
    fn spki_pin_is_stable_and_meaningful() {
        let p1 = spki_pin_from_cert_der(CERT).expect("dev cert has an SPKI");
        let p2 = spki_pin_from_cert_der(CERT).expect("deterministic");
        assert_eq!(p1, p2, "pin is stable");
        assert_ne!(p1, [0u8; 32], "pin is a real digest");
        // The walk yields a P-256 SPKI whose key parses.
        let spki = extract_spki_from_cert_der(CERT).unwrap();
        let point = spki_p256_point(spki).expect("BIT STRING point");
        assert!(VerifyingKey::from_sec1_bytes(point).is_ok(), "P-256 key");
    }

    /// The DER walk consumes attacker-supplied bytes (the Certificate
    /// message) — same fuzz-smoke discipline as the parsers: random
    /// buffers, truncations, and single-byte mutations of the real
    /// cert must return, never panic.
    #[test]
    fn spki_walk_fuzz_smoke_never_panics() {
        let mut seed: u64 = 0xA076_1D64_78BD_642F;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..10_000 {
            let len = (rnd() % 700) as usize;
            let buf: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
            let _ = spki_pin_from_cert_der(&buf);
        }
        for end in 0..CERT.len() {
            let _ = spki_pin_from_cert_der(&CERT[..end]);
        }
        for pos in 0..CERT.len() {
            for _ in 0..8 {
                let mut m = CERT.to_vec();
                m[pos] = rnd() as u8;
                let _ = spki_pin_from_cert_der(&m);
            }
        }
    }

    // ── (h) Chunk-boundary torture ──────────────────────────────────

    /// Feed every server→client byte ONE AT A TIME: the straddle
    /// buffer reassembles records, the hs_buf reassembles messages,
    /// and the handshake still lands — the streaming/loop-across-
    /// transitions discipline, distilled.
    #[test]
    fn one_byte_chunk_torture() {
        let scfg = dev_server_config();
        let ccfg = pinned_client_config();
        let mut client = TlsClient::new_box([0xcc; 32], &ccfg).expect("client");
        let mut server = TlsServer::new_box([0xdd; 32]);

        loop {
            let c2s = drain_client_tx(&mut client);
            if !c2s.is_empty() {
                server.process_chunk(chunk_of(&c2s), &scfg).expect("server");
            }
            let s2c = drain_server_tx(&mut server);
            for &byte in &s2c {
                client
                    .process_chunk(chunk_of(&[byte]), &ccfg)
                    .expect("client, 1-byte chunk");
            }
            if c2s.is_empty() && s2c.is_empty() {
                break;
            }
        }
        assert!(client.is_established());
        assert!(server.is_established());
        assert_eq!(client.tickets_received(), 1);

        // App data server→client, also 1 byte at a time (exercises
        // the rx_partial → copied-plaintext path).
        let msg = b"streamed one byte at a time";
        let mut chain = IOBufChain::new();
        let mut b = IOBuf::new_with_reserved(0, msg.len(), 0);
        b.append_slice(msg).unwrap();
        chain.push_back(b);
        let mut dst = vec![0u8; record::HEADER_LEN + msg.len() + 1 + record::TAG_LEN];
        let n = server.seal_app_data(&mut chain, &mut dst).expect("seal");
        for &byte in &dst[..n] {
            client
                .process_chunk(chunk_of(&[byte]), &ccfg)
                .expect("client, 1-byte app data");
        }
        let pt = client.pop_plaintext().expect("plaintext");
        assert_eq!(pt.data(), msg);
    }

    // ── Post-handshake guards ───────────────────────────────────────

    /// A server-initiated KeyUpdate is rejected cleanly (documented
    /// non-goal — our server never sends one; this hand-crafts the
    /// record under the server's own application key).
    #[test]
    fn server_key_update_rejected_cleanly() {
        let scfg = dev_server_config();
        let ccfg = pinned_client_config();
        let mut client = TlsClient::new_box([0xee; 32], &ccfg).expect("client");
        let mut server = TlsServer::new_box([0xff; 32]);
        pump_ok(&mut client, &mut server, &ccfg, &scfg);
        assert!(client.is_established());

        // Forge a KeyUpdate(update_not_requested) from the server by
        // sealing under its application traffic key directly.
        let ku_msg = [msg_type::KEY_UPDATE, 0, 0, 1, 0];
        let tk = server.server_ap_tk.as_mut().expect("server ap key");
        let mut rec = [0u8; 64];
        let n = record::seal(tk, content_type::HANDSHAKE, &ku_msg, &mut rec).unwrap();

        let err = client
            .process_chunk(chunk_of(&rec[..n]), &ccfg)
            .expect_err("KeyUpdate is unsupported");
        assert_eq!(err, ClientHandshakeError::KeyUpdateUnsupported);
        assert!(client.is_terminated());
    }

    /// The client's `close_notify` round-trips into the server's
    /// Closed state (the alert seals under the client app key).
    #[test]
    fn client_close_notify_reaches_server() {
        let scfg = dev_server_config();
        let ccfg = pinned_client_config();
        let mut client = TlsClient::new_box([0x12; 32], &ccfg).expect("client");
        let mut server = TlsServer::new_box([0x34; 32]);
        pump_ok(&mut client, &mut server, &ccfg, &scfg);

        client.close_notify().expect("close_notify");
        assert!(client.is_terminated());
        let bytes = drain_client_tx(&mut client);
        assert!(!bytes.is_empty());
        server
            .process_chunk(chunk_of(&bytes), &scfg)
            .expect("server takes the alert");
        assert!(server.is_terminated());
    }
}
