// uni-quic/src/conn.rs — QUIC server-side connection state
// machine (RFC 9000 + RFC 9001).
//
// One `Connection` per client. Holds: per-direction packet
// protection keys (Initial / Handshake / 1-RTT), per-PN-space
// packet number state, ACK tracking, the TLS handshake driver
// (`QuicTls`), and outbound packet assembly buffers.
//
// Sans-io: caller (the UDP reactor in `uni-quic-server`) feeds
// inbound datagrams via `process_datagram`, drains outbound
// packets via `pop_packet`. No allocation on the steady-state
// hot path; the only `Vec` growth is the per-level CRYPTO byte
// queue inside `QuicTls`.
//
// Per the architectural decisions (per-core conn pool, no
// cross-core access, one async task per conn): no Arc, no
// Mutex. The connection is owned by a single task on a single
// core and the task `.await`s on UDP recv → `process_datagram`
// → outbound flush → repeat.
//
// Scope (this commit — server-side handshake MVP):
//   * Initial-packet decode + reply (ServerHello in Initial,
//     EE/Cert/CV/Finished in Handshake)
//   * Handshake-packet decode + reply (ACKs)
//   * Client Finished verification → Established
//   * HANDSHAKE_DONE emission in 1-RTT
//   * Single-range ACK frame per outbound packet
//   * Coalesced packets (Initial+Handshake in one datagram —
//     standard rustls / quinn client behavior)
//
// Out of scope (future commits):
//   * Loss detection / retransmission timers (relies on client
//     retransmits today; OK for first interop check)
//   * Stream layer (STREAM frames, app data)
//   * 0-RTT / early data
//   * Connection migration / path validation
//   * Stateless reset
//   * Connection close protocol (we drop on error rather than
//     emit CONNECTION_CLOSE for now)

#![allow(dead_code)]

use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::{
    aes128_gcm_open, aes128_gcm_seal, apply_hp_mask, chacha20_poly1305_open,
    chacha20_poly1305_seal, derive_chacha_keys, derive_initial_keys, derive_initial_secrets,
    hp_mask_aes128, hp_mask_chacha20, next_traffic_secret, packet_nonce, AES_KEY_LEN,
    CHACHA_KEY_LEN, HP_MASK_LEN, HP_SAMPLE_LEN, NONCE_LEN, TAG_LEN,
};
use crate::frame::{parse_frame, write_ack, write_crypto, write_handshake_done, Frame};
use crate::wire::{
    decode_packet_number, long_packet_type, parse_initial_header, parse_long_header_preamble,
    read_varint, write_varint, FIXED_BIT, HEADER_FORM_LONG, QUIC_VERSION_1,
};

use crate::tls::{CryptoLevel, QuicTls, QuicTlsError, QuicTlsState};
use uni_tls::TlsServerConfig;

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnError {
    /// Malformed packet header / frame, oversize CID, etc.
    Wire,
    /// AEAD-tag mismatch — wrong keys or corruption.
    Decrypt,
    /// TLS handshake refused the inbound CRYPTO bytes.
    Tls,
    /// Caller-supplied output buffer too small.
    OutputTooSmall,
    /// State doesn't permit this operation (e.g. pop_packet
    /// before any inbound).
    BadState,
    /// Unsupported QUIC version (server should respond with
    /// Version Negotiation; out of scope for v1).
    UnsupportedVersion,
}

impl From<QuicTlsError> for ConnError {
    fn from(_: QuicTlsError) -> Self {
        ConnError::Tls
    }
}

// ============================================================================
// Connection ID
// ============================================================================

/// Re-export the canonical SERVER_CID_LEN from `inbox`. The two
/// modules need to agree on this; the source of truth lives next
/// to the slot-encoding helpers (make_local_cid / parse_local_cid).
pub use crate::inbox::SERVER_CID_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionId {
    bytes: [u8; 20],
    len: u8,
}

impl ConnectionId {
    pub fn new(bytes: &[u8]) -> Self {
        let mut buf = [0u8; 20];
        let n = bytes.len().min(20);
        buf[..n].copy_from_slice(&bytes[..n]);
        ConnectionId { bytes: buf, len: n as u8 }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }
}

// ============================================================================
// Per-direction packet protection keys
// ============================================================================

/// Variable-key-length AEAD/HP key material. AES-128-GCM uses
/// 16-byte AEAD + 16-byte HP keys; ChaCha20-Poly1305 uses 32-byte
/// for both. Stored as fixed 32-byte arrays with a length byte
/// so the connection can hold either without an enum-per-stage.
#[derive(Clone)]
struct DirKeys {
    aead: [u8; CHACHA_KEY_LEN],
    iv: [u8; NONCE_LEN],
    hp: [u8; CHACHA_KEY_LEN],
    aead_len: u8, // 16 or 32
    hp_len: u8,   // 16 or 32
    /// `true` for ChaCha20-Poly1305 + ChaCha20 HP, `false` for
    /// AES-128-GCM + AES-128-ECB HP (Initial uses AES, post-handshake
    /// uses whichever the TLS suite negotiated — we only support
    /// CHACHA20_POLY1305_SHA256, so post-Initial is always ChaCha20).
    is_chacha: bool,
}

impl DirKeys {
    fn from_initial(k: &crate::crypto::InitialKeys) -> Self {
        let mut aead = [0u8; CHACHA_KEY_LEN];
        let mut hp = [0u8; CHACHA_KEY_LEN];
        aead[..AES_KEY_LEN].copy_from_slice(&k.key);
        hp[..AES_KEY_LEN].copy_from_slice(&k.hp);
        DirKeys {
            aead,
            iv: k.iv,
            hp,
            aead_len: AES_KEY_LEN as u8,
            hp_len: AES_KEY_LEN as u8,
            is_chacha: false,
        }
    }

    fn from_chacha(k: &crate::crypto::ChaChaKeys) -> Self {
        DirKeys {
            aead: k.key,
            iv: k.iv,
            hp: k.hp,
            aead_len: CHACHA_KEY_LEN as u8,
            hp_len: CHACHA_KEY_LEN as u8,
            is_chacha: true,
        }
    }

    /// Build per-key-phase keys: AEAD `key`/`iv` from the freshly-
    /// derived `next_traffic_secret`, but reuse the existing HP key
    /// from `prev`. RFC 9001 §6.1: "the same header protection key
    /// is used" across key phases — only the AEAD half rotates.
    fn from_chacha_reuse_hp(k: &crate::crypto::ChaChaKeys, prev: &DirKeys) -> Self {
        DirKeys {
            aead: k.key,
            iv: k.iv,
            hp: prev.hp,
            aead_len: CHACHA_KEY_LEN as u8,
            hp_len: prev.hp_len,
            is_chacha: true,
        }
    }

    fn aead_seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
        if self.is_chacha {
            chacha20_poly1305_seal(&self.aead, nonce, aad, data)
        } else {
            let mut k16 = [0u8; AES_KEY_LEN];
            k16.copy_from_slice(&self.aead[..AES_KEY_LEN]);
            aes128_gcm_seal(&k16, nonce, aad, data)
        }
    }

    fn aead_open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), ()> {
        if self.is_chacha {
            chacha20_poly1305_open(&self.aead, nonce, aad, data, tag)
        } else {
            let mut k16 = [0u8; AES_KEY_LEN];
            k16.copy_from_slice(&self.aead[..AES_KEY_LEN]);
            aes128_gcm_open(&k16, nonce, aad, data, tag)
        }
    }

    fn hp_mask(&self, sample: &[u8; HP_SAMPLE_LEN]) -> [u8; HP_MASK_LEN] {
        if self.is_chacha {
            hp_mask_chacha20(&self.hp, sample)
        } else {
            let mut k16 = [0u8; AES_KEY_LEN];
            k16.copy_from_slice(&self.hp[..AES_KEY_LEN]);
            hp_mask_aes128(&k16, sample)
        }
    }
}

// ============================================================================
// Per-PN-space state
// ============================================================================

#[derive(Default)]
struct SpaceState {
    /// Next packet number we'll use for an outgoing packet.
    next_send_pn: u64,
    /// Largest PN we've successfully decoded inbound. `None` if
    /// nothing received yet.
    largest_recv_pn: Option<u64>,
    /// Whether we owe the peer an ACK that hasn't been bundled
    /// into an outbound packet yet.
    ack_pending: bool,
}

// ============================================================================
// Connection
// ============================================================================

/// QUIC v1 connection lifecycle (server side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// Created but no Initial received yet (transient — only
    /// observable to internal callers between `new` and the
    /// first `process_datagram`).
    PreHandshake,
    /// Handshake in progress (Initial / Handshake records flowing).
    Connecting,
    /// Handshake complete; server has emitted HANDSHAKE_DONE.
    Established,
    /// Fatal protocol error; future operations are no-ops.
    Failed,
}

pub struct Connection {
    state: ConnState,

    /// Our chosen connection ID. Sent as SCID on the server's
    /// Initial reply; clients use it as DCID on subsequent
    /// packets to us. Per-core conn pool indexes by this.
    local_cid: ConnectionId,

    /// Client's chosen connection ID. Sent as SCID on their
    /// Initial; we use as DCID on outgoing packets to them.
    peer_cid: ConnectionId,

    /// The DCID the client picked for its very first Initial.
    /// Only used to seed Initial-packet protection keys
    /// (RFC 9001 §5.2). Discarded once Initial keys are derived.
    initial_dcid: ConnectionId,

    initial_send: Option<DirKeys>,
    initial_recv: Option<DirKeys>,
    handshake_send: Option<DirKeys>,
    handshake_recv: Option<DirKeys>,
    application_send: Option<DirKeys>,
    application_recv: Option<DirKeys>,
    /// 0-RTT (early-data) packet-protection keys for *receiving*.
    /// `Some` only on a resumed handshake whose PSK validated;
    /// derived from `QuicTls::client_early_traffic_secret` once the
    /// CH has been parsed. The server never sends 0-RTT, so there's
    /// no `early_send` counterpart.
    early_recv: Option<DirKeys>,
    /// 0-RTT packets that arrived before we'd derived `early_recv`
    /// — typically because they were coalesced with (or arrived
    /// before) the LAST fragment of a multi-packet ClientHello.
    /// Drained and replayed by `advance_tls` the moment
    /// `early_recv` becomes available; cleared (without replay)
    /// once the handshake reaches Established without resumption,
    /// since at that point we'll never be able to decrypt them.
    /// Capped to avoid an unbounded memory footprint from a
    /// flood-attempting peer.
    pending_zero_rtt: Vec<Vec<u8>>,

    // ── 1-RTT key update state (RFC 9001 §6) ──────────────────────
    //
    // `application_recv` above holds the keys for the CURRENT recv
    // key phase (the bit value the peer used on packets we've
    // successfully opened). The next-phase recv keys are
    // pre-derived eagerly so that when the peer toggles its
    // KEY_PHASE bit we can trial-decrypt without HKDF on the hot
    // path — Chrome/Firefox routinely do a key update after some
    // traffic volume. The previous-phase keys are retained for one
    // rotation to absorb reordered packets that arrived after the
    // peer's KU but were sent before it.
    application_recv_prev: Option<DirKeys>,
    application_recv_next: Option<DirKeys>,
    /// Latest CLIENT application-traffic secret. Updated on each
    /// successful key update — `next_traffic_secret(client_ap)` is
    /// then ready to feed `derive_chacha_keys` for the
    /// post-rotation `application_recv_next`.
    client_app_secret: Option<[u8; 32]>,
    /// Peer's current KEY_PHASE bit value (0 or 1). Toggled when
    /// we successfully open a packet with `application_recv_next`.
    /// We never initiate KU ourselves on the send side; our own
    /// send packets stay at KP=0 for now.
    recv_key_phase: u8,

    initial_space: SpaceState,
    handshake_space: SpaceState,
    application_space: SpaceState,

    tls: QuicTls,

    /// Whether we've already emitted HANDSHAKE_DONE in 1-RTT.
    handshake_done_sent: bool,

    /// Next-byte offset into the OneRtt CRYPTO stream for outbound
    /// post-handshake messages. Bumped on every CRYPTO frame
    /// emitted at 1-RTT level (currently NewSessionTicket; future
    /// KeyUpdate / NEW_TOKEN). Per RFC 8446 §4.6 each post-
    /// handshake message follows the previous in the same stream,
    /// so the offset accumulates rather than resetting per-frame.
    one_rtt_crypto_offset: u64,

    /// Outbound packet queue: complete UDP datagrams (including
    /// any header-protected, AEAD-sealed packets) ready to ship.
    /// `pop_packet` drains the front entry.
    outbound: Vec<Vec<u8>>,

    /// Per-stream receive state, keyed by stream ID. Lazily
    /// inserted on the first STREAM frame.
    recv_streams: alloc::collections::BTreeMap<u64, crate::streams::RecvStream>,

    /// Per-stream send state, keyed by stream ID. Lazily inserted
    /// the first time the app calls `stream_send` for a stream.
    send_streams: alloc::collections::BTreeMap<u64, crate::streams::SendStream>,

    /// Stream IDs we've seen at least once, in arrival order. The
    /// app's `accept_stream` future drains the head; the listener
    /// is responsible for popping streams it's already accepted.
    opened_streams: Vec<u64>,
}

impl Connection {
    /// Create a fresh connection from the client's first Initial
    /// packet. Caller has already parsed enough of the long header
    /// to know it's an Initial (and to dispatch to "new connection"
    /// vs an existing one). We re-parse the full header here for
    /// simplicity; the cost is negligible.
    ///
    /// `local_cid` is the CID the server picked for itself — the
    /// connection pool's key. `seed` is 32 bytes of randomness
    /// for the X25519 ephemeral.
    ///
    /// Per RFC 9000 §7.2, the server's first Initial reply MUST
    /// echo the client-chosen DCID as its DCID (since we haven't
    /// yet told the client our SCID). After that exchange, both
    /// sides settle on the CIDs they advertised.
    pub fn new_server(local_cid: ConnectionId, seed: [u8; 32]) -> Self {
        Connection {
            state: ConnState::PreHandshake,
            local_cid,
            peer_cid: ConnectionId::new(&[]),
            initial_dcid: ConnectionId::new(&[]),
            initial_send: None,
            initial_recv: None,
            early_recv: None,
            pending_zero_rtt: Vec::new(),
            application_recv_prev: None,
            application_recv_next: None,
            client_app_secret: None,
            recv_key_phase: 0,
            handshake_send: None,
            handshake_recv: None,
            application_send: None,
            application_recv: None,
            initial_space: SpaceState::default(),
            handshake_space: SpaceState::default(),
            application_space: SpaceState::default(),
            tls: QuicTls::new(seed),
            handshake_done_sent: false,
            one_rtt_crypto_offset: 0,
            outbound: Vec::new(),
            recv_streams: alloc::collections::BTreeMap::new(),
            send_streams: alloc::collections::BTreeMap::new(),
            opened_streams: Vec::new(),
        }
    }

    pub fn state(&self) -> ConnState {
        self.state
    }

    pub fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    /// Process one inbound UDP datagram. Coalesced packets
    /// (Initial+Handshake or Initial+0-RTT in one datagram, both
    /// common with browsers) are walked left-to-right; each packet's
    /// protection is removed independently.
    ///
    /// `advance_tls` runs BETWEEN packets in the loop so that keys
    /// derived from earlier packets (e.g. 0-RTT recv keys derived
    /// when the Initial's ClientHello validates a PSK) are
    /// available to LATER packets in the same datagram. Without
    /// this, the 0-RTT packet that Chrome coalesces with its
    /// Initial would hit `process_zero_rtt` before the CH-driven
    /// `client_early_traffic_secret` is computed, and we'd drop
    /// it with `bad_state: no early_recv keys`. `advance_tls` is
    /// idempotent — `tls.advance` returns once no state change
    /// happens — so calling it per packet is cheap.
    pub fn process_datagram(
        &mut self,
        datagram: &[u8],
        config: &TlsServerConfig,
    ) -> Result<(), ConnError> {
        if matches!(self.state, ConnState::Failed) {
            return Ok(());
        }
        let mut p = 0usize;
        while p < datagram.len() {
            // Per-packet drop on AEAD failure (RFC 9000 §9.7:
            // endpoints MUST NOT abandon the connection on
            // packets they cannot decrypt). Most common causes:
            //   * client did a key update (KEY_PHASE bit flipped)
            //     and we don't track key phase yet — pending
            //     follow-up.
            //   * stale-keys retransmit straggler.
            //   * unrelated traffic addressed to our DCID.
            // For long-header packets we know the packet length
            // from the header so we can skip exactly that and
            // continue with the next coalesced packet. For
            // short-header (1-RTT) packets there's no length —
            // the packet IS the rest of the datagram — so on
            // decrypt failure we drop the whole remainder.
            match self.process_one_packet(&datagram[p..], config) {
                Ok(0) => break, // forward-progress guard
                Ok(consumed) => {
                    p += consumed;
                }
                Err(ConnError::Decrypt) => {
                    // Stop walking this datagram; conn stays
                    // alive for future packets. Counter was
                    // already bumped via `aead_decrypt_failed`
                    // inside `unprotect_and_decrypt`.
                    break;
                }
                Err(e) => return Err(e),
            }
            // Drive the TLS state machine to derive any new keys
            // before we attempt to decrypt the next coalesced
            // packet. Especially important for Initial → 0-RTT
            // ordering, where 0-RTT decrypt depends on the
            // early-data secret derived from the CH.
            self.advance_tls(config)?;
        }
        // Drive the TLS state machine + queue outbound after
        // consuming all packets in the datagram.
        self.advance_tls(config)?;
        self.flush_outbound(config)?;
        Ok(())
    }

    /// Drain one ready-to-send UDP datagram into `out`. Returns
    /// number of bytes written (0 if nothing pending).
    pub fn pop_packet(&mut self, out: &mut [u8]) -> usize {
        if self.outbound.is_empty() {
            return 0;
        }
        let pkt = self.outbound.remove(0);
        let n = out.len().min(pkt.len());
        out[..n].copy_from_slice(&pkt[..n]);
        n
    }

    /// Whether there's an outbound datagram queued. Cheap check
    /// for the reactor's wakeup path.
    pub fn has_outbound(&self) -> bool {
        !self.outbound.is_empty()
    }

    // ── Stream API ─────────────────────────────────────────────

    /// Pop the next stream the peer has opened. Returns `None`
    /// if no new streams are pending. Caller drives `stream_recv`
    /// against the returned ID to consume bytes.
    pub fn pop_accepted_stream(&mut self) -> Option<u64> {
        if self.opened_streams.is_empty() {
            None
        } else {
            Some(self.opened_streams.remove(0))
        }
    }

    /// Read up to `out.len()` bytes from the head of stream `sid`'s
    /// recv buffer. Returns `(bytes_copied, eof)`. `eof = true` once
    /// the peer has signaled FIN AND every byte up to it has been
    /// drained.
    pub fn stream_recv(&mut self, sid: u64, out: &mut [u8]) -> (usize, bool) {
        match self.recv_streams.get_mut(&sid) {
            Some(s) => s.drain(out),
            None => (0, false),
        }
    }

    /// Whether stream `sid` has any buffered bytes ready for the
    /// app to drain.
    pub fn stream_has_buffered(&self, sid: u64) -> bool {
        self.recv_streams
            .get(&sid)
            .map(|s| s.has_buffered())
            .unwrap_or(false)
    }

    /// Append `data` to stream `sid`'s outbound queue. Bytes go on
    /// the wire on the next outbound flush. Auto-creates the stream
    /// state lazily.
    pub fn stream_send(&mut self, sid: u64, data: &[u8]) {
        let s = self
            .send_streams
            .entry(sid)
            .or_insert_with(crate::streams::SendStream::default);
        s.write(data);
    }

    /// Mark stream `sid` for FIN. The next outbound STREAM frame
    /// after the buffer drains will carry the FIN flag.
    pub fn stream_close(&mut self, sid: u64) {
        let s = self
            .send_streams
            .entry(sid)
            .or_insert_with(crate::streams::SendStream::default);
        s.close();
    }

    /// Force a 1-RTT packet emission even if no inbound datagram
    /// just arrived — caller invokes this after writing data on a
    /// stream so the connection layer drains the send queue without
    /// waiting for the next inbound packet.
    pub fn flush(&mut self, config: &TlsServerConfig) -> Result<(), ConnError> {
        self.flush_outbound(config)
    }

    // ── Inbound packet processing ───────────────────────────────

    fn process_one_packet(
        &mut self,
        bytes: &[u8],
        _config: &TlsServerConfig,
    ) -> Result<usize, ConnError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let first = bytes[0];
        // QUIC v1 (RFC 9000 §17.3.1) requires bit 6 (FIXED_BIT) set
        // on every long- and short-header packet. A zero (or any
        // byte without FIXED_BIT) at this position is datagram-tail
        // padding — clients pad UDP datagrams to 1200 bytes after
        // the Initial packet's coalesced flight. Consume the rest
        // and stop.
        if first & FIXED_BIT == 0 {
            return Ok(bytes.len());
        }
        if first & HEADER_FORM_LONG != 0 {
            self.process_long_header_packet(bytes)
        } else {
            self.process_short_header_packet(bytes)
        }
    }

    fn process_long_header_packet(&mut self, bytes: &[u8]) -> Result<usize, ConnError> {
        let preamble = parse_long_header_preamble(bytes).map_err(|_| {
            crate::quic_drop!(long_header_parse,
                "size={} first={:#x}", bytes.len(), bytes.first().copied().unwrap_or(0));
            ConnError::Wire
        })?;
        match preamble.long_type {
            long_packet_type::INITIAL => self.process_initial(bytes),
            long_packet_type::HANDSHAKE => self.process_handshake_pkt(bytes),
            long_packet_type::ZERO_RTT => self.process_zero_rtt(bytes),
            long_packet_type::RETRY => {
                crate::quic_drop!(other_wire, "RETRY received as server (peer bug)");
                Err(ConnError::Wire)
            }
            _ => {
                crate::quic_drop!(other_wire, "bogus long_type={}", preamble.long_type);
                Err(ConnError::Wire)
            }
        }
    }

    /// 0-RTT (early-data) packet: long-header type=0x01, layout
    /// matches Handshake (no Token field), but encrypted under the
    /// `client_early_traffic_secret`-derived AEAD keys instead of
    /// the handshake-stage ones. Frames inside share the OneRtt
    /// stream namespace per RFC 9001 §5.5 — STREAM frames at
    /// 0-RTT and 1-RTT level are the same logical streams. We
    /// silently drop the packet if `early_recv` is None (no
    /// resumption negotiated), matching the spec's "0-RTT MAY be
    /// rejected; client treats it as transparent retransmission
    /// over 1-RTT" behaviour.
    fn process_zero_rtt(&mut self, bytes: &[u8]) -> Result<usize, ConnError> {
        let preamble = parse_long_header_preamble(bytes).map_err(|_| {
            crate::quic_drop!(long_header_parse, "0-RTT preamble: size={}", bytes.len());
            ConnError::Wire
        })?;
        let mut p = preamble.tail_offset;
        let (length, n) = read_varint(&bytes[p..]).map_err(|_| ConnError::Wire)?;
        p += n;
        let pn_offset = p;
        let total_packet_len = pn_offset + length as usize;
        if total_packet_len > bytes.len() {
            return Err(ConnError::Wire);
        }
        let recv_keys = match self.early_recv.as_ref() {
            Some(k) => k.clone(),
            None => {
                // Keys aren't ready yet. Buffer the FULL packet
                // (header included) so we can replay it once
                // `advance_tls` derives `early_recv`. This handles:
                //   * 0-RTT coalesced with a multi-packet CH whose
                //     last fragment hasn't arrived yet
                //   * 0-RTT in its own datagram that arrived before
                //     the CH-completing Initial
                // Cap the buffer so a malicious peer can't OOM us
                // by sending undecryptable 0-RTT in a loop. 16
                // packets × ~1500 bytes ≈ 24 KiB/conn worst case.
                const PENDING_ZERO_RTT_CAP: usize = 16;
                if self.pending_zero_rtt.len() < PENDING_ZERO_RTT_CAP {
                    self.pending_zero_rtt.push(bytes[..total_packet_len].to_vec());
                    crate::quic_event!(zero_rtt_buffered,
                        "size={} pending={} local_cid={}",
                        total_packet_len, self.pending_zero_rtt.len(),
                        crate::endpoint::hex8(self.local_cid.as_slice()));
                } else {
                    crate::quic_drop!(bad_state,
                        "0-RTT buffer full ({} packets), dropping new",
                        PENDING_ZERO_RTT_CAP);
                }
                return Ok(total_packet_len);
            }
        };

        let mut buf = bytes[..total_packet_len].to_vec();
        let pn = self.unprotect_and_decrypt(&mut buf, pn_offset, &recv_keys)?;
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        let payload_start = pn_offset + pn_length;
        let payload_end = total_packet_len - TAG_LEN;
        let payload = &buf[payload_start..payload_end];

        // RFC 9001 §5.5: 0-RTT and 1-RTT carry the SAME application
        // data namespace — STREAM frames at 0-RTT belong to the
        // OneRtt stream space. Dispatch under OneRtt so a STREAM
        // frame at 0-RTT followed by a STREAM frame at 1-RTT for
        // the same stream id flows naturally into one RecvStream.
        self.dispatch_frames(CryptoLevel::OneRtt, payload)?;

        // ACKs for 0-RTT live in the application_space PN ring
        // alongside 1-RTT ACKs (RFC 9000 §17.2.3).
        self.application_space.largest_recv_pn = Some(
            self.application_space
                .largest_recv_pn
                .map_or(pn, |x| x.max(pn)),
        );
        self.application_space.ack_pending = true;
        crate::quic_event!(zero_rtt_accepted,
            "pn={} payload_len={} local_cid={}",
            pn, payload_end - payload_start,
            crate::endpoint::hex8(self.local_cid.as_slice()));
        Ok(total_packet_len)
    }

    fn process_initial(&mut self, bytes: &[u8]) -> Result<usize, ConnError> {
        let header = parse_initial_header(bytes).map_err(|_| ConnError::Wire)?;
        // First-Initial path: derive Initial keys from the
        // client's chosen DCID and learn our peer_cid.
        if self.initial_recv.is_none() {
            let dcid = ConnectionId::new(header.preamble.dcid);
            let scid = ConnectionId::new(header.preamble.scid);
            self.initial_dcid = dcid;
            self.peer_cid = scid;
            let secrets = derive_initial_secrets(self.initial_dcid.as_slice());
            let server_keys = derive_initial_keys(&secrets.server);
            let client_keys = derive_initial_keys(&secrets.client);
            self.initial_send = Some(DirKeys::from_initial(&server_keys));
            self.initial_recv = Some(DirKeys::from_initial(&client_keys));
            self.state = ConnState::Connecting;

            // Build server transport parameters (RFC 9001 §8.2).
            // `original_destination_connection_id` = client's first
            // DCID; `initial_source_connection_id` = our chosen SCID.
            let server_params = {
                let p = crate::transport_params::ServerParams::defaults(
                    self.initial_dcid.as_slice(),
                    self.local_cid.as_slice(),
                );
                let mut blob = Vec::with_capacity(64);
                p.encode(&mut blob);
                blob
            };
            self.tls.set_server_transport_params(server_params);
        }

        let total_packet_len = header.pn_offset + header.length as usize;
        if total_packet_len > bytes.len() {
            return Err(ConnError::Wire);
        }
        let recv_keys = self
            .initial_recv
            .as_ref()
            .ok_or(ConnError::BadState)?
            .clone();

        let mut buf = bytes[..total_packet_len].to_vec();
        let pn = self.unprotect_and_decrypt(&mut buf, header.pn_offset, &recv_keys)?;

        // Frame parsing: payload = buf[pn_offset + pn_length .. end - TAG_LEN].
        // unprotect_and_decrypt set buf[pn_offset..pn_offset+pn_length]
        // to the unprotected PN. We need pn_length to find payload start.
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        let payload_start = header.pn_offset + pn_length;
        let payload_end = total_packet_len - TAG_LEN;
        let payload = &buf[payload_start..payload_end];
        self.dispatch_frames(CryptoLevel::Initial, payload)?;

        self.initial_space.largest_recv_pn = Some(
            self.initial_space.largest_recv_pn.map_or(pn, |x| x.max(pn)),
        );
        self.initial_space.ack_pending = true;
        Ok(total_packet_len)
    }

    fn process_handshake_pkt(&mut self, bytes: &[u8]) -> Result<usize, ConnError> {
        // Handshake packet shares the long-header preamble shape
        // with Initial but has no Token field — just Length.
        let preamble = parse_long_header_preamble(bytes).map_err(|_| ConnError::Wire)?;
        let mut p = preamble.tail_offset;
        let (length, n) = read_varint(&bytes[p..]).map_err(|_| ConnError::Wire)?;
        p += n;
        let pn_offset = p;
        let total_packet_len = pn_offset + length as usize;
        if total_packet_len > bytes.len() {
            return Err(ConnError::Wire);
        }

        let recv_keys = self
            .handshake_recv
            .as_ref()
            .ok_or(ConnError::BadState)?
            .clone();

        let mut buf = bytes[..total_packet_len].to_vec();
        let pn = self.unprotect_and_decrypt(&mut buf, pn_offset, &recv_keys)?;
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        let payload_start = pn_offset + pn_length;
        let payload_end = total_packet_len - TAG_LEN;
        let payload = &buf[payload_start..payload_end];
        self.dispatch_frames(CryptoLevel::Handshake, payload)?;

        self.handshake_space.largest_recv_pn = Some(
            self.handshake_space
                .largest_recv_pn
                .map_or(pn, |x| x.max(pn)),
        );
        self.handshake_space.ack_pending = true;
        Ok(total_packet_len)
    }

    fn process_short_header_packet(&mut self, bytes: &[u8]) -> Result<usize, ConnError> {
        // Short-header (1-RTT) layout:
        //   u8 first byte || N-byte DCID || PN bytes || ciphertext || tag.
        // DCID length is endpoint-known. For our server it's
        // always SERVER_CID_LEN — the connection pool routed this
        // datagram to us by matching that prefix.
        if bytes.len() < 1 + SERVER_CID_LEN + 4 + TAG_LEN {
            return Err(ConnError::Wire);
        }
        let pn_offset = 1 + SERVER_CID_LEN;

        // Short-header packets aren't length-prefixed inside the
        // datagram — every byte until the end is one packet for us
        // (no coalescing post-handshake in QUIC v1; receivers MUST
        // process the whole thing).
        let total_packet_len = bytes.len();

        // Key-update aware decryption (RFC 9001 §6).
        //
        // 1. HP unprotect with whichever set of keys; HP keys
        //    persist across phases so any of {prev, current, next}
        //    works — we use `application_recv` since it's always
        //    present once the handshake completes.
        // 2. After HP unprotect, the first byte's bit 2 (KEY_PHASE)
        //    tells us which AEAD keys protect this packet.
        // 3. If KP matches `recv_key_phase` → AEAD-open with
        //    `application_recv`. The common path.
        // 4. If KP differs → trial-decrypt with
        //    `application_recv_next`. On success, peer initiated
        //    a key update: rotate (prev <- current; current <- next;
        //    derive new next from updated client_app_secret) and
        //    flip `recv_key_phase`. This is the path that today
        //    fails silently — without it, every post-update
        //    packet AEAD-fails forever.
        // 5. If trial-decrypt with _next ALSO fails, the packet
        //    might be a reordered straggler from BEFORE the last
        //    update we already processed — try `application_recv_prev`
        //    (which holds the previous-phase keys for one rotation).
        //
        // The header-protection step only happens once; the AEAD
        // attempts share the unprotected first byte / PN bytes.
        let recv_keys_cur = self
            .application_recv
            .as_ref()
            .ok_or(ConnError::BadState)?
            .clone();
        let mut buf = bytes[..total_packet_len].to_vec();
        let pn = self.unprotect_header(&mut buf, pn_offset, &recv_keys_cur)?;
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        let payload_start = pn_offset + pn_length;
        let payload_end = total_packet_len - TAG_LEN;
        if payload_end < payload_start {
            return Err(ConnError::Wire);
        }
        let pkt_kp = (buf[0] & 0x04) >> 2;

        // Try the keys appropriate for this packet's KP.
        let aad: Vec<u8> = buf[..payload_start].to_vec();
        let nonce = packet_nonce(&recv_keys_cur.iv, pn);
        let tag: [u8; TAG_LEN] = buf[payload_end..]
            .try_into()
            .map_err(|_| ConnError::Wire)?;

        let aead_result = if pkt_kp == self.recv_key_phase {
            recv_keys_cur.aead_open(&nonce, &aad, &mut buf[payload_start..payload_end], &tag)
        } else if let Some(next) = self.application_recv_next.as_ref().cloned() {
            // Peer's KP differs from ours: try the next-phase keys.
            let next_nonce = packet_nonce(&next.iv, pn);
            match next.aead_open(&next_nonce, &aad, &mut buf[payload_start..payload_end], &tag) {
                Ok(()) => {
                    // Successful key update — rotate and re-derive.
                    self.rotate_recv_keys();
                    crate::quic_event!(key_updates_accepted,
                        "new_phase={} pn={}", self.recv_key_phase, pn);
                    Ok(())
                }
                Err(()) => {
                    // Try previous-phase keys for reorder absorption.
                    if let Some(prev) = self.application_recv_prev.as_ref() {
                        let prev_nonce = packet_nonce(&prev.iv, pn);
                        prev.aead_open(&prev_nonce, &aad, &mut buf[payload_start..payload_end], &tag)
                    } else {
                        Err(())
                    }
                }
            }
        } else {
            // No next-phase keys yet (shouldn't happen post-handshake)
            // — try previous-phase as a last resort.
            if let Some(prev) = self.application_recv_prev.as_ref() {
                let prev_nonce = packet_nonce(&prev.iv, pn);
                prev.aead_open(&prev_nonce, &aad, &mut buf[payload_start..payload_end], &tag)
            } else {
                Err(())
            }
        };
        aead_result.map_err(|_| {
            crate::quic_drop!(aead_decrypt_failed,
                "1-RTT pn={} kp={} our_kp={} payload_len={}",
                pn, pkt_kp, self.recv_key_phase, payload_end - payload_start);
            ConnError::Decrypt
        })?;

        let payload = &buf[payload_start..payload_end];
        self.dispatch_frames(CryptoLevel::OneRtt, payload)?;

        self.application_space.largest_recv_pn = Some(
            self.application_space
                .largest_recv_pn
                .map_or(pn, |x| x.max(pn)),
        );
        self.application_space.ack_pending = true;
        Ok(total_packet_len)
    }

    /// Promote the next-phase recv keys to current (RFC 9001 §6.1).
    /// Called when a packet's KEY_PHASE bit doesn't match
    /// `recv_key_phase` AND the next-phase keys successfully open
    /// the packet. After rotation the previously-current keys live
    /// in `application_recv_prev` for one more key-phase window so
    /// reordered older packets can still be opened.
    fn rotate_recv_keys(&mut self) {
        // current → prev
        self.application_recv_prev = self.application_recv.take();
        // next → current
        self.application_recv = self.application_recv_next.take();
        self.recv_key_phase ^= 1;
        // Derive a fresh next-phase pair from the updated secret.
        if let Some(secret) = self.client_app_secret.as_ref() {
            let next_secret = next_traffic_secret(secret);
            // Save the new "current" secret so the NEXT KU can
            // derive from it.
            self.client_app_secret = Some(next_secret);
            let next_chacha = derive_chacha_keys(&next_secret);
            // Reuse HP from the new-current keys (HP is invariant
            // across KU per §6.1).
            if let Some(cur) = self.application_recv.as_ref() {
                self.application_recv_next =
                    Some(DirKeys::from_chacha_reuse_hp(&next_chacha, cur));
            }
        }
    }

    /// Remove header protection in place (no AEAD). Returns the
    /// reconstructed full PN. Used by the 1-RTT path which then
    /// trial-decrypts with one of three key-phase key sets;
    /// Initial/Handshake stick with `unprotect_and_decrypt` since
    /// they have no key-phase ambiguity.
    fn unprotect_header(
        &self,
        buf: &mut [u8],
        pn_offset: usize,
        keys: &DirKeys,
    ) -> Result<u64, ConnError> {
        let sample_start = pn_offset + 4;
        if sample_start + HP_SAMPLE_LEN > buf.len() {
            return Err(ConnError::Wire);
        }
        let mut sample = [0u8; HP_SAMPLE_LEN];
        sample.copy_from_slice(&buf[sample_start..sample_start + HP_SAMPLE_LEN]);
        let mask = keys.hp_mask(&sample);

        let is_long = buf[0] & HEADER_FORM_LONG != 0;
        buf[0] ^= mask[0] & if is_long { 0x0f } else { 0x1f };
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        if pn_length > 4 || pn_offset + pn_length + TAG_LEN > buf.len() {
            return Err(ConnError::Wire);
        }
        for i in 0..pn_length {
            buf[pn_offset + i] ^= mask[1 + i];
        }
        let mut truncated = 0u64;
        for i in 0..pn_length {
            truncated = (truncated << 8) | buf[pn_offset + i] as u64;
        }
        let space = if is_long {
            let lt = (buf[0] >> 4) & 0x3;
            match lt {
                long_packet_type::INITIAL => &self.initial_space,
                long_packet_type::HANDSHAKE => &self.handshake_space,
                _ => &self.application_space,
            }
        } else {
            &self.application_space
        };
        let largest = space.largest_recv_pn.unwrap_or(0u64.wrapping_sub(1));
        Ok(decode_packet_number(largest, truncated, pn_length))
    }

    /// Remove header protection AND open the AEAD on a complete
    /// packet buffer in place. Returns the reconstructed full PN.
    /// `buf` enters with protected first byte + protected PN bytes
    /// + ciphertext + tag; exits with unprotected first byte +
    /// PN bytes + decrypted plaintext (tag verified discarded).
    fn unprotect_and_decrypt(
        &self,
        buf: &mut [u8],
        pn_offset: usize,
        keys: &DirKeys,
    ) -> Result<u64, ConnError> {
        // HP sample is 16 bytes starting at pn_offset + 4.
        let sample_start = pn_offset + 4;
        if sample_start + HP_SAMPLE_LEN > buf.len() {
            return Err(ConnError::Wire);
        }
        let mut sample = [0u8; HP_SAMPLE_LEN];
        sample.copy_from_slice(&buf[sample_start..sample_start + HP_SAMPLE_LEN]);
        let mask = keys.hp_mask(&sample);

        // Determine if it's a long-header packet from the protected
        // first byte's top two bits — those are HP-untouched per
        // RFC 9001 §5.4.1 (only low 4/5 bits get masked).
        let is_long = buf[0] & HEADER_FORM_LONG != 0;
        // Two-step HP unprotect (RFC 9001 §5.4.1):
        //   1. XOR mask[0] (low 4 or 5 bits) into the first byte.
        //   2. Read pn_length from the now-unmasked first byte.
        //   3. XOR mask[1 .. 1+pn_length] into exactly the PN bytes.
        // Doing all 4 PN-window bytes up-front would over-XOR the
        // (4 − pn_length) bytes that aren't PN — those are
        // ciphertext, and the corruption breaks AEAD verification.
        buf[0] ^= mask[0] & if is_long { 0x0f } else { 0x1f };
        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        if pn_length > 4 || pn_offset + pn_length + TAG_LEN > buf.len() {
            return Err(ConnError::Wire);
        }
        for i in 0..pn_length {
            buf[pn_offset + i] ^= mask[1 + i];
        }
        // The truncated PN is the first `pn_length` bytes after pn_offset.
        let mut truncated = 0u64;
        for i in 0..pn_length {
            truncated = (truncated << 8) | buf[pn_offset + i] as u64;
        }
        // Reconstruct against the largest seen PN in this space.
        let space = match (buf[0] & 0xc0) | 0 {
            // Initial = type 00 in long header (0xc0..0xcf range)
            x if x & HEADER_FORM_LONG != 0 => {
                let lt = (buf[0] >> 4) & 0x3;
                match lt {
                    long_packet_type::INITIAL => &self.initial_space,
                    long_packet_type::HANDSHAKE => &self.handshake_space,
                    _ => &self.application_space,
                }
            }
            _ => &self.application_space,
        };
        let largest = space.largest_recv_pn.unwrap_or(0u64.wrapping_sub(1));
        let full_pn = decode_packet_number(largest, truncated, pn_length);

        // AEAD AAD = unprotected header bytes (everything before
        // ciphertext): buf[..pn_offset + pn_length].
        let aad_end = pn_offset + pn_length;
        let payload_end = buf.len() - TAG_LEN;
        let aad: Vec<u8> = buf[..aad_end].to_vec();
        let tag: [u8; TAG_LEN] = buf[payload_end..]
            .try_into()
            .map_err(|_| ConnError::Wire)?;
        let nonce = packet_nonce(&keys.iv, full_pn);
        keys.aead_open(&nonce, &aad, &mut buf[aad_end..payload_end], &tag)
            .map_err(|_| {
                crate::quic_drop!(aead_decrypt_failed,
                    "pn={} payload_len={}", full_pn, payload_end - aad_end);
                ConnError::Decrypt
            })?;
        Ok(full_pn)
    }

    fn dispatch_frames(
        &mut self,
        level: CryptoLevel,
        mut payload: &[u8],
    ) -> Result<(), ConnError> {
        while !payload.is_empty() {
            let (frame, consumed) = parse_frame(payload).map_err(|e| {
                crate::quic_drop!(unknown_frame,
                    "level={:?} err={:?} first={:#x} rem={}",
                    level, e, payload[0], payload.len());
                ConnError::Wire
            })?;
            match frame {
                Frame::Padding | Frame::Ping => {}
                Frame::Crypto { offset, data } => {
                    self.tls.push_handshake(level, offset, data);
                }
                Frame::Ack { .. } => {
                    // We don't track outbound packets in flight
                    // yet; ACKs are ignored on the receive side
                    // (no retransmission triggered by us).
                }
                Frame::ConnectionCloseTransport { .. }
                | Frame::ConnectionCloseApplication { .. } => {
                    self.state = ConnState::Failed;
                    return Ok(());
                }
                Frame::HandshakeDone => {
                    // Server only — clients don't send this.
                }
                Frame::Stream { stream_id, offset, data, fin } => {
                    if matches!(level, CryptoLevel::OneRtt) {
                        let s = self
                            .recv_streams
                            .entry(stream_id)
                            .or_insert_with(crate::streams::RecvStream::default);
                        s.ingest(offset, data, fin);
                        if !self.opened_streams.contains(&stream_id) {
                            self.opened_streams.push(stream_id);
                        }
                        // Best-effort STREAM-level ack pending so we
                        // schedule a 1-RTT ACK for it on the next
                        // outbound flush.
                        self.application_space.ack_pending = true;
                    }
                }
                Frame::Skipped { .. } => {
                    // Wire-recognized but no app-level reaction yet
                    // (MAX_DATA, NEW_CONNECTION_ID, …). Frame layer
                    // already consumed the right number of bytes.
                }
            }
            payload = &payload[consumed..];
        }
        Ok(())
    }

    // ── TLS state machine drive + outbound flush ────────────────

    fn advance_tls(&mut self, config: &TlsServerConfig) -> Result<(), ConnError> {
        let new_state = self.tls.advance(config)?;
        // 0-RTT (early-data) recv keys. Only set on resumption,
        // and only after CH has been parsed — `client_early_traffic_secret()`
        // returns Some at that point. Derived eagerly so we can
        // unprotect 0-RTT packets that arrive in the same datagram
        // as the Initial / right after; without these the packets
        // get silently dropped by `aead_decrypt_failed`.
        if let Some(et) = self.tls.client_early_traffic_secret() {
            if self.early_recv.is_none() {
                let recv = derive_chacha_keys(et);
                self.early_recv = Some(DirKeys::from_chacha(&recv));
                crate::quic_event!(early_keys_derived,
                    "local_cid={}",
                    crate::endpoint::hex8(self.local_cid.as_slice()));
                // Replay any 0-RTT packets that arrived before
                // the keys were ready. process_zero_rtt is the
                // canonical handler — call it on each buffered
                // packet so we share decryption + frame-dispatch
                // logic with the steady-state path.
                let pending = core::mem::take(&mut self.pending_zero_rtt);
                for pkt in pending {
                    if let Err(e) = self.process_zero_rtt(&pkt) {
                        // Don't propagate — replay failures are
                        // best-effort and shouldn't kill the conn.
                        crate::quic_drop!(other_wire,
                            "0-RTT replay error: {:?}", e);
                    }
                }
            }
        }
        // Once handshake-stage secrets exist on the TLS side and
        // we haven't yet derived our packet-protection keys for
        // the Handshake space, derive them now.
        if let Some(hs) = self.tls.handshake_secrets() {
            if self.handshake_send.is_none() {
                let send = derive_chacha_keys(&hs.server_hs);
                let recv = derive_chacha_keys(&hs.client_hs);
                self.handshake_send = Some(DirKeys::from_chacha(&send));
                self.handshake_recv = Some(DirKeys::from_chacha(&recv));
            }
        }
        if let Some(ap) = self.tls.application_secrets() {
            if self.application_send.is_none() {
                let send = derive_chacha_keys(&ap.server_ap);
                let recv = derive_chacha_keys(&ap.client_ap);
                self.application_send = Some(DirKeys::from_chacha(&send));
                self.application_recv = Some(DirKeys::from_chacha(&recv));
                // Pre-derive next-phase recv keys so a peer-initiated
                // key update (RFC 9001 §6) doesn't require HKDF on
                // the hot decrypt path — we just trial-decrypt with
                // `application_recv_next` whenever the KEY_PHASE bit
                // disagrees with `recv_key_phase`. HP key persists
                // across phases (§6.1: "the same header protection
                // key is used") so we copy it from the current keys.
                self.client_app_secret = Some(ap.client_ap);
                let next_secret = next_traffic_secret(&ap.client_ap);
                let next_chacha = derive_chacha_keys(&next_secret);
                let cur_recv = self.application_recv.as_ref().unwrap();
                self.application_recv_next = Some(DirKeys::from_chacha_reuse_hp(
                    &next_chacha,
                    cur_recv,
                ));
            }
        }
        if matches!(new_state, QuicTlsState::Established) {
            // Edge-trigger the event so a flapping flush_outbound
            // doesn't double-count.
            if !matches!(self.state, ConnState::Established) {
                crate::quic_event!(handshakes_completed,
                    "local_cid={}",
                    crate::endpoint::hex8(self.local_cid.as_slice()));
                // If the handshake completed WITHOUT resumption
                // (no early_recv ever derived), we'll never be
                // able to decrypt buffered 0-RTT packets — drop
                // them now so they don't sit in memory until conn
                // teardown. Common when a peer optimistically sent
                // 0-RTT with a stale ticket from a previous boot.
                if !self.pending_zero_rtt.is_empty() && self.early_recv.is_none() {
                    crate::quic_event!(zero_rtt_unresumable,
                        "dropped={} reason=resumption_rejected",
                        self.pending_zero_rtt.len());
                    self.pending_zero_rtt.clear();
                }
            }
            self.state = ConnState::Established;
        } else if matches!(new_state, QuicTlsState::Failed) {
            self.state = ConnState::Failed;
        }
        Ok(())
    }

    fn flush_outbound(&mut self, _config: &TlsServerConfig) -> Result<(), ConnError> {
        // Build outbound packets in a single coalesced datagram.
        // Order matters: Initial first, then Handshake, then 1-RTT
        // (RFC 9000 §12.2). Each packet's tx-side CRYPTO bytes
        // come from QuicTls.pop_handshake at the matching level.
        let mut datagram = Vec::with_capacity(1500);

        // Initial packet (if there are bytes to send or an ACK pending).
        let mut initial_crypto = [0u8; 1024];
        let initial_n = self
            .tls
            .pop_handshake(CryptoLevel::Initial, &mut initial_crypto);
        if initial_n > 0 || self.initial_space.ack_pending {
            self.encode_initial_packet(
                &mut datagram,
                &initial_crypto[..initial_n],
                self.initial_space.ack_pending,
            )?;
            self.initial_space.ack_pending = false;
        }

        // Handshake packet (after Initial has at least an ACK).
        let mut hs_crypto = vec![0u8; 8192];
        let hs_n = self
            .tls
            .pop_handshake(CryptoLevel::Handshake, &mut hs_crypto);
        if hs_n > 0 || self.handshake_space.ack_pending {
            self.encode_handshake_packet(
                &mut datagram,
                &hs_crypto[..hs_n],
                self.handshake_space.ack_pending,
            )?;
            self.handshake_space.ack_pending = false;
        }

        // 1-RTT packet — bundles ACK + HANDSHAKE_DONE + STREAM
        // frames + STREAM data drained from per-stream send queues.
        if matches!(self.state, ConnState::Established) {
            self.encode_one_rtt_packet(&mut datagram)?;
        }

        if !datagram.is_empty() {
            self.outbound.push(datagram);
        }
        Ok(())
    }

    // ── Outbound encoding ───────────────────────────────────────

    /// Encode an Initial packet into `out`, appending to it. The
    /// Initial header carries our chosen SCID (`local_cid`) and
    /// the peer's CID as DCID. Payload = optional ACK + optional
    /// CRYPTO frame, with PADDING to a useful size.
    fn encode_initial_packet(
        &mut self,
        out: &mut Vec<u8>,
        crypto_bytes: &[u8],
        emit_ack: bool,
    ) -> Result<(), ConnError> {
        let send_keys = self.initial_send.as_ref().ok_or(ConnError::BadState)?.clone();
        let pn = self.initial_space.next_send_pn;
        self.initial_space.next_send_pn += 1;

        // Build frames.
        let mut frames: Vec<u8> = Vec::with_capacity(1024);
        if emit_ack {
            self.append_ack_frame(&mut frames, &self.initial_space);
        }
        if !crypto_bytes.is_empty() {
            let mut tmp = vec![0u8; crypto_bytes.len() + 16];
            let n = write_crypto(0, crypto_bytes, &mut tmp).map_err(|_| ConnError::Wire)?;
            frames.extend_from_slice(&tmp[..n]);
        }

        // Reserve tail = TAG_LEN bytes for the AEAD tag at the end.
        let pn_length: usize = 4;
        let payload_len = frames.len();
        let length_field = (pn_length + payload_len + TAG_LEN) as u64;

        // First byte: 0xc0 | (pn_length-1).
        let first_byte: u8 = 0xc0 | ((pn_length as u8) - 1);
        let header_start = out.len();
        out.push(first_byte);
        out.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        // Initial-reply DCID is the client's SCID we recorded; for
        // the Initial response we MUST echo the client's chosen
        // SCID (= peer_cid) per RFC 9000 §7.2 (or the client_initial_dcid
        // until the client has picked one — for our case, peer_cid
        // is what the client sent as SCID on its first Initial).
        out.push(self.peer_cid.len() as u8);
        out.extend_from_slice(self.peer_cid.as_slice());
        out.push(self.local_cid.len() as u8);
        out.extend_from_slice(self.local_cid.as_slice());
        // Token Length VARINT = 0.
        out.push(0);
        // Length VARINT.
        let mut lf_buf = [0u8; 4];
        let n = write_varint(length_field, &mut lf_buf).map_err(|_| ConnError::Wire)?;
        out.extend_from_slice(&lf_buf[..n]);
        let pn_offset = out.len();
        // PN bytes (4-byte big-endian).
        out.extend_from_slice(&(pn as u32).to_be_bytes());
        let payload_offset = out.len();
        out.extend_from_slice(&frames);
        out.extend_from_slice(&[0u8; TAG_LEN]); // tag placeholder
        let total_end = out.len();

        self.seal_packet(out, header_start, pn_offset, payload_offset, payload_len, total_end, pn, &send_keys, true)
    }

    fn encode_handshake_packet(
        &mut self,
        out: &mut Vec<u8>,
        crypto_bytes: &[u8],
        emit_ack: bool,
    ) -> Result<(), ConnError> {
        let send_keys = self
            .handshake_send
            .as_ref()
            .ok_or(ConnError::BadState)?
            .clone();
        let pn = self.handshake_space.next_send_pn;
        self.handshake_space.next_send_pn += 1;

        let mut frames: Vec<u8> = Vec::with_capacity(crypto_bytes.len() + 64);
        if emit_ack {
            self.append_ack_frame(&mut frames, &self.handshake_space);
        }
        if !crypto_bytes.is_empty() {
            let mut tmp = vec![0u8; crypto_bytes.len() + 16];
            let n = write_crypto(0, crypto_bytes, &mut tmp).map_err(|_| ConnError::Wire)?;
            frames.extend_from_slice(&tmp[..n]);
        }

        let pn_length: usize = 4;
        let payload_len = frames.len();
        let length_field = (pn_length + payload_len + TAG_LEN) as u64;

        let first_byte: u8 = 0xe0 | ((pn_length as u8) - 1); // type=10 Handshake
        let header_start = out.len();
        out.push(first_byte);
        out.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        out.push(self.peer_cid.len() as u8);
        out.extend_from_slice(self.peer_cid.as_slice());
        out.push(self.local_cid.len() as u8);
        out.extend_from_slice(self.local_cid.as_slice());
        let mut lf_buf = [0u8; 4];
        let n = write_varint(length_field, &mut lf_buf).map_err(|_| ConnError::Wire)?;
        out.extend_from_slice(&lf_buf[..n]);
        let pn_offset = out.len();
        out.extend_from_slice(&(pn as u32).to_be_bytes());
        let payload_offset = out.len();
        out.extend_from_slice(&frames);
        out.extend_from_slice(&[0u8; TAG_LEN]);
        let total_end = out.len();

        self.seal_packet(out, header_start, pn_offset, payload_offset, payload_len, total_end, pn, &send_keys, true)
    }

    /// Build a single 1-RTT packet that bundles the currently-due
    /// frames: ACK (if pending), HANDSHAKE_DONE (if not yet sent),
    /// and as many STREAM-frame chunks as fit before the per-packet
    /// budget. Skips emission entirely if no frames are due.
    fn encode_one_rtt_packet(&mut self, out: &mut Vec<u8>) -> Result<(), ConnError> {
        // Per-packet body budget. Leaves headroom for short-header
        // (1+CID+pn=13) + tag (16) under MTU 1200; STREAM frame
        // headers add ~4-12 bytes of varint overhead.
        const PACKET_BODY_BUDGET: usize = 1100;

        let send_keys = match self.application_send.as_ref() {
            Some(k) => k.clone(),
            None => return Ok(()),
        };

        // Collect frames into a scratch buffer.
        let mut frames: Vec<u8> = Vec::with_capacity(PACKET_BODY_BUDGET);

        if self.application_space.ack_pending {
            self.append_ack_frame(&mut frames, &self.application_space);
            self.application_space.ack_pending = false;
        }
        if !self.handshake_done_sent {
            let mut tmp = [0u8; 4];
            let n = write_handshake_done(&mut tmp).map_err(|_| ConnError::Wire)?;
            frames.extend_from_slice(&tmp[..n]);
            self.handshake_done_sent = true;
        }

        // Drain any 1-RTT-level handshake bytes (NewSessionTicket
        // emitted right after ClientFinished verifies; future
        // KeyUpdate / NewToken). Wrap as a CRYPTO frame at offset 0
        // — this is the OneRtt CRYPTO stream, distinct from
        // Initial/Handshake. Each ticket adds ~150 bytes; the
        // budget check after pop_handshake guards against an
        // unbounded queue.
        let mut one_rtt_crypto = [0u8; 1024];
        let crypto_n = self
            .tls
            .pop_handshake(CryptoLevel::OneRtt, &mut one_rtt_crypto);
        if crypto_n > 0 {
            // Track our own offset for the OneRtt CRYPTO stream so
            // multiple post-handshake messages (e.g. a sequence of
            // tickets, KeyUpdate, NEW_TOKEN) chain correctly.
            let offset = self.one_rtt_crypto_offset;
            let mut tmp = vec![0u8; crypto_n + 16];
            let n = write_crypto(offset, &one_rtt_crypto[..crypto_n], &mut tmp)
                .map_err(|_| ConnError::Wire)?;
            frames.extend_from_slice(&tmp[..n]);
            self.one_rtt_crypto_offset += crypto_n as u64;
            crate::quic_event!(tickets_emitted,
                "size={} local_cid={}", crypto_n,
                crate::endpoint::hex8(self.local_cid.as_slice()));
        }

        // Drain pending STREAM data. Round-robin across streams
        // — each stream can contribute one chunk per packet so a
        // single greedy stream doesn't starve siblings during burst
        // workloads. (For HTTP/3 there's typically only one active
        // request stream at a time anyway.)
        let stream_ids: Vec<u64> = self.send_streams.keys().copied().collect();
        for sid in stream_ids {
            if frames.len() >= PACKET_BODY_BUDGET {
                break;
            }
            let max_chunk = PACKET_BODY_BUDGET.saturating_sub(frames.len() + 16); // varint headroom
            if max_chunk == 0 {
                break;
            }
            let s = match self.send_streams.get_mut(&sid) {
                Some(s) => s,
                None => continue,
            };
            if let Some((offset, chunk, fin)) = s.pop_chunk(max_chunk) {
                let mut tmp = vec![0u8; chunk.len() + 32];
                let n = crate::frame::write_stream(sid, offset, fin, &chunk, &mut tmp)
                    .map_err(|_| ConnError::Wire)?;
                frames.extend_from_slice(&tmp[..n]);
            }
        }

        if frames.is_empty() {
            return Ok(());
        }

        let pn = self.application_space.next_send_pn;
        self.application_space.next_send_pn += 1;

        let pn_length: usize = 4;
        let header_start = out.len();
        // Short-header first byte: form=0 fixed=1 spin=0 reserved=00
        // key-phase=0 pn_length-1 in low 2 bits.
        let first_byte: u8 = FIXED_BIT | ((pn_length as u8) - 1);
        out.push(first_byte);
        out.extend_from_slice(self.peer_cid.as_slice());
        let pn_offset = out.len();
        out.extend_from_slice(&(pn as u32).to_be_bytes());
        let payload_offset = out.len();
        out.extend_from_slice(&frames);
        // Pad to ensure HP sample (4 bytes after PN start) has 16
        // bytes of ciphertext after AEAD seal.
        while out.len() - pn_offset < 4 + HP_SAMPLE_LEN {
            out.push(0); // PADDING frame
        }
        let payload_len = out.len() - payload_offset;
        out.extend_from_slice(&[0u8; TAG_LEN]);
        let total_end = out.len();

        self.seal_packet(
            out,
            header_start,
            pn_offset,
            payload_offset,
            payload_len,
            total_end,
            pn,
            &send_keys,
            false,
        )
    }

    /// Common AEAD seal + HP protect. `out` is the assembled
    /// datagram; we operate on the slice from `header_start`
    /// to `total_end`.
    #[allow(clippy::too_many_arguments)]
    fn seal_packet(
        &self,
        out: &mut Vec<u8>,
        header_start: usize,
        pn_offset: usize,
        payload_offset: usize,
        payload_len: usize,
        total_end: usize,
        pn: u64,
        keys: &DirKeys,
        is_long: bool,
    ) -> Result<(), ConnError> {
        let aad: Vec<u8> = out[header_start..payload_offset].to_vec();
        let nonce = packet_nonce(&keys.iv, pn);
        let payload_slice = &mut out[payload_offset..payload_offset + payload_len];
        let tag = keys.aead_seal(&nonce, &aad, payload_slice);
        out[payload_offset + payload_len..payload_offset + payload_len + TAG_LEN]
            .copy_from_slice(&tag);

        // Header protection sample.
        let sample_start = pn_offset + 4;
        if sample_start + HP_SAMPLE_LEN > total_end {
            return Err(ConnError::OutputTooSmall);
        }
        let mut sample = [0u8; HP_SAMPLE_LEN];
        sample.copy_from_slice(&out[sample_start..sample_start + HP_SAMPLE_LEN]);
        let mask = keys.hp_mask(&sample);

        let pn_length = 4usize;
        let (head, rest) = out.split_at_mut(pn_offset);
        apply_hp_mask(&mut head[header_start], &mut rest[..pn_length], &mask, is_long);
        Ok(())
    }

    fn append_ack_frame(&self, frames: &mut Vec<u8>, space: &SpaceState) {
        let largest = match space.largest_recv_pn {
            Some(x) => x,
            None => return,
        };
        let mut tmp = [0u8; 32];
        if let Ok(n) = write_ack(largest, /* delay */ 0, /* first_range */ 0, &[], &mut tmp) {
            frames.extend_from_slice(&tmp[..n]);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: connection construction yields the expected
    /// initial state. Real handshake driving requires a synthetic
    /// inbound Initial which is itself non-trivial to fabricate
    /// (need to seal under client-side Initial keys); the next
    /// commit will drive an end-to-end handshake against rustls.
    #[test]
    fn connection_starts_pre_handshake() {
        let cid = ConnectionId::new(&[0xaa; 8]);
        let conn = Connection::new_server(cid, [0x42u8; 32]);
        assert_eq!(conn.state(), ConnState::PreHandshake);
        assert!(!conn.has_outbound());
        assert_eq!(conn.local_cid().as_slice(), &[0xaa; 8]);
    }

    #[test]
    fn connection_id_truncates_at_20() {
        let cid = ConnectionId::new(&[0x55; 30]);
        assert_eq!(cid.len(), 20);
        assert_eq!(cid.as_slice(), &[0x55; 20]);
    }

    /// End-to-end: seal a synthetic "client Initial" containing a
    /// real ClientHello, feed it to a fresh server `Connection`,
    /// confirm the connection emits a coalesced Initial + Handshake
    /// reply that round-trips through *our* unprotect+decrypt path.
    /// This exercises the complete pipeline:
    ///
    ///   inbound:   parse header → HP unprotect → AEAD open →
    ///              CRYPTO frame → push to QuicTls
    ///   advance:   QuicTls runs handshake, produces ServerHello +
    ///              EE/Cert/CV/Finished bytes
    ///   outbound:  emit Initial (ServerHello) + Handshake
    ///              (server flight) + ACK frames, AEAD seal,
    ///              HP protect
    ///   verify:    decrypt the outbound packets using the same
    ///              keys our connection derived
    #[test]
    fn end_to_end_self_handshake() {
        use uni_tls::handshake::{
            cipher_suite, ext_type, named_group, msg_type as mt, LEGACY_VERSION_TLS12,
            VERSION_TLS13,
        };

        // 1. Build a TLS ClientHello as the client would.
        let client_pub = [0x77u8; 32];
        let mut ext = Vec::<u8>::new();
        let write_ext = |buf: &mut Vec<u8>, ty: u16, body: &[u8]| {
            buf.extend_from_slice(&ty.to_be_bytes());
            buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
            buf.extend_from_slice(body);
        };
        write_ext(&mut ext, ext_type::SUPPORTED_VERSIONS, &[0x02, 0x03, 0x04]);
        write_ext(&mut ext, ext_type::SUPPORTED_GROUPS, &[0x00, 0x02, 0x00, 0x1d]);
        let mut ks = Vec::<u8>::new();
        ks.extend_from_slice(&36u16.to_be_bytes());
        ks.extend_from_slice(&named_group::X25519.to_be_bytes());
        ks.extend_from_slice(&32u16.to_be_bytes());
        ks.extend_from_slice(&client_pub);
        write_ext(&mut ext, ext_type::KEY_SHARE, &ks);
        write_ext(&mut ext, ext_type::SIGNATURE_ALGORITHMS, &[0x00, 0x02, 0x04, 0x03]);

        let mut ch_body = Vec::<u8>::new();
        ch_body.extend_from_slice(&LEGACY_VERSION_TLS12.to_be_bytes());
        ch_body.extend_from_slice(&[0x11u8; 32]);
        ch_body.push(0);
        ch_body.extend_from_slice(&2u16.to_be_bytes());
        ch_body
            .extend_from_slice(&cipher_suite::TLS_CHACHA20_POLY1305_SHA256.to_be_bytes());
        ch_body.push(1);
        ch_body.push(0);
        ch_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&ext);
        let _ = VERSION_TLS13; // just to silence unused-import warning if any
        let mut ch_msg = Vec::<u8>::new();
        ch_msg.push(mt::CLIENT_HELLO);
        let len = ch_body.len() as u32;
        ch_msg.push(((len >> 16) & 0xff) as u8);
        ch_msg.push(((len >> 8) & 0xff) as u8);
        ch_msg.push((len & 0xff) as u8);
        ch_msg.extend_from_slice(&ch_body);

        // 2. Wrap ChMsg in a CRYPTO frame.
        let mut crypto_frame = vec![0u8; ch_msg.len() + 16];
        let cn = write_crypto(0, &ch_msg, &mut crypto_frame).unwrap();
        let payload = &crypto_frame[..cn];

        // 3. Build a sealed Initial packet using client-direction
        //    Initial keys derived from a synthetic DCID.
        let client_dcid: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xca, 0xfe];
        let client_scid: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let secrets = derive_initial_secrets(&client_dcid);
        let client_keys = derive_initial_keys(&secrets.client);
        let client_dirkeys = DirKeys::from_initial(&client_keys);

        let pn_length: usize = 4;
        let pn: u64 = 0;
        let length_field = (pn_length + payload.len() + TAG_LEN) as u64;

        let mut packet = Vec::<u8>::new();
        packet.push(0xc0 | ((pn_length as u8) - 1));
        packet.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        packet.push(client_dcid.len() as u8);
        packet.extend_from_slice(&client_dcid);
        packet.push(client_scid.len() as u8);
        packet.extend_from_slice(&client_scid);
        packet.push(0); // token len
        let mut lf = [0u8; 4];
        let lf_n = write_varint(length_field, &mut lf).unwrap();
        packet.extend_from_slice(&lf[..lf_n]);
        let pn_offset = packet.len();
        packet.extend_from_slice(&(pn as u32).to_be_bytes());
        let payload_offset = packet.len();
        packet.extend_from_slice(payload);
        packet.extend_from_slice(&[0u8; TAG_LEN]); // placeholder

        // AEAD seal in place.
        let aad = packet[..payload_offset].to_vec();
        let nonce = packet_nonce(&client_dirkeys.iv, pn);
        {
            let payload_slice =
                &mut packet[payload_offset..payload_offset + payload.len()];
            let tag = client_dirkeys.aead_seal(&nonce, &aad, payload_slice);
            packet[payload_offset + payload.len()
                ..payload_offset + payload.len() + TAG_LEN]
                .copy_from_slice(&tag);
        }

        // HP protect.
        let sample_start = pn_offset + 4;
        let mut sample = [0u8; HP_SAMPLE_LEN];
        sample.copy_from_slice(&packet[sample_start..sample_start + HP_SAMPLE_LEN]);
        let mask = client_dirkeys.hp_mask(&sample);
        let (head, rest) = packet.split_at_mut(pn_offset);
        apply_hp_mask(&mut head[0], &mut rest[..pn_length], &mask, true);

        // 4. Drive the server-side connection with this datagram.
        let local_cid = ConnectionId::new(&[0xab; 8]);
        let mut conn = Connection::new_server(local_cid, [0x42u8; 32]);
        let cfg = dev_config();
        conn.process_datagram(&packet, &cfg).expect("process inbound Initial");

        // The server should have moved into Connecting and queued
        // an outbound datagram with the server flight.
        assert_eq!(conn.state(), ConnState::Connecting);
        assert!(conn.has_outbound(), "server should have a reply queued");

        // 5. Drain the outbound datagram and verify both packets
        //    parse + decrypt with the *server* Initial / Handshake
        //    keys (which our connection derived).
        let mut reply = vec![0u8; 4096];
        let n = conn.pop_packet(&mut reply);
        assert!(n > 0, "non-empty reply datagram");
        let reply = &reply[..n];

        // First packet should be Initial. Re-derive server-side
        // keys from the same client_dcid and unprotect.
        let server_initial = derive_initial_keys(&secrets.server);
        let server_initial_dk = DirKeys::from_initial(&server_initial);
        let pre = parse_long_header_preamble(reply).unwrap();
        assert_eq!(pre.long_type, long_packet_type::INITIAL);
        assert_eq!(pre.dcid, &client_scid[..]); // server echoes our SCID
        assert_eq!(pre.scid, &[0xab; 8][..]);   // server's local CID
        // Continue parsing to find pn_offset.
        let initial_hdr = parse_initial_header(reply).unwrap();
        let init_total = initial_hdr.pn_offset + initial_hdr.length as usize;
        let mut init_buf = reply[..init_total].to_vec();
        let _pn = conn.unprotect_and_decrypt(
            &mut init_buf,
            initial_hdr.pn_offset,
            &server_initial_dk,
        ).expect("decrypt server Initial");

        // Second packet (after Initial) should be Handshake.
        let handshake_pkt = &reply[init_total..];
        let pre2 = parse_long_header_preamble(handshake_pkt).unwrap();
        assert_eq!(pre2.long_type, long_packet_type::HANDSHAKE);
        // Server has Handshake-stage keys derived; use them to
        // unprotect the Handshake packet.
        let send_keys = conn.handshake_send.as_ref().unwrap().clone();
        let mut p = pre2.tail_offset;
        let (length, vn) = read_varint(&handshake_pkt[p..]).unwrap();
        p += vn;
        let pn_offset2 = p;
        let mut hs_buf = handshake_pkt[..pn_offset2 + length as usize].to_vec();
        let _pn2 = conn
            .unprotect_and_decrypt(&mut hs_buf, pn_offset2, &send_keys)
            .expect("decrypt server Handshake");
    }

    fn dev_config() -> TlsServerConfig {
        const CERT: &[u8] =
            include_bytes!("../../apps/webserver/dev_certs/dev_cert.der");
        const KEY: &[u8] =
            include_bytes!("../../apps/webserver/dev_certs/dev_key.der");
        TlsServerConfig::from_dev_cert(CERT, KEY).expect("dev cert load")
    }

    /// Server constructs Initial keys correctly given a client
    /// DCID — same value as a known-answer test would, fed back
    /// through `DirKeys` to confirm the conversion shape works.
    #[test]
    fn initial_keys_install_on_first_packet_path() {
        let cid = ConnectionId::new(&[0x11; 8]);
        let conn = Connection::new_server(cid, [0u8; 32]);
        // Inject the post-key-derivation state directly to avoid
        // having to fabricate a sealed Initial in the test
        // (which requires running our own seal pipeline). The
        // logic that *sets* initial_recv lives in process_initial;
        // the next commit's end-to-end test exercises that whole
        // path. Here we just confirm the helper conversions.
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let secrets = derive_initial_secrets(&dcid);
        let server_keys = derive_initial_keys(&secrets.server);
        let dk = DirKeys::from_initial(&server_keys);
        assert_eq!(dk.aead_len, AES_KEY_LEN as u8);
        assert!(!dk.is_chacha);
        // Round-trip seal/open with these keys.
        let nonce = packet_nonce(&dk.iv, 0);
        let mut data = *b"plaintext-ish-block";
        let aad = b"associated-aad";
        let tag = dk.aead_seal(&nonce, aad, &mut data);
        // Tampered tag fails.
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x80;
        let mut data2 = *b"plaintext-ish-block";
        let _ = dk.aead_seal(&nonce, aad, &mut data2);
        assert!(dk.aead_open(&nonce, aad, &mut data2, &bad_tag).is_err());
        // Right tag round-trips.
        let mut data3 = *b"plaintext-ish-block";
        let tag3 = dk.aead_seal(&nonce, aad, &mut data3);
        dk.aead_open(&nonce, aad, &mut data3, &tag3).unwrap();
        assert_eq!(&data3, b"plaintext-ish-block");
        let _ = conn; // silence
    }
}
