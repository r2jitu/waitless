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
    hp_mask_aes128, hp_mask_chacha20, packet_nonce, AES_KEY_LEN, CHACHA_KEY_LEN, HP_MASK_LEN,
    HP_SAMPLE_LEN, NONCE_LEN, TAG_LEN,
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

    initial_space: SpaceState,
    handshake_space: SpaceState,
    application_space: SpaceState,

    tls: QuicTls,

    /// Whether we've already emitted HANDSHAKE_DONE in 1-RTT.
    handshake_done_sent: bool,

    /// Outbound packet queue: complete UDP datagrams (including
    /// any header-protected, AEAD-sealed packets) ready to ship.
    /// `pop_packet` drains the front entry.
    outbound: Vec<Vec<u8>>,
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
            handshake_send: None,
            handshake_recv: None,
            application_send: None,
            application_recv: None,
            initial_space: SpaceState::default(),
            handshake_space: SpaceState::default(),
            application_space: SpaceState::default(),
            tls: QuicTls::new(seed),
            handshake_done_sent: false,
            outbound: Vec::new(),
        }
    }

    pub fn state(&self) -> ConnState {
        self.state
    }

    pub fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    /// Process one inbound UDP datagram. Coalesced packets
    /// (Initial+Handshake in one datagram, common with rustls /
    /// quinn) are walked left-to-right; each packet's protection
    /// is removed independently.
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
            let consumed = self.process_one_packet(&datagram[p..], config)?;
            if consumed == 0 {
                // Defensive — never observed in practice with
                // well-formed datagrams, but guarantees forward
                // progress so a parsing bug can't loop.
                break;
            }
            p += consumed;
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
        if first & HEADER_FORM_LONG != 0 {
            self.process_long_header_packet(bytes)
        } else {
            self.process_short_header_packet(bytes)
        }
    }

    fn process_long_header_packet(&mut self, bytes: &[u8]) -> Result<usize, ConnError> {
        let preamble = parse_long_header_preamble(bytes).map_err(|_| ConnError::Wire)?;
        match preamble.long_type {
            long_packet_type::INITIAL => self.process_initial(bytes),
            long_packet_type::HANDSHAKE => self.process_handshake_pkt(bytes),
            long_packet_type::ZERO_RTT | long_packet_type::RETRY => Err(ConnError::Wire),
            _ => Err(ConnError::Wire),
        }
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

    fn process_short_header_packet(&mut self, _bytes: &[u8]) -> Result<usize, ConnError> {
        // 1-RTT packet — DCID length is endpoint-known (= our
        // SERVER_CID_LEN). We don't need 1-RTT for the handshake
        // MVP, so accept-and-ignore for now.
        Ok(_bytes.len())
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
        let pn_slice_len_max = 4.min(buf.len() - pn_offset);
        // Apply mask to first byte + first 4 bytes after pn_offset.
        // We unprotect 4 bytes regardless of actual PN length — we'll
        // truncate after we read the length from the unprotected
        // first byte.
        {
            let (head, rest) = buf.split_at_mut(pn_offset);
            let pn_window = &mut rest[..pn_slice_len_max];
            apply_hp_mask(&mut head[0], pn_window, &mask, is_long);
        }

        let pn_length = ((buf[0] & 0x03) as usize) + 1;
        if pn_length > 4 || pn_offset + pn_length + TAG_LEN > buf.len() {
            return Err(ConnError::Wire);
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
            .map_err(|_| ConnError::Decrypt)?;
        Ok(full_pn)
    }

    fn dispatch_frames(
        &mut self,
        level: CryptoLevel,
        mut payload: &[u8],
    ) -> Result<(), ConnError> {
        while !payload.is_empty() {
            let (frame, consumed) = parse_frame(payload).map_err(|_| ConnError::Wire)?;
            match frame {
                Frame::Padding | Frame::Ping => {}
                Frame::Crypto { offset: _, data } => {
                    // We trust offset ordering for the MVP — most
                    // clients send CRYPTO frames in offset order
                    // and rustls/quinn always do.
                    self.tls.push_handshake(level, data);
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
                Frame::Stream { .. } => {
                    // Out of scope for the handshake MVP.
                }
            }
            payload = &payload[consumed..];
        }
        Ok(())
    }

    // ── TLS state machine drive + outbound flush ────────────────

    fn advance_tls(&mut self, config: &TlsServerConfig) -> Result<(), ConnError> {
        let new_state = self.tls.advance(config)?;
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
            }
        }
        if matches!(new_state, QuicTlsState::Established) {
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

        // 1-RTT packet for HANDSHAKE_DONE.
        if matches!(self.state, ConnState::Established) && !self.handshake_done_sent {
            self.encode_one_rtt_handshake_done(&mut datagram)?;
            self.handshake_done_sent = true;
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

    fn encode_one_rtt_handshake_done(&mut self, out: &mut Vec<u8>) -> Result<(), ConnError> {
        let send_keys = self
            .application_send
            .as_ref()
            .ok_or(ConnError::BadState)?
            .clone();
        let pn = self.application_space.next_send_pn;
        self.application_space.next_send_pn += 1;

        let mut frames = [0u8; 4];
        let n = write_handshake_done(&mut frames).map_err(|_| ConnError::Wire)?;
        let frames = &frames[..n];

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
        out.extend_from_slice(frames);
        // Pad to ensure HP sample (4 bytes after PN start) has 16
        // bytes of ciphertext after AEAD seal.
        while out.len() - pn_offset < 4 + HP_SAMPLE_LEN {
            out.push(0); // PADDING frame
        }
        let payload_len = out.len() - payload_offset;
        out.extend_from_slice(&[0u8; TAG_LEN]);
        let total_end = out.len();

        self.seal_packet(out, header_start, pn_offset, payload_offset, payload_len, total_end, pn, &send_keys, false)
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
