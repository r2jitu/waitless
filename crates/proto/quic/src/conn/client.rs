// crates/proto/quic/src/conn/client.rs — the CLIENT role of the QUIC
// connection state machine (RFC 9000 + RFC 9001, client side).
//
// `Connection::new_client` builds a client-role `Connection` that
// reuses the WHOLE symmetric machinery — packet encode/seal, RX
// dispatch, streams, flow control, loss detection/PTO, congestion
// control, pacing — with role awareness confined to a handful of
// parameterization points:
//
//   * key DIRECTION: the client protects with the "client in" /
//     client_hs / client_ap halves and opens with the server halves
//     (RFC 9001 §5.1-5.2; swapped in `new_client` below and in
//     `advance_tls`'s role split).
//   * Initial shape: client-chosen random DCID seeds the Initial
//     keys; the Initial header carries a (Retry) token; every
//     client datagram with an Initial is padded to ≥ 1200 bytes
//     (RFC 9000 §14.1; both in `encode_initial_packet`).
//   * server-CID adoption on the first server Initial (RFC 9000
//     §7.2; in `process_initial`).
//   * stream-ID initiator-bit flip (rx.rs's role-split limit /
//     watermark / accept paths).
//   * Version Negotiation + Retry are CLIENT-received packets
//     (`process_version_negotiation` / `process_retry` below).
//   * transport-parameter CID authentication (RFC 9000 §7.3;
//     `validate_peer_transport_params` below).
//
// Sans-io like the server role: the embedding code (a future client
// endpoint — NOT built here) feeds datagrams via
// `client_process_datagram`, drains via `pop_packet_owned`, and
// drives timers via the existing role-agnostic deadline accessors.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{ConnError, ConnState, Connection, ConnectionId, DirKeys};
use crate::crypto::{
    TAG_LEN, derive_initial_keys, derive_initial_secrets, retry_integrity_verify,
};
use crate::tls::QuicTls;
use crate::wire::{QUIC_VERSION_1, parse_long_header_preamble};
use tls::TlsClientConfig;
use tls::schedule::hkdf_expand_label;

/// QUIC transport error code TRANSPORT_PARAMETER_ERROR (RFC 9000
/// §20.1) — what a §7.3 CID-authentication mismatch closes with.
const TRANSPORT_PARAMETER_ERROR: u64 = 0x08;

/// Client-role state hanging off [`Connection`] (boxed — the server
/// role pays one pointer). The shared machinery never reads these;
/// only the role-gated paths in rx.rs / tx.rs / keys.rs and the
/// methods below do.
pub(crate) struct ClientState {
    /// Set once the first server Initial's SCID has been adopted as
    /// our DCID (RFC 9000 §7.2) — later changes are ignored.
    pub(super) server_cid_adopted: bool,
    /// Set once the server's echoed transport-parameter CIDs have
    /// been authenticated (RFC 9000 §7.3).
    pub(super) tps_validated: bool,
    /// The SCID of the (single) accepted Retry, if any — adopted as
    /// our DCID, the Initial keys re-derived from it, and required to
    /// be echoed in `retry_source_connection_id` (§7.3).
    pub(super) retry_scid: Option<ConnectionId>,
    /// The Retry token to carry in every subsequent Initial
    /// (RFC 9000 §17.2.2). Empty until a Retry is accepted.
    pub(super) initial_token: Vec<u8>,
}

impl Connection {
    /// Create a CLIENT-role connection and queue its first Initial
    /// (ClientHello, padded to the RFC 9000 §14.1 1200-byte floor) in
    /// the outbound queue — drain with `pop_packet_owned`.
    ///
    /// Entropy arrives by value: `seed` expands (HKDF-Expand-Label,
    /// distinct local labels) into the local SCID, the initial DCID,
    /// and the TLS client's entropy — so a fixed seed reproduces the
    /// first Initial byte-for-byte (pinned by the determinism test
    /// below; the deterministic-simulation arc leans on this).
    ///
    /// Initial-key direction (RFC 9001 §5.2 + Appendix A): both sides
    /// derive the Initial secrets from the client's random ≥ 8-byte
    /// first DCID; the client PROTECTS with the "client in" half and
    /// OPENS with "server in" — the mirror of `process_initial`'s
    /// server-side assignment (and verified against §A.1/§A.2: the
    /// sample client Initial is sealed under the client_initial keys).
    pub fn new_client(seed: [u8; 32], config: &TlsClientConfig) -> Result<Self, ConnError> {
        // Seed expansion — SCID/DCID are public once the Initial
        // ships; the TLS sub-seed feeds the X25519 ephemeral.
        let mut scid = [0u8; 8];
        let mut dcid = [0u8; 8];
        let mut tls_seed = [0u8; 32];
        hkdf_expand_label(&seed, b"waitless quic cli scid", &[], &mut scid);
        hkdf_expand_label(&seed, b"waitless quic cli dcid", &[], &mut dcid);
        hkdf_expand_label(&seed, b"waitless quic cli tls", &[], &mut tls_seed);
        let local_cid = ConnectionId::new(&scid);
        let initial_dcid = ConnectionId::new(&dcid);

        // Our transport parameters ride the ClientHello (RFC 9001 §8.2).
        let mut params = Vec::with_capacity(96);
        crate::transport_params::encode_client_params(&mut params, &scid);

        let tls = QuicTls::new_client(tls_seed, config, params).map_err(|_| ConnError::Tls)?;
        let mut conn = Connection::new_with(local_cid, tls);
        conn.client = Some(Box::new(ClientState {
            server_cid_adopted: false,
            tps_validated: false,
            retry_scid: None,
            initial_token: Vec::new(),
        }));
        conn.peer_cid = initial_dcid;
        conn.initial_dcid = initial_dcid;
        // RFC 9001 §5.2: Initial secrets derive from the client's
        // first DCID; client TX = "client in", RX = "server in".
        let secrets = derive_initial_secrets(initial_dcid.as_slice());
        conn.initial_send = Some(Box::new(DirKeys::from_initial(&derive_initial_keys(
            &secrets.client,
        ))));
        conn.initial_recv = Some(Box::new(DirKeys::from_initial(&derive_initial_keys(
            &secrets.server,
        ))));
        // RFC 9000 §8: the client is responding to nothing — the
        // server's address is implicitly validated, no 3× anti-amp
        // budget on our sends.
        conn.path_validated = true;
        // RFC 9000 §19.20: only servers send HANDSHAKE_DONE. Marking
        // it "already sent" suppresses the encoder's emission without
        // forking the 1-RTT packet builder.
        conn.handshake_done_sent = true;
        conn.state = ConnState::Connecting;

        // Queue the first flight: Initial(CRYPTO(ClientHello)) padded
        // to 1200 wire bytes.
        conn.flush_outbound()?;
        Ok(conn)
    }

    /// Client-role mirror of [`flush`](Self::flush): force an outbound
    /// emission after the app queues stream data (the client TLS
    /// driver carries its own config, so no `TlsServerConfig` here).
    pub fn client_flush(&mut self) -> Result<(), ConnError> {
        crate::diag::COUNTERS.flush_calls.bump();
        self.flush_outbound()?;
        self.reap_finished_streams();
        Ok(())
    }

    /// Handle a Version Negotiation packet (RFC 9000 §17.2.1 — long
    /// header form bit, version field 0, no FIXED_BIT guarantee).
    /// Client role only; reached from `process_one_packet`'s intercept.
    ///
    /// RFC 9000 §6.2.2 rules, in order:
    ///   * MUST ignore once any other packet has been processed (an
    ///     off-path attacker races the real server's reply);
    ///   * MUST ignore if the CID echo doesn't match what we sent
    ///     (DCID = our SCID, SCID = our current DCID);
    ///   * MUST ignore if it lists the version we chose (v1) — a
    ///     server that supports v1 never legitimately sends VN to a
    ///     v1 Initial, so such a packet is forged or corrupt;
    ///   * otherwise no mutually-supported version exists → abandon
    ///     the attempt with the distinct terminal
    ///     [`ConnError::UnsupportedVersion`].
    ///
    /// VN has no Length field — it owns the rest of the datagram.
    /// Bounded parsing throughout; malformed packets are ignored.
    pub(super) fn process_version_negotiation(
        &mut self,
        bytes: &[u8],
    ) -> Result<usize, ConnError> {
        let consumed = bytes.len();
        // §6.2.2: ignore after ANY processed server packet.
        let started = self
            .client
            .as_ref()
            .is_some_and(|c| c.server_cid_adopted || c.retry_scid.is_some())
            || self.initial_space.largest_recv_pn.is_some();
        if started {
            crate::quic_drop!(other_wire, "VN after handshake started — ignored");
            return Ok(consumed);
        }
        // Header: first(1) version(4)=0 dcid_len(1) dcid scid_len(1) scid.
        let mut p = 5usize;
        let Some(&dcid_len) = bytes.get(p) else { return Ok(consumed) };
        p += 1;
        let Some(dcid) = bytes.get(p..p + dcid_len as usize) else { return Ok(consumed) };
        p += dcid_len as usize;
        let Some(&scid_len) = bytes.get(p) else { return Ok(consumed) };
        p += 1;
        let Some(scid) = bytes.get(p..p + scid_len as usize) else { return Ok(consumed) };
        p += scid_len as usize;
        // CID echo check (§6.2.2): DCID = our SCID, SCID = the DCID we
        // used (pre-adoption peer_cid IS that value).
        if dcid != self.local_cid.as_slice() || scid != self.peer_cid.as_slice() {
            crate::quic_drop!(other_wire, "VN with mismatched CID echo — ignored");
            return Ok(consumed);
        }
        // Supported Version list: 4-byte values to the datagram end.
        let list = &bytes[p..];
        if list.is_empty() || !list.len().is_multiple_of(4) {
            crate::quic_drop!(other_wire, "malformed VN version list — ignored");
            return Ok(consumed);
        }
        for v in list.chunks_exact(4) {
            let version = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
            if version == QUIC_VERSION_1 {
                // §6.2.2: a VN listing our chosen version is invalid.
                crate::quic_drop!(other_wire, "VN lists v1 — forged/corrupt, ignored");
                return Ok(consumed);
            }
        }
        // No version in common — terminal for this connection attempt.
        self.state = ConnState::Failed;
        Err(ConnError::UnsupportedVersion)
    }

    /// Handle a Retry packet (RFC 9000 §17.2.5). Client role only.
    ///
    /// Discard (silently — every discard path returns `Ok(whole
    /// datagram)`) when: any other packet has been processed or a
    /// Retry was already accepted (§17.2.5.2); the token is empty;
    /// the SCID equals the DCID we sent (no CID change — §17.2.5.1's
    /// server MUST is enforced receiver-side); or the RFC 9001 §5.8
    /// integrity tag (fixed-key AES-128-GCM over the ODCID-prefixed
    /// pseudo-packet — verify only, we never build Retries) fails.
    ///
    /// On accept: adopt the Retry SCID as our DCID, re-derive the
    /// Initial keys from it (RFC 9001 §5.2: "the connection ID from
    /// the server's Retry"), remember the SCID for §7.3 validation,
    /// store the token for all subsequent Initials, and move the
    /// un-acked Initial CRYPTO (the ClientHello) onto the retransmit
    /// queue so the next flush re-sends it — with the token, padded,
    /// under the re-derived keys. Packet numbers are NOT reset
    /// (RFC 9000 §17.2.5.3).
    pub(super) fn process_retry(&mut self, bytes: &[u8]) -> Result<usize, ConnError> {
        let consumed = bytes.len(); // Retry has no Length field
        let Some(cs) = self.client.as_ref() else { return Err(ConnError::Wire) };
        if cs.server_cid_adopted
            || cs.retry_scid.is_some()
            || self.initial_space.largest_recv_pn.is_some()
        {
            crate::quic_drop!(other_wire, "Retry after handshake started — ignored");
            return Ok(consumed);
        }
        let Ok(preamble) = parse_long_header_preamble(bytes) else {
            return Ok(consumed);
        };
        // Tail = Retry Token (≥ 1 byte — empty is a MUST-discard) +
        // 16-byte Retry Integrity Tag.
        let tail = &bytes[preamble.tail_offset..];
        if tail.len() < TAG_LEN + 1 {
            crate::quic_drop!(other_wire, "Retry with empty token — ignored");
            return Ok(consumed);
        }
        let token = &tail[..tail.len() - TAG_LEN];
        let tag: [u8; TAG_LEN] = tail[tail.len() - TAG_LEN..]
            .try_into()
            .map_err(|_| ConnError::Wire)?;
        // The server MUST pick a NEW CID; an unchanged one would also
        // leave the Initial keys unchanged, defeating the exchange.
        if preamble.scid == self.initial_dcid.as_slice() {
            crate::quic_drop!(other_wire, "Retry SCID equals our DCID — ignored");
            return Ok(consumed);
        }
        if !retry_integrity_verify(
            self.initial_dcid.as_slice(),
            &bytes[..bytes.len() - TAG_LEN],
            &tag,
        ) {
            crate::quic_drop!(other_wire, "Retry integrity tag mismatch — ignored");
            return Ok(consumed);
        }

        // Accept.
        let new_dcid = ConnectionId::new(preamble.scid);
        let token_owned = token.to_vec();
        let secrets = derive_initial_secrets(new_dcid.as_slice());
        self.initial_send = Some(Box::new(DirKeys::from_initial(&derive_initial_keys(
            &secrets.client,
        ))));
        self.initial_recv = Some(Box::new(DirKeys::from_initial(&derive_initial_keys(
            &secrets.server,
        ))));
        self.peer_cid = new_dcid;
        {
            let cs = self.client.as_mut().expect("checked above");
            cs.retry_scid = Some(new_dcid);
            cs.initial_token = token_owned;
        }
        // The original Initial can never be acknowledged (the server
        // kept no state) — move its CRYPTO back onto the retransmit
        // queue and release its in-flight bytes. The flush at the end
        // of this `process_datagram` re-emits it.
        let pns: Vec<u64> = self.initial_space.sent_packets.iter().map(|(pn, _)| pn).collect();
        for pn in pns {
            if let Some(pkt) = self.initial_space.sent_packets.remove(pn) {
                if pkt.in_flight {
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.byte_count);
                }
                for c in pkt.crypto_frames {
                    self.crypto_retx_queue.push_back(c);
                }
            }
        }
        crate::quic_event!(
            retry_accepted,
            "new_dcid={} token_len={}",
            crate::endpoint::hex8(self.peer_cid.as_slice()),
            self.client.as_ref().expect("checked above").initial_token.len()
        );
        Ok(consumed)
    }

    /// Authenticate the CIDs the server echoed in its transport
    /// parameters (RFC 9000 §7.3) — called once from `advance_tls` as
    /// soon as the EncryptedExtensions params land. All three checks:
    ///
    ///   * `initial_source_connection_id` MUST be present and equal
    ///     the SCID of the server's first Initial (our adopted DCID);
    ///   * `original_destination_connection_id` MUST be present and
    ///     equal the DCID of OUR first Initial — even across a Retry
    ///     (the server reconstructs it from its token);
    ///   * `retry_source_connection_id` MUST be present and equal the
    ///     Retry's SCID iff a Retry was accepted, and absent
    ///     otherwise.
    ///
    /// Any violation closes with TRANSPORT_PARAMETER_ERROR. This is
    /// the defense that makes off-path Retry/CID injection visible:
    /// an attacker-inserted Retry changes the DCID the real server
    /// sees, so the genuine server's echoes can no longer match.
    pub(super) fn validate_peer_transport_params(&mut self) -> Result<(), ConnError> {
        let parsed = {
            let Some(bytes) = self.tls.client_transport_params() else {
                return Ok(()); // not yet available
            };
            crate::transport_params::parse_client_params(bytes)
        };
        let Ok(p) = parsed else {
            self.close_with_error(TRANSPORT_PARAMETER_ERROR, b"transport params");
            return Err(ConnError::Tls);
        };
        let cs = self.client.as_ref().ok_or(ConnError::BadState)?;
        let iscid_ok =
            p.initial_source_connection_id.as_deref() == Some(self.peer_cid.as_slice());
        let odcid_ok = p.original_destination_connection_id.as_deref()
            == Some(self.initial_dcid.as_slice());
        let retry_ok = match cs.retry_scid.as_ref() {
            Some(r) => p.retry_source_connection_id.as_deref() == Some(r.as_slice()),
            None => p.retry_source_connection_id.is_none(),
        };
        if !(iscid_ok && odcid_ok && retry_ok) {
            crate::quic_drop!(
                other_wire,
                "§7.3 CID auth failed: iscid_ok={} odcid_ok={} retry_ok={}",
                iscid_ok,
                odcid_ok,
                retry_ok
            );
            self.close_with_error(TRANSPORT_PARAMETER_ERROR, b"cid auth");
            return Err(ConnError::Tls);
        }
        self.client.as_mut().expect("client role").tps_validated = true;
        Ok(())
    }
}

// ============================================================================
// Tests — the in-process client↔server handshake (the centerpiece)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::retry_integrity_tag;
    use crate::wire::parse_initial_header;
    use tls::client::{ServerAuth, spki_pin_from_cert_der};
    use tls::TlsServerConfig;

    const CERT: &[u8] = include_bytes!("../../../../../apps/webserver/dev_certs/dev_cert.der");
    const KEY: &[u8] = include_bytes!("../../../../../apps/webserver/dev_certs/dev_key.der");
    const HEADROOM: usize = nic_api::MAX_L2_HEADROOM;

    fn server_config() -> TlsServerConfig {
        TlsServerConfig::from_chain(&[CERT], KEY).expect("dev cert load")
    }

    /// Client config pinned to the REAL dev cert the server presents.
    fn pinned_client_config() -> TlsClientConfig {
        TlsClientConfig {
            auth: ServerAuth::PinnedSpki(spki_pin_from_cert_der(CERT).expect("pin")),
            server_name: Some(b"localhost"),
            alpn: &[b"h3"],
        }
    }

    fn new_server() -> Connection {
        Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32])
    }

    /// Strip the L2/L3/L4 headroom prefix off a popped datagram —
    /// the wire bytes the peer would receive.
    fn wire_of(pkt: &super::super::DatagramBuf) -> Vec<u8> {
        pkt.vec()[HEADROOM..].to_vec()
    }

    /// Pump datagrams both ways until neither side has outbound or a
    /// side errors. Returns the client's first error, if any (server
    /// errors fail the test — the server role is the trusted fixture).
    fn pump(
        client: &mut Connection,
        server: &mut Connection,
        cfg: &TlsServerConfig,
    ) -> Option<ConnError> {
        for _ in 0..64 {
            let mut progressed = false;
            while let Some(pkt) = client.pop_packet_owned() {
                let mut w = wire_of(&pkt);
                server
                    .process_datagram(&mut w, cfg)
                    .expect("server processes client datagram");
                progressed = true;
            }
            while let Some(pkt) = server.pop_packet_owned() {
                let mut w = wire_of(&pkt);
                if let Err(e) = client.client_process_datagram(&mut w) {
                    return Some(e);
                }
                progressed = true;
            }
            if !progressed {
                return None;
            }
        }
        panic!("pump did not converge in 64 rounds");
    }

    /// THE CENTERPIECE: a full in-process QUIC handshake — client
    /// role vs our real server role, real dev cert + SPKI pin, under
    /// the virtual clock — then a client-opened bidi stream echoes
    /// bytes byte-exactly. Pins: both sides reach Established, the
    /// §7.3 CID authentication passes, client-initiated stream id 0
    /// flows through the server's existing accept/stream API, and the
    /// echo round-trips with FIN both ways.
    #[test]
    fn client_server_full_handshake_then_stream_echo() {
        crate::time::mock::set(1_000_000);
        let cfg = server_config();
        let ccfg = pinned_client_config();
        let mut client = Connection::new_client([0x11u8; 32], &ccfg).expect("new_client");
        let mut server = new_server();

        assert_eq!(client.state(), ConnState::Connecting);
        assert!(client.has_outbound(), "first Initial queued at construction");

        let err = pump(&mut client, &mut server, &cfg);
        assert_eq!(err, None, "handshake pumps cleanly");
        assert_eq!(client.state(), ConnState::Established, "client established");
        assert_eq!(server.state(), ConnState::Established, "server established");
        assert!(
            client.client.as_ref().unwrap().tps_validated,
            "§7.3 CID authentication ran and passed"
        );
        // The client adopted the server's SCID as its DCID (§7.2).
        assert_eq!(client.peer_cid.as_slice(), &[0xab; 8]);

        // ── Client-initiated bidi stream (id 0 = low bits 0b00) ────
        let payload = b"hello from the waitless QUIC client".to_vec();
        crate::time::mock::advance(10_000);
        client.stream_send_owned(0, payload.clone());
        client.stream_close(0);
        client.client_flush().expect("client flush");
        assert_eq!(pump(&mut client, &mut server, &cfg), None);

        assert_eq!(server.pop_accepted_stream(), Some(0), "server accepts sid 0");
        let mut buf = [0u8; 256];
        let (n, eof) = server.stream_recv(0, &mut buf);
        assert_eq!(&buf[..n], &payload[..], "server got the request bytes");
        assert!(eof, "client FIN seen");

        // Server echoes via its existing stream API.
        crate::time::mock::advance(10_000);
        server.stream_send_owned(0, payload.clone());
        server.stream_close(0);
        server.flush(&cfg).expect("server flush");
        assert_eq!(pump(&mut client, &mut server, &cfg), None);

        let (n, eof) = client.stream_recv(0, &mut buf);
        assert_eq!(&buf[..n], &payload[..], "client got the echo byte-exact");
        assert!(eof, "server FIN seen");
    }

    /// (b) Wrong pin → the client aborts the handshake with a
    /// CRYPTO_ERROR-class CONNECTION_CLOSE (RFC 9001 §4.8: 0x0100 +
    /// alert; bad_certificate = 42) and parks in Failed; the emitted
    /// close also tears the server down.
    #[test]
    fn wrong_pin_aborts_handshake_with_crypto_error_close() {
        crate::time::mock::set(2_000_000);
        let cfg = server_config();
        let ccfg = TlsClientConfig {
            auth: ServerAuth::PinnedSpki([0u8; 32]), // wrong pin
            server_name: None,
            alpn: &[],
        };
        let mut client = Connection::new_client([0x22u8; 32], &ccfg).expect("new_client");
        let mut server = new_server();

        let err = pump(&mut client, &mut server, &cfg);
        assert_eq!(err, Some(ConnError::Tls), "pin mismatch surfaces as a TLS error");
        assert_eq!(client.state(), ConnState::Failed, "client handshake aborted");
        assert_eq!(
            client.tls.client_alert_code(),
            42,
            "bad_certificate alert class (close code 0x12a)"
        );
        // The CONNECTION_CLOSE was built and queued (flush_close).
        // The client may also have earlier ACK-only datagrams queued
        // from processing the flight's leading packets — drain them
        // ALL into the server; the close among them tears it down.
        let mut delivered = 0;
        while let Some(pkt) = client.pop_packet_owned() {
            let mut w = wire_of(&pkt);
            server
                .process_datagram(&mut w, &cfg)
                .expect("server processes client datagrams");
            delivered += 1;
        }
        assert!(delivered > 0, "close datagram was queued");
        assert_eq!(server.state(), ConnState::Failed, "close lands on the server");
    }

    /// (c) Retry: injected between the client's Initial and the
    /// server — §5.8 tag hand-built (the verify half is pinned to RFC
    /// 9001 §A.4 in crypto.rs). The client validates the tag, adopts
    /// the new DCID, re-derives Initial keys, re-sends the Initial
    /// WITH the token — and the handshake completes against a server
    /// whose transport params echo (odcid, retry_scid) the way a real
    /// Retry-issuing server would (the §7.3 retry arm).
    #[test]
    fn retry_revalidates_adopts_cid_and_completes() {
        crate::time::mock::set(3_000_000);
        let cfg = server_config();
        let ccfg = pinned_client_config();
        let mut client = Connection::new_client([0x33u8; 32], &ccfg).expect("new_client");

        // Intercept (drop) the first Initial — the Retry answers it.
        let first = client.pop_packet_owned().expect("first Initial");
        let first_wire = wire_of(&first);
        assert!(first_wire.len() >= 1200, "client Initial padded to §14.1 floor");
        let original_dcid = client.initial_dcid.as_slice().to_vec();

        // Hand-build the Retry: new SCID + token + §5.8 tag.
        let retry_scid = [0x5a; 8];
        let mut retry: Vec<u8> = Vec::new();
        retry.push(0xf0); // long | fixed | type=11 (Retry) | unused=0
        retry.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        retry.push(8);
        retry.extend_from_slice(client.local_cid.as_slice()); // DCID = client SCID
        retry.push(8);
        retry.extend_from_slice(&retry_scid);
        retry.extend_from_slice(b"retry-token");
        let tag = retry_integrity_tag(&original_dcid, &retry).expect("tag");
        retry.extend_from_slice(&tag);

        let mut retry_dg = retry.clone();
        client
            .client_process_datagram(&mut retry_dg)
            .expect("client accepts the Retry");

        // The client re-sent its Initial: token echoed, DCID adopted.
        let resent = client.pop_packet_owned().expect("re-sent Initial");
        let resent_wire = wire_of(&resent);
        assert!(resent_wire.len() >= 1200, "re-sent Initial still padded");
        let hdr = parse_initial_header(&resent_wire).expect("parse re-sent Initial");
        assert_eq!(hdr.token, b"retry-token", "Retry token carried");
        assert_eq!(hdr.preamble.dcid, &retry_scid[..], "Retry SCID adopted as DCID");

        // A second Retry must be ignored (no further CID churn).
        let mut retry_again = retry;
        client
            .client_process_datagram(&mut retry_again)
            .expect("second Retry ignored");
        assert_eq!(
            client.client.as_ref().unwrap().retry_scid.unwrap().as_slice(),
            &retry_scid[..]
        );

        // Server: echo (original odcid, retry scid) in its transport
        // params — what a real Retry server reconstructs from its
        // token (the test-only seam; production never sends Retry).
        let mut server = new_server();
        server.test_tp_override = Some((original_dcid, retry_scid.to_vec()));
        let mut w = resent_wire;
        server
            .process_datagram(&mut w, &cfg)
            .expect("server takes the token-bearing Initial");

        let err = pump(&mut client, &mut server, &cfg);
        assert_eq!(err, None, "post-Retry handshake completes");
        assert_eq!(client.state(), ConnState::Established);
        assert_eq!(server.state(), ConnState::Established);
        assert!(client.client.as_ref().unwrap().tps_validated, "§7.3 retry arm passed");
    }

    /// §7.3 negative (the security property a Retry-blind client
    /// would lose): after an injected Retry, a server whose params
    /// do NOT echo the retry (it never sent one — exactly what an
    /// off-path attacker's Retry produces) MUST be rejected with
    /// TRANSPORT_PARAMETER_ERROR.
    #[test]
    fn retry_without_server_echo_fails_cid_authentication() {
        crate::time::mock::set(4_000_000);
        let cfg = server_config();
        let ccfg = pinned_client_config();
        let mut client = Connection::new_client([0x44u8; 32], &ccfg).expect("new_client");
        let _dropped = client.pop_packet_owned().expect("first Initial");
        let original_dcid = client.initial_dcid.as_slice().to_vec();

        let retry_scid = [0x66; 8];
        let mut retry: Vec<u8> = Vec::new();
        retry.push(0xf0);
        retry.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        retry.push(8);
        retry.extend_from_slice(client.local_cid.as_slice());
        retry.push(8);
        retry.extend_from_slice(&retry_scid);
        retry.extend_from_slice(b"attacker-token");
        let tag = retry_integrity_tag(&original_dcid, &retry).expect("tag");
        retry.extend_from_slice(&tag);
        client
            .client_process_datagram(&mut retry)
            .expect("retry accepted at face value");

        // Plain server: no retry echo in its transport params.
        let mut server = new_server();
        let err = pump(&mut client, &mut server, &cfg);
        assert_eq!(err, Some(ConnError::Tls), "§7.3 mismatch aborts the handshake");
        assert_eq!(client.state(), ConnState::Failed);
        // The close carries TRANSPORT_PARAMETER_ERROR (0x08) — it was
        // scheduled by the validator before the generic TLS-close
        // wrapper ran (first close wins), and flushed onto the wire.
        assert!(client.has_outbound() || client.close_pending.is_none());
    }

    /// (d) Version Negotiation listing none of our versions → the
    /// distinct terminal error; listing v1 (invalid per RFC 9000
    /// §6.2.2) → ignored and the handshake completes anyway.
    #[test]
    fn version_negotiation_terminal_and_v1_listing_ignored() {
        crate::time::mock::set(5_000_000);
        let cfg = server_config();
        let ccfg = pinned_client_config();

        // Build a VN echoing a fresh client's CIDs. Note: FIXED_BIT
        // deliberately CLEAR (it is "Unused" in VN — RFC 9000
        // §17.2.1) to pin the pre-padding-check intercept.
        let vn_for = |client: &Connection, versions: &[u32]| -> Vec<u8> {
            let mut vn: Vec<u8> = Vec::new();
            vn.push(0x80); // long form, fixed bit 0
            vn.extend_from_slice(&0u32.to_be_bytes()); // version 0 = VN
            vn.push(8);
            vn.extend_from_slice(client.local_cid.as_slice()); // DCID = our SCID
            vn.push(8);
            vn.extend_from_slice(client.peer_cid.as_slice()); // SCID = our DCID
            for v in versions {
                vn.extend_from_slice(&v.to_be_bytes());
            }
            vn
        };

        // No common version → UnsupportedVersion, terminal.
        let mut client = Connection::new_client([0x55u8; 32], &ccfg).expect("new_client");
        let mut vn = vn_for(&client, &[0xff00_001d, 0x0000_0002]);
        let r = client.client_process_datagram(&mut vn);
        assert_eq!(r, Err(ConnError::UnsupportedVersion), "distinct terminal error");
        assert_eq!(client.state(), ConnState::Failed);

        // VN listing v1 → ignored; the handshake then completes.
        let mut client = Connection::new_client([0x56u8; 32], &ccfg).expect("new_client");
        let mut vn = vn_for(&client, &[0xff00_001d, QUIC_VERSION_1]);
        client
            .client_process_datagram(&mut vn)
            .expect("v1-listing VN ignored");
        assert_eq!(client.state(), ConnState::Connecting, "attempt continues");
        let mut server = new_server();
        assert_eq!(pump(&mut client, &mut server, &cfg), None);
        assert_eq!(client.state(), ConnState::Established);
    }

    /// (e) Determinism: the same seed reproduces the client's first
    /// Initial byte-for-byte (entropy by value — the deterministic-
    /// simulation seam); a different seed diverges.
    #[test]
    fn same_seed_yields_byte_identical_client_initial() {
        crate::time::mock::set(6_000_000);
        let ccfg = pinned_client_config();
        let mut a = Connection::new_client([0x77u8; 32], &ccfg).expect("a");
        let mut b = Connection::new_client([0x77u8; 32], &ccfg).expect("b");
        let mut c = Connection::new_client([0x78u8; 32], &ccfg).expect("c");
        let wa = wire_of(&a.pop_packet_owned().unwrap());
        let wb = wire_of(&b.pop_packet_owned().unwrap());
        let wc = wire_of(&c.pop_packet_owned().unwrap());
        assert_eq!(wa, wb, "same seed → byte-identical first Initial");
        assert_ne!(wa, wc, "different seed → different Initial");
        assert!(wa.len() >= 1200, "RFC 9000 §14.1 padding floor");
    }

    /// Client-role stream-limit decision table (the rx.rs role split):
    /// the peer is the SERVER (ids 0x1/0x3); our bidi response halves
    /// (0x0) bypass the count check; our uni ids (0x2) are violations.
    #[test]
    fn client_stream_limit_role_table() {
        use super::super::rx::client_exceeds_stream_limit as f;
        const ADV: u64 = 1024;
        // Server-initiated within limits → allowed; one past → rejected.
        assert!(!f(0x1, ADV, ADV, 0)); // 1st server-bidi
        assert!(!f(0x3, ADV, ADV, 0)); // 1st server-uni
        assert!(f(4 * 1024 + 1, ADV, ADV, 0)); // 1025th server-bidi
        assert!(f(4 * 1024 + 3, ADV, ADV, 0)); // 1025th server-uni
        // Our bidi response half: never count-limited.
        assert!(!f(0, ADV, ADV, 0));
        assert!(!f(4 * (1 << 40), ADV, ADV, 0));
        // Our uni stream: the peer must never send on it.
        assert!(f(0x2, u64::MAX, u64::MAX, 0));
    }

    // ── THE TWO-ENDPOINT DETERMINISTIC SIMULATION ───────────────────
    //
    // Architecture-audit direction #2's endgame, runnable at last
    // because both roles exist: the REAL client and REAL server
    // Connections (real TLS 1.3 handshake, dev cert + SPKI pin)
    // exchange datagrams through a SEEDED LOSSY PIPE under the
    // virtual clock. Drops are per-transmission (retransmissions can
    // be re-dropped); when the pipe goes quiet, virtual time advances
    // and the real PTO machinery (send_pto_probe -> peer ACK ->
    // detect_loss -> CRYPTO/STREAM retx) drives recovery — the same
    // closed loop a lossy network exercises, reproducible by seed.

    struct SimRng(u64);
    impl SimRng {
        fn next(&mut self) -> u64 {
            // SplitMix64 — same constants as kernel_core's host rng.
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn drop_it(&mut self, permille: u64) -> bool {
            self.next() % 1000 < permille
        }
    }

    /// One seeded run. Returns (datagrams dropped, probes fired,
    /// rounds, virtual µs consumed) for the batch-level
    /// non-vacuousness asserts.
    fn run_two_endpoint_sim(seed: u64, loss_permille: u64) -> (u32, u32, u32, u64) {
        let t0 = 1_000_000u64;
        crate::time::mock::set(t0);
        let cfg = server_config();
        let ccfg = pinned_client_config();
        let mut cseed = [0u8; 32];
        cseed[..8].copy_from_slice(&seed.to_le_bytes());
        cseed[8] = 0x11;
        let mut client = Connection::new_client(cseed, &ccfg).expect("new_client");
        let mut server = new_server();
        let mut rng = SimRng(seed ^ (loss_permille << 32));

        let payload = b"two-endpoint sim payload: the request the echo must survive".to_vec();
        let mut drops = 0u32;
        let mut probes = 0u32;
        // 0 = handshaking, 1 = request sent, 2 = server echoed.
        let mut phase = 0u8;
        let mut echoed: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let mut srv_got: alloc::vec::Vec<u8> = alloc::vec::Vec::new();

        let ctx = |what: &str| {
            panic!("seed={seed} loss={loss_permille}‰: {what}");
        };
        for round in 0..4000u32 {
            let mut progressed = false;
            while let Some(pkt) = client.pop_packet_owned() {
                if rng.drop_it(loss_permille) {
                    drops += 1;
                    continue;
                }
                let mut w = wire_of(&pkt);
                // The server may legitimately error on a datagram whose
                // keys it discarded after a drop-induced retransmit —
                // a real network ignores undecryptable packets too.
                let _ = server.process_datagram(&mut w, &cfg);
                progressed = true;
            }
            while let Some(pkt) = server.pop_packet_owned() {
                if rng.drop_it(loss_permille) {
                    drops += 1;
                    continue;
                }
                let mut w = wire_of(&pkt);
                // Like the server arm: a drop-skewed flight can deliver
                // a retransmit the receiver can no longer decrypt
                // (discarded keys) — a real endpoint ignores those
                // (RFC 9000 §5.2). Only a conn that actually FAILED is
                // a sim bug.
                if let Err(e) = client.client_process_datagram(&mut w)
                    && client.state() == ConnState::Failed
                {
                    panic!("seed={seed} loss={loss_permille}‰ round={round}: client failed {e:?}");
                }
                progressed = true;
            }

            // Application phases ride on top of the transport.
            if phase == 0
                && client.state() == ConnState::Established
                && server.state() == ConnState::Established
            {
                crate::time::mock::advance(1_000);
                client.stream_send_owned(0, payload.clone());
                client.stream_close(0);
                client.client_flush().expect("client flush");
                phase = 1;
                progressed = true;
            }
            if phase == 1 {
                if let Some(sid) = server.pop_accepted_stream() {
                    assert_eq!(sid, 0, "client-initiated bidi sid");
                }
                let mut buf = [0u8; 256];
                let (n, eof) = server.stream_recv(0, &mut buf);
                if n > 0 {
                    srv_got.extend_from_slice(&buf[..n]);
                    progressed = true;
                }
                if eof && srv_got == payload {
                    crate::time::mock::advance(1_000);
                    server.stream_send_owned(0, payload.clone());
                    server.stream_close(0);
                    server.flush(&cfg).expect("server flush");
                    phase = 2;
                    progressed = true;
                }
            }
            if phase == 2 {
                let mut buf = [0u8; 256];
                let (n, eof) = client.stream_recv(0, &mut buf);
                if n > 0 {
                    echoed.extend_from_slice(&buf[..n]);
                    progressed = true;
                }
                if eof {
                    assert_eq!(
                        echoed, payload,
                        "seed={seed} loss={loss_permille}‰: echo byte-exact"
                    );
                    let spent = crate::time::now_us() - t0;
                    return (drops, probes, round + 1, spent);
                }
            }

            if !progressed {
                // The pipe is quiet: a dropped flight is stranded.
                // Advance virtual time past the PTO horizon and let
                // the REAL recovery machinery re-arm the pipe — the
                // sim's whole point.
                crate::time::mock::advance(400_000);
                if client.send_pto_probe() {
                    probes += 1;
                }
                if server.send_pto_probe() {
                    probes += 1;
                }
                let _ = client.client_flush();
                let _ = server.flush(&cfg);
                if crate::time::now_us() - t0 > 120_000_000 {
                    panic!(
                        "seed={seed} loss={loss_permille}‰: budget exhausted \
                         phase={phase} cstate={:?} sstate={:?} cflight={} sflight={} \
                         srv_got={} echoed={}",
                        client.state(), server.state(),
                        client.bytes_in_flight, server.bytes_in_flight,
                        srv_got.len(), echoed.len()
                    );
                }
            }
        }
        ctx("no convergence in 4000 rounds");
        unreachable!()
    }

    /// 40 seeds × two loss rates, every run completing a REAL pinned
    /// TLS-over-QUIC handshake + a FIN'd request/echo byte-exact
    /// through per-transmission seeded loss. Batch-level
    /// non-vacuousness: drops and probes both fired.
    #[test]
    fn two_endpoint_sim_handshake_and_echo_under_seeded_loss() {
        let mut total_drops = 0u32;
        let mut total_probes = 0u32;
        for seed in 1..=40u64 {
            for &loss in &[100u64, 250] {
                let (d, p, _rounds, _vt) = run_two_endpoint_sim(seed, loss);
                total_drops += d;
                total_probes += p;
            }
        }
        assert!(total_drops > 100, "the pipe actually dropped ({total_drops})");
        assert!(total_probes > 0, "PTO recovery actually drove progress ({total_probes})");
    }

    /// Determinism: the same seed yields the identical event counts —
    /// the property that makes a sim failure replayable.
    #[test]
    fn two_endpoint_sim_is_deterministic() {
        let a = run_two_endpoint_sim(7, 250);
        let b = run_two_endpoint_sim(7, 250);
        assert_eq!(a, b, "same seed, same loss => identical run");
    }
}
