// crates/proto/quic/src/conn/cfg.rs — host-side test fixtures + the
// `Connection`-level integration tests.
//
// Lives behind `#[cfg(test)]` so the dev-cert byte slices are
// only compiled when `bazel test` builds with std. The
// `dev_config()` / `big_chain_config()` helpers feed the tests
// below; the `include_bytes!` paths step up FIVE levels
// (`../../../../../`) from `crates/proto/quic/src/conn/` to reach
// `apps/webserver/dev_certs/`, one more `../` than the original
// flat `conn.rs` needed.
//
// The `mod cfg;` include in `conn/mod.rs` is already
// `#[cfg(test)]`; an inner `#![cfg(test)]` here would trip
// `clippy::duplicated-attributes`.

use super::*;
use crate::crypto::{
    HP_SAMPLE_LEN, TAG_LEN, apply_hp_mask, derive_initial_keys, derive_initial_secrets,
    packet_nonce,
};
use crate::frame::write_crypto;
use crate::wire::{
    QUIC_VERSION_1, long_packet_type, parse_initial_header, parse_long_header_preamble,
    read_varint, write_varint,
};
use tls::TlsServerConfig;

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

/// The client-chosen DCID / SCID the synthetic Initial below
/// carries. The server derives its Initial keys from the DCID
/// (RFC 9001 §5.2) and echoes the SCID back as its reply's DCID.
const CLIENT_DCID: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xca, 0xfe];
const CLIENT_SCID: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

/// Build a sealed, header-protected client Initial packet
/// carrying a real TLS ClientHello — the synthetic inbound
/// datagram both handshake tests drive a fresh server
/// `Connection` with. The packet is padded past 1200 bytes so
/// RFC 9000 §14.1 is satisfied and the server's anti-amplification
/// budget (§8.1.2) is large enough for its full reply flight.
fn make_client_initial() -> alloc::vec::Vec<u8> {
    use tls::handshake::{
        LEGACY_VERSION_TLS12, VERSION_TLS13, cipher_suite, ext_type, msg_type as mt, named_group,
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
    write_ext(
        &mut ext,
        ext_type::SUPPORTED_GROUPS,
        &[0x00, 0x02, 0x00, 0x1d],
    );
    let mut ks = Vec::<u8>::new();
    ks.extend_from_slice(&36u16.to_be_bytes());
    ks.extend_from_slice(&named_group::X25519.to_be_bytes());
    ks.extend_from_slice(&32u16.to_be_bytes());
    ks.extend_from_slice(&client_pub);
    write_ext(&mut ext, ext_type::KEY_SHARE, &ks);
    write_ext(
        &mut ext,
        ext_type::SIGNATURE_ALGORITHMS,
        &[0x00, 0x02, 0x04, 0x03],
    );

    let mut ch_body = Vec::<u8>::new();
    ch_body.extend_from_slice(&LEGACY_VERSION_TLS12.to_be_bytes());
    ch_body.extend_from_slice(&[0x11u8; 32]);
    ch_body.push(0);
    ch_body.extend_from_slice(&2u16.to_be_bytes());
    ch_body.extend_from_slice(&cipher_suite::TLS_AES_128_GCM_SHA256.to_be_bytes());
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

    // 2. Wrap ChMsg in a CRYPTO frame, then pad so the entire
    //    UDP datagram is ≥ 1200 bytes — RFC 9000 §14.1 requires
    //    client Initials to be padded to that size, and the
    //    server's anti-amplification check (§8.1.2) limits its
    //    reply to 3× received bytes. Without padding here the
    //    server's full flight would be throttled.
    let mut crypto_frame = alloc::vec![0u8; ch_msg.len() + 16];
    let cn = write_crypto(0, &ch_msg, &mut crypto_frame).unwrap();
    // Approximate header overhead so the post-AEAD UDP
    // datagram lands at ≥ 1200 bytes; over-estimate is fine.
    let header_overhead = 1 + 4 + 1 + 8 + 1 + 8 + 1 + 4 + 4 + 16;
    let need_payload = 1200_usize.saturating_sub(header_overhead).max(cn);
    let mut padded = alloc::vec::Vec::with_capacity(need_payload);
    padded.extend_from_slice(&crypto_frame[..cn]);
    padded.resize(need_payload, 0u8); // PADDING frame = 0x00
    let payload = padded.as_slice();

    // 3. Build a sealed Initial packet using client-direction
    //    Initial keys derived from the synthetic DCID.
    let secrets = derive_initial_secrets(&CLIENT_DCID);
    let client_keys = derive_initial_keys(&secrets.client);
    let client_dirkeys = DirKeys::from_initial(&client_keys);

    let pn_length: usize = 4;
    let pn: u64 = 0;
    let length_field = (pn_length + payload.len() + TAG_LEN) as u64;

    let mut packet = Vec::<u8>::new();
    packet.push(0xc0 | ((pn_length as u8) - 1));
    packet.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
    packet.push(CLIENT_DCID.len() as u8);
    packet.extend_from_slice(&CLIENT_DCID);
    packet.push(CLIENT_SCID.len() as u8);
    packet.extend_from_slice(&CLIENT_SCID);
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
        let payload_slice = &mut packet[payload_offset..payload_offset + payload.len()];
        let tag = client_dirkeys.aead_seal(&nonce, &aad, payload_slice);
        packet[payload_offset + payload.len()..payload_offset + payload.len() + TAG_LEN]
            .copy_from_slice(&tag);
    }

    // HP protect.
    let sample_start = pn_offset + 4;
    let mut sample = [0u8; HP_SAMPLE_LEN];
    sample.copy_from_slice(&packet[sample_start..sample_start + HP_SAMPLE_LEN]);
    let mask = client_dirkeys.hp_mask(&sample);
    let (head, rest) = packet.split_at_mut(pn_offset);
    apply_hp_mask(&mut head[0], &mut rest[..pn_length], &mask, true);

    packet
}

/// End-to-end: feed a synthetic client Initial to a fresh server
/// `Connection`, confirm it emits a coalesced Initial + Handshake
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
///
/// Uses the single-cert dev config, so the server flight fits one
/// Handshake packet and Initial + Handshake coalesce into one
/// datagram. The large-chain fragmentation path has its own test
/// (`handshake_flight_fragments_across_mtu_datagrams`).
#[test]
fn end_to_end_self_handshake() {
    // 1-3. Synthetic sealed client Initial.
    let mut packet = make_client_initial();

    // 4. Drive the server-side connection with this datagram.
    let local_cid = ConnectionId::new(&[0xab; 8]);
    let mut conn = Connection::new_server(local_cid, [0x42u8; 32]);
    let cfg = dev_config();
    conn.process_datagram(&mut packet, &cfg)
        .expect("process inbound Initial");

    // The server should have moved into Connecting and queued
    // an outbound datagram with the server flight.
    assert_eq!(conn.state(), ConnState::Connecting);
    assert!(conn.has_outbound(), "server should have a reply queued");

    // 5. Drain the outbound datagram and verify both packets
    //    parse + decrypt with the *server* Initial / Handshake
    //    keys (which our connection derived).
    let secrets = derive_initial_secrets(&CLIENT_DCID);
    let pkt = conn
        .pop_packet_owned()
        .expect("server reply datagram queued");
    let reply = &pkt.vec()[nic_api::MAX_L2_HEADROOM..];
    assert!(!reply.is_empty(), "non-empty reply datagram");

    // First packet should be Initial. Re-derive server-side
    // keys from the same client_dcid and unprotect.
    let server_initial = derive_initial_keys(&secrets.server);
    let server_initial_dk = DirKeys::from_initial(&server_initial);
    let pre = parse_long_header_preamble(reply).unwrap();
    assert_eq!(pre.long_type, long_packet_type::INITIAL);
    assert_eq!(pre.dcid, &CLIENT_SCID[..]); // server echoes our SCID
    assert_eq!(pre.scid, &[0xab; 8][..]); // server's local CID
    // Continue parsing to find pn_offset.
    let initial_hdr = parse_initial_header(reply).unwrap();
    let init_total = initial_hdr.pn_offset + initial_hdr.length as usize;
    let mut init_buf = reply[..init_total].to_vec();
    let _pn = conn
        .unprotect_and_decrypt(&mut init_buf, initial_hdr.pn_offset, &server_initial_dk)
        .expect("decrypt server Initial");

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

/// Regression test for the gve HTTP/3 crash. A real
/// leaf+intermediate cert chain makes the server's TLS flight
/// (EncryptedExtensions + Certificate + CertificateVerify +
/// Finished) far exceed one QUIC packet. Before the
/// handshake-CRYPTO fragmentation fix, `flush_outbound` packed
/// the whole flight into ONE Handshake packet — a single ~3 KB
/// datagram. On the zero-copy `TxSlot` send path that overran
/// the driver's 2 KiB TX-pool slot, reallocating a `Vec` off
/// NIC-owned memory and corrupting the heap (the crash surfaced
/// downstream as a `talc::free` page fault).
///
/// Here we drive the same oversized flight on the host. The host
/// `Heap` send path uses a real heap `Vec`, so the *old* code
/// merely produced one too-big datagram instead of crashing —
/// which is exactly why this needs an explicit size assertion
/// rather than relying on a crash. The test fails on the old
/// encoder (one oversized datagram) and passes on the new one
/// (the flight fragmented into MTU-bounded datagrams).
#[test]
fn handshake_flight_fragments_across_mtu_datagrams() {
    use super::MAX_QUIC_DATAGRAM;
    let headroom = nic_api::MAX_L2_HEADROOM;

    let mut packet = make_client_initial();
    let local_cid = ConnectionId::new(&[0xab; 8]);
    let mut conn = Connection::new_server(local_cid, [0x42u8; 32]);
    let cfg = big_chain_config();
    conn.process_datagram(&mut packet, &cfg)
        .expect("process inbound Initial with a large cert chain");
    assert!(conn.has_outbound(), "server queued its handshake flight");

    // Drain every datagram the server queued for this flight.
    let mut datagrams: alloc::vec::Vec<_> = alloc::vec::Vec::new();
    while let Some(pkt) = conn.pop_packet_owned() {
        datagrams.push(pkt);
    }

    // The flight must span MORE than one datagram — that is the
    // fragmentation the fix introduces. The pre-fix encoder
    // produced exactly one (oversized) datagram.
    assert!(
        datagrams.len() >= 2,
        "a large server flight must fragment across datagrams; got {}",
        datagrams.len(),
    );

    // EVERY datagram must stay within MAX_QUIC_DATAGRAM — a
    // violation is exactly what overran the driver TX slot on
    // gve and corrupted the heap.
    for (i, pkt) in datagrams.iter().enumerate() {
        let total = pkt.vec().len();
        assert!(
            total <= MAX_QUIC_DATAGRAM,
            "datagram {i} is {total} B, over MAX_QUIC_DATAGRAM {MAX_QUIC_DATAGRAM} B",
        );
        assert!(
            total > headroom,
            "datagram {i} carries no wire bytes past the L2 headroom",
        );
        // Each fragment is a long-header packet (Initial or
        // Handshake): the long-header form bit and the fixed bit
        // are both set.
        assert_eq!(
            pkt.vec()[headroom] & 0xc0,
            0xc0,
            "datagram {i} is not a long-header QUIC packet",
        );
    }
}

fn dev_config() -> TlsServerConfig {
    const CERT: &[u8] = include_bytes!("../../../../../apps/webserver/dev_certs/dev_cert.der");
    const KEY: &[u8] = include_bytes!("../../../../../apps/webserver/dev_certs/dev_key.der");
    TlsServerConfig::from_chain(&[CERT], KEY).expect("dev cert load")
}

/// A `TlsServerConfig` whose certificate chain is large enough to
/// push the server's handshake flight past one QUIC packet — four
/// copies of the dev cert (~2.2 KiB of certificate DER), close in
/// size to a real Let's Encrypt leaf + intermediate. The server
/// only serialises the chain into its Certificate message;
/// nothing in these tests validates it, so repeated certs are a
/// fine stand-in for a genuinely large chain.
fn big_chain_config() -> TlsServerConfig {
    const CERT: &[u8] = include_bytes!("../../../../../apps/webserver/dev_certs/dev_cert.der");
    const KEY: &[u8] = include_bytes!("../../../../../apps/webserver/dev_certs/dev_key.der");
    TlsServerConfig::from_chain(&[CERT, CERT, CERT, CERT], KEY).expect("big-chain cert load")
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
    // AES-128-GCM only post-migration; no `aead_len` /
    // `is_chacha` discriminants remain on `DirKeys`.
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

/// Receive flow control (RFC 9000 §4.1): a STREAM frame one byte past
/// the per-stream window we advertise (`INITIAL_MAX_STREAM_DATA`,
/// 2 MiB) must trip FLOW_CONTROL_ERROR and schedule a
/// CONNECTION_CLOSE — otherwise a peer that ignores the window grows
/// our recv buffer without bound (heap-OOM on a fixed-heap unikernel).
#[test]
fn recv_flow_control_rejects_over_stream_window() {
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    let over = crate::streams::INITIAL_MAX_STREAM_DATA; // 2 MiB
    let mut buf = [0u8; 32];
    // sid 0, offset == window, 1 byte → frame_end = window + 1 > recv_max.
    let n = crate::frame::write_stream(0, over, false, b"x", &mut buf).unwrap();
    conn.dispatch_frames(crate::CryptoLevel::OneRtt, &buf[..n])
        .unwrap();
    let close = conn
        .close_pending
        .as_ref()
        .expect("over-window STREAM must schedule a close");
    assert_eq!(close.0, 0x03, "FLOW_CONTROL_ERROR");
}

/// Mirror: a STREAM frame within the advertised window is accepted
/// with no close — the enforcement must never false-trip a compliant
/// peer (which is why the live uploads keep working).
#[test]
fn recv_flow_control_accepts_within_window() {
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    let mut buf = [0u8; 64];
    let n = crate::frame::write_stream(0, 0, false, b"hello", &mut buf).unwrap();
    conn.dispatch_frames(crate::CryptoLevel::OneRtt, &buf[..n])
        .unwrap();
    assert!(conn.close_pending.is_none(), "in-window STREAM must not close");
}

/// Connection-level window: the sum of per-stream received high-water
/// marks must not exceed `initial_max_data` (8 MiB) even when each
/// stream stays inside its own 2 MiB window. Four client-bidi streams
/// reaching the per-stream edge total exactly 8 MiB (all accepted); a
/// fifth tips it over → FLOW_CONTROL_ERROR. Flow control is
/// offset-based, so a single byte at a high offset counts in full.
#[test]
fn recv_flow_control_rejects_over_conn_window() {
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    let edge = crate::streams::INITIAL_MAX_STREAM_DATA - 1; // 2 MiB - 1
    for sid in [0u64, 4, 8, 12] {
        let mut buf = [0u8; 32];
        let n = crate::frame::write_stream(sid, edge, false, b"x", &mut buf).unwrap();
        conn.dispatch_frames(crate::CryptoLevel::OneRtt, &buf[..n])
            .unwrap();
        assert!(conn.close_pending.is_none(), "sid {sid} is within the conn window");
    }
    let mut buf = [0u8; 32];
    let n = crate::frame::write_stream(16, edge, false, b"x", &mut buf).unwrap();
    conn.dispatch_frames(crate::CryptoLevel::OneRtt, &buf[..n])
        .unwrap();
    let close = conn
        .close_pending
        .as_ref()
        .expect("exceeding the conn window must schedule a close");
    assert_eq!(close.0, 0x03, "FLOW_CONTROL_ERROR");
}

/// Regression: a stream whose body exactly fills the granted send
/// window (or whose conn-level credit is momentarily 0) must still emit
/// its zero-length FIN. A FIN consumes no flow-control / congestion
/// credit (RFC 9000 §4.1 / §19.8); gating it on data budget deadlocked
/// the close — the peer waited forever for stream end → idle timeout.
#[test]
fn pure_fin_emitted_at_flow_control_boundary() {
    use crate::streams::SendState;
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    // 1-RTT send keys so `encode_one_rtt_packet` produces an app packet
    // (it no-ops without them); the key bytes are irrelevant here.
    let secrets = derive_initial_secrets(&[0xcd; 8]);
    conn.application_send = Some(Box::new(super::keys::DirKeys::from_aes128(
        &derive_initial_keys(&secrets.server),
    )));
    // A response on client-bidi stream 0 whose body exactly fills the
    // granted windows (stream + conn both == body length).
    conn.stream_send_owned(0, alloc::vec![0xABu8; 100]);
    conn.send_streams.get_mut(&0).unwrap().peer_max_stream_data = 100;
    conn.peer_max_data = 100;
    // First flush drains the whole 100-byte body (within window).
    let mut out = alloc::vec::Vec::new();
    conn.encode_one_rtt_packet(&mut out).unwrap();
    assert_eq!(conn.send_streams[&0].send_offset, 100, "body fully sent");
    // Close → only a zero-length FIN remains, at the exact FC boundary
    // (send_offset == peer_max_stream_data, data_sent == peer_max_data).
    conn.send_streams.get_mut(&0).unwrap().close();
    assert_eq!(conn.send_streams[&0].state, SendState::Closing);
    // Second flush MUST emit the FIN despite zero stream/conn DATA budget.
    let mut out2 = alloc::vec::Vec::new();
    conn.encode_one_rtt_packet(&mut out2).unwrap();
    assert_ne!(
        conn.send_streams.get(&0).map(|s| s.state),
        Some(SendState::Closing),
        "FIN must be emitted at the FC boundary (was deadlocked in Closing)"
    );
}

/// Regression: a single ACK that declares MORE than the old fixed
/// 64-PN scratch capacity worth of losses must recover ALL of them. A
/// large cumulative-ACK jump after a burst (the gve-storm case) used to
/// strand the excess in `sent_packets` — pinning `bytes_in_flight` so
/// the cwnd gate never reopened, and never re-queuing their STREAM
/// frames until a later ACK / PTO. The lost-PN list is now an unbounded
/// Vec.
#[test]
fn detect_loss_recovers_more_than_64_at_once() {
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    // 70 ack-eliciting 1-RTT packets, each carrying a 100-byte STREAM frame.
    for pn in 0..70u64 {
        conn.pending_sent_stream_frames = alloc::vec![super::StreamRetx {
            sid: 0,
            offset: pn * 100,
            fin: false,
            data: iobuf::IOBuf::from(alloc::vec![0u8; 100]),
        }];
        conn.record_sent_packet(crate::CryptoLevel::OneRtt, pn, true, 100);
    }
    assert_eq!(conn.application_space.sent_packets.len(), 70);
    assert_eq!(conn.bytes_in_flight, 7000);
    // ACK only PN 69 (first range covers [69,69], no additional ranges).
    let mut ackbuf = [0u8; 16];
    let n = crate::frame::write_ack(69, 0, 0, &[], &mut ackbuf).unwrap();
    let (frame, _) = crate::frame::parse_frame(&ackbuf[..n]).unwrap();
    let crate::frame::Frame::Ack {
        largest_acknowledged,
        ack_delay,
        first_ack_range,
        ack_ranges,
        ..
    } = frame
    else {
        panic!("expected ACK frame");
    };
    conn.process_ack(
        crate::CryptoLevel::OneRtt,
        largest_acknowledged,
        ack_delay,
        first_ack_range,
        ack_ranges,
    );
    // PNs 0..=66 cross the packet threshold (pn + 3 <= 69) → all 67 lost;
    // PN 69 acked; 67 and 68 stay in flight. With the old 64 cap, 3 of the
    // 67 losses were stranded (sent_packets would be 5, retx_queue 64).
    assert_eq!(
        conn.application_space.sent_packets.len(),
        2,
        "all >64 losses declared (none stranded)"
    );
    assert_eq!(conn.bytes_in_flight, 200, "only PN 67,68 still in flight");
    assert_eq!(conn.retx_queue.len(), 67, "every lost STREAM frame requeued");
}

/// Deterministic time-threshold loss under the mock clock
/// (architecture-audit direction #2's pattern-setter, unlocked by the
/// `crate::time` seam): the RFC 9002 §6.1.2 RACK-style detector —
/// "older than 9/8·max(SRTT, latest_rtt)" — is driven entirely by
/// virtual time, the class of behavior that previously needed
/// GCE + netem to observe. Timeline: pn0 at T+0 ms (carrying a STREAM
/// frame), pn1 at T+50 ms, ACK of pn1-only at T+100 ms → the RTT sample
/// is 50 ms, the time threshold 56.25 ms, and pn0 (age 100 ms, below
/// the packet threshold at only 1 PN behind) is declared lost by TIME,
/// its frame re-queued for retransmission.
#[test]
fn mock_clock_drives_time_threshold_loss() {
    let mut conn = Connection::new_server(ConnectionId::new(&[0x77; 8]), [0x55u8; 32]);
    crate::time::mock::set(1_000_000);
    conn.pending_sent_stream_frames = alloc::vec![super::StreamRetx {
        sid: 0,
        offset: 0,
        fin: false,
        data: iobuf::IOBuf::from(alloc::vec![0xAAu8; 100]),
    }];
    conn.record_sent_packet(crate::CryptoLevel::OneRtt, 0, true, 100);
    crate::time::mock::set(1_050_000);
    conn.record_sent_packet(crate::CryptoLevel::OneRtt, 1, true, 100);
    crate::time::mock::set(1_100_000);
    // ACK covering pn1 only (largest=1, first_ack_range=0).
    let mut ackbuf = [0u8; 16];
    let n = crate::frame::write_ack(1, 0, 0, &[], &mut ackbuf).unwrap();
    let (frame, _) = crate::frame::parse_frame(&ackbuf[..n]).unwrap();
    let crate::frame::Frame::Ack {
        largest_acknowledged,
        ack_delay,
        first_ack_range,
        ack_ranges,
        ..
    } = frame
    else {
        panic!("expected ACK frame");
    };
    conn.process_ack(
        crate::CryptoLevel::OneRtt,
        largest_acknowledged,
        ack_delay,
        first_ack_range,
        ack_ranges,
    );
    assert_eq!(conn.smoothed_rtt_us, Some(50_000), "RTT sampled from pn1");
    assert_eq!(
        conn.application_space.sent_packets.len(),
        0,
        "pn1 acked; pn0 time-threshold-lost (age 100ms > 56.25ms)"
    );
    assert_eq!(conn.retx_queue.len(), 1, "pn0's STREAM frame requeued");
    assert_eq!(conn.retx_queue[0].data.len(), 100);
    assert_eq!(conn.bytes_in_flight, 0, "both packets released from flight");
}

/// RFC 9002 §6.2: a lost Handshake packet's CRYPTO fragment is
/// re-queued (at its original offset) for retransmission, not just
/// papered over by a PTO PING. Regression for the long-standing gap
/// where CRYPTO retransmission was unwired and handshake-packet loss
/// stalled the handshake.
#[test]
fn lost_crypto_fragment_is_requeued_for_retransmission() {
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    // 5 Handshake packets, each carrying a CRYPTO fragment at a distinct
    // offset in the Handshake CRYPTO stream.
    for pn in 0..5u64 {
        conn.pending_sent_crypto_frames = alloc::vec![super::CryptoRetx {
            level: crate::CryptoLevel::Handshake,
            offset: pn * 100,
            data: alloc::vec![pn as u8; 100],
        }];
        conn.record_sent_packet(crate::CryptoLevel::Handshake, pn, true, 120);
    }
    assert_eq!(conn.handshake_space.sent_packets.len(), 5);
    assert!(conn.crypto_retx_queue.is_empty());

    // ACK only PN 4 → PNs 0 and 1 cross the packet threshold
    // (pn + 3 <= 4) and are declared lost; PN 2,3 stay in flight.
    let mut ackbuf = [0u8; 16];
    let n = crate::frame::write_ack(4, 0, 0, &[], &mut ackbuf).unwrap();
    let (frame, _) = crate::frame::parse_frame(&ackbuf[..n]).unwrap();
    let crate::frame::Frame::Ack {
        largest_acknowledged,
        ack_delay,
        first_ack_range,
        ack_ranges,
        ..
    } = frame
    else {
        panic!("expected ACK frame");
    };
    conn.process_ack(
        crate::CryptoLevel::Handshake,
        largest_acknowledged,
        ack_delay,
        first_ack_range,
        ack_ranges,
    );

    assert_eq!(conn.crypto_retx_queue.len(), 2, "both lost CRYPTO fragments requeued");
    let offsets: alloc::vec::Vec<u64> = conn.crypto_retx_queue.iter().map(|c| c.offset).collect();
    assert_eq!(offsets, alloc::vec![0, 100], "requeued at their original offsets");
    assert!(
        conn.crypto_retx_queue
            .iter()
            .all(|c| matches!(c.level, crate::CryptoLevel::Handshake)),
        "requeued in the Handshake space",
    );
}

/// RFC 9000 §4.6: a STREAMS_BLOCKED frame means the peer is wedged at
/// its stream limit — most likely a MAX_STREAMS we sent was lost (the
/// level-trigger can't recover that, since it needs the peer to open
/// more streams, which it can't). Processing one must force a
/// re-advertise of the current cap, mirroring the DATA_BLOCKED →
/// MAX_DATA recovery.
#[test]
fn streams_blocked_forces_max_streams_readvertise() {
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    assert!(!conn.force_max_streams_bidi);
    assert!(!conn.force_max_streams_uni);

    // STREAMS_BLOCKED_BIDI (type 0x16) carrying a max-streams varint (5).
    conn.dispatch_frames(crate::CryptoLevel::OneRtt, &[0x16, 0x05])
        .unwrap();
    assert!(
        conn.force_max_streams_bidi,
        "STREAMS_BLOCKED_BIDI forces a MAX_STREAMS (bidi) re-advertise",
    );

    // STREAMS_BLOCKED_UNI (type 0x17).
    conn.dispatch_frames(crate::CryptoLevel::OneRtt, &[0x17, 0x05])
        .unwrap();
    assert!(
        conn.force_max_streams_uni,
        "STREAMS_BLOCKED_UNI forces a MAX_STREAMS (uni) re-advertise",
    );
}

/// RFC 9000 §8.2.2: a PATH_CHALLENGE MUST be echoed in a PATH_RESPONSE.
/// Processing one queues the 8 bytes, and `has_one_rtt_to_send` reports
/// the connection has work so the flush emits the response.
#[test]
fn path_challenge_queues_a_path_response() {
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    assert!(conn.pending_path_response.is_none());

    // PATH_CHALLENGE (type 0x1a) + 8 opaque bytes.
    conn.dispatch_frames(crate::CryptoLevel::OneRtt, &[0x1a, 9, 8, 7, 6, 5, 4, 3, 2])
        .unwrap();
    assert_eq!(
        conn.pending_path_response,
        Some([9, 8, 7, 6, 5, 4, 3, 2]),
        "the challenge data is queued for echo",
    );

    // The append helper writes a well-formed PATH_RESPONSE frame.
    let mut out = alloc::vec::Vec::new();
    super::append_path_response_into(&mut out, &[9, 8, 7, 6, 5, 4, 3, 2]);
    assert_eq!(out, alloc::vec![0x1b, 9, 8, 7, 6, 5, 4, 3, 2]);
}

/// RFC 9001 §6.1: responding to a peer key update must also rotate our
/// SEND keys to the next generation and toggle the KEY_PHASE bit we
/// stamp on 1-RTT packets — otherwise our packets stay at the old phase
/// and the connection breaks once the peer's prev-key window closes.
#[test]
fn key_update_rotates_send_keys_and_toggles_phase() {
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    let secret0 = [0x11u8; 32];
    conn.server_app_secret = Some(secret0);
    let secrets = derive_initial_secrets(&[0xcd; 8]);
    conn.application_send = Some(Box::new(super::keys::DirKeys::from_aes128(
        &derive_initial_keys(&secrets.server),
    )));
    assert_eq!(conn.send_key_phase, 0);

    // First peer key update.
    conn.rotate_recv_keys();
    assert_eq!(conn.send_key_phase, 1, "send KEY_PHASE bit toggled to 1");
    assert_eq!(conn.recv_key_phase, 1, "recv KEY_PHASE bit toggled in lock-step");
    assert_eq!(
        conn.server_app_secret.unwrap(),
        crate::crypto::next_traffic_secret(&secret0),
        "send secret advanced one generation",
    );

    // A second key update toggles the phase bit back and advances again.
    let secret1 = conn.server_app_secret.unwrap();
    conn.rotate_recv_keys();
    assert_eq!(conn.send_key_phase, 0, "second KU toggles the phase bit back to 0");
    assert_eq!(
        conn.server_app_secret.unwrap(),
        crate::crypto::next_traffic_secret(&secret1),
        "send secret advanced again",
    );
}

/// Persistent congestion (RFC 9002 §7.6): once several consecutive PTO
/// periods elapse with no ACK, the congestion window collapses to the
/// minimum and slow start restarts. Regression for the gap where
/// `on_rto`/`on_loss(persistent)` were implemented in the controller but
/// never invoked from the QUIC path, so cwnd never backed off on a path
/// outage.
#[test]
fn repeated_pto_triggers_persistent_congestion_collapse() {
    use net_cc::CongestionControl;
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    let secrets = derive_initial_secrets(&[0xcd; 8]);
    conn.application_send = Some(Box::new(super::keys::DirKeys::from_aes128(
        &derive_initial_keys(&secrets.server),
    )));
    // An in-flight ack-eliciting packet so `send_pto_probe` has a space
    // to probe.
    conn.record_sent_packet(crate::CryptoLevel::OneRtt, 0, true, 1200);
    let cwnd_before = conn.cc.window();
    // First PTO probe: backoff only, no collapse.
    assert!(conn.send_pto_probe(), "probe emitted");
    assert_eq!(conn.cc.window(), cwnd_before, "single PTO must not collapse cwnd");
    // Second consecutive PTO (no ACK in between) → persistent congestion.
    assert!(conn.send_pto_probe(), "probe emitted");
    assert!(
        conn.cc.window() < cwnd_before,
        "repeated PTO collapses cwnd toward the minimum window"
    );
}

/// PTO exponential backoff (RFC 9002 §6.2.1): the probe period doubles
/// per `pto_count` and the exponent is capped so an unresponsive peer
/// probes at a geometric (not fixed) interval. A missing backoff is what
/// let a stuck connection emit 3180 PINGs in 12 s on the gve path; the
/// cap keeps `base << count` from overflowing.
#[test]
fn pto_period_backs_off_exponentially() {
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    // No RTT sample yet → base = kInitialRtt (333 ms) + kGranularity (1 ms).
    let base = conn.pto_period_us();
    assert_eq!(base, 334_000);
    conn.pto_count = 1;
    assert_eq!(conn.pto_period_us(), base * 2);
    conn.pto_count = 4;
    assert_eq!(conn.pto_period_us(), base * 16);
    // Exponent caps at 10: the period stops growing (and can't overflow)
    // however long the peer stays silent — the idle timeout reaps it first.
    conn.pto_count = 9;
    let at_9 = conn.pto_period_us();
    conn.pto_count = 100;
    assert_eq!(conn.pto_period_us(), base * (1 << 10));
    assert!(conn.pto_period_us() > at_9);
}

/// Egress pacer (RFC 9002 §7.7) arming logic: a pacing deadline is reported
/// only when there is pending 1-RTT data AND the token bucket is spent.
/// Without it the unpaced cwnd burst is dropped by GCE's per-VM egress
/// policer (the multi-packet h3 download loss — see reference_gce_h3_burst_loss).
#[test]
fn pacer_arms_deadline_only_when_limited() {
    use net_cc::CongestionControl;
    let mut conn = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    conn.pace_last_us = 1_000_000;
    // Ultra-low-RTT path (0.2 ms) → the fixed-cap regime (cc.pacing_rate would
    // thrash here), so pacing runs at LOW_RTT_PACE_RATE_BPS.
    conn.smoothed_rtt_us = Some(200);

    // No pending 1-RTT data → never pacing-limited, whatever the budget.
    conn.pace_budget = -700;
    assert!(conn.pace_deadline_us().is_none());

    // Pending data (a queued retransmission) + a spent budget → a near-future
    // deadline (one packet's worth of spacing at the capped rate, sub-ms).
    conn.retx_queue.push_back(super::StreamRetx {
        sid: 0,
        offset: 0,
        fin: false,
        data: iobuf::IOBuf::from(alloc::vec![0u8; 100]),
    });
    let d = conn
        .pace_deadline_us()
        .expect("pending data + spent budget → a deadline is armed");
    assert!(d > 1_000_000, "deadline must be in the future");
    assert!(d <= 1_000_000 + 1_000, "≈one packet at the low-RTT capped rate (sub-ms)");

    // Pending data but positive budget → may send now, no deadline.
    conn.pace_budget = 1;
    assert!(conn.pace_deadline_us().is_none());

    // Real-RTT path (50 ms) uncaps: pacing follows cc.pacing_rate, not the
    // fixed cap — the gate still arms a deadline when the budget is spent.
    conn.smoothed_rtt_us = Some(50_000);
    conn.cc.on_ack(12_000, 0, net_cc::Rtt::new(50_000, 50_000), 0);
    conn.pace_budget = -700;
    assert!(conn.pace_deadline_us().is_some());
}
