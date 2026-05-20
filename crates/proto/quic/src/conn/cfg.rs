// crates/proto/quic/src/conn/cfg.rs — host-side test fixtures + the
// `Connection`-level integration tests.
//
// Lives behind `#[cfg(test)]` so the dev-cert byte slices are
// only compiled when `bazel test` builds with std. The
// `dev_config()` helper is shared by every test below; the
// `include_bytes!` paths step up FIVE levels (`../../../../../`)
// from `crates/proto/quic/src/conn/` to reach
// `apps/webserver/dev_certs/`, one more `../` than the original
// flat `conn.rs` needed.

#![cfg(test)]

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
    let pkt = conn
        .pop_packet_owned()
        .expect("server reply datagram queued");
    let reply = &pkt.vec()[executor::reactor::MAX_L2_HEADROOM..];
    assert!(!reply.is_empty(), "non-empty reply datagram");

    // First packet should be Initial. Re-derive server-side
    // keys from the same client_dcid and unprotect.
    let server_initial = derive_initial_keys(&secrets.server);
    let server_initial_dk = DirKeys::from_initial(&server_initial);
    let pre = parse_long_header_preamble(reply).unwrap();
    assert_eq!(pre.long_type, long_packet_type::INITIAL);
    assert_eq!(pre.dcid, &client_scid[..]); // server echoes our SCID
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

fn dev_config() -> TlsServerConfig {
    const CERT: &[u8] = include_bytes!("../../../../../apps/webserver/dev_certs/dev_cert.der");
    const KEY: &[u8] = include_bytes!("../../../../../apps/webserver/dev_certs/dev_key.der");
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
