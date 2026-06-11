// crates/proto/quic/src/conn/abort_tests.rs — per-stream abort (S1,
// RFC 9000 §3.5 / §19.4-19.5) transport-level tests, both directions.
//
// Driven over the same in-process client↔server pump the E1
// client-role tests use (real dev cert + SPKI pin, virtual clock):
// every assertion exercises the REAL frame codec, RX dispatch, TX
// emission, and flow-control accounting on both roles. Lives in its
// own file so the S1 surface has its own test hunk.

use super::*;
use crate::tls::CryptoLevel;
use tls::TlsClientConfig;
use tls::TlsServerConfig;
use tls::client::{ServerAuth, spki_pin_from_cert_der};

const CERT: &[u8] = include_bytes!("../../../../../apps/webserver/dev_certs/dev_cert.der");
const KEY: &[u8] = include_bytes!("../../../../../apps/webserver/dev_certs/dev_key.der");
const HEADROOM: usize = nic_api::MAX_L2_HEADROOM;

fn server_config() -> TlsServerConfig {
    TlsServerConfig::from_chain(&[CERT], KEY).expect("dev cert load")
}

fn pinned_client_config() -> TlsClientConfig {
    TlsClientConfig {
        auth: ServerAuth::PinnedSpki(spki_pin_from_cert_der(CERT).expect("pin")),
        server_name: Some(b"localhost"),
        alpn: &[b"h3"],
    }
}

fn wire_of(pkt: &DatagramBuf) -> Vec<u8> {
    pkt.vec()[HEADROOM..].to_vec()
}

/// Pump datagrams both ways until quiescent. Mirrors the E1 pump;
/// server errors fail the test, the client's first error returns.
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

/// Establish a fresh client↔server pair (handshake pumped through).
fn established(seed: u8) -> (Connection, Connection, TlsServerConfig) {
    crate::time::mock::set(1_000_000 + seed as u64 * 1_000_000);
    let cfg = server_config();
    let ccfg = pinned_client_config();
    let mut client = Connection::new_client([seed; 32], &ccfg).expect("new_client");
    let mut server = Connection::new_server(ConnectionId::new(&[0xab; 8]), [0x42u8; 32]);
    assert_eq!(pump(&mut client, &mut server, &cfg), None);
    assert_eq!(client.state(), ConnState::Established);
    assert_eq!(server.state(), ConnState::Established);
    (client, server, cfg)
}

/// GENERATE → HONOR, client resets its request stream: the server's
/// reader sees a clean `(0, eof)` + the surfaced error code (not a
/// hang), the queued-but-unsent client data is dropped, and the
/// connection-level flow-control accounting absorbs the full final
/// size so later traffic still flows.
#[test]
fn client_reset_stream_surfaces_on_server_reader() {
    let (mut client, mut server, cfg) = established(0x51);

    // Client sends 5 bytes on bidi stream 0, server ingests them.
    client.stream_send_owned(0, b"hello".to_vec());
    client.client_flush().expect("flush");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);
    let mut buf = [0u8; 64];
    let (n, eof) = server.stream_recv(0, &mut buf);
    assert_eq!((n, eof), (5, false), "request bytes arrived, no FIN");

    // Client queues more data it never flushes, then aborts.
    client.stream_send_owned(0, b"never-sent".to_vec());
    client.reset_stream(0, 0x010c /* H3_REQUEST_CANCELLED */);
    assert!(
        matches!(
            client.send_streams.get(&0).unwrap().state,
            crate::streams::SendState::ResetSent
        ),
        "send side terminal after abort"
    );
    assert_eq!(client.stream_send_buffered(0), 0, "queued chunks dropped");
    client.client_flush().expect("flush reset");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);

    // Server: reset surfaced, reader unblocked with eof, code visible.
    assert_eq!(server.stream_reset_code(0), Some(0x010c));
    let (n, eof) = server.stream_recv(0, &mut buf);
    assert_eq!((n, eof), (0, true), "reader sees clean EOF, not a hang");
    // FC accounting: final size (5) is fully consumed; the conn-level
    // counters stay balanced (received == consumed for this stream).
    assert_eq!(server.data_received, 5);
    assert_eq!(server.data_consumed, 5);

    // The connection survives: a fresh stream still round-trips.
    client.stream_send_owned(4, b"next".to_vec());
    client.stream_close(4);
    client.client_flush().expect("flush");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);
    let (n, eof) = server.stream_recv(4, &mut buf);
    assert_eq!((&buf[..n], eof), (&b"next"[..], true));
}

/// HONOR STOP_SENDING: the client stops a server response mid-flight;
/// the server MUST abort its send side with a RESET_STREAM echoing
/// the code (RFC 9000 §3.5), dropping retained/queued data — and the
/// client's reader observes the reset.
#[test]
fn stop_sending_aborts_send_side_with_reset_echo() {
    let (mut client, mut server, cfg) = established(0x52);

    // Client opens stream 0; server starts a response and leaves
    // more queued than one packet flight (so data remains pending).
    client.stream_send_owned(0, b"req".to_vec());
    client.stream_close(0);
    client.client_flush().expect("flush");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);
    server.stream_send_owned(0, alloc::vec![0xAA; 4096]);
    server.flush(&cfg).expect("server flush");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);

    // Client aborts its interest in the response.
    client.stop_sending(0, 0x0107 /* H3_REQUEST_REJECTED-ish */);
    client.client_flush().expect("flush stop_sending");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);

    // Server answered with RESET_STREAM (send side terminal, queue
    // dropped, code copied) — observable on both ends.
    let ss = server.send_streams.get(&0).expect("send stream");
    assert!(matches!(ss.state, crate::streams::SendState::ResetSent));
    assert_eq!(server.stream_send_buffered(0), 0, "queued response dropped");
    assert!(
        server.retx_queue.iter().all(|f| f.sid != 0),
        "retained retx for the aborted stream dropped"
    );
    assert_eq!(
        client.stream_reset_code(0),
        Some(0x0107),
        "server copied the STOP_SENDING code into its RESET_STREAM"
    );
    let (n, eof) = client.stream_recv(0, &mut [0u8; 64]);
    let _ = n; // any straggler bytes that landed pre-abort are fine
    assert!(eof || client.stream_reset_code(0).is_some());
}

/// §4.5 final-size validation: a RESET_STREAM whose final size is
/// below bytes already received is FINAL_SIZE_ERROR (0x12); one past
/// the advertised stream window is FLOW_CONTROL_ERROR (0x03). Frames
/// are injected straight into the server's dispatch (the parser is
/// covered by frame.rs round-trips).
#[test]
fn reset_final_size_violations_close_connection() {
    // Final size below recv_high → FINAL_SIZE_ERROR.
    let (mut client, mut server, cfg) = established(0x53);
    client.stream_send_owned(0, b"0123456789".to_vec());
    client.client_flush().expect("flush");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);
    let mut frame = [0u8; 32];
    let n = crate::frame::write_reset_stream(0, 0x0, 5, &mut frame).unwrap();
    server
        .dispatch_frames(CryptoLevel::OneRtt, &frame[..n])
        .expect("dispatch returns Ok; close is scheduled");
    assert_eq!(
        server.close_pending.as_ref().map(|(code, _)| *code),
        Some(0x12),
        "FINAL_SIZE_ERROR scheduled"
    );

    // Final size past the advertised per-stream window →
    // FLOW_CONTROL_ERROR.
    let (mut client, mut server, cfg) = established(0x54);
    client.stream_send_owned(0, b"x".to_vec());
    client.client_flush().expect("flush");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);
    let over = crate::streams::INITIAL_MAX_STREAM_DATA + 1;
    let n = crate::frame::write_reset_stream(0, 0x0, over, &mut frame).unwrap();
    server
        .dispatch_frames(CryptoLevel::OneRtt, &frame[..n])
        .expect("dispatch ok");
    assert_eq!(
        server.close_pending.as_ref().map(|(code, _)| *code),
        Some(0x03),
        "FLOW_CONTROL_ERROR scheduled"
    );
}

/// A RESET_STREAM whose final size matches a FIN already seen is
/// idempotent-valid; one that disagrees with the FIN is a
/// FINAL_SIZE_ERROR.
#[test]
fn reset_final_size_must_agree_with_fin() {
    let (mut client, mut server, cfg) = established(0x55);
    client.stream_send_owned(0, b"abcde".to_vec());
    client.stream_close(0); // FIN at 5
    client.client_flush().expect("flush");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);

    // Matching final size: accepted, stream resets cleanly.
    let mut frame = [0u8; 32];
    let n = crate::frame::write_reset_stream(0, 0x9, 5, &mut frame).unwrap();
    server
        .dispatch_frames(CryptoLevel::OneRtt, &frame[..n])
        .expect("dispatch ok");
    assert!(server.close_pending.is_none(), "consistent reset accepted");
    assert_eq!(server.stream_reset_code(0), Some(0x9));

    // Disagreeing final size on another stream with a known FIN.
    let (mut client, mut server, cfg) = established(0x56);
    client.stream_send_owned(0, b"abcde".to_vec());
    client.stream_close(0);
    client.client_flush().expect("flush");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);
    let n = crate::frame::write_reset_stream(0, 0x9, 6, &mut frame).unwrap();
    server
        .dispatch_frames(CryptoLevel::OneRtt, &frame[..n])
        .expect("dispatch ok");
    assert_eq!(
        server.close_pending.as_ref().map(|(code, _)| *code),
        Some(0x12),
        "FIN/final-size disagreement is FINAL_SIZE_ERROR"
    );
}

/// §19.5 state errors: STOP_SENDING on a receive-only stream (the
/// peer's own uni stream) or for a locally-initiated stream that was
/// never opened closes the connection with STREAM_STATE_ERROR (0x05).
#[test]
fn stop_sending_state_errors_close_connection() {
    // Receive-only: client uni stream id 2, sent TO the server by
    // the very client that owns it — a protocol violation.
    let (mut client, mut server, cfg) = established(0x57);
    let _ = &mut client;
    let mut frame = [0u8; 24];
    let n = crate::frame::write_stop_sending(2, 0x0, &mut frame).unwrap();
    server
        .dispatch_frames(CryptoLevel::OneRtt, &frame[..n])
        .expect("dispatch ok");
    assert_eq!(
        server.close_pending.as_ref().map(|(code, _)| *code),
        Some(0x05),
        "STOP_SENDING on receive-only stream is STREAM_STATE_ERROR"
    );

    // Locally-initiated (server uni id 3) never opened.
    let (mut client2, mut server2, cfg2) = established(0x58);
    let _ = (&mut client2, &cfg2, &cfg);
    let n = crate::frame::write_stop_sending(3, 0x0, &mut frame).unwrap();
    server2
        .dispatch_frames(CryptoLevel::OneRtt, &frame[..n])
        .expect("dispatch ok");
    assert_eq!(
        server2.close_pending.as_ref().map(|(code, _)| *code),
        Some(0x05),
        "STOP_SENDING for an unopened local stream is STREAM_STATE_ERROR"
    );
}

/// Retransmission coverage (RFC 9000 §13.3): a RESET_STREAM in a
/// packet declared lost is re-queued and re-emitted, while the lost
/// packet's retained STREAM frames for that (aborted) stream are
/// dropped instead of re-queued.
#[test]
fn lost_reset_stream_is_requeued_and_stream_retx_dropped() {
    let (mut client, mut server, cfg) = established(0x59);

    // Stream with one in-flight data packet (unacked).
    client.stream_send_owned(0, alloc::vec![0xBB; 512]);
    client.client_flush().expect("flush");
    // Drop the data packet on the floor (simulated loss) — its
    // StreamRetx views stay retained in sent_packets.
    while client.pop_packet_owned().is_some() {}

    // Abort, emit the RESET_STREAM packet, and drop that too.
    client.reset_stream(0, 0x0102);
    client.client_flush().expect("flush");
    let mut reset_pns: Vec<u64> = Vec::new();
    while client.pop_packet_owned().is_some() {
        // Lost on the wire.
    }
    // The reset frame was staged on its packet (no longer pending).
    assert!(client.pending_reset_streams.is_empty());
    // Find the in-flight PNs and declare them all lost via a far-
    // ahead ACK of a later probe packet (packet-threshold loss).
    for (pn, pkt) in client.application_space.sent_packets.iter() {
        if !pkt.ctrl_frames.is_empty() {
            reset_pns.push(pn);
        }
    }
    assert_eq!(reset_pns.len(), 1, "reset frame retained on its packet");

    // Send 3 more ack-eliciting packets so the lost ones cross the
    // packet threshold (K=3) once the newest is acked.
    for _ in 0..3 {
        crate::time::mock::advance(10_000);
        let mut dg = client.take_datagram_buf(64);
        client
            .encode_ping_probe(dg.vec_mut(), CryptoLevel::OneRtt)
            .expect("ping");
        client.outbound.push_back(dg);
    }
    // Deliver them; then force the server's delayed ACK out (the
    // standalone-ACK threshold is 8 packets / 25 ms — advance the
    // virtual clock past max_ack_delay and flush).
    assert_eq!(pump(&mut client, &mut server, &cfg), None);
    crate::time::mock::advance(30_000);
    server.flush(&cfg).expect("server ACK flush");

    // The ACK names only the pings → the dropped packets cross the
    // K=3 packet threshold → the lost RESET_STREAM is re-queued and
    // re-emitted by the client's post-ACK flush; the server must end
    // up observing the reset.
    assert_eq!(pump(&mut client, &mut server, &cfg), None);
    assert_eq!(server.stream_reset_code(0), Some(0x0102));
    // And the aborted stream's lost STREAM frames were NOT re-queued.
    assert!(client.retx_queue.iter().all(|f| f.sid != 0));
    assert_eq!(client.retx_bytes, 0);
}

/// Late RESET_STREAM / STOP_SENDING for an already-reaped stream are
/// absorbed (ACK'd) without resurrecting state — the quinn
/// post-response STOP_SENDING pattern.
#[test]
fn late_abort_frames_for_reaped_streams_are_absorbed() {
    let (mut client, mut server, cfg) = established(0x5a);

    // Full request/response so the stream reaps on both ends.
    client.stream_send_owned(0, b"req".to_vec());
    client.stream_close(0);
    client.client_flush().expect("flush");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);
    let mut buf = [0u8; 64];
    let (_, eof) = server.stream_recv(0, &mut buf);
    assert!(eof);
    server.stream_send_owned(0, b"resp".to_vec());
    server.stream_close(0);
    server.flush(&cfg).expect("flush");
    assert_eq!(pump(&mut client, &mut server, &cfg), None);
    let (_, eof) = client.stream_recv(0, &mut buf);
    assert!(eof);
    // Reap on the server (recv drained + fin sent).
    server.reap_finished_streams();
    assert!(server.is_reaped(0), "stream reaped server-side");

    // Late STOP_SENDING + RESET_STREAM retransmits: absorbed.
    let mut frame = [0u8; 32];
    let n = crate::frame::write_stop_sending(0, 0x0, &mut frame).unwrap();
    server
        .dispatch_frames(CryptoLevel::OneRtt, &frame[..n])
        .expect("dispatch ok");
    let n = crate::frame::write_reset_stream(0, 0x0, 3, &mut frame).unwrap();
    server
        .dispatch_frames(CryptoLevel::OneRtt, &frame[..n])
        .expect("dispatch ok");
    assert!(server.close_pending.is_none(), "absorbed without error");
    assert!(!server.recv_streams.contains_key(&0), "not resurrected");
}
