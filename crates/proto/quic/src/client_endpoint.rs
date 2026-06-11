// crates/proto/quic/src/client_endpoint.rs — the QUIC CLIENT endpoint:
// UDP/socket glue that puts `Connection::new_client` (conn/client.rs,
// the E1 sans-io client role) on the real stack.
//
// The connector mirrors the smallest honest slice of the server
// listener (endpoint.rs):
//
//   * socket — ONE ephemeral, owner-pinned [`UdpClient`] per
//     connection (the runtime's per-worker ephemeral pool) instead of
//     the server's shared bound port + DCID-routed slot table. The
//     4-tuple is fixed at connect, so no routing/demux is needed: every
//     inbound datagram on the socket belongs to this connection.
//   * conn task — the same shape as the server's `conn_task`: race the
//     socket against the earliest of the idle / PTO / pacing /
//     delayed-ACK deadlines, feed datagrams through the connection
//     (here `client_process_datagram`), drain outbound, wake the
//     handler via the shared `progress` event. No inbox: the
//     owner-pinned socket's per-binding ring IS the queue, and the
//     task recvs from it directly.
//   * arena — the same co-allocated [`ConnArena`] (conn + progress +
//     peer cells); the peer cells are fixed at connect (clients don't
//     follow migrations — RFC 9000 §9 is a server-side concern here).
//
// Worker pinning: `UdpClient::connect` allocates from the CALLING
// worker's ephemeral pool (replies land on this worker's inbox only),
// and `spawn` puts the conn task on the same worker — so the task and
// its socket stay together, exactly like the server's conn task and
// its slot-routed inbox.
//
// Egress: the client never registers with the per-core egress owner —
// it ships inline (the `Heap` datagram path). A GSO super-packet from
// the bulk tail is split back into per-`gso_size` datagrams here,
// since the client socket has no segmentation-offload submit surface.

use alloc::rc::Rc;

use core::cell::{Cell, RefCell};

use waitless::runtime::{AsyncEvent, Either, IpAddr, UdpBindError, UdpClient, select, sleep_us, spawn};

use crate::conn::{ConnError, ConnState, Connection, DatagramBuf};
use crate::endpoint::ConnArena;
use tls::TlsClientConfig;

/// Handshake deadline for [`quic_connect`]: generous against a real
/// RTT + a couple of PTO-driven retransmits, comfortably under the
/// probe endpoints' overall 8 s budget so a dead peer surfaces as a
/// named stage rather than the outer deadline.
const CONNECT_DEADLINE_US: u64 = 4_000_000;

/// Why [`quic_connect`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicConnectError {
    /// No ephemeral UDP port / backend bind failure.
    Bind(UdpBindError),
    /// Building the client connection (TLS client driver) failed.
    Tls,
    /// The handshake terminally failed — wrong pin, CONNECTION_CLOSE
    /// from the peer, version negotiation with no common version, …
    Handshake,
    /// No Established within [`CONNECT_DEADLINE_US`] (peer not a QUIC
    /// server / datagrams blackholed).
    Timeout,
}

/// Per-connection handle for the CLIENT role — the client mirror of
/// [`QuicConn`](crate::endpoint::QuicConn), shaped for an h3 client:
/// open bidi/uni streams, send/recv/close, per-stream abort, and the
/// reset-code surface. `!Send` (Rc + RefCell): stays on the worker
/// that dialled.
pub struct QuicClientConn {
    arena: Rc<ConnArena>,
    udp: Rc<UdpClient>,
    /// Next client-initiated bidi stream id (0, 4, 8, … — RFC 9000
    /// §2.1).
    next_bidi: Cell<u64>,
    /// Next client-initiated uni stream id (2, 6, 10, …).
    next_uni: Cell<u64>,
}

/// Dial a QUIC server at `(ip, port)`: bind an ephemeral owner-pinned
/// UDP socket, build the client-role [`Connection`] from `seed` +
/// `config` (SPKI pin / SNI / ALPN), spawn the conn task, and drive
/// the handshake to Established with a deadline. Entropy arrives by
/// value (`seed`), like every client this stack originates.
pub async fn quic_connect(
    ip: IpAddr,
    port: u16,
    config: &TlsClientConfig,
    seed: [u8; 32],
) -> Result<QuicClientConn, QuicConnectError> {
    let udp = Rc::new(UdpClient::connect(ip, port).map_err(QuicConnectError::Bind)?);
    let conn = Connection::new_client(seed, config).map_err(|_| QuicConnectError::Tls)?;
    let arena = Rc::new(ConnArena {
        conn: RefCell::new(conn),
        progress: AsyncEvent::new(),
        peer_ip: Cell::new(ip),
        peer_port: Cell::new(port),
    });
    arena.conn.borrow_mut().set_last_recv_now();
    // Ship the first flight (Initial/ClientHello — queued at
    // construction) before the task is even spawned.
    drain_client_outbound(&arena.conn, &udp);
    // The conn task owns the socket's recv side from here on. Ignoring
    // the handle is the listener pattern: the task runs to conn end.
    let _ = spawn(client_conn_task(Rc::clone(&arena), Rc::clone(&udp)));

    // Await Established under the connect deadline.
    let deadline = crate::time::now_us() + CONNECT_DEADLINE_US;
    loop {
        match arena.conn.borrow().state() {
            ConnState::Established => break,
            ConnState::Failed => return Err(QuicConnectError::Handshake),
            _ => {}
        }
        arena.progress.reset();
        // Re-check after reset to close the wake/observe race.
        match arena.conn.borrow().state() {
            ConnState::Established => break,
            ConnState::Failed => return Err(QuicConnectError::Handshake),
            _ => {}
        }
        let now = crate::time::now_us();
        if now >= deadline {
            fail_conn(&arena, &udp, 0x0 /* NO_ERROR */, b"connect timeout");
            return Err(QuicConnectError::Timeout);
        }
        if let Either::Right(()) =
            select(arena.progress.wait(), sleep_us(deadline - now)).await
        {
            fail_conn(&arena, &udp, 0x0, b"connect timeout");
            return Err(QuicConnectError::Timeout);
        }
    }
    Ok(QuicClientConn {
        arena,
        udp,
        next_bidi: Cell::new(0),
        next_uni: Cell::new(2),
    })
}

/// Schedule + emit a CONNECTION_CLOSE and mark the conn Failed (the
/// conn task observes Failed and exits).
fn fail_conn(arena: &ConnArena, udp: &UdpClient, code: u64, reason: &[u8]) {
    {
        let mut c = arena.conn.borrow_mut();
        c.close_with_error(code, reason);
        c.flush_close();
    }
    drain_client_outbound(&arena.conn, udp);
    arena.progress.set();
}

/// Ship every queued outbound datagram on the client socket. The
/// client never registers with the egress owner, so packets are heap
/// `DatagramBuf`s shipped inline; a GSO super-packet (bulk-upload
/// tail) is split back into `gso_size` datagrams — the client socket
/// has no segmentation-offload submit surface.
fn drain_client_outbound(conn: &RefCell<Connection>, udp: &UdpClient) {
    use nic_api::MAX_L2_HEADROOM;
    loop {
        let pkt = match conn.borrow_mut().pop_packet_owned() {
            Some(p) => p,
            None => break,
        };
        {
            let wire = &pkt.vec()[MAX_L2_HEADROOM..];
            if let DatagramBuf::GsoSlot { gso_size, .. } = &pkt {
                for seg in wire.chunks((*gso_size).max(1) as usize) {
                    let _ = udp.send(seg);
                    crate::diag::COUNTERS.datagrams_sent.bump();
                }
            } else {
                let _ = udp.send(wire);
                crate::diag::COUNTERS.datagrams_sent.bump();
            }
        }
        conn.borrow_mut().recycle_packet(pkt);
    }
}

/// The client conn task — the server `conn_task`'s shape over the
/// owner-pinned socket: race recv against the earliest deadline,
/// process, drain, wake the handler. Exits when the conn fails or
/// idles out, then marks the conn terminated so handler waits unwind.
async fn client_conn_task(arena: Rc<ConnArena>, udp: Rc<UdpClient>) {
    let conn = &arena.conn;
    let mut buf = [0u8; 1500];
    loop {
        if matches!(conn.borrow().state(), ConnState::Failed) {
            break;
        }
        let (idle_us, last_recv_us, pto_deadline, pace_deadline, ack_deadline) = {
            let c = conn.borrow();
            (
                c.idle_timeout_us(),
                c.last_recv_us(),
                c.pto_deadline_us(),
                c.pace_deadline_us(),
                c.app_ack_deadline_us(),
            )
        };
        let now = crate::time::now_us();
        if now.saturating_sub(last_recv_us) >= idle_us {
            break; // idle timeout (RFC 9000 §10.1)
        }
        let mut timer_deadline = last_recv_us + idle_us;
        if let Some(p) = pto_deadline {
            timer_deadline = timer_deadline.min(p);
        }
        if let Some(p) = pace_deadline {
            timer_deadline = timer_deadline.min(p);
        }
        if let Some(p) = ack_deadline {
            timer_deadline = timer_deadline.min(p);
        }
        let remaining = timer_deadline.saturating_sub(now).max(1);

        match select(udp.recv(&mut buf), sleep_us(remaining)).await {
            Either::Left(n) => {
                let mut tearing_down = false;
                // Process the awaited datagram, then drain anything
                // already queued (bounded batch, like the server).
                const BATCH_LIMIT: usize = 32;
                let mut current = n;
                for _ in 0..BATCH_LIMIT {
                    if current > 0 && !process_one(conn, &mut buf[..current]) {
                        tearing_down = true;
                        break;
                    }
                    current = match udp.try_recv(&mut buf) {
                        Some(m) => m,
                        None => break,
                    };
                }
                drain_client_outbound(conn, &udp);
                arena.progress.set();
                if tearing_down {
                    break;
                }
            }
            Either::Right(()) => {
                let after = crate::time::now_us();
                // Mirror the server's idle re-derivation exactly: a
                // PTO/pace wake a hair early must never read as idle.
                if after.saturating_sub(last_recv_us) >= idle_us {
                    break;
                }
                let mut shipped_work = false;
                if pto_deadline.is_some_and(|p| after >= p)
                    && conn.borrow_mut().send_pto_probe()
                {
                    crate::diag::COUNTERS.pto_probes_sent.bump();
                    shipped_work = true;
                }
                if pace_deadline.is_some_and(|p| after >= p)
                    || ack_deadline.is_some_and(|p| after >= p)
                {
                    let _ = conn.borrow_mut().client_flush();
                    shipped_work = true;
                }
                if shipped_work {
                    drain_client_outbound(conn, &udp);
                    arena.progress.set();
                }
            }
        }
        if matches!(conn.borrow().state(), ConnState::Failed) {
            arena.progress.set();
            break;
        }
    }
    // Unwind any handler parked on progress (same contract as the
    // server conn task's teardown).
    conn.borrow_mut().mark_terminated();
    arena.progress.set();
}

/// Feed one inbound datagram through the client role. Returns `false`
/// when the connection is tearing down (a close was scheduled +
/// emitted). TLS failures already emit their CRYPTO_ERROR close
/// inside `client_process_datagram`; other errors close here with the
/// same mapping the server task uses.
fn process_one(conn: &RefCell<Connection>, datagram: &mut [u8]) -> bool {
    let result = {
        let mut c = conn.borrow_mut();
        c.set_cur_rx_us(crate::time::now_us());
        c.client_process_datagram(datagram)
    };
    match result {
        Ok(()) => true,
        Err(e) => {
            crate::quic_drop!(
                other_wire,
                "client_process_datagram failed: {:?} size={}",
                e,
                datagram.len()
            );
            let (code, reason): (u64, &[u8]) = match e {
                ConnError::Tls => (0x0a, b"tls_alert"), // close already emitted
                ConnError::Wire | ConnError::Decrypt => (0x0a, b"protocol_violation"),
                ConnError::UnsupportedVersion => (0x0a, b"unsupported_version"),
                ConnError::BadState | ConnError::OutputTooSmall => (0x01, b"internal_error"),
            };
            let mut c = conn.borrow_mut();
            c.close_with_error(code, reason);
            c.flush_close();
            false
        }
    }
}

impl QuicClientConn {
    /// Allocate the next client-initiated BIDI stream id (0, 4, 8, …).
    /// The stream materialises lazily on first send.
    pub fn open_bidi_stream(&self) -> u64 {
        let sid = self.next_bidi.get();
        self.next_bidi.set(sid + 4);
        sid
    }

    /// Allocate the next client-initiated UNI stream id (2, 6, 10, …)
    /// — the h3 control stream lives here.
    pub fn open_uni_stream(&self) -> u64 {
        let sid = self.next_uni.get();
        self.next_uni.set(sid + 4);
        sid
    }

    /// Append owned bytes to `sid`'s send queue (no FIN) and flush.
    pub fn send_owned(&self, sid: u64, data: alloc::vec::Vec<u8>) {
        {
            let mut c = self.arena.conn.borrow_mut();
            c.stream_send_owned(sid, data);
            let _ = c.client_flush();
        }
        self.drain();
    }

    /// FIN `sid` (the next/last STREAM frame carries FIN) and flush.
    pub fn close_stream(&self, sid: u64) {
        {
            let mut c = self.arena.conn.borrow_mut();
            c.stream_close(sid);
            let _ = c.client_flush();
        }
        self.drain();
    }

    /// Await bytes on `sid`. Returns `(n, eof)`; `(0, true)` once the
    /// stream ends — including by peer reset, which
    /// [`stream_reset_code`](Self::stream_reset_code) distinguishes —
    /// or the connection fails.
    pub async fn recv(&self, sid: u64, out: &mut [u8]) -> (usize, bool) {
        loop {
            if let Some(r) = self.try_recv_inner(sid, out) {
                return r;
            }
            self.arena.progress.reset();
            if let Some(r) = self.try_recv_inner(sid, out) {
                return r;
            }
            self.arena.progress.wait().await;
        }
    }

    /// Non-blocking [`recv`](Self::recv): `None` when nothing is
    /// buffered and the stream is still open.
    pub fn try_recv(&self, sid: u64, out: &mut [u8]) -> Option<(usize, bool)> {
        self.try_recv_inner(sid, out)
    }

    fn try_recv_inner(&self, sid: u64, out: &mut [u8]) -> Option<(usize, bool)> {
        {
            let mut c = self.arena.conn.borrow_mut();
            let (n, eof) = c.stream_recv(sid, out);
            if n > 0 || eof {
                drop(c);
                if n > 0 {
                    self.flush_recv_credit();
                }
                return Some((n, eof));
            }
            if matches!(c.state(), ConnState::Failed) {
                return Some((0, true));
            }
            // S1: a peer RESET_STREAM consumes the recv state without
            // an EOF — complete the read so the caller's
            // `stream_reset_code` check can surface it (parking here
            // instead was a deadlock: the reset never sets eof).
            if c.stream_reset_code(sid).is_some() {
                return Some((0, true));
            }
        }
        None
    }

    /// Pop the next peer-opened (server-initiated) stream id, if any
    /// — non-blocking. The h3 client drains the server's control /
    /// QPACK uni streams through this between response reads.
    pub fn try_accept_stream(&self) -> Option<u64> {
        self.arena.conn.borrow_mut().pop_accepted_stream()
    }

    /// Abort the send side of `sid` with RESET_STREAM (RFC 9000
    /// §19.4) and flush.
    pub fn reset_stream(&self, sid: u64, app_error_code: u64) {
        {
            let mut c = self.arena.conn.borrow_mut();
            c.reset_stream(sid, app_error_code);
            let _ = c.client_flush();
        }
        self.drain();
    }

    /// Ask the peer to stop sending on `sid` (RFC 9000 §19.5) and
    /// flush.
    pub fn stop_sending(&self, sid: u64, app_error_code: u64) {
        {
            let mut c = self.arena.conn.borrow_mut();
            c.stop_sending(sid, app_error_code);
            let _ = c.client_flush();
        }
        self.drain();
    }

    /// Application error code of a peer RESET_STREAM on `sid`, if any.
    pub fn stream_reset_code(&self, sid: u64) -> Option<u64> {
        self.arena.conn.borrow().stream_reset_code(sid)
    }

    /// Whether the connection has failed / closed.
    pub fn is_failed(&self) -> bool {
        matches!(self.arena.conn.borrow().state(), ConnState::Failed)
    }

    /// Close the connection with an immediate CONNECTION_CLOSE
    /// (transport frame; `0x0` = NO_ERROR for an orderly wind-down).
    pub fn close(&self, error_code: u64, reason: &[u8]) {
        fail_conn(&self.arena, &self.udp, error_code, reason);
    }

    fn drain(&self) {
        drain_client_outbound(&self.arena.conn, &self.udp);
    }

    /// Mirror of the server handle's recv-credit flush: replenish
    /// MAX_STREAM_DATA / MAX_DATA promptly after the app drains, so a
    /// window-blocked sender (a large h3 response) isn't stuck
    /// waiting for traffic that would never come.
    fn flush_recv_credit(&self) {
        let due = {
            let mut c = self.arena.conn.borrow_mut();
            let due = c.recv_credit_due();
            if due {
                let _ = c.client_flush();
            }
            due
        };
        if due {
            self.drain();
        }
    }
}
