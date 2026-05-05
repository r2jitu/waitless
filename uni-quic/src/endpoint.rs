// uni-quic/src/endpoint.rs — QUIC v1 UDP endpoint + dispatcher.
//
// Binds a UDP port, drives the per-worker endpoint loop, and
// maintains the per-worker slot table. The endpoint:
//
//   1. Calls `recv_from` on the bound socket.
//   2. Parses just enough of the long/short header to extract
//      the DCID. (No decrypt — the per-conn task does that.)
//   3. Looks up the DCID in the slot table:
//      - 8-byte DCID encoded with our slot scheme → array index +
//        generation match → existing conn task; push datagram
//        into its inbox.
//      - DCID we don't recognise + Initial packet type → allocate
//        a fresh slot, build a local CID, spawn a new conn task.
//      - Anything else → drop.
//
// One async task per connection. The task owns the `Connection`
// state machine and an `Rc<UdpSocket>` for sending replies. It
// `.await`s its `ConnInbox` for new datagrams; on each, it runs
// `Connection::process_datagram` and drains outbound packets via
// `pop_packet` + `sock.send_to`. When the connection ends
// (Established + a future state-change to Closing/Closed, or
// fatal error), the task exits and its `Rc<ConnInbox>` drops —
// the slot's `Weak` upgrade fails on the next allocator pass and
// the slot is implicitly free.
//
// Per-worker isolation: there's one `QuicListener` task per
// worker (just like `udp_listen`), each with its own slot table.
// All datagrams arrive at the worker their 4-tuple flow-hash
// routes them to, so a single connection always lands on the
// same worker — no cross-worker state migration.

#![allow(dead_code)]

use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::cell::{Cell, RefCell};
use core::future::Future;

use crate::wire::{long_packet_type, parse_long_header_preamble, FIXED_BIT, HEADER_FORM_LONG};

use uni::runtime::{spawn, AsyncEvent, UdpSocket};

use crate::conn::{ConnState, Connection, ConnectionId};
use crate::inbox::{
    make_local_cid, parse_local_cid, ConnInbox, Datagram, SlotTable, SERVER_CID_LEN,
};
use uni_tls::TlsServerConfig;

/// Maximum simultaneous QUIC connections per worker. Each slot
/// is ~16 bytes (gen + Weak), so 1024 slots ≈ 16 KiB per worker
/// — comfortably small. Real connection state lives in the conn
/// task's stack frame, not in the slot.
pub const SLOTS_PER_WORKER: usize = 1024;

/// Errors from `quic_listen` — mirrors `udp_listen`'s error
/// surface so the call site looks the same.
#[derive(Debug)]
pub enum QuicListenError {
    /// UDP bind failed (port in use, registry full, …).
    Bind(uni::runtime::UdpBindError),
    /// Cert / key parse failure.
    CertOrKey,
}

/// Handle returned by `quic_listen`. Drops the listener (and all
/// active connections) when this falls out of scope. Same pattern
/// as `uni::runtime::UdpHandle` / `TcpHandle`.
pub struct QuicListener {
    _udp: uni::runtime::UdpHandle,
}

/// Public per-connection handle the user's handler closure
/// receives. Wraps an `Rc<RefCell<Connection>>` shared with the
/// conn task plus the metadata needed to send replies and wait
/// for new stream activity. Both halves run on the same worker —
/// no cross-worker locking, just RefCell + an `AsyncEvent` for
/// waking the handler when new data arrives.
pub struct QuicConn {
    /// Same `Connection` the conn task drives. The handler reads
    /// stream state via shared borrows + writes outbound via
    /// short mutable borrows, never holding a borrow across an
    /// `.await`.
    conn: Rc<RefCell<Connection>>,
    /// Cert / key bundle. Needed by `flush()` to drive the TLS
    /// state machine even when we're emitting only application
    /// data on an already-Established connection.
    cfg: Arc<TlsServerConfig>,
    /// UDP socket used for outbound packets (the same one the
    /// listener bound).
    sock: Arc<UdpSocket>,
    /// Peer 4-tuple. Updated by the conn task on every inbound
    /// datagram so connection migration "just works" — handler
    /// reads the latest values when it sends a reply.
    peer_ip: Rc<Cell<[u8; 4]>>,
    peer_port: Rc<Cell<u16>>,
    /// Wakes the handler when the conn task ingested an inbound
    /// datagram (new stream data may be available, conn state
    /// may have changed). Manual-reset; consumer drives the
    /// reset cycle via the await loop in `accept_stream` /
    /// `recv`.
    progress: Rc<AsyncEvent>,
    /// The local CID we issued for this connection. App code can
    /// log it as a connection identifier. Stored as bytes since
    /// `ConnectionId` itself is internal.
    pub local_cid: [u8; SERVER_CID_LEN],
}

impl QuicConn {
    /// Local CID we issued — useful as a connection identifier in
    /// logs / handler diagnostics.
    pub fn local_cid(&self) -> [u8; SERVER_CID_LEN] {
        self.local_cid
    }

    /// Await the next stream the peer has opened. Returns `None`
    /// if the connection failed before any stream arrived.
    pub async fn accept_stream(&self) -> Option<u64> {
        loop {
            {
                let mut c = self.conn.borrow_mut();
                if let Some(id) = c.pop_accepted_stream() {
                    return Some(id);
                }
                if matches!(c.state(), ConnState::Failed) {
                    return None;
                }
            }
            self.progress.reset();
            // Re-check after reset to close the wake / observe race.
            {
                let mut c = self.conn.borrow_mut();
                if let Some(id) = c.pop_accepted_stream() {
                    return Some(id);
                }
                if matches!(c.state(), ConnState::Failed) {
                    return None;
                }
            }
            self.progress.wait().await;
        }
    }

    /// Read up to `out.len()` bytes from stream `sid`. Returns
    /// `(bytes_copied, eof)`. `eof = true` once FIN has been
    /// observed AND every byte has been drained.
    pub async fn recv(&self, sid: u64, out: &mut [u8]) -> (usize, bool) {
        loop {
            {
                let mut c = self.conn.borrow_mut();
                let (n, eof) = c.stream_recv(sid, out);
                if n > 0 || eof {
                    return (n, eof);
                }
                if matches!(c.state(), ConnState::Failed) {
                    return (0, true);
                }
            }
            self.progress.reset();
            {
                let mut c = self.conn.borrow_mut();
                let (n, eof) = c.stream_recv(sid, out);
                if n > 0 || eof {
                    return (n, eof);
                }
                if matches!(c.state(), ConnState::Failed) {
                    return (0, true);
                }
            }
            self.progress.wait().await;
        }
    }

    /// Append bytes to stream `sid`'s send queue and immediately
    /// drain any outbound packets onto the wire. Synchronous: by
    /// the time `send` returns, the bytes have been sealed into
    /// 1-RTT packets and `sendto`'d on the UDP socket.
    pub fn send(&self, sid: u64, data: &[u8]) {
        {
            let mut c = self.conn.borrow_mut();
            c.stream_send(sid, data);
            let _ = c.flush(&self.cfg);
        }
        self.drain_outbound();
    }

    /// Mark stream `sid` as closed (FIN). The next outbound STREAM
    /// frame will carry the FIN flag. Drains any packets the
    /// flush produced.
    pub fn close_stream(&self, sid: u64) {
        {
            let mut c = self.conn.borrow_mut();
            c.stream_close(sid);
            let _ = c.flush(&self.cfg);
        }
        self.drain_outbound();
    }

    fn drain_outbound(&self) {
        let mut out = vec![0u8; 1500];
        loop {
            let n = {
                let mut c = self.conn.borrow_mut();
                c.pop_packet(&mut out)
            };
            if n == 0 {
                break;
            }
            let _ = self
                .sock
                .send_to(self.peer_ip.get(), self.peer_port.get(), &out[..n]);
        }
    }
}

/// Start a per-worker QUIC server bound to `port`. `cert_der` and
/// `key_pkcs8_der` are the same blobs `uni_tls::acceptor` accepts
/// — typically `include_bytes!`'d at compile time. `handler` runs
/// once per accepted connection as `async fn(QuicConn) -> ()`.
///
/// Returns a `QuicListener` whose `Drop` tears down the listener
/// and aborts in-flight conn tasks. Store on a long-lived owner
/// (the app's main struct, leaked into a static, etc.) so the
/// listener persists.
///
/// **Per-worker shape:** internally calls `uni::runtime::udp_listen`
/// with a per-worker body. Each worker gets its own `SlotTable` and
/// its own listener loop; QUIC connections stay pinned to the
/// worker that received their first Initial.
pub fn quic_listen<H, F>(
    port: u16,
    cert_der: &'static [u8],
    key_pkcs8_der: &'static [u8],
    handler: H,
) -> Result<QuicListener, QuicListenError>
where
    H: Fn(QuicConn) -> F + Send + Sync + 'static,
    F: Future<Output = ()> + 'static,
{
    let cfg = TlsServerConfig::from_dev_cert(cert_der, key_pkcs8_der)
        .ok_or(QuicListenError::CertOrKey)?;
    // Cross-worker captures must be Send + Sync. `TlsServerConfig`
    // already is (cert is &'static [u8], SigningKey is Sync per p256).
    // Each per-worker future converts to Rc inside the task so the
    // hot path stays single-threaded.
    let cfg_arc: Arc<TlsServerConfig> = Arc::new(cfg);
    let handler_arc: Arc<H> = Arc::new(handler);

    let udp = UdpSocket::bind(port).map_err(QuicListenError::Bind)?;
    let udp_handle = udp.run(move |sock: Arc<UdpSocket>| {
        // Each per-worker invocation: capture Arc clones (cheap,
        // refcount-only). Arcs deref to &T just like Rc would,
        // so the conn-task code is identical regardless of which
        // smart pointer holds the cfg / handler.
        let cfg = cfg_arc.clone();
        let handler = handler_arc.clone();
        async move {
            let slots = Rc::new(SlotTable::new(SLOTS_PER_WORKER));
            listener_loop(sock, slots, cfg, handler).await;
        }
    });

    Ok(QuicListener { _udp: udp_handle })
}

// ============================================================================
// Listener loop (per worker)
// ============================================================================

async fn listener_loop<H, F>(
    sock: Arc<UdpSocket>,
    slots: Rc<SlotTable>,
    cfg: Arc<TlsServerConfig>,
    handler: Arc<H>,
) where
    H: Fn(QuicConn) -> F + Send + Sync + 'static,
    F: Future<Output = ()> + 'static,
{
    let mut buf = vec![0u8; 1500];
    loop {
        let (src_ip, src_port, n) = sock.recv_from(&mut buf).await;
        if n == 0 {
            continue;
        }
        let dgram_bytes = &buf[..n];
        // Extract DCID. Long-header packets carry it explicitly
        // (parse_long_header_preamble); short-header packets put
        // it at a fixed offset (caller-known length = SERVER_CID_LEN
        // for our server-issued CIDs).
        let dcid = match extract_dcid(dgram_bytes) {
            Some(d) => d,
            None => continue, // junk
        };

        // Try the slot table first: if this DCID's first 4 bytes
        // decode as a (slot, gen) pair we recognise, route to
        // that conn.
        if let Some((slot_idx, generation)) = parse_local_cid(&dcid) {
            if let Some(inbox) = slots.lookup(slot_idx, generation) {
                inbox.push(Datagram {
                    src_ip,
                    src_port,
                    bytes: dgram_bytes.to_vec(),
                });
                continue;
            }
        }

        // Not an existing conn. If it's a long-header Initial
        // packet, allocate a slot and spawn a new conn task.
        if !is_long_header_initial(dgram_bytes) {
            // Wrong-length DCID, short-header for unknown conn,
            // or Handshake/0-RTT/Retry without a matching slot
            // — drop. (Stateless reset is out of scope.)
            continue;
        }

        let (slot_idx, generation) = match slots.allocate() {
            Some(x) => x,
            None => continue, // slot table full, drop
        };
        let mut nonce = [0u8; 4];
        if getrandom::getrandom(&mut nonce).is_err() {
            continue;
        }
        let local_cid_bytes = make_local_cid(slot_idx, generation, nonce);
        let local_cid = ConnectionId::new(&local_cid_bytes);

        let inbox = ConnInbox::new();
        slots.install(slot_idx, generation, &inbox);

        // Push the first datagram into the inbox before spawning
        // so the conn task wakes immediately and processes the
        // ClientHello on its first poll.
        inbox.push(Datagram {
            src_ip,
            src_port,
            bytes: dgram_bytes.to_vec(),
        });

        let mut seed = [0u8; 32];
        if getrandom::getrandom(&mut seed).is_err() {
            continue;
        }
        let task_inbox = inbox.clone();
        let task_sock = sock.clone();
        let task_cfg = cfg.clone();
        let task_handler = handler.clone();
        let _ = spawn(conn_task::<H, F>(
            task_inbox,
            task_sock,
            task_cfg,
            task_handler,
            local_cid,
            local_cid_bytes,
            seed,
        ));
    }
}

// ============================================================================
// Per-connection task
// ============================================================================

async fn conn_task<H, F>(
    inbox: Rc<ConnInbox>,
    sock: Arc<UdpSocket>,
    cfg: Arc<TlsServerConfig>,
    handler: Arc<H>,
    local_cid: ConnectionId,
    local_cid_bytes: [u8; SERVER_CID_LEN],
    seed: [u8; 32],
) where
    H: Fn(QuicConn) -> F + Send + Sync + 'static,
    F: Future<Output = ()> + 'static,
{
    let conn = Rc::new(RefCell::new(Connection::new_server(local_cid, seed)));
    let progress = Rc::new(AsyncEvent::new());
    let peer_ip: Rc<Cell<[u8; 4]>> = Rc::new(Cell::new([0; 4]));
    let peer_port: Rc<Cell<u16>> = Rc::new(Cell::new(0));
    let mut handler_spawned = false;

    loop {
        let dgram = match inbox.pop().await {
            Some(d) => d,
            None => break,
        };
        peer_ip.set(dgram.src_ip);
        peer_port.set(dgram.src_port);
        let result = conn.borrow_mut().process_datagram(&dgram.bytes, &cfg);
        if result.is_err() {
            break;
        }

        // Drain outbound packets to the peer. Each iteration
        // borrows the cell briefly, drops, then `send_to`'s.
        let mut out = vec![0u8; 1500];
        loop {
            let n = conn.borrow_mut().pop_packet(&mut out);
            if n == 0 {
                break;
            }
            let _ = sock.send_to(peer_ip.get(), peer_port.get(), &out[..n]);
        }

        // Wake the handler in case new stream data arrived.
        progress.set();

        // Once the handshake completes, spawn the user's handler
        // as its OWN task on this worker. The conn task keeps
        // pumping the connection's inbox (retransmits, future
        // 1-RTT control frames); the handler awaits stream
        // primitives. Splitting the two means a slow handler
        // can't stall wire-level service.
        let est = matches!(conn.borrow().state(), ConnState::Established);
        if !handler_spawned && est {
            handler_spawned = true;
            let qconn = QuicConn {
                conn: Rc::clone(&conn),
                cfg: cfg.clone(),
                sock: Arc::clone(&sock),
                peer_ip: Rc::clone(&peer_ip),
                peer_port: Rc::clone(&peer_port),
                progress: Rc::clone(&progress),
                local_cid: local_cid_bytes,
            };
            let handler_fn = handler.clone();
            let _ = spawn(async move {
                handler_fn(qconn).await;
            });
        }

        if matches!(conn.borrow().state(), ConnState::Failed) {
            // Wake the handler one last time so its await loops
            // can observe `Failed` and exit.
            progress.set();
            break;
        }
    }
    progress.set();
    // Inbox closed or fatal error — drop everything. The slot
    // table's Weak pointer to `inbox` will fail to upgrade on the
    // next allocator pass, freeing the slot implicitly.
}

// ============================================================================
// Header peek helpers
// ============================================================================

/// Pull the DCID out of a packet's bytes. Long-header packets
/// expose it in the standard place; short-header packets
/// (1-RTT) have an endpoint-known DCID length, which for us is
/// always `SERVER_CID_LEN`. Returns `None` for malformed inputs.
fn extract_dcid(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let first = bytes[0];
    if first & FIXED_BIT == 0 {
        return None; // QUIC v1 always has fixed bit set
    }
    if first & HEADER_FORM_LONG != 0 {
        let pre = parse_long_header_preamble(bytes).ok()?;
        Some(pre.dcid.to_vec())
    } else {
        // Short header: bytes[0] is first byte; bytes[1..1+CID_LEN]
        // is DCID. We always issue 8-byte CIDs, so look there.
        if bytes.len() < 1 + SERVER_CID_LEN {
            return None;
        }
        Some(bytes[1..1 + SERVER_CID_LEN].to_vec())
    }
}

fn is_long_header_initial(bytes: &[u8]) -> bool {
    let pre = match parse_long_header_preamble(bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    pre.long_type == long_packet_type::INITIAL
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_dcid_long_header() {
        // Build a minimal long-header Initial header.
        let mut buf = vec![];
        buf.push(0xc0); // long(1) | fixed(1) | type=Initial(00)
        buf.extend_from_slice(&1u32.to_be_bytes()); // version
        buf.push(8); // DCID len
        buf.extend_from_slice(&[0xa1; 8]);
        buf.push(0); // SCID len
        buf.push(0); // Token Length VARINT = 0
        buf.push(0x40); // Length VARINT (2-byte form)
        buf.push(0x01);
        let dcid = extract_dcid(&buf).unwrap();
        assert_eq!(&dcid[..], &[0xa1; 8]);
    }

    #[test]
    fn extract_dcid_short_header() {
        let mut buf = vec![];
        buf.push(0x40); // form=short, fixed=1
        buf.extend_from_slice(&[0xb2; SERVER_CID_LEN]);
        buf.extend_from_slice(&[0x99; 4]); // PN + payload
        let dcid = extract_dcid(&buf).unwrap();
        assert_eq!(&dcid[..], &[0xb2; SERVER_CID_LEN]);
    }

    #[test]
    fn extract_dcid_rejects_zero_fixed_bit() {
        let buf = [0x80u8, 0, 0, 0, 0]; // form=long, fixed=0
        assert!(extract_dcid(&buf).is_none());
    }

    #[test]
    fn is_long_header_initial_recognises_initial() {
        let mut buf = vec![];
        buf.push(0xc0); // long | fixed | type=Initial
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.push(0);
        buf.push(0);
        assert!(is_long_header_initial(&buf));
        // Type=Handshake should be false.
        let mut buf2 = buf.clone();
        buf2[0] = 0xe0; // type=Handshake
        assert!(!is_long_header_initial(&buf2));
    }
}
