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

use crate::conn::{ConnError, ConnState, Connection, ConnectionId};
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
    peer_ip: Rc<Cell<uni::runtime::IpAddr>>,
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
    ///
    /// Includes a stuck-handler watchdog: if the await loop runs
    /// for more than `STUCK_THRESHOLD_US` without making progress,
    /// log the recv stream's interior state once. The threshold
    /// is past the typical idle-page render delay (a few hundred
    /// ms) but well before the user notices a stall, so a real
    /// wedge surfaces in the log with the exact state needed to
    /// diagnose it.
    pub async fn recv(&self, sid: u64, out: &mut [u8]) -> (usize, bool) {
        const STUCK_THRESHOLD_US: u64 = 5_000_000; // 5 s
        let entered_us = uni_tls::ticket::now_us();
        let mut warned = false;
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
            if !warned {
                let elapsed = uni_tls::ticket::now_us().saturating_sub(entered_us);
                if elapsed > STUCK_THRESHOLD_US {
                    let state = self.conn.borrow().recv_stream_state(sid);
                    crate::quic_drop!(other_wire,
                        "stuck recv await sid={} elapsed_ms={} state={:?} local_cid={}",
                        sid, elapsed / 1_000, state,
                        crate::endpoint::hex8(&self.local_cid));
                    warned = true;
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

    /// Append bytes to stream `sid` AND mark it for FIN, then
    /// flush — bundles data + FIN into a single STREAM frame
    /// (and a single 1-RTT packet, when the data fits the
    /// per-packet body budget). The two-call pattern
    /// (`send` then `close_stream`) emits FIN in a separate
    /// STREAM frame at offset = N, len = 0, fin = true; some
    /// peers treat that as a stream-finalize signal that arrives
    /// out of order with the data, so prefer this single-call
    /// path for normal request/response.
    pub fn send_fin(&self, sid: u64, data: &[u8]) {
        {
            let mut c = self.conn.borrow_mut();
            c.stream_send(sid, data);
            c.stream_close(sid);
            let _ = c.flush(&self.cfg);
        }
        self.drain_outbound();
    }

    /// Zero-copy variant of `send_fin`: takes ownership of the
    /// payload Vec and passes it straight into the SendStream's
    /// chunk chain, skipping the extend_from_slice memcpy that
    /// `send_fin(&[u8])` performs. Use this whenever the caller
    /// already holds a built Vec (the H3 server's write_response
    /// is the canonical example).
    pub fn send_fin_owned(&self, sid: u64, data: Vec<u8>) {
        {
            let mut c = self.conn.borrow_mut();
            c.stream_send_owned(sid, data);
            c.stream_close(sid);
            let _ = c.flush(&self.cfg);
        }
        self.drain_outbound();
    }

    /// Discard any bytes buffered for `sid`'s recv side without
    /// awaiting. Use for streams the app never intends to read
    /// (e.g. HTTP/3 peer-initiated uni streams: control, QPACK
    /// encoder, QPACK decoder). Without this, a long-lived
    /// connection accumulates QPACK encoder bytes per request
    /// in `recv_streams[sid].buffer` forever.
    pub fn discard_recv(&self, sid: u64) {
        self.conn.borrow_mut().discard_recv(sid);
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
        loop {
            let pkt = {
                let mut c = self.conn.borrow_mut();
                c.pop_packet_owned()
            };
            let pkt = match pkt {
                Some(p) => p,
                None => break,
            };
            let _ = self
                .sock
                .send_to(self.peer_ip.get(), self.peer_port.get(), &pkt);
            crate::diag::bump(&crate::diag::COUNTERS.datagrams_sent);
            self.conn.borrow_mut().recycle_packet(pkt);
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
    loop {
        // Allocate the recv buffer per iteration so we can move it
        // straight into the Datagram on push, eliminating the
        // `dgram_bytes.to_vec()` memcpy. Same-size allocations are
        // friendly to the talc allocator's free-list. For
        // recoverable bursts the conn task drops these Vecs after
        // process_datagram (which mutates them in place); reuse
        // would require cross-task plumbing not worth the
        // complexity here.
        let mut buf = vec![0u8; 1500];
        let (src_ip, src_port, n) = sock.recv_from(&mut buf).await;
        if n == 0 {
            continue;
        }
        buf.truncate(n);
        let dcid = match extract_dcid(&buf) {
            Some(d) => d,
            None => {
                crate::quic_drop!(no_dcid, "datagram_size={} first={:#x}",
                    buf.len(),
                    buf.first().copied().unwrap_or(0));
                continue;
            }
        };

        // Try the slot table first: if this DCID's first 4 bytes
        // decode as a (slot, gen) pair we recognise, route to
        // that conn. This is the steady-state path — every
        // post-first-reply packet from the client echoes our
        // server-chosen SCID as its DCID.
        if let Some((slot_idx, generation)) = parse_local_cid(&dcid) {
            if let Some(inbox) = slots.lookup(slot_idx, generation) {
                let dgram_size = buf.len();
                let pushed = inbox.push(Datagram {
                    src_ip,
                    src_port,
                    bytes: buf,
                });
                if !pushed {
                    crate::quic_drop!(inbox_full_drops,
                        "size={} slot={} gen={}",
                        dgram_size, slot_idx, generation);
                }
                continue;
            }
        }

        // Try the client-chosen-DCID map BEFORE the Initial-only
        // gate. The map serves two related cases:
        //
        //   1. Multi-packet ClientHello: every Initial fragment
        //      shares one client-chosen DCID; without this lookup
        //      every fragment would allocate a fresh ghost conn.
        //   2. Coalesced/standalone 0-RTT (or Handshake) packets
        //      addressed to that same client-chosen DCID — the
        //      client uses it for ALL packets until it's seen our
        //      first Initial reply (and learned our SCID). 0-RTT
        //      packets in particular often arrive in their own
        //      datagram (Chrome routinely sends Initial+0-RTT in
        //      the SAME datagram, but on retransmit they may
        //      arrive separately), so a long-header non-Initial
        //      packet for a known initial-DCID MUST route to the
        //      same conn — otherwise we drop the 0-RTT data.
        if let Some(inbox) = slots.lookup_initial_dcid(&dcid) {
            let dgram_size = buf.len();
            crate::quic_event!(initial_dcid_hit,
                "size={} dcid={}", dgram_size, hex8(&dcid));
            let pushed = inbox.push(Datagram {
                src_ip,
                src_port,
                bytes: buf,
            });
            if !pushed {
                crate::quic_drop!(inbox_full_drops,
                    "size={} initial-dcid", dgram_size);
            }
            continue;
        }

        // No prior conn for this DCID. If it's a long-header
        // Initial we'll allocate one; otherwise drop.
        if !is_long_header_initial(&buf) {
            // Wrong-length DCID, short-header for unknown conn,
            // or Handshake/0-RTT/Retry without a matching slot
            // — drop. (Stateless reset is out of scope.)
            let first = buf.first().copied().unwrap_or(0);
            if first & 0x80 == 0 {
                crate::quic_drop!(unknown_short_header,
                    "size={} dcid={}", buf.len(), hex8(&dcid));
            } else {
                crate::quic_drop!(unknown_long_header,
                    "size={} dcid={} first={:#x}",
                    buf.len(), hex8(&dcid), first);
            }
            continue;
        }

        let (slot_idx, generation) = match slots.allocate(src_ip) {
            Some(x) => x,
            None => {
                // Either the global table is full or this src_ip
                // is already at its per-IP cap. Both surface as
                // `slot_table_full` for now; the inbox unit tests
                // distinguish them.
                crate::quic_drop!(slot_table_full,
                    "dcid={} src_ip={:?}", hex8(&dcid), src_ip);
                continue;
            }
        };
        slots.register_initial_dcid(&dcid, slot_idx, generation);
        let mut nonce = [0u8; 4];
        if getrandom::getrandom(&mut nonce).is_err() {
            crate::quic_drop!(rng_failed, "minting CID nonce");
            continue;
        }
        let local_cid_bytes = make_local_cid(slot_idx, generation, nonce);
        let local_cid = ConnectionId::new(&local_cid_bytes);
        crate::quic_event!(conns_allocated,
            "slot={} gen={} dcid={} local_cid={}",
            slot_idx, generation, hex8(&dcid), hex8(&local_cid_bytes));

        let inbox = ConnInbox::new();
        slots.install(slot_idx, generation, &inbox);

        // Push the first datagram into the inbox before spawning
        // so the conn task wakes immediately and processes the
        // ClientHello on its first poll.
        inbox.push(Datagram {
            src_ip,
            src_port,
            bytes: buf,
        });

        let mut seed = [0u8; 32];
        if getrandom::getrandom(&mut seed).is_err() {
            crate::quic_drop!(rng_failed, "minting per-conn TLS seed");
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
    // Seed last_recv at conn creation so a peer that allocates a
    // slot via Initial and then disappears gets reaped after the
    // idle window (the listener has already pushed the first
    // datagram into the inbox; we'll process it on the first loop
    // iteration and refresh last_recv there).
    conn.borrow_mut().set_last_recv_now();
    let progress = Rc::new(AsyncEvent::new());
    let peer_ip: Rc<Cell<uni::runtime::IpAddr>> =
        Rc::new(Cell::new(uni::runtime::IpAddr::V4_ANY));
    let peer_port: Rc<Cell<u16>> = Rc::new(Cell::new(0));
    let mut handler_spawned = false;

    loop {
        crate::diag::bump(&crate::diag::COUNTERS.conn_task_iterations);
        // Race the inbox against a single combined timer that
        // fires at the earliest of: idle-timeout deadline,
        // PTO deadline (if any in-flight ack-eliciting packets).
        // After wake we figure out which one fired, since `select`
        // is binary: we know the timer fired, then check now()
        // against each deadline independently.
        let (idle_us, last_recv_us, pto_deadline) = {
            let c = conn.borrow();
            (c.idle_timeout_us(), c.last_recv_us(), c.pto_deadline_us())
        };
        let now = uni_tls::ticket::now_us();
        let elapsed = now.saturating_sub(last_recv_us);
        if elapsed >= idle_us {
            crate::quic_event!(idle_timeouts,
                "elapsed_us={} idle_us={} local_cid={}",
                elapsed, idle_us, hex8(&local_cid_bytes));
            break;
        }
        let idle_deadline = last_recv_us + idle_us;
        let timer_deadline = match pto_deadline {
            Some(p) => p.min(idle_deadline),
            None => idle_deadline,
        };
        let remaining = timer_deadline.saturating_sub(now).max(1);

        let dgram = match uni::runtime::select(
            inbox.pop(),
            uni::runtime::sleep_us(remaining),
        ).await {
            uni::runtime::Either::Left(Some(d)) => d,
            uni::runtime::Either::Left(None) => break, // inbox closed
            uni::runtime::Either::Right(()) => {
                // Timer fired. Distinguish PTO vs idle by which
                // deadline was earlier and is now in the past.
                let after = uni_tls::ticket::now_us();
                if let Some(p) = pto_deadline {
                    if after >= p && p < idle_deadline {
                        // PTO fired first — emit a probe and loop
                        // back. Don't break; PTO is recovery, not
                        // teardown.
                        let probed = conn.borrow_mut().send_pto_probe();
                        if probed {
                            crate::diag::COUNTERS
                                .pto_probes_sent
                                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                            // Drain the probe to the wire
                            // immediately via the ownership-
                            // transfer pop + recycle pattern.
                            loop {
                                let pkt = match conn.borrow_mut().pop_packet_owned() {
                                    Some(p) => p,
                                    None => break,
                                };
                                let _ = sock.send_to(peer_ip.get(), peer_port.get(), &pkt);
                                crate::diag::bump(&crate::diag::COUNTERS.datagrams_sent);
                                conn.borrow_mut().recycle_packet(pkt);
                            }
                        }
                        continue;
                    }
                }
                // Idle path.
                crate::quic_event!(idle_timeouts,
                    "elapsed_us={} idle_us={} local_cid={}",
                    after.saturating_sub(last_recv_us),
                    idle_us, hex8(&local_cid_bytes));
                break;
            }
        };
        // Process the awaited datagram, then opportunistically
        // drain anything else already queued. Each
        // `process_datagram` call also runs `flush_outbound`,
        // which can emit up to 33 packets — without batching, a
        // burst of 32 inbound datagrams from a refresh-spamming
        // browser fills the 256-slot inbox faster than the
        // listener-→drain pipeline can shift, and the listener
        // starts dropping. Batching here lets one wake service
        // many queued datagrams.
        const BATCH_LIMIT: usize = 32;
        let mut tearing_down = false;
        let mut current = Some(dgram);
        let mut processed = 0usize;
        while let Some(d) = current.take() {
            peer_ip.set(d.src_ip);
            peer_port.set(d.src_port);
            // Pass the datagram as `&mut [u8]` so the per-packet
            // processors can do HP-unprotect + AEAD-decrypt in
            // place rather than allocating a fresh buffer per
            // packet. The Datagram owns its bytes Vec, so taking
            // mutable access is straightforward.
            let dgram_size = d.bytes.len();
            let mut bytes = d.bytes;
            let result = conn.borrow_mut().process_datagram(&mut bytes, &cfg);
            if let Err(e) = result {
                crate::quic_drop!(other_wire,
                    "process_datagram failed: {:?} dgram_size={} local_cid={}",
                    e, dgram_size, hex8(&local_cid_bytes));
                let (code, reason): (u64, &[u8]) = match e {
                    ConnError::Wire => (0x0a, b"protocol_violation"),
                    ConnError::Decrypt => (0x0a, b"crypto_error"),
                    ConnError::Tls => (0x0a, b"tls_alert"),
                    ConnError::BadState => (0x01, b"internal_error"),
                    ConnError::OutputTooSmall => (0x01, b"internal_error"),
                    ConnError::UnsupportedVersion => (0x0a, b"unsupported_version"),
                };
                {
                    let mut c = conn.borrow_mut();
                    c.close_with_error(code, reason);
                    c.flush_close();
                }
                tearing_down = true;
                break;
            }
            processed += 1;
            if processed >= BATCH_LIMIT {
                break;
            }
            current = inbox.try_pop();
        }

        // Drain outbound packets to the peer. Each iteration
        // takes the front Vec by ownership (`pop_packet_owned`),
        // sends without copying it into a local scratch buffer,
        // then returns the Vec to the conn's recycle pool. The
        // memcpy that the slice-based `pop_packet` would have
        // performed disappears, and the Vec gets reused on the
        // next encode rather than dropped.
        loop {
            let pkt = match conn.borrow_mut().pop_packet_owned() {
                Some(p) => p,
                None => break,
            };
            let _ = sock.send_to(peer_ip.get(), peer_port.get(), &pkt);
            crate::diag::bump(&crate::diag::COUNTERS.datagrams_sent);
            conn.borrow_mut().recycle_packet(pkt);
        }
        if tearing_down {
            break;
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
/// Compact hex of up to the first 8 bytes of a slice, for log lines.
/// Connection IDs are 8 bytes max in our scheme, so this hits the
/// whole CID; arbitrary slices get truncated with `..`.
pub(crate) fn hex8(b: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(20);
    let n = b.len().min(8);
    for &byte in &b[..n] {
        let _ = write!(s, "{:02x}", byte);
    }
    if b.len() > 8 {
        s.push_str("..");
    }
    s
}

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
