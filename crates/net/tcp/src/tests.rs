// ── Host-native TCP conformance harness ─────────────────────────────────────
//
// packetdrill-style: drive scripted TCP segments into `tcp_receive`
// against a mock `NicOps` that captures every transmitted frame into a
// `Vec`, then assert on the captured output. `tcp_receive` is the real
// RX entry point and the send path is the real TX code — only the NIC
// underneath is mocked.
//
// `tcp.rs`'s per-core pools (`POOLS`, `TCP_HASH`) and the NIC-ops slot
// are process-global, so the scenarios cannot run concurrently:
// `TEST_LOCK` serialises them, and each uses a distinct 4-tuple so
// connection-pool state never bleeds between tests.
//
// The module include in `lib.rs` is already `#[cfg(test)]`; an inner
// `#![cfg(test)]` here would be a duplicated-attribute clippy lint.

use super::*;
use alloc::boxed::Box;
use core::ptr::NonNull;
use from_bytes::FromBytes;
use iobuf::{Chain, IOBufDropFn, OwnedIOBuf};
use nic_api::{CsumOffload, NicOps, set_active_ops};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, Once};
use types::{IpAddr, Ipv4Addr, ntohl, ntohs};

const SERVER_IP: [u8; 4] = [10, 0, 0, 1];
const CLIENT_IP: [u8; 4] = [10, 0, 0, 2];
const SERVER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x00, 0x01];

// ---- mock NIC: capture every transmitted frame ------------------------

static TX: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

// ---- lossy-network egress fixture -------------------------------------
//
// `mock_send` consults a deterministic drop policy before recording a
// frame. A dropped egress frame is *not* pushed to `TX` — it models a
// frame the client never received — so a scenario that drops a
// transmission and then asserts on the eventual retransmit captures the
// recovered frame, not the lost one. Deterministic (drop-the-next-N or
// drop-where-predicate), never random: conformance scenarios must be
// reproducible. `harness()` clears the policy so a drop armed by one
// scenario can't leak into the next.
//
// This is the test seam the timer- and loss-driven scenarios (FIN
// retransmit, fast retransmit) need — the corners that are invisible on
// a loss-free LAN/VM path.
type EgressPred = Box<dyn FnMut(&[u8]) -> bool + Send>;
static EGRESS_DROP: Mutex<Option<EgressPred>> = Mutex::new(None);
static EGRESS_DROPPED: AtomicU32 = AtomicU32::new(0);

fn mock_send(frame: &[u8], _csum: CsumOffload) {
    {
        let mut policy = EGRESS_DROP.lock().unwrap();
        if let Some(pred) = policy.as_mut()
            && pred(frame)
        {
            // Lost on the wire — the client never sees it, so it
            // does not enter the `TX` capture.
            EGRESS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    TX.lock().unwrap().push(frame.to_vec());
}

/// Drop every egress frame for which `pred` returns true. The building
/// block for the loss scenarios; `drop_next_egress` wraps it for the
/// common count-based case.
fn drop_egress_where(pred: impl FnMut(&[u8]) -> bool + Send + 'static) {
    *EGRESS_DROP.lock().unwrap() = Some(Box::new(pred));
}

/// Drop the next `n` egress frames, then deliver normally.
fn drop_next_egress(n: u32) {
    let mut remaining = n;
    drop_egress_where(move |_| {
        if remaining > 0 {
            remaining -= 1;
            true
        } else {
            false
        }
    });
}

/// Count of egress frames the fixture has dropped since the last
/// `harness()` reset.
fn egress_drops() -> u32 {
    EGRESS_DROPPED.load(Ordering::Relaxed)
}
fn mock_get_mac(out: *mut u8) {
    // SAFETY: the NIC-dispatch contract guarantees `out` addresses
    // six writable bytes.
    unsafe { core::ptr::copy_nonoverlapping(SERVER_MAC.as_ptr(), out, 6) };
}
fn yes() -> bool {
    true
}
fn no() -> bool {
    false
}
fn unit() {}
fn no_poll(_: fn(Chain<OwnedIOBuf>)) -> usize {
    0
}
fn no_poll_qp(_: usize, _: fn(Chain<OwnedIOBuf>)) -> usize {
    0
}
fn one_qp() -> u16 {
    1
}

// `acquire_tx_buf` / TSO left `None`, so every transmit funnels
// through `send` — the one path the capture hook covers. The
// stack stamps a pseudo-header partial sum; a real driver finishes
// the L4 checksum, but the conformance assertions check headers /
// seq / ack / payload, not the checksum, so the mock just records
// the frame bytes.
static MOCK_OPS: NicOps = NicOps {
    name: "mock",
    probe: yes,
    send: mock_send,
    acquire_tx_buf: None,
    submit_tx: None,
    tso_available: no,
    acquire_tx_tso_buf: None,
    submit_tx_tso: None,
    udp_gso_available: no,
    acquire_tx_udp_gso_buf: None,
    submit_tx_udp_gso: None,
    poll_rx: no_poll,
    poll_qp: no_poll_qp,
    get_mac: mock_get_mac,
    num_queue_pairs: one_qp,
    enable_irq: unit,
    enable_deferred_tx_kick: unit,
    flush_tx_staging: unit,
    flush_tx_kick_if_dirty: no,
    poke_interrupt_status: unit,
    idle: None,
    diag: None,
};

// ---- one-time bring-up + per-test serialisation -----------------------

static SETUP: Once = Once::new();
static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Lock out the other scenarios, run global bring-up once, and
/// start with an empty TX capture. The returned guard serialises
/// the test for as long as it is held.
fn harness() -> std::sync::MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    SETUP.call_once(|| {
        worker::set_num_workers(1);
        super::init(); // TCP per-core pools
        ipv4::init(); // per-core IP-ID counter (the TX path stamps it)
        ethernet::set_our_mac(SERVER_MAC);
        set_active_ops(&MOCK_OPS);
    });
    TX.lock().unwrap().clear();
    // Hand every scenario a pristine connection pool — `on_tcp_tick`
    // walks the whole pool, so a leftover armed conn would pollute it.
    reset_pool();
    // Clear any egress drop policy so a loss armed by an earlier
    // scenario cannot leak into this one.
    *EGRESS_DROP.lock().unwrap() = None;
    EGRESS_DROPPED.store(0, Ordering::Relaxed);
    // Start every scenario at t=0 so a timer-driven test never
    // inherits clock advanced by an earlier one.
    kernel_core::clock::mock::reset();
    guard
}

/// Snapshot the captured frames.
fn tx() -> Vec<Vec<u8>> {
    TX.lock().unwrap().clone()
}

/// Drop the captured frames — used to open a fresh assertion
/// window mid-scenario (e.g. after the handshake).
fn clear_tx() {
    TX.lock().unwrap().clear();
}

/// Free every connection slot on core 0 so each scenario starts with a
/// pristine pool. The retransmission tick (`on_tcp_tick`) and the
/// lifecycle tick walk the whole per-core pool, so a connection left
/// armed by an earlier scenario would otherwise fire a timer into this
/// scenario's `TX` capture — distinct 4-tuples isolate hash lookups
/// but not pool-global timer ticks.
fn reset_pool() {
    let core = 0u32;
    let cap = pool_capacity(core);
    for i in 0..cap {
        // SAFETY: single worker, test-serialised by `TEST_LOCK`.
        let c = unsafe { &*conn_ptr(core, i) };
        if c.state != TcpState::Closed {
            super::free_connection(core, i);
        }
    }
}

// ---- scripted segment construction / parsing --------------------------

/// A scripted inbound TCP segment. `tcp_receive` is handed the
/// chain already narrowed to the TCP header, so the harness builds
/// no Ethernet/IP for the inbound direction.
struct Seg {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: Vec<u8>,
}

impl Seg {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(TCP_HDR_LEN + self.payload.len());
        b.extend_from_slice(&self.src_port.to_be_bytes());
        b.extend_from_slice(&self.dst_port.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.ack.to_be_bytes());
        b.push(5 << 4); // data offset = 5 32-bit words (a 20-byte header)
        b.push(self.flags);
        b.extend_from_slice(&self.window.to_be_bytes());
        b.extend_from_slice(&[0, 0]); // checksum — tcp_receive does not verify it
        b.extend_from_slice(&[0, 0]); // urgent pointer
        b.extend_from_slice(&self.payload);
        b
    }
}

/// Drop callback for `make_chain` — reclaims the `Box<[u8]>` whose
/// region was handed to `wrap_owned`.
///
/// SAFETY: `base`/`cap` are the `(ptr, len)` of a `Box::<[u8]>`,
/// reclaimed exactly once here.
unsafe fn free_box(base: NonNull<u8>, cap: u32, _ctx: *mut ()) {
    let slice = core::ptr::slice_from_raw_parts_mut(base.as_ptr(), cap as usize);
    drop(unsafe { Box::from_raw(slice) });
}

/// Wrap `bytes` in a single-part `Chain<OwnedIOBuf>` — the shape
/// `tcp_receive` consumes.
fn make_chain(bytes: &[u8]) -> Chain<OwnedIOBuf> {
    let boxed: Box<[u8]> = bytes.to_vec().into_boxed_slice();
    let cap = boxed.len() as u32;
    let raw = Box::into_raw(boxed);
    // SAFETY: `raw` is a non-null `cap`-byte region; `free_box`
    // reclaims it exactly once; offset 0 + len cap fits capacity.
    let buf = unsafe {
        OwnedIOBuf::wrap_owned(
            NonNull::new_unchecked(raw as *mut u8),
            cap,
            0,
            cap,
            free_box as IOBufDropFn,
            core::ptr::null_mut(),
        )
    };
    Chain::from(buf)
}

fn v4(o: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(o[0], o[1], o[2], o[3]))
}

/// Drive one scripted segment from `CLIENT_IP` to `SERVER_IP`.
fn deliver(seg: &Seg) {
    tcp_receive(v4(CLIENT_IP), v4(SERVER_IP), make_chain(&seg.encode()));
}

/// Host-order view of a captured frame's TCP header. Returned by
/// value so callers never hold a reference into the `repr(packed)`
/// `TcpHeader`.
struct TcpView {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
}

/// Parse the TCP header out of a captured `[Eth | IPv4 | TCP]`
/// frame (Ethernet 14 + IPv4 20 = offset 34).
fn tcp_hdr(frame: &[u8]) -> TcpView {
    assert!(
        frame.len() >= 34 + TCP_HDR_LEN,
        "captured frame is {} bytes — too short for Eth+IPv4+TCP",
        frame.len()
    );
    let h = TcpHeader::try_ref_from(&frame[34..]).expect("captured frame has a TCP header");
    TcpView {
        src_port: ntohs(h.src_port),
        dst_port: ntohs(h.dst_port),
        seq: ntohl(h.seq),
        ack: ntohl(h.ack),
        flags: h.flags,
    }
}

// ---- scenarios --------------------------------------------------------

/// A bare SYN to a listening port is answered with a SYN|ACK that
/// acknowledges the client's ISN + 1.
#[test]
fn syn_elicits_syn_ack() {
    let _g = harness();
    const SP: u16 = 9101;
    const CP: u16 = 50101;
    const CLIENT_ISN: u32 = 0x1000;
    super::listen_on_core(0, SP);

    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN,
        ack: 0,
        flags: TCP_SYN,
        window: 65535,
        payload: Vec::new(),
    });

    let frames = tx();
    assert_eq!(frames.len(), 1, "a SYN must elicit exactly one frame");
    let h = tcp_hdr(&frames[0]);
    assert_eq!(h.flags, TCP_SYN | TCP_ACK, "the reply must be SYN|ACK");
    assert_eq!(h.src_port, SP, "reply source port = the listening port");
    assert_eq!(h.dst_port, CP, "reply dest port = the client's port");
    assert_eq!(
        h.ack,
        CLIENT_ISN.wrapping_add(1),
        "SYN|ACK must acknowledge the client ISN + 1",
    );
}

/// Once the three-way handshake completes, an in-order data
/// segment is acknowledged with `ack` advanced past the bytes.
#[test]
fn established_data_is_acked() {
    let _g = harness();
    const SP: u16 = 9102;
    const CP: u16 = 50102;
    const CLIENT_ISN: u32 = 0x2000;
    super::listen_on_core(0, SP);

    let server_isn = handshake(SP, CP, CLIENT_ISN);

    clear_tx();
    let body = b"hello!";
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK | TCP_PSH,
        window: 65535,
        payload: body.to_vec(),
    });

    let frames = tx();
    assert!(!frames.is_empty(), "in-order data must elicit an ACK");
    let last = tcp_hdr(frames.last().unwrap());
    assert_ne!(last.flags & TCP_ACK, 0, "the reply must carry ACK");
    assert_eq!(
        last.ack,
        CLIENT_ISN.wrapping_add(1 + body.len() as u32),
        "ACK must cover the delivered payload",
    );
}

/// A FIN on an established connection is acknowledged, with `ack`
/// advanced one sequence number past the FIN.
#[test]
fn fin_is_acked() {
    let _g = harness();
    const SP: u16 = 9103;
    const CP: u16 = 50103;
    const CLIENT_ISN: u32 = 0x3000;
    super::listen_on_core(0, SP);

    let server_isn = handshake(SP, CP, CLIENT_ISN);

    clear_tx();
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_FIN | TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });

    let frames = tx();
    assert!(!frames.is_empty(), "a FIN must elicit an ACK");
    let last = tcp_hdr(frames.last().unwrap());
    assert_ne!(last.flags & TCP_ACK, 0, "the reply must carry ACK");
    assert_eq!(
        last.ack,
        CLIENT_ISN.wrapping_add(2),
        "ACK must cover the FIN — one sequence number past the handshake",
    );
}

// ---- receiver-side scenarios — no new feature, pure coverage ----------

/// A retransmitted SYN on a 4-tuple already in `SynReceived` (the
/// peer never saw our SYN|ACK) must free the orphaned half-open
/// twin and answer with a fresh SYN|ACK — never leak a second
/// slot for one 4-tuple. Exercises the stale-twin cleanup in
/// `tcp_receive`'s SYN handler.
#[test]
fn retransmitted_syn_replaces_the_stale_twin() {
    let _g = harness();
    const SP: u16 = 9104;
    const CP: u16 = 50104;
    const CLIENT_ISN: u32 = 0x4000;
    super::listen_on_core(0, SP);

    let syn = Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN,
        ack: 0,
        flags: TCP_SYN,
        window: 65535,
        payload: Vec::new(),
    };

    // First SYN → SYN|ACK; the connection is now `SynReceived`.
    deliver(&syn);
    assert_eq!(tcp_hdr(&tx()[0]).flags, TCP_SYN | TCP_ACK);

    // The peer never saw that SYN|ACK and retransmits its SYN.
    clear_tx();
    deliver(&syn);
    let frames = tx();
    assert_eq!(
        frames.len(),
        1,
        "a retransmitted SYN must elicit exactly one fresh SYN|ACK",
    );
    let second = tcp_hdr(&frames[0]);
    assert_eq!(
        second.flags,
        TCP_SYN | TCP_ACK,
        "the retransmit reply must itself be SYN|ACK",
    );
    assert_eq!(
        second.ack,
        CLIENT_ISN.wrapping_add(1),
        "the fresh SYN|ACK still acknowledges the client ISN + 1",
    );

    // The connection from the *second* SYN|ACK is the live one —
    // complete its handshake and prove it delivers data.
    let server_isn = second.seq;
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    clear_tx();
    let body = b"twin-ok";
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK | TCP_PSH,
        window: 65535,
        payload: body.to_vec(),
    });
    assert_eq!(
        tcp_hdr(tx().last().unwrap()).ack,
        CLIENT_ISN.wrapping_add(1 + body.len() as u32),
        "the post-retransmit connection delivers data correctly",
    );
}

/// A duplicate segment wholly below `rcv_nxt` (the peer never saw
/// our ACK and retransmitted) elicits an immediate bare ACK still
/// pointing at `rcv_nxt` — the fast-retransmit signal, with no
/// data re-counted.
#[test]
fn duplicate_data_elicits_an_immediate_dup_ack() {
    let _g = harness();
    const SP: u16 = 9105;
    const CP: u16 = 50105;
    const CLIENT_ISN: u32 = 0x5000;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let rcv_nxt = CLIENT_ISN.wrapping_add(1);

    let body = b"first-copy";
    let seg = Seg {
        src_port: CP,
        dst_port: SP,
        seq: rcv_nxt,
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK | TCP_PSH,
        window: 65535,
        payload: body.to_vec(),
    };
    // One in-order delivery advances rcv_nxt past the segment.
    deliver(&seg);
    let advanced = rcv_nxt.wrapping_add(body.len() as u32);

    // The same bytes arrive again — a pure duplicate.
    clear_tx();
    deliver(&seg);
    let frames = tx();
    assert_eq!(
        frames.len(),
        1,
        "a duplicate segment must elicit exactly one ACK",
    );
    let h = tcp_hdr(&frames[0]);
    assert_ne!(h.flags & TCP_ACK, 0, "the reply must carry ACK");
    assert_eq!(
        h.flags & (TCP_SYN | TCP_FIN | TCP_RST),
        0,
        "a dup-ACK is a bare ACK — no other control flags",
    );
    assert_eq!(
        h.ack, advanced,
        "the dup-ACK still points at rcv_nxt — duplicate bytes are not re-counted",
    );
}

/// An out-of-order segment (a gap before it) is silently dropped:
/// the stack has no reassembly queue (SACK is deferred), so the
/// bytes are neither buffered nor acknowledged. Pinned so a future
/// reassembly feature has to update this deliberately.
#[test]
fn out_of_order_segment_is_not_buffered() {
    let _g = harness();
    const SP: u16 = 9106;
    const CP: u16 = 50106;
    const CLIENT_ISN: u32 = 0x6000;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let rcv_nxt = CLIENT_ISN.wrapping_add(1);

    // A segment 100 bytes past rcv_nxt — there is a gap before it.
    clear_tx();
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: rcv_nxt.wrapping_add(100),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK | TCP_PSH,
        window: 65535,
        payload: vec![0xAB; 10],
    });
    assert!(
        tx().is_empty(),
        "an out-of-order segment is silently dropped — no reassembly queue",
    );

    // The gap-filling in-order segment is accepted at the
    // *original* rcv_nxt; the 10 out-of-order bytes were dropped.
    clear_tx();
    let body = b"in-order";
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: rcv_nxt,
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK | TCP_PSH,
        window: 65535,
        payload: body.to_vec(),
    });
    assert_eq!(
        tcp_hdr(tx().last().unwrap()).ack,
        rcv_nxt.wrapping_add(body.len() as u32),
        "ACK covers only the in-order bytes — the out-of-order segment was not reassembled",
    );
}

/// RFC 5961 §3.2: a RST exactly at `rcv_nxt` is accepted and tears
/// the connection down — a follow-up segment then finds no TCB.
#[test]
fn rst_at_rcv_nxt_tears_down_the_connection() {
    let _g = harness();
    const SP: u16 = 9107;
    const CP: u16 = 50107;
    const CLIENT_ISN: u32 = 0x7000;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let rcv_nxt = CLIENT_ISN.wrapping_add(1);

    clear_tx();
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: rcv_nxt,
        ack: 0,
        flags: TCP_RST,
        window: 0,
        payload: Vec::new(),
    });
    assert!(tx().is_empty(), "an accepted RST elicits no reply");

    // The TCB is gone: follow-up data finds nothing and is dropped
    // without an ACK.
    clear_tx();
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: rcv_nxt,
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK | TCP_PSH,
        window: 65535,
        payload: b"after-rst".to_vec(),
    });
    assert!(
        tx().is_empty(),
        "data on a reset connection finds no TCB — silently dropped",
    );
}

/// RFC 5961 §3.2: a RST whose seq is *not* exactly `rcv_nxt` is a
/// blind-reset candidate — dropped, and the connection survives.
#[test]
fn rst_off_rcv_nxt_is_ignored() {
    let _g = harness();
    const SP: u16 = 9108;
    const CP: u16 = 50108;
    const CLIENT_ISN: u32 = 0x8000;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let rcv_nxt = CLIENT_ISN.wrapping_add(1);

    clear_tx();
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: rcv_nxt.wrapping_add(9999),
        ack: 0,
        flags: TCP_RST,
        window: 0,
        payload: Vec::new(),
    });
    assert!(tx().is_empty(), "an off-sequence RST elicits no reply");

    // The connection is still alive — in-order data is still ACK'd.
    clear_tx();
    let body = b"still-here";
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: rcv_nxt,
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK | TCP_PSH,
        window: 65535,
        payload: body.to_vec(),
    });
    assert_eq!(
        tcp_hdr(tx().last().unwrap()).ack,
        rcv_nxt.wrapping_add(body.len() as u32),
        "the connection survived the off-sequence RST and still delivers data",
    );
}

/// RFC 6298: an outbound data segment whose ACK never arrives is
/// retransmitted once the RTO elapses, and the RTO doubles on each
/// successive expiry (§5.5 exponential backoff). Drives the real
/// send path, withholds the ACK, and advances the mock clock.
#[test]
fn rto_retransmits_unacked_data_with_backoff() {
    let _g = harness();
    const SP: u16 = 9109;
    const CP: u16 = 50109;
    const CLIENT_ISN: u32 = 0x9000;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    // The server sends a response; its ACK will be withheld.
    let (handle, generation) = conn_handle(CP, SP);
    clear_tx();
    let body = b"unacked-response-body";
    let mut chain = iobuf::IOBufChain::from(body.to_vec());
    let sent = super::async_try_send_chain(handle, generation, &mut chain)
        .expect("an established connection accepts the send");
    assert_eq!(sent, body.len(), "the whole body is handed to the wire");
    let first = tcp_hdr(&tx()[0]);
    assert_eq!(
        first.seq,
        server_isn.wrapping_add(1),
        "data is sent starting at snd_una",
    );

    // Before the RTO elapses the tick does nothing.
    clear_tx();
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 - 1);
    super::on_tcp_tick();
    assert!(tx().is_empty(), "no retransmit before the RTO elapses");

    // Crossing the RTO retransmits the segment verbatim.
    kernel_core::clock::mock::advance(2);
    super::on_tcp_tick();
    let rtx = tx();
    assert_eq!(rtx.len(), 1, "exactly one retransmit fires at the RTO");
    let r = tcp_hdr(&rtx[0]);
    assert_eq!(r.seq, first.seq, "the retransmit re-sends from snd_una");
    assert_eq!(
        &rtx[0][34 + TCP_HDR_LEN..],
        body,
        "the retransmit carries the original payload bytes",
    );

    // §5.5: the RTO has doubled. One RTO of further wait — enough
    // the first time — is now not enough for the second expiry.
    clear_tx();
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64);
    super::on_tcp_tick();
    assert!(
        tx().is_empty(),
        "the backed-off (2x) RTO has not elapsed after only one RTO of wait",
    );
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64);
    super::on_tcp_tick();
    assert_eq!(
        tx().len(),
        1,
        "the second retransmit fires only after the doubled RTO",
    );
}

/// RFC 6298 §5.3: an ACK that covers the outstanding data stops
/// the RTO timer — no spurious retransmit afterwards.
#[test]
fn ack_stops_the_retransmission_timer() {
    let _g = harness();
    const SP: u16 = 9110;
    const CP: u16 = 50110;
    const CLIENT_ISN: u32 = 0xA000;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    clear_tx();
    let body = b"acked-response";
    let mut chain = iobuf::IOBufChain::from(body.to_vec());
    super::async_try_send_chain(handle, generation, &mut chain)
        .expect("an established connection accepts the send");

    // The client acknowledges the whole response.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1 + body.len() as u32),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });

    // The timer is disarmed: even far past the original RTO the
    // tick produces nothing.
    clear_tx();
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 * 4);
    super::on_tcp_tick();
    assert!(
        tx().is_empty(),
        "fully-acknowledged data is never retransmitted",
    );
}

/// RFC 6298 §2: the RTT estimator seeds SRTT/RTTVAR from the first
/// measurement (§2.2) and tracks with the EWMA thereafter (§2.3);
/// the RTO follows `SRTT + 4·RTTVAR`, clamped to the 1 s floor.
#[test]
fn rtt_estimator_tracks_rfc6298() {
    // The estimator math is pure — exercise it on a bare TCB.
    let mut c = TcpConnection::new();

    // §2.1: before any measurement the RTO is the 1 s initial value.
    assert_eq!(c.estimated_rto(), RTO_INITIAL_MS);

    // §2.2: first sample R → SRTT = R, RTTVAR = R/2.
    c.sample_rtt(400);
    assert_eq!(c.srtt_ms, 400, "SRTT seeds to the first sample");
    assert_eq!(c.rttvar_ms, 200, "RTTVAR seeds to R/2");
    // RTO = SRTT + 4·RTTVAR = 400 + 800 = 1200.
    assert_eq!(c.estimated_rto(), 1200);

    // §2.3: a second sample folds in (alpha = 1/8, beta = 1/4) —
    // RTTVAR is updated first, against the *old* SRTT.
    c.sample_rtt(440);
    // RTTVAR = 200 - 200/4 + |400-440|/4 = 150 + 10 = 160.
    assert_eq!(c.rttvar_ms, 160);
    // SRTT  = 400 - 400/8 + 440/8 = 350 + 55 = 405.
    assert_eq!(c.srtt_ms, 405);
    assert_eq!(c.estimated_rto(), 405 + 4 * 160);

    // §2.4: a steady low RTT drives the estimate below 1 s, where
    // it is clamped up to the floor.
    for _ in 0..60 {
        c.sample_rtt(20);
    }
    assert_eq!(
        c.estimated_rto(),
        RTO_INITIAL_MS,
        "a low, steady RTT clamps the RTO at the 1 s floor",
    );
}

/// The lossy-network egress fixture itself: a dropped first
/// transmission is invisible to the stack — the bytes stay in the
/// RFC 6298 retransmit ring — and the RTO timer recovers it. Validates
/// the drop seam against the known-good retransmit path before the
/// timer- and loss-driven scenarios for the lifecycle corners and
/// fast retransmit rely on it.
#[test]
fn egress_drop_fixture_loses_a_segment_then_rto_recovers_it() {
    let _g = harness();
    const SP: u16 = 9111;
    const CP: u16 = 50111;
    const CLIENT_ISN: u32 = 0xB000;
    super::listen_on_core(0, SP);
    handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    clear_tx();
    // The wire loses the next egress frame — the server's response.
    drop_next_egress(1);
    let body = b"lost-on-the-wire";
    let mut chain = iobuf::IOBufChain::from(body.to_vec());
    super::async_try_send_chain(handle, generation, &mut chain)
        .expect("an established connection accepts the send");
    assert!(
        tx().is_empty(),
        "the first transmission was dropped by the fixture",
    );
    assert_eq!(egress_drops(), 1, "exactly one egress frame was dropped");

    // The stack does not know the frame was lost — the bytes are in
    // the retransmit ring. Crossing the RTO retransmits them, and the
    // fixture (next-1 exhausted) now lets the frame through.
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 + 1);
    super::on_tcp_tick();
    let rtx = tx();
    assert_eq!(rtx.len(), 1, "the RTO retransmit recovers the lost segment");
    assert_eq!(
        &rtx[0][34 + TCP_HDR_LEN..],
        body,
        "the recovered segment carries the original payload",
    );
}

// ---- connection-lifecycle corners — LastAck / FIN retransmit ----------

/// Passive close: a peer FIN moves the connection to `CloseWait`; the
/// app's `close()` must then send its own FIN and wait in `LastAck`
/// for the acknowledgement — not free the slot immediately (the
/// pre-WAN behaviour, which lost the FIN-retransmit guarantee).
#[test]
fn closewait_close_enters_lastack() {
    let _g = harness();
    const SP: u16 = 9112;
    const CP: u16 = 50112;
    const CLIENT_ISN: u32 = 0xC000;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    // The peer half-closes — Established → CloseWait.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_FIN | TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    assert_eq!(
        conn_state(CP, SP),
        Some(TcpState::CloseWait),
        "a peer FIN moves the connection to CloseWait",
    );

    // The app closes — we send our FIN and wait in LastAck.
    let (handle, generation) = conn_handle(CP, SP);
    clear_tx();
    super::close(handle, generation);
    let frames = tx();
    assert_eq!(frames.len(), 1, "close() in CloseWait sends exactly one FIN");
    assert_eq!(
        tcp_hdr(&frames[0]).flags,
        TCP_FIN | TCP_ACK,
        "the close segment is FIN|ACK",
    );
    assert_eq!(
        conn_state(CP, SP),
        Some(TcpState::LastAck),
        "close() in CloseWait waits for the ACK in LastAck — it does not free the slot",
    );
}

/// `LastAck` completes only when the peer acknowledges our FIN: the
/// slot is freed and a follow-up segment finds no TCB.
#[test]
fn lastack_ack_frees_the_conn() {
    let _g = harness();
    const SP: u16 = 9113;
    const CP: u16 = 50113;
    const CLIENT_ISN: u32 = 0xC100;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_FIN | TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    let (handle, generation) = conn_handle(CP, SP);
    super::close(handle, generation);
    assert_eq!(conn_state(CP, SP), Some(TcpState::LastAck));

    // The peer ACKs our FIN. Our FIN occupied seq `server_isn + 1`
    // (the handshake left `snd_nxt` there); `close()` advanced
    // `snd_nxt` to `server_isn + 2`, which is the `ack` we expect.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(2),
        ack: server_isn.wrapping_add(2),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    assert_eq!(
        conn_state(CP, SP),
        None,
        "the ACK of our FIN frees the LastAck slot",
    );
}

/// A `LastAck` FIN lost on the wire is retransmitted once the RTO
/// elapses — without it a single dropped FIN strands the connection
/// until the peer's keepalive fires.
#[test]
fn lastack_retransmits_lost_fin() {
    let _g = harness();
    const SP: u16 = 9114;
    const CP: u16 = 50114;
    const CLIENT_ISN: u32 = 0xC200;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_FIN | TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });

    let (handle, generation) = conn_handle(CP, SP);
    clear_tx();
    // The wire loses our FIN.
    drop_next_egress(1);
    super::close(handle, generation);
    assert!(tx().is_empty(), "the FIN was dropped by the fixture");
    assert_eq!(egress_drops(), 1);
    assert_eq!(conn_state(CP, SP), Some(TcpState::LastAck));

    // No retransmit before the RTO elapses.
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 - 1);
    super::on_tcp_tick();
    assert!(tx().is_empty(), "no FIN retransmit before the RTO elapses");

    // Crossing the RTO retransmits the FIN.
    kernel_core::clock::mock::advance(2);
    super::on_tcp_tick();
    let rtx = tx();
    assert_eq!(rtx.len(), 1, "the FIN is retransmitted at the RTO");
    let h = tcp_hdr(&rtx[0]);
    assert_eq!(h.flags, TCP_FIN | TCP_ACK, "the retransmit is FIN|ACK");
    assert_eq!(
        h.seq,
        server_isn.wrapping_add(1),
        "the FIN retransmit re-sends from the FIN's sequence number",
    );
    assert_eq!(
        conn_state(CP, SP),
        Some(TcpState::LastAck),
        "the connection still awaits the ACK",
    );
}

/// A `LastAck` connection whose FIN is never acknowledged is forced
/// shut after `FIN_RETX_MAX` retransmissions — a dead peer must not
/// leak the half-closed slot forever.
#[test]
fn lastack_gives_up_after_bounded_retries() {
    let _g = harness();
    const SP: u16 = 9115;
    const CP: u16 = 50115;
    const CLIENT_ISN: u32 = 0xC300;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_FIN | TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });

    let (handle, generation) = conn_handle(CP, SP);
    clear_tx();
    // Every FIN — the initial one and every retransmit — is lost.
    drop_egress_where(|_| true);
    super::close(handle, generation);
    assert_eq!(conn_state(CP, SP), Some(TcpState::LastAck));

    // Tick past each backed-off deadline. The backoff caps at
    // `RTO_MAX_MS`, so advancing past it crosses every interval.
    for _ in 0..=FIN_RETX_MAX {
        kernel_core::clock::mock::advance(RTO_MAX_MS as u64 + 1);
        super::on_tcp_tick();
    }
    assert_eq!(
        conn_state(CP, SP),
        None,
        "the connection is freed after FIN_RETX_MAX unacknowledged retransmits",
    );
    assert_eq!(
        egress_drops(),
        FIN_RETX_MAX as u32 + 1,
        "the initial FIN plus FIN_RETX_MAX retransmits were all sent (and lost)",
    );
}

/// Active close: an app `close()` on an Established connection sends a
/// FIN and enters `FinWait1`. A FIN lost there is retransmitted at the
/// RTO, the same mechanism as the passive-close `LastAck` path.
#[test]
fn finwait1_retransmits_lost_fin() {
    let _g = harness();
    const SP: u16 = 9116;
    const CP: u16 = 50116;
    const CLIENT_ISN: u32 = 0xC400;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    clear_tx();
    drop_next_egress(1);
    super::close(handle, generation);
    assert!(tx().is_empty(), "the FIN was dropped by the fixture");
    assert_eq!(
        conn_state(CP, SP),
        Some(TcpState::FinWait1),
        "active close enters FinWait1",
    );

    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 + 1);
    super::on_tcp_tick();
    let rtx = tx();
    assert_eq!(rtx.len(), 1, "the FIN is retransmitted at the RTO");
    let h = tcp_hdr(&rtx[0]);
    assert_eq!(h.flags, TCP_FIN | TCP_ACK, "the retransmit is FIN|ACK");
    assert_eq!(
        h.seq,
        server_isn.wrapping_add(1),
        "the FIN retransmit re-sends from the FIN's sequence number",
    );
}

/// Locate the live (non-listener) connection for a client/server
/// port pair and return its `(handle, generation)` so a scenario
/// can drive the real send path (`async_try_send_chain`).
fn conn_handle(client_port: u16, server_port: u16) -> (*mut (), u16) {
    let core = 0u32;
    let cap = pool_capacity(core);
    for i in 0..cap {
        // SAFETY: single worker, test-serialised by TEST_LOCK.
        let c = unsafe { &*conn_ptr(core, i) };
        if c.state != TcpState::Closed
            && c.state != TcpState::Listen
            && c.local_port == server_port
            && c.remote_port == client_port
        {
            return (encode_handle(core, i), c.generation);
        }
    }
    panic!("no live connection for ports {client_port} -> {server_port}");
}

/// The `TcpState` of the live connection for a client/server port
/// pair, or `None` if the slot has been freed. Lets a scenario assert
/// on state-machine transitions (CloseWait, LastAck, …) and on
/// teardown.
fn conn_state(client_port: u16, server_port: u16) -> Option<TcpState> {
    let core = 0u32;
    let cap = pool_capacity(core);
    for i in 0..cap {
        // SAFETY: single worker, test-serialised by `TEST_LOCK`.
        let c = unsafe { &*conn_ptr(core, i) };
        if c.state != TcpState::Closed
            && c.state != TcpState::Listen
            && c.local_port == server_port
            && c.remote_port == client_port
        {
            return Some(c.state);
        }
    }
    None
}

/// Drive a full three-way handshake on `(server_port, client_port)`
/// and return the server's chosen ISN (read from the SYN|ACK).
fn handshake(server_port: u16, client_port: u16, client_isn: u32) -> u32 {
    deliver(&Seg {
        src_port: client_port,
        dst_port: server_port,
        seq: client_isn,
        ack: 0,
        flags: TCP_SYN,
        window: 65535,
        payload: Vec::new(),
    });
    let server_isn = tcp_hdr(&tx()[0]).seq;
    deliver(&Seg {
        src_port: client_port,
        dst_port: server_port,
        seq: client_isn.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    server_isn
}
