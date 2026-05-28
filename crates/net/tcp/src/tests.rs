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
use nic_api::{CsumOffload, NicOps, TxBufHandle, TxTsoBufHandle, set_active_ops};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, Once, OnceLock};
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

/// Record a transmitted frame into the `TX` capture — unless the
/// lossy-network egress fixture's drop policy swallows it. Shared by
/// the plain `send` mock and the TSO `submit_tx_tso` mock.
fn record_egress(frame: &[u8]) {
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

fn mock_send(frame: &[u8], _csum: CsumOffload) {
    record_egress(frame);
}

// ---- mock TSO big-slot ------------------------------------------------
//
// `MOCK_OPS_TSO` is a second NIC mock that advertises TSO so the
// `try_send_tso` fast path is exercisable. A scenario opts in with
// `set_active_ops(&MOCK_OPS_TSO)` after `harness()`; the next
// `harness()` resets to the plain `MOCK_OPS`.

/// Capacity of the mock TSO big-slot — comfortably larger than any
/// super-segment the conformance scenarios seal into it.
const TSO_SLOT_CAP: usize = 24_000;

/// Stable pointer to one shared mock TSO slot. Scenarios are
/// `TEST_LOCK`-serialised and submit a single super-segment at a
/// time, so one buffer suffices; leaked deliberately — it lives for
/// the test process.
fn tso_slot_ptr() -> *mut u8 {
    static SLOT: OnceLock<usize> = OnceLock::new();
    *SLOT.get_or_init(|| {
        let boxed = vec![0u8; TSO_SLOT_CAP].into_boxed_slice();
        Box::into_raw(boxed) as *mut u8 as usize
    }) as *mut u8
}

fn mock_acquire_tx_tso_buf() -> Option<TxTsoBufHandle> {
    Some(TxTsoBufHandle(TxBufHandle {
        data_ptr: tso_slot_ptr(),
        data_cap: TSO_SLOT_CAP as u32,
        driver_token: 0,
        release_fn: |_| {},
    }))
}

fn mock_submit_tx_tso(
    mut handle: TxTsoBufHandle,
    frame_len: usize,
    _hdr_len: u16,
    _csum_start: u16,
    _gso_size: u16,
) {
    // Capture the assembled super-segment, subject to the egress-drop
    // fixture — same path as the plain `send` mock.
    let frame = handle.data_mut()[..frame_len].to_vec();
    record_egress(&frame);
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

// TSO-capable NIC mock — identical to `MOCK_OPS` but advertises
// TSOv4 and supplies the big-slot acquire / submit hooks, so the
// `try_send_tso` fast path can be driven by the conformance harness.
static MOCK_OPS_TSO: NicOps = NicOps {
    name: "mock-tso",
    probe: yes,
    send: mock_send,
    acquire_tx_buf: None,
    submit_tx: None,
    tso_available: yes,
    acquire_tx_tso_buf: Some(mock_acquire_tx_tso_buf),
    submit_tx_tso: Some(mock_submit_tx_tso),
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
    });
    // Reset to the non-TSO NIC mock every scenario — a TSO scenario
    // opts into `MOCK_OPS_TSO` after `harness()`, and this restores
    // the default for the next one.
    set_active_ops(&MOCK_OPS);
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

// ---- RFC 5681 congestion control — pure controller arithmetic ---------

/// RFC 5681 §3.1 slow start: each ACK opens `cwnd` by one SMSS — so
/// the window doubles over each RTT's worth of ACKs (exponential).
/// The initial window itself is the RFC 6928 IW10 (`congestion_init`).
#[test]
fn slow_start_grows_cwnd_one_segment_per_ack() {
    // The controller arithmetic is pure — exercise it on a bare TCB.
    let mut c = TcpConnection::new();
    c.congestion_init();
    let smss = 1460u32; // MSS_V4 — `new()` leaves `local_ip` IPv4.

    assert_eq!(c.cwnd, 14600, "the initial window is the RFC 6928 IW10 (10·SMSS)");
    assert!(c.cwnd < c.ssthresh, "a fresh connection opens in slow start");

    let before = c.cwnd;
    c.cwnd_on_ack(smss);
    assert_eq!(c.cwnd, before + smss, "slow start adds one SMSS per ACK");

    // A partial ACK opens the window by only the bytes it covers.
    let before = c.cwnd;
    c.cwnd_on_ack(500);
    assert_eq!(c.cwnd, before + 500, "the increment is capped at bytes acked");
}

/// RFC 5681 §3.1: at `cwnd == ssthresh` the controller switches from
/// slow start to congestion avoidance — growth drops from one SMSS
/// per ACK to roughly one SMSS per RTT.
#[test]
fn cwnd_switches_to_congestion_avoidance_at_ssthresh() {
    let mut c = TcpConnection::new();
    c.congestion_init();
    let smss = 1460u32;
    c.ssthresh = 8 * smss;
    c.cwnd = 7 * smss;

    // Still below ssthresh — slow start, one SMSS per ACK.
    c.cwnd_on_ack(smss);
    assert_eq!(c.cwnd, 8 * smss, "slow start runs up to ssthresh");

    // At ssthresh — congestion avoidance, sub-SMSS per ACK.
    let before = c.cwnd;
    c.cwnd_on_ack(smss);
    let inc = c.cwnd - before;
    assert!(inc >= 1 && inc < smss, "congestion avoidance is sub-SMSS per ACK");
    // SMSS·SMSS/cwnd, with cwnd == 8·SMSS, is SMSS/8.
    assert_eq!(inc, smss * smss / (8 * smss));
}

/// RFC 5681 §3.1: an RTO collapses `cwnd` to one segment and drops
/// `ssthresh` to half the flight size; a second RTO with no
/// intervening progress collapses `cwnd` again but does not re-halve
/// `ssthresh`.
#[test]
fn rto_collapses_cwnd_and_halves_ssthresh() {
    let mut c = TcpConnection::new();
    c.congestion_init();
    let smss = 1460u32;

    // A wide-open window with 20·SMSS in flight.
    c.cwnd = 20 * smss;
    c.ssthresh = 16 * smss;
    c.snd_una = 1000;
    c.snd_nxt = 1000u32.wrapping_add(20 * smss);
    c.rtx_backoff = 0; // the first RTO of this loss episode

    c.congestion_on_rto();
    assert_eq!(c.cwnd, smss, "an RTO collapses cwnd to one segment");
    assert_eq!(
        c.ssthresh,
        (20 * smss) / 2,
        "ssthresh drops to half the flight size",
    );

    // A second RTO before any data is acknowledged.
    c.cwnd = 5 * smss;
    c.rtx_backoff = 1;
    let ssthresh_after_first = c.ssthresh;
    c.congestion_on_rto();
    assert_eq!(c.cwnd, smss, "every RTO re-collapses cwnd");
    assert_eq!(
        c.ssthresh, ssthresh_after_first,
        "ssthresh is not re-halved by a back-to-back RTO",
    );
}

/// RFC 5681 §3.1: `ssthresh` has a 2·SMSS floor — a tiny flight size
/// at RTO time cannot drive it below two segments.
#[test]
fn rto_ssthresh_has_a_two_segment_floor() {
    let mut c = TcpConnection::new();
    c.congestion_init();
    let smss = 1460u32;

    // Only one segment in flight when the RTO fires.
    c.snd_una = 1000;
    c.snd_nxt = 1000 + smss;
    c.rtx_backoff = 0;

    c.congestion_on_rto();
    assert_eq!(
        c.ssthresh,
        2 * smss,
        "ssthresh is floored at 2·SMSS, not flight/2 = SMSS/2",
    );
}

// ---- RFC 5681 §3.2 fast retransmit / fast recovery --------------------

/// Three duplicate ACKs are taken as a loss signal: the server
/// fast-retransmits the missing segment immediately — no RTO wait —
/// and moves `cwnd` / `ssthresh` per RFC 5681 §3.2. The duplicate
/// ACKs themselves model the receiver's reported gap.
#[test]
fn three_dup_acks_trigger_fast_retransmit() {
    let _g = harness();
    const SP: u16 = 9121;
    const CP: u16 = 50121;
    const CLIENT_ISN: u32 = 0xD000;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    clear_tx();
    let body = b"fast-retransmit-payload";
    let mut chain = iobuf::IOBufChain::from(body.to_vec());
    super::async_try_send_chain(handle, generation, &mut chain)
        .expect("an established connection accepts the send");
    assert_eq!(tx().len(), 1, "the response goes out as one segment");

    // A duplicate ACK: `ack` still at snd_una, no payload — the
    // receiver is missing the segment.
    let dup = Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    };
    clear_tx();
    deliver(&dup);
    deliver(&dup);
    assert!(tx().is_empty(), "the first two duplicate ACKs do not retransmit");

    // The third duplicate ACK fast-retransmits — with the mock clock
    // untouched, so this cannot be the RTO timer.
    deliver(&dup);
    let rtx = tx();
    assert_eq!(
        rtx.len(),
        1,
        "the third duplicate ACK fast-retransmits, without an RTO",
    );
    let h = tcp_hdr(&rtx[0]);
    assert_eq!(
        h.seq,
        server_isn.wrapping_add(1),
        "the retransmit re-sends from snd_una",
    );
    assert_eq!(
        &rtx[0][34 + TCP_HDR_LEN..],
        body,
        "the fast retransmit carries the original payload",
    );

    // RFC 5681 §3.2: ssthresh halved against the flight size (floored
    // at 2·SMSS), cwnd inflated to ssthresh + 3·SMSS.
    let smss = 1460u32;
    let expect_ssthresh = ((body.len() as u32) / 2).max(2 * smss);
    let (cwnd, ssthresh) = conn_cwnd_ssthresh(CP, SP);
    assert_eq!(
        ssthresh, expect_ssthresh,
        "ssthresh drops to flight/2, floored at 2·SMSS",
    );
    assert_eq!(
        cwnd,
        expect_ssthresh + 3 * smss,
        "cwnd is inflated to ssthresh + 3·SMSS",
    );
}

/// In fast recovery each extra duplicate ACK inflates `cwnd` by one
/// SMSS; the recovering ACK (covering new data) deflates `cwnd` back
/// to `ssthresh` and exits recovery — RFC 5681 §3.2 steps 4 and 6.
#[test]
fn fast_recovery_inflates_then_deflates_cwnd() {
    let _g = harness();
    const SP: u16 = 9122;
    const CP: u16 = 50122;
    const CLIENT_ISN: u32 = 0xD100;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    let body = b"recovery-window-payload";
    let mut chain = iobuf::IOBufChain::from(body.to_vec());
    super::async_try_send_chain(handle, generation, &mut chain)
        .expect("an established connection accepts the send");

    let dup = Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    };
    // Three duplicate ACKs → fast retransmit + fast recovery.
    deliver(&dup);
    deliver(&dup);
    deliver(&dup);
    let smss = 1460u32;
    let (cwnd_at_entry, ssthresh) = conn_cwnd_ssthresh(CP, SP);
    assert_eq!(
        cwnd_at_entry,
        ssthresh + 3 * smss,
        "fast retransmit inflates cwnd to ssthresh + 3·SMSS",
    );

    // A fourth duplicate ACK inflates cwnd by one more SMSS.
    deliver(&dup);
    let (cwnd_inflated, _) = conn_cwnd_ssthresh(CP, SP);
    assert_eq!(
        cwnd_inflated,
        cwnd_at_entry + smss,
        "an extra duplicate ACK in recovery inflates cwnd by one SMSS",
    );

    // The recovering ACK covers the retransmitted data — cwnd
    // deflates to ssthresh and recovery ends.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1 + body.len() as u32),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    let (cwnd_final, ssthresh_final) = conn_cwnd_ssthresh(CP, SP);
    assert_eq!(
        cwnd_final, ssthresh_final,
        "the recovering ACK deflates cwnd back to ssthresh",
    );
}

/// Fewer than three duplicate ACKs are not a loss signal — no
/// retransmit, and the congestion window is left untouched.
#[test]
fn two_dup_acks_do_not_fast_retransmit() {
    let _g = harness();
    const SP: u16 = 9123;
    const CP: u16 = 50123;
    const CLIENT_ISN: u32 = 0xD200;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    let body = b"two-dup-acks";
    let mut chain = iobuf::IOBufChain::from(body.to_vec());
    super::async_try_send_chain(handle, generation, &mut chain)
        .expect("an established connection accepts the send");
    let before = conn_cwnd_ssthresh(CP, SP);

    let dup = Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    };
    clear_tx();
    deliver(&dup);
    deliver(&dup);
    assert!(tx().is_empty(), "two duplicate ACKs do not trigger a retransmit");
    assert_eq!(
        conn_cwnd_ssthresh(CP, SP),
        before,
        "fewer than three duplicate ACKs leave the congestion window untouched",
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

// ---- connection-lifecycle corners — TimeWait / 2×MSL ------------------

/// Active close completed by the peer: the server's `close()` enters
/// `FinWait1`, the peer's ACK moves it to `FinWait2`, and the peer's
/// FIN must then enter `TimeWait` — holding the TCB, not freeing it.
#[test]
fn finwait2_peer_fin_enters_timewait() {
    let _g = harness();
    const SP: u16 = 9117;
    const CP: u16 = 50117;
    const CLIENT_ISN: u32 = 0xC500;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    super::close(handle, generation);
    assert_eq!(conn_state(CP, SP), Some(TcpState::FinWait1));

    // Peer ACKs our FIN → FinWait2.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(2),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    assert_eq!(conn_state(CP, SP), Some(TcpState::FinWait2));

    // Peer FIN → TimeWait, and the FIN is acknowledged.
    clear_tx();
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(2),
        flags: TCP_FIN | TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    let frames = tx();
    assert!(!frames.is_empty(), "the peer FIN must elicit an ACK");
    let h = tcp_hdr(frames.last().unwrap());
    assert_ne!(h.flags & TCP_ACK, 0, "the reply carries ACK");
    assert_eq!(
        h.ack,
        CLIENT_ISN.wrapping_add(2),
        "the ACK covers the peer's FIN",
    );
    assert_eq!(
        conn_state(CP, SP),
        Some(TcpState::TimeWait),
        "FinWait2 + peer FIN enters TimeWait — the slot is held, not freed",
    );
}

/// Simultaneous close: a peer FIN that arrives in `FinWait1` without
/// acknowledging our FIN shortcuts straight to `TimeWait` (the stack
/// has no separate `Closing` state).
#[test]
fn finwait1_simultaneous_close_enters_timewait() {
    let _g = harness();
    const SP: u16 = 9120;
    const CP: u16 = 50120;
    const CLIENT_ISN: u32 = 0xC800;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    super::close(handle, generation);
    assert_eq!(conn_state(CP, SP), Some(TcpState::FinWait1));

    // Peer FIN whose `ack` does NOT cover our FIN — the conn is still
    // in FinWait1 when the FIN handler runs.
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
        Some(TcpState::TimeWait),
        "FinWait1 + a peer FIN that doesn't ack our FIN shortcuts to TimeWait",
    );
}

/// A `TimeWait` connection is freed once the 2×MSL hold elapses —
/// not before.
#[test]
fn timewait_drops_after_2msl() {
    let _g = harness();
    const SP: u16 = 9118;
    const CP: u16 = 50118;
    const CLIENT_ISN: u32 = 0xC600;
    super::listen_on_core(0, SP);
    enter_timewait(SP, CP, CLIENT_ISN);
    assert_eq!(conn_state(CP, SP), Some(TcpState::TimeWait));

    // Before 2×MSL the tick leaves it alone.
    kernel_core::clock::mock::advance(TIME_WAIT_MS - 1);
    super::on_tcp_tick();
    assert_eq!(
        conn_state(CP, SP),
        Some(TcpState::TimeWait),
        "TimeWait holds the TCB until 2×MSL elapses",
    );

    // Crossing 2×MSL frees it.
    kernel_core::clock::mock::advance(2);
    super::on_tcp_tick();
    assert_eq!(
        conn_state(CP, SP),
        None,
        "the TimeWait slot is freed once 2×MSL has elapsed",
    );
}

/// A retransmitted peer FIN arriving in `TimeWait` (its ACK was lost)
/// is re-acknowledged without advancing state, and restarts the
/// 2×MSL timer so the connection outlives the original deadline.
#[test]
fn timewait_absorbs_retransmitted_fin() {
    let _g = harness();
    const SP: u16 = 9119;
    const CP: u16 = 50119;
    const CLIENT_ISN: u32 = 0xC700;
    super::listen_on_core(0, SP);
    let server_isn = enter_timewait(SP, CP, CLIENT_ISN);
    assert_eq!(conn_state(CP, SP), Some(TcpState::TimeWait));

    // Advance to just shy of the original 2×MSL deadline, then the
    // peer retransmits its FIN.
    kernel_core::clock::mock::advance(TIME_WAIT_MS - 100);
    clear_tx();
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(2),
        flags: TCP_FIN | TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    let frames = tx();
    assert_eq!(
        frames.len(),
        1,
        "a retransmitted FIN in TimeWait elicits exactly one ACK",
    );
    let h = tcp_hdr(&frames[0]);
    assert_ne!(h.flags & TCP_ACK, 0, "the reply carries ACK");
    assert_eq!(
        h.ack,
        CLIENT_ISN.wrapping_add(2),
        "the re-ACK still covers the peer's FIN",
    );
    assert_eq!(
        conn_state(CP, SP),
        Some(TcpState::TimeWait),
        "a retransmitted FIN does not advance TimeWait — it only re-ACKs",
    );

    // Past the *original* deadline: the connection survives because
    // the retransmitted FIN restarted the 2×MSL timer.
    kernel_core::clock::mock::advance(200);
    super::on_tcp_tick();
    assert_eq!(
        conn_state(CP, SP),
        Some(TcpState::TimeWait),
        "the retransmitted FIN restarted the 2×MSL timer",
    );
}

// ---- RFC 5681 cwnd-paced send window ----------------------------------
//
// The send path now caps in-flight bytes at `min(cwnd, rwnd)`. These
// scenarios drive the real `async_try_send_chain` / `try_send_tso`
// hooks and assert on what reaches the wire, on the queued remainder,
// and on the parked-sender wake protocol.

/// A counting `Waker` for the send-path scenarios: every wake bumps a
/// shared atomic so a test can assert the parked `TcpSendChain` waker
/// fired. Built via `std::task::Wake` — the harness compiles with std.
struct CountingWaker(AtomicU32);

impl std::task::Wake for CountingWaker {
    fn wake(self: std::sync::Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &std::sync::Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// A `(Waker, shared-counter)` pair — register the waker on a conn,
/// then read the counter to see how many times it has fired.
fn counting_waker() -> (core::task::Waker, std::sync::Arc<CountingWaker>) {
    let inner = std::sync::Arc::new(CountingWaker(AtomicU32::new(0)));
    (core::task::Waker::from(inner.clone()), inner)
}

/// A send parked on a closed window must observe connection teardown:
/// `free_connection` (here driven by an in-sequence RST) fires the
/// parked `TcpSendChain` waker so the blocked `send().await` re-polls
/// and resolves `Err` instead of sleeping forever on a dropped waker.
#[test]
fn teardown_wakes_a_parked_sender() {
    let _g = harness();
    const SP: u16 = 9130;
    const CP: u16 = 50130;
    const CLIENT_ISN: u32 = 0xE000;
    super::listen_on_core(0, SP);
    handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    let (waker, count) = counting_waker();
    super::register_send_waker(handle, generation, &waker);
    assert_eq!(
        count.0.load(Ordering::Relaxed),
        0,
        "registering a send waker parks it — it must not fire on its own",
    );

    // An in-sequence RST tears the connection down via free_connection.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: 0,
        flags: TCP_RST,
        window: 0,
        payload: Vec::new(),
    });
    assert_eq!(conn_state(CP, SP), None, "the RST freed the connection");
    assert!(
        count.0.load(Ordering::Relaxed) >= 1,
        "teardown must wake the parked sender so its send() resolves",
    );
}

/// Total TCP-payload bytes across every captured frame — the bytes
/// the send path actually put on the wire. Eth(14) + IPv4(20) +
/// TCP(20) = 54 bytes of headers precede each frame's payload.
fn total_tx_payload() -> usize {
    tx().iter().map(|f| f.len() - 34 - TCP_HDR_LEN).sum()
}

/// RFC 5681 §4 usable window: `min(cwnd, rwnd)` minus the in-flight
/// bytes, saturating at 0. Pure arithmetic — exercised on a bare TCB.
#[test]
fn usable_window_arithmetic() {
    let mut c = TcpConnection::new();
    c.congestion_init(); // cwnd = RFC 6928 IW10 = 14600 (new() leaves IPv4)
    let smss = 1460u32;
    c.snd_wnd = 65535;
    c.snd_una = 1000;
    c.snd_nxt = 1000;
    assert_eq!(c.flight(), 0);
    assert_eq!(c.usable_window(), 14600, "an idle conn may send a full cwnd");

    // In-flight bytes are subtracted from the window.
    c.snd_nxt = 1000u32.wrapping_add(2 * smss);
    assert_eq!(c.flight(), 2 * smss);
    assert_eq!(c.usable_window(), 14600 - 2 * smss, "in-flight bytes consume the window");

    // A full congestion window closes the send window.
    c.snd_nxt = 1000u32.wrapping_add(10 * smss); // 10·SMSS == IW10
    assert_eq!(c.usable_window(), 0, "a full cwnd closes the window");

    // The advertised receive window caps the send window below cwnd.
    c.snd_nxt = 1000;
    c.snd_wnd = 2000;
    assert_eq!(c.usable_window(), 2000, "rwnd caps the window below cwnd");

    // A peer that shrinks its window below the flight size closes
    // the window without underflowing (saturating_sub).
    c.snd_wnd = 500;
    c.snd_nxt = 1000u32.wrapping_add(smss);
    assert_eq!(c.usable_window(), 0, "an over-shrunk window saturates at 0");
}

/// A fresh `Established` connection opens at the RFC 6928 initial
/// window (IW10 = 10·SMSS) — and exactly that. The 3-way handshake
/// ACK acknowledges the SYN's sequence number, but the SYN is not
/// data (RFC 5681 §2), so it must not inflate `cwnd` past the IW.
#[test]
fn congestion_window_opens_at_the_initial_window() {
    let _g = harness();
    const SP: u16 = 9152;
    const CP: u16 = 50152;
    const CLIENT_ISN: u32 = 0xF000;
    super::listen_on_core(0, SP);
    handshake(SP, CP, CLIENT_ISN);
    let (cwnd, _) = conn_cwnd_ssthresh(CP, SP);
    assert_eq!(
        cwnd,
        14600,
        "cwnd opens at exactly the RFC 6928 IW10 (10·SMSS) — the \
         handshake ACK of the SYN must not count as a data ACK",
    );
}

/// A send larger than the congestion window puts exactly `cwnd`
/// bytes on the wire (the connection has nothing else in flight) and
/// leaves the rest queued in the chain.
#[test]
fn send_caps_in_flight_at_cwnd() {
    let _g = harness();
    const SP: u16 = 9131;
    const CP: u16 = 50131;
    const CLIENT_ISN: u32 = 0xE100;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    // Nothing is in flight, so the usable window is exactly cwnd.
    let (cwnd, _) = conn_cwnd_ssthresh(CP, SP);
    clear_tx();
    let mut chain = iobuf::IOBufChain::from(vec![0xABu8; 40_000]);
    let sent = super::async_try_send_chain(handle, generation, &mut chain)
        .expect("an established connection accepts the send");
    assert_eq!(sent as u32, cwnd, "the send is capped at the congestion window");
    assert_eq!(
        chain.total_len(),
        40_000 - sent,
        "the bytes past the window stay queued in the chain",
    );
    assert_eq!(total_tx_payload(), sent, "exactly cwnd bytes hit the wire");
    assert_eq!(
        tx().len(),
        sent.div_ceil(1460),
        "the window ships as MSS-sized segments",
    );
    assert_eq!(
        tcp_hdr(&tx()[0]).seq,
        server_isn.wrapping_add(1),
        "the first segment starts at snd_una",
    );
}

/// A second send while the window is fully consumed by in-flight
/// data puts nothing on the wire — `Ok(0)` — and leaves the chain
/// untouched. No busy-wait, no dropped bytes.
#[test]
fn closed_window_sends_nothing() {
    let _g = harness();
    const SP: u16 = 9132;
    const CP: u16 = 50132;
    const CLIENT_ISN: u32 = 0xE200;
    super::listen_on_core(0, SP);
    handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    let mut chain = iobuf::IOBufChain::from(vec![0xCDu8; 40_000]);
    let first = super::async_try_send_chain(handle, generation, &mut chain)
        .expect("the first send is accepted");
    let (cwnd, _) = conn_cwnd_ssthresh(CP, SP);
    assert_eq!(first as u32, cwnd, "the first send fills the congestion window");

    // No ACK — the window stays closed.
    clear_tx();
    let second = super::async_try_send_chain(handle, generation, &mut chain)
        .expect("a closed-window send is not an error");
    assert_eq!(second, 0, "a closed window sends nothing");
    assert!(tx().is_empty(), "no segment goes out on a closed window");
    assert_eq!(
        chain.total_len(),
        40_000 - first,
        "the unsent bytes stay queued — not dropped",
    );
}

/// An ACK that frees in-flight bytes reopens the window: the send
/// that returned `Ok(0)` now drains the queued remainder.
#[test]
fn ack_reopens_the_send_window() {
    let _g = harness();
    const SP: u16 = 9133;
    const CP: u16 = 50133;
    const CLIENT_ISN: u32 = 0xE300;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    let mut chain = iobuf::IOBufChain::from(vec![0u8; 25_000]);
    let first = super::async_try_send_chain(handle, generation, &mut chain).unwrap() as u32;
    assert!(first > 0, "the first send fills the window");

    // The peer acknowledges the whole in-flight window.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1).wrapping_add(first),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });

    // The window has reopened (and cwnd grew) — the queued remainder
    // now goes out.
    clear_tx();
    let second = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert_eq!(
        second as u32,
        25_000 - first,
        "the ACK-reopened window drains the rest",
    );
    assert!(chain.is_empty(), "the whole body is now on the wire");
}

/// A sender parked on a closed window is woken by the ACK that
/// reopens it — the resume signal the reactor's `TcpSendChain`
/// future waits on.
#[test]
fn closed_window_wakes_parked_sender() {
    let _g = harness();
    const SP: u16 = 9134;
    const CP: u16 = 50134;
    const CLIENT_ISN: u32 = 0xE400;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    let (handle, generation) = conn_handle(CP, SP);
    let mut chain = iobuf::IOBufChain::from(vec![0u8; 25_000]);
    let first = super::async_try_send_chain(handle, generation, &mut chain).unwrap() as u32;

    // The window is closed — the reactor would park the send waker.
    let (waker, count) = counting_waker();
    super::register_send_waker(handle, generation, &waker);
    assert_eq!(count.0.load(Ordering::Relaxed), 0, "no spurious wake on register");

    // The ACK that reopens the window must wake the parked sender.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1).wrapping_add(first),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    assert!(
        count.0.load(Ordering::Relaxed) >= 1,
        "the window-opening ACK wakes the parked sender",
    );
}

/// The send window is `min(cwnd, rwnd)`: a small advertised receive
/// window caps in-flight bytes below the (larger) congestion window.
#[test]
fn send_respects_advertised_rwnd() {
    let _g = harness();
    const SP: u16 = 9135;
    const CP: u16 = 50135;
    const CLIENT_ISN: u32 = 0xE500;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);

    // The peer advertises a 2000-byte window — far below the
    // 14600-byte initial cwnd.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 2000,
        payload: Vec::new(),
    });

    let (handle, generation) = conn_handle(CP, SP);
    clear_tx();
    let mut chain = iobuf::IOBufChain::from(vec![0u8; 10_000]);
    let sent = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert_eq!(sent, 2000, "in-flight is capped by rwnd, not the larger cwnd");
    assert_eq!(total_tx_payload(), 2000, "exactly rwnd bytes hit the wire");
}

/// RFC 9293 §3.10.7.4 SND.WL1/SND.WL2: the window from a stale
/// (reordered) segment is ignored; the window from a current
/// segment is taken.
#[test]
fn window_update_obeys_wl1_wl2() {
    let _g = harness();
    const SP: u16 = 9136;
    const CP: u16 = 50136;
    const CLIENT_ISN: u32 = 0xE600;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    // A stale segment — its seq sits *below* the one that last set
    // the window (the 3-way ACK, at CLIENT_ISN+1) — must not install
    // its tiny window.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN, // < snd_wl1
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 100,
        payload: Vec::new(),
    });
    let mut chain = iobuf::IOBufChain::from(vec![0u8; 3000]);
    let sent = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert_eq!(
        sent, 3000,
        "the stale 100-byte window was rejected — the full cwnd applies",
    );

    // A current segment's window is accepted.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1 + 3000),
        flags: TCP_ACK,
        window: 1000,
        payload: Vec::new(),
    });
    let mut chain2 = iobuf::IOBufChain::from(vec![0u8; 5000]);
    let sent2 = super::async_try_send_chain(handle, generation, &mut chain2).unwrap();
    assert_eq!(sent2, 1000, "the current segment's 1000-byte window is honoured");
}

/// RFC 5681 §3.1 slow start, observed at the send path: with each
/// MSS segment acknowledged separately, `cwnd` opens by one SMSS per
/// ACK, so the window the send path offers doubles every RTT.
#[test]
fn send_window_ramps_with_slow_start() {
    let _g = harness();
    const SP: u16 = 9137;
    const CP: u16 = 50137;
    const CLIENT_ISN: u32 = 0xE700;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    let mut chain = iobuf::IOBufChain::from(vec![0u8; 60_000]);

    // RTT 1: the send path offers the initial congestion window.
    let round1 = super::async_try_send_chain(handle, generation, &mut chain).unwrap() as u32;
    assert!(round1 > 0, "RTT 1 sends the initial congestion window");

    // Acknowledge that window one MSS segment at a time — RFC 5681
    // slow start opens cwnd by one SMSS per ACK, so a whole RTT's
    // worth of ACKs adds `round1` and the window doubles.
    let mut acked = 0u32;
    while acked < round1 {
        acked += (round1 - acked).min(1460);
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: CLIENT_ISN.wrapping_add(1),
            ack: server_isn.wrapping_add(1).wrapping_add(acked),
            flags: TCP_ACK,
            window: 65535,
            payload: Vec::new(),
        });
    }

    // RTT 2: the window has doubled — exponential growth on the wire.
    let round2 = super::async_try_send_chain(handle, generation, &mut chain).unwrap() as u32;
    assert_eq!(round2, 2 * round1, "slow start doubled the send window over one RTT");
}

/// After an RTO collapses `cwnd` to one segment, the send path's
/// window follows: it offers only the collapsed `cwnd` minus the
/// still-unacked flight.
#[test]
fn send_window_tracks_cwnd_after_rto() {
    let _g = harness();
    const SP: u16 = 9138;
    const CP: u16 = 50138;
    const CLIENT_ISN: u32 = 0xE800;
    super::listen_on_core(0, SP);
    handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    // Send 1000 bytes and withhold the ACK.
    let mut chain = iobuf::IOBufChain::from(vec![0u8; 1000]);
    let sent = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert_eq!(sent, 1000, "the small send fits the initial window");

    // Cross the RTO — `congestion_on_rto` collapses cwnd to 1·SMSS.
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 + 1);
    super::on_tcp_tick();
    let (cwnd, _) = conn_cwnd_ssthresh(CP, SP);
    assert_eq!(cwnd, 1460, "the RTO collapsed cwnd to one segment");

    // 1000 bytes are still in flight; the collapsed window offers
    // only cwnd − flight = 1460 − 1000 = 460 bytes.
    let mut more = iobuf::IOBufChain::from(vec![0u8; 5000]);
    let after_rto = super::async_try_send_chain(handle, generation, &mut more).unwrap();
    assert_eq!(
        after_rto, 460,
        "the send window is the collapsed cwnd minus the in-flight bytes",
    );
}

/// A multi-hundred-KB transfer never trips `rtx_overflow`: the send
/// window keeps in-flight bytes at or below the 64 KiB retransmit
/// ring, so the ring always covers `[snd_una, snd_nxt)`.
#[test]
fn large_send_never_triggers_rtx_overflow() {
    let _g = harness();
    const SP: u16 = 9139;
    const CP: u16 = 50139;
    const CLIENT_ISN: u32 = 0xE900;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    let mut chain = iobuf::IOBufChain::from(vec![0u8; 400_000]);
    let mut snd_nxt = server_isn.wrapping_add(1);

    // Drain the whole body window by window, fully acknowledging
    // each round before the next.
    loop {
        let sent = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
        assert!(
            sent <= RTX_BUF_BYTES,
            "a single window never exceeds the retransmit ring",
        );
        assert!(
            !conn_rtx_overflow(CP, SP),
            "the retransmit ring never loses coverage of the unacked window",
        );
        if sent == 0 {
            break;
        }
        snd_nxt = snd_nxt.wrapping_add(sent as u32);
        // The peer acknowledges the whole window just sent.
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: CLIENT_ISN.wrapping_add(1),
            ack: snd_nxt,
            flags: TCP_ACK,
            window: 65535,
            payload: Vec::new(),
        });
    }
    assert!(chain.is_empty(), "the whole 400 KB body reached the wire");
}

// ---- RFC 9293 §3.8.6.1 zero-window persist -----------------------------
//
// A peer that advertises a zero receive window stalls the send path.
// The window-update ACK that lifts it carries no data and is not
// itself retransmitted, so a lost update would deadlock the send.
// The persist timer probes the shut window until the peer answers.

/// A zero advertised window blocks the send and arms the persist
/// timer, which then probes the shut window — a bare ACK one
/// sequence number below `snd_una` (the Linux `tcp_xmit_probe_skb`
/// shape).
#[test]
fn zero_window_arms_persist_and_probes() {
    let _g = harness();
    const SP: u16 = 9140;
    const CP: u16 = 50140;
    const CLIENT_ISN: u32 = 0xEA00;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    // The peer advertises a zero receive window.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 0,
        payload: Vec::new(),
    });

    // The send is blocked — and arms the persist timer.
    let mut chain = iobuf::IOBufChain::from(vec![0u8; 2000]);
    let blocked = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert_eq!(blocked, 0, "a zero advertised window blocks the send");

    // No probe before the persist interval elapses.
    let probes_before = super::diag::COUNTERS.persist_probes.get();
    clear_tx();
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 - 1);
    super::on_tcp_tick();
    assert!(tx().is_empty(), "no probe before the persist interval elapses");

    // Crossing it fires exactly one probe.
    kernel_core::clock::mock::advance(2);
    super::on_tcp_tick();
    let frames = tx();
    assert_eq!(frames.len(), 1, "the persist timer fires one probe");
    let h = tcp_hdr(&frames[0]);
    assert_eq!(h.flags, TCP_ACK, "the probe is a bare ACK");
    assert_eq!(
        h.seq, server_isn, // snd_una (server_isn + 1) − 1
        "the probe sits one sequence number below snd_una",
    );
    assert_eq!(
        frames[0].len(),
        34 + TCP_HDR_LEN,
        "the probe carries no payload",
    );
    assert_eq!(
        super::diag::COUNTERS.persist_probes.get(),
        probes_before + 1,
        "the probe bumped the persist_probes counter",
    );
}

/// The persist probe recovers a connection whose window-update ACK
/// was lost on the wire: the probe re-elicits the peer's window, the
/// parked sender wakes, and the queued data drains.
#[test]
fn zero_window_persist_recovers_lost_update() {
    let _g = harness();
    const SP: u16 = 9141;
    const CP: u16 = 50141;
    const CLIENT_ISN: u32 = 0xEB00;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 0,
        payload: Vec::new(),
    });
    let mut chain = iobuf::IOBufChain::from(vec![0u8; 2000]);
    let blocked = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert_eq!(blocked, 0, "the zero window blocks the send");

    // The reactor parks the send waker on the closed window.
    let (waker, count) = counting_waker();
    super::register_send_waker(handle, generation, &waker);

    // The peer's window-update is lost — only the persist probe gets
    // the connection moving again.
    clear_tx();
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 + 1);
    super::on_tcp_tick();
    assert_eq!(tx().len(), 1, "the persist timer probes the shut window");

    // The probe elicits the peer's re-advertised window.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    assert!(
        count.0.load(Ordering::Relaxed) >= 1,
        "the probe-elicited window update wakes the parked sender",
    );

    // The reopened window now drains the queued data.
    let sent = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert_eq!(sent, 2000, "the recovered window drains the queued data");
}

/// Successive persist probes back off exponentially off the RTO
/// estimate.
#[test]
fn zero_window_persist_backs_off() {
    let _g = harness();
    const SP: u16 = 9142;
    const CP: u16 = 50142;
    const CLIENT_ISN: u32 = 0xEC00;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 0,
        payload: Vec::new(),
    });
    let mut chain = iobuf::IOBufChain::from(vec![0u8; 2000]);
    super::async_try_send_chain(handle, generation, &mut chain).unwrap();

    // Probe 1 fires at the initial RTO.
    clear_tx();
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 + 1);
    super::on_tcp_tick();
    assert_eq!(tx().len(), 1, "probe 1 fires at the initial interval");

    // The interval has doubled — one more RTO of wait is not enough.
    clear_tx();
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64);
    super::on_tcp_tick();
    assert!(tx().is_empty(), "the backed-off (2x) interval has not elapsed");

    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64);
    super::on_tcp_tick();
    assert_eq!(tx().len(), 1, "probe 2 fires only after the doubled interval");
}

/// A peer that keeps its window shut across `PERSIST_MAX_PROBES`
/// unanswered probes is treated as dead — the connection is aborted.
#[test]
fn zero_window_persist_gives_up() {
    let _g = harness();
    const SP: u16 = 9143;
    const CP: u16 = 50143;
    const CLIENT_ISN: u32 = 0xED00;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 0,
        payload: Vec::new(),
    });
    let mut chain = iobuf::IOBufChain::from(vec![0u8; 2000]);
    super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert_eq!(conn_state(CP, SP), Some(TcpState::Established));

    // The peer's window stays shut forever — every probe goes
    // unanswered. Tick past each backed-off deadline.
    let giveups_before = super::diag::COUNTERS.persist_giveups.get();
    for _ in 0..=PERSIST_MAX_PROBES {
        kernel_core::clock::mock::advance(RTO_MAX_MS as u64 + 1);
        super::on_tcp_tick();
    }
    assert_eq!(
        conn_state(CP, SP),
        None,
        "a permanently shut window aborts the connection",
    );
    assert_eq!(
        super::diag::COUNTERS.persist_giveups.get(),
        giveups_before + 1,
        "the abort bumped the persist_giveups counter",
    );
    let (_, last) = super::diag::LAST_TEARDOWN.snapshot();
    assert_eq!(
        last.expect("the abort recorded a teardown").reason,
        super::diag::TeardownReason::PersistGiveup,
        "LAST_TEARDOWN attributes the abort to the persist give-up",
    );
}

// ---- RFC 6298 retransmit coverage for the TSO fast path ----------------

/// A TSO super-segment is retransmittable: `try_send_tso` retains its
/// sealed bytes in the RFC 6298 ring, so a TSO send whose ACK never
/// arrives is recovered by the RTO timer — exactly like a chain send.
#[test]
fn tso_send_is_retransmittable_on_rto() {
    let _g = harness();
    const SP: u16 = 9150;
    const CP: u16 = 50150;
    const CLIENT_ISN: u32 = 0xEE00;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    set_active_ops(&MOCK_OPS_TSO);
    let (handle, generation) = conn_handle(CP, SP);

    // A TSO super-segment: payload > MSS, so `try_send_tso` engages.
    clear_tx();
    let body = vec![0x5Au8; 3000];
    let r = super::try_send_tso(handle, generation, body.len(), &mut |slot: &mut [u8]| {
        slot[..body.len()].copy_from_slice(&body);
        Ok(body.len())
    });
    assert_eq!(r, Some(Ok(3000)), "the TSO fast path ships the whole payload");
    assert_eq!(tx().len(), 1, "one TSO super-segment goes on the wire");

    // Withhold the ACK; cross the RTO. The TSO bytes must be
    // retransmitted — without retain coverage they would be lost.
    clear_tx();
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 + 1);
    super::on_tcp_tick();
    let rtx = tx();
    assert_eq!(rtx.len(), 1, "the RTO retransmits the unacked TSO segment");
    assert_eq!(
        tcp_hdr(&rtx[0]).seq,
        server_isn.wrapping_add(1),
        "the retransmit re-sends from snd_una",
    );
    assert_eq!(
        &rtx[0][34 + TCP_HDR_LEN..],
        &body[..1460],
        "the retransmit carries the original TSO payload (one MSS)",
    );
}

/// A response that mixes a TSO send and a chain send keeps the
/// retransmit ring consistent. An ACK covering only the TSO bytes
/// advances `snd_una` past them; the RTO retransmit then resumes at
/// the still-unacked chain bytes. Before TSO retain coverage the ring
/// desynced — TSO bytes advanced `snd_nxt` without entering it, so
/// `rtx_on_ack`'s `min(acked, rtx_len)` dropped live chain bytes.
#[test]
fn tso_then_chain_rtx_stays_consistent() {
    let _g = harness();
    const SP: u16 = 9151;
    const CP: u16 = 50151;
    const CLIENT_ISN: u32 = 0xEF00;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    set_active_ops(&MOCK_OPS_TSO);
    let (handle, generation) = conn_handle(CP, SP);

    // A TSO super-segment (2000 B) followed by a chain send (1000 B).
    let tso_body = vec![0xA1u8; 2000];
    assert_eq!(
        super::try_send_tso(handle, generation, tso_body.len(), &mut |slot: &mut [u8]| {
            slot[..tso_body.len()].copy_from_slice(&tso_body);
            Ok(tso_body.len())
        }),
        Some(Ok(2000)),
        "the TSO send is accepted",
    );
    let chain_body = vec![0xB2u8; 1000];
    let mut chain = iobuf::IOBufChain::from(chain_body.clone());
    let sent = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert_eq!(sent, 1000, "the chain send follows the TSO send");

    // The peer acknowledges only the 2000 TSO bytes.
    clear_tx();
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1 + 2000),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });

    // The RTO retransmit must resume at the chain bytes — `snd_una`
    // has advanced past the acked TSO bytes.
    kernel_core::clock::mock::advance(RTO_INITIAL_MS as u64 + 1);
    super::on_tcp_tick();
    let rtx = tx();
    assert_eq!(rtx.len(), 1, "the RTO retransmits the still-unacked chain bytes");
    assert_eq!(
        tcp_hdr(&rtx[0]).seq,
        server_isn.wrapping_add(1 + 2000),
        "the retransmit resumes at snd_una — past the acked TSO bytes",
    );
    assert_eq!(
        &rtx[0][34 + TCP_HDR_LEN..],
        &chain_body[..],
        "the retransmit carries the chain bytes, not stale TSO bytes",
    );
}

// ---- RFC 9293 §3.10.7.4 ACK acceptability ------------------------------

/// A stale, reordered ACK — `SEG.ACK` below `SND.UNA` — must not drag
/// `SND.UNA` backwards. Reordered ACKs are routine on real paths; an
/// unconditional `snd_una = ack` would desync the send side and
/// corrupt the retransmit ring.
#[test]
fn stale_ack_does_not_rewind_snd_una() {
    let _g = harness();
    const SP: u16 = 9160;
    const CP: u16 = 50160;
    const CLIENT_ISN: u32 = 0xF100;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    // 2000 bytes in flight; the peer acknowledges the first 1000.
    let mut chain = iobuf::IOBufChain::from(vec![0u8; 2000]);
    super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1 + 1000),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    assert_eq!(
        conn_snd_una(CP, SP),
        server_isn.wrapping_add(1 + 1000),
        "the in-order ACK advanced snd_una",
    );

    // A reordered copy of the original ACK arrives late.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    assert_eq!(
        conn_snd_una(CP, SP),
        server_isn.wrapping_add(1 + 1000),
        "a stale old ACK must not drag snd_una backwards",
    );
}

/// An ACK above `SND.NXT` acknowledges data we never sent. RFC 9293
/// §3.10.7.4: answer with a bare ACK and drop the segment — including
/// any payload it carries — leaving `SND.UNA` untouched.
#[test]
fn future_ack_is_dropped_with_a_bare_ack() {
    let _g = harness();
    const SP: u16 = 9161;
    const CP: u16 = 50161;
    const CLIENT_ISN: u32 = 0xF200;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    // 500 bytes in flight.
    let mut chain = iobuf::IOBufChain::from(vec![0u8; 500]);
    super::async_try_send_chain(handle, generation, &mut chain).unwrap();

    // A segment acking 5000 bytes past snd_nxt, carrying injected data.
    clear_tx();
    let ack_unsent_before = super::diag::COUNTERS.ack_unsent.get();
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1 + 5000),
        flags: TCP_ACK | TCP_PSH,
        window: 65535,
        payload: b"injected".to_vec(),
    });

    let frames = tx();
    assert_eq!(frames.len(), 1, "an unacceptable ACK elicits exactly one bare ACK");
    let h = tcp_hdr(&frames[0]);
    assert_eq!(h.flags, TCP_ACK, "the reply is a bare ACK");
    assert_eq!(
        h.seq,
        server_isn.wrapping_add(1 + 500),
        "the reply carries our real snd_nxt",
    );
    assert_eq!(
        h.ack,
        CLIENT_ISN.wrapping_add(1),
        "the reply carries our real rcv_nxt — the injected payload was dropped",
    );
    assert_eq!(
        conn_snd_una(CP, SP),
        server_isn.wrapping_add(1),
        "the bogus ACK left snd_una untouched",
    );
    // The rejection is traced — `ack_unsent` counts it and
    // `LAST_ACK_UNSENT` retains the RFC 9293 acceptability inputs.
    assert_eq!(
        super::diag::COUNTERS.ack_unsent.get(),
        ack_unsent_before + 1,
        "the rejection bumped the ack_unsent counter",
    );
    let (_, last) = super::diag::LAST_ACK_UNSENT.snapshot();
    let last = last.expect("the rejection recorded a snapshot");
    assert_eq!(
        last.seg_ack,
        server_isn.wrapping_add(1 + 5000),
        "LAST_ACK_UNSENT retained the rejected SEG.ACK",
    );
    assert_eq!(
        last.snd_nxt,
        server_isn.wrapping_add(1 + 500),
        "LAST_ACK_UNSENT retained the SND.NXT it failed against",
    );
}

// ---- lossy-transfer recovery -------------------------------------------
//
// The conformance harness is deterministic and loss-free by default;
// the egress-drop fixture is the only loss seam. These two scenarios
// drive a *windowed* multi-segment transfer, drop real segments with
// the fixture, and assert the whole composition — windowed
// `async_try_send_chain`, the RFC 5681 congestion response, and the
// RFC 6298 / fast-retransmit recovery — delivers every byte. They
// exercise the loss behaviour that the loss-free HVF and GCE-loopback
// benches cannot reach.

/// A whole window lost on the wire is recovered by the RTO timer one
/// segment at a time (the stack has no SACK), the loss collapses
/// `cwnd` to one segment, and the transfer still delivers every byte.
#[test]
fn lossy_windowed_transfer_completes() {
    let _g = harness();
    const SP: u16 = 9170;
    const CP: u16 = 50170;
    const CLIENT_ISN: u32 = 0xF300;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    let total: usize = 20_000;
    let mut chain = iobuf::IOBufChain::from(vec![0x5Au8; total]);

    // Window 1 — delivered cleanly, acknowledged in full.
    let w1 = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert!(w1 > 0 && w1 < total, "the body spans more than one window");
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1).wrapping_add(w1 as u32),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });

    // Window 2 — every segment dropped on the wire.
    let w2_frames = (total - w1).div_ceil(1460);
    clear_tx();
    drop_next_egress(w2_frames as u32);
    let w2 = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert_eq!(w1 + w2, total, "the whole body has left the send path");
    assert!(chain.is_empty(), "nothing is left queued in the chain");
    assert!(tx().is_empty(), "window 2's segments were all dropped on the wire");
    assert_eq!(egress_drops(), w2_frames as u32);

    // The RTO recovers window 2 one segment per timeout (no SACK).
    let final_nxt = server_isn.wrapping_add(1).wrapping_add(total as u32);
    let mut cycles = 0u32;
    let mut at_loss: Option<(u32, u32)> = None;
    while conn_snd_una(CP, SP) != final_nxt {
        cycles += 1;
        assert!(cycles <= 32, "RTO recovery must converge");
        clear_tx();
        kernel_core::clock::mock::advance(RTO_MAX_MS as u64 + 1);
        super::on_tcp_tick();
        if at_loss.is_none() {
            at_loss = Some(conn_cwnd_ssthresh(CP, SP));
        }
        let rtx = tx();
        assert_eq!(rtx.len(), 1, "the RTO retransmits exactly one segment per tick");
        let seg_len = (rtx[0].len() - 34 - TCP_HDR_LEN) as u32;
        let acked = conn_snd_una(CP, SP).wrapping_add(seg_len);
        deliver(&Seg {
            src_port: CP,
            dst_port: SP,
            seq: CLIENT_ISN.wrapping_add(1),
            ack: acked,
            flags: TCP_ACK,
            window: 65535,
            payload: Vec::new(),
        });
    }

    let (cwnd_at_loss, ssthresh_at_loss) = at_loss.expect("recovery ran at least one RTO");
    assert_eq!(cwnd_at_loss, 1460, "the RTO collapsed cwnd to one SMSS");
    assert_eq!(
        ssthresh_at_loss,
        (w2 as u32 / 2).max(2 * 1460),
        "ssthresh dropped to half the lost flight (2·SMSS floor)",
    );
    assert_eq!(cycles as usize, w2_frames, "one RTO cycle per lost segment");
    assert_eq!(
        conn_snd_una(CP, SP),
        final_nxt,
        "every byte of the lossy transfer was ultimately delivered",
    );
    assert!(
        !conn_rtx_overflow(CP, SP),
        "the retransmit ring stayed consistent through the loss",
    );
    let (cwnd_after, _) = conn_cwnd_ssthresh(CP, SP);
    assert!(
        cwnd_after < 14_600,
        "the loss persistently shrank the window — cwnd did not snap back",
    );
}

/// A single segment dropped mid-window is recovered by fast
/// retransmit — no RTO wait — and the windowed transfer flows on to
/// completion. The egress-drop fixture really removes the segment,
/// so the recovered frame is unambiguous; the `data_retransmits`
/// counter staying 0 confirms recovery was fast retransmit, not RTO.
#[test]
fn fast_retransmit_keeps_a_windowed_transfer_flowing() {
    let _g = harness();
    const SP: u16 = 9171;
    const CP: u16 = 50171;
    const CLIENT_ISN: u32 = 0xF400;
    super::listen_on_core(0, SP);
    let server_isn = handshake(SP, CP, CLIENT_ISN);
    let (handle, generation) = conn_handle(CP, SP);

    let total: usize = 20_000;
    let body = vec![0xC7u8; total];
    let mut chain = iobuf::IOBufChain::from(body.clone());
    let rto_retransmits_before = super::diag::COUNTERS.data_retransmits.get();

    // Window 1 — the first segment is dropped on the wire.
    clear_tx();
    drop_next_egress(1);
    let w1 = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert!(w1 > 3 * 1460, "window 1 is several segments");
    assert_eq!(egress_drops(), 1, "the first segment was dropped");

    // The peer sees the gap and dup-ACKs; the third triggers fast
    // retransmit of the missing segment — with the clock untouched.
    let dup = Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    };
    clear_tx();
    deliver(&dup);
    deliver(&dup);
    assert!(tx().is_empty(), "two dup-ACKs do not retransmit");
    deliver(&dup);
    let rtx = tx();
    assert_eq!(rtx.len(), 1, "the third dup-ACK fast-retransmits");
    assert_eq!(
        tcp_hdr(&rtx[0]).seq,
        server_isn.wrapping_add(1),
        "the fast retransmit re-sends the dropped segment from snd_una",
    );
    assert_eq!(
        &rtx[0][34 + TCP_HDR_LEN..],
        &body[..1460],
        "the recovered segment carries the dropped segment's bytes",
    );
    assert_eq!(
        super::diag::COUNTERS.data_retransmits.get(),
        rto_retransmits_before,
        "recovery was fast retransmit — no RTO timer fired",
    );

    // The peer now has the whole first window — ACK it; the windowed
    // transfer resumes and the remaining bytes go out.
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1).wrapping_add(w1 as u32),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    let w2 = super::async_try_send_chain(handle, generation, &mut chain).unwrap();
    assert_eq!(w1 + w2, total, "the transfer flowed on past the recovered loss");
    deliver(&Seg {
        src_port: CP,
        dst_port: SP,
        seq: CLIENT_ISN.wrapping_add(1),
        ack: server_isn.wrapping_add(1).wrapping_add(total as u32),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    assert_eq!(
        conn_snd_una(CP, SP),
        server_isn.wrapping_add(1).wrapping_add(total as u32),
        "every byte was delivered after the fast-retransmit recovery",
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

/// The `(cwnd, ssthresh)` of the live connection for a client/server
/// port pair — lets a scenario assert on the RFC 5681 controller.
fn conn_cwnd_ssthresh(client_port: u16, server_port: u16) -> (u32, u32) {
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
            return (c.cwnd, c.ssthresh);
        }
    }
    panic!("no live connection for ports {client_port} -> {server_port}");
}

/// `rtx_overflow` of the live connection for a client/server port
/// pair — lets a scenario assert the retransmit ring never lost
/// coverage of the unacked window.
fn conn_rtx_overflow(client_port: u16, server_port: u16) -> bool {
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
            return c.rtx_overflow;
        }
    }
    panic!("no live connection for ports {client_port} -> {server_port}");
}

/// `snd_una` of the live connection for a client/server port pair —
/// lets a scenario assert on send-sequence bookkeeping.
fn conn_snd_una(client_port: u16, server_port: u16) -> u32 {
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
            return c.snd_una;
        }
    }
    panic!("no live connection for ports {client_port} -> {server_port}");
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

/// Drive a connection through a full active close into `TimeWait`:
/// handshake, `close()` (→ FinWait1), the peer's ACK of our FIN
/// (→ FinWait2), then the peer's FIN (→ TimeWait). Returns the
/// server ISN.
fn enter_timewait(server_port: u16, client_port: u16, client_isn: u32) -> u32 {
    let server_isn = handshake(server_port, client_port, client_isn);
    let (handle, generation) = conn_handle(client_port, server_port);
    super::close(handle, generation);
    deliver(&Seg {
        src_port: client_port,
        dst_port: server_port,
        seq: client_isn.wrapping_add(1),
        ack: server_isn.wrapping_add(2),
        flags: TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    deliver(&Seg {
        src_port: client_port,
        dst_port: server_port,
        seq: client_isn.wrapping_add(1),
        ack: server_isn.wrapping_add(2),
        flags: TCP_FIN | TCP_ACK,
        window: 65535,
        payload: Vec::new(),
    });
    server_isn
}

// ---- rtx_queue scaffolding ---------------------------------------------
//
// The rtx_queue methods on `TcpConnection` are dead code today (the
// send / ACK / RTO paths still drive `rtx_buf` exclusively). These
// tests pin the queue's per-entry behaviour — head-pop, partial-narrow,
// bytes-in-flight sum, deque-allocation preserved across reset — so
// the follow-up commits that wire the send / ACK / RTO paths through
// the queue are swapping a proven-equivalent implementation in.
//
// Driven through a real connection slot (via `handshake`) so the
// per-core pool, the armed-timer list, and the mock clock are all
// initialised — the queue's `arm_rtx` call into `register_armed_slot`
// would null-deref `PerWorker::at` without that setup.

/// `rtx_push` seeds the entry's bookkeeping and the bytes-in-flight
/// sum, and arms the RTT anchor when one is not already outstanding.
#[test]
fn rtx_push_seeds_entry_and_anchor() {
    let _g = harness();
    const SP: u16 = 9180;
    const CP: u16 = 50180;
    handshake(SP, CP, 0xF800);
    super::listen_on_core(0, SP);
    let _ = handshake(SP, CP, 0xF800);

    let core = 0u32;
    let cap = pool_capacity(core);
    for i in 0..cap {
        let c = unsafe { &mut *conn_ptr(core, i) };
        if c.state != crate::state::TcpState::Closed
            && c.state != crate::state::TcpState::Listen
            && c.local_port == SP
            && c.remote_port == CP
        {
            // Clear the RTT anchor the handshake left set so the
            // push exercises the seed branch.
            c.rtt_anchor_active = false;
            let buf = iobuf::IOBuf::from(vec![0u8; 100]);
            assert!(c.rtx_push(buf, 1000, 100, 42));
            assert_eq!(c.rtx_queue.len(), 1);
            assert_eq!(c.rtx_bytes_in_flight, 100);
            let head = c.rtx_queue.front().unwrap();
            assert_eq!(head.seq_start, 1000);
            assert_eq!(head.len, 100);
            assert_eq!(head.first_tx_ms, 42);
            assert_eq!(head.tx_count, 1);
            assert!(c.rtt_anchor_active);
            assert_eq!(c.rtt_anchor_seq, 1100);
            return;
        }
    }
    panic!("no live connection for ports {CP} -> {SP}");
}

/// `rtx_ack` covering the full head entry pops it; covering a prefix
/// of the head entry narrows the IOBuf forward.
#[test]
fn rtx_ack_pops_and_narrows() {
    let _g = harness();
    const SP: u16 = 9181;
    const CP: u16 = 50181;
    super::listen_on_core(0, SP);
    handshake(SP, CP, 0xF810);

    let core = 0u32;
    let cap = pool_capacity(core);
    for i in 0..cap {
        let c = unsafe { &mut *conn_ptr(core, i) };
        if c.state != crate::state::TcpState::Closed
            && c.state != crate::state::TcpState::Listen
            && c.local_port == SP
            && c.remote_port == CP
        {
            let mk = |seed: u8, len: usize| {
                let v: Vec<u8> = (0..len).map(|i| seed.wrapping_add(i as u8)).collect();
                iobuf::IOBuf::from(v)
            };
            c.rtx_push(mk(0xA0, 100), 1000, 100, 1);
            c.rtx_push(mk(0xB0, 200), 1100, 200, 2);

            // Full ACK of the head entry pops it.
            let acked = c.rtx_ack(1100, 10);
            assert_eq!(acked, 100);
            assert_eq!(c.rtx_queue.len(), 1);
            assert_eq!(c.rtx_bytes_in_flight, 200);

            // Partial ACK of the new head (30 of 200) narrows in place.
            let acked = c.rtx_ack(1130, 11);
            assert_eq!(acked, 30);
            assert_eq!(c.rtx_queue.len(), 1);
            assert_eq!(c.rtx_bytes_in_flight, 170);
            let head = c.rtx_queue.front().unwrap();
            assert_eq!(head.seq_start, 1130);
            assert_eq!(head.len, 170);
            assert_eq!(head.iobuf.data().len(), 170);
            assert_eq!(head.iobuf.data()[0], 0xB0u8.wrapping_add(30));
            return;
        }
    }
    panic!("no live connection for ports {CP} -> {SP}");
}

/// `rtx_ack` covers multiple entries cumulatively.
#[test]
fn rtx_ack_cumulative_drains_multiple() {
    let _g = harness();
    const SP: u16 = 9182;
    const CP: u16 = 50182;
    super::listen_on_core(0, SP);
    handshake(SP, CP, 0xF820);

    let core = 0u32;
    let cap = pool_capacity(core);
    for i in 0..cap {
        let c = unsafe { &mut *conn_ptr(core, i) };
        if c.state != crate::state::TcpState::Closed
            && c.state != crate::state::TcpState::Listen
            && c.local_port == SP
            && c.remote_port == CP
        {
            c.rtx_push(iobuf::IOBuf::from(vec![0u8; 100]), 1000, 100, 1);
            c.rtx_push(iobuf::IOBuf::from(vec![0u8; 200]), 1100, 200, 2);
            c.rtx_push(iobuf::IOBuf::from(vec![0u8; 50]), 1300, 50, 3);
            // ACK retires the first two entries fully + 10 bytes of
            // the third.
            assert_eq!(c.rtx_ack(1310, 10), 310);
            assert_eq!(c.rtx_queue.len(), 1);
            assert_eq!(c.rtx_bytes_in_flight, 40);
            let head = c.rtx_queue.front().unwrap();
            assert_eq!(head.seq_start, 1310);
            assert_eq!(head.len, 40);
            return;
        }
    }
    panic!("no live connection for ports {CP} -> {SP}");
}
