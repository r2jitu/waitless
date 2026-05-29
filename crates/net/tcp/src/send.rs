// Outbound TCP segment assembly — the unified frame builder
// (`build_and_send_frame`) and its callers: control-segment
// (`send_segment` / `send_rst`), data-segment-from-cursor
// (`send_segment_from_cursor`), TSO super-segment, and the chain
// send path (`async_try_send_chain`) consumed by the reactor's
// backend hook.

use crate::pool::{conn_ptr, decode_handle};
use crate::state::{
    MSS_MAX, MSS_V4, TCP_ACK, TCP_PSH, TCP_RST, TcpHeader, TcpState, mss_for,
};
use core::ptr;
use types::{IpAddr, MacAddr, htonl, htons};

/// Drop-guard bracketing `async_try_send_chain` in a cycle counter,
/// mirroring `receive::RxGuard`. Fires on every exit (the `Ok(0)`
/// backpressure returns included) so `send_cycles / send_calls` is
/// the true per-call cost. `SEND_CYCLES`/`SEND_CALLS` are per-core
/// single-writer stores. Splits the serve `runtime` residual:
/// response-send vs recv-plumbing + dispatch.
struct SendGuard {
    core: u32,
    start: u64,
}

impl SendGuard {
    #[inline]
    fn new(core: u32) -> Self {
        Self {
            core,
            start: kernel_core::clock::now_cycles(),
        }
    }
}

impl Drop for SendGuard {
    #[inline]
    fn drop(&mut self) {
        let elapsed = kernel_core::clock::now_cycles().wrapping_sub(self.start);
        crate::diag::SEND_CYCLES.add(self.core, elapsed);
        crate::diag::SEND_CALLS.add(self.core, 1);
    }
}

// ─── Unified TCP-frame builder ───────────────────────────────────────────────
//
// Build the full Ethernet+IP+TCP+payload frame in one stack buffer
// and hand it directly to the driver. Replaces the legacy chain of
// `send_l3 → ipv4_send → ethernet_send`, which built a fresh stack
// buffer at each layer and `memcpy`'d the inner bytes forward —
// three memcpys per byte just to attach 54 B of headers.
//
// The two payload-source variants (slice / chain cursor) share
// `fill_tcp_frame_headers` for header-fill and family dispatch;
// only the payload-write step differs.
//
// Frame layout:
//   v4: [ETH 14][IPv4 20][TCP 20][payload ≤ MSS_V4 = 1460]  → ≤ 1514 B
//   v6: [ETH 14][IPv6 40][TCP 20][payload ≤ MSS_V6 = 1440]  → ≤ 1514 B
//
// Same total bound for both families, so one stack buffer fits all.
// TSO super-segments (up to ~16 KiB payload) bypass the stack
// buffer — they always use the driver's direct-fill TX-pool slot
// via `acquire_tx_buf` (which has the larger `data_cap` for the
// super-segment shape). When acquire fails on the TSO path, we
// fall back to the per-MSS loop rather than expanding this stack
// buffer to ~16 KiB.

pub(crate) const ETH_HDR_LEN: usize = ethernet::HEADER_LEN; // 14
pub(crate) const IPV4_HDR_LEN: usize = ipv4::HEADER_LEN; // 20
pub(crate) const IPV6_HDR_LEN: usize = ipv6::HEADER_LEN; // 40
pub(crate) const TCP_HDR_LEN: usize = 20;

/// The 4-tuple + sequence/ack/flags/window metadata that uniquely
/// identifies a TCP segment we're about to emit. Bundled to keep
/// the frame-builder + send-helper signatures readable — every site
/// in this module previously passed the same eight scalars by hand.
/// `dst_mac` is *not* here because it's resolved later (after a
/// successful `mac_resolve::resolve`), and the payload (slice or
/// cursor) varies by caller.
#[derive(Clone, Copy)]
pub(crate) struct SegmentMeta {
    pub local_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}
const FRAME_BUF_LEN: usize = ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN + MSS_V4;
/// Per-conn-state cap on TSO super-segments: the maximum bytes we
/// hand to `submit_tx_tso` in one frame. Sized to cover one TLS
/// 1.3 record (16384 plaintext + 22-byte envelope) plus the
/// L2/L3/L4 headers. The driver's TX-pool slots are sized to
/// match (`MAX_ETH_FRAME` in virtio_net).
const TSO_FRAME_BUF_LEN: usize = ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN + 16384 + 24;

/// Compute the TCP-payload offset within a frame buffer for `local_ip`'s family.
#[inline]
pub(crate) fn payload_offset(local_ip: IpAddr) -> usize {
    match local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN, // 54
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN, // 74
    }
}

/// Fill the ETH + IP + TCP headers of `frame` in place. `frame` must
/// already contain the TCP payload at `frame[payload_offset(local_ip)..]`.
/// `payload_len` is the bytes past the TCP header (TCP segment payload
/// length); 0 for control-only segments. Computes both IP and TCP
/// checksums in place.
unsafe fn fill_tcp_frame_headers(
    frame: &mut [u8],
    meta: &SegmentMeta,
    dst_mac: MacAddr,
    payload_len: usize,
) {
    let tcp_off = match meta.local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN,
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN,
    };
    let tcp_seg_len = TCP_HDR_LEN + payload_len;

    // ── TCP header ───────────────────────────────────────────────────
    // SAFETY: frame[tcp_off..tcp_off+TCP_HDR_LEN] is in-bounds (caller
    // sized the buffer). `TcpHeader` is `repr(C)` POD bytes.
    let tcp_hdr = unsafe { &mut *(frame.as_mut_ptr().add(tcp_off) as *mut TcpHeader) };
    tcp_hdr.src_port = htons(meta.src_port);
    tcp_hdr.dst_port = htons(meta.dst_port);
    tcp_hdr.seq = htonl(meta.seq);
    tcp_hdr.ack = htonl(meta.ack);
    tcp_hdr.data_offset = 0x50;
    tcp_hdr.flags = meta.flags;
    tcp_hdr.window = htons(meta.window);
    tcp_hdr.checksum = 0;
    tcp_hdr.urgent = 0;
    // Stamp the pseudo-header partial sum at the TCP checksum
    // field; the driver finishes it — device CSUM offload, or a
    // software pass when the device never negotiated it.
    tcp_hdr.checksum =
        checksum::l4_pseudo_partial(meta.local_ip, meta.dst_ip, types::proto::TCP, tcp_seg_len);

    // ── IP header (family-dispatched) ────────────────────────────────
    let ip_total = (tcp_off - ETH_HDR_LEN + tcp_seg_len) as u16;
    match (meta.local_ip, meta.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            ipv4::fill_header(
                &mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN],
                s,
                d,
                types::proto::TCP,
                ip_total,
            );
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            ipv6::fill_header(
                &mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV6_HDR_LEN],
                &s,
                &d,
                types::proto::TCP,
                64,
                tcp_seg_len as u16,
            );
        }
        _ => unreachable!("mismatched family"),
    }

    // ── Ethernet header ──────────────────────────────────────────────
    let ethertype = match meta.dst_ip {
        IpAddr::V4(_) => ethernet::ETHERTYPE_IPV4,
        IpAddr::V6(_) => ipv6::ETHERTYPE_IPV6,
    };
    ethernet::fill_header(
        &mut frame[..ETH_HDR_LEN],
        dst_mac,
        ethernet::ethernet_our_mac(),
        ethertype,
    );
}

/// Acquire a TX-pool slot from the driver and run `fill` over its
/// frame region; submit it for transmission. `tcp_hdr_off` is the
/// byte offset of the TCP header within the frame — handed to the
/// driver (via `submit_tx`, or the `send` fallback) as the L4
/// checksum-offload descriptor.
///
/// Falls back to a stack-staged frame + slice-shaped `send` when
/// the driver doesn't expose direct-fill (`acquire_tx_buf == None`)
/// — the gve driver's DQO_RDA path surfaces this today.
///
/// `fill` writes `frame_len` bytes starting at the head of the
/// passed `&mut [u8]` (≥ `FRAME_BUF_LEN` bytes). Caller is
/// responsible for ensuring `frame_len <= FRAME_BUF_LEN`.
#[inline]
fn build_and_send_frame<F>(frame_len: usize, tcp_hdr_off: u16, fill: F)
where
    F: FnOnce(&mut [u8]),
{
    debug_assert!(frame_len <= FRAME_BUF_LEN);
    // `fill` (→ `fill_tcp_frame_headers`) stamps the pseudo-header
    // partial sum at the TCP checksum field; the driver finishes
    // it. 16 = the checksum field's offset within the TCP header.
    let csum = nic::CsumOffload {
        start: tcp_hdr_off,
        offset: 16,
    };
    if let Some(mut handle) = nic::acquire_tx_buf() {
        let cap = handle.data_cap as usize;
        debug_assert!(frame_len <= cap);
        // SAFETY: the handle's `data_mut()` returns a slice of
        // `data_cap` writable bytes; we narrow to `frame_len`
        // for the closure but the underlying buffer covers the
        // full slot.
        fill(&mut handle.data_mut()[..frame_len]);
        nic::submit_tx(handle, frame_len, csum);
        return;
    }
    // Slice-shaped fallback: stage the frame on the stack and hand
    // it to the driver's `send` with the same `csum` descriptor as
    // the `submit_tx` path above — the driver finishes the checksum
    // either way (device offload, or a software pass). The gve
    // DQO_RDA path takes this branch for every frame.
    let mut buf = core::mem::MaybeUninit::<[u8; FRAME_BUF_LEN]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;
    // SAFETY: `from_raw_parts_mut` over uninit memory is fine
    // as long as the resulting slice is fully written before
    // any read. `fill` writes every byte in `[..frame_len]`;
    // `send` then reads them.
    unsafe {
        let frame = core::slice::from_raw_parts_mut(p, frame_len);
        fill(frame);
        let frame_const = core::slice::from_raw_parts(p, frame_len);
        nic::send(frame_const, csum);
    }
}

/// Build and ship a TCP segment whose payload comes from `payload`
/// (a contiguous byte slice). Used by control-path callers (SYN,
/// SYN-ACK, ACK-only, FIN, RST) and by tests.
pub(crate) fn send_segment(meta: &SegmentMeta, payload: &[u8]) {
    let dst_mac = match mac_resolve::resolve(meta.dst_ip) {
        Some(m) => m,
        None => return, // ARP/NDP miss; TCP retransmit will retry
    };

    let payload_off = payload_offset(meta.local_ip);
    let payload_len = payload.len().min(MSS_MAX);
    let frame_len = payload_off + payload_len;
    // TCP header offset within the frame = ETH + IP. Used by the
    // CSUM-offload hint passed to `submit_tx`.
    let tcp_off = match meta.local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN,
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN,
    } as u16;

    build_and_send_frame(frame_len, tcp_off, |frame| unsafe {
        // Copy payload into the frame's payload slot.
        if payload_len > 0 {
            ptr::copy_nonoverlapping(
                payload.as_ptr(),
                frame.as_mut_ptr().add(payload_off),
                payload_len,
            );
        }
        fill_tcp_frame_headers(frame, meta, dst_mac, payload_len);
    });
}

/// Build and ship a TCP TSO super-segment whose payload (up to
/// ~16 KiB — one TLS record's worth) is read from a chain
/// cursor. The driver's NIC segments the payload into MSS-sized
/// chunks host-side, fixing up TCP/IP headers per segment.
///
/// Caller must have verified `nic::tso_available()`
/// before reaching this. Falls back to the per-MSS loop in
/// `async_try_send_chain` when not available.
fn send_super_segment_from_cursor(
    meta: &SegmentMeta,
    cursor: &mut iobuf::Cursor<'_>,
    payload_len: usize,
) {
    let dst_mac = match mac_resolve::resolve(meta.dst_ip) {
        Some(m) => m,
        None => return,
    };

    let payload_off = payload_offset(meta.local_ip);
    let frame_len = payload_off + payload_len;
    debug_assert!(frame_len <= TSO_FRAME_BUF_LEN);

    // TSO super-segments need a big-pool slot (16 KiB capacity).
    // Falls back to per-MSS when the big pool is full or TSO
    // isn't supported on this driver.
    let Some(mut handle) = nic::acquire_tx_tso_buf() else {
        send_per_mss_fallback(meta, cursor, payload_len);
        return;
    };
    let cap = handle.data_cap() as usize;
    debug_assert!(frame_len <= cap);

    let frame = &mut handle.data_mut()[..frame_len];
    // Read the entire super-segment payload directly into the
    // TX-pool slot via the chain cursor — single memcpy across
    // chain → driver TX pool.
    if payload_len > 0 {
        let n = cursor.read(&mut frame[payload_off..payload_off + payload_len]);
        debug_assert_eq!(n, payload_len);
        let _ = n;
    }
    // SAFETY: `frame` is initialised through `frame[payload_off..
    // payload_off + payload_len]` above; the header-fill below
    // writes the rest.
    unsafe {
        fill_tcp_frame_headers(frame, meta, dst_mac, payload_len);
    }
    // Zero the TCP checksum: with VIRTIO_NET_F_NEEDS_CSUM set,
    // the device computes the per-segment TCP checksum (the
    // partial-checksum convention isn't strictly required —
    // HVF's userspace TCP proxy ignores the field and forwards
    // bytes; vhost-net + real NICs honour the gso fields and
    // synthesise full checksums per segment).
    let tcp_off = match meta.local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN,
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN,
    };
    frame[tcp_off + 16] = 0; // TCP checksum field, big-endian high byte
    frame[tcp_off + 17] = 0; //                              low byte

    let mss = mss_for(meta.local_ip);
    let hdr_len = (payload_off) as u16;
    let csum_start = (tcp_off) as u16;
    nic::submit_tx_tso(handle, frame_len, hdr_len, csum_start, mss as u16);
}

/// Try to send a single TCP TSO super-segment whose payload is
/// produced by `fill`. The closure is called with a mutable byte
/// slice into the driver's TX-pool big-slot's payload region
/// (i.e. the bytes after [ETH][IP][TCP] headers); it writes
/// payload bytes there and returns the byte count written.
/// This function fills the L2/L3/L4 headers around the closure's
/// output, calls `submit_tx_tso`, and advances `snd_nxt`.
///
/// The TLS layer uses this to encrypt directly into the TX-pool
/// slot — eliminating the stack-scratch → TX-slot memcpy that
/// the regular `async_try_send_chain` path does. The closure
/// receives access to bytes already in the driver's exclusive-
/// write buffer; the TLS encrypter's chain-to primitive walks
/// the plaintext chain and produces ciphertext directly into
/// those bytes.
///
/// Returns:
///   * `Some(payload_len)` on success — the bytes are in flight.
///   * `None` when no TSO slot is available (TSO not negotiated,
///     big pool full, conn not Established, dst MAC unresolved,
///     stale `gen`). Caller falls back to the regular send path.
pub fn try_send_tso(
    handle: *mut (),
    generation: u16,
    min_payload: usize,
    fill: &mut dyn FnMut(&mut [u8]) -> Result<usize, ()>,
) -> Option<Result<usize, ()>> {
    let (core, slot) = decode_handle(handle)?;
    // SAFETY: per-core ownership; the worker that registered
    // this backend is the one calling here.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return None;
    }
    if c.state != TcpState::Established {
        return None;
    }
    // TSO is only correct when the device will emit multiple
    // segments — gve hardware silently drops sub-MSS TSO frames
    // (the frame goes through `submit_tx_tso` and the device
    // never delivers it on the wire). The same gate as
    // `async_try_send_chain`'s `total > mss` check, but applied
    // to the pre-fill estimate so we don't run the encrypt
    // closure for a single-segment send. Caller falls back to
    // its scratch path on `None`.
    let mss = mss_for(c.local_ip);
    if min_payload <= mss {
        return None;
    }
    // RFC 5681 §4: the TSO fast path must respect the congestion /
    // receive window too. A TLS record is atomic — it cannot be
    // fragmented at this layer — so when the usable window cannot
    // admit the whole record, decline (`None`); the TLS layer then
    // falls back to the windowed `async_try_send_chain` path, which
    // can split the record's ciphertext across the open window.
    // `min_payload` is the record's exact wire size for the sole
    // caller (`tls::send_one_record`).
    if min_payload > c.usable_window() as usize {
        return None;
    }
    let dst_mac = mac_resolve::resolve(c.remote_ip)?;
    let mut handle = nic::acquire_tx_tso_buf()?;

    let payload_off = payload_offset(c.local_ip);
    let cap = handle.data_cap() as usize;
    let max_payload = cap.saturating_sub(payload_off);

    // Hand the post-header region of the slot to the closure.
    // The closure (typically the TLS encrypt-chain path) writes
    // ciphertext bytes here and returns the count, or `Err(())`
    // on a fatal failure (TLS seal error).
    let payload_len = {
        let region = &mut handle.data_mut()[payload_off..payload_off + max_payload];
        match fill(region) {
            Ok(n) => n,
            Err(()) => {
                // Slot returns to the pool via handle's Drop
                // without a virtio descriptor enqueue.
                return Some(Err(()));
            }
        }
    };
    if payload_len == 0 {
        // Nothing to send — slot returns to the pool via the
        // handle's Drop without a virtio descriptor enqueue.
        return Some(Ok(0));
    }
    if payload_len > max_payload {
        // Closure overran (shouldn't happen given the slice we
        // handed in had capacity = max_payload). Defensive.
        return None;
    }

    let frame_len = payload_off + payload_len;
    let frame = &mut handle.data_mut()[..frame_len];

    // Fill ETH + IP + TCP headers in the prefix region.
    // SAFETY: caller verified `c` is exclusively-owned by this
    // worker; the frame slice is a fresh mutable reborrow that
    // doesn't alias with anything else (the closure's earlier
    // payload-region borrow ended above).
    let meta = SegmentMeta {
        local_ip: c.local_ip,
        dst_ip: c.remote_ip,
        src_port: c.local_port,
        dst_port: c.remote_port,
        seq: c.snd_nxt,
        ack: c.rcv_nxt,
        flags: TCP_ACK | TCP_PSH,
        window: c.rx_free() as u16,
    };
    unsafe {
        fill_tcp_frame_headers(frame, &meta, dst_mac, payload_len);
    }
    // Zero the TCP checksum: NEEDS_CSUM tells the device to
    // compute it per emitted segment. Same convention as
    // `send_super_segment_from_cursor`.
    let tcp_off = match c.local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN,
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN,
    };
    frame[tcp_off + 16] = 0;
    frame[tcp_off + 17] = 0;

    let hdr_len = payload_off as u16;
    let csum_start = tcp_off as u16;

    // Advance `snd_nxt` and retain the sealed bytes for retransmit
    // BEFORE `submit_tx_tso` consumes the slot. The TX-pool slot is
    // the only place this ciphertext exists in addressable memory, so
    // RFC 6298 coverage means copying its payload into the retransmit
    // ring now — without this, a lost TSO segment would never be
    // retransmitted and a mixed TSO/chain response would desync the
    // ring. `snd_nxt` is advanced first so the retain's RTT anchor
    // records the post-send sequence number, matching the chain path.
    c.snd_nxt = c.snd_nxt.wrapping_add(payload_len as u32);
    {
        let payload = &handle.data_mut()[payload_off..payload_off + payload_len];
        c.rtx_on_data_sent_slice(payload);
    }
    nic::submit_tx_tso(handle, frame_len, hdr_len, csum_start, mss as u16);
    Some(Ok(payload_len))
}

/// Per-MSS fallback path — used when [`send_super_segment_from_cursor`]
/// can't acquire a TX-pool slot. Loops `send_segment_from_cursor`
/// over the cursor as the original (pre-TSO) path did.
fn send_per_mss_fallback(
    meta: &SegmentMeta,
    cursor: &mut iobuf::Cursor<'_>,
    payload_len: usize,
) {
    let mss = mss_for(meta.local_ip);
    let mut sent = 0usize;
    let mut chunk_meta = *meta;
    while sent < payload_len {
        let chunk = (payload_len - sent).min(mss);
        send_segment_from_cursor(&chunk_meta, cursor, chunk);
        chunk_meta.seq = chunk_meta.seq.wrapping_add(chunk as u32);
        sent += chunk;
    }
}

/// Build and ship a TCP segment whose payload is read from a chain
/// cursor. Used by the data-send hot path (`async_try_send_chain`).
fn send_segment_from_cursor(
    meta: &SegmentMeta,
    cursor: &mut iobuf::Cursor<'_>,
    payload_len: usize,
) {
    let dst_mac = match mac_resolve::resolve(meta.dst_ip) {
        Some(m) => m,
        None => return, // ARP/NDP miss; TCP retransmit will retry
    };

    let payload_off = payload_offset(meta.local_ip);
    let payload_len = payload_len.min(MSS_MAX);
    let frame_len = payload_off + payload_len;
    let tcp_off = match meta.local_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN,
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN,
    } as u16;

    build_and_send_frame(frame_len, tcp_off, |frame| unsafe {
        // Walk chain bytes straight into the payload slot. This is
        // the "one memcpy, no intermediate buffer" property the
        // IOBuf chain design exists for — and on the direct-fill
        // path the cursor reads into the driver's TX pool slot
        // without further memcpy.
        if payload_len > 0 {
            let dst =
                core::slice::from_raw_parts_mut(frame.as_mut_ptr().add(payload_off), payload_len);
            let n = cursor.read(dst);
            debug_assert_eq!(n, payload_len);
            let _ = n;
        }
        fill_tcp_frame_headers(frame, meta, dst_mac, payload_len);
    });
}

pub(crate) fn send_rst(
    local_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
) {
    crate::diag::COUNTERS.rst_sent.bump();
    send_segment(
        &SegmentMeta {
            local_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags: TCP_RST | TCP_ACK,
            window: 0,
        },
        &[],
    );
}

/// Async `TcpSendChain` try-send hook. Walks `chain` via cursor
/// and emits MSS-sized TCP segments, copying directly from chain
/// nodes into each segment's payload area — no user-space
/// scratch coalesce. Drains the sent prefix off the chain as bytes
/// hit the wire so `External` IOBufs (NIC RX descriptors etc.)
/// return to the driver pool as the response leaves the box.
///
/// RFC 5681 §4: the send is capped at the usable window
/// (`min(cwnd, rwnd)` minus the in-flight bytes). It returns the
/// byte count actually put on the wire — `< total` when the window
/// is the limit, `Ok(0)` when the window is fully closed — and
/// leaves the unsent remainder queued in `chain`. The reactor's
/// `TcpSendChain` future loops until the chain is empty, parking the
/// send waker on `Ok(0)`. `Err(TcpSendError::Closed)` on a dead conn
/// / stale `gen`.
pub fn async_try_send_chain(
    handle: *mut (),
    generation: u16,
    chain: &mut iobuf::IOBufChain,
) -> Result<usize, executor::reactor::TcpSendError> {
    use executor::reactor::TcpSendError;
    let (core, slot) = decode_handle(handle).ok_or(TcpSendError::Closed)?;
    let _send_guard = SendGuard::new(core);
    // SAFETY: per-core ownership; the worker that registered this
    // backend is the one polling its `TcpSendChain`.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    if c.generation != generation {
        return Err(TcpSendError::Closed);
    }
    if c.state != TcpState::Established {
        return Err(TcpSendError::Closed);
    }

    let total = chain.total_len();
    if total == 0 {
        return Ok(0);
    }
    // RFC 5681 §4: cap this send at the usable window — the bytes
    // `min(cwnd, rwnd)` admits beyond what is already in flight. The
    // unsent remainder stays queued in the caller's `chain` (held by
    // the `TcpSendChain` future). A fully-closed window returns
    // `Ok(0)`; the reactor parks the send waker and `tcp_receive`
    // re-wakes it when an ACK reopens the window.
    let sendable = total.min(c.usable_window() as usize);
    if sendable == 0 {
        // RFC 9293 §3.8.6.1: a zero advertised window blocks the send
        // and the window-update ACK that lifts it is not itself
        // retransmitted — so arm the persist timer to probe the shut
        // window. A window closed only by `cwnd` / in-flight bytes
        // needs no probe: that data carries its own RFC 6298 RTO.
        if c.snd_wnd == 0 && c.persist_deadline_ms == 0 {
            c.arm_persist(kernel_core::clock::now_ms());
        }
        return Ok(0);
    }

    let mss = mss_for(c.local_ip);
    let mut cursor = chain.cursor();
    // TSO fast path: when the driver advertises TSOv4, hand the
    // whole chain to the driver in a single super-segment. The
    // device does the per-MSS split host-side AND computes per-
    // segment TCP/IP checksums (NEEDS_CSUM), so we save a
    // checksum-compute pass per segment whenever there are 2+
    // segments. The size cap matches the big-pool slot capacity;
    // payloads larger than that fall back to the per-MSS loop
    // (rare for HTTPS — the TLS layer pre-chunks at
    // PLAINTEXT_CHUNK = 16 KiB).
    //
    // The `total > mss` gate keeps single-MSS sends out of the
    // TSO descriptor path. Two reasons:
    //   1. TSO on a single segment is a no-op for the host — it
    //      emits one wire frame regardless. The descriptor-build
    //      cost (TSO+SEG pair vs plain pkt_desc) is pure
    //      overhead.
    //   2. More importantly: it gives `/health` and other small
    //      probe responses a path that doesn't depend on the
    //      driver's TSO descriptor emission being correct. When
    //      we're debugging a new TSO backend (gve in particular,
    //      where serial-port output is gated on GCE) this is
    //      what makes a `/diag-gve` HTTP endpoint reachable on
    //      the same VM that's failing TSO sends for /diagnostics.
    let meta = SegmentMeta {
        local_ip: c.local_ip,
        dst_ip: c.remote_ip,
        src_port: c.local_port,
        dst_port: c.remote_port,
        seq: c.snd_nxt,
        ack: c.rcv_nxt,
        flags: TCP_ACK | TCP_PSH,
        window: c.rx_free() as u16,
    };
    if nic::tso_available()
        && sendable > mss
        && payload_offset(c.local_ip) + sendable <= TSO_FRAME_BUF_LEN
    {
        send_super_segment_from_cursor(&meta, &mut cursor, sendable);
        c.snd_nxt = c.snd_nxt.wrapping_add(sendable as u32);
    } else {
        let mut sent = 0usize;
        let mut chunk_meta = meta;
        while sent < sendable {
            let chunk = (sendable - sent).min(mss);
            send_segment_from_cursor(&chunk_meta, &mut cursor, chunk);
            chunk_meta.seq = chunk_meta.seq.wrapping_add(chunk as u32);
            c.snd_nxt = c.snd_nxt.wrapping_add(chunk as u32);
            sent += chunk;
        }
    }

    // Bytes are on the wire — release the cursor's borrow on the
    // chain. `Cursor` doesn't impl Drop (so clippy gripes about
    // `drop(cursor)`), but binding into `_` moves it and ends the
    // borrow at the same point.
    let _ = cursor;
    // RFC 6298: take ownership of the sent prefix into the
    // retransmit queue. Each chain part is `IOBuf::share`'d into
    // refcounted storage and stored as its own `RtxEntry`; the
    // boundary part (when `sendable` doesn't align to an IOBuf
    // edge) is split via `clone_shared` so the queue and the
    // chain each carry their own view. After this call the
    // chain's front is the unsent tail — no follow-up
    // `chain_drain_prefix` is needed. Drops of fully-consumed
    // parts (no longer in chain or queue) fire front-to-back —
    // `External` callbacks recycle NIC descriptors as they leave.
    c.rtx_on_data_sent(chain, sendable);
    Ok(sendable)
}
