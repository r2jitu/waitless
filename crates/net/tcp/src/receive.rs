// `tcp_receive` — the inbound segment entry point. Drives the state
// machine, dispatches ACKs into the retransmit ring, and either
// direct-copies payload bytes into a parked `TcpRecv`'s user buffer
// or hands the device buffer to a parked `recv_chunk` consumer.

use crate::pool::{
    alloc_connection, conn_ptr, free_connection, listener_find, next_seq, pool_capacity,
    tcp_hash_find, tcp_hash_insert, tcp_hash_key, tcp_linear_find,
};
use crate::send::{SegmentMeta, send_rst, send_segment, send_segment_opts};
use crate::state::{
    RX_RING_BYTES, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, TcpHeader, TcpState, mss_for, seq_lt,
};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use from_bytes::FromBytes;
use iobuf::{Chain, IOBuf, OwnedIOBuf};
use types::{IpAddr, ntohl, ntohs};

// ── RFC 5961 challenge-ACK rate limit (T5) ───────────────────────────
//
// A challenge ACK resyncs a confused peer and forces an off-path
// blind-injection attacker to guess our exact window. But each forged
// trigger (a SYN on a live 4-tuple §4, an out-of-window ACK §3.10.7.4)
// would otherwise elicit one, so a flood turns us into a reflector and
// burns CPU. RFC 5961 §7 caps the rate: a per-core token bucket
// (the RX path is per-core), `CHALLENGE_ACK_BURST` tokens refilled at
// `CHALLENGE_ACK_RATE`/sec. Relaxed atomics — single-writer per core.

const CHALLENGE_ACK_RATE: u32 = 100; // tokens per second
const CHALLENGE_ACK_BURST: u32 = 100; // bucket capacity

static CHALLENGE_TOKENS: [AtomicU32; obs::MAX_CORES] =
    [const { AtomicU32::new(CHALLENGE_ACK_BURST) }; obs::MAX_CORES];
static CHALLENGE_LAST_MS: [AtomicU64; obs::MAX_CORES] =
    [const { AtomicU64::new(0) }; obs::MAX_CORES];

/// Reset every per-core challenge-ACK bucket to full — test-only, so a
/// scenario that drained the bucket can't starve the next one (the
/// buckets are process-global statics the harness can't otherwise
/// clear). Mirrors `reset_pool` / `clock::mock::reset` in the harness.
#[cfg(test)]
pub(crate) fn reset_challenge_acks_for_test() {
    for i in 0..obs::MAX_CORES {
        CHALLENGE_TOKENS[i].store(CHALLENGE_ACK_BURST, Ordering::Relaxed);
        CHALLENGE_LAST_MS[i].store(0, Ordering::Relaxed);
    }
}

/// Consume one challenge-ACK token for `core`; `true` if one was
/// available (the challenge ACK may be sent). Refills lazily from the
/// monotonic ms clock on each call.
fn challenge_ack_allowed(core: u32) -> bool {
    let i = core as usize;
    if i >= obs::MAX_CORES {
        return true; // outside the bucket array — don't rate-limit
    }
    let now = kernel_core::clock::now_ms();
    let last = CHALLENGE_LAST_MS[i].load(Ordering::Relaxed);
    if now > last {
        // Refill proportional to elapsed time; only advance `last` once
        // at least one token's worth of time has passed so sub-10 ms
        // gaps still accumulate toward a token.
        let refill = (now - last).saturating_mul(CHALLENGE_ACK_RATE as u64) / 1000;
        if refill > 0 {
            let cur = CHALLENGE_TOKENS[i].load(Ordering::Relaxed);
            let next = (cur as u64 + refill).min(CHALLENGE_ACK_BURST as u64) as u32;
            CHALLENGE_TOKENS[i].store(next, Ordering::Relaxed);
            CHALLENGE_LAST_MS[i].store(now, Ordering::Relaxed);
        }
    }
    let cur = CHALLENGE_TOKENS[i].load(Ordering::Relaxed);
    if cur > 0 {
        CHALLENGE_TOKENS[i].store(cur - 1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// Send an RFC 5961 challenge ACK — a bare ACK announcing our real
/// `snd_nxt` / `rcv_nxt` — subject to the per-core rate limit. Used for
/// a SYN on a live Established 4-tuple (§4) and an out-of-window ACK
/// (§3.10.7.4). No-op (counted) when the rate limit is exhausted.
#[allow(clippy::too_many_arguments)]
fn send_challenge_ack(
    core: u32,
    local_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    snd_nxt: u32,
    rcv_nxt: u32,
    window: u16,
) {
    if !challenge_ack_allowed(core) {
        crate::diag::COUNTERS.challenge_ack_throttled.bump();
        return;
    }
    crate::diag::COUNTERS.challenge_ack_sent.bump();
    send_segment(
        &SegmentMeta {
            local_ip,
            dst_ip,
            src_port,
            dst_port,
            seq: snd_nxt,
            ack: rcv_nxt,
            flags: TCP_ACK,
            window,
        },
        &[],
    );
}

/// Drop-guard that wraps `tcp_receive` in a cycle-counter bracket.
/// Fires on every exit path (early returns included) so per-packet
/// cost is the true measurement, not the happy-path subset. Two
/// cycle-counter reads on construct/drop — negligible against the
/// segment body. `PerCoreCounter` is single-writer per core, so
/// `RX_CYCLES.add` / `RX_CALLS.add` are uncontended stores.
struct RxGuard {
    core: u32,
    start: u64,
}

impl RxGuard {
    #[inline]
    fn new(core: u32) -> Self {
        Self {
            core,
            start: kernel_core::clock::now_cycles(),
        }
    }
}

impl Drop for RxGuard {
    #[inline]
    fn drop(&mut self) {
        let elapsed = kernel_core::clock::now_cycles().wrapping_sub(self.start);
        crate::diag::RX_CYCLES.add(self.core, elapsed);
        crate::diag::RX_CALLS.add(self.core, 1);
    }
}

/// The SYN options this stack negotiates, collected in one walk of
/// the TCP options blob (`bytes [20, data_offset)` of the header).
/// Everything else (SACK-permitted, Timestamps, ...) is skipped by
/// its length byte.
#[derive(Default)]
struct SynOptions {
    /// RFC 7323 Window-Scale shift, capped at 14 per §2.3. `None`
    /// if absent or malformed.
    wscale: Option<u8>,
    /// RFC 9293 §3.7.1 Maximum Segment Size. `None` if absent or
    /// malformed — the caller then keeps our local default.
    ///
    /// We honor this (clamp our *send* segment size to it) so a peer
    /// on a small-MTU path — cellular / NAT64, where the effective
    /// MTU is the IPv6 minimum 1280 and the advertised MSS is ~1220
    /// — isn't sent 1460-byte segments the path silently drops.
    /// Without it a full TLS handshake (the certificate flight)
    /// stalls on 5G; tiny requests fit, so it only bites a cold
    /// connection that has to send the cert.
    mss: Option<u16>,
}

/// Single walk over a SYN's TCP options. First occurrence of each
/// negotiated option wins; an option with a wrong length is left
/// `None` (its bytes are still skipped so the *other* option can be
/// found after it); a length byte < 2 ends the walk (the blob is no
/// longer parseable).
fn parse_syn_options(opts: &[u8]) -> SynOptions {
    let mut out = SynOptions::default();
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break,  // End of Option List
            1 => i += 1, // No-Operation (1 byte, no length)
            kind => {
                let Some(&len) = opts.get(i + 1) else { break };
                let len = len as usize;
                if len < 2 {
                    break; // malformed (length must cover kind+len)
                }
                match (kind, len) {
                    // Maximum Segment Size: kind=2, len=4, 2-byte value.
                    (2, 4) => {
                        if let (Some(&hi), Some(&lo)) = (opts.get(i + 2), opts.get(i + 3)) {
                            out.mss.get_or_insert(u16::from_be_bytes([hi, lo]));
                        }
                    }
                    // Window Scale: kind=3, len=3, 1-byte shift count.
                    (3, 3) => {
                        if let Some(&s) = opts.get(i + 2) {
                            out.wscale.get_or_insert(s.min(14));
                        }
                    }
                    _ => {} // unknown option, or known kind with wrong len
                }
                i += len;
            }
        }
    }
    out
}

/// Process an incoming TCP packet. Called on the owning core (via flow hash).
/// `src_ip` and `dst_ip` are family-tagged so v4 and v6 connections
/// share the same TCB pool, hash table, and dispatch path.
///
/// `segment` is an owned `Chain<OwnedIOBuf>` covering exactly the TCP
/// segment — header + payload — with the eth/IP headers and any
/// ethernet trailing padding already narrowed off by the caller
/// (`net::net_receive_frame`, RX item D). It is a one-part chain
/// today; a hardware-coalesced super-segment (RX item I) would
/// arrive multi-part, so the payload walk below iterates every part.
///
/// The chain — and the device RX buffer(s) it owns — drops at
/// return; that drop reposts the buffer(s) to the NIC / pool.
/// Payload bytes are copied into the per-conn rx ring before then,
/// or — when a `recv_chunk` consumer is parked and the ring is
/// empty — the single-part device buffer is moved into
/// `pending_chunk` zero-copy.
pub fn tcp_receive(src_ip: IpAddr, dst_ip: IpAddr, mut segment: Chain<OwnedIOBuf>) {
    // Cost instrumentation: bracket every exit (early-return paths
    // included) with a cycle-counter delta. Placed first so we
    // attribute the full per-packet wall clock — including the
    // header-parse early returns the unmeasured version skipped.
    let _rx_guard = RxGuard::new(kernel_core::cpu_id());

    // The TCP header is contiguous in the first chain part: a frame's
    // L2/L3/L4 headers all land in the device's first RX buffer, and
    // the caller narrowed the chain to start exactly at the TCP header.
    let Some(first) = segment.iter().next() else {
        return;
    };
    let hdr = match TcpHeader::try_ref_from(first.data()) {
        Some(h) => h,
        None => return,
    };
    let src_port = ntohs(hdr.src_port);
    let dst_port = ntohs(hdr.dst_port);
    let seq = ntohl(hdr.seq);
    let ack = ntohl(hdr.ack);
    let flags = hdr.flags;
    let window = ntohs(hdr.window);
    let data_offset = ((hdr.data_offset >> 4) as usize) * 4;
    let payload_len = segment.total_len().saturating_sub(data_offset);

    // Parse the peer's Window-Scale (RFC 7323) and MSS (RFC 9293)
    // options from a SYN's TCP options (bytes [20, data_offset) of the
    // contiguous first part) — the last read of `first`, so its borrow
    // ends here before the segment is mutated/narrowed downstream.
    // `None` for non-SYN segments and SYNs without the option.
    let SynOptions {
        wscale: syn_wscale,
        mss: syn_mss,
    } = if flags & TCP_SYN != 0 && data_offset > 20 {
        first
            .data()
            .get(20..data_offset)
            .map(parse_syn_options)
            .unwrap_or_default()
    } else {
        SynOptions::default()
    };

    // Determine which core owns this packet.
    let core = kernel_core::cpu_id();

    // SAFETY for the closures below: per-core ownership — only this
    // core (== `core`) is touching POOLS[core][*].

    // RST handling.
    //
    // RFC 5961 §3.2: a blind off-path attacker with knowledge of the
    // 4-tuple could otherwise send `RST, seq=<anything>` to tear the
    // connection down. Only accept the reset if seq == rcv_nxt (the
    // strict in-sequence position). Any other seq is silently dropped.
    if flags & TCP_RST != 0 {
        let cap = pool_capacity(core);
        for i in 0..cap {
            let c = unsafe { &*conn_ptr(core, i) };
            if c.state != TcpState::Closed
                && c.state != TcpState::Listen
                && c.remote_ip == src_ip
                && c.local_port == dst_port
                && c.remote_port == src_port
            {
                // RFC 5961 §3.2: only an in-sequence RST tears the
                // connection down. Trace it either way — an
                // out-of-window RST is a blind off-path injection we
                // (correctly) dropped, and `LAST_RST.in_window`
                // distinguishes the two.
                let in_window = seq == c.rcv_nxt;
                let state = c.state;
                let rcv_nxt = c.rcv_nxt;
                crate::diag::record_rst(src_port, dst_port, seq, rcv_nxt, in_window, state);
                if in_window {
                    crate::diag::record_teardown(crate::diag::TeardownReason::PeerReset, state);
                    free_connection(core, i);
                }
                return;
            }
        }
        return;
    }

    // SYN — new connection from client
    if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
        crate::diag::COUNTERS.syn_rx.bump();
        // Single pool walk: find the `Listen` slot for `dst_port`,
        // and also spot any existing connection already on this
        // exact 4-tuple. A SYN on a live 4-tuple is the peer
        // (re)starting — a retransmitted SYN whose SYN-ACK was
        // lost, or a fresh connection on a reused ephemeral port.
        // Free that stale twin before allocating, so the pool
        // never holds two connections for one 4-tuple.
        //
        // Without this, a retransmitted SYN `alloc_connection`s a
        // fresh slot and orphans the previous `SynReceived`
        // connection. Nothing reclaims an orphaned `SynReceived`:
        // the stack has no RTO timer, and `alloc_connection`'s
        // pool-exhaustion reclaim scans only closing states. The
        // orphan would leak until its 4-tuple is reused — which is
        // exactly when this scan catches it.
        //
        // An `Established` match is left intact — a live
        // connection, not a stale duplicate.
        let mut listener_idx = listener_find(core, dst_port);
        // Stale-twin detection: a SYN on a live 4-tuple is the peer
        // restarting (retransmitted SYN whose SYN-ACK was lost, or a
        // fresh conn on a reused ephemeral port). The 4-tuple hash
        // already indexes any conn that completed the SYN-ACK insert
        // (line further below), so look there first — O(1) hash
        // probe vs an O(pool_size) scan.
        let key = tcp_hash_key(src_ip, src_port, dst_port);
        let hit = tcp_hash_find(core, key).filter(|&s| {
            let c = unsafe { &*conn_ptr(core, s) };
            c.remote_ip == src_ip && c.local_port == dst_port && c.remote_port == src_port
        });

        // RFC 5961 §4 (T4): a SYN on a live, synchronized 4-tuple must
        // NOT silently allocate a second TCB — that orphans the live
        // connection (nothing reclaims a synchronized orphan; there is
        // no RTO timer and `alloc_connection`'s reclaim scans only
        // closing states). A blind off-path attacker who guesses the
        // 4-tuple could otherwise wedge an established connection. Reply
        // with a (rate-limited) challenge ACK announcing our real
        // `rcv_nxt`; a legitimate peer that truly restarted answers the
        // ACK with an RST, the only thing that tears us down. Leave the
        // connection untouched and drop the SYN.
        if let Some(s) = hit {
            let c = unsafe { &*conn_ptr(core, s) };
            if c.state == TcpState::Established {
                let (snd_nxt, rcv_nxt, win) = (c.snd_nxt, c.rcv_nxt, c.rx_free() as u16);
                send_challenge_ack(core, dst_ip, src_ip, dst_port, src_port, snd_nxt, rcv_nxt, win);
                return;
            }
        }

        let stale_idx = hit.filter(|&s| {
            let c = unsafe { &*conn_ptr(core, s) };
            c.state != TcpState::Closed
                && c.state != TcpState::Listen
                && c.state != TcpState::Established
        });

        // Fall back to a pool scan when the listener wasn't registered
        // in the per-core listener map (>MAX_LISTENERS_PER_CORE
        // listening ports on this core). Stale-twin detection above
        // already used the hash, which is always populated.
        if listener_idx.is_none() {
            crate::diag::COUNTERS.syn_scan_calls.bump();
            let cap = pool_capacity(core);
            for i in 0..cap {
                let c = unsafe { &*conn_ptr(core, i) };
                if c.state == TcpState::Listen && c.local_port == dst_port {
                    listener_idx = Some(i);
                    break;
                }
            }
        }

        if listener_idx.is_none() {
            send_rst(dst_ip, src_ip, dst_port, src_port, 0, seq + 1);
            return;
        }

        // Drop the stale 4-tuple twin (if any) before allocating, so
        // the pool never holds two connections for one 4-tuple.
        if let Some(s) = stale_idx {
            free_connection(core, s);
        }

        // Allocate new connection on this core
        let slot = match alloc_connection(core) {
            Some(i) => i,
            None => {
                // No free slot and nothing reclaimable — the SYN is
                // dropped. Genuinely unexpected below the pool ceiling;
                // `record_pool_exhausted` snapshots the timestamp +
                // core + capacity into `LAST_POOL_EXHAUSTED` so a
                // post-mortem `/obs` shows *when* the cliff first hit
                // and on which core, not just "how many" via the bare
                // `pool_exhausted` counter.
                crate::diag::record_pool_exhausted(core);
                return;
            }
        };

        {
            let c = unsafe { &mut *conn_ptr(core, slot) };
            // Allocate the per-conn RX ring on first use (preserved
            // across reuse; see `free_connection`). OOM here refuses
            // the connection rather than proceeding with a missing
            // ring that would silently drop every payload byte.
            if !c.ensure_rx_ring() {
                let state = c.state;
                send_rst(dst_ip, src_ip, dst_port, src_port, 0, seq + 1);
                crate::diag::record_teardown(crate::diag::TeardownReason::RxRingOom, state);
                free_connection(core, slot);
                return;
            }
            c.state = TcpState::SynReceived;
            c.remote_ip = src_ip;
            c.local_ip = dst_ip;
            c.local_port = dst_port;
            c.remote_port = src_port;
            let isn = next_seq();
            c.snd_nxt = isn;
            c.snd_una = c.snd_nxt;
            // RFC 9293: seed the peer's advertised window from the
            // SYN. SND.WL1 = the SYN's seq; SND.WL2 = 0 (a bare SYN
            // carries no ACK) — the 3-way ACK then advances both.
            // RFC 7323 §2.2: the SYN's window is NOT scaled, so seed it
            // raw; scaling kicks in for post-handshake updates above.
            c.snd_wnd = window as u32;
            c.snd_wl1 = seq;
            c.snd_wl2 = 0;
            // RFC 7323 window-scale negotiation: enable scaling only if
            // the peer offered it (its SYN carried a WS option). We
            // advertise `rcv_wscale = 0` (our 16 KiB RX ring needs no
            // scaling), but echoing a WS option in the SYN-ACK is what
            // unlocks the peer's scaling — letting `snd_wnd` exceed
            // 64 KiB and a high-RTT download run at full speed.
            c.wscale_ok = syn_wscale.is_some();
            c.snd_wscale = syn_wscale.unwrap_or(0);
            // RFC 9293 §3.7.1: honor the peer's advertised MSS. Clamp our
            // send segment size to min(our MSS, peer's) so a peer on a
            // small-MTU path (cellular / NAT64, ~1220) isn't sent
            // 1460-byte segments the path drops — the full-TLS-handshake-
            // stalls-on-5G bug. Floor at 536 (the universal IPv4 minimum)
            // so a malformed/hostile tiny MSS can't force pathological
            // segmentation. Absent option → keep our local default.
            let local_mss = mss_for(c.local_ip) as u16;
            c.snd_mss = match syn_mss {
                Some(peer) => local_mss.min(peer).max(536),
                None => local_mss,
            };
            c.rcv_nxt = seq + 1;
            c.listener_port = dst_port;
            c.accepted = false;
            // RFC 5681 §3.1: open the congestion window at the
            // initial window (3·SMSS) now that `local_ip` — and thus
            // the segment size — is known.
            c.congestion_init();

            // Ring cursors — reset on every SYN so a slot reused from
            // the free list starts empty.
            c.rx_head = 0;
            c.rx_tail = 0;
            c.rx_used = 0;
            c.chunk_wanted = false;
            c.pending_chunk = None;
        }

        // Publish this 4-tuple to the per-core hash index so the
        // subsequent ACK + data segments land in `tcp_hash_find`
        // with one probe instead of a 128-slot linear scan.
        let key = tcp_hash_key(src_ip, src_port, dst_port);
        tcp_hash_insert(core, key, slot);

        // Send SYN+ACK
        {
            let c = unsafe { &*conn_ptr(core, slot) };
            let meta = SegmentMeta {
                local_ip: dst_ip,
                dst_ip: src_ip,
                src_port: dst_port,
                dst_port: src_port,
                seq: c.snd_nxt,
                ack: c.rcv_nxt,
                flags: TCP_SYN | TCP_ACK,
                window: RX_RING_BYTES as u16,
            };
            // SYN-ACK options. We always advertise our own MSS
            // (RFC 9293 §3.7.1) — it tells the peer the largest segment
            // *we* can receive, so the peer sizes its uploads to us. A
            // peer that gets no MSS option must assume the 536 (IPv4) /
            // 1220 (IPv6) default and would send us needlessly small
            // segments; this is the upload-side complement of honoring
            // the peer's MSS (which sizes our downloads — see
            // `parse_syn_options`). We advertise our local receive MSS;
            // a small-MTU path's MSS-clamping middlebox rewrites it down
            // in flight, exactly as it does the peer's.
            //
            // RFC 7323 §2.3: additionally echo a Window-Scale option
            // only when the peer's SYN carried one. We advertise
            // `rcv_wscale = 0` (our 16 KiB RX ring never needs a scale
            // factor), but emitting it authorises the peer to scale the
            // window *it* advertises, lifting `snd_wnd` past 64 KiB so a
            // high-RTT download isn't capped at 64 KiB/RTT.
            let [mss_hi, mss_lo] = (mss_for(c.local_ip) as u16).to_be_bytes();
            if c.wscale_ok {
                // MSS(kind 2,len 4) + NOP(pad) + WS(kind 3,len 3) = 8 B
                // (two 32-bit option words).
                send_segment_opts(&meta, &[], &[2, 4, mss_hi, mss_lo, 1, 3, 3, 0]);
            } else {
                // MSS only — 4 bytes (one option word).
                send_segment_opts(&meta, &[], &[2, 4, mss_hi, mss_lo]);
            }
            crate::diag::COUNTERS.synack_tx.bump();
        }
        unsafe {
            let cp = conn_ptr(core, slot);
            (*cp).snd_nxt = (*cp).snd_nxt.wrapping_add(1);
        }
        return;
    }

    // O(1) hash lookup by 4-tuple (replaces an O(128) linear scan
    // that used to dominate cost on the RX hot path under
    // wrk-c128 load). Also verify state — the linear scan used to
    // filter out Closed/Listen implicitly; with the hash we must
    // guard against stale entries left behind if any transition to
    // Closed took a path that skipped `free_connection`.
    //
    // On a hash miss, fall back to a linear pool scan: the hash is
    // a fixed 256 entries and overflows once the pool grows past
    // that, at which point `tcp_hash_insert` silently drops entries
    // (see `tcp_linear_find`). The fallback keeps an overflowed
    // connection correct — found, just slower — instead of dropping
    // every one of its segments.
    let key = tcp_hash_key(src_ip, src_port, dst_port);
    let slot = match tcp_hash_find(core, key) {
        Some(s) => s,
        None => match tcp_linear_find(core, src_ip, src_port, dst_port) {
            Some(s) => s,
            None => return,
        },
    };
    {
        let c = unsafe { &*conn_ptr(core, slot) };
        if c.state == TcpState::Closed || c.state == TcpState::Listen {
            return;
        }
    }

    let c = unsafe { &mut *conn_ptr(core, slot) };

    // State on entry, before this segment drives any transition —
    // the TimeWait retransmitted-FIN branch below needs to know the
    // connection was *already* in TimeWait (vs entering it this call).
    let prev_state = c.state;

    // Process ACK
    if flags & TCP_ACK != 0 {
        // RFC 9293 §3.10.7.4: an ACK above `SND.NXT` acknowledges data
        // we never sent. Answer with a bare ACK so the peer
        // resynchronizes to our real window, then drop the segment —
        // a forged or badly confused ACK must not be processed.
        if seq_lt(c.snd_nxt, ack) {
            // Trace the rejection — `LAST_ACK_UNSENT` retains the
            // RFC 9293 §3.10.7.4 acceptability inputs (`SEG.ACK` vs
            // `SND.NXT`) that tell a confused peer from an injection.
            crate::diag::record_ack_unsent(src_port, dst_port, ack, c.snd_una, c.snd_nxt, c.state);
            // RFC 5961 §7: an out-of-window ACK is a blind-injection
            // trigger as much as the SYN above — rate-limit the
            // challenge so a forged-ACK flood can't turn us into a
            // reflector or burn a core answering every packet.
            send_challenge_ack(
                core,
                dst_ip,
                src_ip,
                dst_port,
                src_port,
                c.snd_nxt,
                c.rcv_nxt,
                c.rx_free() as u16,
            );
            return;
        }
        // `snd_una` before this ACK advances it — `rtx_on_ack` needs
        // the delta to drop acknowledged bytes from the retransmit
        // ring (RFC 6298 §5.2 / §5.3).
        let old_una = c.snd_una;
        // RFC 9293 §3.10.7.4: an ACK may advance `SND.UNA` only when
        // `SND.UNA < SEG.ACK` (it is already `<= SND.NXT`, guarded
        // above). An ACK at or below `SND.UNA` is old or duplicate —
        // it must not drag `SND.UNA` backwards, though the segment is
        // still processed below for data and the dup-ACK signal.
        let ack_advances = seq_lt(c.snd_una, ack);
        // RFC 5681 §2: a duplicate ACK — a pure ACK that does not
        // advance `snd_una`, carries no data, has no SYN/FIN, and
        // arrives while data is in flight. Classified before the
        // state machine below mutates `snd_una`.
        let is_dup_ack = ack == c.snd_una
            && payload_len == 0
            && flags & (TCP_SYN | TCP_FIN) == 0
            && seq_lt(c.snd_una, c.snd_nxt);
        // RFC 9293 §3.10.7.4: refresh the peer's advertised window,
        // but only from a segment at least as recent as the one that
        // last set it. SND.WL1/SND.WL2 give window updates a total
        // order, so a reordered or retransmitted segment cannot
        // install a stale window.
        if seq_lt(c.snd_wl1, seq) || (c.snd_wl1 == seq && !seq_lt(ack, c.snd_wl2)) {
            // RFC 7323 §2.1: post-handshake, the advertised window is
            // scaled — `SND.WND = SEG.WND << Snd.Wind.Scale`. Without
            // this the peer's true (multi-MB) receive window stays
            // clamped at 64 KiB, throttling a high-RTT download.
            c.snd_wnd = if c.wscale_ok {
                (window as u32) << c.snd_wscale
            } else {
                window as u32
            };
            c.snd_wl1 = seq;
            c.snd_wl2 = ack;
        }
        if c.state == TcpState::SynReceived && ack_advances {
            c.state = TcpState::Established;
            crate::diag::COUNTERS.conns_established.bump();
            c.snd_una = ack;
            // Wake any async `TcpListener::accept` awaiting on this
            // port. Runs on the core that received the 3-way-ACK,
            // which is the same core that owns this conn slot, so
            // the reactor's per-worker waker fires the right task.
            let port = c.listener_port;
            // O(1) hand-off to the listener's accept ring — without
            // this, `accept_on_port_core` linear-scans the entire
            // per-core pool to find this slot (measured ~1257
            // iters/call at 10K conns on the kvm-iterate bench).
            crate::pool::accept_ring_push(core, port, slot as u16);
            executor::reactor::deliver_tcp_ready(port);
        } else if c.state == TcpState::LastAck && ack == c.snd_nxt {
            // The peer acknowledged our FIN — passive close complete.
            crate::diag::record_teardown(
                crate::diag::TeardownReason::PassiveClose,
                TcpState::LastAck,
            );
            // The `ack == snd_nxt` guard matters: a peer retransmitting
            // its own FIN (because it never saw our ACK of it) carries
            // an `ack` below `snd_nxt`, and must not free the slot
            // before our FIN is confirmed — the FIN timer keeps
            // retransmitting and re-acknowledging until it is.
            free_connection(core, slot);
            return;
        } else if c.state == TcpState::FinWait1 && ack == c.snd_nxt {
            // Peer ACK'd our FIN. Disarm the FIN-retransmit timer and
            // move to FinWait2 to await the peer's FIN. Without this
            // transition the slot stays in FinWait1 forever if the
            // peer doesn't piggyback its FIN with the ACK (Linux
            // clients on a half-closed conn frequently send the ACK
            // and the FIN as separate segments).
            c.state = TcpState::FinWait2;
            c.snd_una = ack;
            c.lifecycle_deadline_ms = 0;
            c.fin_retx_count = 0;
        } else if ack_advances {
            c.snd_una = ack;
        }
        // else: an old / duplicate ACK — `SND.UNA` stays put.
        // RFC 6298 §5.2 / §5.3: drop acknowledged bytes from the
        // retransmit ring and re-arm or stop the RTO timer. (The
        // `LastAck` branch above already `return`ed — the connection
        // is gone, so it is correctly skipped here.)
        c.rtx_on_ack(old_una);
        // RFC 5681 §3.2 fast retransmit / fast recovery: a duplicate
        // ACK advances the dup-ACK count (the third triggers an
        // immediate retransmit without waiting for the RTO); any ACK
        // of new data ends a dup-ACK run and the recovery episode.
        if is_dup_ack {
            c.on_dup_ack();
        } else if c.snd_una != old_una {
            c.on_new_data_ack();
        }
        // A reopened (non-zero) advertised window retires the
        // RFC 9293 §3.8.6.1 zero-window persist timer.
        if c.snd_wnd > 0 {
            c.persist_deadline_ms = 0;
            c.persist_backoff = 0;
        }
        // RFC 5681 §4: an ACK may have reopened the send window —
        // `snd_una` advanced (in-flight shrank), `cwnd` grew, or the
        // peer advertised more space. Wake a `TcpSendChain` parked on
        // a previously-closed window so it re-polls and drains more.
        if c.usable_window() > 0
            && let Some(w) = c.send_waker.take()
        {
            w.wake();
        }
    }

    // Process data
    if payload_len > 0
        && (c.state == TcpState::Established
            || c.state == TcpState::FinWait1
            || c.state == TcpState::FinWait2)
    {
        if seq == c.rcv_nxt {
            // A parked `recv_chunk` consumer wants the payload as an
            // owned IOBuf. When the ring is empty, *move* a single-
            // part segment's device buffer straight into
            // `pending_chunk` — zero copy, no `rx_ring` round-trip.
            // Multi-part chains (item I's coalesced super-segments)
            // and the ring-non-empty case fall through to the copy
            // path, which keeps stream order: `pending_chunk` is only
            // ever stashed when the ring is empty, so it holds the
            // *oldest* unread bytes and `do_recv_chunk` drains it
            // strictly first.
            //
            // `chunk_wanted` is false unless a `recv_chunk` future is
            // parked, so a conn with only `recv` consumers never
            // takes this branch — the copy path below is byte-
            // identical to the pre-item-F behaviour.
            let pushed = if c.chunk_wanted
                && c.pending_chunk.is_none()
                && c.rx_used == 0
                && segment.part_count() == 1
            {
                let mut part = segment.pop_front().expect("part_count() == 1");
                match part.narrow(data_offset, payload_len) {
                    Ok(()) => {
                        c.pending_chunk = Some(IOBuf::from(part));
                        c.chunk_wanted = false;
                        payload_len
                    }
                    // Unreachable for a single-part chain — the window
                    // always covers `[data_offset, +payload_len)`. On
                    // the impossible error drop the buffer and let the
                    // peer retransmit rather than desync `rcv_nxt`.
                    Err(_) => 0,
                }
            } else {
                // Walk the chain: skip the `data_offset`-byte TCP
                // header, then deliver each part's payload bytes
                // into the per-conn `rx_ring` via `deliver_payload`.
                // One part today — one `deliver_payload` call over
                // `data()[data_offset..]`; item I's coalesced
                // super-segments arrive multi-part. All synchronous
                // on this core, so the chain's device buffers are
                // still owned at return.
                let mut pushed = 0usize;
                let mut skip = data_offset;
                for part in segment.iter() {
                    let bytes = part.data();
                    if skip >= bytes.len() {
                        skip -= bytes.len();
                        continue;
                    }
                    pushed += c.deliver_payload(&bytes[skip..]);
                    skip = 0;
                }
                pushed
            };
            c.rcv_nxt = c.rcv_nxt.wrapping_add(pushed as u32);
            // T3: this in-order segment may have filled the gap before
            // one or more buffered out-of-order segments — pull every
            // now-contiguous segment into the ring, advancing `rcv_nxt`
            // further so the cumulative ACK below covers them all. The
            // clean in-order path (no buffered segments) skips this.
            let drained = if !c.ooo.is_empty() { c.drain_ooo() } else { 0 };
            c.rcv_wnd = c.rx_free() as u16;
            // Wake any `TcpRecvReady` parked on this conn. Same core
            // owns the waker and the rx ring, so no cross-core hop.
            if pushed + drained > 0
                && let Some(w) = c.recv_waker.take()
            {
                w.wake();
            }
            // Send an immediate ACK. The previous version of this code
            // deferred ACKs to piggyback on the next outbound data
            // segment (avoiding a stall on macOS's delayed-ACK
            // interaction with our own output), but that assumed the
            // app would always have outbound data to send right after
            // receiving input — true on keep-alive /health requests,
            // false on the TLS handshake path where the server has no
            // imminent response after receiving, say, the client's
            // Finished. Without an immediate ACK here the Linux peer
            // waits out its delayed-ACK timer (~40ms) before sending
            // its next handshake record, which capped GCP KVM's
            // `tls_handshake_max` at ~20 hs/s.
            //
            // The immediate ACK does double segment count on the pure
            // receive path (one ACK + one eventual data segment,
            // rather than one data segment carrying the ACK), which
            // on our existing benches costs ~2-3 % on
            // `health_max` / `health_tls_max` — well worth eating to
            // unbreak the handshake path. If the macOS delayed-ACK
            // regression from the old comment shows up again we'll
            // want a real timer-based ACK coalescer rather than
            // pinning this to "next data segment".
            send_segment(
                &SegmentMeta {
                    local_ip: dst_ip,
                    dst_ip: src_ip,
                    src_port: dst_port,
                    dst_port: src_port,
                    seq: c.snd_nxt,
                    ack: c.rcv_nxt,
                    flags: TCP_ACK,
                    window: c.rx_free() as u16,
                },
                &[],
            );
        } else if seq_lt(seq, c.rcv_nxt) {
            // Duplicate/retransmitted segment — send ACK immediately so the
            // sender knows we already have this data (fast retransmit signal).
            send_segment(
                &SegmentMeta {
                    local_ip: dst_ip,
                    dst_ip: src_ip,
                    src_port: dst_port,
                    dst_port: src_port,
                    seq: c.snd_nxt,
                    ack: c.rcv_nxt,
                    flags: TCP_ACK,
                    window: c.rx_free() as u16,
                },
                &[],
            );
        } else {
            // T3: a wholly-future segment (`seq > rcv_nxt`) — there is a
            // gap before it. Buffer it in the out-of-order reassembly
            // queue (bounded; dropped if over budget, the peer
            // retransmits) so a single lost segment no longer forces the
            // sender to RTO-retransmit the whole window. Gather the
            // payload into an owned buffer — the device IOBuf is
            // reclaimed when this call returns, long before the gap
            // fills. Send an immediate duplicate ACK either way
            // (RFC 5681 §4.2) to drive the sender's fast retransmit.
            let mut buf = alloc::vec::Vec::new();
            if buf.try_reserve_exact(payload_len).is_ok() {
                let mut skip = data_offset;
                for part in segment.iter() {
                    let bytes = part.data();
                    if skip >= bytes.len() {
                        skip -= bytes.len();
                        continue;
                    }
                    buf.extend_from_slice(&bytes[skip..]);
                    skip = 0;
                }
                if c.ooo.insert(c.rcv_nxt, seq, buf) {
                    crate::diag::COUNTERS.ooo_queued.bump();
                }
            }
            send_segment(
                &SegmentMeta {
                    local_ip: dst_ip,
                    dst_ip: src_ip,
                    src_port: dst_port,
                    dst_port: src_port,
                    seq: c.snd_nxt,
                    ack: c.rcv_nxt,
                    flags: TCP_ACK,
                    window: c.rx_free() as u16,
                },
                &[],
            );
        }
    }

    // Process FIN.
    //
    // A FIN is in-sequence iff its own seq number (seq + payload_len)
    // equals our current rcv_nxt. Anything else — including an
    // off-path FIN with a guessed seq or a delayed retransmission
    // whose FIN was already consumed — is ignored. Advancing rcv_nxt
    // unconditionally (as the previous version did) let any FIN-bit
    // segment close the connection and desync the receive stream.
    if flags & TCP_FIN != 0 && seq.wrapping_add(payload_len as u32) == c.rcv_nxt {
        c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
        send_segment(
            &SegmentMeta {
                local_ip: dst_ip,
                dst_ip: src_ip,
                src_port: dst_port,
                dst_port: src_port,
                seq: c.snd_nxt,
                ack: c.rcv_nxt,
                flags: TCP_ACK,
                window: c.rx_free() as u16,
            },
            &[],
        );

        match c.state {
            TcpState::Established | TcpState::SynReceived => {
                c.state = TcpState::CloseWait;
            }
            TcpState::FinWait1 | TcpState::FinWait2 => {
                // Peer FIN — enter TimeWait and hold the TCB for
                // 2×MSL (RFC 9293 §3.10.7.4) instead of freeing it
                // immediately. FinWait1 here is the simultaneous-close
                // case (the peer FIN'd before acknowledging our FIN);
                // the stack has no separate Closing state, so it
                // shortcuts straight to TimeWait. The lifecycle timer,
                // armed as a FIN-retransmit deadline in FinWait1, is
                // re-armed here as the 2×MSL drop deadline.
                c.state = TcpState::TimeWait;
                c.fin_retx_count = 0;
                c.arm_time_wait(kernel_core::clock::now_ms());
            }
            _ => {}
        }
        // Peer FIN is also a readable-state transition: a handler
        // parked on `recv` must wake so it observes the close via
        // `is_closed()` / `recv() == 0`. Only CloseWait carries a live
        // handler here (FinWait* / TimeWait are reached only after the
        // app already called `close()`), so fire the waker there.
        if c.state == TcpState::CloseWait
            && let Some(w) = c.recv_waker.take()
        {
            w.wake();
        }
    }

    // RFC 9293 §3.10.7.4: in TimeWait the only segment expected is a
    // retransmitted peer FIN (its ACK was lost). Re-acknowledge it and
    // restart the 2×MSL timer; the state never advances. The
    // in-sequence FIN handler above does not fire for the retransmit —
    // its sequence number sits one below `rcv_nxt` — so this is a
    // distinct branch, gated on the *entry* state so the segment that
    // first drove the connection into TimeWait is not double-handled.
    if prev_state == TcpState::TimeWait && flags & TCP_FIN != 0 {
        send_segment(
            &SegmentMeta {
                local_ip: dst_ip,
                dst_ip: src_ip,
                src_port: dst_port,
                dst_port: src_port,
                seq: c.snd_nxt,
                ack: c.rcv_nxt,
                flags: TCP_ACK,
                window: c.rx_free() as u16,
            },
            &[],
        );
        c.arm_time_wait(kernel_core::clock::now_ms());
    }

    // Streaming-RX liveness recovery (RFC 9293 §3.8.6.1 receiver side).
    //
    // A peer whose receive window we shrank to 0 stops sending and —
    // once its data is acknowledged — emits periodic zero-window
    // persist probes (bare ACKs, no payload). Those skip the
    // payload-bearing ACK/window path above, so without this they go
    // unanswered: the peer learns nothing and backs off exponentially
    // (observed: a 256 KiB upload over the `recv_chunk` path wedging
    // 16-conn TLS uploads to a full client timeout on GCP KVM).
    //
    // On any inbound segment for an Established conn:
    //   * re-advertise the window if the app has drained the ring back
    //     across the one-MSS SWS boundary (answers the probe directly);
    //   * if RX data is still buffered for a consumer (ring bytes or a
    //     stashed chunk) and a `recv_chunk`/`recv` waker is parked,
    //     re-fire it. A consumer whose data-arrival wake was missed
    //     (it parked just as the ring filled and no later segment
    //     re-woke it) is thus re-kicked by the peer's probe, bounding
    //     any stall to one persist interval instead of deadlocking.
    //     `recv_waker.take()` keeps this idempotent — the payload path
    //     above already consumed the waker for data-bearing segments,
    //     so this only fires for the bare-probe case.
    if c.state == TcpState::Established {
        c.maybe_send_window_update();
        if (c.rx_used() > 0 || c.pending_chunk.is_some())
            && let Some(w) = c.recv_waker.take()
        {
            w.wake();
        }
    }
}

