// `tcp_receive` — the inbound segment entry point. Drives the state
// machine, dispatches ACKs into the retransmit ring, and either
// direct-copies payload bytes into a parked `TcpRecv`'s user buffer
// or hands the device buffer to a parked `recv_chunk` consumer.

use crate::pool::{
    TCP_SYN_RX, TCP_SYNACK_TX, alloc_connection, conn_ptr, free_connection, next_seq,
    pool_capacity, tcp_hash_find, tcp_hash_insert, tcp_hash_key, tcp_linear_find,
};
use crate::send::{send_rst, send_segment};
use crate::state::{
    RX_RING_BYTES, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, TcpHeader, TcpState, seq_lt,
};
use from_bytes::FromBytes;
use iobuf::{Chain, IOBuf, OwnedIOBuf};
use types::{IpAddr, ntohl, ntohs};

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
/// Payload bytes are copied out before then: into a parked
/// `TcpRecv`'s direct-copy slot, with the rest into the per-conn
/// ring. RX item D keeps the ring a `Box<[u8; 16384]>` — this commit
/// is plumbing, the copy count is unchanged, only the input is now
/// IOBuf-typed.
pub fn tcp_receive(src_ip: IpAddr, dst_ip: IpAddr, mut segment: Chain<OwnedIOBuf>) {
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
    let data_offset = ((hdr.data_offset >> 4) as usize) * 4;
    let payload_len = segment.total_len().saturating_sub(data_offset);

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
                if seq == c.rcv_nxt {
                    free_connection(core, i);
                }
                return;
            }
        }
        return;
    }

    // SYN — new connection from client
    if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
        TCP_SYN_RX.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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
        let mut listener_idx = None;
        let mut stale_idx = None;
        {
            let cap = pool_capacity(core);
            for i in 0..cap {
                let c = unsafe { &*conn_ptr(core, i) };
                if listener_idx.is_none() && c.state == TcpState::Listen && c.local_port == dst_port
                {
                    listener_idx = Some(i);
                } else if stale_idx.is_none()
                    && c.state != TcpState::Closed
                    && c.state != TcpState::Listen
                    && c.state != TcpState::Established
                    && c.remote_ip == src_ip
                    && c.local_port == dst_port
                    && c.remote_port == src_port
                {
                    stale_idx = Some(i);
                }
                if listener_idx.is_some() && stale_idx.is_some() {
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
            None => return,
        };

        {
            let c = unsafe { &mut *conn_ptr(core, slot) };
            // Allocate the per-conn RX ring on first use (preserved
            // across reuse; see `free_connection`). OOM here refuses
            // the connection rather than proceeding with a missing
            // ring that would silently drop every payload byte.
            if !c.ensure_rx_ring() {
                send_rst(dst_ip, src_ip, dst_port, src_port, 0, seq + 1);
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
            c.rcv_nxt = seq + 1;
            c.listener_port = dst_port;
            c.accepted = false;

            // Ring cursors — reset on every SYN so a slot reused from
            // the free list starts empty.
            c.rx_head = 0;
            c.rx_tail = 0;
            c.rx_used = 0;
            c.direct_bytes = 0;
            c.recv_buf_slot = None;
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
            send_segment(
                dst_ip,
                src_ip,
                dst_port,
                src_port,
                c.snd_nxt,
                c.rcv_nxt,
                TCP_SYN | TCP_ACK,
                RX_RING_BYTES as u16,
                &[],
            );
            TCP_SYNACK_TX.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
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

    // Process ACK
    if flags & TCP_ACK != 0 {
        // `snd_una` before this ACK advances it — `rtx_on_ack` needs
        // the delta to drop acknowledged bytes from the retransmit
        // ring (RFC 6298 §5.2 / §5.3).
        let old_una = c.snd_una;
        if c.state == TcpState::SynReceived {
            c.state = TcpState::Established;
            c.snd_una = ack;
            // Wake any async `TcpListener::accept` awaiting on this
            // port. Runs on the core that received the 3-way-ACK,
            // which is the same core that owns this conn slot, so
            // the reactor's per-worker waker fires the right task.
            let port = c.listener_port;
            executor::reactor::deliver_tcp_ready(port);
        } else if c.state == TcpState::LastAck {
            free_connection(core, slot);
            return;
        } else if c.state == TcpState::FinWait1 && ack == c.snd_nxt {
            // Peer ACK'd our FIN. Move to FinWait2 to await the peer's
            // FIN. Without this transition the slot stays in FinWait1
            // forever if the peer doesn't piggyback its FIN with the
            // ACK (Linux clients on a half-closed conn frequently send
            // the ACK and the FIN as separate segments).
            c.state = TcpState::FinWait2;
            c.snd_una = ack;
        } else {
            c.snd_una = ack;
        }
        // RFC 6298 §5.2 / §5.3: drop acknowledged bytes from the
        // retransmit ring and re-arm or stop the RTO timer. (The
        // `LastAck` branch above already `return`ed — the connection
        // is gone, so it is correctly skipped here.)
        c.rtx_on_ack(old_una);
    }

    // Process data
    if payload_len > 0
        && (c.state == TcpState::Established
            || c.state == TcpState::FinWait1
            || c.state == TcpState::FinWait2)
    {
        if seq == c.rcv_nxt {
            // A parked `recv_chunk` consumer wants the payload as an
            // owned IOBuf. When the ring is empty and no direct-copy
            // `recv` slot is registered, *move* a single-part
            // segment's device buffer straight into `pending_chunk`
            // — zero copy, no `rx_ring` round-trip. Multi-part chains
            // (item I's coalesced super-segments) and the ring-non-
            // empty case fall through to the copy path, which keeps
            // stream order: `pending_chunk` is only ever stashed when
            // the ring is empty, so it holds the *oldest* unread
            // bytes and `do_recv_chunk` drains it strictly first.
            //
            // `chunk_wanted` is false unless a `recv_chunk` future is
            // parked, so a conn with only `recv` consumers never
            // takes this branch — the copy path below is byte-
            // identical to the pre-item-F behaviour.
            let pushed = if c.chunk_wanted
                && c.pending_chunk.is_none()
                && c.rx_used == 0
                && c.recv_buf_slot.is_none()
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
                // header, then deliver each part's payload bytes.
                // `deliver_payload` direct-copies into a parked
                // `TcpRecv`'s user buf when one is registered
                // (consuming the slot on the first call), with the
                // rest into the per-conn ring. One part today — one
                // `deliver_payload` call over `data()[data_offset..]`;
                // item I's coalesced super-segments arrive multi-part.
                // All synchronous on this core, so the chain's device
                // buffers are still owned at return.
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
            c.rcv_wnd = c.rx_free() as u16;
            // Wake any `TcpRecvReady` parked on this conn. Same core
            // owns the waker and the rx ring, so no cross-core hop.
            if pushed > 0
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
                dst_ip,
                src_ip,
                dst_port,
                src_port,
                c.snd_nxt,
                c.rcv_nxt,
                TCP_ACK,
                c.rx_free() as u16,
                &[],
            );
        } else if seq_lt(seq, c.rcv_nxt) {
            // Duplicate/retransmitted segment — send ACK immediately so the
            // sender knows we already have this data (fast retransmit signal).
            send_segment(
                dst_ip,
                src_ip,
                dst_port,
                src_port,
                c.snd_nxt,
                c.rcv_nxt,
                TCP_ACK,
                c.rx_free() as u16,
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
            dst_ip,
            src_ip,
            dst_port,
            src_port,
            c.snd_nxt,
            c.rcv_nxt,
            TCP_ACK,
            c.rx_free() as u16,
            &[],
        );

        match c.state {
            TcpState::Established | TcpState::SynReceived => {
                c.state = TcpState::CloseWait;
            }
            TcpState::FinWait1 => {
                free_connection(core, slot);
            }
            TcpState::FinWait2 => {
                free_connection(core, slot);
            }
            _ => {}
        }
        // Peer FIN is also a readable-state transition: any pending
        // `recv_ready` must resolve so the handler can observe the
        // close via `is_closed()` / `recv() == 0`. `free_connection`
        // above already resets the whole conn (including `recv_waker`)
        // via `TcpConnection::new()`; in the CloseWait branch we still
        // hold the waker, so fire it here.
        if c.state == TcpState::CloseWait
            && let Some(w) = c.recv_waker.take()
        {
            w.wake();
        }
    }
}

