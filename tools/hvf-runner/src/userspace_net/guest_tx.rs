// tools/hvf-runner/src/userspace_net/guest_tx.rs — guest -> host
// packet path: ARP / IPv4 / IPv6 / TCP / UDP / DHCP frame handlers.
//
// Split out of the former monolithic `userspace_net.rs`; see
// `mod.rs` for the module overview and the FFI SAFETY contract
// that every `unsafe { libc::* }` site relies on.

use super::*;
use super::frame::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cumulative guest→host TCP bytes the best-effort non-blocking write
/// couldn't take (host send buffer full) and that were therefore lost —
/// the bytes had already been ACKed to the guest, which won't resend.
/// Bumped + logged-once at the drop site; should stay 0 with the 16 MiB
/// `SO_SNDBUF` for any transfer that fits the buffer.
static HOST_WRITE_DROPPED_BYTES: AtomicU64 = AtomicU64::new(0);

// ── Guest TX (vCPU thread) ──────────────────────────────────────────────────

pub(super) fn handle_guest_tx(frame: &[u8]) {
    if frame.len() < 14 {
        return;
    }
    let guest_mac: [u8; 6] = frame[6..12].try_into().unwrap_or([0; 6]);
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0806 => handle_arp(&frame[14..]),
        0x0800 => handle_ipv4(&frame[14..]),
        0x86dd => handle_ipv6(&frame[14..], guest_mac),
        _ => {}
    }
}

// ── IPv6: NDP responder + ICMPv6 echo bounce + L4 relay ────────
//
// Mirrors the v4 path: NS → NA, ICMPv6 Echo Request → Reply, and
// host-side AF_INET6 sockets bridged to the guest for both UDP
// (`handle_udp_v6`) and TCP (`handle_tcp` with `IpFamily::V6`).
// `bind_listen_v6` and `open_udp_sibling_v6` set up the listeners
// in `start()`; reply frames go through the v6 frame builders
// keyed off the conn's / relay's `family` tag.

pub(super) fn handle_ipv6(ip: &[u8], guest_mac: [u8; 6]) {
    if ip.len() < 40 {
        return;
    }
    let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    let next_header = ip[6];
    if 40 + payload_len > ip.len() {
        return;
    }
    let src_ip: [u8; 16] = ip[8..24].try_into().unwrap_or([0; 16]);
    let dst_ip: [u8; 16] = ip[24..40].try_into().unwrap_or([0; 16]);
    let payload = &ip[40..40 + payload_len];

    match next_header {
        58 => {
            if payload.is_empty() {
                return;
            }
            match payload[0] {
                128 => bounce_icmpv6_echo(src_ip, dst_ip, payload, guest_mac),
                135 => reply_neighbor_solicitation(src_ip, payload, guest_mac),
                _ => {}
            }
        }
        17 => handle_udp_v6(payload, src_ip, dst_ip),
        6 => handle_tcp(IpFamily::V6, payload),
        _ => {}
    }
}

// ── IPv6 UDP relay ─────────────────────────────────────────────
//
// Mirrors the v4 UDP path (`handle_udp_rx` worker-side, `handle_udp_v4`
// vCPU-side) for inbound + reply traffic over IPv6. The runner
// holds an AF_INET6 socket bound to `::1:host_port` per
// `-p udp:H:G` mapping; datagrams arriving there get translated
// into IPv6 UDP frames addressed to the VM's link-local; the VM's
// reply hits `handle_udp_v6`, which `sendto`s back to the
// remembered `sockaddr_in6`.

/// Build a UDP-over-IPv6 frame: virtio_net_hdr | Eth | IPv6 | UDP
/// | payload. Returns total bytes written into `buf`.
pub(super) fn build_udp_frame_v6(
    buf: &mut [u8],
    dst_mac: &[u8; 6],
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> usize {
    let udp_len = 8 + payload.len();
    let total = VIRTIO_NET_HDR_SIZE + 14 + 40 + udp_len;
    debug_assert!(total <= buf.len());
    buf[..VIRTIO_NET_HDR_SIZE].fill(0);
    let mut o = VIRTIO_NET_HDR_SIZE;
    buf[o..o + 6].copy_from_slice(dst_mac);
    o += 6;
    buf[o..o + 6].copy_from_slice(&GW_MAC);
    o += 6;
    buf[o..o + 2].copy_from_slice(&0x86ddu16.to_be_bytes());
    o += 2;
    // IPv6 header.
    buf[o..o + 4].copy_from_slice(&0x6000_0000u32.to_be_bytes());
    o += 4;
    buf[o..o + 2].copy_from_slice(&(udp_len as u16).to_be_bytes());
    o += 2;
    buf[o] = 17;
    o += 1; // next_header = UDP
    buf[o] = 64;
    o += 1; // hop limit
    buf[o..o + 16].copy_from_slice(src_ip);
    o += 16;
    buf[o..o + 16].copy_from_slice(dst_ip);
    o += 16;
    // UDP header + payload first (with checksum=0), then patch in
    // the pseudo-header checksum over header+payload.
    let us = o;
    buf[o..o + 2].copy_from_slice(&src_port.to_be_bytes());
    o += 2;
    buf[o..o + 2].copy_from_slice(&dst_port.to_be_bytes());
    o += 2;
    buf[o..o + 2].copy_from_slice(&(udp_len as u16).to_be_bytes());
    o += 2;
    buf[o..o + 2].fill(0);
    o += 2; // checksum placeholder
    buf[o..o + payload.len()].copy_from_slice(payload);
    let cksum = ipv6_pseudo_checksum(src_ip, dst_ip, 17, &buf[us..us + udp_len]);
    buf[us + 6..us + 8].copy_from_slice(&cksum.to_be_bytes());
    total
}

/// VM IPv6 link-local — derived from `GUEST_MAC` via modified
/// EUI-64 (mirrors what the unikernel computes at boot).
pub(super) const VM_IPV6: [u8; 16] = [
    0xfe,
    0x80,
    0,
    0,
    0,
    0,
    0,
    0,
    GUEST_MAC[0] ^ 0x02,
    GUEST_MAC[1],
    GUEST_MAC[2],
    0xff,
    0xfe,
    GUEST_MAC[3],
    GUEST_MAC[4],
    GUEST_MAC[5],
];

// Worker-side IPv6 UDP RX. Reads from the AF_INET6 sibling fd,
// records the `(guest_port, client_port) → sockaddr_in6` mapping
// in `udp_clients_v6`, and injects a UDP-over-IPv6 frame into
// the guest. Mirrors `handle_udp_rx` for v4.
// `handle_udp_rx_v6` removed — replaced by the listener thread's
// `listener_drain_v6` upstream.

/// vCPU-side handler for guest-TX UDP-over-IPv6 packets.
/// Distinguishes:
///   * Reply path: `src_port` matches a `UDP_RELAYS_V6` entry's
///     `guest_port` → look up the original `sockaddr_in6` in
///     `udp_clients_v6` and `sendto` back to the host.
///   * Outbound (guest-initiated): not supported yet — DHCP
///     equivalent for v6 is SLAAC, which doesn't go through the
///     runner; other outbound v6 patterns aren't a real use case
///     for us right now.
pub(super) fn handle_udp_v6(udp: &[u8], _src_ip: [u8; 16], _dst_ip: [u8; 16]) {
    if udp.len() < 8 {
        return;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let payload = &udp[8..];
    if payload.is_empty() {
        return;
    }

    let vcpu_id = CURRENT_VCPU.with(|c| c.get());
    let inbound = UDP_RELAYS_V6
        .get()
        .and_then(|table| table.iter().find(|r| r.guest_port == src_port));
    let relay = match inbound {
        Some(r) => r,
        None => return,
    };
    let fd = match relay.fds.get(vcpu_id).or_else(|| relay.fds.first()) {
        Some(&fd) => fd,
        None => return,
    };
    let client_addr = {
        let guard = my_worker_shared().udp_clients_v6.lock().unwrap();
        guard.get(&(src_port, dst_port)).copied()
    };
    if let Some(addr) = client_addr {
        unsafe {
            libc::sendto(
                fd,
                payload.as_ptr() as *const _,
                payload.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as u32,
            );
        }
    }
}

/// IPv6 pseudo-header checksum (RFC 8200 §8.1) over the upper-
/// layer payload (already includes any embedded checksum field
/// set to zero).
pub(super) fn ipv6_pseudo_checksum(src: &[u8; 16], dst: &[u8; 16], next_hdr: u8, payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src.chunks(2).chain(dst.chunks(2)) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let len = payload.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += next_hdr as u32;
    let mut i = 0;
    while i + 2 <= payload.len() {
        sum += u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
        i += 2;
    }
    if i < payload.len() {
        sum += (payload[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv6 packet header into `out` and return the total
/// frame length written (header + payload). Caller has already
/// reserved space for the Ethernet header at `out[..14]`.
pub(super) fn build_ipv6_frame(
    dst_mac: &[u8; 6],
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
    out: &mut [u8],
) -> usize {
    let total = VIRTIO_NET_HDR_SIZE + 14 + 40 + payload.len();
    if out.len() < total {
        return 0;
    }
    let mut o = VIRTIO_NET_HDR_SIZE;
    out[o..o + 6].copy_from_slice(dst_mac);
    o += 6;
    out[o..o + 6].copy_from_slice(&GW_MAC);
    o += 6;
    out[o..o + 2].copy_from_slice(&0x86ddu16.to_be_bytes());
    o += 2;
    // IPv6 fixed header.
    out[o..o + 4].copy_from_slice(&0x6000_0000u32.to_be_bytes());
    o += 4;
    out[o..o + 2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    o += 2;
    out[o] = next_header;
    o += 1;
    out[o] = hop_limit;
    o += 1;
    out[o..o + 16].copy_from_slice(src_ip);
    o += 16;
    out[o..o + 16].copy_from_slice(dst_ip);
    o += 16;
    out[o..o + payload.len()].copy_from_slice(payload);
    total
}

/// Reply to an inbound Neighbor Solicitation for our gateway
/// address. The VM's IPv6 stack drives this on bring-up to learn
/// the gateway MAC (mirrors how it ARP-resolves `GW_IP` for v4).
pub(super) fn reply_neighbor_solicitation(src_ip: [u8; 16], ns: &[u8], guest_mac: [u8; 6]) {
    if ns.len() < 24 {
        return;
    }
    let target: [u8; 16] = ns[8..24].try_into().unwrap_or([0; 16]);
    if target != GW_IPV6 {
        return;
    }
    // Build NA: type=136, code=0, cksum=0, flags(S|O), reserved[3], target[16],
    //           TLLA option (type=2, len=1, GW_MAC[6]).
    let mut na = [0u8; 32];
    na[0] = 136;
    na[1] = 0;
    na[4] = 0x60; // S=1, O=1 (no Router flag)
    na[8..24].copy_from_slice(&GW_IPV6);
    na[24] = 2;
    na[25] = 1;
    na[26..32].copy_from_slice(&GW_MAC);
    let cksum = ipv6_pseudo_checksum(&GW_IPV6, &src_ip, 58, &na);
    na[2..4].copy_from_slice(&cksum.to_be_bytes());

    let mut frame = [0u8; MAX_REPLY_FRAME];
    let n = build_ipv6_frame(&guest_mac, &GW_IPV6, &src_ip, 58, 255, &na, &mut frame);
    if n == 0 {
        return;
    }
    let mut f = TxFrame {
        data: [0u8; MAX_REPLY_FRAME],
        len: 0,
    };
    f.data[..n].copy_from_slice(&frame[..n]);
    f.len = n as u16;
    my_worker_shared().tx_replies.lock().unwrap().push_back(f);
}

/// Bounce ICMPv6 Echo Request → Echo Reply. Mirrors the standard
/// host-to-host ping6 behaviour but sourced from the runner's
/// gateway, so `ping6 fe80::aabb:ccff:fedd:eeff` from inside the
/// VM gets replies even when no real host is reachable.
pub(super) fn bounce_icmpv6_echo(src_ip: [u8; 16], dst_ip: [u8; 16], echo_req: &[u8], guest_mac: [u8; 6]) {
    if echo_req.len() < 8 {
        return;
    }
    let mut reply = vec![0u8; echo_req.len()];
    reply.copy_from_slice(echo_req);
    reply[0] = 129; // Echo Reply
    reply[1] = 0;
    reply[2] = 0;
    reply[3] = 0; // checksum placeholder
    let _ = dst_ip; // dst was us (or a multicast we joined); reply src = us.
    let cksum = ipv6_pseudo_checksum(&GW_IPV6, &src_ip, 58, &reply);
    reply[2..4].copy_from_slice(&cksum.to_be_bytes());

    let mut frame = [0u8; MAX_REPLY_FRAME];
    let n = build_ipv6_frame(&guest_mac, &GW_IPV6, &src_ip, 58, 64, &reply, &mut frame);
    if n == 0 {
        return;
    }
    let mut f = TxFrame {
        data: [0u8; MAX_REPLY_FRAME],
        len: 0,
    };
    f.data[..n].copy_from_slice(&frame[..n]);
    f.len = n as u16;
    my_worker_shared().tx_replies.lock().unwrap().push_back(f);
}

pub(super) fn handle_arp(arp: &[u8]) {
    if arp.len() < 28 {
        return;
    }
    if u16::from_be_bytes([arp[6], arp[7]]) != 1 {
        return;
    }
    if arp[24..28] != GW_IP {
        return;
    }
    let guest_mac: [u8; 6] = arp[8..14].try_into().unwrap_or([0; 6]);
    let mut f = TxFrame {
        data: [0u8; MAX_REPLY_FRAME],
        len: 0,
    };
    {
        let b = &mut f.data;
        let mut o = VIRTIO_NET_HDR_SIZE; // virtio-net hdr (zeroed)
        b[o..o + 6].copy_from_slice(&guest_mac);
        o += 6;
        b[o..o + 6].copy_from_slice(&GW_MAC);
        o += 6;
        b[o..o + 2].copy_from_slice(&0x0806u16.to_be_bytes());
        o += 2;
        b[o..o + 2].copy_from_slice(&1u16.to_be_bytes());
        o += 2;
        b[o..o + 2].copy_from_slice(&0x0800u16.to_be_bytes());
        o += 2;
        b[o] = 6;
        b[o + 1] = 4;
        o += 2;
        b[o..o + 2].copy_from_slice(&2u16.to_be_bytes());
        o += 2;
        b[o..o + 6].copy_from_slice(&GW_MAC);
        o += 6;
        b[o..o + 4].copy_from_slice(&GW_IP);
        o += 4;
        b[o..o + 6].copy_from_slice(&arp[8..14]);
        o += 6;
        b[o..o + 4].copy_from_slice(&arp[14..18]);
        o += 4;
        f.len = o as u16;
    }
    my_worker_shared().tx_replies.lock().unwrap().push_back(f);
}

pub(super) fn handle_ipv4(ip: &[u8]) {
    if ip.len() < 20 {
        return;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let src_ip: [u8; 4] = ip[12..16].try_into().unwrap_or([0; 4]);
    let dst_ip: [u8; 4] = ip[16..20].try_into().unwrap_or([0; 4]);
    match ip[9] {
        6 => handle_tcp(IpFamily::V4, &ip[ihl..]),
        17 => handle_udp_v4(&ip[ihl..], src_ip, dst_ip),
        _ => {}
    }
}

pub(super) fn handle_tcp(family: IpFamily, tcp: &[u8]) {
    if tcp.len() < 20 {
        return;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    let flags = tcp[13];
    let payload = if tcp.len() > data_offset {
        &tcp[data_offset..]
    } else {
        &[]
    };

    // The vCPU only processes conns that its paired worker accepted, so
    // the lookup is scoped to this worker's local `conns` map.
    let shared = my_worker_shared();

    // Snapshot connection state under brief lock — don't hold across write().
    struct TxSnap {
        fd: i32,
        port: u16,
        guest_port: u16,
        seq: u32,
        state: ConnState,
    }
    let snap = {
        let mut conns = shared.conns.lock().unwrap();
        if flags & 0x04 != 0 {
            if let Some(c) = conns.get_mut(&dst_port) {
                if c.host_fd >= 0 {
                    // RST the host-side socket too — set SO_LINGER
                    // {1,0} so close() emits RST instead of the
                    // default FIN-ACK dance, mirroring what the guest
                    // just sent. Without this the host TCP socket
                    // sits in ESTABLISHED until keepalive (minutes).
                    let linger = libc::linger {
                        l_onoff: 1,
                        l_linger: 0,
                    };
                    unsafe {
                        libc::setsockopt(
                            c.host_fd,
                            libc::SOL_SOCKET,
                            libc::SO_LINGER,
                            &linger as *const _ as *const _,
                            std::mem::size_of::<libc::linger>() as u32,
                        );
                        libc::close(c.host_fd);
                    }
                    c.host_fd = -1;
                }
                c.state = ConnState::Closed;
            }
            return;
        }
        let c = match conns.get_mut(&dst_port) {
            Some(c) => c,
            None => return,
        };
        let s = TxSnap {
            fd: c.host_fd,
            port: c.src_port,
            guest_port: c.guest_port,
            seq: c.my_seq,
            state: c.state,
        };
        // Update state eagerly (before dropping lock).
        match c.state {
            ConnState::SynSent => {
                if flags & 0x12 == 0x12 {
                    c.peer_ack = seq.wrapping_add(1);
                    c.state = ConnState::Established;
                }
            }
            ConnState::Established => {
                if !payload.is_empty() {
                    c.peer_ack = seq.wrapping_add(payload.len() as u32);
                }
                if flags & 0x01 != 0 {
                    c.peer_ack = c.peer_ack.wrapping_add(1);
                    c.my_seq = c.my_seq.wrapping_add(1);
                    c.state = ConnState::Closed;
                    unsafe {
                        libc::close(c.host_fd);
                    }
                    c.host_fd = -1;
                }
            }
            ConnState::FinWait => {
                // The proxy already sent its FIN (host EOF). The
                // guest's own FIN completes the four-way close — the
                // reply path (below) acknowledges it; move to Closed
                // so the conn is reaped. A bare ACK of our FIN (no
                // FIN bit) needs no state change.
                if flags & 0x01 != 0 {
                    c.peer_ack = seq
                        .wrapping_add(payload.len() as u32)
                        .wrapping_add(1);
                    c.state = ConnState::Closed;
                }
            }
            _ => {}
        }
        s
    }; // conns lock released

    // write() outside both conns and tx_replies locks — no contention.
    //
    // Best-effort non-blocking write. The payload was already ACKed to
    // the guest (peer_ack advanced under the lock), so anything a full
    // host send buffer can't take is *lost* — the guest won't resend.
    // The 16 MiB SO_SNDBUF set at accept makes that rare for any
    // realistic transfer; when it does happen, surface it LOUDLY (the
    // old `break` swallowed it, so it presented only as a flaky
    // downstream "connection error" on large single-conn transfers — a
    // toy-proxy limit, never seen on a real NIC). We deliberately do NOT
    // block-and-retry here: the ACK reply for this segment is queued
    // *after* this write, so stalling the write would delay the ACK and
    // wedge the guest against the proxy's fixed 64 KiB window. A fully
    // lossless guest→host path needs a POLLOUT-drained host-side buffer
    // (with the ACK still emitted promptly) — tracked, not done here;
    // use GCE for definitive large-transfer correctness.
    if snap.state == ConnState::Established && !payload.is_empty() {
        let mut written = 0usize;
        while written < payload.len() {
            let n = unsafe {
                libc::write(
                    snap.fd,
                    payload.as_ptr().add(written) as *const _,
                    payload.len() - written,
                )
            };
            if n <= 0 {
                break;
            }
            written += n as usize;
        }
        if written < payload.len() {
            let dropped = (payload.len() - written) as u64;
            let prev = HOST_WRITE_DROPPED_BYTES.fetch_add(dropped, Ordering::Relaxed);
            if prev == 0 {
                eprintln!(
                    "[hvf-net] WARNING: guest→host TCP write dropped {dropped} bytes \
                     (host send buffer full on port {}); a large single-connection \
                     transfer may truncate. Toy-proxy limit, not a guest bug.",
                    snap.port
                );
            }
        }
    }

    // Brief lock: push reply frames into this worker's tx_replies slice.
    let mut replies = shared.tx_replies.lock().unwrap();
    match snap.state {
        ConnState::SynSent => {
            if flags & 0x12 == 0x12 {
                let ack = seq.wrapping_add(1);
                let f =
                    build_tcp_reply(family, snap.port, snap.guest_port, snap.seq, ack, 0x10, &[]);
                replies.push_back(f);
            }
        }
        ConnState::Established => {
            if !payload.is_empty() {
                let ack = seq.wrapping_add(payload.len() as u32);
                let f = build_tcp_reply(family, snap.port, src_port, snap.seq, ack, 0x10, &[]);
                replies.push_back(f);
            }
            if flags & 0x01 != 0 {
                // ACK the guest's FIN *and* any data the same segment
                // carried. The server coalesces FIN onto the last data
                // segment for a small `Connection: close` response, so
                // the ack must cover `payload.len() + 1`. A `peer_ack`
                // snapshot taken before this segment would under-ack a
                // data+FIN by the payload length — leaving the guest in
                // FinWait waiting for an ack that never comes, so the
                // conn never frees (fresh-conn workloads then leaked
                // every connection → guest heap OOM under churn).
                let ack = seq.wrapping_add(payload.len() as u32).wrapping_add(1);
                let f = build_tcp_reply(family, snap.port, src_port, snap.seq, ack, 0x11, &[]);
                replies.push_back(f);
            }
        }
        ConnState::FinWait => {
            // The proxy has already sent its FIN (host EOF); reply to
            // the guest's FIN with a bare ACK so its LastAck close
            // completes. Without this the guest strands the
            // connection waiting for an acknowledgement that never
            // arrives.
            if flags & 0x01 != 0 {
                let ack = seq.wrapping_add(payload.len() as u32).wrapping_add(1);
                let f = build_tcp_reply(family, snap.port, src_port, snap.seq, ack, 0x10, &[]);
                replies.push_back(f);
            }
        }
        _ => {}
    }
}

pub(super) fn handle_udp_v4(udp: &[u8], _src_ip: [u8; 4], dst_ip: [u8; 4]) {
    if udp.len() < 8 {
        return;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    // DHCP: guest port 68 → server port 67.
    if src_port == 68 && dst_port == 67 {
        handle_dhcp(&udp[8..]);
        return;
    }
    let payload = &udp[8..];
    if payload.is_empty() {
        return;
    }

    // First try the inbound-relay reply path: the guest is replying
    // to a client whose datagram came in via one of our `-p udp:H:G`
    // mappings. Match by `src_port == guest_port` of a relay entry.
    let vcpu_id = CURRENT_VCPU.with(|c| c.get());
    let inbound = UDP_RELAYS
        .get()
        .and_then(|table| table.iter().find(|r| r.guest_port == src_port));
    if let Some(relay) = inbound {
        // Per-vCPU sibling fd; fall back to sibling 0 if the
        // vCPU id is out of range (shouldn't happen).
        let fd = match relay.fds.get(vcpu_id).or_else(|| relay.fds.first()) {
            Some(&fd) => fd,
            None => return,
        };
        let client_addr = {
            let guard = my_worker_shared().udp_clients.lock().unwrap();
            guard.get(&(src_port, dst_port)).copied()
        };
        if let Some(addr) = client_addr {
            unsafe {
                libc::sendto(
                    fd,
                    payload.as_ptr() as *const _,
                    payload.len(),
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                );
            }
        }
        return;
    }

    // Outbound: guest is initiating a UDP flow (gateway / sidecar
    // pattern). Forward to (host_loopback, dst_port) — the only
    // host-side reachable destination in HVF user-mode networking
    // is loopback; we map any guest-side dst_ip (typically the
    // virtual gateway 10.0.2.2) to 127.0.0.1. Open a fresh
    // unbound UDP socket per guest src_port, register it with this
    // vCPU's poll loop, and remember the original dst for the
    // synthesised reply frame.
    handle_udp_outbound(src_port, dst_ip, dst_port, payload);
}

/// Allocate (or reuse) an outbound NAT fd for the given guest
/// `src_port` on the current vCPU and forward `payload` to
/// `(127.0.0.1, dst_port)`. Records the original guest-side dst
/// (`dst_ip`, `dst_port`) so when the host's reply lands on the fd
/// we can rebuild a UDP frame that the guest will accept (`src_ip`
/// = original dst, `src_port` = original dst_port, `dst` = guest).
pub(super) fn handle_udp_outbound(guest_src_port: u16, dst_ip: [u8; 4], dst_port: u16, payload: &[u8]) {
    let vcpu_id = CURRENT_VCPU.with(|c| c.get());
    let vcpu_ios = match VCPU_IOS.get() {
        Some(v) => v,
        None => return,
    };
    let mut io = match vcpu_ios.get(vcpu_id) {
        Some(m) => m.lock().unwrap(),
        None => return,
    };
    let fd = match io.outbound_udp.get_mut(&guest_src_port) {
        Some(o) => {
            o.last_dst_ip = dst_ip;
            o.last_dst_port = dst_port;
            o.fd
        }
        None => unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if fd < 0 {
                return;
            }
            let flags = libc::fcntl(fd, libc::F_GETFL, 0);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            io.outbound_udp.insert(
                guest_src_port,
                OutboundUdp {
                    fd,
                    last_dst_ip: dst_ip,
                    last_dst_port: dst_port,
                },
            );
            fd
        },
    };
    // Forward to host loopback. The guest believes it's talking to
    // `dst_ip` (typically the gateway 10.0.2.2) but the only
    // host-reachable endpoint under user-mode networking is
    // 127.0.0.1; the synthesised reply will carry the original
    // `dst_ip` so the guest's stack accepts it.
    let host_addr = libc::sockaddr_in {
        #[cfg(target_os = "macos")]
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        #[cfg(target_os = "macos")]
        sin_family: libc::AF_INET as u8,
        #[cfg(target_os = "linux")]
        sin_family: libc::AF_INET as u16,
        sin_port: dst_port.to_be(),
        sin_addr: libc::in_addr {
            // 127.0.0.1 in network-byte-order memory; see the
            // matching `from_ne_bytes` rationale in
            // waitless-backend/native::udp_send.
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    unsafe {
        libc::sendto(
            fd,
            payload.as_ptr() as *const _,
            payload.len(),
            0,
            &host_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
    }
}

pub(super) fn handle_dhcp(bootp: &[u8]) {
    if bootp.len() < 240 {
        return;
    }
    let mut msg_type: u8 = 0;
    let mut i = 240;
    while i < bootp.len() {
        let opt = bootp[i];
        if opt == 255 {
            break;
        }
        if opt == 0 {
            i += 1;
            continue;
        }
        if i + 1 >= bootp.len() {
            break;
        }
        let len = bootp[i + 1] as usize;
        if i + 2 + len > bootp.len() {
            break;
        }
        if opt == 53 && len >= 1 {
            msg_type = bootp[i + 2];
        }
        i += 2 + len;
    }
    if msg_type != 1 && msg_type != 3 {
        return;
    }
    let reply_type: u8 = if msg_type == 1 { 2 } else { 5 };
    let guest_mac: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    // Build DHCP reply directly in a TxFrame (cold path, boot only).
    let mut f = TxFrame {
        data: [0u8; MAX_REPLY_FRAME],
        len: 0,
    };
    let b = &mut f.data;
    let mut o = VIRTIO_NET_HDR_SIZE; // skip virtio-net hdr (zeroed)
    b[o..o + 6].fill(0xff);
    o += 6;
    b[o..o + 6].copy_from_slice(&GW_MAC);
    o += 6;
    b[o..o + 2].copy_from_slice(&0x0800u16.to_be_bytes());
    o += 2;
    let ip_start = o;
    o += 20; // IP header (filled below)
    let udp_start = o;
    o += 8; // UDP header (filled below)
    let bp = o;
    o += 236; // BOOTP reply
    b[bp] = 2;
    b[bp + 1] = 1;
    b[bp + 2] = 6;
    b[bp + 4..bp + 8].copy_from_slice(&bootp[4..8]);
    b[bp + 16..bp + 20].copy_from_slice(&VM_IP);
    b[bp + 20..bp + 24].copy_from_slice(&GW_IP);
    b[bp + 28..bp + 34].copy_from_slice(&guest_mac);
    // DHCP options
    let opts: &[u8] = &[
        99, 130, 83, 99, 53, 1, reply_type, 54, 4, GW_IP[0], GW_IP[1], GW_IP[2], GW_IP[3], 51, 4,
        0, 1, 0x51, 0x80, 1, 4, 255, 255, 255, 0, 3, 4, GW_IP[0], GW_IP[1], GW_IP[2], GW_IP[3], 6,
        4, 10, 0, 2, 3, 255,
    ];
    b[o..o + opts.len()].copy_from_slice(opts);
    o += opts.len();
    // Fill UDP header
    let ul = (o - udp_start) as u16;
    b[udp_start..udp_start + 2].copy_from_slice(&67u16.to_be_bytes());
    b[udp_start + 2..udp_start + 4].copy_from_slice(&68u16.to_be_bytes());
    b[udp_start + 4..udp_start + 6].copy_from_slice(&ul.to_be_bytes());
    // Fill IP header
    let it = (o - ip_start) as u16;
    b[ip_start] = 0x45;
    b[ip_start + 2..ip_start + 4].copy_from_slice(&it.to_be_bytes());
    b[ip_start + 6] = 0x40;
    b[ip_start + 8] = 64;
    b[ip_start + 9] = 17;
    b[ip_start + 12..ip_start + 16].copy_from_slice(&GW_IP);
    b[ip_start + 16..ip_start + 20].copy_from_slice(&BROADCAST_IP);
    let cs = ipv4_checksum(&b[ip_start..ip_start + 20]);
    b[ip_start + 10..ip_start + 12].copy_from_slice(&cs.to_be_bytes());
    f.len = o as u16;
    my_worker_shared().tx_replies.lock().unwrap().push_back(f);
}

