// tools/hvf-runner/src/userspace_net/frame.rs — pure packet
// construction: Ethernet / IP / TCP / UDP frame builders + checksums.
//
// Split out of the former monolithic `userspace_net.rs`; see
// `mod.rs` for the module overview and the FFI SAFETY contract
// that every `unsafe { libc::* }` site relies on. This file does no
// I/O — it only writes bytes into caller-supplied buffers — so it
// needs nothing from std beyond what `super::*` brings in.

use super::*;

// ── Packet construction ─────────────────────────────────────────────────────

pub(super) fn build_grat_arp_frame(mac: &[u8; 6]) -> TxFrame {
    let mut f = TxFrame {
        data: [0u8; MAX_REPLY_FRAME],
        len: 0,
    };
    let b = &mut f.data;
    let mut o = VIRTIO_NET_HDR_SIZE; // virtio-net hdr (zeroed)
    b[o..o + 6].fill(0xff);
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
    b[o..o + 6].copy_from_slice(mac);
    o += 6;
    b[o..o + 4].copy_from_slice(&GW_IP);
    o += 4;
    f.len = o as u16;
    f
}

// Write a TCP frame into `buf`. Returns the total frame length.
// Header layout: [virtio_net_hdr 12B][Eth 14B][IP 20B][TCP 20B][payload]
// ---- Family-aware TCP reply builders ----------------------------------------
//
// These three functions previously existed as v4/v6 pairs (eight
// functions total). The IP-header section is the only genuinely
// family-specific part — the virtio-net-hdr, Ethernet header, and
// TCP header layouts are identical between families. So we
// factored the family branch into `IpAddrPair` (above) and have
// one function each for: write-full-frame, write-headers-around-
// pre-populated-payload, and the TxFrame wrapper.

/// The five TCP-header scalars (4-tuple ports + seq/ack/flags)
/// shared by every reply-frame builder in this module. Grouped to
/// keep `write_tcp_frame*` / `build_tcp_*` signatures tractable —
/// each used to pass these as five separate parameters.
#[derive(Clone, Copy)]
pub(super) struct TcpFrameSpec {
    pub(super) src_port: u16,
    pub(super) dst_port: u16,
    pub(super) seq: u32,
    pub(super) ack: u32,
    pub(super) flags: u8,
}

/// Write a complete TCP reply frame:
///   `[virtio_net_hdr 12 B][Eth 14 B][IP 20|40 B][TCP 20 B][payload]`
/// into `buf` starting at offset 0 and return the byte count
/// written. `addrs` selects v4 vs v6 layout + checksum form;
/// `dst_mac` is the guest MAC (we always use `GW_MAC` as source).
pub(super) fn write_tcp_frame(
    buf: &mut [u8],
    dst_mac: &[u8; 6],
    addrs: &IpAddrPair,
    spec: &TcpFrameSpec,
    payload: &[u8],
) -> usize {
    let tcp_len = 20 + payload.len();
    let total = VIRTIO_NET_HDR_SIZE + 14 + addrs.ip_hdr_len() + tcp_len;
    debug_assert!(total <= buf.len());

    // virtio-net header (12 zero bytes) + Ethernet header.
    buf[..VIRTIO_NET_HDR_SIZE].fill(0);
    let mut o = VIRTIO_NET_HDR_SIZE;
    buf[o..o + 6].copy_from_slice(dst_mac);
    o += 6;
    buf[o..o + 6].copy_from_slice(&GW_MAC);
    o += 6;
    buf[o..o + 2].copy_from_slice(&addrs.ethertype().to_be_bytes());
    o += 2;

    // IP header (family-specific layout + v4 csum).
    let ip_len = addrs.ip_hdr_len();
    addrs.write_ip_header(&mut buf[o..o + ip_len], tcp_len);
    o += ip_len;

    // TCP header + payload (identical layout across families).
    let ts = o;
    write_tcp_header(&mut buf[o..o + 20], spec);
    o += 20;
    buf[o..o + payload.len()].copy_from_slice(payload);

    // Family-correct pseudo-header checksum over [TCP-hdr || payload].
    let cksum = addrs.tcp_checksum(&buf[ts..ts + tcp_len]);
    buf[ts + 16..ts + 18].copy_from_slice(&cksum.to_be_bytes());
    total
}

/// Like `write_tcp_frame` but the payload is already at
/// `buf[hdr_total..hdr_total+payload_len]` (read(2) dropped it
/// straight into guest RAM). Only the prefix headers are written
/// here, then the TCP checksum is patched over header + payload.
/// Returns total frame length.
pub(super) fn write_tcp_frame_around_payload(
    buf: *mut u8,
    dst_mac: &[u8; 6],
    addrs: &IpAddrPair,
    spec: &TcpFrameSpec,
    payload_len: usize,
) -> usize {
    let tcp_len = 20 + payload_len;
    let hdr_total = VIRTIO_NET_HDR_SIZE + 14 + addrs.ip_hdr_len() + 20;
    let total = hdr_total + payload_len;
    // Write headers via a scoped slice over the prefix region only;
    // payload bytes live past it and were placed there by the
    // caller's read(2). SAFETY: caller guarantees `buf[..hdr_total
    // + payload_len]` is a valid mutable region in guest RAM.
    let prefix = unsafe { std::slice::from_raw_parts_mut(buf, hdr_total) };
    write_tcp_headers_only(prefix, dst_mac, addrs, spec, tcp_len);
    // Patch the TCP checksum over [TCP-hdr || payload].
    let tcp_start = VIRTIO_NET_HDR_SIZE + 14 + addrs.ip_hdr_len();
    let tcp_seg = unsafe { std::slice::from_raw_parts(buf.add(tcp_start), tcp_len) };
    let tc = addrs.tcp_checksum(tcp_seg);
    unsafe {
        *buf.add(tcp_start + 16) = (tc >> 8) as u8;
        *buf.add(tcp_start + 17) = (tc & 0xff) as u8;
    }
    total
}

/// Write the TCP-only header (20 B) at `buf[..20]`, leaving the
/// checksum field zeroed for the caller to patch once payload is
/// in place.
#[inline]
pub(super) fn write_tcp_header(buf: &mut [u8], spec: &TcpFrameSpec) {
    buf[0..2].copy_from_slice(&spec.src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&spec.dst_port.to_be_bytes());
    buf[4..8].copy_from_slice(&spec.seq.to_be_bytes());
    buf[8..12].copy_from_slice(&spec.ack.to_be_bytes());
    buf[12] = 0x50;
    buf[13] = spec.flags;
    buf[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
    buf[16..20].fill(0); // checksum + urgent ptr (csum patched by caller)
}

/// Write `[virtio_net_hdr | Eth | IP | TCP]` into `buf[..hdr_total]`,
/// with the TCP checksum left as zero. Caller patches the
/// checksum once the payload is in place.
pub(super) fn write_tcp_headers_only(
    buf: &mut [u8],
    dst_mac: &[u8; 6],
    addrs: &IpAddrPair,
    spec: &TcpFrameSpec,
    tcp_len: usize,
) {
    buf[..VIRTIO_NET_HDR_SIZE].fill(0);
    let mut o = VIRTIO_NET_HDR_SIZE;
    buf[o..o + 6].copy_from_slice(dst_mac);
    o += 6;
    buf[o..o + 6].copy_from_slice(&GW_MAC);
    o += 6;
    buf[o..o + 2].copy_from_slice(&addrs.ethertype().to_be_bytes());
    o += 2;
    let ip_len = addrs.ip_hdr_len();
    addrs.write_ip_header(&mut buf[o..o + ip_len], tcp_len);
    o += ip_len;
    write_tcp_header(&mut buf[o..o + 20], spec);
}

/// `TxFrame` wrapper: stack-only allocation, fills with
/// `write_tcp_frame` and returns the populated frame. Used by
/// `build_tcp_reply` to avoid heap churn on every reply.
pub(super) fn build_tcp_frame_fixed(
    dst_mac: &[u8; 6],
    addrs: &IpAddrPair,
    spec: &TcpFrameSpec,
    payload: &[u8],
) -> TxFrame {
    let mut f = TxFrame {
        data: [0u8; MAX_REPLY_FRAME],
        len: 0,
    };
    f.len = write_tcp_frame(&mut f.data, dst_mac, addrs, spec, payload) as u16;
    f
}

/// Family-aware reply-frame builder. Both `GW_*`/`VM_*` constants
/// and `GUEST_MAC` are runner-fixed, so the family alone fully
/// determines which addressing pair to use.
pub(super) fn build_tcp_reply(
    family: IpFamily,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> TxFrame {
    let addrs = match family {
        IpFamily::V4 => IpAddrPair::V4 {
            src: GW_IP,
            dst: VM_IP,
        },
        IpFamily::V6 => IpAddrPair::V6 {
            src: GW_IPV6,
            dst: VM_IPV6,
        },
    };
    let spec = TcpFrameSpec {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
    };
    build_tcp_frame_fixed(&GUEST_MAC, &addrs, &spec, payload)
}

/// Build a guest-bound UDP frame using the saved outbound-NAT
/// destination as the apparent source. Used by the outbound-UDP
/// reply drain to synthesise replies the guest's IP stack will
/// accept (matching the original destination 4-tuple).
pub(super) fn build_udp_frame_in(
    dst_mac: &[u8; 6],
    src_ip: [u8; 4],
    src_port: u16,
    guest_dst_port: u16,
    payload: &[u8],
) -> TxFrame {
    let mut f = TxFrame {
        data: [0u8; MAX_REPLY_FRAME],
        len: 0,
    };
    f.len = build_udp_frame_v4(
        &mut f.data,
        dst_mac,
        src_ip,
        VM_IP,
        src_port,
        guest_dst_port,
        payload,
    ) as u16;
    f
}

/// Build a UDP frame: [virtio_net_hdr 12B][Eth 14B][IP 20B][UDP 8B][payload].
/// Returns total frame length written into `buf`.
pub(super) fn build_udp_frame_v4(
    buf: &mut [u8],
    dst_mac: &[u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> usize {
    let udp_len = 8 + payload.len();
    let ip_total = 20 + udp_len;
    let total = VIRTIO_NET_HDR_SIZE + 14 + ip_total;
    debug_assert!(total <= buf.len());

    // Virtio-net header (12 zero bytes).
    buf[..VIRTIO_NET_HDR_SIZE].fill(0);
    let mut o = VIRTIO_NET_HDR_SIZE;

    // Ethernet header.
    buf[o..o + 6].copy_from_slice(dst_mac);
    o += 6;
    buf[o..o + 6].copy_from_slice(&GW_MAC);
    o += 6;
    buf[o..o + 2].copy_from_slice(&0x0800u16.to_be_bytes());
    o += 2;

    // IPv4 header.
    let is = o;
    buf[o] = 0x45;
    buf[o + 1] = 0;
    o += 2;
    buf[o..o + 2].copy_from_slice(&(ip_total as u16).to_be_bytes());
    o += 2;
    buf[o..o + 4].copy_from_slice(&[0, 0, 0x40, 0]);
    o += 4; // id=0, DF, frag=0
    buf[o] = 64;
    buf[o + 1] = 17;
    o += 2; // TTL=64, protocol=UDP
    buf[o..o + 2].fill(0);
    o += 2; // checksum placeholder
    buf[o..o + 4].copy_from_slice(&src_ip);
    o += 4;
    buf[o..o + 4].copy_from_slice(&dst_ip);
    o += 4;
    let cs = ipv4_checksum(&buf[is..is + 20]);
    buf[is + 10] = (cs >> 8) as u8;
    buf[is + 11] = (cs & 0xff) as u8;

    // UDP header.
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
    let uc = udp_checksum(&src_ip, &dst_ip, &buf[us..us + udp_len]);
    buf[us + 6] = (uc >> 8) as u8;
    buf[us + 7] = (uc & 0xff) as u8;

    total
}

pub(super) fn udp_checksum(si: &[u8; 4], di: &[u8; 4], seg: &[u8]) -> u16 {
    let mut s: u32 = 0;
    s += ((si[0] as u32) << 8) | si[1] as u32;
    s += ((si[2] as u32) << 8) | si[3] as u32;
    s += ((di[0] as u32) << 8) | di[1] as u32;
    s += ((di[2] as u32) << 8) | di[3] as u32;
    s += 17; // protocol = UDP
    s += seg.len() as u32;
    let mut i = 0;
    while i + 1 < seg.len() {
        s += ((seg[i] as u32) << 8) | seg[i + 1] as u32;
        i += 2;
    }
    if i < seg.len() {
        s += (seg[i] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    let r = !(s as u16);
    // UDP checksum of 0x0000 is transmitted as 0xFFFF (RFC 768).
    if r == 0 { 0xffff } else { r }
}

pub(super) fn ipv4_checksum(h: &[u8]) -> u16 {
    let mut s: u32 = 0;
    let mut i = 0;
    while i + 1 < h.len() {
        s += ((h[i] as u32) << 8) | h[i + 1] as u32;
        i += 2;
    }
    if i < h.len() {
        s += (h[i] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

pub(super) fn tcp_checksum(si: &[u8; 4], di: &[u8; 4], seg: &[u8]) -> u16 {
    let mut s: u32 = 0;
    s += ((si[0] as u32) << 8) | si[1] as u32;
    s += ((si[2] as u32) << 8) | si[3] as u32;
    s += ((di[0] as u32) << 8) | di[1] as u32;
    s += ((di[2] as u32) << 8) | di[3] as u32;
    s += 6;
    s += seg.len() as u32;
    let mut i = 0;
    while i + 1 < seg.len() {
        s += ((seg[i] as u32) << 8) | seg[i + 1] as u32;
        i += 2;
    }
    if i < seg.len() {
        s += (seg[i] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}
