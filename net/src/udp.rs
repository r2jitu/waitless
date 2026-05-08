// net/udp.rs — UDP send/receive.
//
// Simple datagram protocol — no state machine, no connection
// tracking. The async reactor (`uni_runtime::net::UdpSocket`) is
// the only binder these days; the pre-async `bind(port, handler)`
// sync-callback registry is gone.

#![no_std]

extern crate uni_runtime;
extern crate uni_drivers;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate net_arp as arp;
extern crate net_ethernet as ethernet;
extern crate net_ipv4 as ipv4;
extern crate net_ipv6 as ipv6;
extern crate net_ipv6_send as ipv6_send;
extern crate net_ndp as ndp;

use from_bytes::FromBytes;
use types::{IpAddr, Ipv4Addr, MacAddr, CONFIG, tcp_checksum, tcp_checksum_v6, htons, ntohs};
use ipv4::PROTO_UDP;

#[repr(C, packed)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

// SAFETY: repr(C, packed), all fields u16.
unsafe impl FromBytes for UdpHeader {}

/// Backend send entrypoint registered with the runtime
/// `UdpBackend` vtable. Forwards to `send_to_addr`. Kept as a
/// thin wrapper so the runtime sees a stable function pointer
/// signature even if `send_to_addr` evolves.
pub fn send(dst_ip: IpAddr, src_port: u16, dst_port: u16, data: &[u8]) {
    send_to_addr(dst_ip, src_port, dst_port, data);
}

// ─── Unified UDP-frame builder ───────────────────────────────────────────────
//
// Mirror of the post-A TCP TX path: build the full Ethernet+IP+UDP
// +payload frame in one stack buffer and hand it directly to the
// driver. Replaces the legacy chain of
// `udp::send_to_addr → ipv4_send → ethernet_send`, which built a
// fresh stack buffer at each layer and `memcpy`'d the inner bytes
// forward (3 wrap memcpys per byte).
//
// Frame layout:
//   v4: [ETH 14][IPv4 20][UDP 8][payload ≤ 1472]  → ≤ 1514 B
//   v6: [ETH 14][IPv6 40][UDP 8][payload ≤ 1452]  → ≤ 1514 B

const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = ipv4::HEADER_LEN;       // 20
const IPV6_HDR_LEN: usize = ipv6::HEADER_LEN;       // 40
const UDP_HDR_LEN: usize = 8;
const FRAME_BUF_LEN: usize = ETH_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN + (1500 - IPV6_HDR_LEN - UDP_HDR_LEN);
// = 14 + 40 + 8 + 1452 = 1514. Same total bound for both families.

/// Compute the UDP-payload offset within a frame buffer for `dst_ip`'s family.
#[inline]
fn payload_offset(dst_ip: IpAddr) -> usize {
    match dst_ip {
        IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN,   // 42
        IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN,   // 62
    }
}

/// Resolve the destination MAC for `dst_ip`. Returns `None` (drop)
/// on ARP/NDP cache miss; UDP is fire-and-forget so retries fall to
/// the application layer (e.g. QUIC retransmits, DNS retries).
#[inline]
fn resolve_dst_mac(dst_ip: IpAddr) -> Option<MacAddr> {
    match dst_ip {
        IpAddr::V4(d) => {
            if CONFIG.ip() == Ipv4Addr::ANY {
                Some(MacAddr::BROADCAST)
            } else {
                arp::arp_resolve(d)
            }
        }
        IpAddr::V6(d) => {
            if d.is_multicast() {
                Some(d.multicast_mac())
            } else {
                ndp::ndp_resolve(&d)
            }
        }
    }
}

/// Family-aware UDP send. Builds [ETH][IP][UDP][payload] in one
/// stack buffer and hands it straight to the driver — no
/// per-layer wrap memcpys. Used by the async reactor's
/// `UdpSocket::send_to`, by QUIC's outbound packet flush, and by
/// the receive-path reply paths in protocols that piggyback UDP.
///
/// On ARP/NDP cache miss the packet is dropped silently. UDP is
/// fire-and-forget; QUIC handles loss via its own retransmit, DNS
/// retries at the resolver layer, etc. (The legacy `ipv6_send`
/// fast-path issued an active Neighbor Solicitation on miss; we
/// drop here for simplicity. Inbound traffic on the same flow
/// fills the cache via passive learning.)
pub fn send_to_addr(dst: IpAddr, src_port: u16, dst_port: u16, data: &[u8]) {
    let udp_len = UDP_HDR_LEN + data.len();
    if udp_len > 1500 - IPV4_HDR_LEN {
        // Conservative bound — the v6 case allows slightly less
        // because the v6 header is 20 B larger; clamp here so
        // either family fits in the FRAME_BUF_LEN buffer below.
        return;
    }

    let dst_mac = match resolve_dst_mac(dst) {
        Some(m) => m,
        None => return, // ARP/NDP miss; drop, app-layer retries
    };

    let payload_off = payload_offset(dst);
    let frame_len = payload_off + data.len();

    let mut buf = core::mem::MaybeUninit::<[u8; FRAME_BUF_LEN]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;

    unsafe {
        // 1. Copy payload into the frame's payload slot (one copy
        // total — the legacy path made three).
        if !data.is_empty() {
            core::ptr::copy_nonoverlapping(data.as_ptr(), p.add(payload_off), data.len());
        }

        // 2. UDP header at (eth + ip) offset.
        let udp_off = match dst {
            IpAddr::V4(_) => ETH_HDR_LEN + IPV4_HDR_LEN,
            IpAddr::V6(_) => ETH_HDR_LEN + IPV6_HDR_LEN,
        };
        let udp_hdr = &mut *(p.add(udp_off) as *mut UdpHeader);
        udp_hdr.src_port = htons(src_port);
        udp_hdr.dst_port = htons(dst_port);
        udp_hdr.length = htons(udp_len as u16);
        udp_hdr.checksum = 0;

        // 3. UDP checksum (over pseudo-header + UDP header + payload).
        // 4. IP header.
        let ip_total = (udp_off - ETH_HDR_LEN + udp_len) as u16;
        match dst {
            IpAddr::V4(d) => {
                udp_hdr.checksum = tcp_checksum(
                    CONFIG.ip(), d, PROTO_UDP, p.add(udp_off), udp_len,
                );
                ipv4::fill_header(
                    core::slice::from_raw_parts_mut(
                        p.add(ETH_HDR_LEN), IPV4_HDR_LEN,
                    ),
                    CONFIG.ip(), d, PROTO_UDP, ip_total,
                );
            }
            IpAddr::V6(d) => {
                // Source IPv6 is the unspecified `::` until the
                // SLAAC global lands; matches the previous
                // behaviour of this function.
                let src = types::Ipv6Addr::ANY;
                udp_hdr.checksum = tcp_checksum_v6(
                    &src, &d, ipv6::next_header::UDP, p.add(udp_off), udp_len,
                );
                ipv6::fill_header(
                    core::slice::from_raw_parts_mut(
                        p.add(ETH_HDR_LEN), IPV6_HDR_LEN,
                    ),
                    &src, &d, ipv6::next_header::UDP,
                    ipv6::DEFAULT_HOP_LIMIT,
                    udp_len as u16,
                );
            }
        }

        // 5. Ethernet header.
        let ethertype = match dst {
            IpAddr::V4(_) => ethernet::ETHERTYPE_IPV4,
            IpAddr::V6(_) => ipv6::ETHERTYPE_IPV6,
        };
        ethernet::fill_header(
            core::slice::from_raw_parts_mut(p, ETH_HDR_LEN),
            dst_mac,
            ethernet::ethernet_our_mac(),
            ethertype,
        );

        // 6. Hand frame to driver.
        let frame = core::slice::from_raw_parts(p, frame_len);
        uni_drivers::net::send(frame);
    }
}

/// Called by the network dispatch layer when protocol == UDP.
/// Delivers the datagram to the async reactor if a
/// `uni_runtime::net::UdpSocket` is bound to the destination port;
/// otherwise drops it.
///
/// The caller hands an owned `IOBuf` whose `data()` slice is the
/// UDP datagram (header at the front, then payload). After parsing
/// the header, this function `consume()`s 8 bytes off the front of
/// the IOBuf so its visible payload becomes just the body, and
/// forwards via `deliver_udp`. The IOBuf moves into the inbox slot
/// — no memcpy at the protocol-recv boundary on the IPv4 fast
/// path. (The IPv6 caller currently wraps a borrowed `&[u8]` slice
/// in a Heap IOBuf inline before calling here; that's a per-
/// packet alloc the IPv4 fast path avoids.)
pub fn udp_receive(src_ip: IpAddr, _dst_ip: IpAddr, mut iobuf: uni_iobuf::IOBuf) {
    let data = iobuf.data();
    let Some(hdr) = UdpHeader::try_ref_from(data) else { return };
    let dst_port = ntohs(hdr.dst_port);
    let src_port = ntohs(hdr.src_port);
    let udp_len = ntohs(hdr.length) as usize;
    if udp_len < 8 || udp_len > data.len() {
        return;
    }
    let body_len = udp_len - 8;
    // Narrow visible payload to just the UDP body — `narrow` runs
    // `consume(8)` then trims any trailing IP padding past the
    // body length. NLL ends the `data` / `hdr` borrow chain after
    // the integer extractions above so the mutable borrow is OK.
    if iobuf.narrow(8, body_len).is_err() {
        return;
    }
    let _ = uni_runtime::net::deliver_udp(dst_port, src_ip, src_port, iobuf);
}
