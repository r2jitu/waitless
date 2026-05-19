// net/udp.rs — UDP send/receive.
//
// Simple datagram protocol — no state machine, no connection
// tracking. The async reactor (`uni_runtime::net::UdpSocket`) is
// the only binder these days; the pre-async `bind(port, handler)`
// sync-callback registry is gone.

#![no_std]

extern crate net_checksum as checksum;
extern crate net_dst_mac as dst_mac;
extern crate net_ethernet as ethernet;
extern crate net_from_bytes as from_bytes;
extern crate net_ipv4 as ipv4;
extern crate net_ipv6 as ipv6;
extern crate net_ipv6_send as ipv6_send;
extern crate net_types as types;
extern crate nic;
extern crate uni_net_driver;
extern crate uni_runtime;

use from_bytes::FromBytes;
use types::{CONFIG, IpAddr, MacAddr, htons, ntohs};

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
// `send_with_l2_headroom` is the single primitive: caller hands a
// frame buffer with MAX_L2_HEADROOM = 62 B reserved at the front,
// payload at `frame[MAX_L2_HEADROOM..]`. Fills the L2/L3/L4
// headers in place and ships the contiguous frame to the driver —
// no payload memcpy, replacing the legacy chain of
// `send_to_addr → ipv4_send → ethernet_send` (3 wrap memcpys per
// byte).
//
// `send_to_addr` is the slice-shaped wrapper that pre-existing
// callers (UdpSocket::send_to, DHCP, ICMP-piggyback) still use.
// It does one memcpy of the payload into a stack frame and calls
// the headroom primitive — same total memcpy count as the
// legacy 3-stack-buf path, but consolidated into one site.
//
// Frame layout:
//   v4: [ETH 14][IPv4 20][UDP 8][payload ≤ 1472]  → ≤ 1514 B
//   v6: [ETH 14][IPv6 40][UDP 8][payload ≤ 1452]  → ≤ 1514 B

const ETH_HDR_LEN: usize = ethernet::HEADER_LEN; // 14
const IPV4_HDR_LEN: usize = ipv4::HEADER_LEN; // 20
const IPV6_HDR_LEN: usize = ipv6::HEADER_LEN; // 40
const UDP_HDR_LEN: usize = 8;

/// Total stack-buffer size used by `send_to_addr`. Sized so a v6
/// frame ([14 + 40 + 8 + 1452]) fits; v4 uses fewer header bytes
/// so its payload slot is larger.
const FRAME_BUF_LEN: usize =
    uni_runtime::net::MAX_L2_HEADROOM + (1500 - IPV6_HDR_LEN - UDP_HDR_LEN);
// = 62 + 1452 = 1514. Same total bound for both families.

/// Fill the ETH + IP + UDP headers of `frame` in place — the UDP
/// analogue of `net_tcp`'s `fill_tcp_frame_headers`. `eth_off` is
/// where the Ethernet header starts; the IP and UDP headers follow
/// contiguously, and the UDP payload must already sit past them.
/// The two send paths lay the frame out at different `eth_off`s.
/// Stamps the UDP pseudo-header partial sum and the IPv4 header
/// checksum in place.
unsafe fn fill_udp_frame_headers(
    frame: &mut [u8],
    eth_off: usize,
    dst: IpAddr,
    dst_mac: MacAddr,
    src_port: u16,
    dst_port: u16,
    udp_len: usize,
) {
    // For v6 the UDP source is the unspecified `::` — no SLAAC
    // global yet; peers accept it for short-lived response traffic.
    let (ip_hdr_len, ethertype, src) = match dst {
        IpAddr::V4(_) => (
            IPV4_HDR_LEN,
            ethernet::ETHERTYPE_IPV4,
            IpAddr::V4(CONFIG.ip()),
        ),
        IpAddr::V6(_) => (
            IPV6_HDR_LEN,
            ipv6::ETHERTYPE_IPV6,
            IpAddr::V6(types::Ipv6Addr::ANY),
        ),
    };
    let ip_off = eth_off + ETH_HDR_LEN;
    let udp_off = ip_off + ip_hdr_len;

    // ── UDP header ───────────────────────────────────────────────────
    // SAFETY: `frame` holds the whole frame from `eth_off` (caller
    // sized it); `UdpHeader` is `repr(C)` POD bytes.
    let udp_hdr = unsafe { &mut *(frame.as_mut_ptr().add(udp_off) as *mut UdpHeader) };
    udp_hdr.src_port = htons(src_port);
    udp_hdr.dst_port = htons(dst_port);
    udp_hdr.length = htons(udp_len as u16);
    // Stamp the pseudo-header partial sum at the UDP checksum
    // field; the driver finishes it — device CSUM offload, or a
    // software pass when the device never negotiated it.
    udp_hdr.checksum = checksum::l4_pseudo_partial(src, dst, types::proto::UDP, udp_len);

    // ── IP header (family-dispatched) ────────────────────────────────
    let ip_total = (ip_hdr_len + udp_len) as u16;
    let ip_slot = &mut frame[ip_off..ip_off + ip_hdr_len];
    match dst {
        IpAddr::V4(d) => {
            ipv4::fill_header(ip_slot, CONFIG.ip(), d, types::proto::UDP, ip_total);
        }
        IpAddr::V6(d) => {
            ipv6::fill_header(
                ip_slot,
                &types::Ipv6Addr::ANY,
                &d,
                types::proto::UDP,
                ipv6::DEFAULT_HOP_LIMIT,
                udp_len as u16,
            );
        }
    }

    // ── Ethernet header ──────────────────────────────────────────────
    ethernet::fill_header(
        &mut frame[eth_off..eth_off + ETH_HDR_LEN],
        dst_mac,
        ethernet::ethernet_our_mac(),
        ethertype,
    );
}

/// Zero-copy UDP send. Caller pre-supplies a frame buffer where
/// the first [`uni_runtime::net::MAX_L2_HEADROOM`] (= 62) bytes
/// are reserved for the L2/L3/L4 headers and the UDP payload
/// starts at `frame[MAX_L2_HEADROOM..]`. Fills the headers in
/// place and ships the contiguous frame to the driver — no
/// payload memcpy.
///
/// 62 covers v6 (14 + 40 + 8). For v4 destinations the actual
/// headers are 42 bytes; we write them into the trailing 42 bytes
/// of the reserve and ship from `frame[20..]` (skipping the 20
/// unused leading bytes). Caller doesn't need to know the family.
///
/// Used by the QUIC reactor (via `UdpSocket::send_to_with_l2_
/// headroom`) to skip the per-packet UDP-wrap memcpy. ARP/NDP
/// miss drops the packet — UDP is fire-and-forget; the application
/// layer (QUIC retransmits, DNS retries) handles loss.
pub fn send_with_l2_headroom(dst: IpAddr, src_port: u16, dst_port: u16, frame: &mut [u8]) {
    use uni_runtime::net::MAX_L2_HEADROOM;
    debug_assert!(frame.len() >= MAX_L2_HEADROOM);

    let payload_len = frame.len() - MAX_L2_HEADROOM;
    if payload_len == 0 || payload_len > 1500 - IPV4_HDR_LEN - UDP_HDR_LEN {
        return;
    }
    let udp_len = UDP_HDR_LEN + payload_len;

    let dst_mac = match dst_mac::resolve(dst) {
        Some(m) => m,
        None => return,
    };

    // The buffer reserves MAX_L2_HEADROOM (= 62, the v6 header size)
    // at the front. A v4 frame's headers are 20 B shorter, so they go
    // in the trailing bytes of the reserve and the frame ships from
    // `prefix_skip` — the leading 20 B go unused (no payload move,
    // unlike `send_via_tx_handle`).
    let ip_hdr_len = match dst {
        IpAddr::V4(_) => IPV4_HDR_LEN,
        IpAddr::V6(_) => IPV6_HDR_LEN,
    };
    let prefix_skip = MAX_L2_HEADROOM - (ETH_HDR_LEN + ip_hdr_len + UDP_HDR_LEN);

    // SAFETY: `frame` holds the headroom reserve plus the payload
    // (bounds-checked above), so the frame from `prefix_skip` on is
    // in-bounds.
    unsafe {
        fill_udp_frame_headers(
            frame,
            prefix_skip,
            dst,
            dst_mac,
            src_port,
            dst_port,
            udp_len,
        );
        let frame_slice =
            core::slice::from_raw_parts(frame.as_ptr().add(prefix_skip), frame.len() - prefix_skip);
        // The UDP checksum field holds the pseudo-header partial
        // sum; `send` hands the driver these offsets to finish it.
        // 6 = the checksum field's offset within the UDP header.
        let csum = nic::CsumOffload {
            start: (ETH_HDR_LEN + ip_hdr_len) as u16,
            offset: 6,
        };
        nic::send(frame_slice, csum);
    }
}

/// Submit a `TxBufHandle` (acquired via
/// [`uni_runtime::net::acquire_tx_buf`]) for transmission. Caller
/// has written the UDP payload at
/// `handle.data_mut()[MAX_L2_HEADROOM..frame_len]`; we fill the
/// L2/L3/L4 headers in the headroom in place and submit the slot
/// to the driver.
///
/// For v6 destinations the wire frame uses all 62 bytes of
/// headroom (14 ETH + 40 IPv6 + 8 UDP), so the layout is
/// already correct — fill headers, submit, ship.
///
/// For v4 destinations the wire frame needs only 42 bytes of
/// header (14 + 20 + 8). To put the L2 frame at the start of
/// the slot's data field (where the driver's submit_tx assumes
/// it lives), we'd need either a 2-descriptor SG submit or an
/// in-place memmove that shifts the payload back by 20 bytes.
/// We do the memmove — same memcpy cost as the legacy
/// slice-shaped path (which also memcpy'd the payload into a
/// pool slot at submit time), so v4 doesn't regress; only v6
/// gets the full B2 win.
///
/// Bypasses the `udp::send_to_addr → drivers::net::send` chain
/// for v6 callers that build their UDP payload (e.g. the QUIC
/// encoder) directly into a TX pool slot.
pub fn send_via_tx_handle(
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    mut handle: uni_net_driver::TxBufHandle,
    frame_len: usize,
) {
    use uni_runtime::net::MAX_L2_HEADROOM;
    debug_assert!(frame_len >= MAX_L2_HEADROOM);
    debug_assert!(frame_len <= handle.data_cap as usize);

    let payload_len = frame_len - MAX_L2_HEADROOM;
    if payload_len == 0 || payload_len > 1500 - IPV4_HDR_LEN - UDP_HDR_LEN {
        // Invalid input — drop. Handle's `Drop` returns the slot
        // to the pool unused.
        return;
    }
    let udp_len = UDP_HDR_LEN + payload_len;

    let dst_mac = match dst_mac::resolve(dst) {
        Some(m) => m,
        None => return, // ARP/NDP miss; fire-and-forget UDP drop.
    };

    let ip_hdr_len = match dst {
        IpAddr::V4(_) => IPV4_HDR_LEN,
        IpAddr::V6(_) => IPV6_HDR_LEN,
    };
    // Total bytes on wire (after any in-place memmove for v4).
    let on_wire_actual = ETH_HDR_LEN + ip_hdr_len + UDP_HDR_LEN + payload_len;
    let actual_headroom = ETH_HDR_LEN + ip_hdr_len + UDP_HDR_LEN;

    {
        let frame = handle.data_mut();
        // SAFETY: `frame` is `data_cap` bytes — >= the whole on-wire
        // frame (bounds-checked above), so all offset arithmetic
        // stays in-bounds.
        unsafe {
            // For v4: shift the payload back 20 B so the L2 frame
            // starts at slot.data[0], where `submit_tx` expects it.
            // Overlapping move — `ptr::copy`.
            if matches!(dst, IpAddr::V4(_)) {
                let p = frame.as_mut_ptr();
                core::ptr::copy(p.add(MAX_L2_HEADROOM), p.add(actual_headroom), payload_len);
            }
            // Frame starts at offset 0 (after any v4 shift).
            fill_udp_frame_headers(frame, 0, dst, dst_mac, src_port, dst_port, udp_len);
        }
    }

    // The L2 frame now starts at slot.data[0] for both families.
    // The UDP checksum field holds the pseudo-header partial sum;
    // `submit_tx` hands the driver these offsets to finish it.
    // 6 = the checksum field's offset within the UDP header.
    let _ = &mut handle;
    let csum = nic::CsumOffload {
        start: (ETH_HDR_LEN + ip_hdr_len) as u16,
        offset: 6,
    };
    nic::submit_tx(handle, on_wire_actual, csum);
}

/// Slice-shaped UDP send. Copies `data` into a stack-local
/// framing buffer with the headers' reserved headroom, then
/// delegates to [`send_with_l2_headroom`] for the in-place
/// header fill + driver hand-off. One payload memcpy total —
/// the legacy `udp::send_to_addr → ipv4_send → ethernet_send`
/// chain made three.
///
/// Used by `UdpSocket::send_to`, by the receive-path reply paths
/// in protocols that piggyback UDP (DNS, ICMP-port-unreachable),
/// and as the native-backend fallback for callers that opted
/// into `send_to_with_l2_headroom`.
pub fn send_to_addr(dst: IpAddr, src_port: u16, dst_port: u16, data: &[u8]) {
    use uni_runtime::net::MAX_L2_HEADROOM;
    if data.len() > 1500 - IPV4_HDR_LEN - UDP_HDR_LEN {
        return;
    }
    let mut buf = core::mem::MaybeUninit::<[u8; FRAME_BUF_LEN]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;
    unsafe {
        // Copy payload into the frame's payload slot. Headers
        // get filled in-place by `send_with_l2_headroom`.
        if !data.is_empty() {
            core::ptr::copy_nonoverlapping(data.as_ptr(), p.add(MAX_L2_HEADROOM), data.len());
        }
        let frame = core::slice::from_raw_parts_mut(p, MAX_L2_HEADROOM + data.len());
        send_with_l2_headroom(dst, src_port, dst_port, frame);
    }
}

/// Called by the network dispatch layer when protocol == UDP.
/// Delivers the datagram to the async reactor if a
/// `uni_runtime::net::UdpSocket` is bound to the destination port;
/// otherwise drops it.
///
/// `segment` is a borrow over driver-pool storage covering the full
/// UDP datagram (header + body). After header parse the body slice
/// is handed to `deliver_udp`, which copies it into the per-bind
/// inbox slot — synchronous w.r.t. this call, so the borrow is
/// released before we return.
pub fn udp_receive(src_ip: IpAddr, _dst_ip: IpAddr, segment: &[u8]) {
    let Some(hdr) = UdpHeader::try_ref_from(segment) else {
        return;
    };
    let dst_port = ntohs(hdr.dst_port);
    let src_port = ntohs(hdr.src_port);
    let udp_len = ntohs(hdr.length) as usize;
    if udp_len < 8 || udp_len > segment.len() {
        return;
    }
    let body = &segment[8..udp_len];
    let _ = uni_runtime::net::deliver_udp(dst_port, src_ip, src_port, body);
}
