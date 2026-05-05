// net/udp.rs — UDP send/receive.
//
// Simple datagram protocol — no state machine, no connection
// tracking. The async reactor (`uni_runtime::net::UdpSocket`) is
// the only binder these days; the pre-async `bind(port, handler)`
// sync-callback registry is gone.

#![no_std]

extern crate uni_runtime;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate net_ipv4 as ipv4;
extern crate net_ipv6 as ipv6;
extern crate net_ipv6_send as ipv6_send;

use from_bytes::FromBytes;
use types::{IpAddr, CONFIG, tcp_checksum, tcp_checksum_v6, htons, ntohs};
use ipv4::{ipv4_send, PROTO_UDP};

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

/// Family-aware UDP send. Builds the datagram + pseudo-checksum
/// for the appropriate L3 family, then dispatches to `ipv4_send`
/// / `ipv6_send`. Used by the dual-stack reactor and by the
/// receive-path reply paths in TCP / UDP.
pub fn send_to_addr(dst: IpAddr, src_port: u16, dst_port: u16, data: &[u8]) {
    let udp_len = 8 + data.len();
    if udp_len > 1480 {
        return;
    }
    let mut buf = core::mem::MaybeUninit::<[u8; 1480]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;
    unsafe {
        let hdr = &mut *(p as *mut UdpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.length = htons(udp_len as u16);
        hdr.checksum = 0;
        core::ptr::copy_nonoverlapping(data.as_ptr(), p.add(8), data.len());

        match dst {
            IpAddr::V4(d) => {
                hdr.checksum = tcp_checksum(CONFIG.ip(), d, PROTO_UDP, p, udp_len);
                ipv4_send(d, PROTO_UDP, core::slice::from_raw_parts(p, udp_len));
            }
            IpAddr::V6(d) => {
                // Source IPv6 is filled in by the L3 send path's
                // checksum computation; we don't have a CONFIG-
                // tracked global v6 address yet, so use the
                // unspecified `::` source. Most peers accept this
                // for short-lived response-path traffic; once the
                // SLAAC global lands (Phase 5d follow-up), the
                // reactor's `send_to` will pass the right source.
                let src = types::Ipv6Addr::ANY;
                hdr.checksum = tcp_checksum_v6(&src, &d, ipv6::next_header::UDP, p, udp_len);
                ipv6_send::ipv6_send(
                    &src,
                    &d,
                    ipv6::next_header::UDP,
                    ipv6::DEFAULT_HOP_LIMIT,
                    core::slice::from_raw_parts(p, udp_len),
                );
            }
        }
    }
}

/// Called by the network dispatch layer when protocol == UDP.
/// Delivers the datagram to the async reactor if a
/// `uni_runtime::net::UdpSocket` is bound to the destination port;
/// otherwise drops it.
pub fn udp_receive(src_ip: IpAddr, _dst_ip: IpAddr, data: &[u8]) {
    let hdr = match UdpHeader::try_ref_from(data) {
        Some(h) => h,
        None => return,
    };
    let dst_port = ntohs(hdr.dst_port);
    let src_port = ntohs(hdr.src_port);
    let udp_len = ntohs(hdr.length) as usize;

    if udp_len < 8 || udp_len > data.len() {
        return;
    }
    let payload = &data[8..udp_len];

    let _ = uni_runtime::net::deliver_udp(dst_port, src_ip, src_port, payload);
}
