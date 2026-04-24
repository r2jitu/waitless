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

use from_bytes::FromBytes;
use types::{Ipv4Addr, CONFIG, tcp_checksum, htons, ntohs};
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

/// Send a UDP datagram.
pub fn send(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]) {
    let udp_len = 8 + data.len();
    if udp_len > 1480 {
        return;
    }

    let dst = Ipv4Addr::from(dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
    let mut buf = core::mem::MaybeUninit::<[u8; 1480]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;

    unsafe {
        let hdr = &mut *(p as *mut UdpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.length = htons(udp_len as u16);
        hdr.checksum = 0;

        core::ptr::copy_nonoverlapping(data.as_ptr(), p.add(8), data.len());

        hdr.checksum = tcp_checksum(CONFIG.ip(), dst, PROTO_UDP, p, udp_len);

        ipv4_send(dst, PROTO_UDP, core::slice::from_raw_parts(p, udp_len));
    }
}

/// Called by the network dispatch layer when protocol == UDP.
/// Delivers the datagram to the async reactor if a
/// `uni_runtime::net::UdpSocket` is bound to the destination port;
/// otherwise drops it.
pub fn udp_receive(src_ip: Ipv4Addr, _dst_ip: Ipv4Addr, data: &[u8]) {
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

    let _ = uni_runtime::net::deliver_udp(dst_port, src_ip.octets(), src_port, payload);
}
