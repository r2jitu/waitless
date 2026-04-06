// net/udp.rs — UDP send/receive.
//
// Simple datagram protocol — no state machine, no connection tracking.
// Port-based dispatch via registered handlers.

use types::{Ipv4Addr, CONFIG, tcp_checksum, htons, ntohs};
use crate::ipv4::{ipv4_send, PROTO_UDP};

#[repr(C, packed)]
pub(crate) struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

const MAX_HANDLERS: usize = 8;

struct PortHandler {
    port: u16,
    handler: fn([u8; 4], u16, &[u8]),
}

static mut HANDLERS: [Option<PortHandler>; MAX_HANDLERS] = [const { None }; MAX_HANDLERS];

/// Register a handler for incoming UDP packets on a specific port.
/// Callback receives (src_ip_octets, src_port, payload).
pub fn bind(port: u16, handler: fn([u8; 4], u16, &[u8])) {
    unsafe {
        for slot in HANDLERS.iter_mut() {
            if slot.is_none() {
                *slot = Some(PortHandler { port, handler });
                return;
            }
        }
    }
}

/// Send a UDP datagram.
pub fn send(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]) {
    let udp_len = 8 + data.len();
    if udp_len > 1480 {
        return;
    }

    let dst = Ipv4Addr::from(dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
    static mut TX_BUF: [u8; 1480] = [0; 1480];

    unsafe {
        let hdr = &mut *(TX_BUF.as_mut_ptr() as *mut UdpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.length = htons(udp_len as u16);
        hdr.checksum = 0;

        core::ptr::copy_nonoverlapping(data.as_ptr(), TX_BUF.as_mut_ptr().add(8), data.len());

        hdr.checksum = tcp_checksum(CONFIG.ip, dst, PROTO_UDP, TX_BUF.as_ptr(), udp_len);

        ipv4_send(dst, PROTO_UDP, &TX_BUF[..udp_len]);
    }
}

/// Called by ipv4_receive when protocol == UDP.
pub(crate) fn udp_receive(src_ip: Ipv4Addr, _dst_ip: Ipv4Addr, data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    let hdr = unsafe { &*(data.as_ptr() as *const UdpHeader) };
    let dst_port = ntohs(hdr.dst_port);
    let src_port = ntohs(hdr.src_port);
    let udp_len = ntohs(hdr.length) as usize;

    if udp_len < 8 || udp_len > data.len() {
        return;
    }
    let payload = &data[8..udp_len];

    unsafe {
        for slot in HANDLERS.iter() {
            if let Some(h) = slot {
                if h.port == dst_port {
                    (h.handler)(src_ip.octets(), src_port, payload);
                    return;
                }
            }
        }
    }
}
