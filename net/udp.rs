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

/// Registered UDP port handler.
struct PortHandler {
    port: u16,
    handler: fn(src_ip: Ipv4Addr, src_port: u16, data: &[u8]),
}

static mut HANDLERS: [Option<PortHandler>; MAX_HANDLERS] = [const { None }; MAX_HANDLERS];

/// Register a handler for incoming UDP packets on a specific port.
pub fn bind(port: u16, handler: fn(Ipv4Addr, u16, &[u8])) {
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
pub fn send(dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, data: &[u8]) {
    let udp_len = 8 + data.len();
    if udp_len > 1480 {
        return; // Too large for single IPv4 packet
    }

    static mut TX_BUF: [u8; 1480] = [0; 1480];

    unsafe {
        let hdr = &mut *(TX_BUF.as_mut_ptr() as *mut UdpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.length = htons(udp_len as u16);
        hdr.checksum = 0;

        // Copy payload after header
        core::ptr::copy_nonoverlapping(data.as_ptr(), TX_BUF.as_mut_ptr().add(8), data.len());

        // UDP checksum (optional for IPv4, but good practice)
        hdr.checksum = tcp_checksum(CONFIG.ip, dst_ip, PROTO_UDP, TX_BUF.as_ptr(), udp_len);

        ipv4_send(dst_ip, PROTO_UDP, &TX_BUF[..udp_len]);
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

    // Dispatch to registered handler
    unsafe {
        for slot in HANDLERS.iter() {
            if let Some(h) = slot {
                if h.port == dst_port {
                    (h.handler)(src_ip, src_port, payload);
                    return;
                }
            }
        }
    }
}
