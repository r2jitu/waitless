// net/ethernet.rs — Ethernet frame parsing/building.
//
// Layer 2 only: MAC addresses, frame headers, send/receive.
// Protocol dispatch (ARP, IPv4) is handled by callers, not here.

#![no_std]
#![allow(static_mut_refs)]

extern crate net_types as types;
extern crate drivers;

use core::ptr;
use types::{MacAddr, htons};

pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const HEADER_LEN: usize = 14;

#[repr(C, packed)]
pub struct EthernetHeader {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16, // network byte order
}

static mut OUR_MAC: MacAddr = MacAddr::ZERO;
static mut MAC_CACHED: bool = false;

pub fn ethernet_our_mac() -> MacAddr {
    unsafe {
        if !MAC_CACHED {
            drivers::virtio_net::get_mac(OUR_MAC.bytes.as_mut_ptr());
            MAC_CACHED = true;
        }
        OUR_MAC
    }
}

pub fn ethernet_send(dst: MacAddr, ethertype: u16, payload: &[u8]) {
    // Stack-allocated buffer: safe for multi-core (each core has its own stack).
    let mut buf = [0u8; 1514];
    unsafe {
        let hdr = &mut *(buf.as_mut_ptr() as *mut EthernetHeader);
        hdr.dst = dst;
        hdr.src = ethernet_our_mac();
        hdr.ethertype = htons(ethertype);

        let payload_len = payload.len().min(1500);
        ptr::copy_nonoverlapping(payload.as_ptr(), buf.as_mut_ptr().add(HEADER_LEN), payload_len);

        drivers::virtio_net::send(&buf[..HEADER_LEN + payload_len]);
    }
}

/// Parse an Ethernet frame into ethertype + payload. Returns None if too short.
pub fn ethernet_parse(frame: &[u8]) -> Option<(u16, &[u8])> {
    if frame.len() < HEADER_LEN {
        return None;
    }
    let hdr = unsafe { &*(frame.as_ptr() as *const EthernetHeader) };
    Some((u16::from_be(hdr.ethertype), &frame[HEADER_LEN..]))
}
