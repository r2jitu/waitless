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

/// Cache our MAC address. Called once at boot after virtio-net init.
pub fn init_mac() {
    unsafe {
        drivers::virtio_net::get_mac(OUR_MAC.bytes.as_mut_ptr());
    }
}

pub fn ethernet_our_mac() -> MacAddr {
    unsafe { OUR_MAC }
}

pub fn ethernet_send(dst: MacAddr, ethertype: u16, payload: &[u8]) {
    // Stack-allocated buffer: safe for multi-core (each core has its own stack).
    // Use MaybeUninit to avoid zeroing 1514 bytes — we fill the header and
    // copy the payload, so the used portion is always initialized.
    let mut buf = core::mem::MaybeUninit::<[u8; 1514]>::uninit();
    unsafe {
        let p = buf.as_mut_ptr() as *mut u8;
        let hdr = &mut *(p as *mut EthernetHeader);
        hdr.dst = dst;
        hdr.src = ethernet_our_mac();
        hdr.ethertype = htons(ethertype);

        let payload_len = payload.len().min(1500);
        ptr::copy_nonoverlapping(payload.as_ptr(), p.add(HEADER_LEN), payload_len);

        drivers::virtio_net::send(core::slice::from_raw_parts(p, HEADER_LEN + payload_len));
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
