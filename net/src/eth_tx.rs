// net/eth_tx.rs — Ethernet send path: NIC MAC-cache init + frame TX.
//
// The send half of what used to be `net_ethernet` — split out so
// `net_ethernet` itself is a pure, host-testable leaf. Depends on
// `net_ethernet` (the header builder + MAC cache) and `//drivers:nic`
// (the host-buildable NIC dispatch). `arp` / `ipv6_send` link against
// this for `ethernet_send`; boot calls `init_mac`.

#![no_std]

extern crate net_ethernet as ethernet;
extern crate net_types as types;
extern crate nic;

use core::ptr;
use ethernet::{EthernetHeader, HEADER_LEN, ethernet_our_mac};
use types::{MacAddr, htons};

/// Cache the NIC's MAC address. Called once at boot after virtio-net
/// init: reads the MAC from the driver and publishes it into
/// `net_ethernet`'s cross-core cache via `set_our_mac`.
pub fn init_mac() {
    let mut bytes = [0u8; 6];
    nic::get_mac(bytes.as_mut_ptr());
    ethernet::set_our_mac(bytes);
}

/// Build an Ethernet frame around `payload` and hand it to the NIC.
/// The legacy memcpy-through send path; upper layers that compose
/// the whole `[ETH][IP][L4]` frame in one buffer use `fill_header`
/// + the driver TX pool directly instead.
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

        // ARP / ICMPv6 / NDP only — never an offloadable L4
        // segment, so the frame ships with no checksum descriptor.
        nic::send(
            core::slice::from_raw_parts(p, HEADER_LEN + payload_len),
            nic::CsumOffload::NONE,
        );
    }
}
