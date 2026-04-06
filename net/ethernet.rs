// net/ethernet.rs — Ethernet frame parsing/building and receive callback.

use core::ptr;

use crate::types::MacAddr;
use crate::{htons, ntohs};
use crate::arp::arp_receive;
use crate::ipv4::ipv4_receive;

pub(crate) const ETHERTYPE_ARP: u16 = 0x0806;
pub(crate) const ETHERTYPE_IPV4: u16 = 0x0800;

#[repr(C, packed)]
pub(crate) struct EthernetHeader {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16, // network byte order
}

static mut OUR_MAC: MacAddr = MacAddr::ZERO;
static mut MAC_CACHED: bool = false;

pub(crate) fn ethernet_our_mac() -> MacAddr {
    unsafe {
        if !MAC_CACHED {
            drivers::virtio_net::get_mac(OUR_MAC.bytes.as_mut_ptr());
            MAC_CACHED = true;
        }
        OUR_MAC
    }
}

pub(crate) static mut ETH_TX_BUF: [u8; 1514] = [0; 1514]; // 14 header + 1500 payload

pub(crate) fn ethernet_send(dst: MacAddr, ethertype: u16, payload: &[u8]) {
    unsafe {
        let hdr = &mut *(ETH_TX_BUF.as_mut_ptr() as *mut EthernetHeader);
        hdr.dst = dst;
        hdr.src = ethernet_our_mac();
        hdr.ethertype = htons(ethertype);

        let payload_len = payload.len().min(1500);
        ptr::copy_nonoverlapping(payload.as_ptr(), ETH_TX_BUF.as_mut_ptr().add(14), payload_len);

        drivers::virtio_net::send(&ETH_TX_BUF[..14 + payload_len]);
    }
}

/// Ethernet frame receive callback — dispatches to ARP or IPv4.
pub(crate) fn ethernet_receive(frame: &[u8]) {
    if frame.len() < 14 {
        return;
    }
    let hdr = unsafe { &*(frame.as_ptr() as *const EthernetHeader) };
    let ethertype = ntohs(hdr.ethertype);
    let payload = &frame[14..];

    match ethertype {
        ETHERTYPE_ARP => arp_receive(payload),
        ETHERTYPE_IPV4 => ipv4_receive(payload),
        _ => {}
    }
}
