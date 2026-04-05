// net/ipv4.rs — IPv4 packet parsing/building.

use core::ptr;

use crate::types::{MacAddr, Ipv4Addr, CONFIG, checksum};
use crate::ethernet::{ethernet_send, ETHERTYPE_IPV4};
use crate::arp::arp_resolve;
use crate::tcp::tcp_receive;
use crate::{htons, ntohs};

pub(crate) const PROTO_TCP: u8 = 6;
pub(crate) const PROTO_UDP: u8 = 17;

#[repr(C, packed)]
pub(crate) struct Ipv4Header {
    pub version_ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

static mut IP_ID_COUNTER: u16 = 1;
static mut IPV4_TX_BUF: [u8; 1500] = [0; 1500];

pub(crate) fn ipv4_send(dst: Ipv4Addr, proto: u8, payload: &[u8]) {
    let payload_len = payload.len().min(1480);
    let total_len = 20 + payload_len;

    unsafe {
        let hdr = &mut *(IPV4_TX_BUF.as_mut_ptr() as *mut Ipv4Header);
        hdr.version_ihl = 0x45; // IPv4, IHL=5 (20 bytes)
        hdr.tos = 0;
        hdr.total_length = htons(total_len as u16);
        hdr.identification = htons(IP_ID_COUNTER);
        IP_ID_COUNTER = IP_ID_COUNTER.wrapping_add(1);
        hdr.flags_fragment = htons(0x4000); // Don't Fragment
        hdr.ttl = 64;
        hdr.protocol = proto;
        hdr.checksum = 0;
        hdr.src = CONFIG.ip;
        hdr.dst = dst;

        // Header checksum
        hdr.checksum = checksum(IPV4_TX_BUF.as_ptr(), 20);

        // Copy payload
        ptr::copy_nonoverlapping(payload.as_ptr(), IPV4_TX_BUF.as_mut_ptr().add(20), payload_len);
    }

    // Resolve destination MAC
    let dst_mac = if unsafe { CONFIG.ip } == Ipv4Addr::ANY {
        // Pre-DHCP: send as broadcast
        MacAddr::BROADCAST
    } else {
        match arp_resolve(dst) {
            Some(mac) => mac,
            None => return, // Can't resolve — drop packet
        }
    };

    unsafe {
        ethernet_send(dst_mac, ETHERTYPE_IPV4, &IPV4_TX_BUF[..total_len]);
    }
}

pub(crate) fn ipv4_receive(data: *const u8, len: usize) {
    if len < 20 {
        return;
    }
    let hdr = unsafe { &*(data as *const Ipv4Header) };

    // Validate
    let version = hdr.version_ihl >> 4;
    if version != 4 {
        return;
    }
    let ihl = (hdr.version_ihl & 0x0F) as usize;
    if ihl < 5 {
        return;
    }
    let header_len = ihl * 4;
    let total_len = ntohs(hdr.total_length) as usize;
    if total_len > len || total_len < header_len {
        return;
    }

    // Check destination
    let our_ip = unsafe { CONFIG.ip };
    let dst = hdr.dst;
    if dst != our_ip && dst != Ipv4Addr::BROADCAST && our_ip != Ipv4Addr::ANY {
        // Check subnet broadcast
        let mask = unsafe { CONFIG.subnet_mask.addr };
        if mask != 0 && (dst.addr & !mask) != !mask {
            return;
        }
    }

    let payload = unsafe { data.add(header_len) };
    let payload_len = total_len - header_len;

    match hdr.protocol {
        PROTO_TCP => tcp_receive(hdr.src, hdr.dst, payload, payload_len),
        _ => {}
    }
}
