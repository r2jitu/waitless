// net/ipv4.rs — IPv4 packet parsing/building.

#![no_std]
#![allow(static_mut_refs)]

extern crate net_types as types;
extern crate net_ethernet as ethernet;
extern crate net_arp as arp;

use core::ptr;
use types::{MacAddr, Ipv4Addr, CONFIG, checksum, htons, ntohs};
use ethernet::{ethernet_send, ETHERTYPE_IPV4};
use arp::arp_resolve;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[repr(C, packed)]
pub struct Ipv4Header {
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

/// Parsed IPv4 packet returned by ipv4_receive.
pub struct Ipv4Packet<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub payload: &'a [u8],
}

// Volatile (not atomic) — see SEQ_COUNTER comment in tcp.rs.
static mut IP_ID_COUNTER: u16 = 1;

pub fn ipv4_send(dst: Ipv4Addr, proto: u8, payload: &[u8]) {
    let payload_len = payload.len().min(1480);
    let total_len = 20 + payload_len;

    // Stack-allocated buffer: safe for multi-core (each core has its own stack).
    // MaybeUninit avoids zeroing — we fill header + payload before send.
    let mut buf = core::mem::MaybeUninit::<[u8; 1500]>::uninit();
    let buf_ptr = buf.as_mut_ptr() as *mut u8;
    unsafe {
        let hdr = &mut *(buf_ptr as *mut Ipv4Header);
        hdr.version_ihl = 0x45;
        hdr.tos = 0;
        hdr.total_length = htons(total_len as u16);
        let ip_id = core::ptr::read_volatile(&IP_ID_COUNTER);
        core::ptr::write_volatile(&raw mut IP_ID_COUNTER, ip_id.wrapping_add(1));
        hdr.identification = htons(ip_id);
        hdr.flags_fragment = htons(0x4000);
        hdr.ttl = 64;
        hdr.protocol = proto;
        hdr.checksum = 0;
        hdr.src = CONFIG.ip;
        hdr.dst = dst;

        hdr.checksum = checksum(buf_ptr, 20);

        ptr::copy_nonoverlapping(payload.as_ptr(), buf_ptr.add(20), payload_len);
    }

    let dst_mac = if unsafe { CONFIG.ip } == Ipv4Addr::ANY {
        MacAddr::BROADCAST
    } else {
        match arp_resolve(dst) {
            Some(mac) => mac,
            None => return,
        }
    };

    let frame = unsafe { core::slice::from_raw_parts(buf_ptr, total_len) };
    ethernet_send(dst_mac, ETHERTYPE_IPV4, frame);
}

/// Parse and validate an IPv4 packet. Returns None if invalid or not for us.
/// Caller is responsible for dispatching based on protocol field.
pub fn ipv4_receive(data: &[u8]) -> Option<Ipv4Packet<'_>> {
    if data.len() < 20 {
        return None;
    }
    let hdr = unsafe { &*(data.as_ptr() as *const Ipv4Header) };

    let version = hdr.version_ihl >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (hdr.version_ihl & 0x0F) as usize;
    if ihl < 5 {
        return None;
    }
    let header_len = ihl * 4;
    let total_len = ntohs(hdr.total_length) as usize;
    if total_len > data.len() || total_len < header_len {
        return None;
    }

    let our_ip = unsafe { CONFIG.ip };
    let dst = hdr.dst;
    if dst != our_ip && dst != Ipv4Addr::BROADCAST && our_ip != Ipv4Addr::ANY {
        let mask = unsafe { CONFIG.subnet_mask.addr };
        if mask != 0 && (dst.addr & !mask) != !mask {
            return None;
        }
    }

    Some(Ipv4Packet {
        src: hdr.src,
        dst: hdr.dst,
        protocol: hdr.protocol,
        payload: &data[header_len..total_len],
    })
}
