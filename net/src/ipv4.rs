// net/ipv4.rs — IPv4 packet parsing/building.

#![no_std]

extern crate uni_kernel;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate net_ethernet as ethernet;
extern crate net_arp as arp;

use core::ptr;
use from_bytes::FromBytes;
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

// SAFETY: repr(C, packed), all fields are POD integer / Ipv4Addr.
unsafe impl FromBytes for Ipv4Header {}

/// Parsed IPv4 packet returned by ipv4_receive.
pub struct Ipv4Packet<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub payload: &'a [u8],
}

/// IPv4 packet identification counter — per core to avoid the cache-line
/// ping-pong from a global atomic incrementing on every TX. Each core
/// gets its own 16-bit space starting at `cpu_id << 13`, so collisions
/// across cores are rare and limited to wraparound, which doesn't
/// matter for non-fragmented traffic (the ID is only used for fragment
/// reassembly).
#[repr(align(64))]
struct IpIdSlot(core::sync::atomic::AtomicU16);

const IP_ID_SLOTS: usize = uni_kernel::percpu::MAX_CORES;
static IP_ID_PERCORE: [IpIdSlot; IP_ID_SLOTS] =
    [const { IpIdSlot(core::sync::atomic::AtomicU16::new(0)) }; IP_ID_SLOTS];

/// True if `ip` is in the same IPv4 subnet as our configured address.
/// Used by receive-side ARP snooping: only snoop (src_ip, src_mac)
/// pairs when the sender is on our LAN segment (off-subnet traffic's
/// L2 src MAC is the gateway's, not the ip's own MAC).
pub fn same_subnet(ip: Ipv4Addr) -> bool {
    let mask = CONFIG.subnet_mask().addr;
    if mask == 0 { return false; }
    let our_ip = CONFIG.ip().addr;
    (ip.addr & mask) == (our_ip & mask)
}

#[inline]
fn next_ip_id() -> u16 {
    let core = uni_kernel::cpu_id() as usize;
    let slot = if core < IP_ID_SLOTS { core } else { 0 };
    // Per-core access, but the field is still atomic so the Rust memory
    // model is happy and a borrow check on `&IpIdSlot` works through the
    // shared static. Relaxed is fine — IP IDs have no ordering needs.
    IP_ID_PERCORE[slot].0.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

pub fn ipv4_send(dst: Ipv4Addr, proto: u8, payload: &[u8]) {
    let payload_len = payload.len().min(1480);
    let total_len = 20 + payload_len;

    // Stack-allocated buffer: safe for multi-core (each core has its own stack).
    // MaybeUninit avoids zeroing — we fill header + payload before send.
    let mut buf = core::mem::MaybeUninit::<[u8; 1500]>::uninit();
    let buf_ptr = buf.as_mut_ptr() as *mut u8;
    let ip_id = next_ip_id();
    unsafe {
        let hdr = &mut *(buf_ptr as *mut Ipv4Header);
        hdr.version_ihl = 0x45;
        hdr.tos = 0;
        hdr.total_length = htons(total_len as u16);
        hdr.identification = htons(ip_id);
        hdr.flags_fragment = htons(0x4000);
        hdr.ttl = 64;
        hdr.protocol = proto;
        hdr.checksum = 0;
        hdr.src = CONFIG.ip();
        hdr.dst = dst;

        hdr.checksum = checksum(buf_ptr, 20);

        ptr::copy_nonoverlapping(payload.as_ptr(), buf_ptr.add(20), payload_len);
    }

    let dst_mac = if CONFIG.ip() == Ipv4Addr::ANY {
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
    let hdr = Ipv4Header::try_ref_from(data)?;

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

    let our_ip = CONFIG.ip();
    let dst = hdr.dst;
    if dst != our_ip && dst != Ipv4Addr::BROADCAST && our_ip != Ipv4Addr::ANY {
        let mask = CONFIG.subnet_mask().addr;
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
