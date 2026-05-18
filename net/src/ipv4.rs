// net/ipv4.rs — IPv4 packet parsing/building.

#![no_std]

extern crate net_arp as arp;
extern crate net_ethernet as ethernet;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate uni_kernel;

use arp::arp_resolve;
use core::ptr;
use ethernet::{ETHERTYPE_IPV4, ethernet_send};
use from_bytes::FromBytes;
use types::{CONFIG, Ipv4Addr, MacAddr, checksum, htons, ntohs};

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

/// Per-core IP-ID counter slots, sized at boot to actual core count.
static IP_ID_PERCORE: uni_kernel::percpu::PerWorker<IpIdSlot> =
    uni_kernel::percpu::PerWorker::new();

/// Allocate the per-core IP-ID counter table. Called from net stack
/// init on the BSP after `percpu::init`. Idempotent.
pub fn init() {
    IP_ID_PERCORE.init(uni_kernel::percpu::num_cores(), |_| {
        IpIdSlot(core::sync::atomic::AtomicU16::new(0))
    });
}

/// True if `ip` is in the same IPv4 subnet as our configured address.
/// Used by receive-side ARP snooping: only snoop (src_ip, src_mac)
/// pairs when the sender is on our LAN segment (off-subnet traffic's
/// L2 src MAC is the gateway's, not the ip's own MAC).
pub fn same_subnet(ip: Ipv4Addr) -> bool {
    let mask = CONFIG.subnet_mask().addr;
    if mask == 0 {
        return false;
    }
    let our_ip = CONFIG.ip().addr;
    (ip.addr & mask) == (our_ip & mask)
}

#[inline]
fn next_ip_id() -> u16 {
    // Per-core access, but the field is still atomic so the Rust memory
    // model is happy and a borrow check on `&IpIdSlot` works through the
    // shared static. Relaxed is fine — IP IDs have no ordering needs.
    IP_ID_PERCORE
        .at(uni_kernel::cpu_id())
        .0
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// Length in bytes of the IPv4 header (no options).
pub const HEADER_LEN: usize = 20;

/// Write an IPv4 header in place into `slot` (which must be at
/// least [`HEADER_LEN`] bytes). `total_len` is the IP `total_length`
/// field (header + L4 payload). Used by upper layers that want to
/// compose `[ETH][IP][L4][payload]` in a single buffer without
/// memcpy'ing through the legacy `ipv4_send` slow path.
#[inline]
pub fn fill_header(slot: &mut [u8], src: Ipv4Addr, dst: Ipv4Addr, proto: u8, total_len: u16) {
    debug_assert!(slot.len() >= HEADER_LEN);
    // SAFETY: caller ensures `slot.len() >= HEADER_LEN`. `Ipv4Header` is
    // `repr(C)` plain bytes (`FromBytes`), so writing through the cast
    // is well-defined for all field bytes.
    unsafe {
        let hdr = &mut *(slot.as_mut_ptr() as *mut Ipv4Header);
        hdr.version_ihl = 0x45;
        hdr.tos = 0;
        hdr.total_length = htons(total_len);
        hdr.identification = htons(next_ip_id());
        hdr.flags_fragment = htons(0x4000);
        hdr.ttl = 64;
        hdr.protocol = proto;
        hdr.checksum = 0;
        hdr.src = src;
        hdr.dst = dst;
        hdr.checksum = checksum(slot.as_ptr(), HEADER_LEN);
    }
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
