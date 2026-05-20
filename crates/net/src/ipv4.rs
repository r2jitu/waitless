// net/ipv4.rs — IPv4 packet parsing/building.

#![cfg_attr(not(test), no_std)]

extern crate net_checksum as checksum;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;

use from_bytes::FromBytes;
use types::{CONFIG, Ipv4Addr, htons, ntohs};

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

/// The fields `ipv4_parse` extracts from an IPv4 packet — the L3
/// addresses, the protocol, and a borrowed view of the L4 payload.
/// Not the packet itself: it owns no bytes and omits the rest of
/// the wire header (`Ipv4Header`).
pub struct Ipv4Parsed<'a> {
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
static IP_ID_PERCORE: kernel_core::percpu::PerWorker<IpIdSlot> =
    kernel_core::percpu::PerWorker::new();

/// Allocate the per-core IP-ID counter table. Called from net stack
/// init on the BSP after `percpu::init`. Idempotent.
pub fn init() {
    IP_ID_PERCORE.init(kernel_core::percpu::num_cores(), |_| {
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
        .at(kernel_core::cpu_id())
        .0
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// Length in bytes of the IPv4 header (no options).
pub const HEADER_LEN: usize = 20;

/// Write an IPv4 header in place into `slot` (which must be at
/// least [`HEADER_LEN`] bytes). `total_len` is the IP `total_length`
/// field (header + L4 payload). Upper layers compose
/// `[ETH][IP][L4][payload]` in a single buffer with this + the
/// driver TX pool — there is no longer a memcpy-through send path.
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
        hdr.checksum = checksum::internet_checksum(slot.as_ptr(), HEADER_LEN);
    }
}

/// Parse and validate an IPv4 packet. Returns None if invalid or not for us.
/// Caller is responsible for dispatching based on protocol field.
pub fn ipv4_parse(data: &[u8]) -> Option<Ipv4Parsed<'_>> {
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
    // `total_len < header_len` is genuinely malformed — the packet
    // claims fewer bytes than its own header. `header_len > data.len()`
    // means part 0 of the RX chain doesn't even hold the claimed IPv4
    // header (with options), so the `&data[header_len..]` slice below
    // would be out of bounds. Both stay hard rejects.
    if total_len < header_len || header_len > data.len() {
        return None;
    }
    // A HW-GRO / RSC / LRO coalesced super-segment (RX item M) arrives
    // as one IPv4 packet whose `total_length` — a 16-bit field, so
    // ≤ 65535 — can far exceed part 0 of the RX chain; the payload
    // continues in later chain parts this parser never sees. So
    // `total_len > data.len()` is deliberately NOT a reject here:
    // clamp the part-0 payload view to the bytes physically present
    // and let the chain walk in `tcp_receive` cover the continuation.
    // For an ordinary single-buffer frame `total_len <= data.len()`,
    // so `payload_end == total_len` and this still trims any ethernet
    // trailing padding exactly as before — behaviour-neutral until an
    // RX-offload item (I / N) actually delivers a multi-buffer chain.
    let payload_end = total_len.min(data.len());

    let our_ip = CONFIG.ip();
    let dst = hdr.dst;
    if dst != our_ip && dst != Ipv4Addr::BROADCAST && our_ip != Ipv4Addr::ANY {
        let mask = CONFIG.subnet_mask().addr;
        if mask != 0 && (dst.addr & !mask) != !mask {
            return None;
        }
    }

    Some(Ipv4Parsed {
        src: hdr.src,
        dst: hdr.dst,
        protocol: hdr.protocol,
        payload: &data[header_len..payload_end],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_packet() {
        // version=4 IHL=5, total_length=24 (20 header + 4 payload),
        // protocol=TCP. Default `CONFIG` is all-zero (our_ip == ANY),
        // so the dst-address filter is skipped.
        let mut f = [0u8; 24];
        f[0] = 0x45;
        f[2..4].copy_from_slice(&24u16.to_be_bytes());
        f[9] = types::proto::TCP;
        f[20..24].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let pkt = ipv4_parse(&f).expect("parse");
        assert_eq!(pkt.protocol, types::proto::TCP);
        assert_eq!(pkt.payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn accepts_coalesced_super_segment_length() {
        // RX item M: a HW-GRO super-segment's `total_length` (50000
        // here) outruns part 0 of the RX chain. `ipv4_parse` must
        // not reject it — it clamps the part-0 payload view to the
        // bytes present and leaves the rest to `tcp_receive`'s chain
        // walk. (The real function — the parallel-logic check in
        // `protocol_tests.rs` predates `ipv4` being host-testable.)
        let mut f = [0u8; 24]; // 20-byte header + 4 payload bytes
        f[0] = 0x45;
        f[2..4].copy_from_slice(&50_000u16.to_be_bytes());
        f[9] = types::proto::TCP;
        let pkt = ipv4_parse(&f).expect("super-segment accepted");
        assert_eq!(pkt.payload.len(), 4); // clamped to 24 - 20
    }

    #[test]
    fn rejects_wrong_version() {
        let mut f = [0u8; 24];
        f[0] = 0x65; // version = 6
        f[2..4].copy_from_slice(&24u16.to_be_bytes());
        assert!(ipv4_parse(&f).is_none());
    }

    #[test]
    fn rejects_total_len_below_header() {
        // total_length = 10 — fewer bytes than the 20-byte header.
        let mut f = [0u8; 24];
        f[0] = 0x45;
        f[2..4].copy_from_slice(&10u16.to_be_bytes());
        assert!(ipv4_parse(&f).is_none());
    }
}
