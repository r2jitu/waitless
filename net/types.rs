// net/types.rs — Network types, byte order, config, and checksum helpers.
//
// This module has no dependencies on other net/ modules or external crates.
// It can be compiled as a standalone crate (//net:types).

#![cfg_attr(not(test), no_std)]

// ── Byte-order utilities ─────────────────────────────────────────────────────

#[inline]
pub fn htons(h: u16) -> u16 { h.to_be() }
#[inline]
pub fn ntohs(n: u16) -> u16 { u16::from_be(n) }
#[inline]
pub fn htonl(h: u32) -> u32 { h.to_be() }
#[inline]
pub fn ntohl(n: u32) -> u32 { u32::from_be(n) }

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct MacAddr {
    pub bytes: [u8; 6],
}

impl MacAddr {
    pub const ZERO: Self = MacAddr { bytes: [0; 6] };
    pub const BROADCAST: Self = MacAddr { bytes: [0xff; 6] };

}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4Addr {
    pub addr: u32, // network byte order
}

impl Ipv4Addr {
    pub const ANY: Self = Ipv4Addr { addr: 0 };
    pub const BROADCAST: Self = Ipv4Addr { addr: 0xFFFFFFFF };

    pub fn from(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr {
            addr: u32::from_ne_bytes([a, b, c, d]),
        }
    }

    pub fn octets(&self) -> [u8; 4] {
        self.addr.to_ne_bytes()
    }
}

#[derive(Clone, Copy)]
pub struct NetConfig {
    pub ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Ipv4Addr,
}

pub static mut CONFIG: NetConfig = NetConfig {
    ip: Ipv4Addr::ANY,
    subnet_mask: Ipv4Addr::ANY,
    gateway: Ipv4Addr::ANY,
    dns: Ipv4Addr::ANY,
};

/// RFC 1071 internet checksum over a byte buffer.
/// Reads 16-bit words in little-endian byte order.
/// so that the returned u16 can be stored directly in packed struct fields.
pub fn checksum(data: *const u8, len: usize) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < len {
        let word = unsafe { (*data.add(i) as u16) | ((*data.add(i + 1) as u16) << 8) };
        sum += word as u32;
        i += 2;
    }
    if i < len {
        sum += unsafe { *data.add(i) as u32 };
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP/UDP pseudo-header checksum.
/// Pseudo-header + data summed in LE byte order.
pub fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, data: *const u8, len: usize) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header — read addr fields as LE 16-bit words
    sum += (src.addr & 0xFFFF) as u32;
    sum += (src.addr >> 16) as u32;
    sum += (dst.addr & 0xFFFF) as u32;
    sum += (dst.addr >> 16) as u32;
    sum += (proto as u32) << 8; // zero byte | proto byte, LE word
    sum += htons(len as u16) as u32; // length in network byte order, stored LE

    // Data — read in LE byte order
    let mut i = 0;
    while i + 1 < len {
        let word = unsafe { (*data.add(i) as u16) | ((*data.add(i + 1) as u16) << 8) };
        sum += word as u32;
        i += 2;
    }
    if i < len {
        sum += unsafe { *data.add(i) as u32 };
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_order_roundtrip() {
        assert_eq!(ntohs(htons(0x1234)), 0x1234);
        assert_eq!(ntohl(htonl(0x12345678)), 0x12345678);
        assert_eq!(htons(80), 80u16.to_be());
        assert_eq!(ntohs(80u16.to_be()), 80);
    }

    #[test]
    fn mac_addr_constants() {
        assert_eq!(MacAddr::ZERO.bytes, [0; 6]);
        assert_eq!(MacAddr::BROADCAST.bytes, [0xff; 6]);
        assert_ne!(MacAddr::ZERO, MacAddr::BROADCAST);
    }

    #[test]
    fn ipv4_addr_from_octets() {
        let addr = Ipv4Addr::from(10, 0, 2, 15);
        assert_eq!(addr.octets(), [10, 0, 2, 15]);
    }

    #[test]
    fn ipv4_addr_constants() {
        assert_eq!(Ipv4Addr::ANY.addr, 0);
        assert_eq!(Ipv4Addr::BROADCAST.addr, 0xFFFFFFFF);
    }

    #[test]
    fn ipv4_addr_equality() {
        let a = Ipv4Addr::from(192, 168, 1, 1);
        let b = Ipv4Addr::from(192, 168, 1, 1);
        let c = Ipv4Addr::from(192, 168, 1, 2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn checksum_zeros() {
        // All-zero data should checksum to 0xFFFF
        let data = [0u8; 20];
        assert_eq!(checksum(data.as_ptr(), data.len()), 0xFFFF);
    }

    #[test]
    fn checksum_ones() {
        // All-0xFF data (20 bytes = 10 words of 0xFFFF)
        // Folded sum = 0xFFFF, complement = 0x0000
        let data = [0xFFu8; 20];
        assert_eq!(checksum(data.as_ptr(), data.len()), 0x0000);
    }

    #[test]
    fn checksum_odd_length() {
        let data = [0x01, 0x02, 0x03];
        // sum = 0x0201 + 0x03 = 0x0204, complement = 0xFDFB
        assert_eq!(checksum(data.as_ptr(), data.len()), 0xFDFB);
    }

    #[test]
    fn checksum_verification() {
        // Compute checksum of an IPv4-like header, then verify it
        // produces 0 when re-checked with the checksum filled in.
        let hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3C,
            0x1C, 0x46, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,  // checksum field = 0
            0xAC, 0x10, 0x0A, 0x63,
            0xAC, 0x10, 0x0A, 0x0C,
        ];
        let cksum = checksum(hdr.as_ptr(), hdr.len());
        // Fill in checksum (LE byte order) and re-verify
        let mut verified = hdr;
        verified[10] = (cksum & 0xFF) as u8;
        verified[11] = (cksum >> 8) as u8;
        assert_eq!(checksum(verified.as_ptr(), verified.len()), 0);
    }

    #[test]
    fn udp_checksum_verification() {
        // Build a UDP pseudo-header + payload and verify the checksum.
        let src = Ipv4Addr::from(10, 0, 2, 15);
        let dst = Ipv4Addr::from(10, 0, 2, 2);
        // UDP header (8 bytes): src_port=5000, dst_port=80, len=13, cksum=0
        // + payload "hello" (5 bytes) = 13 bytes total
        let udp_data: [u8; 13] = [
            0x13, 0x88, // src_port = 5000 (big-endian)
            0x00, 0x50, // dst_port = 80
            0x00, 0x0D, // length = 13
            0x00, 0x00, // checksum = 0 (to be computed)
            b'h', b'e', b'l', b'l', b'o',
        ];
        let cksum = tcp_checksum(src, dst, 17, udp_data.as_ptr(), udp_data.len());
        // Fill in and re-verify
        let mut verified = udp_data;
        verified[6] = (cksum & 0xFF) as u8;
        verified[7] = (cksum >> 8) as u8;
        assert_eq!(tcp_checksum(src, dst, 17, verified.as_ptr(), verified.len()), 0);
    }
}
