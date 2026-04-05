// net/types.rs — Network types, config, and checksum helpers.

use crate::htons;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct MacAddr {
    pub bytes: [u8; 6],
}

impl MacAddr {
    pub const ZERO: Self = MacAddr { bytes: [0; 6] };
    pub const BROADCAST: Self = MacAddr { bytes: [0xff; 6] };

    pub fn is_broadcast(&self) -> bool {
        self.bytes == [0xff; 6]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct Ipv4Addr {
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
pub(crate) struct NetConfig {
    pub ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Ipv4Addr,
}

pub(crate) static mut CONFIG: NetConfig = NetConfig {
    ip: Ipv4Addr::ANY,
    subnet_mask: Ipv4Addr::ANY,
    gateway: Ipv4Addr::ANY,
    dns: Ipv4Addr::ANY,
};

/// RFC 1071 internet checksum over a byte buffer.
/// Reads 16-bit words in little-endian (matching the C++ implementation)
/// so that the returned u16 can be stored directly in packed struct fields.
pub(crate) fn checksum(data: *const u8, len: usize) -> u16 {
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
/// Matches the C++ implementation: pseudo-header + data summed in LE byte order.
pub(crate) fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, data: *const u8, len: usize) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header — read addr fields as LE 16-bit words (matching C++ struct layout)
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
