// net/types.rs — Network types, byte order, config, and checksum helpers.
//
// This module has no dependencies on other net/ modules or external crates.
// It can be compiled as a standalone crate (//net:types).

#![cfg_attr(not(test), no_std)]

// ── Byte-order utilities ─────────────────────────────────────────────────────

#[inline]
pub fn htons(h: u16) -> u16 {
    h.to_be()
}
#[inline]
pub fn ntohs(n: u16) -> u16 {
    u16::from_be(n)
}
#[inline]
pub fn htonl(h: u32) -> u32 {
    h.to_be()
}
#[inline]
pub fn ntohl(n: u32) -> u32 {
    u32::from_be(n)
}

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
    pub const BROADCAST: Self = Ipv4Addr { addr: 0xFFFF_FFFF };

    pub fn from(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr {
            addr: u32::from_ne_bytes([a, b, c, d]),
        }
    }

    pub fn octets(&self) -> [u8; 4] {
        self.addr.to_ne_bytes()
    }
}

// ── IPv6 ────────────────────────────────────────────────────────────────────

/// 128-bit IPv6 address. Stored as 16 bytes in network order so
/// the type can be embedded directly in `repr(C, packed)` headers
/// without per-field byte-swap. Mirrors `Ipv4Addr`'s plain-data
/// shape but expanded to v6 width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv6Addr {
    pub octets: [u8; 16],
}

impl Ipv6Addr {
    /// All zeros — the unspecified address (RFC 4291 §2.5.2).
    pub const ANY: Self = Ipv6Addr { octets: [0; 16] };

    /// `ff02::1` — the all-nodes link-local multicast group. Every
    /// IPv6 host MUST receive packets sent here.
    pub const ALL_NODES_LL: Self = Ipv6Addr {
        octets: [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
    };

    /// `ff02::2` — all-routers link-local multicast group. Hosts
    /// send Router Solicitations to this address (RFC 4861 §4.1).
    pub const ALL_ROUTERS_LL: Self = Ipv6Addr {
        octets: [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02],
    };

    pub fn from(o: [u8; 16]) -> Self {
        Ipv6Addr { octets: o }
    }

    /// True if `self` is in `fe80::/10` — the link-local prefix.
    pub fn is_link_local(&self) -> bool {
        self.octets[0] == 0xfe && (self.octets[1] & 0xc0) == 0x80
    }

    /// True if `self` is `ff00::/8` — the multicast prefix.
    pub fn is_multicast(&self) -> bool {
        self.octets[0] == 0xff
    }

    /// Construct a solicited-node multicast address for a target
    /// unicast `addr`: `ff02::1:ffXX:XXXX` where the low 24 bits
    /// match the low 24 bits of `addr` (RFC 4291 §2.7.1). NDP
    /// Neighbor Solicitation messages target this group so only
    /// hosts whose address matches the suffix are interrupted.
    pub fn solicited_node(addr: &Ipv6Addr) -> Self {
        let mut o = [0u8; 16];
        o[0] = 0xff;
        o[1] = 0x02;
        o[11] = 0x01;
        o[12] = 0xff;
        o[13] = addr.octets[13];
        o[14] = addr.octets[14];
        o[15] = addr.octets[15];
        Ipv6Addr { octets: o }
    }

    /// Derive the link-local address from a MAC via modified
    /// EUI-64 (RFC 4291 Appendix A): split MAC at byte 3, insert
    /// `ff fe`, flip the universal/local bit (bit 1 of byte 0),
    /// prefix with `fe80::`. Used by SLAAC bring-up before any
    /// router has been observed.
    pub fn link_local_from_mac(mac: &MacAddr) -> Self {
        let mut o = [0u8; 16];
        o[0] = 0xfe;
        o[1] = 0x80;
        // Modified EUI-64: flip bit 1 of byte 0 of the MAC.
        o[8] = mac.bytes[0] ^ 0x02;
        o[9] = mac.bytes[1];
        o[10] = mac.bytes[2];
        o[11] = 0xff;
        o[12] = 0xfe;
        o[13] = mac.bytes[3];
        o[14] = mac.bytes[4];
        o[15] = mac.bytes[5];
        Ipv6Addr { octets: o }
    }

    /// Solicited-node multicast → Ethernet MAC mapping
    /// `33:33:XX:XX:XX:XX` where the low 32 bits of the multicast
    /// address are placed in the low 32 bits of the MAC
    /// (RFC 2464 §7).
    pub fn multicast_mac(&self) -> MacAddr {
        MacAddr {
            bytes: [
                0x33,
                0x33,
                self.octets[12],
                self.octets[13],
                self.octets[14],
                self.octets[15],
            ],
        }
    }
}

// ── Family-agnostic IP address ─────────────────────────────────────────────

/// Either an IPv4 or IPv6 unicast address. Used in dual-stack
/// signatures (TCP TCB peer, UDP recv source, runtime API). Tag +
/// 16-byte payload = ~24 bytes incl. alignment, plain Copy data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl IpAddr {
    /// Wildcard / unspecified — any v4 address. Mirrors `Ipv4Addr::ANY`
    /// for callers that need a typed default.
    pub const V4_ANY: Self = IpAddr::V4(Ipv4Addr::ANY);

    /// True if the address belongs to the IPv4 family.
    pub fn is_v4(&self) -> bool {
        matches!(self, IpAddr::V4(_))
    }

    /// True if the address belongs to the IPv6 family.
    pub fn is_v6(&self) -> bool {
        matches!(self, IpAddr::V6(_))
    }
}

impl From<Ipv4Addr> for IpAddr {
    fn from(v: Ipv4Addr) -> Self {
        IpAddr::V4(v)
    }
}

impl From<Ipv6Addr> for IpAddr {
    fn from(v: Ipv6Addr) -> Self {
        IpAddr::V6(v)
    }
}

// ── Parsed L2/L3 frame summary ─────────────────────────────────────

/// The L2/L3 parse of a received IPv4 frame — ethertype resolved,
/// IP addresses extracted, the L4 segment located — computed once so
/// a later stage need not re-walk the headers.
///
/// The Tier-2 RX distributor produces one per IPv4 frame in its
/// classify pass (which picks the owning core) and carries it — on the
/// cross-core inbox node for a distributed frame, directly for an
/// inline one — so the receiving core skips straight to `tcp_receive` /
/// `udp_receive` instead of re-parsing eth + IPv4. See
/// `docs/rx-path-optimizations.md`, "Fuse the Tier-2 classify parse".
///
/// Plain `Copy` data with no borrow of the frame buffer: the L4
/// segment is referenced by `(l4_off, l4_len)` into the frame's part-0
/// buffer, not by slice, so a `ParsedL3` can ride an inbox node
/// alongside the frame's `Chain` without a lifetime. There is no
/// `ethertype` field — `src`/`dst` already encode the IP family, and
/// IPv4 and IPv6 frames alike are summarised here.
#[derive(Clone, Copy, Debug)]
pub struct ParsedL3 {
    /// IP protocol number of the L4 segment — `6` (TCP) or `17` (UDP)
    /// for a frame the stack handles; any other value parses through
    /// (carried only so the receive path can still ARP-snoop) and the
    /// L4 dispatch no-ops on it.
    pub proto: u8,
    /// Source IP address (the frame's L3 src).
    pub src: IpAddr,
    /// Destination IP address (the frame's L3 dst).
    pub dst: IpAddr,
    /// Byte offset of the L4 segment within the frame's part-0 buffer.
    pub l4_off: usize,
    /// Length in bytes of the L4 segment.
    pub l4_len: usize,
    /// The on-link sender's L2 source MAC, to snoop into the
    /// *receiving* core's neighbor cache — the ARP cache for a v4
    /// frame, the NDP cache for v6. `None` when a v4 sender is
    /// off-subnet (its L2 src MAC is the gateway's, not the IP's own
    /// — snooping it would be wrong; see `arp_learn`); a v6 sender is
    /// link-local or same-prefix SLAAC, hence always on-link, so a v6
    /// frame always carries `Some`. For a distributed frame the
    /// receiving core is not the core the distributor warmed, so
    /// honouring this is not redundant.
    pub snoop_mac: Option<MacAddr>,
}

impl ParsedL3 {
    /// Re-derive the L4 segment from `frame` — the part-0 buffer the
    /// borrow-free `(l4_off, l4_len)` pair indexes into. The inverse
    /// of the offset the classify pass captured; `None` only if the
    /// range falls outside `frame`, which never happens for the frame
    /// this summary was built from. Lets the receive path name the
    /// re-slice instead of open-coding `l4_off..l4_off + l4_len`.
    #[inline]
    pub fn l4<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]> {
        frame.get(self.l4_off..self.l4_off + self.l4_len)
    }
}

#[derive(Clone, Copy)]
pub struct NetConfig {
    pub ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Ipv4Addr,
}

/// Network configuration storage. Each field is an `AtomicU32` so the
/// config can be set during DHCP and read by every core thereafter
/// without `static mut` aliasing UB. Loads/stores use `Relaxed` ordering;
/// the four fields are not atomically consistent with each other, but
/// in practice they are all written together during the DHCP transaction
/// during single-threaded init, and all reads happen long after that
/// init completes — the only window where torn reads could matter is a
/// few cycles during DHCP, and the only readers during that window are
/// DHCP itself.
pub struct ConfigStore {
    ip: core::sync::atomic::AtomicU32,
    subnet_mask: core::sync::atomic::AtomicU32,
    gateway: core::sync::atomic::AtomicU32,
    dns: core::sync::atomic::AtomicU32,
}

impl ConfigStore {
    pub const fn new() -> Self {
        ConfigStore {
            ip: core::sync::atomic::AtomicU32::new(0),
            subnet_mask: core::sync::atomic::AtomicU32::new(0),
            gateway: core::sync::atomic::AtomicU32::new(0),
            dns: core::sync::atomic::AtomicU32::new(0),
        }
    }

    pub fn store(&self, c: NetConfig) {
        use core::sync::atomic::Ordering;
        self.ip.store(c.ip.addr, Ordering::Relaxed);
        self.subnet_mask
            .store(c.subnet_mask.addr, Ordering::Relaxed);
        self.gateway.store(c.gateway.addr, Ordering::Relaxed);
        self.dns.store(c.dns.addr, Ordering::Relaxed);
    }

    pub fn load(&self) -> NetConfig {
        use core::sync::atomic::Ordering;
        NetConfig {
            ip: Ipv4Addr {
                addr: self.ip.load(Ordering::Relaxed),
            },
            subnet_mask: Ipv4Addr {
                addr: self.subnet_mask.load(Ordering::Relaxed),
            },
            gateway: Ipv4Addr {
                addr: self.gateway.load(Ordering::Relaxed),
            },
            dns: Ipv4Addr {
                addr: self.dns.load(Ordering::Relaxed),
            },
        }
    }

    pub fn ip(&self) -> Ipv4Addr {
        Ipv4Addr {
            addr: self.ip.load(core::sync::atomic::Ordering::Relaxed),
        }
    }
    pub fn subnet_mask(&self) -> Ipv4Addr {
        Ipv4Addr {
            addr: self.subnet_mask.load(core::sync::atomic::Ordering::Relaxed),
        }
    }
    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr {
            addr: self.gateway.load(core::sync::atomic::Ordering::Relaxed),
        }
    }
    pub fn dns(&self) -> Ipv4Addr {
        Ipv4Addr {
            addr: self.dns.load(core::sync::atomic::Ordering::Relaxed),
        }
    }
}

pub static CONFIG: ConfigStore = ConfigStore::new();

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

/// 16-bit one's-complement pseudo-header partial sum (no
/// invert), suitable for placement in the L4 checksum field
/// before handing the frame to a NIC that supports
/// `VIRTIO_NET_HDR_F_NEEDS_CSUM` (or equivalent CSUM-offload).
/// The device adds the data checksum to this value and writes
/// the final 16-bit checksum at the same offset.
///
/// Cheaper than `tcp_checksum_any` because it skips the data
/// pass — that's the whole point of CSUM-offload.
#[inline]
pub fn tcp_pseudo_partial(src: IpAddr, dst: IpAddr, proto: u8, l4_len: usize) -> u16 {
    let mut sum: u32 = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut s32: u32 = 0;
            s32 += (s.addr & 0xFFFF) as u32;
            s32 += (s.addr >> 16) as u32;
            s32 += (d.addr & 0xFFFF) as u32;
            s32 += (d.addr >> 16) as u32;
            s32 += (proto as u32) << 8; // proto byte in LE high
            s32 += htons(l4_len as u16) as u32;
            s32
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut s32: u32 = 0;
            for chunk in s.octets.chunks(2).chain(d.octets.chunks(2)) {
                s32 += u16::from_le_bytes([chunk[0], chunk[1]]) as u32;
            }
            let len_be = (l4_len as u32).to_be();
            s32 += (len_be & 0xffff) as u32;
            s32 += (len_be >> 16) as u32;
            s32 += (proto as u32) << 8;
            s32
        }
        _ => 0, // mismatched families — caller bug; safe fallback
    };
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// TCP/UDP pseudo-header checksum, family-dispatched.
/// `src`/`dst` must agree on family; mismatched families fall back
/// to `tcp_checksum_v4` on the v4 component (caller bug).
pub fn tcp_checksum_any(src: IpAddr, dst: IpAddr, proto: u8, data: *const u8, len: usize) -> u16 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => tcp_checksum(s, d, proto, data, len),
        (IpAddr::V6(s), IpAddr::V6(d)) => tcp_checksum_v6(&s, &d, proto, data, len),
        // Mismatched families — should never happen in correct code.
        // Use whichever is v4 to keep the response well-formed
        // rather than crashing.
        (IpAddr::V4(s), _) => tcp_checksum(s, Ipv4Addr::ANY, proto, data, len),
        (_, IpAddr::V4(d)) => tcp_checksum(Ipv4Addr::ANY, d, proto, data, len),
    }
}

/// TCP/UDP pseudo-header checksum over IPv6 (RFC 8200 §8.1).
/// Returns the one's-complement folded sum suitable for direct
/// placement in the upper-layer checksum field — same convention
/// as the IPv4 `tcp_checksum`.
pub fn tcp_checksum_v6(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    proto: u8,
    data: *const u8,
    len: usize,
) -> u16 {
    // IPv6 pseudo-header: src(16) || dst(16) || u32 upper-len ||
    // 3 zeros || u8 next-header. Sum as LE u16 words to match the
    // existing `tcp_checksum` byte-order convention (the result is
    // stored directly in a `repr(C, packed)` u16 field).
    let mut sum: u32 = 0;
    for chunk in src.octets.chunks(2).chain(dst.octets.chunks(2)) {
        sum += u16::from_le_bytes([chunk[0], chunk[1]]) as u32;
    }
    // u32 upper-layer length, big-endian → split into LE u16 halves.
    let len32 = len as u32;
    let len_be = len32.to_be();
    sum += (len_be & 0xffff) as u32;
    sum += (len_be >> 16) as u32;
    // 3 zero bytes + 1 next_header byte. Same trick as v4: treat
    // as LE u16 (zero | proto<<8) then (zero | zero<<8).
    sum += (proto as u32) << 8;
    // (no extra word needed — the high two bytes of the next-
    // header field area sum to zero.)

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
        assert_eq!(Ipv4Addr::BROADCAST.addr, 0xFFFF_FFFF);
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
    fn ipv6_link_local_from_mac_eui64() {
        // RFC 4291 Appendix A example: MAC 02:00:00:00:00:01 →
        // EUI-64 with universal/local bit flipped (0x02 → 0x00),
        // resulting interface ID = 0000:00ff:fe00:0001.
        let mac = MacAddr {
            bytes: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        };
        let ll = Ipv6Addr::link_local_from_mac(&mac);
        assert!(ll.is_link_local());
        assert_eq!(
            ll.octets,
            [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01
            ]
        );
    }

    #[test]
    fn ipv6_solicited_node_low_24_bits() {
        // Target fe80::5054:ff:fe12:3456 → solicited-node
        // ff02::1:ff12:3456 (low 24 bits of target).
        let target = Ipv6Addr {
            octets: [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x52, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56,
            ],
        };
        let sn = Ipv6Addr::solicited_node(&target);
        assert!(sn.is_multicast());
        assert_eq!(
            sn.octets,
            [
                0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, 0x12, 0x34, 0x56
            ]
        );
    }

    #[test]
    fn ipv6_multicast_mac() {
        // ff02::1 → 33:33:00:00:00:01 (RFC 2464 §7).
        let mac = Ipv6Addr::ALL_NODES_LL.multicast_mac();
        assert_eq!(mac.bytes, [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn ipv6_classification() {
        assert!(Ipv6Addr::ALL_NODES_LL.is_multicast());
        assert!(!Ipv6Addr::ALL_NODES_LL.is_link_local());
        let ll = Ipv6Addr::from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(ll.is_link_local());
        assert!(!ll.is_multicast());
    }

    #[test]
    fn ip_addr_family_predicates() {
        let v4: IpAddr = Ipv4Addr::from(10, 0, 0, 1).into();
        let v6: IpAddr =
            Ipv6Addr::from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).into();
        assert!(v4.is_v4());
        assert!(!v4.is_v6());
        assert!(v6.is_v6());
        assert!(!v6.is_v4());
    }

    #[test]
    fn tcp_checksum_v6_matches_v6_pseudo_header() {
        // Same input, same output as the spec — verify by placing
        // the returned cksum and re-checksumming to 0.
        let src = Ipv6Addr::from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Addr::from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let payload: [u8; 14] = [
            0x12, 0x34, // src port
            0x00, 0x50, // dst port
            0x00, 0x06, // length
            0x00, 0x00, // checksum placeholder
            b'h', b'e', b'l', b'l', b'o', 0,
        ];
        let cksum = tcp_checksum_v6(&src, &dst, 17, payload.as_ptr(), payload.len());
        let mut verified = payload;
        verified[6] = (cksum & 0xff) as u8;
        verified[7] = (cksum >> 8) as u8;
        let recheck = tcp_checksum_v6(&src, &dst, 17, verified.as_ptr(), verified.len());
        assert_eq!(recheck, 0);
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
            0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00,
            0x00, // checksum field = 0
            0xAC, 0x10, 0x0A, 0x63, 0xAC, 0x10, 0x0A, 0x0C,
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
        assert_eq!(
            tcp_checksum(src, dst, 17, verified.as_ptr(), verified.len()),
            0
        );
    }
}
