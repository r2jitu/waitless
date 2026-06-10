// net/types.rs — Network types, byte order, and config.
//
// This module has no dependencies on other net/ modules or external crates.
// It can be compiled as a standalone crate (//crates/net:types).

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

// ── Protocol numbers ─────────────────────────────────────────────────────────

/// IANA protocol numbers — the IPv4 `protocol` byte and the IPv6
/// `next_header` byte share one numeric space. Direction- and
/// family-neutral: the RX L4 dispatch, the TX header builders, and
/// both IP modules all refer to these.
pub mod proto {
    pub const ICMPV4: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
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

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new()
    }
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

// ── IPv4 next-hop selection ──────────────────────────────────────────────────

/// `next_hop_v4` found no usable next hop: the destination is
/// off-link and no gateway is configured. Distinguishable from a
/// neighbor-resolution failure (the next hop is known but its MAC
/// never resolved) — that's `arp::ResolveError::Timeout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoRoute;

/// The IPv4 routing decision — which IP do we put on the local link
/// to reach `dest`? On-link (`dest & mask == our_net & mask`) →
/// `dest` itself; off-link → the configured gateway. Lives here,
/// next to the DHCP-recorded facts (`NetConfig`) it consults, so the
/// sync ARP path (`arp_resolve`) and the async resolver
/// (`arp::resolve_route`) share one copy of the policy.
///
/// Edge cases, deliberately:
///   * limited broadcast (255.255.255.255) never crosses a router —
///     always on-link;
///   * an all-zero mask (unconfigured, or a deliberate /0) makes
///     everything on-link, matching the stack's pre-DHCP behavior.
pub fn next_hop_v4(dest: Ipv4Addr, cfg: &NetConfig) -> Result<Ipv4Addr, NoRoute> {
    if dest == Ipv4Addr::BROADCAST {
        return Ok(dest);
    }
    let mask = cfg.subnet_mask.addr;
    if (dest.addr & mask) == (cfg.ip.addr & mask) {
        return Ok(dest);
    }
    if cfg.gateway != Ipv4Addr::ANY {
        return Ok(cfg.gateway);
    }
    Err(NoRoute)
}

impl ConfigStore {
    /// [`next_hop_v4`] against the live configuration.
    pub fn next_hop(&self, dest: Ipv4Addr) -> Result<Ipv4Addr, NoRoute> {
        next_hop_v4(dest, &self.load())
    }
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

    fn cfg(ip: [u8; 4], mask: [u8; 4], gw: [u8; 4]) -> NetConfig {
        NetConfig {
            ip: Ipv4Addr::from(ip[0], ip[1], ip[2], ip[3]),
            subnet_mask: Ipv4Addr::from(mask[0], mask[1], mask[2], mask[3]),
            gateway: Ipv4Addr::from(gw[0], gw[1], gw[2], gw[3]),
            dns: Ipv4Addr::ANY,
        }
    }

    #[test]
    fn next_hop_on_link_is_dest() {
        let c = cfg([10, 0, 2, 15], [255, 255, 255, 0], [10, 0, 2, 2]);
        let dest = Ipv4Addr::from(10, 0, 2, 99);
        assert_eq!(next_hop_v4(dest, &c), Ok(dest));
    }

    #[test]
    fn next_hop_off_link_is_gateway() {
        let c = cfg([10, 0, 2, 15], [255, 255, 255, 0], [10, 0, 2, 2]);
        let dest = Ipv4Addr::from(93, 184, 216, 34);
        assert_eq!(next_hop_v4(dest, &c), Ok(Ipv4Addr::from(10, 0, 2, 2)));
    }

    #[test]
    fn next_hop_off_link_no_gateway_is_no_route() {
        let c = cfg([10, 0, 2, 15], [255, 255, 255, 0], [0, 0, 0, 0]);
        assert_eq!(
            next_hop_v4(Ipv4Addr::from(93, 184, 216, 34), &c),
            Err(NoRoute)
        );
    }

    #[test]
    fn next_hop_zero_mask_is_always_on_link() {
        // Pre-DHCP (all-zero config) and deliberate /0 alike: no
        // destination is ever routed through a gateway.
        let c = cfg([10, 0, 2, 15], [0, 0, 0, 0], [0, 0, 0, 0]);
        let dest = Ipv4Addr::from(93, 184, 216, 34);
        assert_eq!(next_hop_v4(dest, &c), Ok(dest));
    }

    #[test]
    fn next_hop_slash32_mask_routes_everyone_but_self() {
        let c = cfg([10, 0, 2, 15], [255, 255, 255, 255], [10, 0, 2, 2]);
        let me = Ipv4Addr::from(10, 0, 2, 15);
        assert_eq!(next_hop_v4(me, &c), Ok(me));
        let neighbor = Ipv4Addr::from(10, 0, 2, 16);
        assert_eq!(next_hop_v4(neighbor, &c), Ok(Ipv4Addr::from(10, 0, 2, 2)));
    }

    #[test]
    fn next_hop_subnet_boundary_edges() {
        // /30: network 10.0.2.12, hosts .13/.14, broadcast .15 —
        // .16 is the next block over and must route via the gateway.
        let c = cfg([10, 0, 2, 13], [255, 255, 255, 252], [10, 0, 2, 14]);
        let in_net = Ipv4Addr::from(10, 0, 2, 14);
        assert_eq!(next_hop_v4(in_net, &c), Ok(in_net));
        assert_eq!(
            next_hop_v4(Ipv4Addr::from(10, 0, 2, 16), &c),
            Ok(Ipv4Addr::from(10, 0, 2, 14))
        );
    }

    #[test]
    fn next_hop_limited_broadcast_is_on_link() {
        // Even off-subnet by mask math, 255.255.255.255 never routes.
        let c = cfg([10, 0, 2, 15], [255, 255, 255, 0], [10, 0, 2, 2]);
        assert_eq!(
            next_hop_v4(Ipv4Addr::BROADCAST, &c),
            Ok(Ipv4Addr::BROADCAST)
        );
        // And without a gateway it still must not be NoRoute.
        let c = cfg([10, 0, 2, 15], [255, 255, 255, 0], [0, 0, 0, 0]);
        assert_eq!(
            next_hop_v4(Ipv4Addr::BROADCAST, &c),
            Ok(Ipv4Addr::BROADCAST)
        );
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
}
