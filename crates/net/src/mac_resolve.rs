// net/dst_mac.rs — destination MAC resolution for L4 TX paths.
//
// Both TCP and UDP need to resolve the next-hop MAC address from
// the destination IP before they can fill an Ethernet header. The
// dispatch is the same in both: ARP for v4, NDP multicast-mac /
// cache lookup for v6, broadcast for the unconfigured-IP edge
// case. This module owns the policy so `tcp.rs` and `udp.rs`
// don't carry duplicate copies.
//
// Slow paths that don't go through the unified L2/L3/L4 frame
// builder (ARP itself, DHCP, ICMP) keep using the layered
// `ipv4_send` / `ipv6_send` / `ethernet_send` chain — those
// already handle resolve internally.

#![no_std]

extern crate arp;
extern crate ndp;
extern crate net_types as types;

use types::{CONFIG, IpAddr, Ipv4Addr, MacAddr};

/// Resolve the destination MAC for `dst_ip`. Returns `None` (drop
/// the packet) on ARP/NDP cache miss; the caller's retransmit
/// (TCP) or fire-and-forget semantics (UDP, QUIC) handle the
/// loss.
///
///   * IPv4 unicast → `arp::arp_resolve(dst)`. The
///     unconfigured-IP edge case (boot before DHCP completes)
///     uses Ethernet broadcast, mirroring `ipv4_send`'s
///     behaviour.
///   * IPv6 multicast → deterministic MAC mapping
///     (`MacAddr::33:33:xx:xx:xx:xx`, RFC 2464 §7).
///   * IPv6 unicast → `ndp::ndp_resolve(dst)`. On miss the
///     `ipv6_send`-fast-path used to issue a Neighbor
///     Solicitation and drop; we don't here — the inbound
///     traffic on the same flow fills the cache via passive
///     learning, and the sender's retry covers the gap.
#[inline]
pub fn resolve(dst_ip: IpAddr) -> Option<MacAddr> {
    match dst_ip {
        IpAddr::V4(d) => {
            if CONFIG.ip() == Ipv4Addr::ANY {
                Some(MacAddr::BROADCAST)
            } else {
                arp::arp_resolve(d)
            }
        }
        IpAddr::V6(d) => {
            if d.is_multicast() {
                Some(d.multicast_mac())
            } else {
                ndp::ndp_resolve(&d)
            }
        }
    }
}
