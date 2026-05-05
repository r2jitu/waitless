// net/ipv6_send.rs — outbound IPv6 packet builder + dispatcher.
//
// IPv6 counterpart to `ipv4_send` in `net/ipv4.rs`. Combines the
// pure wire-format `ipv6::ipv6_build` with NDP MAC resolution and
// `ethernet_send`. Two flavours:
//
//   * `ipv6_send(src, dst, next_header, hop_limit, payload)` —
//     resolves the destination MAC via the NDP cache (or the
//     33:33:* deterministic mapping for multicast). On unicast
//     cache miss, sends a Neighbor Solicitation to the dst's
//     solicited-node multicast and drops the original packet —
//     same pattern as `ipv4_send` on ARP miss. The upper layer
//     (TCP retransmit / UDP best-effort) is responsible for
//     retrying once the NA arrives and the cache fills.
//   * `ipv6_send_to_mac(src, dst, dst_mac, ...)` — caller already
//     knows the destination MAC (e.g. the inbound frame's source
//     for a receive-path reply). Skips NDP entirely.

#![no_std]

extern crate net_ethernet as ethernet;
extern crate net_icmpv6 as icmpv6;
extern crate net_ipv6 as ipv6;
extern crate net_ndp as ndp;
extern crate net_types as types;

use ethernet::ethernet_send;
use ipv6::ETHERTYPE_IPV6;
use types::{Ipv6Addr, MacAddr};

/// Send an IPv6 packet `(src, dst, next_header, hop_limit,
/// payload)`. The destination MAC is computed deterministically
/// for multicast destinations (RFC 2464 §7) or looked up in the
/// NDP cache for unicast. On unicast cache miss the packet is
/// dropped (the packet's owner — typically a TCP/UDP retransmit
/// timer — will retry; the cache fills as inbound frames arrive).
pub fn ipv6_send(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
) {
    let dst_mac = if dst.is_multicast() {
        dst.multicast_mac()
    } else {
        match ndp::ndp_resolve(dst) {
            Some(m) => m,
            None => {
                // Cache miss → fire a Neighbor Solicitation to
                // the dst's solicited-node multicast, drop the
                // original packet. Symmetric with `ipv4_send`'s
                // ARP-miss behaviour: TCP will retransmit once
                // the NA fills the cache; UDP's best-effort
                // semantics handle the loss naturally.
                solicit(src, dst);
                return;
            }
        }
    };
    ipv6_send_to_mac(src, dst, dst_mac, next_header, hop_limit, payload);
}

/// Send a Neighbor Solicitation for `target`. Source = our `src`
/// (typically link-local), destination = solicited-node multicast
/// for `target` (`ff02::1:ffXX:XXXX`). Dst MAC is the deterministic
/// `33:33:ff:XX:XX:XX` mapping (RFC 2464 §7) — no recursive NDP.
/// SLLA option carries our MAC so the peer can reply with an NA
/// directly to us without itself doing a lookup first.
fn solicit(src: &Ipv6Addr, target: &Ipv6Addr) {
    let our_mac = ethernet::ethernet_our_mac();
    if our_mac == MacAddr::ZERO {
        return; // no NIC initialised → can't solicit
    }
    let snm = Ipv6Addr::solicited_node(target);
    let mut icmp = [0u8; 32];
    let n = match icmpv6::build_neighbor_solicitation(src, &snm, target, &our_mac, &mut icmp) {
        Some(n) => n,
        None => return,
    };
    let mut buf = [0u8; 1500];
    let total = match ipv6::ipv6_build(src, &snm, ipv6::next_header::ICMPV6, 255, &icmp[..n], &mut buf) {
        Some(t) => t,
        None => return,
    };
    ethernet_send(snm.multicast_mac(), ETHERTYPE_IPV6, &buf[..total]);
}

/// Send an IPv6 packet to a known MAC. Used by the receive-path
/// reply pattern (NA, Echo Reply, ICMPv6 errors): the inbound
/// frame's source MAC is fresh and reliable, so we sidestep NDP.
pub fn ipv6_send_to_mac(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    dst_mac: MacAddr,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
) {
    let mut buf = [0u8; 1500];
    let n = match ipv6::ipv6_build(src, dst, next_header, hop_limit, payload, &mut buf) {
        Some(n) => n,
        None => return,
    };
    ethernet_send(dst_mac, ETHERTYPE_IPV6, &buf[..n]);
}
