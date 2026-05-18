//! IPv6 control plane — link-local + SLAAC address state, Router
//! Solicitation / Advertisement handling, and the ICMPv6 service
//! (echo reply, NDP Neighbor Solicitation / Advertisement).
//!
//! Carved out of the crate root so the IPv6 bring-up logic no longer
//! sits interleaved with the RX poll machinery. The receive pipeline
//! (`crate::rx`) calls `our_v6_addrs` to build the dst-address
//! accept-list and `handle_icmpv6` to service an inbound ICMPv6
//! packet; `init_ipv6` is invoked once from `crate::init_stack`.

use crate::{ethernet, icmpv6, ipv6, ipv6_send, types};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// Our link-local IPv6 address, derived from the NIC MAC at
/// `init_ipv6` time via modified EUI-64 (RFC 4291). Stored as 16
/// `AtomicU8`s so a multi-core read-during-init never races.
/// Single writer (BSP at boot); many readers (per-core RX paths).
static IPV6_LL_OCTETS: [AtomicU8; 16] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static IPV6_INITIALIZED: AtomicBool = AtomicBool::new(false);

fn ipv6_ll() -> types::Ipv6Addr {
    let mut o = [0u8; 16];
    for (i, slot) in IPV6_LL_OCTETS.iter().enumerate() {
        o[i] = slot.load(Ordering::Acquire);
    }
    types::Ipv6Addr { octets: o }
}

/// Our SLAAC-assigned global IPv6 address. Populated when a Router
/// Advertisement carrying a Prefix Information option (autonomous
/// flag set) arrives. Same atomic-array shape as the link-local
/// for race-free per-core reads.
static IPV6_GLOBAL_OCTETS: [AtomicU8; 16] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static IPV6_GLOBAL_SET: AtomicBool = AtomicBool::new(false);

fn ipv6_global() -> Option<types::Ipv6Addr> {
    if !IPV6_GLOBAL_SET.load(Ordering::Acquire) {
        return None;
    }
    let mut o = [0u8; 16];
    for (i, slot) in IPV6_GLOBAL_OCTETS.iter().enumerate() {
        o[i] = slot.load(Ordering::Acquire);
    }
    Some(types::Ipv6Addr { octets: o })
}

/// Initialise our IPv6 link-local address from the cached MAC. Idempotent;
/// the BSP calls this once after `ethernet::init_mac`.
pub fn init_ipv6() {
    if IPV6_INITIALIZED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let mac = ethernet::ethernet_our_mac();
    let ll = types::Ipv6Addr::link_local_from_mac(&mac);
    for (i, slot) in IPV6_LL_OCTETS.iter().enumerate() {
        slot.store(ll.octets[i], Ordering::Release);
    }
    uni_kernel::serial::write_fmt(format_args!(
        "[net] ipv6 link-local fe80::{:x}:{:x}:{:x}:{:x}\n",
        u16::from_be_bytes([ll.octets[8], ll.octets[9]]),
        u16::from_be_bytes([ll.octets[10], ll.octets[11]]),
        u16::from_be_bytes([ll.octets[12], ll.octets[13]]),
        u16::from_be_bytes([ll.octets[14], ll.octets[15]]),
    ));
    // Send Router Solicitation to ff02::2 to ask any on-link
    // router to advertise its prefix. RFC 4861 §6.3.7: hosts
    // SHOULD send RS at startup to avoid waiting up to 200 s for
    // an unsolicited RA. Multicast destination → MAC is the
    // deterministic 33:33:00:00:00:02 so we don't need NDP.
    send_router_solicitation();
}

fn send_router_solicitation() {
    let mac = ethernet::ethernet_our_mac();
    let ll = ipv6_ll();
    let dst = types::Ipv6Addr::ALL_ROUTERS_LL;
    let mut icmp = [0u8; 32];
    let n = match icmpv6::build_router_solicitation(&ll, &dst, &mac, &mut icmp) {
        Some(n) => n,
        None => return,
    };
    // Multicast destination → ipv6_send picks the
    // 33:33:00:00:00:02 mapping internally.
    ipv6_send::ipv6_send(&ll, &dst, ipv6::next_header::ICMPV6, 255, &icmp[..n]);
}

/// Process an inbound Router Advertisement. If it carries a
/// Prefix Information option with the autonomous flag set, derive
/// our global address by combining the prefix with the modified
/// EUI-64 interface ID and stash it. The first such RA wins;
/// later RAs with different prefixes are ignored (single-prefix
/// MVP — adding multi-prefix support is a future expansion).
fn handle_router_advertisement(payload: &[u8]) {
    let ra = match icmpv6::parse_router_advertisement(payload) {
        Ok(r) => r,
        Err(_) => return,
    };
    let pfx = match icmpv6::find_prefix_info(ra.options) {
        Some(p) => p,
        None => return,
    };
    if !pfx.autonomous || pfx.prefix_length != 64 {
        // §5.5.3: SLAAC only when A=1 and prefix length is 64
        // (the EUI-64 interface ID is exactly 64 bits).
        return;
    }
    if IPV6_GLOBAL_SET.swap(true, Ordering::AcqRel) {
        return; // already configured
    }
    let mac = ethernet::ethernet_our_mac();
    let ll = types::Ipv6Addr::link_local_from_mac(&mac);
    // Combine: high 64 bits from prefix, low 64 bits from
    // link-local's EUI-64 interface ID.
    let mut o = [0u8; 16];
    o[..8].copy_from_slice(&pfx.prefix.octets[..8]);
    o[8..].copy_from_slice(&ll.octets[8..]);
    for (i, slot) in IPV6_GLOBAL_OCTETS.iter().enumerate() {
        slot.store(o[i], Ordering::Release);
    }
    uni_kernel::serial::write_fmt(format_args!(
        "[net] ipv6 SLAAC: configured {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::{:x}:{:x}:{:x}:{:x}\n",
        o[0],
        o[1],
        o[2],
        o[3],
        o[4],
        o[5],
        o[6],
        o[7],
        u16::from_be_bytes([o[8], o[9]]),
        u16::from_be_bytes([o[10], o[11]]),
        u16::from_be_bytes([o[12], o[13]]),
        u16::from_be_bytes([o[14], o[15]]),
    ));
}

/// Fill `out` with the addresses we accept inbound IPv6 packets
/// to: link-local, its solicited-node multicast, all-nodes
/// link-local (ff02::1), and the SLAAC global (when configured)
/// + its solicited-node group. Returns the number of slots used.
pub(crate) fn our_v6_addrs(out: &mut [types::Ipv6Addr; 5]) -> usize {
    let ll = ipv6_ll();
    out[0] = ll;
    out[1] = types::Ipv6Addr::solicited_node(&ll);
    out[2] = types::Ipv6Addr::ALL_NODES_LL;
    let mut n = 3;
    if let Some(g) = ipv6_global() {
        out[n] = g;
        out[n + 1] = types::Ipv6Addr::solicited_node(&g);
        n += 2;
    }
    n
}

pub(crate) fn handle_icmpv6(
    src: &types::Ipv6Addr,
    dst: &types::Ipv6Addr,
    payload: &[u8],
    src_mac: types::MacAddr,
) {
    if payload.is_empty() {
        return;
    }
    if icmpv6::verify_checksum(src, dst, payload).is_err() {
        return;
    }
    match payload[0] {
        icmpv6::msg::ECHO_REQUEST => {
            // Reply: src = our LL, dst = original src. RFC 4443 §4.2:
            // hop limit 64 (default).
            let mut icmp_out = [0u8; 1500 - ipv6::HEADER_LEN];
            let n = match icmpv6::build_echo_reply(&ipv6_ll(), src, payload, &mut icmp_out) {
                Some(n) => n,
                None => return,
            };
            ipv6_send::ipv6_send_to_mac(
                &ipv6_ll(),
                src,
                src_mac,
                ipv6::next_header::ICMPV6,
                64,
                &icmp_out[..n],
            );
        }
        icmpv6::msg::ROUTER_ADVERTISEMENT => {
            handle_router_advertisement(payload);
        }
        icmpv6::msg::NEIGHBOR_SOLICITATION => {
            let ns = match icmpv6::parse_neighbor_solicitation(payload) {
                Ok(ns) => ns,
                Err(_) => return,
            };
            // Respond if the target is one of our addresses
            // (link-local OR the SLAAC global).
            let is_ours = ns.target == ipv6_ll() || ipv6_global().map_or(false, |g| g == ns.target);
            if !is_ours {
                return;
            }
            let mac = ethernet::ethernet_our_mac();
            // src of the NA echoes the target the peer asked
            // about so they can match it against their NS state.
            let na_src = ns.target;
            let mut icmp_out = [0u8; 64];
            let n = match icmpv6::build_neighbor_advertisement(
                &na_src,
                src,
                &ns.target,
                &mac,
                &mut icmp_out,
            ) {
                Some(n) => n,
                None => return,
            };
            // Send the NA back to the soliciting host. Prefer the
            // SLLA option's MAC if present, falling back to the
            // inbound frame's source MAC.
            let dst_mac = ns.src_lla.unwrap_or(src_mac);
            ipv6_send::ipv6_send_to_mac(
                &na_src,
                src,
                dst_mac,
                ipv6::next_header::ICMPV6,
                255,
                &icmp_out[..n],
            );
        }
        _ => {}
    }
}
