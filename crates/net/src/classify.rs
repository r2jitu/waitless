// net/classify.rs — the RX classify stage + Tier-2 flow distribution.
//
// Pure leaf crate (`net_classify`): turns a received frame's part-0 bytes
// into a `Classified` verdict — eth + L3 parse, once, IPv4 and IPv6
// alike — and maps a TCP/UDP flow to an owning core. Depends only on
// the pure wire-format leaves (ethernet / ipv4 / ipv6 /
// net_types) — no driver, no kernel — so the verdict logic and the
// flow hash are host-unit-testable.
//
// `net_stack`'s `rx` module is the thin os:none shell around
// this: it supplies the IPv6 dst-address accept-list (a closure,
// called only for v6 frames) and then `deliver`s the verdict to the
// transport stack.

#![cfg_attr(not(test), no_std)]

extern crate net_types as types;

use types::{IpAddr, Ipv6Addr, MacAddr, ParsedL3};

// ── classify — eth + L3 parse, exactly once ─────────────────────────

/// The classification verdict for one received frame, from a single
/// eth + L3 parse. `Copy` and frame-borrow-free: the `Ip` variant's
/// `ParsedL3` references the L4 segment by `(l4_off, l4_len)` rather
/// than by slice, and `Arp` carries a byte offset — so a verdict can
/// outlive the frame borrow and ride a cross-core inbox node.
#[derive(Clone, Copy)]
pub enum Classified {
    /// ARP — L2.5, no L3/L4, no flow; handled inline on any core.
    /// Carries the byte offset of the ARP payload within the frame
    /// (past the Ethernet header) so the caller re-slices it without
    /// a second parse.
    Arp(usize),
    /// An IP packet — IPv4 or IPv6 — summarised into a `ParsedL3`.
    Ip(ParsedL3),
    /// Unparseable, not addressed to us, or an ethertype with no
    /// handler in this stack.
    Drop,
}

/// Byte offset of `inner` within `outer`. `inner` must be a
/// sub-slice of `outer` (it always is here — both come from
/// the same frame buffer).
fn offset_within(outer: &[u8], inner: &[u8]) -> usize {
    inner.as_ptr() as usize - outer.as_ptr() as usize
}

/// One RX frame past the Ethernet parse — the input to the L3
/// summarize step. `l3` is the Ethernet payload (`ipv4_parse` /
/// `ipv6_parse`'s input); `l3_off` is where `l3` sits in the frame's
/// part-0 buffer, the anchor every `ParsedL3.l4_off` is measured
/// from; `src_mac` is the L2 sender, for the neighbor-cache snoop.
/// Borrow-bearing and short-lived — it never escapes `classify`, so
/// unlike `ParsedL3` it can carry the `l3` slice directly.
#[derive(Clone, Copy)]
struct EthFrame<'a> {
    l3_off: usize,
    src_mac: MacAddr,
    l3: &'a [u8],
}

/// Parse one frame's L2/L3 headers exactly once. `frame` is part 0
/// of the RX chain — the headers are contiguous there. Pure: the
/// arp/ndp snoop and the L4 dispatch are the caller's job, so the
/// same `classify` serves Tier 1 and Tier 2 with no behavioural fork.
///
/// `accept_v6` answers "is this IPv6 dst one of ours?" — the host's
/// address policy. It is consulted **only for an IPv6 frame**, so an
/// IPv4 or ARP frame pays nothing for it (the caller passes the
/// os:none `ipv6_nd::v6_addr_is_ours`, which `net_classify` must not depend
/// on).
pub fn classify(frame: &[u8], accept_v6: impl Fn(&Ipv6Addr) -> bool) -> Classified {
    let Some((src_mac, ethertype, l3)) = ethernet::ethernet_parse_full(frame) else {
        return Classified::Drop;
    };
    // `l3` is a sub-slice of `frame`; its offset is the Ethernet
    // header length — the anchor every `ParsedL3.l4_off` is measured
    // from, and the ARP payload's offset directly.
    let eth = EthFrame {
        l3_off: offset_within(frame, l3),
        src_mac,
        l3,
    };
    match ethertype {
        ethernet::ETHERTYPE_ARP => Classified::Arp(eth.l3_off),
        ethernet::ETHERTYPE_IPV4 => summarize_ipv4(eth).map_or(Classified::Drop, Classified::Ip),
        ipv6::ETHERTYPE_IPV6 => {
            summarize_ipv6(eth, accept_v6).map_or(Classified::Drop, Classified::Ip)
        }
        _ => Classified::Drop,
    }
}

/// Summarise an IPv4 packet into a [`ParsedL3`]. `eth` is the frame
/// past the Ethernet parse — `ipv4_parse`'s input and where it sits.
/// A non-TCP/UDP IPv4 packet still summarises to `Some` — the L4
/// dispatch no-ops on the protocol, but carrying it keeps the
/// arp-snoop alive.
fn summarize_ipv4(eth: EthFrame<'_>) -> Option<ParsedL3> {
    let pkt = ipv4::ipv4_parse(eth.l3)?;
    Some(ParsedL3 {
        proto: pkt.protocol,
        src: IpAddr::V4(pkt.src),
        dst: IpAddr::V4(pkt.dst),
        // Frame-relative L4 offset: where the L3 header starts in the
        // frame, plus where L4 starts within L3 (the IPv4 header,
        // robust across its options).
        l4_off: eth.l3_off + offset_within(eth.l3, pkt.payload),
        l4_len: pkt.payload.len(),
        // Snoop only on-subnet senders: off-subnet traffic's L2 src
        // MAC is the gateway's, not the IP's own.
        snoop_mac: if ipv4::same_subnet(pkt.src) {
            Some(eth.src_mac)
        } else {
            None
        },
    })
}

/// Summarise an IPv6 packet into a [`ParsedL3`] — the IPv6 twin of
/// `summarize_ipv4`. `accept_v6` is the host's dst-address policy: a
/// v6 frame whose dst it rejects summarises to `None` (→ `Drop`).
fn summarize_ipv6(eth: EthFrame<'_>, accept_v6: impl Fn(&Ipv6Addr) -> bool) -> Option<ParsedL3> {
    let pkt = ipv6::ipv6_parse(eth.l3)?;
    // `ipv6_parse` is a pure wire parse; applying the dst-address
    // policy is ours. `net_classify` stays a leaf — the predicate is
    // supplied by the os:none caller.
    if !accept_v6(&pkt.dst) {
        return None;
    }
    Some(ParsedL3 {
        proto: pkt.next_header,
        src: IpAddr::V6(pkt.src),
        dst: IpAddr::V6(pkt.dst),
        // Frame-relative L4 offset: where the L3 header starts in the
        // frame, plus where L4 starts within L3.
        l4_off: eth.l3_off + offset_within(eth.l3, pkt.payload),
        l4_len: pkt.payload.len(),
        // A v6 sender is link-local or same-prefix SLAAC — always
        // on-link — so always snoop it.
        snoop_mac: Some(eth.src_mac),
    })
}

// ── owner — Tier-2 flow → core ──────────────────────────────────────

/// Map a Tier-2 TCP/UDP flow to its owning core. A pure function of
/// the 4-tuple, so every segment of a flow lands on the same core
/// and the per-core TCP connection pool stays consistent. Called by
/// the Tier-2 distributor (`net_stack`'s `distribute_frame`);
/// Tier 1 leaves distribution to the NIC's hardware RSS.
pub fn owner(parsed: &ParsedL3, frame: &[u8], num_cores: u32) -> u32 {
    // L4 ports are the first 4 bytes of the segment `classify` located.
    let l4 = parsed.l4(frame).unwrap_or(&[]);
    let (src_port, dst_port) = if l4.len() >= 4 {
        (
            u16::from_be_bytes([l4[0], l4[1]]),
            u16::from_be_bytes([l4[2], l4[3]]),
        )
    } else {
        (0, 0)
    };
    flow_owner(parsed.src, parsed.dst, src_port, dst_port, num_cores)
}

/// Map a raw TCP/UDP 4-tuple to its owning core — THE software flow
/// hash, shared by the Tier-2 RX distributor ([`owner`], which feeds
/// it the parsed inbound frame) and TCP's client-side ephemeral-port
/// picker (`tcp::ephemeral`, which iterates candidate local ports
/// until the tuple hashes back to the connecting core). One function
/// so the two can never disagree: a port chosen at connect time is
/// guaranteed to route the peer's replies to the connecting core on
/// every software-distributed (single-queue) path.
///
/// The tuple is oriented as an INBOUND frame carries it: `src` = the
/// remote peer, `dst` = us, `src_port` = the peer's port, `dst_port`
/// = our local port.
pub fn flow_owner(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, num_cores: u32) -> u32 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            flow_hash_v4(s.addr, d.addr, src_port, dst_port, num_cores)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            flow_hash_v6(&s.octets, &d.octets, src_port, dst_port, num_cores)
        }
        // A frame is one address family or the other — mixed is
        // impossible (the L3 parse yields one or the other).
        _ => 0,
    }
}

/// FNV-1a 32-bit offset basis.
const FNV_BASIS: u32 = 2166136261;

/// One FNV-1a step — fold `v` into the running hash `h`.
fn fnv_step(h: u32, v: u32) -> u32 {
    (h ^ v).wrapping_mul(16777619)
}

/// Murmur3 `fmix32` finalizer — makes every output bit depend
/// uniformly on the whole input, so `% num_cores` spreads evenly
/// even when the 4-tuple varies in only one field (e.g. wrk's N
/// connections from one src IP to one dst port — without it all
/// such flows collapse to a single core on `num_cores = 2`).
fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h
}

/// IPv4 flow hash — FNV-1a over the 4-tuple, then the `fmix32`
/// finalizer (see `fmix32` for why the finalizer earns its keep).
fn flow_hash_v4(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, num_cores: u32) -> u32 {
    let mut h = FNV_BASIS;
    h = fnv_step(h, src_ip);
    h = fnv_step(h, dst_ip);
    h = fnv_step(h, src_port as u32);
    h = fnv_step(h, dst_port as u32);
    fmix32(h) % num_cores
}

/// The IPv6 twin of `flow_hash_v4` — folds the two 16-byte addresses
/// byte-by-byte into the same FNV-1a stream, then the same `fmix32`.
fn flow_hash_v6(
    src: &[u8; 16],
    dst: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    num_cores: u32,
) -> u32 {
    let mut h = FNV_BASIS;
    for &b in src.iter().chain(dst.iter()) {
        h = fnv_step(h, b as u32);
    }
    h = fnv_step(h, src_port as u32);
    h = fnv_step(h, dst_port as u32);
    fmix32(h) % num_cores
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[dst6][src6][ethertype]` + `body`. src MAC = 52:54:00:12:34:56.
    fn eth_frame(ethertype: u16, body: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        f[12..14].copy_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(body);
        f
    }

    /// Minimal IPv4 packet: version 4 / IHL 5, `proto`, `payload`.
    fn ipv4_pkt(proto: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[9] = proto;
        p.extend_from_slice(payload);
        p
    }

    // The IPv6 dst-address accept predicate for tests: accept any.
    fn accept_any(_dst: &Ipv6Addr) -> bool {
        true
    }

    #[test]
    fn classifies_arp() {
        let frame = eth_frame(ethernet::ETHERTYPE_ARP, &[0xaa; 28]);
        match classify(&frame, accept_any) {
            Classified::Arp(off) => assert_eq!(off, 14), // past the eth header
            _ => panic!("expected Arp"),
        }
    }

    #[test]
    fn classifies_ipv4_tcp() {
        // 4 L4 bytes so `owner` can read ports off it.
        let frame = eth_frame(
            ethernet::ETHERTYPE_IPV4,
            &ipv4_pkt(6 /* TCP */, &[0x00, 0x50, 0x30, 0x39]),
        );
        match classify(&frame, accept_any) {
            Classified::Ip(p) => {
                assert!(matches!(p.src, IpAddr::V4(_)));
                assert_eq!(p.proto, 6);
            }
            _ => panic!("expected Ip(v4)"),
        }
    }

    #[test]
    fn classifies_ipv6_tcp() {
        // 40-byte IPv6 header: version 6, payload_length, next_header.
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60; // version 6
        v6[4..6].copy_from_slice(&4u16.to_be_bytes()); // payload_length = 4
        v6[6] = 6; // next_header = TCP
        v6.extend_from_slice(&[0x00, 0x50, 0x30, 0x39]);
        let frame = eth_frame(0x86dd, &v6);
        match classify(&frame, accept_any) {
            Classified::Ip(p) => {
                assert!(matches!(p.src, IpAddr::V6(_)));
                assert_eq!(p.proto, 6);
            }
            _ => panic!("expected Ip(v6)"),
        }
    }

    #[test]
    fn drops_ipv6_dst_not_ours() {
        // A well-formed IPv6/TCP frame whose dst the accept predicate
        // rejects classifies to `Drop`. `ipv6_parse` no longer applies
        // the dst-address policy itself — `summarize_ipv6` does, via
        // the predicate `classify` is handed.
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60; // version 6
        v6[4..6].copy_from_slice(&4u16.to_be_bytes()); // payload_length = 4
        v6[6] = 6; // next_header = TCP
        v6.extend_from_slice(&[0x00, 0x50, 0x30, 0x39]);
        let frame = eth_frame(0x86dd, &v6);
        assert!(matches!(classify(&frame, |_| false), Classified::Drop));
    }

    #[test]
    fn drops_unparseable_and_unknown() {
        // Too short for an Ethernet header.
        assert!(matches!(classify(&[0u8; 8], accept_any), Classified::Drop));
        // Unknown ethertype.
        let frame = eth_frame(0x1234, &[0u8; 20]);
        assert!(matches!(classify(&frame, accept_any), Classified::Drop));
    }

    #[test]
    fn owner_is_deterministic_and_in_range() {
        // A v4 ParsedL3 with the L4 segment at offset 0 of a 4-byte
        // `frame` holding the ports.
        let p = ParsedL3 {
            proto: 6,
            src: IpAddr::V4(types::Ipv4Addr { addr: 0x0a00_0201 }),
            dst: IpAddr::V4(types::Ipv4Addr { addr: 0x0a00_0202 }),
            l4_off: 0,
            l4_len: 4,
            snoop_mac: None,
        };
        let frame = [0x30, 0x39, 0x00, 0x50];
        let core = owner(&p, &frame, 4);
        assert!(core < 4);
        for _ in 0..64 {
            assert_eq!(owner(&p, &frame, 4), core);
        }
    }

    #[test]
    fn owner_spreads_v4_flows() {
        // 256 src ports → 4 cores: every core must be reached (the
        // fmix32 finalizer's whole purpose).
        let mut seen = [false; 4];
        for port in 0u16..256 {
            let p = ParsedL3 {
                proto: 6,
                src: IpAddr::V4(types::Ipv4Addr { addr: 0x0a00_0201 }),
                dst: IpAddr::V4(types::Ipv4Addr { addr: 0x0a00_0202 }),
                l4_off: 0,
                l4_len: 4,
                snoop_mac: None,
            };
            let frame = [(port >> 8) as u8, port as u8, 0x00, 0x50];
            seen[owner(&p, &frame, 4) as usize] = true;
        }
        assert!(seen.iter().all(|&x| x));
    }
}
