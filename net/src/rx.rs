//! The RX receive pipeline — Ethernet → L3 → L4 dispatch.
//!
//! One shape, two entry points. `net_receive` is the single-core /
//! Tier-1 callback; `distribute_frame` is the Tier-2 distributor
//! callback (`crate::sched` hands the driver whichever the tier
//! calls for). Both run the same three-step pipeline:
//!
//!   * `classify` — eth + L3 parse, **once**, IPv4 and IPv6 alike,
//!     into a `Classified` verdict. Pure: no snoop, no dispatch.
//!   * `owner` — Tier-2 only: flow-hash the 4-tuple to an owning
//!     core. Tier 1 skips this (the NIC's RSS already distributed).
//!   * `deliver` — snoop the sender + dispatch to L4 (TCP / UDP /
//!     ICMPv6), on the core that owns the frame.
//!
//! The IPv6 control plane (ICMPv6 / NDP / SLAAC) lives in
//! `crate::ipv6_nd`; `deliver` calls into it for ICMPv6.
//!
//! **One chain is one frame.** The driver invokes the callback once
//! per frame; a frame is a single device buffer today, or — once
//! RSC lands (item I) — a hardware-coalesced super-segment spanning
//! several buffers (one chain, several parts). The chain is handled
//! as a unit: headers parse from part 0, and for TCP the whole
//! narrowed chain moves into `tcp::tcp_receive`, which walks every
//! part. The chain — and the device RX buffer(s) it owns — drops
//! when the callback returns (or, for TCP, when `tcp_receive`
//! returns), reposting the buffer(s) via each part's drop callback.

use crate::{arp, ethernet, ipv4, ipv6, ipv6_nd, ndp, sched, tcp, types, udp};
use uni_iobuf::{Chain, OwnedIOBuf};
use uni_kernel::percpu;

// ── Entry points — the tier adapters ────────────────────────────────

/// Single-core / Tier-1 RX callback. Classifies one frame and
/// delivers it on this core. No distribution: single-core has
/// nowhere else to send it, and Tier 1's NIC already hashed the flow
/// to this core's own RX queue.
pub fn net_receive(chain: Chain<OwnedIOBuf>) {
    // Part 0 carries the L2/L3/L4 headers contiguously.
    let Some(first) = chain.iter().next() else {
        return;
    };
    let frame = first.data();
    match classify(frame) {
        Classified::Arp(off) => {
            if let Some(payload) = frame.get(off..) {
                arp::arp_receive(payload);
            }
        }
        Classified::Ip(parsed) => deliver(parsed, chain),
        Classified::Drop => {}
    }
}

/// Tier-2 distributor RX callback — the `NicOps::poll_rx` callback in
/// single-queue mode. Classifies one frame, then for a TCP/UDP packet
/// owned by another core *moves the whole chain* into that core's
/// `rx_inbox` (item C — no frame-byte copy), bundled with the
/// `ParsedL3` so the owning core skips straight to `deliver` with no
/// re-parse. ARP, non-TCP/UDP, and frames this core owns are
/// delivered inline. The owning core drains the inbox via
/// `crate::sched::net_drain_cb`.
pub(crate) fn distribute_frame(chain: Chain<OwnedIOBuf>) {
    let num_cores = percpu::num_cores();
    let my_core = uni_kernel::cpu_id();
    let Some(first) = chain.iter().next() else {
        return;
    };
    let frame = first.data();
    match classify(frame) {
        Classified::Arp(off) => {
            if let Some(payload) = frame.get(off..) {
                arp::arp_receive(payload);
            }
        }
        Classified::Ip(parsed) => {
            // Only TCP/UDP have a 4-tuple to flow-hash and a per-core
            // connection pool to honour. Anything else (ICMPv6, ...)
            // has no owning core — deliver it inline on this one.
            let target = if parsed.proto == ipv4::PROTO_TCP || parsed.proto == ipv4::PROTO_UDP {
                owner(&parsed, frame, num_cores)
            } else {
                my_core
            };
            if target == my_core || num_cores <= 1 {
                deliver(parsed, chain);
            } else {
                // Warm *this* (distributor) core's neighbor cache for
                // the on-link sender — the owning core warms its own
                // when it drains the frame. Then move the chain over.
                snoop(&parsed);
                // SAFETY: `percpu::init()` runs before any AP starts;
                // `target` is bounded by `num_cores`.
                let core = unsafe { percpu::get(target) };
                let rxframe = percpu::RxChain { parsed, chain };
                match percpu::rx_node_pool().distribute(&core.rx_inbox, rxframe) {
                    Ok(()) => {
                        sched::WAKEUP
                            .at(target)
                            .store(true, core::sync::atomic::Ordering::Relaxed);
                    }
                    Err(_frame) => {
                        // Unreachable: the node pool is sized ≥ the RX
                        // queue's buffer count, so a frame in flight
                        // always has a free node (see `rx_inbox`'s
                        // overflow proof). `_frame` drops here, which
                        // auto-reposts its chain's device buffers.
                    }
                }
            }
        }
        Classified::Drop => {}
    }
}

// ── classify — eth + L3 parse, exactly once ─────────────────────────

/// The classification verdict for one received frame, from a single
/// eth + L3 parse. `Copy` and frame-borrow-free: the `Ip` variant's
/// `ParsedL3` references the L4 segment by `(l4_off, l4_len)` rather
/// than by slice, and `Arp` carries a byte offset — so a verdict can
/// outlive the frame borrow and ride a cross-core inbox node.
#[derive(Clone, Copy)]
enum Classified {
    /// ARP — L2.5, no L3/L4, no flow; handled inline on any core.
    /// Carries the byte offset of the ARP payload within the frame
    /// (past the Ethernet header) so the caller re-slices it without
    /// a second parse.
    Arp(usize),
    /// An IP packet — IPv4 or IPv6 — summarised into a `ParsedL3`.
    Ip(types::ParsedL3),
    /// Unparseable, not addressed to us, or an ethertype with no
    /// handler in this stack.
    Drop,
}

/// Parse one frame's L2/L3 headers exactly once. `frame` is part 0
/// of the RX chain — the headers are contiguous there. Pure: the
/// arp/ndp snoop and the L4 dispatch are the caller's job (`deliver`
/// / `distribute_frame`), so the same `classify` serves Tier 1 and
/// Tier 2 with no behavioural fork.
fn classify(frame: &[u8]) -> Classified {
    let Some((src_mac, ethertype, payload)) = ethernet::ethernet_parse_full(frame) else {
        return Classified::Drop;
    };
    match ethertype {
        ethernet::ETHERTYPE_ARP => {
            // `payload` is a sub-slice of `frame`, so this offset is
            // in-bounds by construction.
            Classified::Arp(payload.as_ptr() as usize - frame.as_ptr() as usize)
        }
        ethernet::ETHERTYPE_IPV4 => match parse_ipv4(frame, payload, src_mac) {
            Some(p) => Classified::Ip(p),
            None => Classified::Drop,
        },
        ipv6::ETHERTYPE_IPV6 => match parse_ipv6(frame, payload, src_mac) {
            Some(p) => Classified::Ip(p),
            None => Classified::Drop,
        },
        _ => Classified::Drop,
    }
}

/// Summarise an IPv4 packet into a [`ParsedL3`]. `frame` is part 0's
/// bytes (so the L4 offset is absolute within it); `eth_payload` is
/// the IPv4 packet with the Ethernet header stripped; `src_mac` is
/// the L2 source. `None` for a packet `ipv4_receive` rejects. A
/// non-TCP/UDP IPv4 packet still parses to `Some` — `deliver` no-ops
/// on the protocol, but carrying it keeps the arp-snoop alive.
///
/// [`ParsedL3`]: types::ParsedL3
fn parse_ipv4(
    frame: &[u8],
    eth_payload: &[u8],
    src_mac: types::MacAddr,
) -> Option<types::ParsedL3> {
    let pkt = ipv4::ipv4_receive(eth_payload)?;
    // L4 segment's (offset, len) within part 0 — pointer arithmetic
    // over the backing buffer `pkt.payload` views. Robust across IPv4
    // header options (a fixed header-length constant is not).
    let l4_off = pkt.payload.as_ptr() as usize - frame.as_ptr() as usize;
    let l4_len = pkt.payload.len();
    Some(types::ParsedL3 {
        proto: pkt.protocol,
        src: types::IpAddr::V4(pkt.src),
        dst: types::IpAddr::V4(pkt.dst),
        l4_off,
        l4_len,
        // Snoop only on-subnet senders: off-subnet traffic's L2 src
        // MAC is the gateway's, not the IP's own (see `arp::arp_learn`).
        snoop_mac: if ipv4::same_subnet(pkt.src) {
            Some(src_mac)
        } else {
            None
        },
    })
}

/// Summarise an IPv6 packet into a [`ParsedL3`] — the IPv6 twin of
/// [`parse_ipv4`]. The L4 offset is robust across IPv6 extension
/// headers (a fixed `eth + 40` constant would miss them). `None` for
/// a packet `ipv6_receive` rejects (malformed, or not addressed to
/// one of `our_v6_addrs`).
///
/// [`ParsedL3`]: types::ParsedL3
fn parse_ipv6(
    frame: &[u8],
    eth_payload: &[u8],
    src_mac: types::MacAddr,
) -> Option<types::ParsedL3> {
    let mut addr_buf = [types::Ipv6Addr::ANY; 5];
    let n = ipv6_nd::our_v6_addrs(&mut addr_buf);
    let pkt = ipv6::ipv6_receive(eth_payload, &addr_buf[..n])?;
    let l4_off = pkt.payload.as_ptr() as usize - frame.as_ptr() as usize;
    let l4_len = pkt.payload.len();
    Some(types::ParsedL3 {
        proto: pkt.next_header,
        src: types::IpAddr::V6(pkt.src),
        dst: types::IpAddr::V6(pkt.dst),
        l4_off,
        l4_len,
        // A v6 sender is link-local or same-prefix SLAAC — always
        // on-link — so always snoop it (the pre-merge
        // `ipv6_receive_frame` learned unconditionally too).
        snoop_mac: Some(src_mac),
    })
}

// ── owner — Tier-2 flow → core ──────────────────────────────────────

/// Map a Tier-2 TCP/UDP flow to its owning core. A pure function of
/// the 4-tuple, so every segment of a flow lands on the same core
/// and the per-core TCP connection pool stays consistent. Called
/// only by `distribute_frame`; Tier 1 leaves distribution to the
/// NIC's hardware RSS and never computes this.
fn owner(parsed: &types::ParsedL3, frame: &[u8], num_cores: u32) -> u32 {
    // L4 ports are the first 4 bytes of the segment `classify` located.
    let l4 = frame
        .get(parsed.l4_off..parsed.l4_off + parsed.l4_len)
        .unwrap_or(&[]);
    let (src_port, dst_port) = if l4.len() >= 4 {
        (
            u16::from_be_bytes([l4[0], l4[1]]),
            u16::from_be_bytes([l4[2], l4[3]]),
        )
    } else {
        (0, 0)
    };
    match (parsed.src, parsed.dst) {
        (types::IpAddr::V4(s), types::IpAddr::V4(d)) => {
            flow_hash(s.addr, d.addr, src_port, dst_port, num_cores)
        }
        (types::IpAddr::V6(s), types::IpAddr::V6(d)) => {
            flow_hash_v6(&s.octets, &d.octets, src_port, dst_port, num_cores)
        }
        // A frame is one address family or the other — mixed is
        // impossible (`parse_ipv4`/`parse_ipv6` each yield one).
        _ => 0,
    }
}

/// IPv4 flow hash — FNV-1a over the 4-tuple, Murmur3 `fmix32`
/// finalizer so `% num_cores` stays uniform even when inputs vary in
/// only one field (e.g. wrk's N connections from one src IP to one
/// dst port — without the finalizer all flows collapse to a single
/// core on `num_cores = 2`).
fn flow_hash(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, num_cores: u32) -> u32 {
    let mut h: u32 = 2166136261; // FNV offset basis
    h ^= src_ip;
    h = h.wrapping_mul(16777619);
    h ^= dst_ip;
    h = h.wrapping_mul(16777619);
    h ^= src_port as u32;
    h = h.wrapping_mul(16777619);
    h ^= dst_port as u32;
    h = h.wrapping_mul(16777619);
    // Murmur3 fmix32 — make low bits depend uniformly on the whole input.
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h % num_cores
}

/// IPv6 flow hash — the v6 twin of [`flow_hash`]. Folds the two
/// 16-byte addresses byte-by-byte into the same FNV-1a stream, then
/// the same `fmix32` finalizer. Independent of `flow_hash`: a v4 and
/// a v6 flow need not agree, only each be self-consistent.
fn flow_hash_v6(
    src: &[u8; 16],
    dst: &[u8; 16],
    src_port: u16,
    dst_port: u16,
    num_cores: u32,
) -> u32 {
    let mut h: u32 = 2166136261; // FNV offset basis
    for &b in src.iter().chain(dst.iter()) {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    h ^= src_port as u32;
    h = h.wrapping_mul(16777619);
    h ^= dst_port as u32;
    h = h.wrapping_mul(16777619);
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h % num_cores
}

// ── deliver — L4 dispatch ───────────────────────────────────────────

/// Snoop an on-link sender's L2 MAC into *this* core's neighbor
/// cache — the ARP cache for a v4 frame, the NDP cache for v6. A
/// no-op when `snoop_mac` is `None` (an off-subnet v4 sender, whose
/// L2 MAC is the gateway's; see `parse_ipv4`).
fn snoop(parsed: &types::ParsedL3) {
    match (parsed.snoop_mac, parsed.src) {
        (Some(mac), types::IpAddr::V4(s)) => arp::arp_learn(s, mac),
        (Some(mac), types::IpAddr::V6(s)) => ndp::ndp_learn(s, mac),
        _ => {}
    }
}

/// Deliver a parsed frame to the transport stack — the single place
/// the receive path reaches L4. Runs on the frame's *handling* core:
/// Tier-1 inline, the Tier-2 distributor for a frame it owns, or the
/// owning core after a cross-core inbox drain. Snoops the sender into
/// this core's neighbor cache, then routes by L4 protocol. Consumes
/// `chain` — it drops here (or in `tcp_receive`), reposting buffers.
pub(crate) fn deliver(parsed: types::ParsedL3, chain: Chain<OwnedIOBuf>) {
    snoop(&parsed);
    // Protocol numbers are family-neutral (IANA): TCP 6 / UDP 17 for
    // both v4 and v6, ICMPv6 58 for v6 only.
    match parsed.proto {
        ipv4::PROTO_TCP => {
            tcp_receive_segment(parsed.src, parsed.dst, chain, parsed.l4_off, parsed.l4_len);
        }
        ipv4::PROTO_UDP => {
            // The borrowed segment never outlives `udp_receive` (it
            // runs synchronously); `chain` then drops, reposting.
            let Some(first) = chain.iter().next() else {
                return;
            };
            let Some(segment) = first
                .data()
                .get(parsed.l4_off..parsed.l4_off + parsed.l4_len)
            else {
                return;
            };
            udp::udp_receive(parsed.src, parsed.dst, segment);
        }
        ipv6::next_header::ICMPV6 => {
            // ICMPv6 — meaningful only for a v6 frame. Hand the IPv6
            // control plane the (src, dst, payload, L2 src); the
            // snoop above already warmed the NDP cache.
            if let (types::IpAddr::V6(s), types::IpAddr::V6(d), Some(mac)) =
                (parsed.src, parsed.dst, parsed.snoop_mac)
            {
                let Some(first) = chain.iter().next() else {
                    return;
                };
                if let Some(segment) = first
                    .data()
                    .get(parsed.l4_off..parsed.l4_off + parsed.l4_len)
                {
                    ipv6_nd::handle_icmpv6(&s, &d, segment, mac);
                }
            }
        }
        // Any other L4 protocol — no handler; `chain` drops, reposting.
        _ => {}
    }
}

/// Narrow a received frame's chain down to its TCP segment and hand
/// it to `tcp::tcp_receive` (RX item D). Part 0 — which holds the
/// eth/IP/TCP headers — is narrowed to start at the TCP header and
/// end at the segment's extent; the eth/IP headers and any ethernet
/// trailing padding fall outside the visible window without a byte
/// moving, and the `OwnedIOBuf`'s drop callback still reposts the
/// *whole* device buffer.
///
/// One-part chain today, so this narrows the entire frame down to
/// exactly the TCP segment. A future RSC super-segment (item I) is
/// multi-part — part 0 holds the headers + first payload chunk,
/// parts 1..N the payload continuation. `narrow` then only
/// `consume`s the header bytes off part 0 (the segment outruns part
/// 0, so there is no tail to trim), and `tcp_receive` walks every
/// part — but item I must additionally refresh the chain's cached
/// `total_len` (via `Chain::shrink_total_len`), which a `Single`-repr
/// chain computes live and so does not need today.
fn tcp_receive_segment(
    src: types::IpAddr,
    dst: types::IpAddr,
    mut chain: Chain<OwnedIOBuf>,
    l4_off: usize,
    l4_len: usize,
) {
    // Single-part invariant (see fn doc): `narrow` mutates part 0 via
    // `front_mut`, which bypasses a `Many` chain's cached `total_len`
    // — so a multi-part chain would reach `tcp_receive` with a stale
    // length. Tripwire for item I, which is what first produces
    // multi-part RSC chains: it must narrow chain-aware (refresh
    // `total_len`). Compiled out in release; never trips today.
    debug_assert_eq!(
        chain.part_count(),
        1,
        "multi-part RX chain in tcp_receive_segment: RSC (item I) must \
         refresh the chain's cached total_len after the part-0 narrow",
    );
    let Some(part0) = chain.front_mut() else {
        return;
    };
    if part0.narrow(l4_off, l4_len).is_err() {
        // Unreachable: `l4_off + l4_len` is the end of `pkt.payload`,
        // a sub-slice of part 0, in-bounds by construction.
        // Defensive — `chain` drops here, reposting.
        return;
    }
    tcp::tcp_receive(src, dst, chain);
}
