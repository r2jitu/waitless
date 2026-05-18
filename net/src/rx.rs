//! The RX receive pipeline — Ethernet → L3 → L4 dispatch. `net_receive`
//! is the single-core / Tier-1 entry; `distribute_frame` is the Tier-2
//! distributor entry. Which one runs is decided by `crate::sched`; the
//! IPv6 control plane (ICMPv6 / NDP / SLAAC) lives in `crate::ipv6_nd`.

use crate::{arp, ethernet, ipv4, ipv6, ipv6_nd, ndp, sched, tcp, types, udp};
use uni_iobuf::{Chain, OwnedIOBuf};
use uni_kernel::percpu;

/// RX callback for the NIC poll path (`NicOps::poll_rx` / `poll_qp`)
/// — dispatches one received frame through the full stack. This is
/// the single-core and Tier-1 receive entry point, and the ARP / IPv6
/// inline path of the Tier-2 distributor (`distribute_frame`'s
/// `InlineReparse`). Tier 2's IPv4 frames skip this and reach the L4
/// stack through `net_receive_parsed`, reusing the parse the
/// distributor's classify pass already did — but this function funnels
/// its own IPv4 frames through `net_receive_parsed` too, so the
/// arp-snoop + L4 dispatch has exactly one implementation.
///
/// **One chain is one frame.** The driver invokes this callback once
/// per received frame; a frame is a single device buffer today, or —
/// once RSC lands (item I) — a hardware-coalesced super-segment
/// spanning several buffers (one chain, several parts). The chain is
/// therefore handled as a *unit*: the L2/L3/L4 headers are parsed
/// from part 0, and for TCP the whole narrowed chain is moved into
/// `tcp::tcp_receive`, which walks every part for payload. Splitting
/// the chain and re-parsing each part as its own frame would be
/// wrong for RSC — parts 1..N of a super-segment are raw TCP payload
/// continuation, not framed packets.
///
/// The chain — and the device RX buffer(s) it owns — drops when this
/// returns (or, for TCP, when `tcp_receive` returns); that drop
/// reposts the buffer(s) via each part's drop callback.
pub fn net_receive(chain: Chain<OwnedIOBuf>) {
    // Part 0 carries the L2/L3/L4 headers contiguously.
    let Some(first) = chain.iter().next() else {
        return;
    };
    let Some((src_mac, ethertype, payload)) = ethernet::ethernet_parse_full(first.data()) else {
        return;
    };
    match ethertype {
        ethernet::ETHERTYPE_ARP => arp::arp_receive(payload),
        ethernet::ETHERTYPE_IPV4 => {
            // Single-core / Tier-1 parse the IPv4 headers here; Tier 2
            // already parsed them in `classify_for_distribution` and
            // routes through `net_receive_parsed` directly.
            if let Some(parsed) = parse_ipv4(first.data(), payload, src_mac) {
                net_receive_parsed(parsed, chain);
            }
        }
        ipv6::ETHERTYPE_IPV6 => ipv6_receive_frame(chain, src_mac),
        _ => {}
    }
}

/// Receive a frame whose L2/L3 headers are already parsed — the Tier 2
/// fast path. The owning core (a distributed frame, drained from its
/// `rx_inbox`) and the distributor core (an inline IPv4 frame) both
/// reach the L4 stack through here, skipping the eth + IPv4 re-parse
/// `net_receive` would otherwise do a *second* time. `net_receive`
/// funnels its own IPv4 frames through here too, so there is one
/// arp-snoop + L4-dispatch path.
///
/// ARP-snoops `parsed.arp` (the on-subnet sender's MAC) into *this*
/// core's fast-cache. For a distributed frame that is the owning
/// core's cache — a different one than the distributor warmed in
/// `classify_for_distribution` — so it is not the redundant learn the
/// fuse removed. The duplicate the fuse removed was on the *inline*
/// path: classify no longer learns for inline frames, leaving this the
/// single learn on that core.
pub(crate) fn net_receive_parsed(parsed: types::ParsedL3, chain: Chain<OwnedIOBuf>) {
    if let (Some(src_mac), types::IpAddr::V4(src_v4)) = (parsed.arp, parsed.src) {
        arp::arp_learn(src_v4, src_mac);
    }
    dispatch_l4(&parsed, chain);
}

/// Parse the eth-stripped IPv4 packet of a frame into a [`ParsedL3`]
/// — the single L2/L3 parse a Tier-2 frame now gets. `frame` is part
/// 0's bytes (so the L4 offset is absolute within it); `eth_payload`
/// is the IPv4 packet with the ethernet header already stripped;
/// `src_mac` is the L2 source.
///
/// Returns `None` for a packet `ipv4_receive` rejects (malformed, or
/// not addressed to us). A non-TCP/UDP IPv4 packet still parses to
/// `Some` — the stack has no handler for it, but carrying it lets the
/// receive path ARP-snoop an on-subnet sender exactly as the pre-fuse
/// code did; `dispatch_l4` then no-ops on the protocol.
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
    // `pkt.payload` is a sub-slice of `frame`, so the offset is
    // in-bounds by construction.
    let l4_off = pkt.payload.as_ptr() as usize - frame.as_ptr() as usize;
    let l4_len = pkt.payload.len();
    Some(types::ParsedL3 {
        proto: pkt.protocol,
        src: types::IpAddr::V4(pkt.src),
        dst: types::IpAddr::V4(pkt.dst),
        l4_off,
        l4_len,
        // Snoop only on-subnet senders: off-subnet traffic's L2 src MAC
        // is the gateway's, not the IP's own (see `arp::arp_learn`).
        arp: if ipv4::same_subnet(pkt.src) {
            Some(src_mac)
        } else {
            None
        },
    })
}

/// Hand a parsed frame to the L4 stack: narrow the chain to its TCP
/// segment for `tcp_receive`, or slice out the UDP datagram for
/// `udp_receive`. A non-TCP/UDP `proto` falls through — this stack has
/// no other IPv4 L4 handler. Consumes `chain` (it drops here, or in
/// `tcp_receive`, reposting its device buffer).
fn dispatch_l4(parsed: &types::ParsedL3, chain: Chain<OwnedIOBuf>) {
    match parsed.proto {
        ipv4::PROTO_TCP => {
            tcp_receive_segment(parsed.src, parsed.dst, chain, parsed.l4_off, parsed.l4_len);
        }
        ipv4::PROTO_UDP => {
            // The borrowed segment never outlives `udp_receive` (it
            // runs synchronously); `chain` then drops at the end of
            // this arm, reposting its device buffer.
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

/// Tier 2 distributor decision — classify a frame for distribution,
/// parsing its L2/L3 headers exactly once. Returns where the frame
/// should go, carrying a [`ParsedL3`] so the receiving path never
/// re-walks eth + IPv4 (the fuse — see `docs/rx-path-optimizations.md`,
/// "Fuse the Tier-2 classify parse"). ARP / IPv6 fall back to
/// `net_receive`'s own parse via `InlineReparse`.
///
/// Side effect: ARP-snoops on-subnet IPv4 senders of *distributed*
/// frames, warming this (distributor) core's cache regardless of where
/// the frame ends up handled — the comment the pre-fuse code carried.
/// It deliberately does *not* snoop for inline frames: there
/// `net_receive_parsed` does the single learn on this same core, so a
/// learn here would be the redundant one the fuse removed.
///
/// [`ParsedL3`]: types::ParsedL3
fn classify_for_distribution(frame: &[u8], num_cores: u32, my_core: u32) -> ClassifyResult {
    let Some((src_mac, ethertype, payload)) = ethernet::ethernet_parse_full(frame) else {
        return ClassifyResult::Drop;
    };
    match ethertype {
        ethernet::ETHERTYPE_ARP | ipv6::ETHERTYPE_IPV6 => ClassifyResult::InlineReparse,
        ethernet::ETHERTYPE_IPV4 => {
            let Some(parsed) = parse_ipv4(frame, payload, src_mac) else {
                return ClassifyResult::Drop;
            };
            let (src_v4, dst_v4) = match (parsed.src, parsed.dst) {
                (types::IpAddr::V4(s), types::IpAddr::V4(d)) => (s, d),
                // Unreachable: `parse_ipv4` only ever yields V4.
                _ => return ClassifyResult::Drop,
            };
            // Non-TCP/UDP IPv4 (ICMP, ...) has no 4-tuple to hash and
            // no L4 handler — run it inline. `net_receive_parsed` still
            // ARP-snoops an on-subnet sender; `dispatch_l4` no-ops.
            if parsed.proto != ipv4::PROTO_TCP && parsed.proto != ipv4::PROTO_UDP {
                return ClassifyResult::InlineParsed(parsed);
            }
            // Flow-hash the 4-tuple — the L4 ports are the first 4
            // bytes of the segment `parse_ipv4` already located.
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
            let target = flow_hash(src_v4.addr, dst_v4.addr, src_port, dst_port, num_cores);
            if target == my_core || num_cores <= 1 {
                ClassifyResult::InlineParsed(parsed)
            } else {
                // Distributed: warm this (distributor) core's ARP
                // cache for the on-subnet sender — the owning core
                // warms its own when it drains the frame.
                if let Some(mac) = parsed.arp {
                    arp::arp_learn(src_v4, mac);
                }
                ClassifyResult::Distribute(target, parsed)
            }
        }
        _ => ClassifyResult::Drop,
    }
}

/// Where `classify_for_distribution` decided a Tier-2 frame should go.
enum ClassifyResult {
    /// ARP or IPv6 — hand the whole chain to `net_receive` on this
    /// core, which re-parses. Classify stops at the ethertype for
    /// these: they are rare, not the Tier-2 hot path the fuse targets.
    InlineReparse,
    /// IPv4 destined for this core — handle inline via
    /// `net_receive_parsed`, reusing the parse classify just did.
    InlineParsed(types::ParsedL3),
    /// IPv4 TCP/UDP owned by another core — move the chain *and* its
    /// parse into that core's `rx_inbox`; the owning core wakes,
    /// drains it via `net_drain_cb`, and skips straight to the L4
    /// stack with no re-parse.
    Distribute(u32, types::ParsedL3),
    /// Frame is unparseable, not for us, or a wrong ethertype.
    Drop,
}

/// Tier 2 distributor — the `NicOps::poll_rx` callback in
/// single-queue mode. Receives one frame as an owned
/// `Chain<OwnedIOBuf>` and picks a target core: runs the receive
/// path inline for ARP / IPv6 / my-core IPv4, or — for IPv4 owned by
/// another core — *moves the whole chain* into that core's `rx_inbox`
/// (item C), bundled with the L2/L3 parse so the owning core does not
/// re-walk the headers. The move copies no frame bytes; the chain
/// carries its device RX buffers cross-core and reposts them when
/// the owning core drops it after processing.
///
/// A Tier 2 frame is a single-buffer chain, so classification keys
/// on the first part; a hypothetical multi-part chain (item I) is
/// one flow, so part 0's verdict applies to the whole chain.
pub(crate) fn distribute_frame(chain: Chain<OwnedIOBuf>) {
    let num_cores = percpu::num_cores();
    let my_core = uni_kernel::cpu_id();
    let Some(first) = chain.iter().next() else {
        return;
    };
    match classify_for_distribution(first.data(), num_cores, my_core) {
        // ARP / IPv6 — `net_receive` re-parses; the chain drops there.
        ClassifyResult::InlineReparse => net_receive(chain),
        // IPv4 for this core — receive inline, reusing classify's parse.
        ClassifyResult::InlineParsed(parsed) => net_receive_parsed(parsed, chain),
        ClassifyResult::Distribute(target, parsed) => {
            // SAFETY: `percpu::init()` runs before any AP starts;
            // target is bounded by `num_cores`.
            let core = unsafe { percpu::get(target) };
            let frame = percpu::RxChain { parsed, chain };
            match percpu::rx_node_pool().distribute(&core.rx_inbox, frame) {
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
        ClassifyResult::Drop => {}
    }
}

fn ipv6_receive_frame(chain: Chain<OwnedIOBuf>, src_mac: types::MacAddr) {
    let Some(first) = chain.iter().next() else {
        return;
    };
    let Some((_, _, eth_payload)) = ethernet::ethernet_parse_full(first.data()) else {
        return;
    };
    let mut addr_buf = [types::Ipv6Addr::ANY; 5];
    let n = ipv6_nd::our_v6_addrs(&mut addr_buf);
    let pkt = match ipv6::ipv6_receive(eth_payload, &addr_buf[..n]) {
        Some(p) => p,
        None => return,
    };
    // Snoop (peer_v6, peer_mac) into the NDP cache so future
    // server-initiated outbound to this peer doesn't need an active
    // Neighbor Solicitation. Mirrors the IPv4 ARP-snoop pattern.
    ndp::ndp_learn(pkt.src, src_mac);
    match pkt.next_header {
        ipv6::next_header::ICMPV6 => {
            ipv6_nd::handle_icmpv6(&pkt, src_mac);
        }
        proto @ (ipv6::next_header::TCP | ipv6::next_header::UDP) => {
            let src = types::IpAddr::V6(pkt.src);
            let dst = types::IpAddr::V6(pkt.dst);
            if proto == ipv6::next_header::TCP {
                // L4 segment's (offset, len) within the frame —
                // pointer arithmetic over the backing buffer. Robust
                // across IPv6 extension headers (which a fixed
                // `eth + 40` constant would miss).
                let l4_off = pkt.payload.as_ptr() as usize - first.data().as_ptr() as usize;
                let l4_len = pkt.payload.len();
                tcp_receive_segment(src, dst, chain, l4_off, l4_len);
            } else {
                udp::udp_receive(src, dst, pkt.payload);
            }
        }
        _ => {}
    }
}

/// Flow hash: map a 4-tuple to a core index for Tier 2 distribution.
///
/// Tier 2 uses a rotating distributor: any idle core can try_lock the
/// RX_LOCK and become the distributor for one poll cycle. Flows are
/// hashed across all cores, and the current distributor processes its
/// own flows inline while pushing other cores' flows to their inbox.
///
/// Uses FNV-1a over the 4-tuple followed by a Murmur3 fmix32 so that
/// `% num_cores` is uniform even when inputs vary in only one field
/// (e.g. wrk opens N connections from the same src IP to the same
/// dst port — without the finalizer all flows collapse to a single
/// core on `num_cores = 2`, which was masking the multi-core path).
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
