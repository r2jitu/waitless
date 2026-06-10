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

use crate::{arp, ipv6_nd, ndp, sched, tcp, types, udp};
use iobuf::{Chain, OwnedIOBuf};
use kernel_bare::percpu;
use net_classify::{Classified, classify, owner};

// ── Entry points — the tier adapters ────────────────────────────────

/// Single-core / Tier-1 RX callback. Classifies one frame and
/// delivers it on this core. No distribution: single-core has
/// nowhere else to send it, and Tier 1's NIC already hashed the
/// flow to this core's own RX queue. `pub(crate)` because it's
/// passed as a fn pointer to `nic::poll` from within `sched`;
/// no external caller.
pub(crate) fn net_receive(chain: Chain<OwnedIOBuf>) {
    // Part 0 carries the L2/L3/L4 headers contiguously.
    let Some(first) = chain.iter().next() else {
        return;
    };
    let frame = first.data();
    match classify(frame, ipv6_nd::v6_addr_is_ours) {
        Classified::Arp(off) => {
            if let Some(payload) = frame.get(off..) {
                arp::arp_receive(payload);
            }
        }
        Classified::Ip(parsed) => deliver(parsed, chain),
        Classified::Drop => crate::diag::record_classified_drop(frame),
    }
}

/// Tier-2 distributor RX callback — the `Nic::poll_rx` callback in
/// single-queue mode. Classifies one frame, then for a TCP/UDP packet
/// owned by another core *moves the whole chain* into that core's
/// `rx_inbox` (item C — no frame-byte copy), bundled with the
/// `ParsedL3` so the owning core skips straight to `deliver` with no
/// re-parse. ARP, non-TCP/UDP, and frames this core owns are
/// delivered inline. The owning core drains the inbox via
/// `crate::sched::net_drain_cb`.
pub(crate) fn distribute_frame(chain: Chain<OwnedIOBuf>) {
    let num_cores = percpu::num_cores();
    let my_core = kernel_bare::cpu_id();
    let Some(first) = chain.iter().next() else {
        return;
    };
    let frame = first.data();
    match classify(frame, ipv6_nd::v6_addr_is_ours) {
        Classified::Arp(off) => {
            if let Some(payload) = frame.get(off..) {
                arp::arp_receive(payload);
            }
        }
        Classified::Ip(parsed) => {
            // Only TCP/UDP have a 4-tuple to flow-hash and a per-core
            // connection pool to honour. Anything else (ICMPv6, ...)
            // has no owning core — deliver it inline on this one.
            let target = if parsed.proto == types::proto::TCP || parsed.proto == types::proto::UDP {
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
        Classified::Drop => crate::diag::record_classified_drop(frame),
    }
}

// ── deliver — L4 dispatch ───────────────────────────────────────────

/// Snoop an on-link sender's L2 MAC into *this* core's neighbor
/// cache — the ARP cache for a v4 frame, the NDP cache for v6. A
/// no-op when `snoop_mac` is `None` (an off-subnet v4 sender, whose
/// L2 MAC is the gateway's; see `summarize_ipv4`).
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
        types::proto::TCP => {
            tcp_receive_segment(parsed.src, parsed.dst, chain, parsed.l4_off, parsed.l4_len);
        }
        types::proto::UDP => {
            // The borrowed segment never outlives `udp_receive` (it
            // runs synchronously); `chain` then drops, reposting.
            let Some(first) = chain.iter().next() else {
                return;
            };
            let Some(segment) = parsed.l4(first.data()) else {
                return;
            };
            udp::udp_receive(parsed.src, parsed.dst, segment);
        }
        types::proto::ICMPV6 => {
            // ICMPv6 — meaningful only for a v6 frame. Hand the IPv6
            // control plane the (src, dst, payload, L2 src); the
            // snoop above already warmed the NDP cache.
            if let (types::IpAddr::V6(s), types::IpAddr::V6(d), Some(mac)) =
                (parsed.src, parsed.dst, parsed.snoop_mac)
            {
                let Some(first) = chain.iter().next() else {
                    return;
                };
                if let Some(segment) = parsed.l4(first.data()) {
                    ipv6_nd::handle_icmpv6(&s, &d, segment, mac);
                }
            }
        }
        types::proto::ICMPV4 => {
            // ICMPv4 — we act only on Destination-Unreachable /
            // Fragmentation-Needed (RFC 1191 PMTUD); everything else
            // (echo, other unreachables) is parsed-and-ignored.
            let Some(first) = chain.iter().next() else {
                return;
            };
            if let Some(seg) = parsed.l4(first.data())
                && let Some((rip, rport, lport, seq, mss)) = icmpv4_pmtu_report(seg)
                && tcp::note_path_mtu(rip, rport, lport, seq, mss) == tcp::PathMtuOutcome::NoConn
            {
                // Not our flow — RSS hashed the ICMP error by its own
                // header. Route it to the owning core.
                crate::ctrl::broadcast_path_mtu(rip, rport, lport, seq, mss);
            }
        }
        // Any other L4 protocol — no handler; `chain` drops, reposting.
        _ => crate::diag::COUNTERS.unknown_l4.bump(),
    }
}

/// Decode an ICMPv4 Destination-Unreachable / Fragmentation-Needed
/// (type 3, code 4, RFC 1191) into a Path-MTU report — `(remote_ip,
/// remote_port, local_port, quoted_seq, candidate_mss)`, where
/// `candidate_mss = next-hop-MTU − IPv4(20) − TCP(20)`. `None` for any
/// other ICMP type/code, a non-TCP or truncated quoted datagram, or a
/// next-hop MTU below the IPv4 minimum. The quoted datagram was
/// local→peer, so its IPv4 src is ours and dst is the peer.
fn icmpv4_pmtu_report(icmp: &[u8]) -> Option<(types::IpAddr, u16, u16, u32, u16)> {
    // ICMP header (8 B) + quoted IPv4 header (≥ 20) + ≥ 8 B of TCP.
    if icmp.len() < 8 + 20 + 8 || icmp[0] != 3 || icmp[1] != 4 {
        return None;
    }
    // RFC 1191: the low 16 bits of the 32-bit field after the checksum
    // carry the next-hop MTU (the high 16 bits are zero).
    let next_hop_mtu = u16::from_be_bytes([icmp[6], icmp[7]]);
    if next_hop_mtu < 68 {
        return None; // below the IPv4 minimum MTU — bogus / legacy zero
    }
    let ip = &icmp[8..];
    if ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl + 8 || ip[9] != types::proto::TCP {
        return None;
    }
    let peer = types::Ipv4Addr::from(ip[16], ip[17], ip[18], ip[19]); // quoted dst
    let tcp = &ip[ihl..];
    let local_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let remote_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let candidate_mss = next_hop_mtu.saturating_sub(40);
    Some((types::IpAddr::V4(peer), remote_port, local_port, seq, candidate_mss))
}

/// Narrow a received frame's chain down to its TCP segment and hand
/// it to `tcp::tcp_receive` (RX item D). Part 0 — which holds the
/// eth/IP/TCP headers — is narrowed to start at the TCP header and
/// end at the segment's extent; the eth/IP headers and any ethernet
/// trailing padding fall outside the visible window without a byte
/// moving, and the `OwnedIOBuf`'s drop callback still reposts the
/// *whole* device buffer.
///
/// Single- and multi-part chains alike: a non-coalesced frame is one
/// part and the narrow trims the whole frame down to its TCP segment;
/// an RSC super-segment (RX items I + J) is multi-part — part 0 holds
/// the headers + first payload chunk, parts 1..N the payload
/// continuation. `narrow` only `consume`s the header bytes off part 0
/// in that case (the segment outruns part 0, so there's no tail to
/// trim), and `tcp_receive` walks every part. The `shrink_total_len`
/// after the narrow refreshes the chain's cached `total_len` — a no-op
/// for the `Single`-repr (which derives it live) and the load-bearing
/// fix for `Many`.
fn tcp_receive_segment(
    src: types::IpAddr,
    dst: types::IpAddr,
    mut chain: Chain<OwnedIOBuf>,
    l4_off: usize,
    l4_len: usize,
) {
    let Some(part0) = chain.front_mut() else {
        return;
    };
    let before = part0.len();
    if part0.narrow(l4_off, l4_len).is_err() {
        // Unreachable: `l4_off + l4_len` is the end of `pkt.payload`,
        // a sub-slice of part 0, in-bounds by construction.
        // Defensive — `chain` drops here, reposting.
        return;
    }
    // `narrow` mutated part 0 via `front_mut`, which bypasses a `Many`
    // chain's cached `total_len`; subtract the bytes it trimmed off
    // part 0 so a multi-part RSC chain reaches `tcp_receive` with the
    // correct length. No-op for `Single`/`Empty`.
    let trimmed = before - part0.len();
    chain.shrink_total_len(trimmed);
    tcp::tcp_receive(src, dst, chain);
}
