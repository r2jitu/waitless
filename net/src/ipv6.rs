// net/ipv6.rs — IPv6 packet parsing/building (RFC 8200).
//
// Counterpart to `net/ipv4.rs`, but pure wire-format: no kernel
// or driver dependency, no calls into Ethernet send. The umbrella
// crate (`//net:net`) wires this to `ethernet_send` + the NDP
// MAC resolver. Splitting that way keeps `ipv6.rs` host-testable
// without dragging in `os:none`-only deps.
//
// Scope (Phase 5a):
//   * 40-byte fixed header parse + build (RFC 8200 §3).
//   * `ipv6_build` — fills a caller-supplied buffer with header +
//     payload, returns total length.
//   * `ipv6_parse` — peels the v6 header, returns src/dst/
//     next_header/payload. Pure parse: dst-address policy (is
//     this packet for us?) is the caller's.
//
// Out of scope until needed:
//   * Extension header chain walking (Hop-by-Hop, Routing,
//     Fragment, AH, ESP, Destination). RFC 8200 §4 recommends
//     supporting them; in practice "no extension headers, ever"
//     interoperates with every modern peer.
//   * Path MTU discovery / fragmentation. Caller caps payload at
//     `MAX_PAYLOAD`.

#![no_std]

extern crate net_from_bytes as from_bytes;
extern crate net_types as types;

use from_bytes::FromBytes;
use types::{Ipv6Addr, htons, ntohs};

/// EtherType for IPv6 (RFC 2464).
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Minimum hop limit for outbound traffic when the caller doesn't
/// have a specific value. RFC 4861 §6.2.4 defaults to 64 for most
/// host-to-host traffic; ICMPv6 NDP messages use 255 (handled at
/// the call site).
pub const DEFAULT_HOP_LIMIT: u8 = 64;

/// IPv6 fixed header (RFC 8200 §3). 40 bytes, no checksum,
/// `payload_length` does NOT include the header itself (unlike
/// `total_length` in IPv4).
#[repr(C, packed)]
pub struct Ipv6Header {
    /// 4-bit version (= 6) | 8-bit traffic class | 20-bit flow label.
    /// Stored as a raw u32 in network byte order; helpers below
    /// extract / set the parts.
    pub version_class_flow: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

unsafe impl FromBytes for Ipv6Header {}

pub const HEADER_LEN: usize = 40;

/// The fields `ipv6_parse` extracts from an IPv6 packet — the L3
/// addresses, the next-header / hop-limit, and a borrowed view of
/// the L4 payload. Not the packet itself: it owns no bytes and
/// omits the rest of the wire header (`Ipv6Header`).
pub struct Ipv6Parsed<'a> {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_header: u8,
    pub hop_limit: u8,
    pub payload: &'a [u8],
}

/// Largest payload that fits in a non-fragmented IPv6 packet over
/// the standard 1500-byte Ethernet MTU.
pub const MAX_PAYLOAD: usize = 1500 - HEADER_LEN;

/// Write an IPv6 header in place into `slot` (which must be at
/// least [`HEADER_LEN`] bytes). `payload_len` is the bytes that
/// follow the header (the IPv6 `payload_length` field). Used by
/// upper layers composing `[ETH][IP6][L4][payload]` in one buffer.
#[inline]
pub fn fill_header(
    slot: &mut [u8],
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload_len: u16,
) {
    debug_assert!(slot.len() >= HEADER_LEN);
    // First u32: version(4) | traffic_class(8) | flow_label(20).
    // Always emit version=6, class=0, flow=0 → 0x60000000.
    slot[0..4].copy_from_slice(&0x6000_0000u32.to_be_bytes());
    slot[4..6].copy_from_slice(&htons(payload_len).to_ne_bytes());
    slot[6] = next_header;
    slot[7] = hop_limit;
    slot[8..24].copy_from_slice(&src.octets);
    slot[24..40].copy_from_slice(&dst.octets);
}

/// Build a complete IPv6 packet (header + payload) into `out`.
/// Returns the total bytes written, or `None` if `out` is too
/// small or `payload` exceeds `MAX_PAYLOAD`.
pub fn ipv6_build(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if payload.len() > MAX_PAYLOAD {
        return None;
    }
    let total = HEADER_LEN + payload.len();
    if out.len() < total {
        return None;
    }
    // First u32: version(4) | traffic_class(8) | flow_label(20).
    // We always emit version=6, class=0, flow=0 → 0x60000000 host
    // order, written big-endian into the first 4 bytes.
    out[0..4].copy_from_slice(&0x6000_0000u32.to_be_bytes());
    out[4..6].copy_from_slice(&htons(payload.len() as u16).to_ne_bytes());
    out[6] = next_header;
    out[7] = hop_limit;
    out[8..24].copy_from_slice(&src.octets);
    out[24..40].copy_from_slice(&dst.octets);
    out[HEADER_LEN..total].copy_from_slice(payload);
    Some(total)
}

/// Parse and validate an IPv6 packet's fixed header. Returns `None`
/// only when the bytes are malformed — too short for the 40-byte
/// header, or not version 6. A pure wire parse: whether the packet
/// is addressed to us (dst-address policy) is the caller's call.
/// The IPv6 module is plain L3, so `net_rx`'s `summarize_ipv6`
/// applies the host accept predicate against the returned `dst`;
/// the address policy itself lives in higher layers (NDP / SLAAC /
/// app config).
pub fn ipv6_parse(data: &[u8]) -> Option<Ipv6Parsed<'_>> {
    let hdr = Ipv6Header::try_ref_from(data)?;
    let v_c_f = ntohl_local(hdr.version_class_flow);
    if (v_c_f >> 28) != 6 {
        return None;
    }
    let payload_len = ntohs(hdr.payload_length) as usize;
    // A HW-GRO / RSC / LRO coalesced super-segment (RX item M) arrives
    // as one IPv6 packet whose `payload_length` — a 16-bit field, so
    // ≤ 65535 — can far exceed part 0 of the RX chain; the rest of the
    // payload continues in later chain parts this parser never sees.
    // So `HEADER_LEN + payload_len > data.len()` is deliberately NOT a
    // reject here: clamp the part-0 payload view to the bytes
    // physically present and let `tcp_receive`'s chain walk cover the
    // continuation. For an ordinary single-buffer frame
    // `HEADER_LEN + payload_len <= data.len()`, so `payload_end` is
    // unchanged and any ethernet trailing padding is still trimmed —
    // behaviour-neutral until an RX-offload item delivers a
    // multi-buffer chain. `try_ref_from` already guaranteed
    // `data.len() >= HEADER_LEN`, so `payload_end >= HEADER_LEN`.
    let payload_end = (HEADER_LEN + payload_len).min(data.len());
    Some(Ipv6Parsed {
        src: hdr.src,
        dst: hdr.dst,
        next_header: hdr.next_header,
        hop_limit: hdr.hop_limit,
        payload: &data[HEADER_LEN..payload_end],
    })
}

#[inline]
fn ntohl_local(n: u32) -> u32 {
    u32::from_be(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_build_parse_round_trip() {
        let src = Ipv6Addr {
            octets: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        };
        let dst = Ipv6Addr {
            octets: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02],
        };
        let payload = &[0xde, 0xad, 0xbe, 0xef];
        let mut buf = [0u8; HEADER_LEN + 4];
        let n =
            ipv6_build(&src, &dst, types::proto::ICMPV6, 255, payload, &mut buf).expect("build");
        assert_eq!(n, HEADER_LEN + 4);

        let pkt = ipv6_parse(&buf).expect("parse");
        assert_eq!(pkt.src, src);
        assert_eq!(pkt.dst, dst);
        assert_eq!(pkt.next_header, types::proto::ICMPV6);
        assert_eq!(pkt.hop_limit, 255);
        assert_eq!(pkt.payload, payload);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = 0x40; // version=4 (impossible in v6 header but caught)
        assert!(ipv6_parse(&buf).is_none());
    }

    #[test]
    fn accepts_coalesced_super_segment_length() {
        // RX item M: a HW-GRO / RSC coalesced super-segment hands the
        // IPv6 parse only part 0 of the RX chain — the 40-byte header
        // plus the first slice of payload — while `payload_length`
        // declares the *whole* coalesced length, far more than is
        // physically present. Pre-item-M the `HEADER_LEN + payload_len
        // > data.len()` check rejected this and dropped every
        // super-segment; now the parse clamps the part-0 payload view
        // to the bytes present and accepts it (the continuation rides
        // in later chain parts that `tcp_receive` walks).
        let mut buf = [0u8; HEADER_LEN + 24]; // 40-byte hdr + 24 payload bytes here
        buf[0] = 0x60; // version 6
        // payload_length = 50000: a ~49 KiB coalesced segment whose
        // tail lives in later chain parts the parser never sees.
        buf[4..6].copy_from_slice(&50000u16.to_be_bytes());
        buf[6] = types::proto::TCP;
        let pkt = ipv6_parse(&buf).expect("super-segment accepted");
        assert_eq!(pkt.next_header, types::proto::TCP);
        // Payload view is clamped to what part 0 actually holds — the
        // 24 bytes after the header — not the 50000 declared.
        assert_eq!(pkt.payload.len(), 24);
    }

    #[test]
    fn rejects_too_short_for_header() {
        // The super-segment clamp relaxes the *payload* length check,
        // not the header one: a buffer too short to hold the 40-byte
        // fixed header is still rejected by `try_ref_from`, which
        // guards the header read the clamp relies on.
        let buf = [0x60u8; HEADER_LEN - 1];
        assert!(ipv6_parse(&buf).is_none());
    }
}
