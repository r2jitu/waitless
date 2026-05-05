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
//   * `ipv6_receive` — peels the v6 header, returns src/dst/
//     next_header/payload after dst-address filtering.
//   * `pseudo_checksum` — IPv6 pseudo-header for ICMPv6 / UDP /
//     TCP (RFC 8200 §8.1 + RFC 4443 §2.3).
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
use types::{htons, ntohs, Ipv6Addr};

/// EtherType for IPv6 (RFC 2464).
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Next-header byte (= protocol) values we care about. Same
/// numeric space as IPv4 protocol numbers, plus ICMPv6 (58).
pub mod next_header {
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
}

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

/// View into an IPv6 packet returned by `ipv6_receive`.
pub struct Ipv6Packet<'a> {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_header: u8,
    pub hop_limit: u8,
    pub payload: &'a [u8],
}

/// Largest payload that fits in a non-fragmented IPv6 packet over
/// the standard 1500-byte Ethernet MTU.
pub const MAX_PAYLOAD: usize = 1500 - HEADER_LEN;

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

/// Parse and validate an IPv6 packet. Returns `None` if malformed
/// or addressed elsewhere.
///
/// `our_addrs` is the slice of unicast / solicited-node /
/// all-nodes-link-local addresses we accept. The receive path
/// drops packets whose dst isn't in this set. Caller-managed
/// because the IPv6 module is plain L3 — the address policy lives
/// in higher layers (NDP / SLAAC / app config).
pub fn ipv6_receive<'a>(data: &'a [u8], our_addrs: &[Ipv6Addr]) -> Option<Ipv6Packet<'a>> {
    let hdr = Ipv6Header::try_ref_from(data)?;
    let v_c_f = ntohl_local(hdr.version_class_flow);
    if (v_c_f >> 28) != 6 {
        return None;
    }
    let payload_len = ntohs(hdr.payload_length) as usize;
    if HEADER_LEN + payload_len > data.len() {
        return None;
    }
    if !our_addrs.iter().any(|a| *a == hdr.dst) {
        return None;
    }
    Some(Ipv6Packet {
        src: hdr.src,
        dst: hdr.dst,
        next_header: hdr.next_header,
        hop_limit: hdr.hop_limit,
        payload: &data[HEADER_LEN..HEADER_LEN + payload_len],
    })
}

/// IPv6 pseudo-header checksum for ICMPv6 / UDP / TCP. RFC 8200 §8.1
/// defines the input as: src(16) || dst(16) || u32 upper-layer-len ||
/// 3 zero bytes || u8 next-header || upper-layer payload. Returns
/// the one's-complement sum suitable for placement in the
/// upper-layer checksum field.
pub fn pseudo_checksum(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    // src + dst (each 16 bytes = 8 u16 words).
    for chunk in src.octets.chunks(2).chain(dst.octets.chunks(2)) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    // upper-layer-length as u32 — we send small messages so the
    // high 16 bits are always zero.
    let len = payload.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    // Next header byte (already in low byte of the u32 form).
    sum += next_header as u32;
    // Payload: pad with one zero byte if odd-length.
    let mut i = 0;
    while i + 2 <= payload.len() {
        sum += u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
        i += 2;
    }
    if i < payload.len() {
        sum += (payload[i] as u32) << 8;
    }
    // Fold carries.
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let folded = sum as u16;
    // Network-byte-order one's complement, returned in host byte
    // order so callers can `to_be_bytes()` for placement. Same
    // convention as `types::checksum`.
    (!folded).to_be()
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
            ipv6_build(&src, &dst, next_header::ICMPV6, 255, payload, &mut buf).expect("build");
        assert_eq!(n, HEADER_LEN + 4);

        let pkt = ipv6_receive(&buf, &[dst]).expect("parse");
        assert_eq!(pkt.src, src);
        assert_eq!(pkt.dst, dst);
        assert_eq!(pkt.next_header, next_header::ICMPV6);
        assert_eq!(pkt.hop_limit, 255);
        assert_eq!(pkt.payload, payload);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = 0x40; // version=4 (impossible in v6 header but caught)
        let addrs: [Ipv6Addr; 0] = [];
        assert!(ipv6_receive(&buf, &addrs).is_none());
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut buf = [0u8; HEADER_LEN + 1];
        buf[0] = 0x60;
        buf[5] = 8; // payload_length = 8 but only 1 byte of payload follows
        buf[6] = next_header::UDP;
        let our = [Ipv6Addr::ANY];
        assert!(ipv6_receive(&buf, &our).is_none());
    }

    #[test]
    fn rejects_dst_not_ours() {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = 0x60;
        buf[6] = next_header::ICMPV6;
        buf[24 + 15] = 0x42; // dst = ::42
        let our = [Ipv6Addr::ANY]; // ::
        assert!(ipv6_receive(&buf, &our).is_none());
    }

    #[test]
    fn pseudo_checksum_known_answer() {
        // From RFC 4443 §A.2 / by hand: sum a known src + dst +
        // length + next_header + payload, fold, complement. We
        // verify that an icmp_checksum field containing the
        // returned value zeros out when included in a recompute.
        let src = Ipv6Addr {
            octets: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        };
        let dst = Ipv6Addr {
            octets: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02],
        };
        // ICMPv6 echo request body: type=128, code=0, checksum=0,
        // identifier=0x1234, sequence=0x0001, data="abcdefg".
        let mut payload = [0u8; 15];
        payload[0] = 128; // type
        payload[1] = 0;   // code
        // checksum (bytes 2-3) left zero
        payload[4] = 0x12; payload[5] = 0x34;
        payload[6] = 0x00; payload[7] = 0x01;
        payload[8..15].copy_from_slice(b"abcdefg");

        let cksum = pseudo_checksum(&src, &dst, next_header::ICMPV6, &payload);

        // Splice into the payload's checksum field, recompute,
        // expect 0 (the verification convention).
        let mut verified = payload;
        verified[2] = (cksum & 0xff) as u8;
        verified[3] = (cksum >> 8) as u8;
        let recheck = pseudo_checksum(&src, &dst, next_header::ICMPV6, &verified);
        assert_eq!(recheck, 0);
    }
}
