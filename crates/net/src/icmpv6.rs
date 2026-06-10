// net/icmpv6.rs — ICMPv6 + NDP wire format (RFC 4443 + RFC 4861).
//
// Pure wire-format codec for the ICMPv6 messages we actually emit
// or consume on the unikernel:
//
//   128 Echo Request        — incoming `ping6`, we reply with 129.
//   129 Echo Reply          — outgoing reply to 128.
//   133 Router Solicitation — outgoing on bring-up to discover RAs.
//   134 Router Advertisement — incoming, drives SLAAC prefix
//                              selection.
//   135 Neighbor Solicitation  — both directions: incoming asks
//                              "what's the MAC for this IPv6?" and
//                              we answer; outgoing asks the peer.
//   136 Neighbor Advertisement — both directions, mirrors NS.
//
// All ICMPv6 messages use the IPv6 pseudo-header for their
// checksum (RFC 4443 §2.3) — the caller passes (src, dst) in to
// `build_*` and `verify_checksum_*` so the math is computed once.
//
// Out of scope: Multicast Listener Discovery (MLD), Path MTU
// Discovery, Redirects, Time Exceeded, Parameter Problem.
// Modern hosts on a single broadcast domain don't need any of
// these for basic interoperability.

#![no_std]

extern crate net_checksum as checksum;
extern crate net_types as types;

use types::{Ipv6Addr, MacAddr, ntohs};

/// ICMPv6 message types we recognize.
pub mod msg {
    /// RFC 4443 §3.2 Packet Too Big — carries the next-hop MTU; drives
    /// IPv6 Path MTU Discovery (RFC 8201).
    pub const PACKET_TOO_BIG: u8 = 2;
    pub const ECHO_REQUEST: u8 = 128;
    pub const ECHO_REPLY: u8 = 129;
    pub const ROUTER_SOLICITATION: u8 = 133;
    pub const ROUTER_ADVERTISEMENT: u8 = 134;
    pub const NEIGHBOR_SOLICITATION: u8 = 135;
    pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
}

/// NDP option types (RFC 4861 §4.6).
pub mod opt {
    pub const SOURCE_LINK_LAYER_ADDRESS: u8 = 1;
    pub const TARGET_LINK_LAYER_ADDRESS: u8 = 2;
    pub const PREFIX_INFORMATION: u8 = 3;
    pub const MTU: u8 = 5;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpError {
    Truncated,
    BadType,
    BadChecksum,
}

// ============================================================================
// Echo Request / Reply (RFC 4443 §4)
// ============================================================================
//
// Layout (after the 4-byte IPv6-pseudo-protected ICMPv6 header):
//   u8  type        (128 or 129)
//   u8  code        = 0
//   u16 checksum
//   u16 identifier
//   u16 sequence
//   u8* opaque data (echoed verbatim in the reply)

/// Build an Echo Reply for an incoming Echo Request `body`.
/// `body` is the ICMPv6 message starting at byte 0 (type field);
/// we copy bytes 4..end (identifier + sequence + data) verbatim.
/// Returns bytes written into `out`.
pub fn build_echo_reply(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    request_body: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if request_body.len() < 8 || out.len() < request_body.len() {
        return None;
    }
    out[0] = msg::ECHO_REPLY;
    out[1] = 0; // code
    out[2] = 0;
    out[3] = 0; // checksum placeholder
    out[4..request_body.len()].copy_from_slice(&request_body[4..]);
    let cksum = checksum::l4_checksum_v6(
        src,
        dst,
        types::proto::ICMPV6,
        out.as_ptr(),
        request_body.len(),
    );
    out[2..4].copy_from_slice(&cksum.to_ne_bytes());
    Some(request_body.len())
}

// ============================================================================
// Neighbor Solicitation (RFC 4861 §4.3)
// ============================================================================
//
// Layout:
//   u8  type = 135
//   u8  code = 0
//   u16 checksum
//   u32 reserved
//   16  target_address
//   options*    (TLV: u8 type, u8 length-in-units-of-8-bytes, ...)
//
// Source link-layer address option (type 1, length 1) is 8 bytes:
//   u8 1, u8 1, 6 bytes MAC.

const NS_BODY_LEN: usize = 24;
const NA_BODY_LEN: usize = 24;

/// Build a Neighbor Advertisement in response to an NS for our
/// `target` address. `our_mac` is included as the
/// target-link-layer-address option so the peer's NDP cache learns
/// our MAC in one round.
///
/// `flags`: bit 7 (R) router, bit 6 (S) solicited, bit 5 (O)
/// override. Standard host reply has S=1, O=1.
pub fn build_neighbor_advertisement(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    target: &Ipv6Addr,
    our_mac: &MacAddr,
    out: &mut [u8],
) -> Option<usize> {
    const FLAG_SOLICITED: u8 = 0x40;
    const FLAG_OVERRIDE: u8 = 0x20;
    let total = NA_BODY_LEN + 8; // body + TLLA option
    if out.len() < total {
        return None;
    }
    out[0] = msg::NEIGHBOR_ADVERTISEMENT;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0; // checksum placeholder
    out[4] = FLAG_SOLICITED | FLAG_OVERRIDE;
    out[5] = 0;
    out[6] = 0;
    out[7] = 0; // reserved
    out[8..24].copy_from_slice(&target.octets);
    // Target Link-Layer Address option (type 2, length 1 = 8 bytes).
    out[24] = opt::TARGET_LINK_LAYER_ADDRESS;
    out[25] = 1;
    out[26..32].copy_from_slice(&our_mac.bytes);
    let cksum = checksum::l4_checksum_v6(src, dst, types::proto::ICMPV6, out.as_ptr(), total);
    out[2..4].copy_from_slice(&cksum.to_ne_bytes());
    Some(total)
}

/// Build a Neighbor Solicitation for `target` — used when we want
/// to learn the MAC of a peer at IPv6 `target`. `dst` should be
/// `solicited_node(target)`.
pub fn build_neighbor_solicitation(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    target: &Ipv6Addr,
    our_mac: &MacAddr,
    out: &mut [u8],
) -> Option<usize> {
    let total = NS_BODY_LEN + 8; // body + SLLA option
    if out.len() < total {
        return None;
    }
    out[0] = msg::NEIGHBOR_SOLICITATION;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4..8].copy_from_slice(&[0, 0, 0, 0]); // reserved
    out[8..24].copy_from_slice(&target.octets);
    out[24] = opt::SOURCE_LINK_LAYER_ADDRESS;
    out[25] = 1;
    out[26..32].copy_from_slice(&our_mac.bytes);
    let cksum = checksum::l4_checksum_v6(src, dst, types::proto::ICMPV6, out.as_ptr(), total);
    out[2..4].copy_from_slice(&cksum.to_ne_bytes());
    Some(total)
}

/// Build a Router Solicitation. RS is sent with src = link-local
/// (or unspecified ::), dst = ff02::2 (all-routers). Carries an
/// optional source-link-layer-address.
pub fn build_router_solicitation(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    our_mac: &MacAddr,
    out: &mut [u8],
) -> Option<usize> {
    let total = 8 /* RS body */ + 8 /* SLLA option */;
    if out.len() < total {
        return None;
    }
    out[0] = msg::ROUTER_SOLICITATION;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4..8].copy_from_slice(&[0, 0, 0, 0]); // reserved
    out[8] = opt::SOURCE_LINK_LAYER_ADDRESS;
    out[9] = 1;
    out[10..16].copy_from_slice(&our_mac.bytes);
    let cksum = checksum::l4_checksum_v6(src, dst, types::proto::ICMPV6, out.as_ptr(), total);
    out[2..4].copy_from_slice(&cksum.to_ne_bytes());
    Some(total)
}

// ============================================================================
// Inbound parsers
// ============================================================================

/// Parsed view of an incoming Neighbor Solicitation. The target
/// address is what the peer is asking about; we should reply with
/// an NA if it matches one of our addresses.
pub struct NeighborSolicitation<'a> {
    pub target: Ipv6Addr,
    /// Source link-layer address option, if present.
    pub src_lla: Option<MacAddr>,
    /// Raw body bytes — exposed for diagnostics.
    pub raw: &'a [u8],
}

pub fn parse_neighbor_solicitation(body: &[u8]) -> Result<NeighborSolicitation<'_>, IcmpError> {
    if body.len() < NS_BODY_LEN {
        return Err(IcmpError::Truncated);
    }
    if body[0] != msg::NEIGHBOR_SOLICITATION {
        return Err(IcmpError::BadType);
    }
    let mut target_octets = [0u8; 16];
    target_octets.copy_from_slice(&body[8..24]);
    let target = Ipv6Addr {
        octets: target_octets,
    };
    let src_lla = parse_lla_option(&body[NS_BODY_LEN..], opt::SOURCE_LINK_LAYER_ADDRESS);
    Ok(NeighborSolicitation {
        target,
        src_lla,
        raw: body,
    })
}

/// Parsed view of an incoming Router Advertisement (RFC 4861 §4.2)
/// — only the fields SLAAC needs.
pub struct RouterAdvertisement<'a> {
    /// Cur Hop Limit field (host's default outbound hop limit).
    pub cur_hop_limit: u8,
    /// "Managed" + "Other Configuration" flags packed in the byte
    /// after Cur Hop Limit.
    pub flags: u8,
    pub router_lifetime_secs: u16,
    pub reachable_time_ms: u32,
    pub retrans_timer_ms: u32,
    /// Raw bytes from the start of the options section. Caller
    /// iterates via [`iter_prefix_info`] to find Prefix Information
    /// options.
    pub options: &'a [u8],
}

pub fn parse_router_advertisement(body: &[u8]) -> Result<RouterAdvertisement<'_>, IcmpError> {
    if body.len() < 16 {
        return Err(IcmpError::Truncated);
    }
    if body[0] != msg::ROUTER_ADVERTISEMENT {
        return Err(IcmpError::BadType);
    }
    Ok(RouterAdvertisement {
        cur_hop_limit: body[4],
        flags: body[5],
        router_lifetime_secs: u16::from_be_bytes([body[6], body[7]]),
        reachable_time_ms: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
        retrans_timer_ms: u32::from_be_bytes([body[12], body[13], body[14], body[15]]),
        options: &body[16..],
    })
}

/// Prefix Information option (RFC 4861 §4.6.2). 32 bytes total
/// including the type/length prefix.
pub struct PrefixInfo {
    pub prefix_length: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_lifetime_secs: u32,
    pub preferred_lifetime_secs: u32,
    pub prefix: Ipv6Addr,
}

/// Iterate `(option_type, option_body)` pairs in an NDP options
/// blob. `option_body` excludes the 2-byte (type, length) header.
pub fn iter_options(mut bytes: &[u8]) -> impl Iterator<Item = (u8, &[u8])> + '_ {
    core::iter::from_fn(move || {
        if bytes.len() < 2 {
            return None;
        }
        let ty = bytes[0];
        let len_units = bytes[1] as usize;
        if len_units == 0 {
            return None;
        }
        let total = len_units * 8;
        if bytes.len() < total {
            return None;
        }
        let body = &bytes[2..total];
        bytes = &bytes[total..];
        Some((ty, body))
    })
}

/// Find the first Prefix Information option in an RA's options
/// blob. Returns `None` if absent or malformed.
pub fn find_prefix_info(options: &[u8]) -> Option<PrefixInfo> {
    for (ty, body) in iter_options(options) {
        if ty != opt::PREFIX_INFORMATION || body.len() < 30 {
            continue;
        }
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&body[14..30]);
        let flags = body[1];
        return Some(PrefixInfo {
            prefix_length: body[0],
            on_link: flags & 0x80 != 0,
            autonomous: flags & 0x40 != 0,
            valid_lifetime_secs: u32::from_be_bytes([body[2], body[3], body[4], body[5]]),
            preferred_lifetime_secs: u32::from_be_bytes([body[6], body[7], body[8], body[9]]),
            prefix: Ipv6Addr { octets: prefix },
        });
    }
    None
}

/// Verify an inbound ICMPv6 message's checksum against the IPv6
/// pseudo-header. Returns Ok(()) when valid.
pub fn verify_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, body: &[u8]) -> Result<(), IcmpError> {
    if checksum::l4_checksum_v6(src, dst, types::proto::ICMPV6, body.as_ptr(), body.len()) != 0 {
        return Err(IcmpError::BadChecksum);
    }
    Ok(())
}

fn parse_lla_option(mut bytes: &[u8], wanted: u8) -> Option<MacAddr> {
    while bytes.len() >= 8 {
        let ty = bytes[0];
        let len_units = bytes[1];
        if len_units == 0 {
            return None;
        }
        let total = (len_units as usize) * 8;
        if bytes.len() < total {
            return None;
        }
        if ty == wanted && total >= 8 {
            return Some(MacAddr {
                bytes: [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]],
            });
        }
        bytes = &bytes[total..];
    }
    None
}

// `ntohs` happens to be unused here; keep the import path stable.
const _: fn(u16) -> u16 = ntohs;

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_src() -> Ipv6Addr {
        Ipv6Addr {
            octets: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        }
    }
    fn dev_dst() -> Ipv6Addr {
        Ipv6Addr {
            octets: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02],
        }
    }
    fn dev_mac() -> MacAddr {
        MacAddr {
            bytes: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        }
    }

    #[test]
    fn echo_reply_round_trip() {
        let req: [u8; 16] = [
            128, 0, 0, 0, // type, code, cksum=0
            0x12, 0x34, 0, 1, // identifier, sequence
            b'p', b'i', b'n', b'g', b'_', b'd', b'a', b't', // 8 bytes data
        ];
        let mut out = [0u8; 32];
        let n = build_echo_reply(&dev_src(), &dev_dst(), &req, &mut out).expect("build");
        assert_eq!(n, 16);
        assert_eq!(out[0], msg::ECHO_REPLY);
        assert_eq!(out[1], 0);
        // Checksum must verify.
        verify_checksum(&dev_src(), &dev_dst(), &out[..n]).expect("verify");
        // Identifier + sequence + data echoed verbatim.
        assert_eq!(&out[4..16], &req[4..16]);
    }

    #[test]
    fn neighbor_advertisement_includes_tlla_option() {
        let target = dev_src();
        let mut out = [0u8; 64];
        let n = build_neighbor_advertisement(&dev_src(), &dev_dst(), &target, &dev_mac(), &mut out)
            .expect("build");
        assert_eq!(n, 32);
        assert_eq!(out[0], msg::NEIGHBOR_ADVERTISEMENT);
        // Solicited + Override flags set in the first reserved
        // byte of the body.
        assert_eq!(out[4] & 0x60, 0x60);
        // Target address echoed.
        assert_eq!(&out[8..24], &target.octets);
        // TLLA option (type 2, len 1, 6 bytes MAC).
        assert_eq!(out[24], opt::TARGET_LINK_LAYER_ADDRESS);
        assert_eq!(out[25], 1);
        assert_eq!(&out[26..32], &dev_mac().bytes);
        verify_checksum(&dev_src(), &dev_dst(), &out[..n]).expect("verify");
    }

    #[test]
    fn neighbor_solicitation_round_trip() {
        let target = dev_dst();
        let mut buf = [0u8; 64];
        let n = build_neighbor_solicitation(&dev_src(), &dev_dst(), &target, &dev_mac(), &mut buf)
            .expect("build");
        let parsed = parse_neighbor_solicitation(&buf[..n]).expect("parse");
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.src_lla, Some(dev_mac()));
    }

    #[test]
    fn router_advertisement_prefix_extraction() {
        // Hand-build an RA body with a single Prefix Information
        // option carrying 2001:db8::/64 (autonomous + on_link).
        let mut body = [0u8; 16 + 32];
        body[0] = msg::ROUTER_ADVERTISEMENT;
        body[4] = 64; // cur hop limit
        body[5] = 0; // flags
        body[6] = 0x07;
        body[7] = 0x08; // router_lifetime = 1800s
        // Prefix Information at offset 16.
        body[16] = opt::PREFIX_INFORMATION;
        body[17] = 4; // length in 8-byte units → 32 bytes total
        body[18] = 64; // prefix length
        body[19] = 0xc0; // L=1 A=1
        // valid lifetime, preferred lifetime, reserved2 — leave 0.
        // prefix at body[16 + 16..32]: 2001:db8::
        // (the option body after the 2-byte option header is at
        // 18..; prefix sits 16 bytes into THAT, i.e. 18 + 16 = 34).
        body[16 + 16] = 0x20;
        body[16 + 17] = 0x01;
        body[16 + 18] = 0x0d;
        body[16 + 19] = 0xb8;

        let ra = parse_router_advertisement(&body).expect("parse RA");
        assert_eq!(ra.cur_hop_limit, 64);
        let pfx = find_prefix_info(ra.options).expect("prefix info");
        assert_eq!(pfx.prefix_length, 64);
        assert!(pfx.on_link);
        assert!(pfx.autonomous);
        assert_eq!(pfx.prefix.octets[0..4], [0x20, 0x01, 0x0d, 0xb8]);
    }
}
