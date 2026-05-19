// net/checksum.rs — RFC 1071 internet checksum + the L4
// (TCP/UDP/ICMPv6) pseudo-header checksums.
//
// Pure arithmetic leaf: depends only on `net_types` for the address
// types and byte-order helpers. Host-testable. Carved out of
// `net_types` so the checksum math is a crate with one job, rather
// than a fourth concern stuffed into the types grab-bag.

#![cfg_attr(not(test), no_std)]

extern crate net_types as types;

use types::{IpAddr, Ipv4Addr, Ipv6Addr, htons};

/// Sum a `len`-byte buffer as little-endian 16-bit words into a
/// one's-complement accumulator; a trailing odd byte is the low byte
/// of a final word. Pair with [`fold`] to finish a checksum.
fn sum_words(data: *const u8, len: usize) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < len {
        sum += unsafe { (*data.add(i) as u16) | ((*data.add(i + 1) as u16) << 8) } as u32;
        i += 2;
    }
    if i < len {
        sum += unsafe { *data.add(i) as u32 };
    }
    sum
}

/// Fold a one's-complement accumulator down to 16 bits.
fn fold(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// RFC 1071 internet checksum over a byte buffer. Sums 16-bit words
/// in little-endian byte order, so the returned `u16` drops straight
/// into a network-order `repr(C, packed)` field.
///
/// Two call sites, identical arithmetic. `ipv4::fill_header` runs it
/// over the 20-byte IPv4 header (checksum field zeroed). A driver
/// that has to finish an L4 checksum in software — the device never
/// negotiated CSUM offload — runs it over the L4 segment, whose
/// checksum field already holds the pseudo-header partial sum from
/// [`l4_pseudo_partial`]: summing the segment folds that partial
/// straight in, yielding the value a NEEDS_CSUM device would write.
pub fn internet_checksum(data: *const u8, len: usize) -> u16 {
    !fold(sum_words(data, len))
}

/// 16-bit one's-complement pseudo-header partial sum (no
/// invert), suitable for placement in the L4 checksum field
/// before handing the frame to a NIC that supports
/// `VIRTIO_NET_HDR_F_NEEDS_CSUM` (or equivalent CSUM-offload).
/// The device adds the data checksum to this value and writes
/// the final 16-bit checksum at the same offset.
///
/// Cheaper than `l4_checksum` because it skips the data
/// pass — that's the whole point of CSUM-offload.
#[inline]
pub fn l4_pseudo_partial(src: IpAddr, dst: IpAddr, proto: u8, l4_len: usize) -> u16 {
    let sum: u32 = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut s32: u32 = 0;
            s32 += (s.addr & 0xFFFF) as u32;
            s32 += (s.addr >> 16) as u32;
            s32 += (d.addr & 0xFFFF) as u32;
            s32 += (d.addr >> 16) as u32;
            s32 += (proto as u32) << 8; // proto byte in LE high
            s32 += htons(l4_len as u16) as u32;
            s32
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut s32: u32 = 0;
            for chunk in s.octets.chunks(2).chain(d.octets.chunks(2)) {
                s32 += u16::from_le_bytes([chunk[0], chunk[1]]) as u32;
            }
            let len_be = (l4_len as u32).to_be();
            s32 += (len_be & 0xffff) as u32;
            s32 += (len_be >> 16) as u32;
            s32 += (proto as u32) << 8;
            s32
        }
        _ => 0, // mismatched families — caller bug; safe fallback
    };
    fold(sum)
}

/// TCP/UDP pseudo-header checksum, family-dispatched.
/// `src`/`dst` must agree on family; mismatched families fall back
/// to `l4_checksum_v4` on the v4 component (caller bug).
pub fn l4_checksum(src: IpAddr, dst: IpAddr, proto: u8, data: *const u8, len: usize) -> u16 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => l4_checksum_v4(s, d, proto, data, len),
        (IpAddr::V6(s), IpAddr::V6(d)) => l4_checksum_v6(&s, &d, proto, data, len),
        // Mismatched families — should never happen in correct code.
        // Use whichever is v4 to keep the response well-formed
        // rather than crashing.
        (IpAddr::V4(s), _) => l4_checksum_v4(s, Ipv4Addr::ANY, proto, data, len),
        (_, IpAddr::V4(d)) => l4_checksum_v4(Ipv4Addr::ANY, d, proto, data, len),
    }
}

/// TCP/UDP pseudo-header checksum over IPv6 (RFC 8200 §8.1).
/// Returns the one's-complement folded sum suitable for direct
/// placement in the upper-layer checksum field — same convention
/// as the IPv4 `l4_checksum_v4`.
pub fn l4_checksum_v6(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    proto: u8,
    data: *const u8,
    len: usize,
) -> u16 {
    // IPv6 pseudo-header: src(16) || dst(16) || u32 upper-len ||
    // 3 zeros || u8 next-header. Sum as LE u16 words to match the
    // existing `l4_checksum_v4` byte-order convention (the result is
    // stored directly in a `repr(C, packed)` u16 field).
    let mut sum: u32 = 0;
    for chunk in src.octets.chunks(2).chain(dst.octets.chunks(2)) {
        sum += u16::from_le_bytes([chunk[0], chunk[1]]) as u32;
    }
    // u32 upper-layer length, big-endian → split into LE u16 halves.
    let len32 = len as u32;
    let len_be = len32.to_be();
    sum += (len_be & 0xffff) as u32;
    sum += (len_be >> 16) as u32;
    // 3 zero bytes + 1 next_header byte. Same trick as v4: treat
    // as LE u16 (zero | proto<<8) then (zero | zero<<8).
    sum += (proto as u32) << 8;
    // (no extra word needed — the high two bytes of the next-
    // header field area sum to zero.)
    !fold(sum + sum_words(data, len))
}

/// TCP/UDP pseudo-header checksum.
/// Pseudo-header + data summed in LE byte order.
pub fn l4_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, data: *const u8, len: usize) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header — read addr fields as LE 16-bit words
    sum += (src.addr & 0xFFFF) as u32;
    sum += (src.addr >> 16) as u32;
    sum += (dst.addr & 0xFFFF) as u32;
    sum += (dst.addr >> 16) as u32;
    sum += (proto as u32) << 8; // zero byte | proto byte, LE word
    sum += htons(len as u16) as u32; // length in network byte order, stored LE

    // Data summed in the same LE word order.
    !fold(sum + sum_words(data, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l4_checksum_v6_matches_v6_pseudo_header() {
        // Same input, same output as the spec — verify by placing
        // the returned cksum and re-checksumming to 0.
        let src = Ipv6Addr::from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let dst = Ipv6Addr::from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let payload: [u8; 14] = [
            0x12, 0x34, // src port
            0x00, 0x50, // dst port
            0x00, 0x06, // length
            0x00, 0x00, // checksum placeholder
            b'h', b'e', b'l', b'l', b'o', 0,
        ];
        let cksum = l4_checksum_v6(&src, &dst, 17, payload.as_ptr(), payload.len());
        let mut verified = payload;
        verified[6] = (cksum & 0xff) as u8;
        verified[7] = (cksum >> 8) as u8;
        let recheck = l4_checksum_v6(&src, &dst, 17, verified.as_ptr(), verified.len());
        assert_eq!(recheck, 0);
    }

    #[test]
    fn internet_checksum_zeros() {
        // All-zero data should checksum to 0xFFFF
        let data = [0u8; 20];
        assert_eq!(internet_checksum(data.as_ptr(), data.len()), 0xFFFF);
    }

    #[test]
    fn internet_checksum_ones() {
        // All-0xFF data (20 bytes = 10 words of 0xFFFF)
        // Folded sum = 0xFFFF, complement = 0x0000
        let data = [0xFFu8; 20];
        assert_eq!(internet_checksum(data.as_ptr(), data.len()), 0x0000);
    }

    #[test]
    fn internet_checksum_odd_length() {
        let data = [0x01, 0x02, 0x03];
        // sum = 0x0201 + 0x03 = 0x0204, complement = 0xFDFB
        assert_eq!(internet_checksum(data.as_ptr(), data.len()), 0xFDFB);
    }

    #[test]
    fn internet_checksum_verification() {
        // Compute checksum of an IPv4-like header, then verify it
        // produces 0 when re-checked with the checksum filled in.
        let hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00,
            0x00, // checksum field = 0
            0xAC, 0x10, 0x0A, 0x63, 0xAC, 0x10, 0x0A, 0x0C,
        ];
        let cksum = internet_checksum(hdr.as_ptr(), hdr.len());
        // Fill in checksum (LE byte order) and re-verify
        let mut verified = hdr;
        verified[10] = (cksum & 0xFF) as u8;
        verified[11] = (cksum >> 8) as u8;
        assert_eq!(internet_checksum(verified.as_ptr(), verified.len()), 0);
    }

    #[test]
    fn udp_checksum_verification() {
        // Build a UDP pseudo-header + payload and verify the checksum.
        let src = Ipv4Addr::from(10, 0, 2, 15);
        let dst = Ipv4Addr::from(10, 0, 2, 2);
        // UDP header (8 bytes): src_port=5000, dst_port=80, len=13, cksum=0
        // + payload "hello" (5 bytes) = 13 bytes total
        let udp_data: [u8; 13] = [
            0x13, 0x88, // src_port = 5000 (big-endian)
            0x00, 0x50, // dst_port = 80
            0x00, 0x0D, // length = 13
            0x00, 0x00, // checksum = 0 (to be computed)
            b'h', b'e', b'l', b'l', b'o',
        ];
        let cksum = l4_checksum_v4(src, dst, 17, udp_data.as_ptr(), udp_data.len());
        // Fill in and re-verify
        let mut verified = udp_data;
        verified[6] = (cksum & 0xFF) as u8;
        verified[7] = (cksum >> 8) as u8;
        assert_eq!(
            l4_checksum_v4(src, dst, 17, verified.as_ptr(), verified.len()),
            0
        );
    }
}
