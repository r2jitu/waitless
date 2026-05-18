// net/ethernet.rs — Ethernet frame parsing + header building.
//
// Layer 2 wire format only: MAC addresses, the frame header, parse,
// and in-place header fill. Pure — no driver dependency — so this
// is a host-testable leaf crate (the `net_ipv6` model). The
// os:none send path (`ethernet_send`, `init_mac`) lives in the
// sibling `net_eth_tx` crate, which depends on this one plus
// `//drivers`.

#![cfg_attr(not(test), no_std)]

extern crate net_from_bytes as from_bytes;
extern crate net_types as types;

use from_bytes::FromBytes;
use types::{MacAddr, htons};

pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const HEADER_LEN: usize = 14;

#[repr(C, packed)]
pub struct EthernetHeader {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16, // network byte order
}

// SAFETY: repr(C, packed) (alignment 1) and all fields are POD
// (MacAddr is [u8; 6], ethertype is u16). Any byte pattern is a valid
// EthernetHeader.
unsafe impl FromBytes for EthernetHeader {}

/// Cached MAC address. Packed into the low 48 bits of an `AtomicU64` so
/// the cross-core publish is data-race-free without depending on
/// `uni_kernel::once::InitOnce` (this leaf crate has no kernel dep).
/// `net_eth_tx::init_mac` writes it once on the BSP after virtio-net
/// init via `set_our_mac`; readers on every core load via Acquire.
static OUR_MAC_PACKED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Store the NIC's MAC into the cross-core cache. Called once at boot
/// by `net_eth_tx::init_mac`, which reads the MAC from the driver —
/// the store lives here because the cache static and its readers do.
pub fn set_our_mac(bytes: [u8; 6]) {
    let packed = (bytes[0] as u64)
        | ((bytes[1] as u64) << 8)
        | ((bytes[2] as u64) << 16)
        | ((bytes[3] as u64) << 24)
        | ((bytes[4] as u64) << 32)
        | ((bytes[5] as u64) << 40);
    OUR_MAC_PACKED.store(packed, core::sync::atomic::Ordering::Release);
}

pub fn ethernet_our_mac() -> MacAddr {
    let p = OUR_MAC_PACKED.load(core::sync::atomic::Ordering::Acquire);
    MacAddr {
        bytes: [
            p as u8,
            (p >> 8) as u8,
            (p >> 16) as u8,
            (p >> 24) as u8,
            (p >> 32) as u8,
            (p >> 40) as u8,
        ],
    }
}

/// Write an Ethernet II header in place into `slot` (which must be
/// at least [`HEADER_LEN`] bytes). Used by upper layers composing
/// `[ETH][IP][L4][payload]` in one buffer instead of memcpy'ing
/// through the legacy `ethernet_send` slow path.
#[inline]
pub fn fill_header(slot: &mut [u8], dst: MacAddr, src: MacAddr, ethertype: u16) {
    debug_assert!(slot.len() >= HEADER_LEN);
    // SAFETY: caller ensures `slot.len() >= HEADER_LEN`.
    // `EthernetHeader` is `repr(C, packed)` plain bytes (`FromBytes`).
    unsafe {
        let hdr = &mut *(slot.as_mut_ptr() as *mut EthernetHeader);
        hdr.dst = dst;
        hdr.src = src;
        hdr.ethertype = htons(ethertype);
    }
}

/// Parse an Ethernet frame into ethertype + payload. Returns None if too short.
pub fn ethernet_parse(frame: &[u8]) -> Option<(u16, &[u8])> {
    let hdr = EthernetHeader::try_ref_from(frame)?;
    let ethertype = hdr.ethertype;
    Some((u16::from_be(ethertype), &frame[HEADER_LEN..]))
}

/// Same as `ethernet_parse` but also returns the source MAC. Used by
/// the receive path to seed the ARP fast-cache from any incoming
/// frame, so the first reply doesn't pay an ARP resolve round-trip.
pub fn ethernet_parse_full(frame: &[u8]) -> Option<(MacAddr, u16, &[u8])> {
    let hdr = EthernetHeader::try_ref_from(frame)?;
    Some((hdr.src, u16::from_be(hdr.ethertype), &frame[HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_extracts_src_ethertype_payload() {
        // dst, src=52:54:00:12:34:56, ethertype=0x0806 (ARP), 4 payload bytes.
        let frame = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x08, 0x06,
            0xde, 0xad, 0xbe, 0xef,
        ];
        let (src, ethertype, payload) = ethernet_parse_full(&frame).expect("parse");
        assert_eq!(src.bytes, [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(ethertype, ETHERTYPE_ARP);
        assert_eq!(payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_rejects_short_frame() {
        // Fewer than the 14-byte header — `try_ref_from` must reject.
        let frame = [0u8; 13];
        assert!(ethernet_parse(&frame).is_none());
        assert!(ethernet_parse_full(&frame).is_none());
    }

    #[test]
    fn fill_header_round_trips() {
        let mut buf = [0u8; HEADER_LEN];
        let dst = MacAddr {
            bytes: [1, 2, 3, 4, 5, 6],
        };
        let src = MacAddr {
            bytes: [7, 8, 9, 10, 11, 12],
        };
        fill_header(&mut buf, dst, src, ETHERTYPE_IPV4);
        let (got_src, et, _) = ethernet_parse_full(&buf).expect("parse");
        assert_eq!(got_src.bytes, src.bytes);
        assert_eq!(et, ETHERTYPE_IPV4);
        assert_eq!(&buf[0..6], &dst.bytes);
    }
}
