// net/ethernet.rs — Ethernet frame parsing/building.
//
// Layer 2 only: MAC addresses, frame headers, send/receive.
// Protocol dispatch (ARP, IPv4) is handled by callers, not here.

#![no_std]
#![allow(static_mut_refs)]

extern crate net_types as types;
extern crate drivers;

use core::ptr;
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

/// Cached MAC address. Packed into the low 48 bits of an `AtomicU64` so
/// the cross-core publish is data-race-free without depending on
/// `kernel::once::InitOnce` (this leaf crate has no kernel dep).
/// `init_mac` runs once on the BSP after virtio-net init; readers on
/// every core load via Acquire and decode.
static OUR_MAC_PACKED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Cache our MAC address. Called once at boot after virtio-net init.
pub fn init_mac() {
    let mut bytes = [0u8; 6];
    drivers::virtio_net::get_mac(bytes.as_mut_ptr());
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

pub fn ethernet_send(dst: MacAddr, ethertype: u16, payload: &[u8]) {
    // Stack-allocated buffer: safe for multi-core (each core has its own stack).
    // Use MaybeUninit to avoid zeroing 1514 bytes — we fill the header and
    // copy the payload, so the used portion is always initialized.
    let mut buf = core::mem::MaybeUninit::<[u8; 1514]>::uninit();
    unsafe {
        let p = buf.as_mut_ptr() as *mut u8;
        let hdr = &mut *(p as *mut EthernetHeader);
        hdr.dst = dst;
        hdr.src = ethernet_our_mac();
        hdr.ethertype = htons(ethertype);

        let payload_len = payload.len().min(1500);
        ptr::copy_nonoverlapping(payload.as_ptr(), p.add(HEADER_LEN), payload_len);

        drivers::virtio_net::send(core::slice::from_raw_parts(p, HEADER_LEN + payload_len));
    }
}

/// Parse an Ethernet frame into ethertype + payload. Returns None if too short.
pub fn ethernet_parse(frame: &[u8]) -> Option<(u16, &[u8])> {
    if frame.len() < HEADER_LEN {
        return None;
    }
    let hdr = unsafe { &*(frame.as_ptr() as *const EthernetHeader) };
    Some((u16::from_be(hdr.ethertype), &frame[HEADER_LEN..]))
}
