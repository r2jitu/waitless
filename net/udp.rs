// net/udp.rs — UDP send/receive.
//
// Simple datagram protocol — no state machine, no connection tracking.
// Port-based dispatch via registered handlers.

#![no_std]

extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate net_ipv4 as ipv4;

use core::sync::atomic::{AtomicPtr, AtomicU16, Ordering};
use from_bytes::FromBytes;
use types::{Ipv4Addr, CONFIG, tcp_checksum, htons, ntohs};
use ipv4::{ipv4_send, PROTO_UDP};

#[repr(C, packed)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
}

// SAFETY: repr(C, packed), all fields u16.
unsafe impl FromBytes for UdpHeader {}

type UdpHandlerFn = fn([u8; 4], u16, &[u8]);

const MAX_HANDLERS: usize = 8;

/// Port→handler dispatch table. Each slot is `(port, handler_fn)`.
/// Slots are filled in-order during init via `bind()` (single-threaded
/// boot phase); reads happen from any core during packet dispatch.
/// `port = 0` means "empty slot" (UDP port 0 isn't usable for traffic).
///
/// Atomic stores publish each slot in two steps: handler first, then
/// port — so a reader that sees a non-zero port is guaranteed to also
/// see the matching handler (acquire-pair).
static HANDLER_PORTS: [AtomicU16; MAX_HANDLERS] = [
    AtomicU16::new(0), AtomicU16::new(0), AtomicU16::new(0), AtomicU16::new(0),
    AtomicU16::new(0), AtomicU16::new(0), AtomicU16::new(0), AtomicU16::new(0),
];
static HANDLER_FNS: [AtomicPtr<()>; MAX_HANDLERS] = [
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
];

/// Register a handler for incoming UDP packets on a specific port.
/// On QEMU/KVM uses CAS to claim a slot race-free; on vz_compat (where
/// atomic RMW faults) falls back to load+store, which is sound because
/// `bind` runs from app init on the BSP single-threaded.
pub fn bind(port: u16, handler: UdpHandlerFn) {
    if port == 0 { return; }
    for i in 0..MAX_HANDLERS {
        #[cfg(not(vz_compat))]
        let claimed = HANDLER_PORTS[i]
            .compare_exchange(0, port, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok();
        #[cfg(vz_compat)]
        let claimed = if HANDLER_PORTS[i].load(Ordering::Acquire) == 0 {
            HANDLER_PORTS[i].store(port, Ordering::Release);
            true
        } else {
            false
        };

        if claimed {
            HANDLER_FNS[i].store(handler as *mut (), Ordering::Release);
            return;
        }
    }
}

/// Send a UDP datagram.
pub fn send(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]) {
    let udp_len = 8 + data.len();
    if udp_len > 1480 {
        return;
    }

    let dst = Ipv4Addr::from(dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
    let mut buf = core::mem::MaybeUninit::<[u8; 1480]>::uninit();
    let p = buf.as_mut_ptr() as *mut u8;

    unsafe {
        let hdr = &mut *(p as *mut UdpHeader);
        hdr.src_port = htons(src_port);
        hdr.dst_port = htons(dst_port);
        hdr.length = htons(udp_len as u16);
        hdr.checksum = 0;

        core::ptr::copy_nonoverlapping(data.as_ptr(), p.add(8), data.len());

        hdr.checksum = tcp_checksum(CONFIG.ip(), dst, PROTO_UDP, p, udp_len);

        ipv4_send(dst, PROTO_UDP, core::slice::from_raw_parts(p, udp_len));
    }
}

/// Called by the network dispatch layer when protocol == UDP.
pub fn udp_receive(src_ip: Ipv4Addr, _dst_ip: Ipv4Addr, data: &[u8]) {
    let hdr = match UdpHeader::try_ref_from(data) {
        Some(h) => h,
        None => return,
    };
    let dst_port = ntohs(hdr.dst_port);
    let src_port = ntohs(hdr.src_port);
    let udp_len = ntohs(hdr.length) as usize;

    if udp_len < 8 || udp_len > data.len() {
        return;
    }
    let payload = &data[8..udp_len];

    for i in 0..MAX_HANDLERS {
        let p = HANDLER_PORTS[i].load(Ordering::Acquire);
        if p == 0 { continue; }
        if p == dst_port {
            let raw = HANDLER_FNS[i].load(Ordering::Acquire);
            if raw.is_null() { continue; }
            // SAFETY: published by `bind` with the same fn type.
            let h: UdpHandlerFn = unsafe {
                core::mem::transmute::<*mut (), UdpHandlerFn>(raw)
            };
            h(src_ip.octets(), src_port, payload);
            return;
        }
    }
}
