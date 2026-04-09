// net/arp.rs — ARP cache, request/reply, resolve, announce.

#![no_std]
#![allow(static_mut_refs)]

extern crate net_types as types;
extern crate net_ethernet as ethernet;
extern crate drivers;

use types::{MacAddr, Ipv4Addr, CONFIG, htons, ntohs};
use ethernet::{ethernet_our_mac, ethernet_send, ethernet_parse, ETHERTYPE_ARP};

const ARP_CACHE_SIZE: usize = 64;

#[repr(C, packed)]
struct ArpPacket {
    hw_type: u16,
    proto_type: u16,
    hw_len: u8,
    proto_len: u8,
    operation: u16,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
}

const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;

struct ArpEntry {
    ip: Ipv4Addr,
    mac: MacAddr,
    valid: bool,
}

impl ArpEntry {
    const fn new() -> Self {
        ArpEntry {
            ip: Ipv4Addr::ANY,
            mac: MacAddr::ZERO,
            valid: false,
        }
    }
}

static mut ARP_CACHE: [ArpEntry; ARP_CACHE_SIZE] = [const { ArpEntry::new() }; ARP_CACHE_SIZE];
static mut GATEWAY_MAC: MacAddr = MacAddr::ZERO;
static mut GATEWAY_MAC_VALID: bool = false;

fn arp_lookup(ip: Ipv4Addr) -> Option<MacAddr> {
    unsafe {
        for i in 0..ARP_CACHE_SIZE {
            if ARP_CACHE[i].valid && ARP_CACHE[i].ip == ip {
                return Some(ARP_CACHE[i].mac);
            }
        }
        None
    }
}

fn arp_cache_update(ip: Ipv4Addr, mac: MacAddr) {
    unsafe {
        for i in 0..ARP_CACHE_SIZE {
            if ARP_CACHE[i].valid && ARP_CACHE[i].ip == ip {
                ARP_CACHE[i].mac = mac;
                return;
            }
        }
        for i in 0..ARP_CACHE_SIZE {
            if !ARP_CACHE[i].valid {
                ARP_CACHE[i] = ArpEntry { ip, mac, valid: true };
                return;
            }
        }
        ARP_CACHE[0] = ArpEntry { ip, mac, valid: true };
    }
}

fn arp_request(target_ip: Ipv4Addr) {
    let our_mac = ethernet_our_mac();
    let our_ip = unsafe { CONFIG.ip };

    let pkt = ArpPacket {
        hw_type: htons(1),
        proto_type: htons(0x0800),
        hw_len: 6,
        proto_len: 4,
        operation: htons(ARP_OP_REQUEST),
        sender_mac: our_mac,
        sender_ip: our_ip,
        target_mac: MacAddr::ZERO,
        target_ip,
    };
    let data = unsafe { core::slice::from_raw_parts(&pkt as *const _ as *const u8, 28) };
    ethernet_send(MacAddr::BROADCAST, ETHERTYPE_ARP, data);
    // On VZ (vz_compat), this call stages the ARP request rather than sending
    // it directly. When arp_resolve is spinning (not running the event loop),
    // net_flush_cb never fires, so core 0 stays in WFI until a VirtIO RX
    // interrupt arrives — but that can't happen until the ARP request is sent.
    // One targeted flush_tx_staging call breaks the deadlock by waking core 0.
    // This fires at most 3 times per arp_resolve (once per retry), not thousands.
    drivers::virtio_net::flush_tx_staging();
}

pub fn arp_receive(data: &[u8]) {
    if data.len() < 28 {
        return;
    }
    let pkt = unsafe { &*(data.as_ptr() as *const ArpPacket) };
    let our_ip = unsafe { CONFIG.ip };

    let sender_ip = pkt.sender_ip;
    let sender_mac = pkt.sender_mac;
    let target_ip = pkt.target_ip;
    let operation = pkt.operation;

    if sender_ip != Ipv4Addr::ANY {
        arp_cache_update(sender_ip, sender_mac);
        unsafe {
            if sender_ip == CONFIG.gateway {
                GATEWAY_MAC = sender_mac;
                GATEWAY_MAC_VALID = true;
            }
        }
    }

    let op = ntohs(operation);
    if op == ARP_OP_REQUEST && target_ip == our_ip && our_ip != Ipv4Addr::ANY {
        let our_mac = ethernet_our_mac();
        let reply = ArpPacket {
            hw_type: htons(1),
            proto_type: htons(0x0800),
            hw_len: 6,
            proto_len: 4,
            operation: htons(ARP_OP_REPLY),
            sender_mac: our_mac,
            sender_ip: our_ip,
            target_mac: sender_mac,
            target_ip: sender_ip,
        };
        let data = unsafe { core::slice::from_raw_parts(&reply as *const _ as *const u8, 28) };
        ethernet_send(sender_mac, ETHERTYPE_ARP, data);
    }
}

pub fn arp_resolve(ip: Ipv4Addr) -> Option<MacAddr> {
    if ip == Ipv4Addr::BROADCAST || ip.addr == 0xFFFFFFFF {
        return Some(MacAddr::BROADCAST);
    }
    if ip == Ipv4Addr::ANY {
        return None;
    }

    let target = unsafe {
        let mask = CONFIG.subnet_mask.addr;
        if (ip.addr & mask) != (CONFIG.ip.addr & mask) && CONFIG.gateway != Ipv4Addr::ANY {
            if GATEWAY_MAC_VALID {
                return Some(GATEWAY_MAC);
            }
            CONFIG.gateway
        } else {
            ip
        }
    };

    if let Some(mac) = arp_lookup(target) {
        return Some(mac);
    }

    for _retry in 0..3 {
        arp_request(target);
        for _poll in 0..200_000 {
            // Use poll_if_safe: on VZ (vz_compat), only core 0 may access
            // the VirtIO RX ring.  AP cores skip the poll and spin on
            // arp_lookup instead — core 0's event loop flushes the staged
            // ARP request and processes the reply via distribute_frame,
            // which updates the ARP cache that arp_lookup reads.
            drivers::virtio_net::poll_if_safe(arp_poll_callback);
            if let Some(mac) = arp_lookup(target) {
                return Some(mac);
            }
        }
    }
    None
}

pub fn arp_announce() {
    let our_mac = ethernet_our_mac();
    let our_ip = unsafe { CONFIG.ip };

    let pkt = ArpPacket {
        hw_type: htons(1),
        proto_type: htons(0x0800),
        hw_len: 6,
        proto_len: 4,
        operation: htons(ARP_OP_REPLY),
        sender_mac: our_mac,
        sender_ip: our_ip,
        target_mac: MacAddr::BROADCAST,
        target_ip: our_ip,
    };
    let data = unsafe { core::slice::from_raw_parts(&pkt as *const _ as *const u8, 28) };
    ethernet_send(MacAddr::BROADCAST, ETHERTYPE_ARP, data);
}

fn arp_poll_callback(frame: &[u8]) {
    if let Some((ETHERTYPE_ARP, payload)) = ethernet_parse(frame) {
        arp_receive(payload);
    }
}
