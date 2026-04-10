// net/arp.rs — ARP cache, request/reply, resolve, announce.

#![no_std]

extern crate kernel;
extern crate net_from_bytes as from_bytes;
extern crate net_types as types;
extern crate net_ethernet as ethernet;
extern crate drivers;

use from_bytes::FromBytes;
use kernel::sync::Spinlock;
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

// SAFETY: repr(C, packed), all fields are POD integers/byte arrays.
unsafe impl FromBytes for ArpPacket {}

impl ArpPacket {
    /// View this packet as a `&[u8]` of exactly its 28-byte wire size.
    /// Safe because `ArpPacket` is `repr(C, packed)` POD.
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: ArpPacket is repr(C, packed) with no padding and only
        // POD fields, so any bit pattern is a valid byte slice.
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                core::mem::size_of::<ArpPacket>(),
            )
        }
    }
}

const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;

#[derive(Clone, Copy)]
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

/// ARP cache + cached gateway MAC, all behind one lock so reads from
/// one core can't observe a half-written entry from another core. The
/// cache is mutated by `arp_receive` (which can run on any core under
/// the distributor) and read by `arp_resolve` (which runs on the
/// sending core), so it's the textbook case for `Spinlock<T>`.
struct ArpCache {
    entries: [ArpEntry; ARP_CACHE_SIZE],
    gateway_mac: MacAddr,
    gateway_mac_valid: bool,
}

impl ArpCache {
    const fn new() -> Self {
        ArpCache {
            entries: [const { ArpEntry::new() }; ARP_CACHE_SIZE],
            gateway_mac: MacAddr::ZERO,
            gateway_mac_valid: false,
        }
    }

    fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        for entry in &self.entries {
            if entry.valid && entry.ip == ip {
                return Some(entry.mac);
            }
        }
        None
    }

    fn update(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        for entry in &mut self.entries {
            if entry.valid && entry.ip == ip {
                entry.mac = mac;
                return;
            }
        }
        for entry in &mut self.entries {
            if !entry.valid {
                *entry = ArpEntry { ip, mac, valid: true };
                return;
            }
        }
        self.entries[0] = ArpEntry { ip, mac, valid: true };
    }
}

static ARP_CACHE: Spinlock<ArpCache> = Spinlock::new(ArpCache::new());

fn arp_request(target_ip: Ipv4Addr) {
    let our_mac = ethernet_our_mac();
    let our_ip = CONFIG.ip();

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
    ethernet_send(MacAddr::BROADCAST, ETHERTYPE_ARP, pkt.as_bytes());
    // ethernet_send stages the ARP request rather than sending it directly.
    // When arp_resolve is spinning (not running the event loop), net_flush_cb
    // never fires, so core 0 stays in WFI until a VirtIO RX interrupt
    // arrives — but that can't happen until the ARP request is sent. One
    // targeted flush_tx_staging call breaks the deadlock by waking core 0.
    // Fires at most 3 times per arp_resolve (once per retry), not thousands.
    drivers::virtio_net::flush_tx_staging();
}

pub fn arp_receive(data: &[u8]) {
    let pkt = match ArpPacket::try_ref_from(data) {
        Some(p) => p,
        None => return,
    };
    let our_ip = CONFIG.ip();

    let sender_ip = pkt.sender_ip;
    let sender_mac = pkt.sender_mac;
    let target_ip = pkt.target_ip;
    let operation = pkt.operation;

    if sender_ip != Ipv4Addr::ANY {
        let mut cache = ARP_CACHE.lock();
        cache.update(sender_ip, sender_mac);
        if sender_ip == CONFIG.gateway() {
            cache.gateway_mac = sender_mac;
            cache.gateway_mac_valid = true;
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
        ethernet_send(sender_mac, ETHERTYPE_ARP, reply.as_bytes());
    }
}

pub fn arp_resolve(ip: Ipv4Addr) -> Option<MacAddr> {
    if ip == Ipv4Addr::BROADCAST {
        return Some(MacAddr::BROADCAST);
    }
    if ip == Ipv4Addr::ANY {
        return None;
    }

    let target = {
        let mask = CONFIG.subnet_mask().addr;
        let our_ip = CONFIG.ip().addr;
        let gateway = CONFIG.gateway();
        if (ip.addr & mask) != (our_ip & mask) && gateway != Ipv4Addr::ANY {
            let cache = ARP_CACHE.lock();
            if cache.gateway_mac_valid {
                return Some(cache.gateway_mac);
            }
            gateway
        } else {
            ip
        }
    };

    if let Some(mac) = ARP_CACHE.lock().lookup(target) {
        return Some(mac);
    }

    for _retry in 0..3 {
        arp_request(target);
        for _poll in 0..200_000 {
            // Drain the RX queue. poll() takes the TX_LOCK try-lock
            // around the queue access, so concurrent calls across cores
            // are serialised; an ARP reply observed here updates the
            // cache that arp_lookup reads on the next iteration.
            drivers::virtio_net::poll(arp_poll_callback);
            if let Some(mac) = ARP_CACHE.lock().lookup(target) {
                return Some(mac);
            }
        }
    }
    None
}

pub fn arp_announce() {
    let our_mac = ethernet_our_mac();
    let our_ip = CONFIG.ip();

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
    ethernet_send(MacAddr::BROADCAST, ETHERTYPE_ARP, pkt.as_bytes());
}

fn arp_poll_callback(frame: &[u8]) {
    if let Some((ETHERTYPE_ARP, payload)) = ethernet_parse(frame) {
        arp_receive(payload);
    }
}
