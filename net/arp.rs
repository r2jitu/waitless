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

// ─── Per-core lock-free ARP fast-cache ──────────────────────────────────────
//
// Every TCP/UDP send goes through `arp_resolve`, which under the original
// design took the global `ARP_CACHE` spinlock once per packet. With 8 cores
// transmitting at 200k pkt/s each, that one lock dropped per-core throughput
// from ~250k → ~33k req/s on the bench.
//
// The fast-cache is an array of single-entry caches indexed by `cpu_id()`.
// Each core's owner is the only writer of its own MAC field; the IP field
// is also written cross-core by `arp_fast_invalidate_all` when an ARP reply
// updates the slow cache. Both fields use atomics so the Rust memory model
// is happy regardless of who's reading.
//
// IP is the validity tag — readers load it first, load the MAC, then load
// the IP again and verify it matches. A torn write produces a miss, never
// a wrong MAC. On a hit (the common case — wrk hammers one destination),
// `arp_resolve` returns without touching shared state at all.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[repr(align(64))]
struct ArpFastSlot {
    ip: AtomicU32,
    /// MAC packed into a u64: bytes 0..6 occupy the low 48 bits.
    mac: AtomicU64,
}

const ARP_FAST_SLOTS: usize = kernel::percpu::MAX_CORES;
static ARP_FAST: [ArpFastSlot; ARP_FAST_SLOTS] =
    [const { ArpFastSlot {
        ip: AtomicU32::new(0),
        mac: AtomicU64::new(0),
    } }; ARP_FAST_SLOTS];

#[inline]
fn pack_mac(m: MacAddr) -> u64 {
    let b = m.bytes;
    (b[0] as u64)
        | ((b[1] as u64) << 8)
        | ((b[2] as u64) << 16)
        | ((b[3] as u64) << 24)
        | ((b[4] as u64) << 32)
        | ((b[5] as u64) << 40)
}

#[inline]
fn unpack_mac(v: u64) -> MacAddr {
    MacAddr {
        bytes: [
            v as u8,
            (v >> 8) as u8,
            (v >> 16) as u8,
            (v >> 24) as u8,
            (v >> 32) as u8,
            (v >> 40) as u8,
        ],
    }
}

#[inline]
fn arp_fast_lookup(ip: Ipv4Addr) -> Option<MacAddr> {
    if ip.addr == 0 {
        return None;
    }
    let core = kernel::cpu_id() as usize;
    if core >= ARP_FAST_SLOTS {
        return None;
    }
    let slot = &ARP_FAST[core];
    let ip1 = slot.ip.load(Ordering::Acquire);
    if ip1 != ip.addr {
        return None;
    }
    let mac = slot.mac.load(Ordering::Relaxed);
    // Re-check IP after MAC load: if a writer raced us between the two
    // loads the IP would now mismatch and we'd return None.
    if slot.ip.load(Ordering::Acquire) != ip1 {
        return None;
    }
    Some(unpack_mac(mac))
}

#[inline]
fn arp_fast_store(ip: Ipv4Addr, mac: MacAddr) {
    let core = kernel::cpu_id() as usize;
    if core >= ARP_FAST_SLOTS {
        return;
    }
    let slot = &ARP_FAST[core];
    // Invalidate by zeroing IP first, then write the MAC, then publish
    // the new IP. A reader on the same core won't observe a half-written
    // entry, and a cross-core invalidator only zeroes the IP.
    slot.ip.store(0, Ordering::Relaxed);
    slot.mac.store(pack_mac(mac), Ordering::Relaxed);
    slot.ip.store(ip.addr, Ordering::Release);
}

/// Invalidate every per-core fast slot. Called whenever the global
/// ARP_CACHE is mutated so a core caching the old MAC drops into the
/// slow path on its next resolve.
fn arp_fast_invalidate_all() {
    for slot in &ARP_FAST {
        slot.ip.store(0, Ordering::Relaxed);
    }
}

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
        // Drop the slow lock before invalidating per-core fast slots so
        // we don't hold both at once.
        drop(cache);
        arp_fast_invalidate_all();
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

    // Per-core fast path: hit returns without touching shared state.
    if let Some(mac) = arp_fast_lookup(ip) {
        return Some(mac);
    }

    let target = {
        let mask = CONFIG.subnet_mask().addr;
        let our_ip = CONFIG.ip().addr;
        let gateway = CONFIG.gateway();
        if (ip.addr & mask) != (our_ip & mask) && gateway != Ipv4Addr::ANY {
            let cache = ARP_CACHE.lock();
            if cache.gateway_mac_valid {
                let mac = cache.gateway_mac;
                drop(cache);
                arp_fast_store(ip, mac);
                return Some(mac);
            }
            gateway
        } else {
            ip
        }
    };

    if let Some(mac) = ARP_CACHE.lock().lookup(target) {
        arp_fast_store(ip, mac);
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
                arp_fast_store(ip, mac);
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
