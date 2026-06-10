// net/arp.rs — ARP cache, request/reply, resolve, announce, and the
// async next-hop resolver (`resolve_route` / `resolve_mac`) the TCP
// active-open path uses to solicit a MAC before the first SYN.

#![cfg_attr(not(test), no_std)]

extern crate net_from_bytes as from_bytes;
extern crate net_types as types;

use ethernet::{ETHERTYPE_ARP, ethernet_our_mac, ethernet_parse};
use ethernet_send::ethernet_send;
use from_bytes::FromBytes;
use iobuf::{Chain, OwnedIOBuf};
use sync::Spinlock;
use types::{CONFIG, Ipv4Addr, MacAddr, htons, ntohs};

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
                *entry = ArpEntry {
                    ip,
                    mac,
                    valid: true,
                };
                return;
            }
        }
        self.entries[0] = ArpEntry {
            ip,
            mac,
            valid: true,
        };
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

/// Per-core fast cache slots, sized to actual core count at boot.
static ARP_FAST: kernel_core::percpu::PerWorker<ArpFastSlot> =
    kernel_core::percpu::PerWorker::new();

/// Allocate the per-core ARP fast cache. Called from the net stack's
/// init path on the BSP after `kernel_core::percpu::init` has set
/// `num_workers`. Idempotent.
pub fn init() {
    ARP_FAST.init(kernel_core::percpu::num_cores(), |_| ArpFastSlot {
        ip: AtomicU32::new(0),
        mac: AtomicU64::new(0),
    });
}

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
    let core = kernel_core::cpu_id();
    if core >= ARP_FAST.len() {
        return None;
    }
    let slot = ARP_FAST.at(core);
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
    let core = kernel_core::cpu_id();
    if core >= ARP_FAST.len() {
        return;
    }
    let slot = ARP_FAST.at(core);
    // Invalidate by zeroing IP first, then write the MAC, then publish
    // the new IP. A reader on the same core won't observe a half-written
    // entry, and a cross-core invalidator only zeroes the IP.
    slot.ip.store(0, Ordering::Relaxed);
    slot.mac.store(pack_mac(mac), Ordering::Relaxed);
    slot.ip.store(ip.addr, Ordering::Release);
}

fn arp_request(target_ip: Ipv4Addr) {
    diag::COUNTERS.requests_sent.bump();
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
    nic::flush_tx_staging();
}

/// Snoop a peer's MAC from any received L2 frame with a usable
/// (src_ip, src_mac) pair. Populates the per-core fast cache only
/// — the slow cache stays filled exclusively from actual ARP
/// replies — which gives us instant first-packet replies without
/// ever firing an ARP request for peers that already talked to us.
///
/// The caller must ensure `src_ip` is in our subnet (off-subnet
/// traffic comes from the gateway's MAC, not the IP's own MAC, so
/// snooping that mapping would be wrong). In practice this is
/// called from ipv4 receive with the Ethernet src MAC and the IP
/// header's src IP after the subnet check.
pub fn arp_learn(src_ip: Ipv4Addr, src_mac: MacAddr) {
    if src_ip == Ipv4Addr::ANY
        || src_ip == Ipv4Addr::BROADCAST
        || src_mac == MacAddr::BROADCAST
        || src_mac == MacAddr::ZERO
    {
        return;
    }
    arp_fast_store(src_ip, src_mac);
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
        drop(cache);
        // Publish the fresh mapping into the current core's fast cache.
        // We deliberately do NOT invalidate other cores' slots: under
        // high load (udp_async) the only peer a core ever resolves is
        // the wrk/udp_bench client, the mapping never really changes,
        // and blowing away a hot entry just forces the next TX to fall
        // into the slow-path spin inside arp_resolve — which in turn
        // discards every non-ARP frame the poll loop sees.
        arp_fast_store(sender_ip, sender_mac);
        // Wake any async resolvers parked on this IP (the slow cache
        // they re-read on wake was updated above).
        pending_wake(sender_ip);
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

    // Shared routing decision (`types::next_hop_v4`). NoRoute
    // (off-link, no gateway) falls back to ARPing the destination
    // directly — hopeless on a real network, but byte-identical to
    // the historical behavior of this path.
    let target = types::next_hop_v4(ip, &CONFIG.load()).unwrap_or(ip);
    if target != ip {
        // Routed via the gateway: the cached gateway MAC short-
        // circuits the cache walk (and warms this core's fast slot
        // for the *destination* IP).
        let cache = ARP_CACHE.lock();
        if cache.gateway_mac_valid {
            let mac = cache.gateway_mac;
            drop(cache);
            arp_fast_store(ip, mac);
            return Some(mac);
        }
    }

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
            nic::poll(arp_poll_callback);
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

fn arp_poll_callback(chain: Chain<OwnedIOBuf>) {
    for part in chain.iter() {
        if let Some((ETHERTYPE_ARP, payload)) = ethernet_parse(part.data()) {
            arp_receive(payload);
        }
        // Non-ARP frames are dropped silently — the ARP-resolve
        // loop only cares about replies.
    }
    // `chain` drops at scope exit → each part's drop callback
    // reposts the backing buffer to the device.
}

// ─── Async next-hop resolution (active solicitation) ────────────────────────
//
// The synchronous `arp_resolve` above is fine for the server role —
// peers are always learned from their own inbound frames before we
// ever transmit — but its miss path is a busy-spin that monopolizes
// the core and *discards* every non-ARP frame it drains. A client
// connect to a fresh destination starts from a guaranteed miss, so
// it gets a proper async path instead: emit the request, park on the
// runtime's waker discipline, and let `arp_receive` wake us when the
// reply lands.
//
// Per-core vs global: the learn-side caches stay exactly as they are
// (global slow cache + per-core fast slots). The PENDING table below
// is global-but-tiny, and deliberately so — inbound ARP is delivered
// inline on whichever core the frame happens to land on (Tier 1: the
// NIC's non-IP queue placement; Tier 2: the distributor core; see
// `net_stack::rx`), which is in general NOT the core the resolver is
// parked on. A per-core pending set would strand waiters whenever the
// reply lands elsewhere. Cross-core waking is the runtime's bread and
// butter (same discipline as DHCP's `AsyncEvent`), the table is 8
// entries of two words each, and the touch rate is per-connect-miss,
// not per-packet — so global costs nothing where it matters.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use executor::waker_slot::{Parked, WakerSlot};

/// Why an async next-hop resolution failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    /// Destination is off-link and no gateway is configured
    /// (`types::next_hop_v4` said [`types::NoRoute`]).
    NoRoute,
    /// All [`RESOLVE_ATTEMPTS`] solicitations went unanswered.
    Timeout,
    /// The pending-resolve table was full — more concurrent
    /// first-contact resolutions than [`PENDING_RESOLVERS`]. Counted
    /// in `diag::COUNTERS.pending_overflow`.
    PendingOverflow,
}

/// Concurrent first-contact resolutions, process-wide. Connects to
/// already-known next hops never claim a slot (fast path), and every
/// distinct destination behind one gateway shares the gateway's
/// resolution — so a handful of slots covers any sane workload.
const PENDING_RESOLVERS: usize = 8;
/// Solicitations per resolution, ~[`RESOLVE_RETRY_US`] apart.
const RESOLVE_ATTEMPTS: u32 = 3;
const RESOLVE_RETRY_US: u64 = 1_000_000;

struct PendingSlot {
    /// IP being resolved (`Ipv4Addr::addr` form), `0` = slot free.
    /// The CAS on this field is the slot allocator; `pending_wake`
    /// matches against it lock-free.
    ip: AtomicU32,
    waker: WakerSlot,
}

impl PendingSlot {
    const fn new() -> Self {
        PendingSlot {
            ip: AtomicU32::new(0),
            waker: WakerSlot::new(),
        }
    }
}

static PENDING: [PendingSlot; PENDING_RESOLVERS] =
    [const { PendingSlot::new() }; PENDING_RESOLVERS];

/// Wake every resolver parked on `ip`. Called from `arp_receive` —
/// on whichever core the ARP frame landed — right after the slow
/// cache learned the mapping the waiters will re-read.
fn pending_wake(ip: Ipv4Addr) {
    for slot in &PENDING {
        if slot.ip.load(Ordering::Acquire) == ip.addr {
            slot.waker.wake();
        }
    }
}

/// A claimed [`PendingSlot`] — RAII, released on drop. `owner` marks
/// the first waiter for this IP at claim time: only the owner emits
/// solicitations, so N conns racing to the same fresh next hop put
/// one request per retry on the wire (the coalescing contract).
struct PendingClaim {
    slot: &'static PendingSlot,
    owner: bool,
}

impl PendingClaim {
    fn claim(ip: Ipv4Addr) -> Option<PendingClaim> {
        // Owner scan before the claim CAS, so our own slot can't
        // shadow the check. Two cores racing the same fresh IP can
        // both conclude "owner" and each send a request — harmless
        // (one duplicate per retry, bounded by the table size).
        let owner = !PENDING
            .iter()
            .any(|s| s.ip.load(Ordering::Acquire) == ip.addr);
        for slot in &PENDING {
            if slot
                .ip
                .compare_exchange(0, ip.addr, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(PendingClaim { slot, owner });
            }
        }
        None
    }
}

impl Drop for PendingClaim {
    fn drop(&mut self) {
        // No waker cleanup needed: the `Parked` guard inside the
        // wait future deregistered itself when that future dropped
        // (RAII), strictly before this claim drops. A `pending_wake`
        // racing the release can at worst spuriously wake a waiter
        // that re-claimed this slot — it re-checks its cache entry
        // and re-parks.
        self.slot.ip.store(0, Ordering::Release);
    }
}

/// Future: the slow-cache MAC for `ip`, parking on the claim's waker
/// slot until `arp_receive` learns it. Re-armed fresh for every
/// retry window (`timeout_us` drops the loser, and the `Parked`
/// field deregisters the waker structurally — audit #7).
struct WaitMac {
    ip: Ipv4Addr,
    slot: &'static PendingSlot,
    parked: Option<Parked<'static>>,
}

impl Future for WaitMac {
    type Output = MacAddr;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<MacAddr> {
        let this = self.get_mut();
        if let Some(mac) = ARP_CACHE.lock().lookup(this.ip) {
            return Poll::Ready(mac);
        }
        match &mut this.parked {
            Some(p) => p.repark(cx.waker()),
            None => this.parked = Some(this.slot.waker.park_guard(cx.waker())),
        }
        // Park-then-re-check: a reply that landed between the first
        // read and the park already consumed (or missed) our waker;
        // the second read closes the race — `WakerSlot`'s lock
        // orders the two critical sections.
        if let Some(mac) = ARP_CACHE.lock().lookup(this.ip) {
            return Poll::Ready(mac);
        }
        Poll::Pending
    }
}

/// Resolve the MAC of an on-link `next_hop` IP, actively soliciting
/// on a miss. Cache hit (per-core fast slot or shared slow cache)
/// returns without awaiting; a miss claims a pending slot, emits up
/// to [`RESOLVE_ATTEMPTS`] ARP requests ~1s apart, and parks between
/// them. Concurrent resolutions of the same IP coalesce to one
/// request stream; all waiters wake on the reply.
pub async fn resolve_mac(next_hop: Ipv4Addr) -> Result<MacAddr, ResolveError> {
    if next_hop == Ipv4Addr::BROADCAST {
        return Ok(MacAddr::BROADCAST);
    }
    if next_hop == Ipv4Addr::ANY {
        return Err(ResolveError::NoRoute);
    }
    if let Some(mac) = arp_fast_lookup(next_hop) {
        return Ok(mac);
    }
    if let Some(mac) = ARP_CACHE.lock().lookup(next_hop) {
        arp_fast_store(next_hop, mac);
        return Ok(mac);
    }
    let Some(claim) = PendingClaim::claim(next_hop) else {
        diag::COUNTERS.pending_overflow.bump();
        return Err(ResolveError::PendingOverflow);
    };
    for _ in 0..RESOLVE_ATTEMPTS {
        if claim.owner {
            arp_request(next_hop);
        }
        let wait = WaitMac {
            ip: next_hop,
            slot: claim.slot,
            parked: None,
        };
        if let Some(mac) = executor::select::timeout_us(RESOLVE_RETRY_US, wait).await {
            arp_fast_store(next_hop, mac);
            diag::COUNTERS.resolves_ok.bump();
            return Ok(mac);
        }
        // Timed out this window. A non-owner keeps waiting on its
        // own schedule — if the owner already gave up and released,
        // nobody re-solicits, but this waiter's residual windows are
        // bounded by the same ~3s budget.
    }
    diag::COUNTERS.resolve_timeouts.bump();
    Err(ResolveError::Timeout)
}

/// Route + resolve in one step: pick the next hop for `dest`
/// ([`types::next_hop_v4`] against the live config) and resolve its
/// MAC. The TCP active-open path calls this *before* sending the
/// SYN, so the SYN's `mac_resolve::resolve` → `arp_resolve` lookup
/// hits the (now-warm) caches and the sync spin path stays cold.
pub async fn resolve_route(dest: Ipv4Addr) -> Result<MacAddr, ResolveError> {
    let cfg = CONFIG.load();
    if cfg.ip == Ipv4Addr::ANY {
        // Boot-before-DHCP edge: mirror `mac_resolve` / `ipv4_send`,
        // which fall back to Ethernet broadcast.
        return Ok(MacAddr::BROADCAST);
    }
    let hop = types::next_hop_v4(dest, &cfg).map_err(|types::NoRoute| ResolveError::NoRoute)?;
    resolve_mac(hop).await
}

// ─── Diag — active-resolve observability ────────────────────────────────────

/// Counters for the ARP resolver, surfaced through the `/obs` `"net"`
/// block (`net_stack::diag` appends [`snapshot`](diag::snapshot)).
pub mod diag {
    use obs::Counter;

    pub struct Counters {
        /// ARP requests put on the wire — both the async resolver's
        /// solicitations and the legacy sync-spin path's (counted at
        /// the single `arp_request` choke point).
        pub requests_sent: Counter,
        /// Async resolutions that completed via solicitation (cache
        /// fast-path hits are not counted — they answer without ever
        /// touching the pending table).
        pub resolves_ok: Counter,
        /// Async resolutions that exhausted every solicitation window.
        pub resolve_timeouts: Counter,
        /// Resolutions refused because the pending table was full.
        pub pending_overflow: Counter,
    }

    impl Counters {
        const fn new() -> Self {
            Counters {
                requests_sent: Counter::new(),
                resolves_ok: Counter::new(),
                resolve_timeouts: Counter::new(),
                pending_overflow: Counter::new(),
            }
        }
    }

    pub static COUNTERS: Counters = Counters::new();

    /// Counter `(name, value)` pairs in declaration order, prefixed
    /// for splicing into the `"net"` `/obs` block.
    pub fn snapshot() -> [(&'static str, u64); 4] {
        let c = &COUNTERS;
        [
            ("arp_requests_sent", c.requests_sent.get()),
            ("arp_resolves_ok", c.resolves_ok.get()),
            ("arp_resolve_timeouts", c.resolve_timeouts.get()),
            ("arp_pending_overflow", c.pending_overflow.get()),
        ]
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::AtomicUsize;
    use std::task::{Wake, Waker};

    /// `PENDING` and `ARP_CACHE` are process globals and libtest runs
    /// tests on multiple threads — serialize the tests that touch them.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct CountingWake(AtomicUsize);
    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn waker() -> (Waker, Arc<CountingWake>) {
        let cw = Arc::new(CountingWake(AtomicUsize::new(0)));
        (Waker::from(Arc::clone(&cw)), cw)
    }

    fn poll_wait(wait: &mut WaitMac, w: &Waker) -> Poll<MacAddr> {
        let mut cx = Context::from_waker(w);
        Pin::new(wait).poll(&mut cx)
    }

    /// 28-byte wire-format ARP reply from `ip` claiming `mac`.
    fn reply_bytes(ip: Ipv4Addr, mac: MacAddr) -> std::vec::Vec<u8> {
        let pkt = ArpPacket {
            hw_type: htons(1),
            proto_type: htons(0x0800),
            hw_len: 6,
            proto_len: 4,
            operation: htons(ARP_OP_REPLY),
            sender_mac: mac,
            sender_ip: ip,
            target_mac: MacAddr::ZERO,
            target_ip: Ipv4Addr::ANY,
        };
        pkt.as_bytes().to_vec()
    }

    #[test]
    fn resolve_coalesces_two_waiters_one_owner_both_woken() {
        let _g = TEST_LOCK.lock().unwrap();
        let ip = Ipv4Addr::from(192, 168, 77, 1);
        let mac = MacAddr {
            bytes: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        };

        // Two concurrent claims for one IP: exactly one owner — the
        // owner flag is what gates request emission in `resolve_mac`,
        // so this IS the "one request emitted" contract.
        let a = PendingClaim::claim(ip).expect("slot");
        let b = PendingClaim::claim(ip).expect("slot");
        assert!(a.owner, "first claim solicits");
        assert!(!b.owner, "second claim coalesces");

        // Park both waiters (cache is cold → Pending).
        let (wa, ca) = waker();
        let (wb, cb) = waker();
        let mut fa = WaitMac { ip, slot: a.slot, parked: None };
        let mut fb = WaitMac { ip, slot: b.slot, parked: None };
        assert!(poll_wait(&mut fa, &wa).is_pending());
        assert!(poll_wait(&mut fb, &wb).is_pending());

        // The reply lands (on any core): both waiters wake, and both
        // resolve to the learned MAC on their next poll.
        arp_receive(&reply_bytes(ip, mac));
        assert_eq!(ca.0.load(Ordering::Relaxed), 1, "waiter A woken");
        assert_eq!(cb.0.load(Ordering::Relaxed), 1, "waiter B woken");
        assert_eq!(poll_wait(&mut fa, &wa), Poll::Ready(mac));
        assert_eq!(poll_wait(&mut fb, &wb), Poll::Ready(mac));

        // Claims release their slots on drop.
        drop((fa, fb, a, b));
        assert!(
            PENDING.iter().all(|s| s.ip.load(Ordering::Relaxed) != ip.addr),
            "slots released"
        );
    }

    #[test]
    fn pending_table_overflow_refuses_and_recovers() {
        let _g = TEST_LOCK.lock().unwrap();
        let mut held = std::vec::Vec::new();
        for i in 0..PENDING_RESOLVERS as u8 {
            held.push(PendingClaim::claim(Ipv4Addr::from(10, 99, 0, i + 1)).expect("slot"));
        }
        assert!(
            PendingClaim::claim(Ipv4Addr::from(10, 99, 1, 1)).is_none(),
            "table full refuses"
        );
        held.pop();
        assert!(
            PendingClaim::claim(Ipv4Addr::from(10, 99, 1, 1)).is_some(),
            "released slot is claimable again"
        );
    }

    #[test]
    fn wait_mac_park_then_recheck_closes_pre_park_race() {
        let _g = TEST_LOCK.lock().unwrap();
        let ip = Ipv4Addr::from(192, 168, 77, 2);
        let mac = MacAddr {
            bytes: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x02],
        };
        let claim = PendingClaim::claim(ip).expect("slot");
        // Reply already in the cache before the first poll: the
        // future must resolve immediately, never parking.
        arp_receive(&reply_bytes(ip, mac));
        let (w, cw) = waker();
        let mut f = WaitMac { ip, slot: claim.slot, parked: None };
        assert_eq!(poll_wait(&mut f, &w), Poll::Ready(mac));
        assert_eq!(cw.0.load(Ordering::Relaxed), 0, "no spurious wake");
    }
}
