// net/ndp.rs — NDP (Neighbor Discovery Protocol) MAC cache.
//
// IPv6 counterpart to the ARP cache in `net/arp.rs`. Same shape:
// a small fixed-size table behind a `Spinlock` so the receive
// path (any core, under the Tier 2 distributor or any Tier 1
// queue worker) can `learn` from snooped frames and the send
// path can `resolve` to find a destination MAC.
//
// MVP scope:
//   * `ndp_learn(ip, mac)` — populate from snooped inbound v6
//     frames + Source/Target Link-Layer Address NDP options.
//   * `ndp_resolve(ip) -> Option<MacAddr>` — caller checks the
//     cache before sending; on miss the caller drops (or, for a
//     server response path, falls back to the inbound frame's
//     source MAC). Active Neighbor Solicitation is deferred.
//
// Out of scope for this commit:
//   * Active Neighbor Solicitation when the cache misses — would
//     queue the outbound packet and re-emit on NA receipt.
//   * Reachability state machine (REACHABLE / STALE / DELAY /
//     PROBE) per RFC 4861 §7.3. For a server that mostly replies
//     inline using the inbound frame's MAC, learn-only suffices.
//   * Per-entry timeout — an entry stays valid until evicted.

#![cfg_attr(not(test), no_std)]

extern crate net_types as types;

use kernel_core::sync::Spinlock;
use types::{Ipv6Addr, MacAddr};

const NDP_CACHE_SIZE: usize = 32;

#[derive(Clone, Copy)]
struct NdpEntry {
    ip: Ipv6Addr,
    mac: MacAddr,
    valid: bool,
}

impl NdpEntry {
    const fn new() -> Self {
        NdpEntry {
            ip: Ipv6Addr::ANY,
            mac: MacAddr::ZERO,
            valid: false,
        }
    }
}

struct NdpCache {
    entries: [NdpEntry; NDP_CACHE_SIZE],
    /// FIFO replacement cursor — when the cache is full and a new
    /// entry needs a slot, we evict whichever entry sits at this
    /// position and bump the cursor. Simpler than LRU (no per-
    /// access bookkeeping) and has acceptable churn at our cache
    /// size (32 entries vs typical L2 segment of <8 hosts).
    next_evict: usize,
}

impl NdpCache {
    const fn new() -> Self {
        NdpCache {
            entries: [const { NdpEntry::new() }; NDP_CACHE_SIZE],
            next_evict: 0,
        }
    }

    fn lookup(&self, ip: &Ipv6Addr) -> Option<MacAddr> {
        for e in &self.entries {
            if e.valid && e.ip == *ip {
                return Some(e.mac);
            }
        }
        None
    }

    fn update(&mut self, ip: Ipv6Addr, mac: MacAddr) {
        // Existing entry → refresh the MAC.
        for e in &mut self.entries {
            if e.valid && e.ip == ip {
                e.mac = mac;
                return;
            }
        }
        // Empty slot → install.
        for e in &mut self.entries {
            if !e.valid {
                *e = NdpEntry {
                    ip,
                    mac,
                    valid: true,
                };
                return;
            }
        }
        // Cache full — FIFO evict.
        let idx = self.next_evict;
        self.entries[idx] = NdpEntry {
            ip,
            mac,
            valid: true,
        };
        self.next_evict = (idx + 1) % NDP_CACHE_SIZE;
    }
}

static NDP: Spinlock<NdpCache> = Spinlock::new(NdpCache::new());

/// Snoop a `(IPv6 address, MAC)` pair into the cache. Called from
/// the receive path on every inbound IPv6 frame's source — the
/// (src, src_mac) pair is reliable peer-locality information for
/// hosts on the same L2 segment.
pub fn ndp_learn(ip: Ipv6Addr, mac: MacAddr) {
    if ip == Ipv6Addr::ANY || ip.is_multicast() {
        // Don't cache multicast or unspecified — they're never
        // valid as the destination of a unicast packet.
        return;
    }
    NDP.lock().update(ip, mac);
}

/// Look up the MAC for an IPv6 unicast destination. Returns
/// `None` on miss; callers decide whether to fall back to a
/// known peer MAC (response path) or drop.
pub fn ndp_resolve(ip: &Ipv6Addr) -> Option<MacAddr> {
    if ip.is_multicast() {
        // Multicast destinations have a deterministic MAC mapping
        // (RFC 2464 §7); resolution shouldn't go through the
        // cache. Return None so callers don't accidentally cache-
        // hit on a stale unicast entry with the same address.
        return None;
    }
    NDP.lock().lookup(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A global-unicast IPv6 address (`2000::/3`) keyed by its last
    /// octet — distinct from `ANY` and from any multicast group.
    fn ip(last: u8) -> Ipv6Addr {
        let mut o = [0u8; 16];
        o[0] = 0x20;
        o[15] = last;
        Ipv6Addr::from(o)
    }

    fn mac(tag: u8) -> MacAddr {
        MacAddr { bytes: [tag; 6] }
    }

    #[test]
    fn lookup_misses_on_empty_cache() {
        let cache = NdpCache::new();
        assert_eq!(cache.lookup(&ip(1)), None);
    }

    #[test]
    fn update_then_lookup_hits() {
        let mut cache = NdpCache::new();
        cache.update(ip(1), mac(0xaa));
        assert_eq!(cache.lookup(&ip(1)), Some(mac(0xaa)));
        assert_eq!(cache.lookup(&ip(2)), None);
    }

    #[test]
    fn update_refreshes_existing_entry() {
        let mut cache = NdpCache::new();
        cache.update(ip(1), mac(0xaa));
        cache.update(ip(1), mac(0xbb));
        assert_eq!(cache.lookup(&ip(1)), Some(mac(0xbb)));
        // A refresh must reuse the slot, not consume a second one:
        // fill the rest of the table and confirm ip(1) is not evicted.
        for i in 0..(NDP_CACHE_SIZE - 1) as u8 {
            cache.update(ip(100 + i), mac(i));
        }
        assert_eq!(cache.lookup(&ip(1)), Some(mac(0xbb)));
    }

    #[test]
    fn fifo_eviction_when_full() {
        let mut cache = NdpCache::new();
        for i in 0..NDP_CACHE_SIZE as u8 {
            cache.update(ip(i), mac(i));
        }
        assert_eq!(cache.lookup(&ip(0)), Some(mac(0)));
        // One past full — FIFO evicts the oldest entry (slot 0 = ip(0)).
        cache.update(ip(200), mac(0xff));
        assert_eq!(cache.lookup(&ip(0)), None);
        assert_eq!(cache.lookup(&ip(200)), Some(mac(0xff)));
        // The second-oldest entry survives.
        assert_eq!(cache.lookup(&ip(1)), Some(mac(1)));
    }

    #[test]
    fn resolve_rejects_multicast() {
        // Multicast destinations have a deterministic MAC mapping
        // (RFC 2464 §7) and must never resolve through the cache.
        assert_eq!(ndp_resolve(&Ipv6Addr::ALL_NODES_LL), None);
    }

    #[test]
    fn learn_ignores_unspecified() {
        // The unspecified address is never a valid unicast
        // destination — `ndp_learn` must drop it silently.
        ndp_learn(Ipv6Addr::ANY, mac(0x11));
        assert_eq!(ndp_resolve(&Ipv6Addr::ANY), None);
    }
}
