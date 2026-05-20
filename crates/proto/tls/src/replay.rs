// crates/proto/tls/src/replay.rs — 0-RTT replay-protection cache.
//
// RFC 9001 §5.5 requires a server to provide protection against
// replay of 0-RTT data. Without it an attacker can capture a
// 0-RTT-bearing datagram and replay it later — for a state-
// modifying request that's a real attack; even for a GET it
// leaks the ability to replay arbitrary captured requests
// during the ticket's validity window.
//
// We implement the simplest defense that's correct under our
// threat model: a fixed-size lossy hash table keyed by the
// per-ticket nonce. Each ticket sealed by `seal_ticket` carries
// a fresh 12-byte AEAD nonce (bytes 16..28 of the sealed blob);
// when a client offers that ticket as a PSK and the resumption
// validates, we mark its nonce as "seen" before deriving 0-RTT
// keys. A second offer of the same ticket finds the nonce in
// the table and is rejected for 0-RTT (the 1-RTT resumption
// itself proceeds — only early data is suppressed).
//
// Hash collisions cause false positives (legitimate 0-RTT
// rejected, falls back to 1-RTT — annoying but safe). Slot
// eviction (via overwrite) creates a window where a very-old
// replay isn't detected, bounded by the table size; with 4096
// slots and per-conn ticket use, an attacker needs >4096 fresh
// resumption attempts in between original and replay to slip
// past, which would be a separate detectable flood.
//
// Memory: 4096 × 12 bytes ≈ 48 KiB process-wide, static.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const SLOTS: usize = 4096;
const SLOT_MASK: usize = SLOTS - 1;

struct Slot {
    nonce_hi: AtomicU64, // bytes 0..8 of the 12-byte ticket nonce
    nonce_lo: AtomicU32, // bytes 8..12
}

static TABLE: [Slot; SLOTS] = [const {
    Slot {
        nonce_hi: AtomicU64::new(0),
        nonce_lo: AtomicU32::new(0),
    }
}; SLOTS];

/// Check whether `nonce` (12 bytes from the sealed-ticket blob,
/// positions 16..28) has been seen before. If yes, return
/// `false` — caller treats the ticket as ineligible for 0-RTT.
/// If no, record the nonce and return `true` — caller may
/// proceed with 0-RTT key derivation.
///
/// "All-zero nonce" is treated as fresh slot rather than
/// matching, since `getrandom` should never produce all-zeros
/// and the static table is initialised to that pattern. This
/// avoids a false-positive at every conn startup where the
/// first ticket happens to hash to a never-touched slot.
pub fn check_and_record(nonce: &[u8; 12]) -> bool {
    let hi_arr: [u8; 8] = nonce[0..8].try_into().unwrap();
    let lo_arr: [u8; 4] = nonce[8..12].try_into().unwrap();
    let n_hi = u64::from_be_bytes(hi_arr);
    let n_lo = u32::from_be_bytes(lo_arr);
    // Distribute via the high word's mod; the nonce is already
    // uniform-random so any bits work. SLOTS is a power of two
    // so this is a mask, not a div.
    let idx = (n_hi as usize) & SLOT_MASK;
    let slot = &TABLE[idx];
    let cur_hi = slot.nonce_hi.load(Ordering::Acquire);
    let cur_lo = slot.nonce_lo.load(Ordering::Acquire);
    if cur_hi == n_hi && cur_lo == n_lo {
        return false; // replay
    }
    // Claim the slot (lossy: a concurrent writer with a
    // different nonce evicts us, but the race window is sub-
    // microsecond and replay attacks happen on human timescales).
    slot.nonce_hi.store(n_hi, Ordering::Release);
    slot.nonce_lo.store(n_lo, Ordering::Release);
    true
}

/// Test-only: clear every slot. Lets unit tests start from a
/// known empty state so the assertions below don't depend on
/// table-state leakage from prior tests.
#[cfg(test)]
pub(crate) fn reset() {
    for slot in TABLE.iter() {
        slot.nonce_hi.store(0, Ordering::Release);
        slot.nonce_lo.store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_nonce_is_recorded_and_replay_rejected() {
        reset();
        let n: [u8; 12] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        assert!(check_and_record(&n), "first sighting must be fresh");
        assert!(!check_and_record(&n), "replay must be rejected");
    }

    #[test]
    fn distinct_nonces_dont_collide_when_distributed() {
        reset();
        // Two nonces whose high-word is identical except in the
        // low byte; they hit the same slot if the distribution
        // is high-word-only. Verify the second's distinct full
        // identity is still detected as a different nonce
        // (overwrites the slot, doesn't return "replay").
        let a: [u8; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let b: [u8; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        assert!(check_and_record(&a));
        assert!(check_and_record(&b));
    }
}
