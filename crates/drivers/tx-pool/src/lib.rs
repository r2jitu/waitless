//! Shared TX slot-pool primitives for NIC drivers whose TX buffers
//! are a two-tier (small/big) `AtomicBool` free-bitmap indexed by
//! `(qp-or-worker, slot, pool)`. gve-GQI and virtio-net both use this
//! exact pool shape and had independently grown byte-identical copies
//! of the token codec and the scan-claim loop; this crate is their
//! shared home.
//!
//! **Scope, not universality.** This is the codec + allocator *for
//! that pool pattern*, not "the NIC TX token." A driver with a
//! different slot structure encodes differently — e.g. gve-DQO
//! identifies its slot by a bare `qp` (slot == pkt_idx) and uses none
//! of this. So the abstraction is "the two-tier bitmap pool," and the
//! token codec is one facet of it, which is why both live here rather
//! than in the `nic_api` contract crate (where `driver_token` is
//! deliberately opaque).

#![cfg_attr(not(test), no_std)]

mod stall;
pub use stall::{STALL_BUDGET_US, STALL_COOLDOWN_US, TxStallBreaker};

use core::sync::atomic::{AtomicBool, Ordering};

/// Pool identifier packed into a driver token: TX slots split into a
/// "small" pool (MTU frames) and a "big" pool (TSO/GSO super-segments).
pub const POOL_ID_SMALL: u8 = 0;
pub const POOL_ID_BIG: u8 = 1;

/// Pack `(qp, slot, pool)` into a 64-bit opaque driver token. Layout:
/// bit 63 = pool, bits 32..62 = qp/worker, bits 0..31 = slot. Inverse
/// is [`decode_token`].
#[inline]
pub fn encode_token(qp: usize, slot: usize, pool: u8) -> u64 {
    let pool_bit = ((pool & 1) as u64) << 63;
    pool_bit | (((qp as u64) & 0x7FFF_FFFF) << 32) | (slot as u64 & 0xFFFF_FFFF)
}

/// Inverse of [`encode_token`] → `(qp, slot, pool)`.
#[inline]
pub fn decode_token(token: u64) -> (usize, usize, u8) {
    let pool = ((token >> 63) & 1) as u8;
    let qp = ((token >> 32) & 0x7FFF_FFFF) as usize;
    let slot = (token & 0xFFFF_FFFF) as usize;
    (qp, slot, pool)
}

/// Claim the first free slot in a lock-free `AtomicBool` free-bitmap,
/// returning `(claimed_slot, slots_scanned)`. `slots_scanned` is how
/// many cells were examined this call — the caller folds it into its
/// scan-depth diagnostic and accumulates it across spin retries. The
/// slot is `None` when every cell is taken (then `slots_scanned ==
/// used.len()`).
///
/// Lock-free, no CAS: the `Acquire` load + `Relaxed` store is sound
/// only under a **single-writer-per-pool** invariant — exactly one
/// core ever claims from a given pool (per-qp on gve Tier 1,
/// per-worker on virtio-net). Two concurrent claimers could both
/// observe the same `false` and double-claim, so callers MUST uphold
/// that invariant (as both drivers do today).
#[inline]
pub fn claim_first_free(used: &[AtomicBool]) -> (Option<usize>, usize) {
    for (slot, cell) in used.iter().enumerate() {
        if !cell.load(Ordering::Acquire) {
            cell.store(true, Ordering::Relaxed);
            return (Some(slot), slot + 1);
        }
    }
    (None, used.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trips() {
        for &(qp, slot, pool) in &[
            (0usize, 0usize, POOL_ID_SMALL),
            (3, 17, POOL_ID_BIG),
            (0x7FFF_FFFF, 0xFFFF_FFFF, POOL_ID_BIG),
        ] {
            let t = encode_token(qp, slot, pool);
            assert_eq!(decode_token(t), (qp, slot, pool));
        }
        // `pool` is masked to one bit on the way in.
        assert_eq!(decode_token(encode_token(1, 2, 3)).2, 1);
    }

    #[test]
    fn claim_scans_marks_and_reports_depth() {
        let used = [
            AtomicBool::new(false),
            AtomicBool::new(false),
            AtomicBool::new(false),
        ];
        assert_eq!(claim_first_free(&used), (Some(0), 1));
        assert_eq!(claim_first_free(&used), (Some(1), 2)); // 0 now taken
        assert_eq!(claim_first_free(&used), (Some(2), 3));
        assert_eq!(claim_first_free(&used), (None, 3)); // full → scanned all
    }
}
