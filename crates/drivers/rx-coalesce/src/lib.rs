//! Multi-buffer RX chain accumulator for NIC drivers whose hardware
//! delivers one logical frame as several completions — HW-GRO / RSC
//! coalesced super-frames (gve DQO), or any multi-descriptor RX where
//! only the last completion carries end-of-packet.
//!
//! The driver wraps each completion's buffer as an `OwnedIOBuf` and
//! feeds it here with its end-of-packet flag; non-EOP fragments
//! accumulate into a per-queue pending `Chain` and the EOP fragment
//! takes + returns the assembled chain. A stuck chain (whose EOP never
//! arrives) is dropped by `drop_stale` so its buffers recycle.
//!
//! Pure and `core`-only (one `iobuf` dep): the driver owns the I/O —
//! device reads, buffer wrapping, the per-queue cell and its
//! single-writer discipline, the wall clock — while this owns only the
//! state machine, so it is host-unit-tested in isolation (which the
//! driver crate, with its `os:none` deps, can't be).

#![cfg_attr(not(test), no_std)]

use iobuf::{Chain, OwnedIOBuf};

/// Per-queue accumulator: the in-progress coalesced chain and the
/// wall-clock ms (the driver's clock) at which it started accumulating.
/// `started_ms` is meaningless while `pending` is `None`.
///
/// Not internally synchronized — the caller must uphold
/// single-writer-per-instance (e.g. one polling core per RX queue), the
/// same discipline its backing storage already requires.
pub struct RxCoalescer {
    pending: Option<Chain<OwnedIOBuf>>,
    started_ms: u64,
}

impl RxCoalescer {
    pub const fn new() -> Self {
        Self {
            pending: None,
            started_ms: 0,
        }
    }

    /// `true` while a multi-buffer frame is mid-accumulation. A cheap
    /// shared read the caller can use to skip forming a `&mut` — e.g.
    /// during a poll-ownership handoff window where only concurrent
    /// shared access is sound.
    #[inline]
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Fold one completion's buffer into the accumulator. Returns the
    /// assembled chain to deliver when this completion is end-of-packet
    /// (`eop`), else `None` while the frame is still accumulating.
    ///
    /// A single-buffer frame (`eop` on an empty accumulator) returns
    /// immediately as a one-part chain without touching the pending
    /// slot — the common, non-coalesced case. `now_ms` stamps the start
    /// of a fresh multi-buffer frame for [`drop_stale`](Self::drop_stale).
    #[inline]
    pub fn accumulate(
        &mut self,
        buf: OwnedIOBuf,
        eop: bool,
        now_ms: u64,
    ) -> Option<Chain<OwnedIOBuf>> {
        match self.pending.as_mut() {
            Some(chain) => chain.push_back(buf),
            None => {
                if eop {
                    // Single-buffer frame — emit directly, no stash.
                    return Some(Chain::from(buf));
                }
                // First fragment of a new multi-buffer frame.
                self.started_ms = now_ms;
                self.pending = Some(Chain::from(buf));
            }
        }
        if eop { self.pending.take() } else { None }
    }

    /// Drop a pending chain that has been accumulating longer than
    /// `timeout_ms` (its EOP never arrived) so the held device buffers
    /// recycle when the chain drops. Returns `true` iff a stuck chain
    /// was dropped. No-op when nothing is pending.
    #[inline]
    pub fn drop_stale(&mut self, now_ms: u64, timeout_ms: u64) -> bool {
        if self.pending.is_some() && now_ms.wrapping_sub(self.started_ms) > timeout_ms {
            self.pending = None;
            true
        } else {
            false
        }
    }
}

impl Default for RxCoalescer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::NonNull;
    use iobuf::IOBufDropFn;

    // Reclaim the `Box<[u8]>` whose region was handed to `wrap_owned`
    // (under `cfg(test)` the crate is std, so `Box`/`vec!` are prelude).
    // SAFETY: `base`/`cap` are the (ptr, len) of a `Box<[u8]>`, freed
    // exactly once here.
    unsafe fn free_box(base: NonNull<u8>, cap: u32, _ctx: *mut ()) {
        let slice = core::ptr::slice_from_raw_parts_mut(base.as_ptr(), cap as usize);
        drop(unsafe { Box::from_raw(slice) });
    }

    /// A synthetic owned device buffer of `n` bytes (all zero).
    fn buf(n: usize) -> OwnedIOBuf {
        let boxed: Box<[u8]> = vec![0u8; n].into_boxed_slice();
        let cap = boxed.len() as u32;
        let raw = Box::into_raw(boxed);
        // SAFETY: `raw` is a non-null `cap`-byte region; `free_box`
        // reclaims it once; offset 0 + len cap fits capacity.
        unsafe {
            OwnedIOBuf::wrap_owned(
                NonNull::new_unchecked(raw as *mut u8),
                cap,
                0,
                cap,
                free_box as IOBufDropFn,
                core::ptr::null_mut(),
            )
        }
    }

    #[test]
    fn single_buffer_eop_emits_one_part_without_stashing() {
        let mut c = RxCoalescer::new();
        assert!(!c.is_pending());
        let chain = c.accumulate(buf(1500), true, 0).expect("EOP emits");
        assert_eq!(chain.part_count(), 1);
        assert!(!c.is_pending(), "single-buf EOP leaves the slot empty");
    }

    #[test]
    fn multi_buffer_accumulates_then_emits_on_eop() {
        let mut c = RxCoalescer::new();
        assert!(c.accumulate(buf(2048), false, 10).is_none(), "frag 1 → accumulate");
        assert!(c.is_pending());
        assert!(c.accumulate(buf(2048), false, 10).is_none(), "frag 2 → accumulate");
        assert!(c.is_pending());
        let chain = c.accumulate(buf(900), true, 10).expect("EOP emits the chain");
        assert_eq!(chain.part_count(), 3, "all three fragments stitched");
        assert_eq!(chain.total_len(), 2048 + 2048 + 900);
        assert!(!c.is_pending(), "slot empty after emit");
    }

    #[test]
    fn drop_stale_only_fires_past_the_timeout() {
        let mut c = RxCoalescer::new();
        // Nothing pending → never drops.
        assert!(!c.drop_stale(1_000_000, 100));
        // Start a multi-buf frame at t=0.
        assert!(c.accumulate(buf(2048), false, 0).is_none());
        assert!(c.is_pending());
        // Within the window → kept.
        assert!(!c.drop_stale(50, 100));
        assert!(c.is_pending());
        // Past the window → dropped, slot empties, buffers recycle.
        assert!(c.drop_stale(150, 100));
        assert!(!c.is_pending());
        assert!(!c.drop_stale(150, 100), "no double-drop");
    }

    #[test]
    fn fresh_frame_after_a_completed_one() {
        let mut c = RxCoalescer::new();
        let _ = c.accumulate(buf(2048), false, 5);
        let first = c.accumulate(buf(10), true, 5).expect("first frame emits");
        assert_eq!(first.part_count(), 2);
        // A second multi-buf frame reuses the now-empty slot cleanly.
        assert!(c.accumulate(buf(2048), false, 99).is_none());
        let second = c.accumulate(buf(20), true, 99).expect("second frame emits");
        assert_eq!(second.part_count(), 2);
        assert!(!c.is_pending());
    }
}
