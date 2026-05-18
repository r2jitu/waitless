// uni-iobuf/src/pool.rs — fixed-size slab pool for IOBuf RX recycling.
//
// `IOBufPool` hands out `IOBuf`s backed by pre-allocated, fixed-size
// heap slabs. Each slab is sized for one MTU frame plus whatever
// header reserves a driver wants (~1.6 KiB is the canonical figure).
// On drop, the slab returns itself to the pool's free list — no
// allocator round-trip on the RX hot path.
//
// Canonical consumer (RX-path optimization plan, item B): the gVNIC
// GQI driver. GQI reposts receive buffers to the device strictly
// in-order, so — unlike DQO / virtio — it cannot hand a device
// buffer up the stack and rely on an auto-repost when the IOBuf
// drops. Instead GQI copies each received frame into a pooled slab,
// reposts the device buffer immediately, and lets the *slab* travel
// up the stack. When the slab's IOBuf drops — possibly on another
// core — its drop callback recycles the slab here.
//
// ── Ownership: the pool always outlives its IOBufs ──────────────
//
// The slab region, the free list, and the counters live in a
// heap-pinned `PoolInner` behind an `Arc`. `IOBufPool` itself is a
// cheap, clonable handle around that `Arc`. Crucially, every IOBuf
// the pool issues *also* holds one `Arc` strong reference — stashed
// (via `Arc::into_raw`) as its drop-callback context. So the slab
// region is reference-counted alive for at least as long as any
// IOBuf views it: dropping every pool handle while IOBufs are still
// in flight is sound, and the region is freed only when the last
// reference — handle or IOBuf — goes away. There is no
// outlives-or-don't-move invariant for the caller to uphold; `alloc`
// is a genuinely safe function.
//
// ── Free list: a tagged-pointer Treiber stack ───────────────────
//
// The free list is a lock-free `tagged_treiber::TaggedTreiberStack`
// — a single `AtomicU64` head packing `(slot_index, version_tag)`,
// the version as the ABA defence. The mechanism lives, audited once,
// in that crate's docs; `uni_kernel::rx_inbox::RxNodePool` is its
// other consumer.
//
// The one pool-specific point is link storage. Free slabs are linked
// through a dedicated `next` array (one `AtomicU32` per slab), handed
// to the stack via `PoolInner`'s `TreiberLinks` impl — NOT through
// the slab bytes themselves, so reading a link can never race a
// payload write on a slab that was just popped and handed out.
//
// If the stack ever shows contention in production, the documented
// escape hatch (docs/rx-path-optimizations.md, "Operational") is to
// shard into per-core pool partitions. Correctness here does not
// depend on that — the Treiber stack is lock-free as-is.
//
// ── Panic-safety of the drop callback ───────────────────────────
//
// `return_slab` runs from `IOBuf`'s `Drop`. Under `#![no_std]` a
// panic in `Drop` is poison — there is no unwinding contract to
// lean on. So the recycle path *never* panics: an unmappable base
// pointer (impossible unless a foreign IOBuf reached the callback,
// or memory was corrupted) bumps the `leaked` counter and returns,
// leaking that one slab rather than aborting.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use tagged_treiber::{TaggedTreiberStack, TreiberLinks};

use crate::{IOBufDropFn, OwnedIOBuf};

/// Free-list sentinel: a `slot_index` of [`tagged_treiber::NULL_INDEX`]
/// (`u32::MAX`) marks both the empty stack and the tail of the `next`
/// link chain. The pool rejects a `capacity_slabs` that could collide
/// with it, so no real slot ever has this index.
const NULL_SLOT: u32 = tagged_treiber::NULL_INDEX;

/// Shared inner state of a pool: the slab region, the lock-free
/// free list, and the counters. Heap-pinned behind an `Arc` (see
/// [`IOBufPool`]) so it sits at a stable address and is kept alive
/// by reference count for at least as long as any pool-issued
/// IOBuf — which is what makes the pool's API sound.
struct PoolInner {
    /// The slab region: a fat pointer over the whole
    /// `slab_size * capacity_slabs`-byte allocation. Obtained from
    /// `Box::<[u8]>::into_raw` — so it carries mutable provenance
    /// for the whole allocation (pool-issued IOBufs write payload
    /// through sub-pointers derived from it) — and fed back to
    /// `Box::from_raw` in `Drop`. Keeping the length in the pointer
    /// metadata means `Drop` round-trips the *exact* pointer
    /// `into_raw` produced, and `recycle` reads `base.len()` rather
    /// than recomputing the region size. `PoolInner` itself never
    /// dereferences this pointer — only IOBufs do.
    base: NonNull<[u8]>,
    /// Bytes per slab. Immutable after construction.
    slab_size: u32,
    /// Number of slabs. Immutable after construction.
    capacity_slabs: u32,
    /// Intrusive free-list links, one `AtomicU32` per slab.
    /// `next[i]` is the slot index following slab `i` on the free
    /// list, or `NULL_SLOT` at the tail. Dedicated storage — never
    /// aliased with slab payload — so reading a link cannot race a
    /// payload write on a popped-and-reused slab.
    next: Box<[AtomicU32]>,
    /// The lock-free free list: a tagged-pointer Treiber stack of
    /// slot indices, empty when its head index is `NULL_SLOT`. Its
    /// `next` links are this struct's `next` array, reached through
    /// the `TreiberLinks` impl below.
    free_list: TaggedTreiberStack,
    /// Live count of free slabs. Eventually-consistent with `head`
    /// (each successful CAS updates it with `Relaxed` ordering);
    /// exact once the pool quiesces. For observability and tests.
    free_count: AtomicUsize,
    /// Count of slabs leaked by the panic-safe drop bailout —
    /// impossible under correct use (see [`PoolInner::recycle`]).
    /// A non-zero value signals a foreign IOBuf or memory
    /// corruption reached the drop callback.
    leaked: AtomicUsize,
}

// SAFETY: `PoolInner` is `!Send + !Sync` only because of the
// `NonNull<[u8]>` field. That pointer is used solely for address
// arithmetic (deriving slab sub-pointers) and, exactly once, for
// `Box::from_raw` in `Drop`; `PoolInner` never dereferences it to
// read or write slab bytes — only IOBufs do, each through its own
// disjoint sub-pointer. Every field mutated after construction is
// an atomic counter (`free_count`, `leaked`), a lock-free stack of
// atomics (`free_list`), or a slice of atomics (`next`), so
// concurrent `&PoolInner` access is data-race-free (`Sync`). The
// backing allocation is owned by `PoolInner` and
// released through the global (thread-safe) allocator in `Drop`, so
// the value — and that `Drop` — may run on any thread (`Send`).
unsafe impl Send for PoolInner {}
unsafe impl Sync for PoolInner {}

impl PoolInner {
    /// Take a slab off the lock-free free list. Returns `None` only
    /// when the pool is genuinely exhausted.
    fn pop_slot(&self) -> Option<u32> {
        let slot = self.free_list.pop(self)?;
        // `free_count` is a `Relaxed`, eventually-consistent
        // observability counter (see the field docs). Bumping it
        // just after the stack's CAS — rather than inside the stack
        // — is observationally identical: no reader synchronises on
        // it, so the code motion changes nothing.
        self.free_count.fetch_sub(1, Ordering::Relaxed);
        Some(slot)
    }

    /// Return a slab to the lock-free free list.
    fn push_slot(&self, slot: u32) {
        self.free_list.push(slot, self);
        // See `pop_slot` on why this `Relaxed` counter bump is sound
        // outside the stack's CAS.
        self.free_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Map a slab `base` back to its slot index and return it to
    /// the free list.
    ///
    /// The slot-mapping bailout is the panic-safe escape hatch: a
    /// `base` that does not land on a slab boundary inside this
    /// pool's region is impossible under correct use (the pool
    /// issued the IOBuf, so its base is one of our slab starts).
    /// Reaching the `None` arm means a foreign IOBuf or memory
    /// corruption — we bump `leaked` and return, leaking that one
    /// slab. Panicking here would poison a `#![no_std]` `Drop`.
    fn recycle(&self, base: NonNull<u8>) {
        let region_start = self.base.cast::<u8>().as_ptr() as usize;
        let region_len = self.base.len();
        let addr = base.as_ptr() as usize;
        let slot = addr
            .checked_sub(region_start)
            .filter(|off| *off < region_len && off % self.slab_size as usize == 0)
            .map(|off| (off / self.slab_size as usize) as u32);
        match slot {
            Some(slot) => self.push_slot(slot),
            None => {
                // Impossible under correct use — leak, never panic.
                self.leaked.fetch_add(1, Ordering::Relaxed);
                report_leak(addr);
            }
        }
    }
}

impl TreiberLinks for PoolInner {
    /// The free-list `next` links live in the dedicated `next` array
    /// — never aliased with slab payload, so a link read cannot race
    /// a payload write on a popped-and-reused slab. `idx` came off
    /// the stack, so it indexes a real slot.
    fn next_link(&self, idx: u32) -> &AtomicU32 {
        &self.next[idx as usize]
    }
}

impl Drop for PoolInner {
    fn drop(&mut self) {
        // SAFETY: `base` is exactly the `*mut [u8]` that
        // `Box::<[u8]>::into_raw` produced in `IOBufPool::new` —
        // same address, same length metadata — so `Box::from_raw`
        // rebuilds the original `Box` and frees the slab region
        // once. `PoolInner` drops only when its last `Arc`
        // reference goes away, and every pool-issued IOBuf holds
        // one, so no live IOBuf still views the region here.
        unsafe {
            drop(Box::from_raw(self.base.as_ptr()));
        }
    }
}

/// A handle to a fixed-size pool of MTU-sized heap slabs, recycled
/// through a lock-free tagged-pointer Treiber stack.
///
/// `IOBufPool` is a cheap, clonable handle: the slab region, the
/// free list, and the counters live in a heap-pinned [`PoolInner`]
/// behind an `Arc`. Every [`IOBuf`] the pool issues also holds one
/// `Arc` strong reference (in its drop-callback context), so the
/// slab region is guaranteed to outlive every IOBuf that views it.
/// Dropping all pool handles while IOBufs are still in flight is
/// **sound** — the region is freed only when the last reference,
/// handle or IOBuf, drops. There is therefore no outlives-or-move
/// invariant for the caller to uphold.
pub struct IOBufPool {
    inner: Arc<PoolInner>,
}

impl Clone for IOBufPool {
    /// Cheap — bumps the `Arc` strong count. All clones address the
    /// same slab region and free list.
    fn clone(&self) -> Self {
        IOBufPool {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl IOBufPool {
    /// Build a pool of `capacity_slabs` slabs, each `slab_size_bytes`
    /// wide. The whole slab region is allocated up front as one
    /// contiguous `Box<[u8]>`; every slab starts on the free list.
    ///
    /// Panics if `capacity_slabs` could collide with the
    /// `NULL_SLOT` sentinel, if `slab_size_bytes` is zero or
    /// exceeds `u32::MAX`, or if `slab_size * capacity` overflows
    /// `usize`.
    pub fn new(capacity_slabs: usize, slab_size_bytes: usize) -> Self {
        assert!(
            capacity_slabs < NULL_SLOT as usize,
            "IOBufPool: capacity_slabs {} must be < {} (NULL_SLOT)",
            capacity_slabs,
            NULL_SLOT,
        );
        assert!(
            (1..=u32::MAX as usize).contains(&slab_size_bytes),
            "IOBufPool: slab_size_bytes {} out of range [1, u32::MAX]",
            slab_size_bytes,
        );
        let region_len = slab_size_bytes
            .checked_mul(capacity_slabs)
            .expect("IOBufPool: slab_size * capacity overflows usize");

        // Contiguous slab region. `Box::into_raw` hands the
        // allocation off as a `*mut [u8]` carrying mutable
        // provenance for the whole region (pool-issued IOBufs write
        // payload through sub-pointers of it); `PoolInner::drop`
        // feeds the same pointer back to `Box::from_raw`. Zero-
        // filled to keep info-leak-class bugs away, matching
        // `IOBuf::new_with_reserved`.
        let storage: Box<[u8]> = alloc::vec![0u8; region_len].into_boxed_slice();
        let base: NonNull<[u8]> =
            NonNull::new(Box::into_raw(storage)).expect("Box<[u8]> pointer is never null");

        // Intrusive free-list links: slab i → slab i+1, tail → NULL.
        // The whole pool starts free with the head at slot 0.
        let next: Box<[AtomicU32]> = (0..capacity_slabs)
            .map(|i| {
                let link = if i + 1 < capacity_slabs {
                    (i + 1) as u32
                } else {
                    NULL_SLOT
                };
                AtomicU32::new(link)
            })
            .collect();
        // The whole pool starts free, so the stack's head is slot 0
        // — or `NULL_SLOT` for the degenerate zero-capacity pool.
        let head_slot = if capacity_slabs == 0 { NULL_SLOT } else { 0 };

        IOBufPool {
            inner: Arc::new(PoolInner {
                base,
                slab_size: slab_size_bytes as u32,
                capacity_slabs: capacity_slabs as u32,
                next,
                free_list: TaggedTreiberStack::new(head_slot),
                free_count: AtomicUsize::new(capacity_slabs),
                leaked: AtomicUsize::new(0),
            }),
        }
    }

    /// Take a slab off the free list, copy `frame` into it, and
    /// return it as a filled `OwnedIOBuf` — or `None` when the pool
    /// is exhausted, or `frame` is larger than one slab.
    ///
    /// The copy lives **here**, not behind an `OwnedIOBuf` mutation
    /// method: the pool allocated the slab region as a `Box<[u8]>`,
    /// so it *knows* the bytes are writable. A writable surface on
    /// `OwnedIOBuf` would instead force *every* `wrap_owned` caller's
    /// region to be writable (exclusive ≠ writable), which the type
    /// model deliberately avoids — so `OwnedIOBuf` stays read-only
    /// and the pool, the one place a slab's writability is known,
    /// owns the fill. Canonical caller: the gVNIC GQI RX path.
    ///
    /// The returned `OwnedIOBuf` is `Send`; on drop the slab recycles
    /// itself back here, possibly from another core. It carries a
    /// strong `Arc` reference to the pool's inner state, so it keeps
    /// the slab region alive on its own — see the [`IOBufPool`] type
    /// docs.
    pub fn alloc(&self, frame: &[u8]) -> Option<OwnedIOBuf> {
        // An oversize frame can't fit a slab — reject before taking
        // a slot so a `None` leaks nothing. Slabs are MTU-sized and
        // RX frames MTU-bounded, so this is a never-in-practice
        // guard; the caller recovers a dropped frame via TCP
        // retransmit / UDP retry, same as a pool-exhaustion `None`.
        if frame.len() > self.inner.slab_size as usize {
            return None;
        }
        let slot = self.inner.pop_slot()?;

        // Hand the IOBuf its own strong reference to `PoolInner`:
        // `into_raw` consumes one `Arc` clone, parking that strong
        // count in the IOBuf's drop context; `return_slab` reclaims
        // it with `from_raw`. While the IOBuf lives, the pool's
        // slab region is reference-counted alive. (Done only after
        // `pop_slot` succeeds, so a `None` alloc leaks no count.)
        let ctx = Arc::into_raw(Arc::clone(&self.inner)) as *mut ();

        // SAFETY: `slot` came off the free list, so it is in
        // `0..capacity_slabs`; therefore `slot * slab_size` is
        // strictly less than the region length and the resulting
        // pointer stays in bounds of the slab allocation. `cast`
        // only reinterprets the region pointer as a thin `*u8`
        // (same address, same whole-allocation provenance).
        let slab_base: NonNull<u8> = unsafe {
            self.inner
                .base
                .cast::<u8>()
                .add(slot as usize * self.inner.slab_size as usize)
        };

        // Copy the frame into the slab before wrapping it as a
        // read-only `OwnedIOBuf`. `pop_slot` removed this slab from
        // the free list, so it is exclusively ours.
        // SAFETY: `slab_base .. slab_base + frame.len()` is within
        // this one slab (`frame.len() <= slab_size` checked above)
        // and disjoint from every other live slab; `frame` is a
        // distinct caller slice, so source and dest don't overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                slab_base.as_ptr(),
                frame.len(),
            );
        }

        // SAFETY:
        //  * `slab_base .. slab_base + slab_size` is one distinct
        //    slab of the region; no other live IOBuf or concurrent
        //    pool op aliases it.
        //  * offset 0 + len `frame.len()` <= slab_size.
        //  * `return_slab` is sound to invoke once at drop: it
        //    reclaims the `Arc` parked in `ctx` and recycles the
        //    slab. That `Arc` strong reference keeps `PoolInner`
        //    (slab region + free list) alive for the IOBuf's whole
        //    lifetime, so the slab bytes and the `ctx` pointee both
        //    stay valid until after the callback runs.
        //  * the `(drop_fn, drop_ctx)` pair is Send-safe:
        //    `PoolInner` is `Send + Sync`, so the parked `Arc` may
        //    be reclaimed on whichever core ultimately drops the
        //    IOBuf.
        let buf = unsafe {
            OwnedIOBuf::wrap_owned(
                slab_base,
                self.inner.slab_size,
                0,
                frame.len() as u32,
                return_slab as IOBufDropFn,
                ctx,
            )
        };
        Some(buf)
    }

    /// Free slabs currently on the list. Eventually-consistent
    /// under concurrency; exact once the pool quiesces.
    pub fn free_count(&self) -> usize {
        self.inner.free_count.load(Ordering::Relaxed)
    }

    /// Slabs leaked by the panic-safe drop bailout. Always `0`
    /// under correct use; a non-zero value is a red flag.
    pub fn leaked_count(&self) -> usize {
        self.inner.leaked.load(Ordering::Relaxed)
    }

    /// Total number of slabs (free + in flight).
    pub fn capacity(&self) -> usize {
        self.inner.capacity_slabs as usize
    }

    /// Bytes per slab.
    pub fn slab_size(&self) -> usize {
        self.inner.slab_size as usize
    }
}

/// Drop callback for pool-issued IOBufs. Installed as the `drop_fn`
/// by [`IOBufPool::alloc`]; runs once when the IOBuf drops, possibly
/// on a different core than `alloc`.
///
/// Must stay an `unsafe fn`: `ctx` carries a precondition that no
/// caller can check. (`IOBufDropFn` is itself an `unsafe fn` type,
/// so this still coerces into one.)
///
/// SAFETY: `ctx` must be a pointer produced by
/// `Arc::<PoolInner>::into_raw` and not yet reclaimed — which is
/// exactly what [`IOBufPool::alloc`] installs. `Arc::from_raw` then
/// reclaims the one strong reference the IOBuf held; the pairing is
/// balanced (one `into_raw` per `alloc`, one `from_raw` per drop,
/// and `Drop` runs once). `base` / `capacity` are the originals
/// passed to `wrap_owned`.
unsafe fn return_slab(base: NonNull<u8>, _capacity: u32, ctx: *mut ()) {
    // SAFETY: per the contract above, `ctx` is a live, not-yet-
    // reclaimed `Arc::<PoolInner>::into_raw` pointer.
    let inner: Arc<PoolInner> = unsafe { Arc::from_raw(ctx as *const PoolInner) };
    // `inner` holds a strong reference for the whole of this call,
    // so `PoolInner` (and the slab region) is alive while we
    // recycle into it.
    inner.recycle(base);
    // `inner` drops here: strong count -= 1. If this IOBuf held the
    // last reference, `PoolInner::drop` now frees the slab region.
}

/// Best-effort report of a leaked slab. In `cfg(test)` / debug
/// builds it writes to stderr; in release `#![no_std]` builds —
/// where this dep-less crate has no logging facility — it is a
/// no-op, and the leak stays observable through
/// [`IOBufPool::leaked_count`].
#[cfg(any(test, debug_assertions))]
fn report_leak(base_addr: usize) {
    extern crate std;
    std::eprintln!(
        "IOBufPool: leaking a slab — drop callback received base \
         {:#x}, which maps to no slot in this pool (foreign IOBuf \
         or memory corruption). Panic-safe bailout; see leaked_count().",
        base_addr,
    );
}

#[cfg(not(any(test, debug_assertions)))]
#[inline(always)]
fn report_leak(_base_addr: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::thread;
    use std::vec::Vec;

    #[test]
    fn fresh_pool_reports_full_free_count() {
        let pool = IOBufPool::new(16, 1600);
        assert_eq!(pool.free_count(), 16);
        assert_eq!(pool.leaked_count(), 0);
        assert_eq!(pool.capacity(), 16);
        assert_eq!(pool.slab_size(), 1600);
    }

    #[test]
    fn zero_capacity_pool_allocs_nothing() {
        let pool = IOBufPool::new(0, 128);
        assert_eq!(pool.free_count(), 0);
        assert!(pool.alloc(b"x").is_none());
    }

    #[test]
    fn alloc_copies_frame_and_recycles() {
        let pool = IOBufPool::new(4, 256);
        {
            // `alloc` copies the frame into a slab and hands back a
            // filled, read-only OwnedIOBuf.
            let buf = pool.alloc(b"frame-bytes").expect("fresh pool has slabs");
            assert_eq!(buf.data(), b"frame-bytes");
            assert_eq!(buf.len(), 11);
            assert_eq!(buf.headroom(), 0);
            assert_eq!(buf.tailroom(), 256 - 11);
            assert_eq!(pool.free_count(), 3);
        } // buf dropped here → drop callback recycles the slab
        assert_eq!(pool.free_count(), 4);
        assert_eq!(pool.leaked_count(), 0);
    }

    #[test]
    fn oversize_frame_yields_none() {
        // A frame larger than a slab can't be copied in — `alloc`
        // rejects it without taking a slot.
        let pool = IOBufPool::new(2, 8);
        assert!(pool.alloc(b"this frame is way too long").is_none());
        assert_eq!(pool.free_count(), 2, "no slot consumed by the reject");
    }

    #[test]
    fn exhaustion_yields_none_then_recovers() {
        let pool = IOBufPool::new(2, 64);
        let a = pool.alloc(b"f");
        let b = pool.alloc(b"f");
        assert!(a.is_some() && b.is_some());
        assert!(pool.alloc(b"f").is_none(), "exhausted pool yields None");
        assert_eq!(pool.free_count(), 0);
        drop(a);
        assert_eq!(pool.free_count(), 1);
        assert!(pool.alloc(b"f").is_some(), "a freed slab is reusable");
        drop(b);
        assert_eq!(pool.free_count(), 2);
    }

    #[test]
    fn iobuf_outlives_dropped_pool_handle() {
        // The soundness property: dropping every pool *handle* while
        // an IOBuf is still alive must be safe. The IOBuf holds an
        // Arc strong reference to the slab region, so the region —
        // and the free list `return_slab` recycles into — survives
        // until the last IOBuf drops. Under a raw-pointer-to-pool
        // design this body is a use-after-free.
        let buf = {
            let pool = IOBufPool::new(4, 256);
            let buf = pool.alloc(b"data").expect("fresh pool has slabs");
            buf
            // every `pool` handle drops here; `buf` keeps the region alive
        };
        // Reading the slab is sound — the region is still mapped.
        assert_eq!(buf.data(), b"data");
        assert_eq!(buf.len(), 4);
        // Dropping `buf` runs `return_slab`: it recycles into the
        // still-live PoolInner, then the last Arc drops and frees
        // the region. No use-after-free.
        drop(buf);
    }

    #[test]
    fn lifecycle_scrambled_drop_round_trip() {
        // Plan's stated test: alloc N, drop in scrambled order,
        // verify free_count returns to its initial value.
        let pool = IOBufPool::new(16, 128);
        assert_eq!(pool.free_count(), 16);

        // Drain the whole pool.
        let mut slots: Vec<Option<OwnedIOBuf>> =
            (0..16).map(|_| pool.alloc(b"x")).collect();
        assert!(slots.iter().all(Option::is_some), "pool fully drained");
        assert_eq!(pool.free_count(), 0);

        // Drop in a scrambled permutation of 0..16 — neither LIFO
        // nor FIFO — so the free list is rebuilt in arbitrary order.
        let scramble = [3usize, 11, 0, 7, 15, 1, 9, 5, 13, 2, 10, 6, 14, 4, 12, 8];
        for &i in &scramble {
            drop(slots[i].take()); // drop callback recycles the slab
        }
        assert_eq!(pool.free_count(), 16, "free_count back to initial");
        assert_eq!(pool.leaked_count(), 0);

        // The pool is fully reusable afterward.
        let again: Vec<Option<OwnedIOBuf>> = (0..16).map(|_| pool.alloc(b"x")).collect();
        assert!(again.iter().all(Option::is_some), "pool reusable post-recycle");
    }

    #[test]
    fn foreign_base_is_leaked_not_panicked() {
        // Drive the panic-safe drop path directly: a base pointer
        // that maps to no slot must bump `leaked` and return,
        // never panic, and never disturb the free list.
        let pool = IOBufPool::new(2, 64);
        // `recycle` only does pointer arithmetic on `base` — never
        // dereferences it — so a dangling NonNull is safe input and
        // is guaranteed to fall outside the pool's region.
        pool.inner.recycle(NonNull::<u8>::dangling());
        assert_eq!(pool.leaked_count(), 1, "unmappable base leaks, no panic");
        assert_eq!(pool.free_count(), 2, "free list untouched by the bailout");
    }

    #[test]
    fn concurrent_alloc_free_preserves_all_slabs() {
        // A small pool hammered by many threads: the same handful
        // of slots cycle through the free list constantly,
        // maximising the rate at which a slot is popped, reused,
        // and pushed back inside another thread's pop window — the
        // ABA-prone interleaving. The tagged-pointer head upholds
        // the post-run invariants below deterministically; a naive
        // non-tagged Treiber stack is liable to fail them under
        // this contention (a stale-`next` reinstall resurrects a
        // live slab or drops a free one).
        const SLABS: usize = 8;
        const SLAB_SIZE: usize = 64;
        const THREADS: usize = 8;
        const ITERS: usize = 20_000;

        let pool = IOBufPool::new(SLABS, SLAB_SIZE);
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            // `IOBufPool` is itself a cheap clonable handle (an Arc
            // inside) — no outer `Arc` wrapper needed.
            let p = pool.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..ITERS {
                    // Hold a short batch before freeing it, so a
                    // slot is in flight while peers churn the rest
                    // — widens the ABA window.
                    let mut batch: [Option<OwnedIOBuf>; 3] = [None, None, None];
                    for cell in batch.iter_mut() {
                        *cell = p.alloc(b"frame");
                    }
                    // Drop in reverse to vary the rebuild order.
                    for cell in batch.iter_mut().rev() {
                        *cell = None;
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // Invariant 1: every slab found its way home, none leaked.
        assert_eq!(pool.free_count(), SLABS, "free_count back to initial");
        assert_eq!(pool.leaked_count(), 0, "no slab leaked");

        // Invariant 2: draining the pool yields exactly SLABS
        // slabs, all at DISTINCT base addresses. A free list
        // corrupted by an ABA-induced stale-`next` reinstall would
        // either resurrect a live slab (a duplicate address, or
        // > SLABS pops) or drop one (< SLABS pops).
        let mut held: Vec<OwnedIOBuf> = Vec::new();
        while let Some(buf) = pool.alloc(b"d") {
            held.push(buf);
        }
        let mut bases: Vec<usize> = held.iter().map(|b| b.data().as_ptr() as usize).collect();
        assert_eq!(held.len(), SLABS, "drained slab count");
        bases.sort_unstable();
        bases.dedup();
        assert_eq!(bases.len(), SLABS, "all drained slabs at distinct addresses");
    }
}
