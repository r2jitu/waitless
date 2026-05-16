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
// ── Free list: a tagged-pointer Treiber stack ───────────────────
//
// The free list is a lock-free Treiber stack. Its head is a single
// `AtomicU64` packing `(slot_index: u32, version_tag: u32)`. Free
// slabs are linked through a dedicated `next` array (one `AtomicU32`
// per slab) — NOT through the slab bytes themselves, so reading a
// link can never race a payload write on a slab that was just
// popped and handed out.
//
// The `version_tag` is the ABA defense. A plain Treiber stack that
// keys its CAS on the head index alone is vulnerable to ABA: a
// popping thread reads head = slot A, stalls, and by the time it
// runs its CAS another thread has popped A, popped more, and pushed
// A back. The CAS still sees `A` and succeeds — but reinstalls a
// stale `next` link, corrupting the list (resurrecting a live slab,
// or dropping a free one). Incrementing the tag on every *push*
// means any push between a pop's read and its CAS changes the
// 64-bit head word, so the pop's CAS fails and retries. A pop→pop
// pair without an intervening push can't trigger ABA on its own
// (the head index genuinely moves), so tagging pushes alone is
// sufficient.
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
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::{IOBuf, IOBufDropFn};

/// Free-list sentinel: a `slot_index` of `u32::MAX` marks both the
/// empty stack and the tail of the `next` link chain. The pool
/// rejects a `capacity_slabs` that could collide with it, so no
/// real slot ever has this index.
const NULL_SLOT: u32 = u32::MAX;

/// Pack `(slot_index, version)` into the 64-bit Treiber head word.
#[inline]
fn pack(slot: u32, version: u32) -> u64 {
    ((slot as u64) << 32) | (version as u64)
}

/// Inverse of [`pack`].
#[inline]
fn unpack(word: u64) -> (u32, u32) {
    ((word >> 32) as u32, word as u32)
}

/// Fixed-size pool of MTU-sized heap slabs, recycled through a
/// lock-free tagged-pointer Treiber stack.
///
/// # Invariant — the pool must outlive every IOBuf it issues
///
/// [`alloc`](Self::alloc) installs `self` as the drop-callback
/// context of the returned IOBuf. The IOBuf does **not** keep the
/// pool alive (the context is a bare pointer, not an `Arc` handle),
/// and the IOBuf's `data()` views memory the pool owns. The caller
/// MUST therefore guarantee the pool:
///
///   * stays at a **stable address** (place it behind a `Box`,
///     `Arc`, or in a `'static`; do not move it by value), and
///   * **outlives** every IOBuf still in flight,
///
/// for as long as any pool-issued IOBuf — anywhere, on any core —
/// remains undropped. Item B holds the pool in a per-queue-pair
/// driver struct, which satisfies both. Violating this is
/// use-after-free; it is the one safety obligation `alloc` cannot
/// discharge for the caller.
pub struct IOBufPool {
    /// Start of the contiguous slab region: `slab_size *
    /// capacity_slabs` bytes. Obtained via `Box::<[u8]>::into_raw`
    /// (so the pointer carries mutable provenance — pool-issued
    /// IOBufs write slab payload through it); `Drop` reconstructs
    /// the `Box` to free it. The pool itself never reads or writes
    /// slab bytes — only IOBufs do.
    base: NonNull<u8>,
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
    /// Treiber-stack head: packed `(slot_index, version)`. A
    /// `slot_index` of `NULL_SLOT` means the stack is empty. The
    /// version increments on every push to defeat ABA.
    head: AtomicU64,
    /// Live count of free slabs. Eventually-consistent with `head`
    /// (each successful CAS updates it with `Relaxed` ordering);
    /// exact once the pool quiesces. For observability and tests.
    free_count: AtomicUsize,
    /// Count of slabs leaked by the panic-safe drop bailout —
    /// impossible under correct use (see [`recycle`](Self::recycle)).
    /// A non-zero value signals a foreign IOBuf or memory
    /// corruption reached the drop callback.
    leaked: AtomicUsize,
}

// SAFETY: every field mutated after construction is an atomic
// (`head`, `free_count`, `leaked`) or a slice of atomics (`next`) —
// all sound to touch through `&self` from many threads. `base` is a
// raw pointer used only for address arithmetic and for handing slab
// pointers to IOBufs; the pool itself never dereferences it, so it
// introduces no data race. `slab_size` / `capacity_slabs` are
// immutable. Hence concurrent shared access is sound (`Sync`), and
// moving the pool across threads before it issues any IOBuf is
// sound (`Send`) — moving it *after* would break the
// pool-outlives-IOBufs invariant documented on the type, which is
// the caller's obligation, not something `Send` can police.
unsafe impl Send for IOBufPool {}
unsafe impl Sync for IOBufPool {}

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
        let span = slab_size_bytes
            .checked_mul(capacity_slabs)
            .expect("IOBufPool: slab_size * capacity overflows usize");

        // Contiguous slab region. `Box::into_raw` hands the
        // allocation to a raw pointer carrying mutable provenance
        // (pool-issued IOBufs write payload through it); `Drop`
        // reconstructs the `Box` to free it. Zero-filled to keep
        // info-leak-class bugs away, matching `IOBuf::new_with_reserved`.
        let storage: Box<[u8]> = alloc::vec![0u8; span].into_boxed_slice();
        // SAFETY: a `Box`'s data pointer is always non-null.
        let base = unsafe { NonNull::new_unchecked(Box::into_raw(storage) as *mut u8) };

        // Intrusive free-list links: slab i → slab i+1, tail → NULL.
        // The whole pool starts free with the head at slot 0.
        let mut links = alloc::vec::Vec::with_capacity(capacity_slabs);
        for i in 0..capacity_slabs {
            let next = if i + 1 < capacity_slabs {
                (i + 1) as u32
            } else {
                NULL_SLOT
            };
            links.push(AtomicU32::new(next));
        }
        let head = if capacity_slabs == 0 {
            pack(NULL_SLOT, 0)
        } else {
            pack(0, 0)
        };

        IOBufPool {
            base,
            slab_size: slab_size_bytes as u32,
            capacity_slabs: capacity_slabs as u32,
            next: links.into_boxed_slice(),
            head: AtomicU64::new(head),
            free_count: AtomicUsize::new(capacity_slabs),
            leaked: AtomicUsize::new(0),
        }
    }

    /// Take a slab off the free list and wrap it as an
    /// `ExternalOwned` IOBuf, or `None` when the pool is exhausted.
    ///
    /// The returned IOBuf has an empty visible payload (`len = 0`,
    /// zero headroom, the whole slab as tailroom) — the consumer
    /// grows it via `append_slice` / `extend_uninit`. On drop, the
    /// slab recycles itself back here, possibly from another core.
    ///
    /// See the type-level docs for the pool-outlives-IOBufs
    /// invariant the caller must uphold.
    pub fn alloc(&self) -> Option<IOBuf> {
        let slot = self.pop_slot()?;
        // SAFETY:
        //  * `slab_base .. slab_base + slab_size` is one distinct
        //    slab inside our region — `slot` came off the free list
        //    so it is in `0..capacity_slabs`, and `pop_slot`
        //    removed it, so no other live IOBuf or concurrent pool
        //    op aliases it.
        //  * offset 0 + len 0 <= slab_size (the IOBuf's capacity).
        //  * `return_slab` is sound to invoke once at drop: it maps
        //    `base` back to a slot and Treiber-pushes it. The
        //    `drop_ctx` is `self`; the pool-outlives-IOBufs
        //    invariant (type docs) guarantees it stays live and
        //    unmoved, so the callback's `&*` is valid.
        let slab_base = unsafe {
            NonNull::new_unchecked(
                self.base
                    .as_ptr()
                    .add(slot as usize * self.slab_size as usize),
            )
        };
        let buf = unsafe {
            IOBuf::wrap_owned(
                slab_base,
                self.slab_size,
                0,
                0,
                Self::return_slab as IOBufDropFn,
                self as *const IOBufPool as *mut (),
            )
        };
        Some(buf)
    }

    /// Free slabs currently on the list. Eventually-consistent
    /// under concurrency; exact once the pool quiesces.
    pub fn free_count(&self) -> usize {
        self.free_count.load(Ordering::Relaxed)
    }

    /// Slabs leaked by the panic-safe drop bailout. Always `0`
    /// under correct use; a non-zero value is a red flag.
    pub fn leaked_count(&self) -> usize {
        self.leaked.load(Ordering::Relaxed)
    }

    /// Total number of slabs (free + in flight).
    pub fn capacity(&self) -> usize {
        self.capacity_slabs as usize
    }

    /// Bytes per slab.
    pub fn slab_size(&self) -> usize {
        self.slab_size as usize
    }

    /// Treiber-stack pop. Loops on CAS contention; returns `None`
    /// only when the stack is genuinely empty.
    fn pop_slot(&self) -> Option<u32> {
        loop {
            let head = self.head.load(Ordering::Acquire);
            let (slot, version) = unpack(head);
            if slot == NULL_SLOT {
                return None; // pool exhausted
            }
            // `next[slot]` is published by the push that placed
            // `slot` at the head: that push stored the link, then
            // ran a `Release` CAS on `head`; our `Acquire` load
            // above synchronizes-with it, so this `Relaxed` load
            // observes the correct link.
            let next = self.next[slot as usize].load(Ordering::Relaxed);
            // Pop keeps the version word unchanged — only pushes
            // bump it. If a push slips in before our CAS, the head
            // word differs and the CAS retries.
            let new = pack(next, version);
            if self
                .head
                .compare_exchange_weak(head, new, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                self.free_count.fetch_sub(1, Ordering::Relaxed);
                return Some(slot);
            }
            // CAS lost the race (or spuriously failed) — retry.
        }
    }

    /// Treiber-stack push. Loops on CAS contention.
    fn push_slot(&self, slot: u32) {
        loop {
            let head = self.head.load(Ordering::Acquire);
            let (head_slot, version) = unpack(head);
            // Point this slab's link at the current head. Only one
            // thread ever pushes a given slab (the one dropping its
            // IOBuf), so this store is unconflicted; the CAS below
            // publishes it.
            self.next[slot as usize].store(head_slot, Ordering::Relaxed);
            // Bump the version on push — the tagged-pointer ABA
            // defense. Any pop that read the old head between its
            // load and CAS now sees a changed word and retries.
            let new = pack(slot, version.wrapping_add(1));
            if self
                .head
                .compare_exchange_weak(head, new, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                self.free_count.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Drop callback for pool-issued IOBufs. Installed as the
    /// `drop_fn` by [`alloc`](Self::alloc); runs once when the
    /// IOBuf drops, possibly on a different core than `alloc`.
    ///
    /// SAFETY: `ctx` is the `*const IOBufPool` installed by
    /// `alloc`; the pool-outlives-IOBufs invariant (type docs)
    /// guarantees it points at a live, unmoved pool. `base` /
    /// `capacity` are the originals passed to `wrap_owned`.
    unsafe fn return_slab(base: NonNull<u8>, _capacity: u32, ctx: *mut ()) {
        // SAFETY: see the doc comment — `ctx` is a live pool.
        let pool = unsafe { &*(ctx as *const IOBufPool) };
        pool.recycle(base);
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
        let region_start = self.base.as_ptr() as usize;
        let addr = base.as_ptr() as usize;
        let span = self.slab_size as usize * self.capacity_slabs as usize;
        let slot = addr
            .checked_sub(region_start)
            .filter(|off| *off < span && off % self.slab_size as usize == 0)
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

impl Drop for IOBufPool {
    fn drop(&mut self) {
        // Reconstruct the `Box<[u8]>` leaked via `Box::into_raw` in
        // `new` so the slab region is freed exactly once.
        //
        // SAFETY: `base` came from `Box::<[u8]>::into_raw`;
        // rebuilding a `*mut [u8]` of the original length and
        // calling `Box::from_raw` is the documented round-trip. The
        // pool-outlives-IOBufs invariant means no live IOBuf still
        // views this region at drop time.
        let span = self.slab_size as usize * self.capacity_slabs as usize;
        unsafe {
            let slice = core::ptr::slice_from_raw_parts_mut(self.base.as_ptr(), span);
            drop(Box::from_raw(slice));
        }
    }
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
    use std::sync::Arc;
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
        assert!(pool.alloc().is_none());
    }

    #[test]
    fn alloc_slab_is_writable_and_recycles() {
        let pool = IOBufPool::new(4, 256);
        {
            let mut buf = pool.alloc().expect("fresh pool has slabs");
            // Empty payload, whole slab is tailroom.
            assert_eq!(buf.len(), 0);
            assert_eq!(buf.headroom(), 0);
            assert_eq!(buf.tailroom(), 256);
            // The ExternalOwned slab is a fully usable IOBuf.
            buf.append_slice(b"frame-bytes").unwrap();
            assert_eq!(buf.data(), b"frame-bytes");
            assert_eq!(pool.free_count(), 3);
        } // buf dropped here → drop callback recycles the slab
        assert_eq!(pool.free_count(), 4);
        assert_eq!(pool.leaked_count(), 0);
    }

    #[test]
    fn exhaustion_yields_none_then_recovers() {
        let pool = IOBufPool::new(2, 64);
        let a = pool.alloc();
        let b = pool.alloc();
        assert!(a.is_some() && b.is_some());
        assert!(pool.alloc().is_none(), "exhausted pool yields None");
        assert_eq!(pool.free_count(), 0);
        drop(a);
        assert_eq!(pool.free_count(), 1);
        assert!(pool.alloc().is_some(), "a freed slab is reusable");
        drop(b);
        assert_eq!(pool.free_count(), 2);
    }

    #[test]
    fn lifecycle_scrambled_drop_round_trip() {
        // Plan's stated test: alloc N, drop in scrambled order,
        // verify free_count returns to its initial value.
        let pool = IOBufPool::new(16, 128);
        assert_eq!(pool.free_count(), 16);

        // Drain the whole pool.
        let mut slots: Vec<Option<IOBuf>> = (0..16).map(|_| pool.alloc()).collect();
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
        let again: Vec<Option<IOBuf>> = (0..16).map(|_| pool.alloc()).collect();
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
        pool.recycle(NonNull::<u8>::dangling());
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

        let pool = Arc::new(IOBufPool::new(SLABS, SLAB_SIZE));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let p = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                for _ in 0..ITERS {
                    // Hold a short batch before freeing it, so a
                    // slot is in flight while peers churn the rest
                    // — widens the ABA window.
                    let mut batch: [Option<IOBuf>; 3] = [None, None, None];
                    for cell in batch.iter_mut() {
                        *cell = p.alloc();
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
        let mut held: Vec<IOBuf> = Vec::new();
        while let Some(buf) = pool.alloc() {
            held.push(buf);
        }
        let mut bases: Vec<usize> = held.iter().map(|b| b.data().as_ptr() as usize).collect();
        assert_eq!(held.len(), SLABS, "drained slab count");
        bases.sort_unstable();
        bases.dedup();
        assert_eq!(bases.len(), SLABS, "all drained slabs at distinct addresses");
        // `held` drops before `pool` (reverse declaration order):
        // each IOBuf recycles into the still-live pool, then the
        // pool's `Arc` drops and frees the slab region.
    }
}
