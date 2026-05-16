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
use alloc::sync::Arc;
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

/// Shared inner state of a pool: the slab region, the lock-free
/// free list, and the counters. Heap-pinned behind an `Arc` (see
/// [`IOBufPool`]) so it sits at a stable address and is kept alive
/// by reference count for at least as long as any pool-issued
/// IOBuf — which is what makes the pool's API sound.
struct PoolInner {
    /// Start of the contiguous slab region: `slab_size *
    /// capacity_slabs` bytes. Obtained via `Box::<[u8]>::into_raw`
    /// (so the pointer carries mutable provenance — pool-issued
    /// IOBufs write slab payload through it); `Drop` reconstructs
    /// the `Box` to free it. `PoolInner` itself never reads or
    /// writes slab bytes — only IOBufs do.
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
    /// impossible under correct use (see [`PoolInner::recycle`]).
    /// A non-zero value signals a foreign IOBuf or memory
    /// corruption reached the drop callback.
    leaked: AtomicUsize,
}

// SAFETY: every field mutated after construction is an atomic
// (`head`, `free_count`, `leaked`) or a slice of atomics (`next`) —
// all sound to touch through `&self` from many threads. `base` is a
// raw pointer used only for address arithmetic and for handing slab
// pointers to IOBufs; `PoolInner` itself never dereferences it, so
// it introduces no data race. `slab_size` / `capacity_slabs` are
// immutable. Hence concurrent shared access is sound (`Sync`), and
// it is sound to move / drop the `Arc<PoolInner>` on any thread
// (`Send`).
unsafe impl Send for PoolInner {}
unsafe impl Sync for PoolInner {}

impl PoolInner {
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

impl Drop for PoolInner {
    fn drop(&mut self) {
        // Reconstruct the `Box<[u8]>` leaked via `Box::into_raw` in
        // `IOBufPool::new` so the slab region is freed exactly once.
        //
        // SAFETY: `base` came from `Box::<[u8]>::into_raw`;
        // rebuilding a `*mut [u8]` of the original length and
        // calling `Box::from_raw` is the documented round-trip.
        // `PoolInner` drops only when its last `Arc` reference goes
        // away — and every pool-issued IOBuf holds one — so no live
        // IOBuf still views this region at drop time.
        let span = self.slab_size as usize * self.capacity_slabs as usize;
        unsafe {
            let slice = core::ptr::slice_from_raw_parts_mut(self.base.as_ptr(), span);
            drop(Box::from_raw(slice));
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
        let span = slab_size_bytes
            .checked_mul(capacity_slabs)
            .expect("IOBufPool: slab_size * capacity overflows usize");

        // Contiguous slab region. `Box::into_raw` hands the
        // allocation to a raw pointer carrying mutable provenance
        // (pool-issued IOBufs write payload through it);
        // `PoolInner::drop` reconstructs the `Box` to free it.
        // Zero-filled to keep info-leak-class bugs away, matching
        // `IOBuf::new_with_reserved`.
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
            inner: Arc::new(PoolInner {
                base,
                slab_size: slab_size_bytes as u32,
                capacity_slabs: capacity_slabs as u32,
                next: links.into_boxed_slice(),
                head: AtomicU64::new(head),
                free_count: AtomicUsize::new(capacity_slabs),
                leaked: AtomicUsize::new(0),
            }),
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
    /// The IOBuf carries a strong `Arc` reference to the pool's
    /// inner state, so it keeps the slab region alive on its own —
    /// see the [`IOBufPool`] type docs.
    pub fn alloc(&self) -> Option<IOBuf> {
        let slot = self.inner.pop_slot()?;
        // Hand the IOBuf its own strong reference to `PoolInner`:
        // `into_raw` consumes one `Arc` clone, parking that strong
        // count in the IOBuf's drop context; `return_slab` reclaims
        // it with `from_raw`. While the IOBuf lives, the pool's
        // slab region is reference-counted alive. (Done only after
        // `pop_slot` succeeds, so a `None` alloc leaks no count.)
        let ctx = Arc::into_raw(Arc::clone(&self.inner)) as *mut ();
        // SAFETY:
        //  * `slab_base .. slab_base + slab_size` is one distinct
        //    slab inside the region — `slot` came off the free list
        //    so it is in `0..capacity_slabs`, and `pop_slot`
        //    removed it, so no other live IOBuf or concurrent pool
        //    op aliases it.
        //  * offset 0 + len 0 <= slab_size (the IOBuf's capacity).
        //  * `return_slab` is sound to invoke once at drop: it
        //    reclaims the `Arc` from `ctx` and recycles the slab.
        //    The `Arc` strong reference keeps `PoolInner` (and the
        //    slab region) alive for the IOBuf's whole lifetime, so
        //    both the slab bytes and the `ctx` pointee stay valid.
        let buf = unsafe {
            let slab_base = NonNull::new_unchecked(
                self.inner
                    .base
                    .as_ptr()
                    .add(slot as usize * self.inner.slab_size as usize),
            );
            IOBuf::wrap_owned(
                slab_base,
                self.inner.slab_size,
                0,
                0,
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
/// SAFETY: `ctx` is the pointer produced by
/// `Arc::<PoolInner>::into_raw` in `alloc`. `Arc::from_raw` reclaims
/// exactly the one strong reference the IOBuf held; the pairing is
/// balanced (one `into_raw` per `alloc`, one `from_raw` per drop,
/// and `Drop` runs once). `base` / `capacity` are the originals
/// passed to `wrap_owned`.
unsafe fn return_slab(base: NonNull<u8>, _capacity: u32, ctx: *mut ()) {
    // SAFETY: see the doc comment — `ctx` is a live `into_raw`'d Arc.
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
    fn iobuf_outlives_dropped_pool_handle() {
        // The soundness property: dropping every pool *handle* while
        // an IOBuf is still alive must be safe. The IOBuf holds an
        // Arc strong reference to the slab region, so the region —
        // and the free list `return_slab` recycles into — survives
        // until the last IOBuf drops. Under a raw-pointer-to-pool
        // design this body is a use-after-free.
        let buf = {
            let pool = IOBufPool::new(4, 256);
            let buf = pool.alloc().expect("fresh pool has slabs");
            buf
            // every `pool` handle drops here; `buf` keeps the region alive
        };
        // Reading the slab is sound — the region is still mapped.
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.tailroom(), 256);
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
    }
}
