// util/tagged_treiber/lib.rs — the shared tagged-pointer Treiber
// free-list core.
//
// A `TaggedTreiberStack` is a lock-free LIFO of `u32` slot indices —
// the free-list machinery that backs a fixed-size object pool. Two
// pools in this workspace use it: `iobuf::IOBufPool` (the gVNIC
// GQI RX slab recycler) and `uni_kernel::rx_inbox::RxNodePool` (the
// Tier-2 cross-core hand-off node pool). Each used to carry its own
// byte-identical copy of this ~40-line CAS core; this crate is the
// one audited copy they both delegate to.
//
// Kept zero-dep and `core`-only — like `util/atomic_fn` — so the
// `rust_test`s that pull it in (`//uni-iobuf:iobuf_test`,
// `//kernel:rx_inbox_test`) don't inherit `//kernel`'s RustCrypto /
// talc / `panic=abort` dependency chain.
//
// ── What the stack is ───────────────────────────────────────────
//
// The stack is *just a head word*: one `AtomicU64` packing
// `(index: u32, version: u32)`. It owns no storage — not the slots,
// not the `next` links. The consuming pool owns those and lends its
// link space to every `push` / `pop` through the `TreiberLinks`
// accessor (see below). That is what keeps this crate
// index-and-`AtomicU32`-only and genuinely zero-dep `core`.
//
// `pop` takes the head index off and republishes its `next` link as
// the new head; `push` links a returned index in at the head. Both
// are CAS loops — lock-free, and safe under any number of concurrent
// producers and consumers.
//
// ── The version tag: the ABA defence ────────────────────────────
//
// A plain Treiber stack that keys its CAS on the head index alone is
// vulnerable to ABA. A popping thread reads head = slot A, stalls,
// and by the time it runs its CAS another thread has popped A,
// popped more, and pushed A back. The CAS still sees `A` and
// succeeds — but reinstalls a *stale* `next` link, corrupting the
// list (resurrecting a live slot, or dropping a free one).
//
// The `version` half of the head word is the defence: every `push`
// increments it. Any push that slips between a pop's head read and
// its CAS therefore changes the 64-bit head word, so the pop's CAS
// fails and retries. A pop→pop pair with no intervening push cannot
// trigger ABA on its own (the head index genuinely moves), so
// tagging pushes alone is sufficient.
//
// ── Generic over the next-link accessor ─────────────────────────
//
// The two pools store their `next` links differently: `IOBufPool` in
// a dedicated `Box<[AtomicU32]>` array (kept apart from slab payload
// so a link read never races a payload write on a reused slab),
// `RxNodePool` in a per-node `AtomicU32` field. The stack stays
// agnostic by taking a `&impl TreiberLinks` on every `push` / `pop`
// — a one-method trait mapping a slot index to its `&AtomicU32`
// link. Each pool implements it; the calls monomorphise per consumer,
// so there is no dynamic dispatch on the RX hot path.
//
// ── What is NOT here ────────────────────────────────────────────
//
// Only the lock-free core. The pools' `free_count` / `leaked`
// observability counters stay pool-side: they are eventually-
// consistent `Relaxed` counters, not part of the stack's lock-free
// correctness, and each pool surfaces them through its own public
// API. Extracting them would mean a shared type that is no longer
// "just the stack core".

// `cfg_attr(not(test), no_std)` is the workspace-standard test
// pattern (see `util/atomic_fn`): `no_std` for every production
// build, flipping to `std` only under `--test` so the libtest
// harness has the `std` it needs.
#![cfg_attr(not(test), no_std)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Sentinel slot index: marks both the empty stack and the tail of a
/// `next` link chain. A pool must reject any real index that could
/// collide with it — both current consumers assert
/// `capacity < NULL_INDEX` at construction.
pub const NULL_INDEX: u32 = u32::MAX;

/// Pack `(index, version)` into the 64-bit head word.
#[inline]
const fn pack(index: u32, version: u32) -> u64 {
    ((index as u64) << 32) | version as u64
}

/// Inverse of [`pack`].
#[inline]
const fn unpack(word: u64) -> (u32, u32) {
    ((word >> 32) as u32, word as u32)
}

/// The `next`-link accessor a pool lends to its [`TaggedTreiberStack`].
///
/// The stack holds only the head word; the intrusive `next` links
/// live in pool-owned storage. Implementing this one method is the
/// whole of wiring that storage to the shared stack core.
pub trait TreiberLinks {
    /// Borrow the `AtomicU32` holding slot `idx`'s `next` link.
    ///
    /// `idx` is always a value the stack previously took from this
    /// same pool's link space — in `0..capacity`, never
    /// [`NULL_INDEX`] — so an implementation needs no validation
    /// beyond the bounds check the slot lookup already performs.
    fn next_link(&self, idx: u32) -> &AtomicU32;
}

/// A lock-free tagged-pointer Treiber stack of `u32` slot indices.
///
/// One `AtomicU64` head word packing `(index, version)`; see the
/// module docs for the ABA rationale. The stack owns no slot storage
/// — every `push` / `pop` is handed the pool's [`TreiberLinks`]
/// accessor.
pub struct TaggedTreiberStack {
    /// Packed `(index, version)`. `index == NULL_INDEX` means the
    /// stack is empty; `version` increments on every push to defeat
    /// ABA.
    head: AtomicU64,
}

impl TaggedTreiberStack {
    /// A stack whose head is slot `head` at version 0. Pass
    /// [`NULL_INDEX`] for an initially-empty stack.
    ///
    /// `const` so a pool's own `const fn new` can build one for a
    /// `static` (the kernel's `RxNodePool` relies on this).
    pub const fn new(head: u32) -> Self {
        TaggedTreiberStack {
            head: AtomicU64::new(pack(head, 0)),
        }
    }

    /// Republish the head as slot `head` at version 0.
    ///
    /// For a pool that constructs its stack empty in a `const`
    /// context and links its slots only later: `reset` is the
    /// single-threaded "the free-list now starts here" call. Release-
    /// ordered, so the `next` links the caller stored beforehand are
    /// visible to the first concurrent [`pop`](Self::pop).
    pub fn reset(&self, head: u32) {
        self.head.store(pack(head, 0), Ordering::Release);
    }

    /// Push slot `idx` onto the stack. Loops on CAS contention;
    /// safe under any number of concurrent producers.
    ///
    /// `idx`'s `next` link is overwritten, so `idx` must be off this
    /// stack and off every other intrusive list. Only the thread
    /// returning a given slot pushes it, so the `next` store is
    /// unconflicted; the CAS publishes it.
    pub fn push(&self, idx: u32, links: &impl TreiberLinks) {
        loop {
            let head = self.head.load(Ordering::Acquire);
            let (head_idx, version) = unpack(head);
            // Point this slot's link at the current head.
            links.next_link(idx).store(head_idx, Ordering::Relaxed);
            // Bump the version on push — the tagged-pointer ABA
            // defence. Any pop that read the old head between its
            // load and CAS now sees a changed word and retries.
            // Release publishes the `next` store to that pop's
            // Acquire load.
            if self
                .head
                .compare_exchange_weak(
                    head,
                    pack(idx, version.wrapping_add(1)),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return;
            }
            // CAS lost the race (or spuriously failed) — retry.
        }
    }

    /// Pop the head slot, or `None` when the stack is empty. Loops on
    /// CAS contention; safe under any number of concurrent consumers.
    pub fn pop(&self, links: &impl TreiberLinks) -> Option<u32> {
        loop {
            let head = self.head.load(Ordering::Acquire);
            let (idx, version) = unpack(head);
            if idx == NULL_INDEX {
                return None; // stack empty
            }
            // `next[idx]` was published by the push that placed `idx`
            // at the head: that push stored the link, then ran a
            // Release CAS on `head`; our Acquire load above
            // synchronises-with it, so this Relaxed load observes the
            // correct link.
            let next = links.next_link(idx).load(Ordering::Relaxed);
            // Pop keeps the version word unchanged — only pushes bump
            // it. If a push slips in before our CAS, the head word
            // differs and the CAS retries.
            if self
                .head
                .compare_exchange_weak(
                    head,
                    pack(next, version),
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Some(idx);
            }
            // CAS lost the race (or spuriously failed) — retry.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::thread;

    /// A minimal pool: a `next`-link array plus the stack — exactly
    /// the wiring `IOBufPool` and `RxNodePool` each build around the
    /// shared core, reduced to the parts the stack touches.
    struct LinkPool {
        next: Vec<AtomicU32>,
        stack: TaggedTreiberStack,
    }

    impl TreiberLinks for LinkPool {
        fn next_link(&self, idx: u32) -> &AtomicU32 {
            &self.next[idx as usize]
        }
    }

    impl LinkPool {
        /// `n` slots, all free: links `0 → 1 → … → n-1 → NULL`, head
        /// at slot 0 (or empty when `n == 0`).
        fn full(n: u32) -> Self {
            let next = (0..n)
                .map(|i| AtomicU32::new(if i + 1 < n { i + 1 } else { NULL_INDEX }))
                .collect();
            let head = if n == 0 { NULL_INDEX } else { 0 };
            LinkPool {
                next,
                stack: TaggedTreiberStack::new(head),
            }
        }

        /// `n` slots linked but the stack left empty — the pattern a
        /// `const`-constructed pool uses before its `reset` call.
        fn unlinked(n: u32) -> Self {
            let mut pool = LinkPool::full(n);
            pool.stack = TaggedTreiberStack::new(NULL_INDEX);
            pool
        }

        fn pop(&self) -> Option<u32> {
            self.stack.pop(self)
        }

        fn push(&self, idx: u32) {
            self.stack.push(idx, self);
        }

        /// Drain the whole stack into a vector, in pop order.
        fn drain(&self) -> Vec<u32> {
            let mut out = Vec::new();
            while let Some(idx) = self.pop() {
                out.push(idx);
            }
            out
        }
    }

    #[test]
    fn pack_unpack_round_trips() {
        for &(idx, ver) in &[
            (0u32, 0u32),
            (1, 2),
            (NULL_INDEX, 0),
            (7, u32::MAX),
            (u32::MAX, u32::MAX),
        ] {
            assert_eq!(unpack(pack(idx, ver)), (idx, ver));
        }
    }

    #[test]
    fn empty_stack_pops_none() {
        let pool = LinkPool::full(0);
        assert!(pool.pop().is_none());
    }

    #[test]
    fn pop_drains_lifo_then_push_restores() {
        let pool = LinkPool::full(4);
        // Head is slot 0, links run 0→1→2→3, so pops come out 0,1,2,3.
        assert_eq!(pool.drain(), vec![0, 1, 2, 3], "pop order from head 0");
        assert!(pool.pop().is_none(), "drained stack is empty");

        // Push back in a scrambled order so the list rebuilds
        // arbitrarily; every slot must still come home.
        for &idx in &[2u32, 0, 3, 1] {
            pool.push(idx);
        }
        let mut back = pool.drain();
        back.sort_unstable();
        assert_eq!(back, vec![0, 1, 2, 3], "every slot recovered");
    }

    #[test]
    fn push_is_lifo() {
        // A fresh stack with no slots on it; push 0,1,2 and they pop
        // back newest-first.
        let pool = LinkPool::unlinked(3);
        assert!(pool.pop().is_none(), "unlinked stack starts empty");
        pool.push(0);
        pool.push(1);
        pool.push(2);
        assert_eq!(pool.drain(), vec![2, 1, 0], "LIFO pop order");
    }

    #[test]
    fn reset_republishes_the_head() {
        // `unlinked` mirrors a `const`-constructed pool: slots linked,
        // stack empty. `reset` is the single-threaded call that makes
        // the free-list live.
        let pool = LinkPool::unlinked(3);
        assert!(pool.pop().is_none(), "empty before reset");
        pool.stack.reset(0);
        assert_eq!(pool.drain(), vec![0, 1, 2], "reset made slot 0 the head");
    }

    /// 8-thread ABA stress test, ported from `IOBufPool`'s
    /// `concurrent_alloc_free_preserves_all_slabs` and `RxNodePool`'s
    /// `concurrent_pool_alloc_free_stress`: a tiny stack hammered by
    /// many threads, each popping a short batch and pushing it back —
    /// so a slot is constantly popped, reused, and pushed back inside
    /// another thread's pop window, the ABA-prone interleaving. The
    /// version tag holds the post-run invariant; a non-tagged stack
    /// is liable to fail it (a stale-`next` reinstall resurrects a
    /// live slot or drops a free one).
    #[test]
    fn concurrent_push_pop_preserves_every_slot() {
        const SLOTS: u32 = 8;
        const THREADS: usize = 8;
        const ITERS: usize = 20_000;

        // `LinkPool` is `Send + Sync` automatically — its fields are a
        // `Vec<AtomicU32>` and an `AtomicU64`-backed stack — so it
        // needs no `unsafe` wrapper to cross threads in an `Arc`.
        let pool = Arc::new(LinkPool::full(SLOTS));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let p = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                for _ in 0..ITERS {
                    // Hold a short batch before pushing it back, so a
                    // slot is in flight while peers churn the rest —
                    // widens the ABA window.
                    let mut batch = [NULL_INDEX; 3];
                    for cell in batch.iter_mut() {
                        if let Some(idx) = p.pop() {
                            *cell = idx;
                        }
                    }
                    // Push in reverse to vary the rebuild order.
                    for &idx in batch.iter().rev() {
                        if idx != NULL_INDEX {
                            p.push(idx);
                        }
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // Draining yields exactly SLOTS slots at DISTINCT indices. An
        // ABA-induced stale-`next` reinstall would resurrect a live
        // slot (a duplicate, or > SLOTS pops) or drop one (< SLOTS).
        let mut drained = pool.drain();
        assert_eq!(drained.len(), SLOTS as usize, "drained slot count");
        drained.sort_unstable();
        drained.dedup();
        assert_eq!(drained.len(), SLOTS as usize, "all drained slots distinct");
    }
}
