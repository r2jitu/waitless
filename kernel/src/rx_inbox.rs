// kernel/rx_inbox.rs — intrusive-node cross-core hand-off list.
//
// The lock-free machinery behind the Tier 2 RX inbox: one shared NIC
// RX queue, many cores. One core polls the queue (the rotating
// distributor) and hands each received frame to its flow's owning
// core. This module is *how* it crosses — generically, over whatever
// payload `T` the node carries; the kernel instantiates it with
// `T = Chain<OwnedIOBuf>` in `percpu.rs`, so a frame's device RX
// buffers move core-to-core with no payload-byte copy.
//
// Kept generic (like `spsc::Ring<T>`) and `core`-only so it builds
// and unit-tests standalone on the host — the lock-free correctness
// is independent of the payload type.
//
// ── What this replaced ──────────────────────────────────────────
//
// The pre-item-C inbox was a bounded `[u8; 1514]` array ring: the
// distributor `memcpy`'d every frame into a slot. A bounded ring
// forces a drop-on-overflow policy, and tail-dropping a *fresh* TCP
// ACK under load stalls the sender's window — the regression that
// sank the first item-C attempt. This design has no overflow to have
// a policy for (see below) and moves the payload instead of copying.
//
// ── Why an intrusive node, and why it cannot overflow ───────────
//
//   * One `RxNode<T>` exists per slot in a fixed `RxNodePool`.
//   * The kernel's payload is one received frame, which holds exactly
//     one device RX buffer; the NIC has a fixed RX-buffer pool.
//   * A frame can be in-flight through the inbox only while it pins
//     one of those buffers, and distinct in-flight frames pin
//     distinct buffers — so the number of frames parked across every
//     per-core inbox is at most the RX queue's buffer count.
//   * The kernel sizes the pool (`RX_NODE_POOL_CAP` in `percpu.rs`)
//     ≥ that buffer count. So the node supply provably never runs
//     dry: there is never an (N+1)th frame needing an (N+1)th node.
//
// `distribute` still returns `Result` — Rust makes the empty case
// representable — but the `Err` arm is unreachable when the pool is
// sized per that proof. The caller treats it like `IOBufPool`'s
// `leaked` counter: a panic-free bailout for a proven-impossible
// state, not a drop policy.
//
// A cleaner shape exists — fold the node into the driver's per-buffer
// RX state so node-supply *is* buffer-supply and the pool vanishes
// (`sk_buff`/`mbuf` style). That needs a driver-wide RX-surface
// redesign; it is tracked as a planned item in
// `docs/rx-path-optimizations.md`. This module is the contained,
// driver-untouching form.
//
// ── The two lists ───────────────────────────────────────────────
//
// An `RxNode` lives on exactly one intrusive list at a time, so a
// single `next` link (a node index; `NULL` ends the list) serves
// both:
//
//   * Free-list — a Treiber stack in `RxNodePool`. `alloc` pops,
//     `free` pushes. Its head is a **tagged** `AtomicU64` packing
//     `(node_index, version)`; the version increments on every push.
//     That defeats ABA — a node popped, reused, and pushed back
//     under a stalled `alloc` changes the version, so the stale
//     `alloc`'s CAS fails and retries. So the free-list is correct
//     under *any* number of concurrent `alloc`s / `free`s — no
//     single-allocator discipline is load-bearing for soundness
//     (Tier 2 happens to serialise distributors under `RX_LOCK`, but
//     that is now only a performance fact). Same tagged-stack design
//     as `uni_iobuf::IOBufPool`.
//
//   * Inbox — a lock-free MPSC list rooted at `RxInbox::head`, one
//     per core. `push` CAS-prepends; `drain_each` `swap(NULL)`s the
//     whole list. The push is ABA-free without a tag because it
//     never dereferences the old head — a successful CAS just means
//     "head was X, link my node after X", sound regardless of X's
//     history. The swap-detached list is newest-first; `drain_each`
//     reverses it to arrival order so same-flow TCP segments are not
//     reordered.
//
// Everything is index-based (`u32` into the pool's node array), not
// raw pointers: the only `unsafe` left is the `UnsafeCell` payload
// access, guarded by the producer/consumer discipline below.

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// Sentinel node index: terminates an intrusive list and marks the
/// empty free-list. `RxNodePool::new` rejects an `N` that could
/// collide with it, so no real node ever has this index.
const NULL: u32 = u32::MAX;

/// Pack `(node_index, version)` into the tagged free-list head word.
#[inline]
const fn pack(idx: u32, version: u32) -> u64 {
    ((idx as u64) << 32) | version as u64
}

/// Inverse of [`pack`].
#[inline]
const fn unpack(word: u64) -> (u32, u32) {
    ((word >> 32) as u32, word as u32)
}

/// One intrusive hand-off node. Carries a single payload `T` from the
/// distributor core to the owning core. Pre-allocated in an
/// [`RxNodePool`]; never heap-allocated on the hot path.
pub struct RxNode<T> {
    /// Index of the next node on whichever single list currently
    /// holds this one — the pool free-list or one core's inbox — or
    /// `NULL` at the list tail. The two uses are mutually exclusive
    /// (a node is either idle or carrying a payload), so one link
    /// suffices.
    next: AtomicU32,
    /// The parked payload. `None` while the node is on the free-list;
    /// `Some` from when the distributor fills it until the owning
    /// core takes it back out. `UnsafeCell` because both accesses go
    /// through a shared `&RxNode` — the producer/consumer discipline
    /// below, not the type system, keeps them from racing.
    payload: UnsafeCell<Option<T>>,
}

// SAFETY: `RxNode<T>` is `!Sync` only because of the `UnsafeCell`.
// The cell is touched at exactly two points, never concurrently:
//   * the distributor writes it (`store`) on a node it just popped
//     from the free-list — it is the node's sole owner until
//     `RxInbox::push` publishes it;
//   * the owning core reads it (`take`) on a node it just detached
//     via `RxInbox::drain_each`'s `swap` — it is the sole consumer of
//     its own inbox.
// The inbox head's Release CAS (push) / Acquire swap (drain) pair
// orders the write before the read. `T: Send` is required because the
// payload itself crosses cores.
unsafe impl<T: Send> Sync for RxNode<T> {}

impl<T> RxNode<T> {
    const fn new() -> Self {
        RxNode {
            next: AtomicU32::new(NULL),
            payload: UnsafeCell::new(None),
        }
    }

    /// Move `value` into the node.
    ///
    /// SAFETY: the caller must be the node's sole owner — the node
    /// was just `alloc`'d and not yet `push`ed to an inbox. The cell
    /// is always `None` here (a node is freed only after `take` left
    /// `None`, and `new` starts `None`), so nothing live is dropped.
    #[inline]
    unsafe fn store(&self, value: T) {
        unsafe { *self.payload.get() = Some(value) };
    }

    /// Take the parked payload out, leaving the cell `None`.
    ///
    /// SAFETY: the caller must be the node's sole consumer — the node
    /// was just detached from its inbox by `drain_each`.
    #[inline]
    unsafe fn take(&self) -> Option<T> {
        unsafe { (*self.payload.get()).take() }
    }
}

/// A per-core cross-core inbox: the lock-free MPSC list a payload's
/// owning core drains. One lives in each `PerCore`. It is just a head
/// index — the nodes belong to the shared [`RxNodePool`], so every
/// operation is paired with a pool reference.
pub struct RxInbox {
    /// Index of the head node of the intrusive push-list, or `NULL`
    /// when empty. Producers CAS-prepend; the single consumer `swap`s
    /// the whole list out.
    head: AtomicU32,
}

impl Default for RxInbox {
    fn default() -> Self {
        Self::new()
    }
}

impl RxInbox {
    pub const fn new() -> Self {
        RxInbox {
            head: AtomicU32::new(NULL),
        }
    }

    /// Producer side: CAS-prepend node `idx` onto the list. Lock-free
    /// and multi-producer-safe (though Tier 2 has one distributor at
    /// a time under `RX_LOCK`).
    ///
    /// `idx` must already carry its payload and be on no other list.
    fn push<T: Send, const N: usize>(&self, idx: u32, pool: &RxNodePool<T, N>) {
        let node = &pool.nodes[idx as usize];
        loop {
            let head = self.head.load(Ordering::Acquire);
            node.next.store(head, Ordering::Relaxed);
            // Release: publishes both `node.next` and the
            // distributor's earlier `store` to the consumer's Acquire
            // swap. The push never dereferences `head`, so a head
            // that ABA'd back to its old value is harmless here.
            if self
                .head
                .compare_exchange_weak(head, idx, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Consumer side: drain every parked payload in arrival (FIFO)
    /// order, hand each to `f`, and recycle each node back into
    /// `pool`. Returns the number of payloads drained.
    ///
    /// Single-consumer: only the inbox's owning core calls this. Each
    /// payload is taken out and its node freed *before* `f` runs, so
    /// the node is back in the pool while `f` (the network stack) —
    /// possibly slow — processes the payload.
    pub fn drain_each<T: Send, const N: usize>(
        &self,
        pool: &RxNodePool<T, N>,
        mut f: impl FnMut(T),
    ) -> usize {
        // Detach the whole list. Acquire pairs with every producer's
        // Release CAS, so the parked payloads are visible to us.
        let detached = self.head.swap(NULL, Ordering::Acquire);

        // The detached list is newest-first (LIFO). Reverse it so `f`
        // sees payloads oldest-first — LIFO would reorder same-flow
        // TCP segments and stall reassembly.
        let mut fifo = NULL;
        let mut node = detached;
        while node != NULL {
            // We are the sole consumer; no producer touches a node
            // once its CAS linked it.
            let n = &pool.nodes[node as usize];
            let next = n.next.load(Ordering::Relaxed);
            n.next.store(fifo, Ordering::Relaxed);
            fifo = node;
            node = next;
        }

        // Walk oldest-first: snapshot `next`, take the payload,
        // recycle the node, then run `f`.
        let mut count = 0;
        let mut node = fifo;
        while node != NULL {
            let next = pool.nodes[node as usize].next.load(Ordering::Relaxed);
            // SAFETY: sole consumer of this inbox; `node` is detached,
            // so this `&RxNode` is exclusively ours.
            let payload = unsafe { pool.nodes[node as usize].take() };
            // Recycle before running `f`: the node is back in the
            // pool while the (possibly slow) stack processes the
            // payload. Sound even if another core re-`alloc`s it —
            // we already snapshotted `next`.
            pool.free(node);
            // A queued node always carries `Some`; stay panic-free
            // and skip an (impossible) `None` rather than unwrap.
            if let Some(payload) = payload {
                f(payload);
            }
            count += 1;
            node = next;
        }
        count
    }

    /// True if no payloads are parked. Racy by nature — for
    /// diagnostics and drain-loop termination only.
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == NULL
    }
}

/// A fixed pool of `N` pre-allocated [`RxNode`]s with a lock-free
/// tagged-pointer free-list — the whole node supply for one
/// cross-core inbox system.
///
/// `N` is a const parameter so the kernel can hold a `static`
/// `RxNodePool<_, RX_NODE_POOL_CAP>` while tests build a small pool
/// to stress the free-list under contention.
pub struct RxNodePool<T, const N: usize> {
    /// The node storage. Indices into this array are the currency of
    /// both intrusive lists.
    nodes: [RxNode<T>; N],
    /// Treiber-stack head of the free-list: packed `(node_index,
    /// version)`. `node_index == NULL` means exhausted. The version
    /// increments on every push to defeat ABA.
    free_head: AtomicU64,
    /// Live count of free nodes — eventually-consistent, for
    /// observability and tests. Exact once the pool quiesces.
    free_count: AtomicUsize,
}

impl<T: Send, const N: usize> RxNodePool<T, N> {
    /// Build an *uninitialised* pool — every node present but the
    /// free-list empty. Call [`init`](Self::init) once before use.
    /// `const` so the kernel's pool can be a `static`.
    pub const fn new() -> Self {
        // `NULL` is reserved as the list sentinel — a pool large
        // enough to mint it as a real index would corrupt the lists.
        assert!(
            N < NULL as usize,
            "RxNodePool: N must be < u32::MAX (the NULL sentinel)",
        );
        RxNodePool {
            nodes: [const { RxNode::new() }; N],
            free_head: AtomicU64::new(pack(NULL, 0)),
            free_count: AtomicUsize::new(0),
        }
    }

    /// Link every node onto the free-list. Call exactly once, before
    /// any `distribute` / `drain_each`, while single-threaded (BSP
    /// boot for the kernel pool; test setup otherwise).
    pub fn init(&self) {
        for i in 0..N {
            let next = if i + 1 < N { (i + 1) as u32 } else { NULL };
            self.nodes[i].next.store(next, Ordering::Relaxed);
        }
        let head = if N == 0 { NULL } else { 0 };
        self.free_head.store(pack(head, 0), Ordering::Release);
        self.free_count.store(N, Ordering::Relaxed);
    }

    /// Pop a free node index, or `None` if the pool is empty.
    /// Correct under any number of concurrent `alloc`s / `free`s —
    /// the tagged head defeats ABA (see the module docs).
    fn alloc(&self) -> Option<u32> {
        loop {
            let head = self.free_head.load(Ordering::Acquire);
            let (idx, version) = unpack(head);
            if idx == NULL {
                return None;
            }
            // `next[idx]` was published by the push that placed `idx`
            // at the head (its Release CAS); our Acquire load above
            // synchronises with it.
            let next = self.nodes[idx as usize].next.load(Ordering::Relaxed);
            // Pop leaves the version untouched — only pushes bump it.
            // A push slipping in before this CAS changes the word, so
            // the CAS fails and retries.
            if self
                .free_head
                .compare_exchange_weak(
                    head,
                    pack(next, version),
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.free_count.fetch_sub(1, Ordering::Relaxed);
                return Some(idx);
            }
        }
    }

    /// Return node `idx` to the free-list. Multi-producer-safe.
    /// `idx` must be off both the free-list and every inbox.
    fn free(&self, idx: u32) {
        loop {
            let head = self.free_head.load(Ordering::Acquire);
            let (head_idx, version) = unpack(head);
            self.nodes[idx as usize]
                .next
                .store(head_idx, Ordering::Relaxed);
            // Bump the version — the ABA defence. Release publishes
            // the `next` store to a future `alloc`'s Acquire load.
            if self
                .free_head
                .compare_exchange_weak(
                    head,
                    pack(idx, version.wrapping_add(1)),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.free_count.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Distributor side: take a free node, move `payload` into it, and
    /// publish it on `inbox` (the target core's). The caller must then
    /// wake that core.
    ///
    /// Returns `Err(payload)` only if the pool is momentarily empty —
    /// unreachable when the pool is sized per the overflow proof. The
    /// caller drops the returned payload (for the kernel that
    /// auto-reposts its device buffers) and should count the event as
    /// the "impossible happened" signal.
    pub fn distribute(&self, inbox: &RxInbox, payload: T) -> Result<(), T> {
        let idx = match self.alloc() {
            Some(i) => i,
            None => return Err(payload),
        };
        // SAFETY: `idx` just came off the free-list; this core is its
        // sole owner until `push` publishes it, so the payload move
        // is an uncontended store.
        unsafe { self.nodes[idx as usize].store(payload) };
        inbox.push(idx, self);
        Ok(())
    }

    /// Free nodes currently on the list. Eventually-consistent under
    /// concurrency; exact once the pool quiesces.
    pub fn free_count(&self) -> usize {
        self.free_count.load(Ordering::Relaxed)
    }

    /// Total node count (free + in-flight).
    pub fn capacity(&self) -> usize {
        N
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use std::sync::atomic::{AtomicBool, AtomicU64 as StdAtomicU64};
    use std::sync::Arc;
    use std::thread;
    use std::vec::Vec;

    /// A mock payload that carries a sequence number and counts its
    /// own live instances — drop it and the count falls. Stands in
    /// for `Chain<OwnedIOBuf>`: a correct run drops every payload
    /// exactly once (the auto-repost the real driver performs).
    struct Frame {
        seq: u64,
        live: Arc<StdAtomicU64>,
    }

    impl Frame {
        fn new(seq: u64, live: &Arc<StdAtomicU64>) -> Self {
            live.fetch_add(1, Ordering::Relaxed);
            Frame {
                seq,
                live: Arc::clone(live),
            }
        }
    }

    impl Drop for Frame {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn fresh_pool_links_every_node() {
        let pool: RxNodePool<Frame, 16> = RxNodePool::new();
        assert_eq!(pool.free_count(), 0, "uninitialised pool is empty");
        pool.init();
        assert_eq!(pool.free_count(), 16);
        assert_eq!(pool.capacity(), 16);
    }

    #[test]
    fn alloc_drains_then_free_restores() {
        let pool: RxNodePool<Frame, 4> = RxNodePool::new();
        pool.init();
        let mut held = Vec::new();
        while let Some(idx) = pool.alloc() {
            held.push(idx);
        }
        assert_eq!(held.len(), 4, "alloc drains exactly capacity nodes");
        assert_eq!(pool.free_count(), 0);
        // Every drained index is distinct.
        let mut sorted = held.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "alloc never hands out a node twice");
        // Free in a scrambled order so the free-list rebuilds
        // arbitrarily — mirrors `IOBufPool`'s lifecycle test.
        for &i in &[2usize, 0, 3, 1] {
            pool.free(held[i]);
        }
        assert_eq!(pool.free_count(), 4, "free restores the full count");
    }

    #[test]
    fn inbox_drains_in_fifo_order() {
        // The push-list is newest-first; `drain_each` must reverse it
        // so payloads come out oldest-first.
        let live = Arc::new(StdAtomicU64::new(0));
        let pool: RxNodePool<Frame, 8> = RxNodePool::new();
        pool.init();
        let inbox = RxInbox::new();
        for seq in 0..5u64 {
            pool.distribute(&inbox, Frame::new(seq, &live))
                .unwrap_or_else(|_| panic!("pool has nodes"));
        }
        let mut seen = Vec::new();
        let drained = inbox.drain_each(&pool, |f| seen.push(f.seq));
        assert_eq!(drained, 5);
        assert_eq!(seen, std::vec![0, 1, 2, 3, 4], "FIFO, not LIFO");
        assert_eq!(pool.free_count(), 8, "every node recycled");
        assert_eq!(live.load(Ordering::Relaxed), 0, "every payload dropped");
    }

    #[test]
    fn empty_inbox_drains_nothing() {
        let pool: RxNodePool<Frame, 4> = RxNodePool::new();
        pool.init();
        let inbox = RxInbox::new();
        let drained = inbox.drain_each(&pool, |_| panic!("no payloads expected"));
        assert_eq!(drained, 0);
    }

    /// Pure free-list stress, modelled directly on `IOBufPool`'s
    /// 8-thread Treiber-stack test: a tiny pool hammered by many
    /// threads each allocating and freeing concurrently — the
    /// ABA-prone interleaving (a node popped, reused, and pushed back
    /// inside another thread's pop window). The tagged head holds the
    /// post-run invariants; a non-tagged stack is liable to fail them.
    #[test]
    fn concurrent_pool_alloc_free_stress() {
        const POOL: usize = 8;
        const THREADS: usize = 8;
        const ITERS: usize = 20_000;

        struct P(RxNodePool<(), POOL>);
        // SAFETY: `RxNodePool<(), _>` is `Sync` (its `()` payload is
        // `Send`); the wrapper just lets us `Arc` it by name.
        unsafe impl Sync for P {}

        let pool = Arc::new(P(RxNodePool::new()));
        pool.0.init();

        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let p = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                for _ in 0..ITERS {
                    // Hold a short batch so a node is in flight while
                    // peers churn the rest — widens the ABA window.
                    let mut batch = [NULL; 3];
                    for cell in batch.iter_mut() {
                        if let Some(idx) = p.0.alloc() {
                            *cell = idx;
                        }
                    }
                    for &idx in batch.iter() {
                        if idx != NULL {
                            p.0.free(idx);
                        }
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // Every node found its way home — none leaked, none lost.
        assert_eq!(pool.0.free_count(), POOL, "free_count back to initial");
        // Draining yields exactly POOL nodes at distinct indices. An
        // ABA-induced stale-`next` reinstall would resurrect a live
        // node (a duplicate) or drop a free one.
        let mut drained = Vec::new();
        while let Some(idx) = pool.0.alloc() {
            drained.push(idx);
        }
        assert_eq!(drained.len(), POOL, "drained node count");
        drained.sort_unstable();
        drained.dedup();
        assert_eq!(drained.len(), POOL, "all drained nodes distinct");
    }

    /// One distributor core feeds many owning cores through a small
    /// shared pool, hammered hard — the inbox's real concurrency
    /// shape: a single distributor (Tier 2 holds `RX_LOCK`) and many
    /// concurrent `free`rs (the owning cores). A tiny pool forces the
    /// distributor to race the consumers' frees on nearly every node.
    ///
    /// Post-run invariants:
    ///   * every node returns to the pool — none lost or duplicated;
    ///   * every distributed payload is consumed exactly once;
    ///   * per inbox, payloads arrive in FIFO order — the proof that
    ///     `drain_each`'s LIFO→FIFO reversal holds under contention;
    ///   * every payload dropped exactly once — no leak.
    #[test]
    fn concurrent_distribute_drain_stress() {
        const POOL: usize = 8; // tiny: maximise alloc/free races
        const CORES: usize = 4;
        const FRAMES: u64 = 40_000;

        struct Shared {
            pool: RxNodePool<Frame, POOL>,
            inboxes: [RxInbox; CORES],
            done: AtomicBool,
        }
        // SAFETY: every field is `Sync` (`RxNodePool<Frame, _>` —
        // `Frame: Send`; `RxInbox` — a plain atomic; `AtomicBool`).
        // The wrapper just lets us `Arc` it.
        unsafe impl Sync for Shared {}

        let shared = Arc::new(Shared {
            pool: RxNodePool::new(),
            inboxes: [const { RxInbox::new() }; CORES],
            done: AtomicBool::new(false),
        });
        shared.pool.init();
        let live = Arc::new(StdAtomicU64::new(0));

        // Owning cores: each drains its own inbox until the
        // distributor signals done *and* its inbox is empty.
        let mut consumers = Vec::new();
        for core in 0..CORES {
            let s = Arc::clone(&shared);
            consumers.push(thread::spawn(move || {
                let mut seen: Vec<u64> = Vec::new();
                loop {
                    let n = s.inboxes[core].drain_each(&s.pool, |f| seen.push(f.seq));
                    if n == 0 {
                        if s.done.load(Ordering::Acquire) && s.inboxes[core].is_empty() {
                            break;
                        }
                        thread::yield_now();
                    }
                }
                seen
            }));
        }

        // The single distributor: round-robins frames across inboxes,
        // each tagged with a globally-increasing seq. On a momentary
        // pool-empty it spins — a consumer will free a node soon.
        let s = Arc::clone(&shared);
        let live_d = Arc::clone(&live);
        let distributor = thread::spawn(move || {
            let mut sent = [0u64; CORES];
            for seq in 0..FRAMES {
                let target = (seq as usize) % CORES;
                let mut payload = Frame::new(seq, &live_d);
                loop {
                    match s.pool.distribute(&s.inboxes[target], payload) {
                        Ok(()) => break,
                        Err(returned) => {
                            payload = returned;
                            thread::yield_now();
                        }
                    }
                }
                sent[target] += 1;
            }
            s.done.store(true, Ordering::Release);
            sent
        });

        let sent = distributor.join().unwrap();
        let seen: Vec<Vec<u64>> = consumers.into_iter().map(|h| h.join().unwrap()).collect();

        assert_eq!(
            shared.pool.free_count(),
            POOL,
            "every node returned to the pool",
        );
        assert_eq!(live.load(Ordering::Relaxed), 0, "no payload leaked");

        let mut total_seen = 0u64;
        for core in 0..CORES {
            assert_eq!(
                seen[core].len() as u64, sent[core],
                "core {core}: drained count matches sent count",
            );
            total_seen += seen[core].len() as u64;
            // The distributor sent this inbox strictly-increasing
            // seqs; FIFO drain must preserve that. A LIFO bug, or a
            // lost/duplicated node, breaks monotonicity.
            for w in seen[core].windows(2) {
                assert!(
                    w[0] < w[1],
                    "core {core}: payloads out of order ({} then {})",
                    w[0], w[1],
                );
            }
        }
        assert_eq!(total_seen, FRAMES, "every distributed frame consumed once");
    }
}
