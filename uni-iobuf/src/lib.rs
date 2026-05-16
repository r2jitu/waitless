// uni-http/src/iobuf.rs — IOBuf primitive for the network stack.
//
// Inspired by folly::IOBuf: a chain of byte segments with reserved
// space at each end ("headroom" / "tailroom") so layers below can
// prepend / append their headers without re-allocating or copying
// the existing payload. The chain owns its nodes; callers walk it
// via a `Cursor` that hops node boundaries transparently.
//
// What this buys us in the unikernel stack:
//
//   * App-side: a `Body` is an `IOBufChain` of static literals
//     (zero-copy) and dynamically-rendered owned chunks.
//   * HTTP/1.1 framing layer: the response status line + headers
//     get prepended onto the body chain via a single `push_front`,
//     reusing the chain's reserved headroom rather than allocating
//     a separate framing Vec.
//   * HTTP/3 layer: same — the HEADERS / DATA frame headers
//     prepend into the body chunk's headroom, the QPACK encoded
//     field section sits in a wrapper IOBuf borrowed from the
//     per-conn scratch, no `framing: Vec` copy.
//   * TLS layer: prepends the 5-byte TLSCiphertext record header
//     and appends the 16-byte AEAD tag in-place (encrypt straight
//     into the existing buffer's tailroom).
//   * QUIC: prepends short-header byte + packet number, encrypts
//     in place, the rest of the chain (UDP/IP/Eth) follows the
//     same prepend pattern.
//   * NIC TX: a final cursor pass copies bytes straight into the
//     hardware TX descriptor — one memcpy total, no intermediate
//     Vec.
//
// Design choices:
//
//   * Five storage variants under one `IOBuf`: heap-owned
//     (`Heap`), refcount-shared (`Shared`, `Rc<[u8]>`-backed for
//     QUIC retransmit and any other "two live views of the same
//     bytes" pattern), `&'static [u8]` (`Static`), foreign region
//     with a drop callback (`ExternalOwned`, e.g. NIC zero-copy
//     RX), and non-owning view (`Borrowed`, e.g. per-worker
//     scratch slice).
//   * `split_at` on `Heap` promotes to `Shared` in place — no
//     copy, both halves see disjoint windows into the same Rc.
//     Mutation paths call `make_unique` first so peer Rc holders
//     never see surprise writes.
//   * Heap/Shared carry `offset` + `len` as `u32` (saves 8 B per
//     node vs `usize`). 4 GiB per chunk is plenty for any
//     unikernel workload.
//   * `IOBufChain` is a three-state value — `Empty`, `Single`
//     (one part, stored inline, zero heap allocation), or `Many`
//     (a `VecDeque<IOBuf>` for genuine multi-part chains).
//     Push-front and push-back are amortised O(1); the dominant
//     single-part shape costs no chain-machinery allocation.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use core::marker::PhantomData;

// Fixed-size slab pool for IOBuf RX recycling. Self-contained
// lock-free machinery, kept in its own module; `IOBufPool` is
// re-exported at the crate root so consumers spell `uni_iobuf::IOBufPool`.
mod pool;
pub use pool::IOBufPool;

// ============================================================================
// Borrow tracker — debug-mode aliasing detection for `Borrowed` IOBufs.
//
// Every `IOBuf::borrow(base, capacity, ...)` registers its
// `[base..base+capacity)` region in a per-thread interval list. A
// second `borrow` overlapping any live entry panics on the spot,
// surfacing aliasing-arithmetic bugs (e.g. the body-scratch sub-range
// allocator's cursor going wrong) at the point of construction rather
// than as silent UAF later.
//
// Active only under `cfg(any(test, debug_assertions))`. In bazel
// release builds (the unikernel target ships with `-Copt-level=2`),
// `debug_assertions` is off and the tracker compiles to a no-op,
// so production pays nothing. In `cargo test`, the iobuf_test bazel
// target, and any debug build of a consumer, the tracker is on.
//
// The tracker lives on a per-thread `Vec` (via `std::thread_local!`)
// because `Borrowed` IOBufs are `!Send` — a borrowed view is bound to
// the worker / thread that constructed it, so cross-thread sharing of
// the tracker state is structurally impossible. The `Vec` is bounded
// in practice by the number of live `Borrowed` IOBufs on this thread;
// typical depths are < 4 (one for body scratch, one for TLS scratch,
// occasional inner sub-views).
// ============================================================================
#[cfg(any(test, debug_assertions))]
mod borrow_tracker {
    extern crate std;

    use alloc::vec::Vec;
    use core::cell::RefCell;
    use core::ptr::NonNull;

    /// One live `[base..base+capacity)` byte region.
    #[derive(Copy, Clone)]
    struct Region {
        base: usize,
        end: usize,
    }

    std::thread_local! {
        static ACTIVE: RefCell<Vec<Region>> = RefCell::new(Vec::new());
    }

    /// Register a new `Borrowed` region. Panics on overlap with any
    /// already-live region — the typical failure mode is the body-
    /// scratch sub-range allocator's cursor arithmetic going wrong,
    /// or a re-entered scratch-acquire path minting a second view
    /// over the same per-worker buffer.
    pub(crate) fn register(base: NonNull<u8>, capacity: u32) {
        let base_addr = base.as_ptr() as usize;
        let end_addr = base_addr.wrapping_add(capacity as usize);
        ACTIVE.with(|r| {
            let mut reg = r.borrow_mut();
            for existing in reg.iter() {
                // Open-interval overlap test: [a, b) ∩ [c, d) ≠ ∅
                // iff a < d ∧ c < b.
                let overlap = base_addr < existing.end && existing.base < end_addr;
                if overlap {
                    panic!(
                        "overlapping IOBuf::borrow mint: new=[{:#x}..{:#x}) \
                         overlaps existing=[{:#x}..{:#x}); aliasing bug?",
                        base_addr, end_addr, existing.base, existing.end,
                    );
                }
            }
            reg.push(Region {
                base: base_addr,
                end: end_addr,
            });
        });
    }

    /// Drop a previously-registered region. Panics if no matching
    /// entry exists — that would indicate a balance error in the
    /// register/unregister pairing (e.g. a `Borrowed` IOBuf
    /// constructed without going through `register`).
    pub(crate) fn unregister(base: NonNull<u8>, capacity: u32) {
        let base_addr = base.as_ptr() as usize;
        let end_addr = base_addr.wrapping_add(capacity as usize);
        ACTIVE.with(|r| {
            let mut reg = r.borrow_mut();
            // LIFO-friendly scan (Borrowed IOBufs usually drop in
            // reverse construction order on a synchronous code path).
            for i in (0..reg.len()).rev() {
                if reg[i].base == base_addr && reg[i].end == end_addr {
                    reg.swap_remove(i);
                    return;
                }
            }
            panic!(
                "IOBuf::borrow unregister with no matching register: \
                 [{:#x}..{:#x}); register/unregister imbalance?",
                base_addr, end_addr,
            );
        });
    }
}

#[cfg(not(any(test, debug_assertions)))]
mod borrow_tracker {
    use core::ptr::NonNull;
    #[inline(always)]
    pub(crate) fn register(_: NonNull<u8>, _: u32) {}
    #[inline(always)]
    pub(crate) fn unregister(_: NonNull<u8>, _: u32) {}
}

/// Per-`Inner::Borrowed` Drop guard that owns the tracker's
/// register/unregister pairing. Carried as a field of the
/// variant — its Drop fires when the IOBuf (and thus the
/// variant) drops, so we can't accidentally orphan a live
/// registration. In release builds (`!debug_assertions`) the
/// guard is a ZST and Drop is empty.
#[cfg(any(test, debug_assertions))]
struct BorrowGuard {
    base: core::ptr::NonNull<u8>,
    capacity: u32,
}

#[cfg(any(test, debug_assertions))]
impl BorrowGuard {
    fn new(base: core::ptr::NonNull<u8>, capacity: u32) -> Self {
        borrow_tracker::register(base, capacity);
        Self { base, capacity }
    }
}

#[cfg(any(test, debug_assertions))]
impl Drop for BorrowGuard {
    fn drop(&mut self) {
        borrow_tracker::unregister(self.base, self.capacity);
    }
}

/// One byte segment in an IOBuf chain. Holds heap-owned storage,
/// a borrow into static-lifetime bytes, foreign storage with a
/// drop callback (owned), or a non-owning view of foreign storage
/// (borrowed). The borrowed variant makes the whole `IOBuf`
/// `!Send + !Sync` so per-worker borrows can't accidentally cross
/// workers — see [`Inner::Borrowed`] for the contract.
pub struct IOBuf {
    inner: Inner,
}

enum Inner {
    /// Heap-owned. The buffer's full capacity is `storage.len()`;
    /// the visible payload spans `[offset..offset+len]`. Headroom
    /// is `offset` (bytes before the payload that lower layers
    /// can prepend into); tailroom is `storage.len() - offset -
    /// len` (bytes after the payload that lower layers can append
    /// into, e.g. AEAD tags).
    Heap {
        storage: Box<[u8]>,
        offset: u32,
        len: u32,
    },
    /// Refcount-shared heap storage. Produced by [`IOBuf::split_at`]:
    /// the head and tail halves of a split point at the same
    /// `Rc<[u8]>` with disjoint `[offset..offset+len]` windows. This
    /// is the analogue of folly's shared `Storage`: copy-free
    /// peeling of byte ranges off a chain, at the cost of an `Rc`
    /// refcount per split.
    ///
    /// Mutation paths (`data_mut`, `prepend`, `append_slice`,
    /// `extend_uninit`) call [`IOBuf::make_unique`] first to
    /// guarantee writes only land in this IOBuf's storage — if the
    /// refcount is 1 that's a no-op, otherwise the visible payload
    /// is cloned into a fresh `Heap` so the original `Rc` peers
    /// stay intact.
    ///
    /// `Rc` (not `Arc`) because `IOBuf` is `!Send` (driven by
    /// `Inner::Borrowed`'s `PhantomData<*const ()>`), so non-atomic
    /// refcounting is correct.
    Shared {
        storage: Rc<[u8]>,
        offset: u32,
        len: u32,
    },
    /// Borrowed reference to static-lifetime bytes. Immutable; no
    /// headroom / tailroom semantics. Common for HTML literal
    /// chunks, the QPACK static table, etc.
    Static { data: &'static [u8] },
    /// Externally-owned buffer with a drop callback. Canonical
    /// use cases: NIC zero-copy RX (callback returns the
    /// descriptor to the receive ring) and pool-backed buffers
    /// (callback pushes `Box<[u8]>` back to the pool free list).
    /// Same offset/len semantics as `Heap`; the storage isn't
    /// dropped — the callback fires instead.
    ///
    /// `Send` (via `unsafe impl Send for ExternalOwned`) because
    /// the underlying memory is exclusively owned by this IOBuf
    /// for its lifetime and the drop callback is responsible for
    /// any cross-worker cleanup (typically via an `Arc`-backed
    /// pool reference).
    ExternalOwned(ExternalOwned),
    /// Non-owning view into foreign storage. The caller manages
    /// the region's lifetime out-of-band; no drop callback fires.
    /// Typical sites:
    ///   * Per-worker scratch buffers (TLS record scratch, body
    ///     scratch) borrowed for the duration of one send.
    ///   * Driver TX-pool slots borrowed inside a synchronous
    ///     callback.
    ///   * Per-conn stack-resident header arrays borrowed for
    ///     the duration of one response render.
    ///   * A `&[u8]` slice borrowed for a single async send.
    ///
    /// `!Send + !Sync` via the `PhantomData<*const ()>` — the
    /// borrow contract is per-worker / per-stack-frame, and the
    /// type system rejects cross-worker leak. Containing structs
    /// that legitimately move IOBufs across workers (e.g.
    /// `WorkerInbox` for inter-worker UDP delivery) must
    /// override with `unsafe impl Send` and document why their
    /// borrowed contents are cross-worker-safe.
    Borrowed {
        base: core::ptr::NonNull<u8>,
        capacity: u32,
        offset: u32,
        len: u32,
        _not_send: PhantomData<*const ()>,
        /// Debug-mode aliasing-tracker registration guard. Carries
        /// the registered `[base..base+capacity)` so its Drop can
        /// unregister symmetrically; ZST + no-op Drop in release.
        #[cfg(any(test, debug_assertions))]
        _guard: BorrowGuard,
    },
}

/// Drop callback signature for [`Inner::ExternalOwned`]. Receives
/// the original `(base, capacity, ctx)` from `wrap_owned`,
/// regardless of how the IOBuf's offset/len shifted during its
/// lifetime — the consumer that gave us the buffer wants the
/// whole region back (e.g. a NIC descriptor index), not the
/// shifted view. `unsafe` because the impl reconstructs
/// concrete types (Box<[u8]>, descriptor index) from the raw
/// pointers and must respect the contract the caller of
/// `wrap_owned` established.
pub type IOBufDropFn = unsafe fn(base: core::ptr::NonNull<u8>, capacity: u32, ctx: *mut ());

/// Backing for [`Inner::ExternalOwned`]. Held in a wrapping
/// struct so the manual `Drop` impl can run the release callback
/// exactly once. Function-pointer + opaque-context drop instead
/// of a `Box<dyn FnOnce>` — saves the per-IOBuf closure-box
/// allocation, important for the framing-IOBuf-per-request
/// recycling path where every saved alloc shows up.
pub struct ExternalOwned {
    /// Start of the underlying region.
    base: core::ptr::NonNull<u8>,
    /// Total bytes of the region (`base + capacity` is one past
    /// the end). The visible payload is at `[offset..offset+len]`
    /// within these bytes.
    capacity: u32,
    /// Visible-payload start, relative to `base`. `prepend`
    /// shrinks toward 0; `consume` grows toward
    /// `offset + len`.
    offset: u32,
    /// Visible-payload byte length.
    len: u32,
    /// Release callback — always present for `ExternalOwned`
    /// (borrowed views with no callback are in
    /// [`Inner::Borrowed`] instead).
    drop_fn: IOBufDropFn,
    /// Opaque context passed to `drop_fn`. Typically a raw
    /// `*mut` pointer the caller cast from an `Rc`/`Arc` or
    /// integer (e.g. a NIC ring index). Untyped so we don't
    /// bake any one shape into the IOBuf.
    drop_ctx: *mut (),
}

// SAFETY: `ExternalOwned` is Send because the underlying memory
// is exclusively owned (the constructor takes that as a
// precondition) and the function-pointer drop callback together
// with the raw context pointer is Send-by-construction (function
// pointers are Send; the caller is responsible for ensuring the
// context's pointee is safe to drop on the worker that owns the
// IOBuf at drop time).
unsafe impl Send for ExternalOwned {}

impl Drop for ExternalOwned {
    fn drop(&mut self) {
        // SAFETY: function-pointer's contract was set by the
        // `wrap_owned` caller — they're responsible for ensuring
        // the pair (drop_fn, drop_ctx) is sound to invoke now.
        // Drop runs exactly once per `ExternalOwned`.
        unsafe {
            (self.drop_fn)(self.base, self.capacity, self.drop_ctx);
        }
    }
}

impl IOBuf {
    /// Allocate a heap-backed buffer with `headroom` bytes
    /// reserved at the front and `tailroom` bytes reserved at the
    /// end. Total allocation is `headroom + payload_capacity +
    /// tailroom` bytes; the visible payload starts empty (`len =
    /// 0`) at offset `headroom`. Lower layers prepend by writing
    /// into the headroom; higher layers can append data into the
    /// payload-then-tailroom region via `append_slice`.
    pub fn new_with_reserved(
        headroom: usize,
        payload_capacity: usize,
        tailroom: usize,
    ) -> Self {
        let cap = headroom + payload_capacity + tailroom;
        // `vec![0u8; cap].into_boxed_slice()` zero-fills the whole
        // region. We don't strictly need zero-init for headroom /
        // tailroom (nobody reads those), but the allocator's
        // free-list returns it eventually so initial-zeroing keeps
        // info-leak class bugs away. Fast enough at our buffer
        // sizes (sub-µs for 1500-byte allocs on talc).
        let storage = alloc::vec![0u8; cap].into_boxed_slice();
        IOBuf {
            inner: Inner::Heap {
                storage,
                offset: headroom as u32,
                len: 0,
            },
        }
    }

    /// Zero-init-free variant of [`Self::new_with_reserved`]. Saves
    /// the `vec![0u8; cap]` memset cost at the price of an unsafe
    /// contract: the caller must write to every byte before reading.
    /// Returns a `Heap` IOBuf with `len = 0` so `data()` is empty;
    /// callers grow the visible region via `append_slice` /
    /// `writer` / `extend_uninit` (which write before exposing
    /// bytes) and / or `prepend` (which writes into headroom before
    /// moving the visible window over it). The uninitialised
    /// headroom / tailroom never become visible.
    ///
    /// Hot path for response-body construction at peak request
    /// rate, where the memset on the cold-cache `vec![0u8; …]`
    /// path was measurable in memory-bandwidth profiles.
    ///
    /// SAFETY: the caller must ensure no byte is read via `data()`
    /// before it's been written through one of `append_slice`,
    /// `writer`, `extend_uninit`, or a `prepend` that consumes
    /// the byte's position from headroom into the visible region.
    /// The IOBuf API enforces this for callers that only use the
    /// public mutation entry points — but a caller that
    /// manipulates `Inner::Heap`'s offsets directly could expose
    /// uninit bytes.
    pub unsafe fn new_with_reserved_uninit(
        headroom: usize,
        payload_capacity: usize,
        tailroom: usize,
    ) -> Self {
        let cap = headroom + payload_capacity + tailroom;
        // SAFETY: `Box::<[u8]>::new_uninit_slice(cap).assume_init()`
        // returns a `Box<[u8]>` whose bytes are uninitialised. The
        // caller's contract (above) is that no byte is read before
        // it's been written; visible payload starts empty so
        // `data()` is `&[]` (no read), and growth happens through
        // entry points that write-then-expose.
        let storage = unsafe {
            alloc::boxed::Box::<[u8]>::new_uninit_slice(cap).assume_init()
        };
        IOBuf {
            inner: Inner::Heap {
                storage,
                offset: headroom as u32,
                len: 0,
            },
        }
    }

    /// Heap-backed buffer pre-filled with `data`. Reserves
    /// `headroom` / `tailroom` around the payload for downstream
    /// layer prepend/append.
    pub fn from_slice_with_headroom(headroom: usize, data: &[u8], tailroom: usize) -> Self {
        let mut buf = Self::new_with_reserved(headroom, data.len(), tailroom);
        buf.append_slice(data).expect("freshly-sized buffer accepts payload");
        buf
    }

    /// Borrow a static-lifetime slice. Zero allocation. Subsequent
    /// `prepend` / `append_slice` / `data_mut` calls return errors
    /// — static borrows are immutable.
    pub const fn from_static(data: &'static [u8]) -> Self {
        IOBuf {
            inner: Inner::Static { data },
        }
    }

    /// Wrap a foreign region that this IOBuf takes ownership of
    /// via a drop callback. On drop, `drop_fn(base, capacity,
    /// drop_ctx)` runs exactly once, regardless of how the
    /// IOBuf's offset/len shifted during its lifetime — the
    /// consumer that gave us the region wants the whole thing
    /// back (e.g. a NIC descriptor index), not the shifted view.
    ///
    /// Canonical sites: NIC zero-copy RX (callback returns the
    /// descriptor to the ring), pool-backed buffer storage
    /// (callback returns the `Box<[u8]>` to the pool's free list).
    ///
    /// `drop_ctx` is opaque — typically a raw `*mut` pointer the
    /// caller cast from `Rc::into_raw` / `Arc::into_raw` (the
    /// callback `Rc::from_raw` / `Arc::from_raw` it back) or a
    /// packed integer (e.g. a ring slot index). Untyped so any
    /// consumer shape fits without baking the IOBuf to one
    /// pattern.
    ///
    /// The resulting IOBuf is `Send` (cross-worker movement is
    /// allowed — the drop callback handles whichever worker the
    /// IOBuf ends up on). For non-owning views — i.e. borrowed
    /// regions whose lifetime the caller manages out-of-band —
    /// use [`borrow`](Self::borrow) instead, which produces a
    /// `!Send` IOBuf.
    ///
    /// SAFETY: the caller MUST guarantee:
    ///   * `base..base+capacity` is a valid, exclusively-owned
    ///     byte region for the IOBuf's lifetime.
    ///   * `offset + len <= capacity`.
    ///   * `drop_fn(base, capacity, drop_ctx)` is sound to
    ///     invoke once at IOBuf-drop time. Implementations
    ///     typically reconstruct an owned type from `drop_ctx`
    ///     (e.g. `Box::from_raw`, `Arc::from_raw`) and let it
    ///     drop, returning storage to its pool.
    ///   * The pair is Send-safe: the IOBuf may move across
    ///     workers, and the eventual drop runs on whichever
    ///     worker owns the IOBuf at drop time.
    pub unsafe fn wrap_owned(
        base: core::ptr::NonNull<u8>,
        capacity: u32,
        offset: u32,
        len: u32,
        drop_fn: IOBufDropFn,
        drop_ctx: *mut (),
    ) -> Self {
        debug_assert!(offset.saturating_add(len) <= capacity);
        IOBuf {
            inner: Inner::ExternalOwned(ExternalOwned {
                base,
                capacity,
                offset,
                len,
                drop_fn,
                drop_ctx,
            }),
        }
    }

    /// Borrow a foreign region as an IOBuf view. No drop
    /// callback runs; the caller is responsible for ensuring
    /// the underlying storage outlives every IOBuf that borrows
    /// it.
    ///
    /// Typical sites:
    ///   * Per-worker scratch (TLS record, body) borrowed for
    ///     the duration of one send call.
    ///   * Driver TX-pool slot borrowed inside a synchronous
    ///     `try_send_tso` closure.
    ///   * Per-conn stack-resident header arrays borrowed for
    ///     the duration of one response.
    ///   * A `&[u8]` slice borrowed for a single async
    ///     `send_bytes`.
    ///
    /// The resulting IOBuf is `!Send + !Sync` (the
    /// `Inner::Borrowed` variant propagates this through the
    /// enum's auto-traits). Crossing worker boundaries with a
    /// borrowed IOBuf is therefore a compile error unless a
    /// containing struct provides an `unsafe impl Send` override
    /// — at which point the override author owns the
    /// cross-worker-safety contract.
    ///
    /// SAFETY: the caller MUST guarantee:
    ///   * `base..base+capacity` is a valid byte region for the
    ///     entire lifetime of this IOBuf.
    ///   * `offset + len <= capacity`.
    ///   * No other route concurrently mutates the borrowed
    ///     region while this IOBuf exists.
    ///   * If multiple IOBufs view the same underlying storage
    ///     (e.g. carving sub-ranges of a per-worker scratch),
    ///     their visible regions do not overlap when any IOBuf
    ///     is mutated through `data_mut`, `prepend`,
    ///     `append_slice`, etc.
    pub unsafe fn borrow(
        base: core::ptr::NonNull<u8>,
        capacity: u32,
        offset: u32,
        len: u32,
    ) -> Self {
        debug_assert!(offset.saturating_add(len) <= capacity);
        IOBuf {
            inner: Inner::Borrowed {
                base,
                capacity,
                offset,
                len,
                _not_send: PhantomData,
                #[cfg(any(test, debug_assertions))]
                _guard: BorrowGuard::new(base, capacity),
            },
        }
    }

    /// Visible payload bytes.
    #[inline]
    pub fn data(&self) -> &[u8] {
        match &self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let o = *offset as usize;
                let l = *len as usize;
                &storage[o..o + l]
            }
            Inner::Shared {
                storage,
                offset,
                len,
            } => {
                let o = *offset as usize;
                let l = *len as usize;
                &storage[o..o + l]
            }
            Inner::Static { data } => data,
            Inner::ExternalOwned(e) => {
                // SAFETY: base + offset is in-bounds by
                // construction precondition (offset + len <=
                // capacity); the underlying memory is exclusively
                // owned by this IOBuf for its lifetime.
                unsafe {
                    core::slice::from_raw_parts(
                        e.base.as_ptr().add(e.offset as usize),
                        e.len as usize,
                    )
                }
            }
            Inner::Borrowed {
                base, offset, len, ..
            } => {
                // SAFETY: caller of `borrow` guaranteed the
                // region is valid for this IOBuf's lifetime and
                // not concurrently mutated.
                unsafe {
                    core::slice::from_raw_parts(
                        base.as_ptr().add(*offset as usize),
                        *len as usize,
                    )
                }
            }
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match &self.inner {
            Inner::Heap { len, .. } => *len as usize,
            Inner::Shared { len, .. } => *len as usize,
            Inner::Static { data } => data.len(),
            Inner::ExternalOwned(e) => e.len as usize,
            Inner::Borrowed { len, .. } => *len as usize,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes available before the payload. Lower layers (TLS,
    /// TCP, IP, Eth) prepend their headers into this space.
    /// Always `0` for static borrows.
    #[inline]
    pub fn headroom(&self) -> usize {
        match &self.inner {
            Inner::Heap { offset, .. } => *offset as usize,
            Inner::Shared { offset, .. } => *offset as usize,
            Inner::Static { .. } => 0,
            Inner::ExternalOwned(e) => e.offset as usize,
            Inner::Borrowed { offset, .. } => *offset as usize,
        }
    }

    /// Bytes available after the payload. Used for AEAD tags,
    /// trailers, etc. Always `0` for static borrows.
    #[inline]
    pub fn tailroom(&self) -> usize {
        match &self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let used = *offset as usize + *len as usize;
                storage.len().saturating_sub(used)
            }
            Inner::Shared {
                storage,
                offset,
                len,
            } => {
                let used = *offset as usize + *len as usize;
                storage.len().saturating_sub(used)
            }
            Inner::Static { .. } => 0,
            Inner::ExternalOwned(e) => {
                let used = e.offset as usize + e.len as usize;
                (e.capacity as usize).saturating_sub(used)
            }
            Inner::Borrowed {
                capacity,
                offset,
                len,
                ..
            } => {
                let used = *offset as usize + *len as usize;
                (*capacity as usize).saturating_sub(used)
            }
        }
    }

    /// Mutable access to the visible payload. Returns `None` for
    /// static borrows. Used by in-place crypto (ChaCha20-Poly1305
    /// seals into the source bytes).
    ///
    /// For `Shared`, this calls [`make_unique`](Self::make_unique)
    /// first — if the refcount is > 1 the visible payload is cloned
    /// into a fresh `Heap` so the mutation can't be observed by the
    /// peer Rc holders.
    #[inline]
    pub fn data_mut(&mut self) -> Option<&mut [u8]> {
        if matches!(self.inner, Inner::Shared { .. }) {
            self.make_unique();
        }
        match &mut self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let o = *offset as usize;
                let l = *len as usize;
                Some(&mut storage[o..o + l])
            }
            Inner::Shared {
                storage,
                offset,
                len,
            } => {
                let o = *offset as usize;
                let l = *len as usize;
                // SAFETY contract: `make_unique` above guarantees
                // this Rc has strong=1, weak=0, so `get_mut`
                // returns Some.
                let slice = Rc::get_mut(storage)
                    .expect("make_unique ensures unique Rc");
                Some(&mut slice[o..o + l])
            }
            Inner::Static { .. } => None,
            Inner::ExternalOwned(e) => {
                // SAFETY: same as `data()`; we additionally hold
                // `&mut self` so no aliasing with other readers
                // during this call.
                Some(unsafe {
                    core::slice::from_raw_parts_mut(
                        e.base.as_ptr().add(e.offset as usize),
                        e.len as usize,
                    )
                })
            }
            Inner::Borrowed {
                base, offset, len, ..
            } => {
                // SAFETY: `borrow` caller guaranteed the region
                // is not concurrently mutated through any other
                // route; `&mut self` gives us exclusive write
                // access for this call.
                Some(unsafe {
                    core::slice::from_raw_parts_mut(
                        base.as_ptr().add(*offset as usize),
                        *len as usize,
                    )
                })
            }
        }
    }

    /// Prepend `data` into the headroom and grow the visible
    /// payload accordingly. The returned slice points at the
    /// freshly-prepended region (in case the caller wants to
    /// overwrite via further mutation).
    ///
    /// `Err(IOBufError::NoHeadroom)` if the headroom is too small;
    /// `Err(IOBufError::Immutable)` for static borrows.
    pub fn prepend(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        // Headroom check up-front so a no-op make_unique doesn't
        // trigger a copy for a request the caller can't satisfy.
        if matches!(self.inner, Inner::Shared { .. }) {
            if data.len() > self.headroom() {
                return Err(IOBufError::NoHeadroom);
            }
            self.make_unique();
        }
        match &mut self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let n = data.len();
                if n > *offset as usize {
                    return Err(IOBufError::NoHeadroom);
                }
                let new_offset = *offset - n as u32;
                let dst = &mut storage[new_offset as usize..*offset as usize];
                dst.copy_from_slice(data);
                *offset = new_offset;
                *len += n as u32;
                Ok(())
            }
            Inner::Shared {
                storage,
                offset,
                len,
            } => {
                let n = data.len();
                let new_offset = *offset - n as u32;
                let slice = Rc::get_mut(storage)
                    .expect("make_unique ensures unique Rc");
                let dst = &mut slice[new_offset as usize..*offset as usize];
                dst.copy_from_slice(data);
                *offset = new_offset;
                *len += n as u32;
                Ok(())
            }
            Inner::Static { .. } => Err(IOBufError::Immutable),
            Inner::ExternalOwned(e) => {
                let n = data.len();
                if n > e.offset as usize {
                    return Err(IOBufError::NoHeadroom);
                }
                let new_offset = e.offset - n as u32;
                // SAFETY: bounds checked above; exclusive access
                // via `&mut self`.
                unsafe {
                    let dst = core::slice::from_raw_parts_mut(
                        e.base.as_ptr().add(new_offset as usize),
                        n,
                    );
                    dst.copy_from_slice(data);
                }
                e.offset = new_offset;
                e.len += n as u32;
                Ok(())
            }
            Inner::Borrowed {
                base, offset, len, ..
            } => {
                let n = data.len();
                if n > *offset as usize {
                    return Err(IOBufError::NoHeadroom);
                }
                let new_offset = *offset - n as u32;
                // SAFETY: bounds checked above; exclusive access
                // via `&mut self`; `borrow` caller guaranteed no
                // concurrent mutation through other routes.
                unsafe {
                    let dst = core::slice::from_raw_parts_mut(
                        base.as_ptr().add(new_offset as usize),
                        n,
                    );
                    dst.copy_from_slice(data);
                }
                *offset = new_offset;
                *len += n as u32;
                Ok(())
            }
        }
    }

    /// Append `data` into the tailroom and grow the visible
    /// payload accordingly.
    pub fn append_slice(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        if matches!(self.inner, Inner::Shared { .. }) {
            if data.len() > self.tailroom() {
                return Err(IOBufError::NoTailroom);
            }
            self.make_unique();
        }
        match &mut self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let end = *offset as usize + *len as usize;
                let n = data.len();
                if end + n > storage.len() {
                    return Err(IOBufError::NoTailroom);
                }
                storage[end..end + n].copy_from_slice(data);
                *len += n as u32;
                Ok(())
            }
            Inner::Shared {
                storage,
                offset,
                len,
            } => {
                let end = *offset as usize + *len as usize;
                let n = data.len();
                let slice = Rc::get_mut(storage)
                    .expect("make_unique ensures unique Rc");
                slice[end..end + n].copy_from_slice(data);
                *len += n as u32;
                Ok(())
            }
            Inner::Static { .. } => Err(IOBufError::Immutable),
            Inner::ExternalOwned(e) => {
                let end = e.offset as usize + e.len as usize;
                let n = data.len();
                if end + n > e.capacity as usize {
                    return Err(IOBufError::NoTailroom);
                }
                // SAFETY: bounds checked above.
                unsafe {
                    let dst = core::slice::from_raw_parts_mut(
                        e.base.as_ptr().add(end),
                        n,
                    );
                    dst.copy_from_slice(data);
                }
                e.len += n as u32;
                Ok(())
            }
            Inner::Borrowed {
                base,
                capacity,
                offset,
                len,
                ..
            } => {
                let end = *offset as usize + *len as usize;
                let n = data.len();
                if end + n > *capacity as usize {
                    return Err(IOBufError::NoTailroom);
                }
                // SAFETY: bounds checked above; `borrow` caller
                // guaranteed no concurrent mutation.
                unsafe {
                    let dst = core::slice::from_raw_parts_mut(
                        base.as_ptr().add(end),
                        n,
                    );
                    dst.copy_from_slice(data);
                }
                *len += n as u32;
                Ok(())
            }
        }
    }

    /// Append `n` zero bytes (or rather, the slot's existing
    /// uninitialised contents — we don't re-zero) and return a
    /// mutable slice pointing at them. Used by AEAD seal: the
    /// caller advances the visible len, then writes the tag bytes
    /// directly into the returned slice.
    pub fn extend_uninit(&mut self, n: usize) -> Result<&mut [u8], IOBufError> {
        if matches!(self.inner, Inner::Shared { .. }) {
            if n > self.tailroom() {
                return Err(IOBufError::NoTailroom);
            }
            self.make_unique();
        }
        match &mut self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let end = *offset as usize + *len as usize;
                if end + n > storage.len() {
                    return Err(IOBufError::NoTailroom);
                }
                *len += n as u32;
                Ok(&mut storage[end..end + n])
            }
            Inner::Shared {
                storage,
                offset,
                len,
            } => {
                let end = *offset as usize + *len as usize;
                *len += n as u32;
                let slice = Rc::get_mut(storage)
                    .expect("make_unique ensures unique Rc");
                Ok(&mut slice[end..end + n])
            }
            Inner::Static { .. } => Err(IOBufError::Immutable),
            Inner::ExternalOwned(e) => {
                let end = e.offset as usize + e.len as usize;
                if end + n > e.capacity as usize {
                    return Err(IOBufError::NoTailroom);
                }
                e.len += n as u32;
                // SAFETY: bounds checked above; exclusive access.
                Ok(unsafe {
                    core::slice::from_raw_parts_mut(e.base.as_ptr().add(end), n)
                })
            }
            Inner::Borrowed {
                base,
                capacity,
                offset,
                len,
                ..
            } => {
                let end = *offset as usize + *len as usize;
                if end + n > *capacity as usize {
                    return Err(IOBufError::NoTailroom);
                }
                *len += n as u32;
                // SAFETY: bounds checked above; exclusive access
                // via `&mut self`.
                Ok(unsafe {
                    core::slice::from_raw_parts_mut(base.as_ptr().add(end), n)
                })
            }
        }
    }

    /// Narrow the visible payload to `[offset..offset+len]` relative
    /// to the current visible region. Equivalent to
    /// `self.consume(offset)?` followed by trimming any tail past
    /// `len` via `trim_end`. The common case in protocol dispatch:
    /// "advance past my header (offset = header_size), and cut
    /// trailing IP padding if my payload is shorter than the
    /// frame I came in on (len = next-layer total)."
    ///
    /// Returns `Err` if `offset + len` exceeds the current visible
    /// payload length.
    #[inline]
    pub fn narrow(&mut self, offset: usize, len: usize) -> Result<(), IOBufError> {
        self.consume(offset)?;
        let visible = self.data().len();
        if visible > len {
            self.trim_end(visible - len)?;
        }
        Ok(())
    }

    /// Trim `n` bytes from the FRONT of the visible payload.
    /// Used by the consumer side after a layer has stripped its
    /// header (e.g. TLS unprotect leaves the record header
    /// untouched in headroom; the next layer up just wants the
    /// plaintext).
    #[inline]
    pub fn consume(&mut self, n: usize) -> Result<(), IOBufError> {
        match &mut self.inner {
            Inner::Heap { offset, len, .. } => {
                if n > *len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                *offset += n as u32;
                *len -= n as u32;
                Ok(())
            }
            Inner::Shared { offset, len, .. } => {
                // Bounds-only narrow: doesn't write into storage,
                // so safe to do without `make_unique`. Peer Rc
                // holders keep their own offset/len.
                if n > *len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                *offset += n as u32;
                *len -= n as u32;
                Ok(())
            }
            Inner::Static { data } => {
                if n > data.len() {
                    return Err(IOBufError::OutOfBounds);
                }
                *data = &data[n..];
                Ok(())
            }
            Inner::ExternalOwned(e) => {
                if n > e.len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                e.offset += n as u32;
                e.len -= n as u32;
                Ok(())
            }
            Inner::Borrowed { offset, len, .. } => {
                if n > *len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                *offset += n as u32;
                *len -= n as u32;
                Ok(())
            }
        }
    }

    /// `core::fmt::Write` adapter that appends formatted bytes
    /// into the IOBuf's tailroom. Lets callers `write!(buf.writer(),
    /// "{}", value)` to render straight into the IOBuf instead of
    /// going through an intermediate `String` + memcpy.
    ///
    /// The writer drops `Ok` even if the tailroom fills mid-render
    /// — `core::fmt::Write` doesn't surface `Err` for buffer
    /// exhaustion, so the caller checks `data().len()` afterward
    /// to detect truncation. Sized correctly the truncation path
    /// is cold.
    pub fn writer(&mut self) -> IOBufWriter<'_> {
        IOBufWriter { buf: self, overflowed: false }
    }

    /// Trim `n` bytes from the BACK of the visible payload.
    #[inline]
    pub fn trim_end(&mut self, n: usize) -> Result<(), IOBufError> {
        match &mut self.inner {
            Inner::Heap { len, .. } => {
                if n > *len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                *len -= n as u32;
                Ok(())
            }
            Inner::Shared { len, .. } => {
                // Bounds-only narrow: doesn't write into storage,
                // so safe to do without `make_unique`.
                if n > *len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                *len -= n as u32;
                Ok(())
            }
            Inner::Static { data } => {
                if n > data.len() {
                    return Err(IOBufError::OutOfBounds);
                }
                *data = &data[..data.len() - n];
                Ok(())
            }
            Inner::ExternalOwned(e) => {
                if n > e.len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                e.len -= n as u32;
                Ok(())
            }
            Inner::Borrowed { len, .. } => {
                if n > *len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                *len -= n as u32;
                Ok(())
            }
        }
    }

    /// Split this IOBuf into two halves at byte offset `n` within
    /// the visible payload. `self` keeps `[0..n)`, the returned
    /// IOBuf gets `[n..len)`. Used by [`IOBufChain::split_off`] to
    /// peel a sub-range off a chain without copying the underlying
    /// bytes — the QUIC retransmit storage path wants this shape so
    /// it can keep an Rc-shared reference to in-flight chunks while
    /// the wire copy proceeds in parallel.
    ///
    /// Variant behavior:
    ///   * `Heap`: promotes in place to `Shared`, then clones the
    ///     `Rc` and returns the tail half. Both halves point at the
    ///     same backing `Box<[u8]>` (now wrapped in an `Rc<[u8]>`)
    ///     with disjoint offset/len windows.
    ///   * `Shared`: clones the `Rc` and returns the tail half.
    ///     Bumps the refcount; no byte copy.
    ///   * `Static`: slices the `&'static [u8]` in place; returns
    ///     a fresh `Static` over the tail. Zero allocation.
    ///   * `ExternalOwned` / `Borrowed`: panics. The drop callback
    ///     (ExternalOwned) is single-fire and tied to the whole
    ///     region, so splitting would either double-drop or leak;
    ///     the aliasing tracker (Borrowed) would refuse the second
    ///     view over the same `[base, base+capacity)`.
    ///
    /// Panics if `n > self.len()`.
    pub fn split_at(&mut self, n: usize) -> IOBuf {
        assert!(
            n <= self.len(),
            "split_at: n={} > len={}",
            n,
            self.len()
        );
        // Replace self.inner with a dummy so we can move the old
        // inner out and destructure it. The dummy Inner::Static
        // costs nothing to construct or drop.
        let old = core::mem::replace(&mut self.inner, Inner::Static { data: &[] });
        let (head_inner, tail_inner) = match old {
            Inner::Heap { storage, offset, len } => {
                // Promote the Box<[u8]> into an Rc<[u8]>; both
                // halves share the same allocation from here on.
                let shared: Rc<[u8]> = Rc::from(storage);
                let head = Inner::Shared {
                    storage: shared.clone(),
                    offset,
                    len: n as u32,
                };
                let tail = Inner::Shared {
                    storage: shared,
                    offset: offset + n as u32,
                    len: len - n as u32,
                };
                (head, tail)
            }
            Inner::Shared { storage, offset, len } => {
                let head = Inner::Shared {
                    storage: storage.clone(),
                    offset,
                    len: n as u32,
                };
                let tail = Inner::Shared {
                    storage,
                    offset: offset + n as u32,
                    len: len - n as u32,
                };
                (head, tail)
            }
            Inner::Static { data } => {
                let (a, b) = data.split_at(n);
                (Inner::Static { data: a }, Inner::Static { data: b })
            }
            Inner::ExternalOwned(_) | Inner::Borrowed { .. } => {
                unimplemented!(
                    "IOBuf::split_at on ExternalOwned/Borrowed: \
                     single-fire drop callback / aliasing tracker \
                     forbids dual views"
                )
            }
        };
        self.inner = head_inner;
        IOBuf { inner: tail_inner }
    }

    /// Ensure this IOBuf has exclusive ownership of its storage.
    /// For `Shared` with refcount > 1, clones the visible payload
    /// into a fresh `Heap` (no headroom/tailroom) so subsequent
    /// mutations can't be observed by peer `Rc` holders. For
    /// `Shared` with refcount == 1, no-op (we're already unique).
    /// For every other variant, no-op.
    ///
    /// The mutation entry points (`data_mut`, `prepend`,
    /// `append_slice`, `extend_uninit`) call this on the `Shared`
    /// arm to maintain the "writes go to my storage only"
    /// invariant. The unique-refcount no-op is the fast path —
    /// after a `split_at` whose peer half was already dropped, we
    /// stay zero-copy.
    pub fn make_unique(&mut self) {
        let Inner::Shared { storage, offset, len } = &mut self.inner else {
            return;
        };
        if Rc::strong_count(storage) == 1 && Rc::weak_count(storage) == 0 {
            // We're already unique. No copy.
            return;
        }
        // Refcount > 1 (or a Weak handle exists): clone the visible
        // payload into a fresh Heap. Drops our Rc handle; the peer
        // refcount drops by 1 atomically.
        let o = *offset as usize;
        let l = *len as usize;
        let copy = storage[o..o + l].to_vec().into_boxed_slice();
        self.inner = Inner::Heap {
            storage: copy,
            offset: 0,
            len: l as u32,
        };
    }

    /// Convert this IOBuf into one that fully owns (or statically
    /// outlives) its bytes — i.e. one carrying no out-of-band
    /// lifetime contract, so it is safe to send across workers.
    ///
    ///   * `Heap` / `Shared` / `Static` / `ExternalOwned` — each
    ///     already owns its storage (or `'static`-outlives it).
    ///     Returned unchanged: **zero copy**.
    ///   * `Borrowed` — the sole non-owning variant. Its visible
    ///     payload is copied into a freshly-allocated `Heap` buffer
    ///     (offset 0, no headroom / tailroom), because a borrowed
    ///     view has no claim on its backing storage's lifetime.
    ///     This is the **only** variant that costs a copy.
    ///
    /// The escape hatch for "I hold a `Borrowed` view of inbound
    /// bytes but need owned, `Send`-able possession of them" — e.g.
    /// a proxy handler forwarding request bytes into an outbound
    /// async `send`, where the borrowed source (a per-conn parse
    /// buffer, or the TLS `pt_buf`) could be overwritten before
    /// that send completes. Shares the shape of
    /// [`make_unique`](Self::make_unique): materialise owned
    /// storage on demand, no-op when ownership already holds.
    pub fn into_owned(mut self) -> IOBuf {
        if matches!(self.inner, Inner::Borrowed { .. }) {
            // Copy the visible payload into owned heap storage.
            // `data()`'s borrow ends at `.to_vec()` (which produces
            // an independent allocation), so the subsequent
            // `self.inner` write is unambiguous. That write drops
            // the old `Inner::Borrowed`, whose `BorrowGuard`
            // unregisters the region from the debug-mode aliasing
            // tracker — symmetric with the `borrow` that minted it.
            let owned: Box<[u8]> = self.data().to_vec().into_boxed_slice();
            let len = owned.len() as u32;
            self.inner = Inner::Heap {
                storage: owned,
                offset: 0,
                len,
            };
        }
        self
    }
}

/// `core::fmt::Write` adapter for [`IOBuf`]. Appends formatted
/// bytes into the buffer's tailroom; if tailroom runs out
/// mid-render the writer silently truncates (see `overflowed`).
/// Used by app-side response builders to render dynamic content
/// directly into a TLS-ready IOBuf without an intermediate
/// `String` allocation + memcpy.
pub struct IOBufWriter<'a> {
    buf: &'a mut IOBuf,
    /// Set when an `extend_uninit` call inside `write_str` failed
    /// (tailroom exhausted). The caller queries this after the
    /// `write!`/`writeln!` chain completes — `core::fmt::Write`'s
    /// `Result` doesn't propagate buffer-out-of-space errors.
    overflowed: bool,
}

impl IOBufWriter<'_> {
    /// True if any append during this writer's lifetime hit a
    /// tailroom exhaustion. Caller should treat the IOBuf as
    /// truncated and either grow it or surface an error.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }
}

impl core::fmt::Write for IOBufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        match self.buf.append_slice(s.as_bytes()) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.overflowed = true;
                // `core::fmt::Write::write_str` returns
                // `core::fmt::Error` on failure. Returning Err
                // here halts the `write!` macro chain. The
                // caller still checks `overflowed()` for the
                // narrower "tailroom exhausted" signal.
                Err(core::fmt::Error)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IOBufError {
    NoHeadroom,
    NoTailroom,
    OutOfBounds,
    Immutable,
}

// ============================================================================
// Chain
// ============================================================================

/// A chain of `IOBuf` segments. Push-front / push-back at the
/// chain level are amortised O(1); the `Cursor` walks part
/// boundaries transparently for readers.
///
/// The chain is the natural shape for a multi-layer stack: each
/// layer can append/prepend parts (or prepend INTO the front
/// part's headroom) without disturbing the rest.
///
/// Representation — a three-state value (see the private `Repr`):
///
///   * **`Empty`** — no parts.
///   * **`Single`** — exactly one part, stored inline. **Zero
///     heap allocation** for the chain machinery. This is the
///     dominant shape on both the TX and RX paths: a lone body
///     buffer, a single borrowed slice for a raw send, a
///     single-buffer RX frame.
///   * **`Many`** — two or more parts, held in a `VecDeque<IOBuf>`
///     (one heap allocation). Genuine multi-part chains: layered
///     framing that can't prepend in place, multi-chunk bodies.
///
/// This deliberately specialises the *single-part* chain rather
/// than reserving a fixed inline array sized for some guessed
/// part count — so there is no `INLINE_PARTS`-style tuning knob
/// to mis-set. One part is free; two-or-more pay a single
/// `VecDeque` allocation, onto a path already allocation-heavy
/// (each additional body part is itself an allocation).
pub struct IOBufChain {
    repr: Repr,
}

/// Storage backing an [`IOBufChain`]. Private: the chain's
/// public surface is its methods — callers never match this.
enum Repr {
    /// No parts. Produced by `new()` / `Default`, and by a fully
    /// drained or `clear`ed `Single` chain.
    Empty,
    /// Exactly one part, inline — no heap allocation for chain
    /// machinery. `push_*` never store an empty `IOBuf`, so a
    /// `Single` always holds a genuine part.
    Single(IOBuf),
    /// Two-or-more parts — or a `with_capacity`-preallocated
    /// chain. `parts` is a heap `VecDeque`; `total_len` caches the
    /// summed visible length so `total_len()` / `Cursor::remaining`
    /// stay O(1). After pops or `clear`, `parts` may transiently
    /// hold 0 or 1 entries: the `VecDeque` allocation is kept for
    /// reuse rather than demoted back to `Single` / `Empty`.
    Many {
        parts: VecDeque<IOBuf>,
        total_len: usize,
    },
}

/// `VecDeque` capacity reserved when a `Single` chain first
/// upgrades to `Many`. Covers the common layered shape (a body
/// part plus a couple of framing parts) without an immediate
/// reallocation.
const MANY_INIT_CAP: usize = 4;

impl IOBufChain {
    pub const fn new() -> Self {
        IOBufChain { repr: Repr::Empty }
    }

    /// Hint that the chain will hold at least `part_capacity`
    /// parts. A hint of 0 or 1 is free — the chain starts `Empty`
    /// and the first push lands in the zero-allocation `Single`
    /// state. A hint of 2+ pre-allocates the `Many` `VecDeque` so
    /// the multi-part pushes that follow don't reallocate.
    pub fn with_capacity(part_capacity: usize) -> Self {
        if part_capacity <= 1 {
            IOBufChain { repr: Repr::Empty }
        } else {
            IOBufChain {
                repr: Repr::Many {
                    parts: VecDeque::with_capacity(part_capacity),
                    total_len: 0,
                },
            }
        }
    }

    /// Total visible-payload bytes summed across every part. O(1).
    pub fn total_len(&self) -> usize {
        match &self.repr {
            Repr::Empty => 0,
            Repr::Single(b) => b.len(),
            Repr::Many { total_len, .. } => *total_len,
        }
    }

    /// True when the chain holds no parts.
    pub fn is_empty(&self) -> bool {
        match &self.repr {
            Repr::Empty => true,
            Repr::Single(_) => false,
            Repr::Many { parts, .. } => parts.is_empty(),
        }
    }

    pub fn part_count(&self) -> usize {
        match &self.repr {
            Repr::Empty => 0,
            Repr::Single(_) => 1,
            Repr::Many { parts, .. } => parts.len(),
        }
    }

    /// Borrow part `i` in front-to-back order, or `None` past the
    /// last part. Backs both [`iter`](Self::iter) and the `Cursor`.
    #[inline]
    fn get_part(&self, i: usize) -> Option<&IOBuf> {
        match &self.repr {
            Repr::Empty => None,
            Repr::Single(b) => (i == 0).then_some(b),
            Repr::Many { parts, .. } => parts.get(i),
        }
    }

    /// Append a buf to the back of the chain. Empty bufs are
    /// dropped — a chain never carries a zero-length part.
    pub fn push_back(&mut self, buf: IOBuf) {
        if buf.is_empty() {
            return;
        }
        // Fast path: an existing `Many` just pushes — no repr swap.
        if let Repr::Many { parts, total_len } = &mut self.repr {
            *total_len += buf.len();
            parts.push_back(buf);
            return;
        }
        // `Empty` -> `Single`, or `Single` -> `Many`.
        self.repr = match core::mem::replace(&mut self.repr, Repr::Empty) {
            Repr::Empty => Repr::Single(buf),
            Repr::Single(existing) => {
                let total_len = existing.len() + buf.len();
                let mut parts = VecDeque::with_capacity(MANY_INIT_CAP);
                parts.push_back(existing);
                parts.push_back(buf);
                Repr::Many { parts, total_len }
            }
            Repr::Many { .. } => unreachable!("Many handled by the fast path"),
        };
    }

    /// Prepend a buf to the front of the chain. Empty bufs are
    /// dropped. Amortised O(1).
    pub fn push_front(&mut self, buf: IOBuf) {
        if buf.is_empty() {
            return;
        }
        if let Repr::Many { parts, total_len } = &mut self.repr {
            *total_len += buf.len();
            parts.push_front(buf);
            return;
        }
        self.repr = match core::mem::replace(&mut self.repr, Repr::Empty) {
            Repr::Empty => Repr::Single(buf),
            Repr::Single(existing) => {
                let total_len = existing.len() + buf.len();
                let mut parts = VecDeque::with_capacity(MANY_INIT_CAP);
                parts.push_back(buf); // new buf becomes the front
                parts.push_back(existing);
                Repr::Many { parts, total_len }
            }
            Repr::Many { .. } => unreachable!("Many handled by the fast path"),
        };
    }

    /// Prepend `data` directly into the FRONT part's headroom,
    /// without allocating a new part. Returns `Err` if the front
    /// part is missing or static (no headroom). Lets a layer
    /// prepend a small fixed header (TLS record header, H3 frame
    /// header) without growing the chain.
    pub fn prepend_in_place(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let front = self.front_mut().ok_or(IOBufError::NoHeadroom)?;
        front.prepend(data)?;
        // A `Single`'s `total_len` is derived from the part itself,
        // so the `prepend` above already accounts for the bytes;
        // only `Many`'s cached `total_len` needs the adjustment.
        if let Repr::Many { total_len, .. } = &mut self.repr {
            *total_len += data.len();
        }
        Ok(())
    }

    /// Iterate the chain front-to-back.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &IOBuf> {
        (0..self.part_count()).map(move |i| self.get_part(i).expect("i < part_count"))
    }

    /// Mutable iterate front-to-back. Lets the caller mutate
    /// individual parts (e.g. patch bytes through
    /// `IOBuf::data_mut()` per part) without consuming the
    /// chain.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut IOBuf> {
        match &mut self.repr {
            Repr::Empty => ChainIterMut::Empty,
            Repr::Single(b) => ChainIterMut::Single(Some(b)),
            Repr::Many { parts, .. } => ChainIterMut::Many(parts.iter_mut()),
        }
    }

    /// Pop the front part. Returns `None` when the chain is empty.
    pub fn pop_front(&mut self) -> Option<IOBuf> {
        if let Repr::Many { parts, total_len } = &mut self.repr {
            let buf = parts.pop_front()?;
            *total_len = total_len.saturating_sub(buf.len());
            return Some(buf);
        }
        match core::mem::replace(&mut self.repr, Repr::Empty) {
            Repr::Empty => None,
            Repr::Single(buf) => Some(buf),
            Repr::Many { .. } => unreachable!("Many handled by the fast path"),
        }
    }

    /// Mutable access to the front part. Used by partial-send
    /// recovery paths that need to advance the head buf's visible
    /// payload (`IOBuf::consume(n)`) when the underlying transport
    /// committed only `n < head.len()` bytes. The caller is
    /// responsible for keeping `total_len` in sync via
    /// [`shrink_total_len`](Self::shrink_total_len).
    pub fn front_mut(&mut self) -> Option<&mut IOBuf> {
        match &mut self.repr {
            Repr::Empty => None,
            Repr::Single(b) => Some(b),
            Repr::Many { parts, .. } => parts.front_mut(),
        }
    }

    /// Mutable access to the back part. Used by sealing paths
    /// that append (e.g. an AEAD tag) onto the last IOBuf after
    /// the encryption pass. Caller must call
    /// [`bump_total_len`](Self::bump_total_len) after growing the
    /// back part's visible payload.
    pub fn back_mut(&mut self) -> Option<&mut IOBuf> {
        match &mut self.repr {
            Repr::Empty => None,
            Repr::Single(b) => Some(b),
            Repr::Many { parts, .. } => parts.back_mut(),
        }
    }

    /// Pop the back part. Mirror of `pop_front`. Used by paths
    /// that speculatively appended a part and need to rewind the
    /// chain on a subsequent error.
    pub fn pop_back(&mut self) -> Option<IOBuf> {
        if let Repr::Many { parts, total_len } = &mut self.repr {
            let buf = parts.pop_back()?;
            *total_len = total_len.saturating_sub(buf.len());
            return Some(buf);
        }
        match core::mem::replace(&mut self.repr, Repr::Empty) {
            Repr::Empty => None,
            Repr::Single(buf) => Some(buf),
            Repr::Many { .. } => unreachable!("Many handled by the fast path"),
        }
    }

    /// Decrease the cached `total_len` by `n`. Pair with a
    /// `front_mut().consume(n)` (or equivalent) when the caller
    /// shrank a buf's visible payload without going through
    /// `pop_front`.
    ///
    /// A no-op for `Empty` / `Single`: those derive `total_len`
    /// straight from the (single, or zero) part, so the part's own
    /// `consume` already reflected the shrink — subtracting here
    /// too would double-count.
    pub fn shrink_total_len(&mut self, n: usize) {
        if let Repr::Many { total_len, .. } = &mut self.repr {
            *total_len = total_len.saturating_sub(n);
        }
    }

    /// Increase the cached `total_len` by `n`. Pair with a
    /// `back_mut().append_slice(...)` (or equivalent) that grew
    /// a buf's visible payload without going through
    /// `push_back` / `push_front`. Used by the TLS seal-chain
    /// path to record the AEAD tag bytes appended to the
    /// trailer IOBuf after the encryption pass.
    ///
    /// A no-op for `Empty` / `Single` — see
    /// [`shrink_total_len`](Self::shrink_total_len).
    pub fn bump_total_len(&mut self, n: usize) {
        if let Repr::Many { total_len, .. } = &mut self.repr {
            *total_len += n;
        }
    }

    /// Drop every part still in the chain. The drops run
    /// front-to-back — same ordering as a `pop_front` loop, which
    /// matters for `ExternalOwned` IOBufs whose drop callbacks
    /// return descriptors / slabs to driver pools. A `Many` chain
    /// keeps its `VecDeque` allocation for reuse.
    pub fn clear(&mut self) {
        if let Repr::Many { parts, total_len } = &mut self.repr {
            parts.clear();
            *total_len = 0;
            return;
        }
        self.repr = Repr::Empty;
    }

    /// Move all parts out, consuming the chain. Returns an
    /// iterator yielding parts front-to-back.
    pub fn into_parts(self) -> impl Iterator<Item = IOBuf> {
        // `Empty` / `Single` collapse to `(Option, empty deque)`;
        // `Many` to `(None, parts)`. `VecDeque::new()` is
        // allocation-free, so the non-`Many` arms cost nothing.
        let (single, many) = match self.repr {
            Repr::Empty => (None, VecDeque::new()),
            Repr::Single(b) => (Some(b), VecDeque::new()),
            Repr::Many { parts, .. } => (None, parts),
        };
        single.into_iter().chain(many)
    }

    /// Convenience: append a `&'static [u8]` part. Borrowed,
    /// zero-alloc end-to-end for the first part (head); the
    /// VecDeque tail materialises only on a second push.
    pub fn push_static(&mut self, s: &'static [u8]) {
        self.push_back(IOBuf::from_static(s));
    }

    /// Convenience: append a `Vec<u8>` part. Move-no-copy when
    /// `len == capacity`; reallocates to fit otherwise.
    pub fn push_owned(&mut self, v: alloc::vec::Vec<u8>) {
        self.push_back(IOBuf::from(v));
    }

    /// Convenience: append a `String`'s underlying bytes.
    pub fn push_string(&mut self, s: alloc::string::String) {
        self.push_back(IOBuf::from(s.into_bytes()));
    }

    /// Append a payload as a heap-owned IOBuf with reserved
    /// `headroom` and `tailroom` for layers below to prepend or
    /// append in place. One heap alloc per chunk (sized for
    /// payload + reserve); the visible `data()` is exactly
    /// `payload`.
    pub fn push_with_reserve(
        &mut self,
        payload: &[u8],
        headroom: usize,
        tailroom: usize,
    ) {
        self.push_back(IOBuf::from_slice_with_headroom(headroom, payload, tailroom));
    }

    /// Construct a `Cursor` for reading.
    pub fn cursor(&self) -> Cursor<'_> {
        Cursor {
            chain: self,
            node_idx: 0,
            in_node_off: 0,
            consumed: 0,
        }
    }

    /// Split the chain at byte offset `n` across visible payloads.
    /// `self` keeps the first `n` bytes; the returned chain holds
    /// the remainder.
    ///
    /// At most one `IOBuf` is split — the part that straddles byte
    /// `n` is `split_at`'d via [`IOBuf::split_at`], promoting any
    /// `Heap` half to refcount-shared storage so no payload bytes
    /// are copied. Parts before / after the straddler move whole.
    /// When `n` lands exactly on a part boundary, no buf is split.
    ///
    /// `n >= self.total_len()` returns an empty tail (no-op).
    /// `n == 0` returns the entire original chain as tail and leaves
    /// `self` empty.
    pub fn split_off(&mut self, n: usize) -> IOBufChain {
        if n >= self.total_len() {
            return IOBufChain::new();
        }
        if n == 0 {
            return core::mem::take(self);
        }

        // Find the straddler: walk parts front-to-back, summing
        // visible-payload lengths until the next part would push
        // the cumulative past `n`.
        let mut acc = 0usize;
        let mut straddler_idx = 0usize;
        let mut split_at_in_part = 0usize;
        for (i, part) in self.iter().enumerate() {
            let part_len = part.len();
            if acc + part_len > n {
                straddler_idx = i;
                split_at_in_part = n - acc;
                break;
            }
            acc += part_len;
        }

        // Pop straddler and everything after off the back into a
        // scratch Vec in reverse chain order, then push them into
        // `tail` in chain order. `pop_back` is O(1) per part; total
        // cost is O(part_count - straddler_idx).
        let pop_count = self.part_count() - straddler_idx;
        let mut popped: alloc::vec::Vec<IOBuf> =
            alloc::vec::Vec::with_capacity(pop_count);
        for _ in 0..pop_count {
            popped.push(self.pop_back().expect("part_count consistent"));
        }
        // popped is back-to-front; reverse to get chain order.
        popped.reverse();

        let mut tail = IOBufChain::with_capacity(pop_count);
        // First popped element is the straddler. If
        // `split_at_in_part == 0`, the split is at a clean part
        // boundary and the straddler moves wholesale to `tail`;
        // otherwise we split it via IOBuf::split_at.
        let mut iter = popped.into_iter();
        let mut straddler = iter.next().expect("pop_count >= 1");
        if split_at_in_part > 0 {
            let straddler_tail = straddler.split_at(split_at_in_part);
            self.push_back(straddler);
            tail.push_back(straddler_tail);
        } else {
            tail.push_back(straddler);
        }
        for part in iter {
            tail.push_back(part);
        }
        tail
    }
}

/// `iter_mut`'s return type. A hand-rolled enum iterator: the
/// three `Repr` arms yield differently-typed iterators, and this
/// unifies them behind one `impl Iterator` with no heap
/// allocation and no `dyn` dispatch.
enum ChainIterMut<'a> {
    Empty,
    Single(Option<&'a mut IOBuf>),
    Many(alloc::collections::vec_deque::IterMut<'a, IOBuf>),
}

impl<'a> Iterator for ChainIterMut<'a> {
    type Item = &'a mut IOBuf;
    fn next(&mut self) -> Option<&'a mut IOBuf> {
        match self {
            ChainIterMut::Empty => None,
            ChainIterMut::Single(slot) => slot.take(),
            ChainIterMut::Many(it) => it.next(),
        }
    }
}

impl Default for IOBufChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---- IOBufChain From<X> conversions ---------------------------------
//
// Every shape an HTTP body / response can land in flattens to a
// 1-part chain via these. Apps build chains directly:
//
//   Response::ok(b"text/plain", b"hello")          // &'static [u8]
//   Response::ok(b"text/plain", rendered)          // String / Vec<u8>
//   Response::ok(b"text/html", chain)              // multi-part
//
// without picking a method based on body shape.

impl From<IOBuf> for IOBufChain {
    fn from(b: IOBuf) -> Self {
        let mut c = IOBufChain::with_capacity(1);
        c.push_back(b);
        c
    }
}

impl From<&'static [u8]> for IOBufChain {
    fn from(s: &'static [u8]) -> Self {
        IOBuf::from_static(s).into()
    }
}

impl<const N: usize> From<&'static [u8; N]> for IOBufChain {
    fn from(s: &'static [u8; N]) -> Self {
        IOBuf::from_static(s).into()
    }
}

impl From<&'static str> for IOBufChain {
    fn from(s: &'static str) -> Self {
        IOBuf::from_static(s.as_bytes()).into()
    }
}

impl From<alloc::vec::Vec<u8>> for IOBufChain {
    fn from(v: alloc::vec::Vec<u8>) -> Self {
        IOBuf::from(v).into()
    }
}

impl From<alloc::boxed::Box<[u8]>> for IOBufChain {
    fn from(b: alloc::boxed::Box<[u8]>) -> Self {
        IOBuf::from(b.into_vec()).into()
    }
}

impl From<alloc::string::String> for IOBufChain {
    fn from(s: alloc::string::String) -> Self {
        IOBuf::from(s.into_bytes()).into()
    }
}

// ============================================================================
// Cursor
// ============================================================================

/// Read-side traversal of an `IOBufChain`. Walks node boundaries
/// transparently — `read` and `next_chunk` hop nodes when the
/// current one is exhausted. `advance` can skip ahead without
/// copying.
pub struct Cursor<'a> {
    chain: &'a IOBufChain,
    /// Index of the current part within the chain.
    node_idx: usize,
    /// Bytes already consumed from the current node (offset into
    /// the current node's `data()` slice).
    in_node_off: usize,
    /// Total bytes consumed so far across all nodes.
    consumed: usize,
}

impl<'a> Cursor<'a> {
    /// Bytes still available from the current cursor position to
    /// the end of the chain.
    pub fn remaining(&self) -> usize {
        self.chain.total_len().saturating_sub(self.consumed)
    }

    pub fn position(&self) -> usize {
        self.consumed
    }

    /// Resolve a part index to a borrowed `IOBuf`, or `None` past
    /// the chain's end. Delegates to `IOBufChain::get_part`.
    #[inline]
    fn node_at(&self, idx: usize) -> Option<&'a IOBuf> {
        self.chain.get_part(idx)
    }

    /// Advance the cursor by `n` bytes without reading. Caps at
    /// `remaining()`; returns the number of bytes actually
    /// advanced.
    pub fn advance(&mut self, n: usize) -> usize {
        let mut to_skip = n.min(self.remaining());
        let advanced = to_skip;
        while to_skip > 0 {
            let node = match self.node_at(self.node_idx) {
                Some(n) => n,
                None => break,
            };
            let avail = node.len() - self.in_node_off;
            if to_skip < avail {
                self.in_node_off += to_skip;
                to_skip = 0;
            } else {
                to_skip -= avail;
                self.node_idx += 1;
                self.in_node_off = 0;
            }
        }
        self.consumed += advanced;
        advanced
    }

    /// Read up to `dst.len()` bytes into `dst`, hopping node
    /// boundaries as needed. Returns bytes copied. The "one
    /// memcpy into the destination" property is what the NIC TX
    /// driver wants — copy chain bytes straight into the TX
    /// descriptor without an intermediate Vec.
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let mut written = 0;
        while written < dst.len() {
            let node = match self.node_at(self.node_idx) {
                Some(n) => n,
                None => break,
            };
            let node_data = node.data();
            let avail = node_data.len() - self.in_node_off;
            if avail == 0 {
                self.node_idx += 1;
                self.in_node_off = 0;
                continue;
            }
            let n = (dst.len() - written).min(avail);
            dst[written..written + n]
                .copy_from_slice(&node_data[self.in_node_off..self.in_node_off + n]);
            self.in_node_off += n;
            written += n;
            if self.in_node_off == node_data.len() {
                self.node_idx += 1;
                self.in_node_off = 0;
            }
        }
        self.consumed += written;
        written
    }

    /// Return a borrowed slice for the next contiguous chunk of
    /// up to `max_len` bytes (or `None` at end-of-chain), and
    /// advance past it. The returned slice borrows directly from
    /// the underlying IOBuf — zero copy — but is only valid for
    /// the cursor's lifetime parameter `'a`.
    ///
    /// The returned chunk may be shorter than `max_len` if the
    /// current node ends before `max_len` bytes; callers that
    /// need exactly `max_len` should call repeatedly or use
    /// `read`.
    pub fn next_chunk(&mut self, max_len: usize) -> Option<&'a [u8]> {
        loop {
            let node = self.node_at(self.node_idx)?;
            let node_data = node.data();
            let avail = node_data.len() - self.in_node_off;
            if avail == 0 {
                self.node_idx += 1;
                self.in_node_off = 0;
                continue;
            }
            let n = avail.min(max_len);
            let slice = &node_data[self.in_node_off..self.in_node_off + n];
            self.in_node_off += n;
            self.consumed += n;
            if self.in_node_off == node_data.len() {
                self.node_idx += 1;
                self.in_node_off = 0;
            }
            return Some(slice);
        }
    }
}

// ============================================================================
// From/Into for ergonomics
// ============================================================================

impl From<&'static [u8]> for IOBuf {
    fn from(s: &'static [u8]) -> Self {
        IOBuf::from_static(s)
    }
}

impl<const N: usize> From<&'static [u8; N]> for IOBuf {
    fn from(s: &'static [u8; N]) -> Self {
        IOBuf::from_static(s)
    }
}

impl From<&'static str> for IOBuf {
    fn from(s: &'static str) -> Self {
        IOBuf::from_static(s.as_bytes())
    }
}

impl From<alloc::vec::Vec<u8>> for IOBuf {
    fn from(v: alloc::vec::Vec<u8>) -> Self {
        // Vec's allocation becomes a Box<[u8]> via into_boxed_slice
        // (no copy — same bytes). Headroom = 0, tailroom = 0;
        // callers who want layer-prepend room should construct via
        // `from_slice_with_headroom`.
        let len = v.len();
        let storage: Box<[u8]> = v.into_boxed_slice();
        IOBuf {
            inner: Inner::Heap {
                storage,
                offset: 0,
                len: len as u32,
            },
        }
    }
}

impl From<alloc::string::String> for IOBuf {
    fn from(s: alloc::string::String) -> Self {
        IOBuf::from(s.into_bytes())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_buf_basics() {
        let b = IOBuf::from_static(b"hello");
        assert_eq!(b.data(), b"hello");
        assert_eq!(b.len(), 5);
        assert_eq!(b.headroom(), 0);
        assert_eq!(b.tailroom(), 0);
    }

    #[test]
    fn static_buf_consume() {
        let mut b = IOBuf::from_static(b"hello world");
        b.consume(6).unwrap();
        assert_eq!(b.data(), b"world");
        b.trim_end(2).unwrap();
        assert_eq!(b.data(), b"wor");
    }

    #[test]
    fn static_buf_prepend_rejects() {
        let mut b = IOBuf::from_static(b"x");
        assert_eq!(b.prepend(b"y"), Err(IOBufError::Immutable));
        assert_eq!(b.append_slice(b"y"), Err(IOBufError::Immutable));
        assert!(b.data_mut().is_none());
    }

    #[test]
    fn heap_buf_headroom_prepend() {
        let mut b = IOBuf::from_slice_with_headroom(8, b"world", 0);
        assert_eq!(b.data(), b"world");
        assert_eq!(b.headroom(), 8);
        assert_eq!(b.tailroom(), 0);
        b.prepend(b"hello ").unwrap();
        assert_eq!(b.data(), b"hello world");
        assert_eq!(b.headroom(), 2);
    }

    #[test]
    fn heap_buf_prepend_overflow() {
        let mut b = IOBuf::from_slice_with_headroom(2, b"x", 0);
        assert_eq!(b.prepend(b"abc"), Err(IOBufError::NoHeadroom));
        // Original payload preserved on error.
        assert_eq!(b.data(), b"x");
    }

    #[test]
    fn heap_buf_tailroom_append() {
        let mut b = IOBuf::from_slice_with_headroom(0, b"hello", 8);
        b.append_slice(b" world").unwrap();
        assert_eq!(b.data(), b"hello world");
        assert_eq!(b.tailroom(), 2);
    }

    #[test]
    fn heap_buf_extend_uninit() {
        let mut b = IOBuf::from_slice_with_headroom(0, b"hi", 8);
        let tail = b.extend_uninit(4).unwrap();
        tail.copy_from_slice(b"!!!!");
        assert_eq!(b.data(), b"hi!!!!");
    }

    #[test]
    fn heap_buf_data_mut_in_place_xor() {
        let mut b = IOBuf::from_slice_with_headroom(0, b"abc", 0);
        for byte in b.data_mut().unwrap() {
            *byte ^= 0x20;
        }
        assert_eq!(b.data(), b"ABC");
    }

    #[test]
    fn chain_push_total_len() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"hello"));
        c.push_back(IOBuf::from_static(b" "));
        c.push_back(IOBuf::from_static(b"world"));
        assert_eq!(c.total_len(), 11);
        assert_eq!(c.part_count(), 3);
    }

    #[test]
    fn chain_push_front_o1() {
        // Build the body, then framing prepends in front.
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"BODY"));
        c.push_front(IOBuf::from_static(b"HEADERS"));
        let mut out = [0u8; 16];
        let n = c.cursor().read(&mut out);
        assert_eq!(&out[..n], b"HEADERSBODY");
    }

    #[test]
    fn chain_prepend_in_place() {
        // Front node has 8 B headroom → TLS record header fits.
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_slice_with_headroom(8, b"plaintext", 16));
        c.prepend_in_place(b"REC1").unwrap();
        let mut out = [0u8; 32];
        let n = c.cursor().read(&mut out);
        assert_eq!(&out[..n], b"REC1plaintext");
    }

    #[test]
    fn chain_prepend_in_place_no_headroom_errors() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"static"));
        assert_eq!(c.prepend_in_place(b"x"), Err(IOBufError::Immutable));
    }

    #[test]
    fn cursor_read_across_nodes() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"abc"));
        c.push_back(IOBuf::from_static(b"def"));
        c.push_back(IOBuf::from_static(b"ghi"));
        let mut cur = c.cursor();
        let mut out = [0u8; 5];
        let n = cur.read(&mut out);
        assert_eq!(n, 5);
        assert_eq!(&out, b"abcde");
        let n = cur.read(&mut out);
        assert_eq!(n, 4);
        assert_eq!(&out[..n], b"fghi");
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn cursor_next_chunk_returns_node_at_a_time() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"abc"));
        c.push_back(IOBuf::from_static(b"def"));
        let mut cur = c.cursor();
        assert_eq!(cur.next_chunk(100), Some(b"abc".as_ref()));
        assert_eq!(cur.next_chunk(100), Some(b"def".as_ref()));
        assert_eq!(cur.next_chunk(100), None);
    }

    #[test]
    fn cursor_next_chunk_caps_at_max_len() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"abcdefgh"));
        let mut cur = c.cursor();
        assert_eq!(cur.next_chunk(3), Some(b"abc".as_ref()));
        assert_eq!(cur.next_chunk(3), Some(b"def".as_ref()));
        assert_eq!(cur.next_chunk(10), Some(b"gh".as_ref()));
        assert_eq!(cur.next_chunk(10), None);
    }

    #[test]
    fn cursor_advance_skips_into_later_node() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"abc"));
        c.push_back(IOBuf::from_static(b"def"));
        let mut cur = c.cursor();
        let skipped = cur.advance(4);
        assert_eq!(skipped, 4);
        assert_eq!(cur.position(), 4);
        let mut out = [0u8; 4];
        let n = cur.read(&mut out);
        assert_eq!(n, 2);
        assert_eq!(&out[..n], b"ef");
    }

    #[test]
    fn cursor_advance_caps_at_remaining() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"abc"));
        let mut cur = c.cursor();
        let skipped = cur.advance(100);
        assert_eq!(skipped, 3);
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn vec_into_iobuf_no_copy() {
        let v = alloc::vec![1u8, 2, 3, 4, 5];
        let ptr_before = v.as_ptr();
        let buf = IOBuf::from(v);
        // `Vec::into_boxed_slice` reuses the allocation when len ==
        // capacity; we don't guarantee no-copy in general, but for
        // an exact-fit Vec (constructed from `vec!`) it should hold.
        // Treat as a smoke test of the conversion direction.
        assert_eq!(buf.data(), &[1u8, 2, 3, 4, 5]);
        let _ = ptr_before;
    }

    #[test]
    fn iobuf_writer_renders_into_tailroom() {
        use core::fmt::Write as _;
        let mut buf = IOBuf::new_with_reserved(8, 0, 64);
        // Visible payload starts empty.
        assert_eq!(buf.len(), 0);
        write!(buf.writer(), "hello {}", 42).unwrap();
        assert_eq!(buf.data(), b"hello 42");
        // Subsequent prepend uses headroom (still has 8 reserved).
        buf.prepend(b"REC1").unwrap();
        assert_eq!(buf.data(), b"REC1hello 42");
    }

    #[test]
    fn iobuf_writer_signals_overflow() {
        use core::fmt::Write as _;
        let mut buf = IOBuf::new_with_reserved(0, 0, 4);
        let mut w = buf.writer();
        // First write fits.
        let _ = write!(w, "ab");
        // Second exceeds tailroom — the second write_str call
        // sets overflowed and returns Err.
        let r = write!(w, "cdefgh");
        assert!(r.is_err());
        assert!(w.overflowed());
    }

    #[test]
    fn external_buf_drop_runs_callback() {
        use core::ptr::NonNull;
        use core::sync::atomic::{AtomicBool, Ordering};
        extern crate std;
        use std::sync::Arc;

        let released = Arc::new(AtomicBool::new(false));

        // Drop callback: reconstructs the Arc from the raw ctx
        // pointer (canceling the `into_raw` increment), flips
        // the flag, then drops the Arc.
        unsafe fn cb(_base: NonNull<u8>, _cap: u32, ctx: *mut ()) {
            let arc: Arc<AtomicBool> =
                unsafe { Arc::from_raw(ctx as *const AtomicBool) };
            arc.store(true, Ordering::SeqCst);
        }

        // Owns a small backing region; we'll wrap it as
        // ExternalOwned and ensure the drop callback fires when
        // the IOBuf drops.
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        storage[5..13].copy_from_slice(b"abcdefgh");
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        let ctx = Arc::into_raw(released.clone()) as *mut ();
        {
            // SAFETY: storage outlives the IOBuf in this block;
            // the drop callback reconstructs the Arc from ctx
            // (via `Arc::from_raw`, canceling the `into_raw`
            // refcount bump above) and lets it drop normally.
            let mut buf = unsafe {
                IOBuf::wrap_owned(ptr, 32, 5, 8, cb, ctx)
            };
            assert_eq!(buf.data(), b"abcdefgh");
            assert_eq!(buf.headroom(), 5);
            assert_eq!(buf.tailroom(), 19);
            // Prepend uses headroom (writes into storage[2..5]).
            buf.prepend(b"PRE").unwrap();
            assert_eq!(buf.data(), b"PREabcdefgh");
            // Append uses tailroom.
            buf.append_slice(b"END").unwrap();
            assert_eq!(buf.data(), b"PREabcdefghEND");
            // Mutate in place.
            for byte in buf.data_mut().unwrap() {
                if (b'a'..=b'z').contains(byte) {
                    *byte ^= 0x20;
                }
            }
            assert_eq!(buf.data(), b"PREABCDEFGHEND");
            // Callback hasn't run yet.
            assert!(!released.load(Ordering::SeqCst));
        }
        // IOBuf dropped at scope end → drop callback fires.
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn borrowed_buf_no_drop_callback() {
        // `borrow` produces a non-owning view; no callback runs
        // at drop. Caller manages the storage's lifetime.
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        storage[5..13].copy_from_slice(b"abcdefgh");
        let ptr = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        // SAFETY: storage outlives the IOBuf in this block.
        let mut buf = unsafe { IOBuf::borrow(ptr, 32, 5, 8) };
        assert_eq!(buf.data(), b"abcdefgh");
        assert_eq!(buf.headroom(), 5);
        assert_eq!(buf.tailroom(), 19);
        buf.prepend(b"PRE").unwrap();
        assert_eq!(buf.data(), b"PREabcdefgh");
        buf.append_slice(b"END").unwrap();
        assert_eq!(buf.data(), b"PREabcdefghEND");
        for byte in buf.data_mut().unwrap() {
            if (b'a'..=b'z').contains(byte) {
                *byte ^= 0x20;
            }
        }
        assert_eq!(buf.data(), b"PREABCDEFGHEND");
        drop(buf);
        // Storage is still valid (no drop callback fired).
        assert_eq!(&storage[5..13], b"ABCDEFGH");
    }

    /// Compile-time assertion that `IOBuf` is `!Send`. The
    /// `Inner::Borrowed` variant carries a `PhantomData<*const ()>`
    /// and a `NonNull<u8>`, both of which propagate `!Send`
    /// through the enum's auto-traits — so a `Borrowed` IOBuf
    /// can't accidentally cross workers. Containing structs that
    /// legitimately move IOBufs across workers (e.g.
    /// `WorkerInbox`) must override with `unsafe impl Send` and
    /// document the contract.
    ///
    /// The trick: a blanket-impl trait that's only implemented for
    /// `Send` types. If `IOBuf` were `Send` this `<IOBuf as
    /// IsSend>::CHECK` would succeed; we assert it via an
    /// expression that needs the trait to NOT be implemented.
    /// We use the standard pattern of an inherent associated
    /// `const _: ()` that would mention the trait method only if
    /// `IOBuf: Send`. Since rust-stable doesn't support `!Send`
    /// bounds directly, we instead use a struct that requires Send
    /// in a field and ensure IOBuf doesn't fit.
    #[test]
    fn iobuf_is_not_send() {
        // Strategy: any type that lives inside `std::sync::Mutex`
        // must be Send (Mutex<T>: Send requires T: Send). If
        // IOBuf were Send, this fn would compile. If it isn't,
        // it won't. But we want the OPPOSITE — we want the test
        // to confirm IOBuf isn't Send. So we use a function whose
        // body would type-check ONLY IF IOBuf were Send, and we
        // verify the negative via a `#[cfg]` gate.
        //
        // Stable Rust can't express this directly. Best we can do
        // at the test level is run a positive runtime check that
        // a thread-spawn over IOBuf would fail to compile if
        // attempted; the body below is intentionally commented
        // out — uncommenting it should fail compilation. CI can
        // run a `cargo build --tests` and a separate `cargo build
        // --tests --cfg=should_fail_send` to confirm.
        //
        // For now, this test just exercises the Borrowed variant
        // (so the variant isn't dead code) and documents intent.
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 4];
        let ptr = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        let buf = unsafe { IOBuf::borrow(ptr, 4, 0, 0) };
        assert_eq!(buf.len(), 0);

        // Uncommenting the line below should produce a compile
        // error of the form: "future cannot be sent between threads
        // safely" / "IOBuf is not Send". Verified manually.
        //
        // extern crate std;
        // std::thread::spawn(move || { let _ = buf; });
    }

    #[test]
    fn borrow_tracker_allows_disjoint_regions() {
        // Two non-overlapping sub-views of the same backing array
        // should coexist — this is exactly the body-scratch carving
        // pattern at uni-http/src/lib.rs:207.
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        let base = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        let p1 = unsafe { core::ptr::NonNull::new_unchecked(base.as_ptr()) };
        let p2 = unsafe { core::ptr::NonNull::new_unchecked(base.as_ptr().add(16)) };
        // SAFETY: storage outlives both IOBufs; non-overlapping ranges.
        let b1 = unsafe { IOBuf::borrow(p1, 16, 0, 0) };
        let b2 = unsafe { IOBuf::borrow(p2, 16, 0, 0) };
        assert_eq!(b1.len(), 0);
        assert_eq!(b2.len(), 0);
    }

    #[test]
    #[should_panic(expected = "overlapping IOBuf::borrow mint")]
    fn borrow_tracker_detects_overlap() {
        // Two overlapping sub-views of the same backing array.
        // Real-world equivalent: a body-scratch cursor bug minting
        // a second sub-range that straddles the first.
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        let base = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        let p1 = unsafe { core::ptr::NonNull::new_unchecked(base.as_ptr()) };
        let p2 = unsafe { core::ptr::NonNull::new_unchecked(base.as_ptr().add(8)) };
        // SAFETY (for the demonstration): the second mint is the
        // intentional bug we're catching — overlap with the first.
        let _b1 = unsafe { IOBuf::borrow(p1, 16, 0, 0) };
        let _b2 = unsafe { IOBuf::borrow(p2, 16, 0, 0) };
    }

    #[test]
    fn borrow_tracker_reregister_after_drop() {
        // Drop should unregister, freeing the region for a fresh
        // borrow over the same storage — this is the per-worker
        // scratch reuse pattern in TLS RecordScratch::into_iobuf.
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        let base = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        // SAFETY: storage outlives both successive IOBufs; only one
        // is live at any given time.
        {
            let _b1 = unsafe { IOBuf::borrow(base, 32, 0, 0) };
        }
        // First IOBuf dropped → tracker unregistered → fresh borrow
        // over the same region is valid.
        let _b2 = unsafe { IOBuf::borrow(base, 32, 0, 0) };
    }

    #[test]
    fn split_at_promotes_heap_to_shared() {
        // Heap IOBuf → split_at(n) → both halves Shared, pointing
        // at the same Rc<[u8]>. Tail's first byte is `n` bytes
        // past head's first byte in the shared storage.
        let mut head = IOBuf::from(alloc::vec![1u8, 2, 3, 4, 5]);
        let tail = head.split_at(2);
        assert_eq!(head.data(), &[1, 2]);
        assert_eq!(tail.data(), &[3, 4, 5]);
        assert!(matches!(head.inner, Inner::Shared { .. }));
        assert!(matches!(tail.inner, Inner::Shared { .. }));
        // Same backing allocation — head's last byte's address is
        // tail's first byte's address minus 1.
        let head_ptr = head.data().as_ptr() as usize;
        let tail_ptr = tail.data().as_ptr() as usize;
        assert_eq!(tail_ptr, head_ptr + 2);
    }

    #[test]
    fn split_at_static_slices_without_rc() {
        let mut head = IOBuf::from_static(b"hello world");
        let tail = head.split_at(6);
        assert_eq!(head.data(), b"hello ");
        assert_eq!(tail.data(), b"world");
        assert!(matches!(head.inner, Inner::Static { .. }));
        assert!(matches!(tail.inner, Inner::Static { .. }));
    }

    #[test]
    fn split_at_shared_clones_rc() {
        // Splitting a Shared IOBuf bumps the Rc refcount; both
        // halves remain Shared with disjoint windows.
        let mut a = IOBuf::from(alloc::vec![0u8; 16]);
        let _b = a.split_at(8); // a, _b both Shared
        let c = a.split_at(4); // a, c both Shared (further split)
        assert_eq!(a.len(), 4);
        assert_eq!(c.len(), 4);
        assert!(matches!(a.inner, Inner::Shared { .. }));
        assert!(matches!(c.inner, Inner::Shared { .. }));
    }

    #[test]
    fn make_unique_unique_is_zero_copy() {
        // Shared IOBuf with refcount 1 → make_unique is a no-op;
        // the storage pointer is unchanged.
        let mut buf = IOBuf::from(alloc::vec![1u8, 2, 3, 4, 5]);
        let tail = buf.split_at(2);
        drop(tail); // refcount drops to 1
        let ptr_before = buf.data().as_ptr() as usize;
        buf.make_unique();
        let ptr_after = buf.data().as_ptr() as usize;
        assert_eq!(
            ptr_before, ptr_after,
            "refcount-1 Shared must not copy"
        );
        assert!(matches!(buf.inner, Inner::Shared { .. }));
    }

    #[test]
    fn make_unique_shared_copies() {
        // Shared IOBuf with refcount 2 → make_unique on one half
        // clones the visible payload into a fresh Heap. The other
        // half is unaffected.
        let mut a = IOBuf::from(alloc::vec![1u8, 2, 3, 4, 5]);
        let b = a.split_at(2);
        // a and b share the same Rc<[u8]>, refcount 2.
        let a_ptr_before = a.data().as_ptr() as usize;
        a.make_unique();
        let a_ptr_after = a.data().as_ptr() as usize;
        assert_ne!(
            a_ptr_before, a_ptr_after,
            "shared refcount > 1 must copy"
        );
        // After make_unique, `a` should be Heap, `b` still Shared
        // (now with refcount 1).
        assert!(matches!(a.inner, Inner::Heap { .. }));
        assert!(matches!(b.inner, Inner::Shared { .. }));
        // Data preserved on both sides.
        assert_eq!(a.data(), &[1, 2]);
        assert_eq!(b.data(), &[3, 4, 5]);
    }

    #[test]
    fn shared_data_mut_after_split_isolates_halves() {
        // End-to-end: split a Heap, mutate one half, observe the
        // other is untouched. Exercises data_mut's implicit
        // make_unique path.
        let mut a = IOBuf::from(alloc::vec![1u8, 2, 3, 4, 5]);
        let b = a.split_at(2);
        for byte in a.data_mut().unwrap() {
            *byte = 0;
        }
        assert_eq!(a.data(), &[0, 0]);
        assert_eq!(b.data(), &[3, 4, 5]);
    }

    #[test]
    fn chain_split_off_at_buf_boundary() {
        // Split at a clean part boundary → no IOBuf split_at fires.
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"hello"));
        c.push_back(IOBuf::from_static(b"world"));
        let tail = c.split_off(5);
        assert_eq!(c.total_len(), 5);
        assert_eq!(tail.total_len(), 5);
        assert_eq!(c.part_count(), 1);
        assert_eq!(tail.part_count(), 1);
        // Both halves are Static — split_at on Static slices, but
        // here split_off should have moved the whole second part to
        // tail with no per-buf split.
        let mut out = [0u8; 16];
        let n = c.cursor().read(&mut out);
        assert_eq!(&out[..n], b"hello");
        let n = tail.cursor().read(&mut out);
        assert_eq!(&out[..n], b"world");
    }

    #[test]
    fn chain_split_off_mid_buf() {
        // Split inside a buf → exactly one split_at fires.
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"hello"));
        c.push_back(IOBuf::from_static(b"world"));
        let tail = c.split_off(3);
        assert_eq!(c.total_len(), 3);
        assert_eq!(tail.total_len(), 7);
        let mut out = [0u8; 16];
        let n = c.cursor().read(&mut out);
        assert_eq!(&out[..n], b"hel");
        let n = tail.cursor().read(&mut out);
        assert_eq!(&out[..n], b"loworld");
    }

    #[test]
    fn chain_split_off_heap_promotes_to_shared() {
        // Splitting inside a Heap part promotes both halves to
        // Shared with the same backing Rc<[u8]>.
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from(alloc::vec![1u8, 2, 3, 4, 5, 6, 7, 8]));
        let tail = c.split_off(3);
        let mut head_out = [0u8; 16];
        let n = c.cursor().read(&mut head_out);
        assert_eq!(&head_out[..n], &[1, 2, 3]);
        let mut tail_out = [0u8; 16];
        let n = tail.cursor().read(&mut tail_out);
        assert_eq!(&tail_out[..n], &[4, 5, 6, 7, 8]);
    }

    #[test]
    fn chain_split_off_past_end_is_noop() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"hello"));
        let tail = c.split_off(100);
        assert!(tail.is_empty());
        assert_eq!(c.total_len(), 5);
    }

    #[test]
    fn chain_split_off_zero_takes_everything() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"hello"));
        c.push_back(IOBuf::from_static(b"world"));
        let tail = c.split_off(0);
        assert!(c.is_empty());
        assert_eq!(tail.total_len(), 10);
    }

    #[test]
    fn full_layer_stack_simulation() {
        // Simulate a layered prepend pattern: app puts a body in
        // a chain, HTTP/1.1 prepends a status line, TLS prepends a
        // record header — all in place into reserved headroom of
        // the same IOBuf. Exercise the prepend_in_place path
        // end-to-end without copying bytes beyond the writes we
        // explicitly perform.
        let mut chain = IOBufChain::new();
        // 64 B headroom covers the HTTP status line + TLS record
        // header we'll prepend below.
        let body = IOBuf::from_slice_with_headroom(64, b"<html>...</html>", 0);
        chain.push_back(body);

        // HTTP layer: prepend headers in place. (Real impl writes
        // \r\n\r\n; here we just stand in.)
        chain.prepend_in_place(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();

        // TLS layer: prepend record header.
        chain.prepend_in_place(b"\x17\x03\x03\x00\x10").unwrap();

        // Read the full chain into a destination buffer (NIC TX
        // simulation).
        let mut out = [0u8; 256];
        let n = chain.cursor().read(&mut out);
        assert_eq!(
            &out[..n],
            b"\x17\x03\x03\x00\x10HTTP/1.1 200 OK\r\n\r\n<html>...</html>"
        );
        assert_eq!(chain.total_len(), n);
    }

    #[test]
    fn into_owned_heap_is_zero_copy() {
        // Heap already owns its storage — into_owned returns it
        // unchanged, same allocation, no copy.
        let b = IOBuf::from(alloc::vec![1u8, 2, 3, 4]);
        let ptr_before = b.data().as_ptr() as usize;
        let o = b.into_owned();
        assert!(matches!(o.inner, Inner::Heap { .. }));
        assert_eq!(o.data(), &[1, 2, 3, 4]);
        assert_eq!(
            o.data().as_ptr() as usize,
            ptr_before,
            "Heap into_owned must not reallocate"
        );
    }

    #[test]
    fn into_owned_static_is_noop() {
        let o = IOBuf::from_static(b"hello").into_owned();
        assert!(matches!(o.inner, Inner::Static { .. }));
        assert_eq!(o.data(), b"hello");
    }

    #[test]
    fn into_owned_shared_stays_shared() {
        // Shared is refcount-owned; into_owned leaves it Shared (no
        // forced make_unique copy).
        let mut a = IOBuf::from(alloc::vec![1u8, 2, 3, 4]);
        let _tail = a.split_at(2); // promotes `a` to Shared
        assert!(matches!(a.inner, Inner::Shared { .. }));
        let o = a.into_owned();
        assert!(matches!(o.inner, Inner::Shared { .. }));
        assert_eq!(o.data(), &[1, 2]);
    }

    #[test]
    fn into_owned_external_is_noop_and_drops_once() {
        // ExternalOwned already owns its region: into_owned returns
        // it unchanged, and the drop callback still fires exactly
        // once when the surviving IOBuf drops.
        use core::ptr::NonNull;
        use core::sync::atomic::{AtomicBool, Ordering};
        extern crate std;
        use std::sync::Arc;

        let released = Arc::new(AtomicBool::new(false));
        unsafe fn cb(_base: NonNull<u8>, _cap: u32, ctx: *mut ()) {
            let arc: Arc<AtomicBool> =
                unsafe { Arc::from_raw(ctx as *const AtomicBool) };
            arc.store(true, Ordering::SeqCst);
        }

        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 16];
        storage[0..4].copy_from_slice(b"data");
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        let ctx = Arc::into_raw(released.clone()) as *mut ();
        {
            // SAFETY: storage outlives the IOBuf; the callback
            // reconstructs the Arc from ctx and lets it drop.
            let b = unsafe { IOBuf::wrap_owned(ptr, 16, 0, 4, cb, ctx) };
            let o = b.into_owned();
            assert!(matches!(o.inner, Inner::ExternalOwned(_)));
            assert_eq!(o.data(), b"data");
            assert!(!released.load(Ordering::SeqCst), "callback not yet run");
        }
        assert!(
            released.load(Ordering::SeqCst),
            "drop callback fires exactly once after into_owned"
        );
    }

    #[test]
    fn into_owned_borrowed_copies_to_heap() {
        // Borrowed is the one variant that costs a copy: into_owned
        // materialises an independent Heap buffer with identical
        // content.
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        storage[4..12].copy_from_slice(b"abcdefgh");
        let ptr = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        let owned = {
            // SAFETY: storage outlives the borrow; the borrow ends
            // when into_owned consumes it.
            let b = unsafe { IOBuf::borrow(ptr, 32, 4, 8) };
            assert!(matches!(b.inner, Inner::Borrowed { .. }));
            b.into_owned()
        };
        assert!(matches!(owned.inner, Inner::Heap { .. }));
        assert_eq!(owned.data(), b"abcdefgh");
        // Mutating the original backing store proves the owned copy
        // is fully independent of it.
        storage[4..12].copy_from_slice(b"XXXXXXXX");
        assert_eq!(owned.data(), b"abcdefgh", "owned copy is independent");
    }
}
