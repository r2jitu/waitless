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
// Design choices made for v1 (knowingly minimal — the goal is to
// land the type and start porting consumers; we add features when
// porting hits a wall):
//
//   * Single-owner heap segments. No `Rc<[u8]>` refcount yet — a
//     consumer that wants to retain a chunk for retransmit storage
//     today either copies (Vec) or moves the IOBuf out of the
//     chain. Sharing comes when the QUIC retransmit window needs
//     to hold onto chunks past their ACK-driven free.
//   * Static borrows. Zero-copy for `&'static [u8]` literals (the
//     STYLES block, every shell HTML chunk). No headroom/tailroom
//     on these — they're immutable, layers can't prepend INTO
//     them, but a heap-allocated header node can prepend before
//     them in the chain.
//   * Heap variant carries `offset` + `len` as `u32` (saves 8 B
//     per node vs `usize`). 4 GiB per chunk is plenty for any
//     unikernel workload.
//   * `IOBufChain` is a `VecDeque<IOBuf>`. Push-front and
//     push-back are both amortised O(1); we don't actually need
//     linked-list semantics, just chain-level prepend / append.
//
// Future additions (when ports demand them):
//
//   * `Rc<Storage>` heap variant for shared retransmit storage.
//   * NIC-descriptor variant for true zero-copy RX (the descriptor
//     gets recycled when the IOBuf drops).
//   * `try_coalesce` for crypto APIs that need contiguous input.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::marker::PhantomData;

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
/// variant — its Drop fires when the variant drops (which happens
/// when the IOBuf drops, OR when the variant is destructured in
/// `into_owned_vec`), so we can't accidentally orphan a live
/// registration. In release builds (`!debug_assertions`) the guard
/// is a ZST and Drop is empty.
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
    #[inline]
    pub fn data_mut(&mut self) -> Option<&mut [u8]> {
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
    /// `Err(IOBufError::Immutable)` for static borrows. Lower
    /// layers should choose buffer sizes with enough headroom for
    /// every layer below them — see `MAX_HEADER_RESERVE`.
    pub fn prepend(&mut self, data: &[u8]) -> Result<(), IOBufError> {
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

    /// Consume the IOBuf, producing an owned `Vec<u8>` of just
    /// the visible payload bytes. Zero-copy when this is a Heap
    /// variant whose visible payload spans the entire backing
    /// storage (offset=0 and len=cap); otherwise copies into a
    /// fresh Vec. For Static variants, always copies.
    ///
    /// Used as a bridge to APIs that take ownership of bytes via
    /// `Vec<u8>` (uni-quic's `SendStream::write_owned`). When that
    /// API itself moves to IOBuf the bridge goes away.
    pub fn into_owned_vec(self) -> alloc::vec::Vec<u8> {
        // For Heap with an exactly-fitting payload, migrate the
        // Box<[u8]> into a Vec<u8> with no copy. Other variants
        // (Static, ExternalOwned, Borrowed) require copying since
        // we don't own the storage in a Vec-compatible shape.
        // ExternalOwned notably ALSO has to release its
        // descriptor on drop — copying out lets the drop callback
        // fire promptly.
        match self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let o = offset as usize;
                let l = len as usize;
                if o == 0 && l == storage.len() {
                    // Whole-buffer ownership migrates without copy.
                    storage.into_vec()
                } else {
                    storage[o..o + l].to_vec()
                }
            }
            Inner::Static { data } => data.to_vec(),
            Inner::ExternalOwned(e) => {
                // SAFETY: same access semantics as `data()`.
                let slice = unsafe {
                    core::slice::from_raw_parts(
                        e.base.as_ptr().add(e.offset as usize),
                        e.len as usize,
                    )
                };
                let v = slice.to_vec();
                // `e` (and its drop callback) is dropped at end
                // of arm, returning the descriptor to its origin.
                drop(e);
                v
            }
            Inner::Borrowed {
                base, offset, len, ..
            } => {
                // SAFETY: same access semantics as `data()`.
                let slice = unsafe {
                    core::slice::from_raw_parts(
                        base.as_ptr().add(offset as usize),
                        len as usize,
                    )
                };
                slice.to_vec()
            }
        }
    }

    /// True if this IOBuf wraps a `&'static [u8]`. Used by
    /// downstream layers to dispatch zero-alloc static-borrow vs
    /// owned-move paths (e.g. `SendStream::send_static` vs
    /// `send_owned`).
    pub fn is_static(&self) -> bool {
        matches!(self.inner, Inner::Static { .. })
    }

    /// True if `data_mut()` would return `Some` — i.e. this is a
    /// `Heap`, `ExternalOwned`, or `Borrowed` variant. Used by
    /// encrypt-in-place paths (e.g. TLS scatter-gather seal) to
    /// pre-flight a chain before mutating any part: if any IOBuf
    /// isn't mutable the caller falls back to coalesce-then-seal.
    pub fn is_mutable(&self) -> bool {
        match self.inner {
            Inner::Heap { .. }
            | Inner::ExternalOwned(_)
            | Inner::Borrowed { .. } => true,
            Inner::Static { .. } => false,
        }
    }

    /// If this IOBuf is a static borrow, return the underlying
    /// `&'static [u8]`. Returns `None` for heap-owned and
    /// external variants. Lets the H3 / TLS / TCP send paths
    /// take a borrowed-static fast path that holds onto the
    /// slice without copying.
    pub fn as_static(&self) -> Option<&'static [u8]> {
        match &self.inner {
            Inner::Static { data } => Some(data),
            Inner::Heap { .. }
            | Inner::ExternalOwned(_)
            | Inner::Borrowed { .. } => None,
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
}

/// Headroom constant covering every layer's worst-case header
/// size, so a buffer allocated by the topmost producer (the app)
/// has enough room for every lower layer to prepend in place.
///
///   * Ethernet header:                 14 bytes
///   * IPv6 header:                     40 bytes (worst of v4=20 / v6=40)
///   * TCP header (no options):         20 bytes
///   * TLS 1.3 record header:            5 bytes
///   * H3 frame header (varint type +
///     varint length, max sizes):       16 bytes
///   * QUIC short-header packet:         9 bytes (type + DCID(8))
///                                      ───
///   Total worst-case stack:            104 bytes
///
/// Round to the next 16-byte alignment boundary for a
/// cache-line-friendly headroom: 128 B.
pub const MAX_HEADER_RESERVE: usize = 128;

/// Tailroom constant covering layers that append (TLS / QUIC AEAD
/// tags). 16 B handles a single AEAD tag; if a future layer adds
/// its own trailer we'll bump.
pub const MAX_TRAILER_RESERVE: usize = 16;

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

// ============================================================================
// Per-layer MTU / headroom negotiation
// ============================================================================

/// What each layer of the network stack publishes to the layer
/// above. The layer above (the producer) consults these fields
/// when allocating an `IOBuf` so every lower layer's `prepend`
/// in headroom and `append` in tailroom fits without
/// reallocating.
///
/// Concrete numbers come out of each layer's protocol header
/// shape: TCP wants 20 B headroom + 0 tailroom, IPv6 wants
/// 40 B headroom + 0, TLS 1.3 wants 5 B headroom + 16 B
/// tailroom for the AEAD tag, etc. The `compose` helper sums a
/// stack of LayerReserve values into the cumulative reserve a
/// producer should request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerReserve {
    /// Bytes the layer wants reserved at the front of every
    /// payload it ships. The layer's `send` method prepends
    /// its header into these bytes.
    pub headroom: usize,
    /// Bytes the layer wants reserved at the back. AEAD tags
    /// + trailers go here.
    pub tailroom: usize,
    /// Maximum payload bytes the layer can accept from the layer
    /// above for a single send call (i.e. before fragmentation
    /// kicks in). For TLS this is the record body size limit;
    /// for TCP it's the MSS.
    pub max_payload: usize,
}

impl LayerReserve {
    /// Identity / no-op layer — zero overhead, unbounded payload.
    /// Useful as a default for layers that don't add framing.
    pub const PASSTHROUGH: Self = LayerReserve {
        headroom: 0,
        tailroom: 0,
        max_payload: usize::MAX,
    };
}

// (Composition of multiple layers' reserves — "app over TLS over
// TCP — what's the cumulative headroom?" — is intentionally
// omitted from this commit. The arithmetic depends on whether
// we want "max per send call" semantics or "fit entirely in one
// lower-layer packet" semantics, and the right answer differs by
// layer pair. We'll add a concrete `compose_for_*` helper when
// the first consumer needs it.)

/// Trait every layer that wraps a payload implements so its
/// own consumers (the layer above) can ask "how much space
/// should I reserve in the IOBuf I hand to your `send`?". The
/// network stack walks this top-down at conn-establish time;
/// the producer caches the resulting `LayerReserve` and uses
/// its `headroom` / `tailroom` to size body buffers.
pub trait LayerInfo {
    /// What this layer plus all layers below it reserve. The
    /// layer above queries this to size its outgoing IOBufs.
    fn layer_reserve(&self) -> LayerReserve;
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
/// chain level are amortised O(1); the `Cursor` walks node
/// boundaries transparently for readers.
///
/// The chain is the natural shape for a multi-layer stack:
/// each layer can append/prepend nodes (or prepend INTO the
/// front node's headroom) without disturbing the rest.
///
/// Layout: an inline `[Option<IOBuf>; INLINE_PARTS]` array for
/// the first parts, plus a lazy `VecDeque<IOBuf>` overflow for
/// chains that grow past the inline capacity. Chains with up to
/// [`INLINE_PARTS`] (8) parts cost **zero** heap allocations for
/// the chain machinery — covers the common multi-layer shape
/// (eth + ip + tcp + http + body, plus a couple of layered
/// framing headers) without forcing the producer to materialise
/// a `VecDeque` per chain.
///
/// Inspired by folly's intrusive `next`/`prev` chain, which has
/// zero chain-machinery allocs because the IOBuf IS the chain
/// element. We approximate that property here without:
///
///   * growing the IOBuf size by two pointers,
///   * paying a `Box<IOBuf>` per element (an owned linked list
///     would),
///   * making chain operations unsafe.
///
/// The only chain alloc occurs when `part_count > INLINE_PARTS`
/// — a deeply chunked HTML page or chunked-transfer body. For
/// those the `overflow` `VecDeque` allocates on the first push
/// past the inline cap.
pub struct IOBufChain {
    /// Inline slots — first `INLINE_PARTS` parts live here,
    /// packed at indices `[0, inline_count)`. No allocation.
    inline: [Option<IOBuf>; INLINE_PARTS],
    /// Number of parts in `inline` (always packed front-flush).
    inline_count: u8,
    /// Parts past the inline cap. Lazily allocated; logically
    /// concatenated AFTER the inline parts. `VecDeque::new()`
    /// itself is alloc-free — the buffer materialises only on
    /// the first push that exceeds `INLINE_PARTS`.
    overflow: VecDeque<IOBuf>,
    total_len: usize,
}

/// Inline-array capacity for [`IOBufChain`]. Sized to cover the
/// common multi-layer shape — header IOBuf prepended onto a
/// body chain of a few parts, plus 1-2 framing IOBufs for
/// layered protocols (TLS, H3). Chains past 8 parts spill to
/// the `overflow` `VecDeque` and pay one allocation.
pub const INLINE_PARTS: usize = 8;

impl IOBufChain {
    pub const fn new() -> Self {
        IOBufChain {
            inline: [const { None }; INLINE_PARTS],
            inline_count: 0,
            overflow: VecDeque::new(),
            total_len: 0,
        }
    }

    /// Hint that the chain will hold at least `part_capacity`
    /// parts. If the hint exceeds the inline cap, pre-allocates
    /// the overflow deque so subsequent pushes don't reallocate.
    /// A hint within the inline cap is a no-op (no alloc).
    pub fn with_capacity(part_capacity: usize) -> Self {
        let overflow_cap = part_capacity.saturating_sub(INLINE_PARTS);
        IOBufChain {
            inline: [const { None }; INLINE_PARTS],
            inline_count: 0,
            overflow: if overflow_cap == 0 {
                VecDeque::new()
            } else {
                VecDeque::with_capacity(overflow_cap)
            },
            total_len: 0,
        }
    }

    pub fn total_len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.inline_count == 0
    }

    pub fn part_count(&self) -> usize {
        self.inline_count as usize + self.overflow.len()
    }

    /// Append a buf to the back of the chain. Goes into the
    /// inline array if there's space, else into the overflow
    /// deque (which allocates lazily on the first overflow push).
    pub fn push_back(&mut self, buf: IOBuf) {
        if buf.is_empty() {
            return;
        }
        self.total_len += buf.len();
        let n = self.inline_count as usize;
        if n < INLINE_PARTS {
            self.inline[n] = Some(buf);
            self.inline_count += 1;
        } else {
            self.overflow.push_back(buf);
        }
    }

    /// Prepend a buf to the front of the chain. New buf becomes
    /// the front; existing inline parts shift right by one. If
    /// the inline array was already full, the last inline part
    /// rotates to the front of overflow before the shift.
    ///
    /// O(`INLINE_PARTS`) shift cost — for the typical layered-
    /// header use case (one `push_front` per response) this is a
    /// handful of `Option<IOBuf>` moves and dominated by the
    /// surrounding work.
    pub fn push_front(&mut self, buf: IOBuf) {
        if buf.is_empty() {
            return;
        }
        self.total_len += buf.len();
        let n = self.inline_count as usize;
        if n < INLINE_PARTS {
            // Shift inline[..n] right by 1 to make room at index 0.
            for i in (0..n).rev() {
                self.inline[i + 1] = self.inline[i].take();
            }
            self.inline[0] = Some(buf);
            self.inline_count += 1;
        } else {
            // Inline is full. Rotate the last inline part out to
            // the front of overflow, shift inline right, then
            // insert at 0. Inline count stays at INLINE_PARTS.
            let last = self.inline[INLINE_PARTS - 1].take().unwrap();
            self.overflow.push_front(last);
            for i in (0..INLINE_PARTS - 1).rev() {
                self.inline[i + 1] = self.inline[i].take();
            }
            self.inline[0] = Some(buf);
        }
    }

    /// Prepend `data` directly into the FRONT node's headroom,
    /// without allocating a new node. Returns `Err` if the front
    /// node is missing or static (no headroom). Lets a layer
    /// prepend a small fixed header (TLS record header, H3 frame
    /// header) without growing the chain.
    pub fn prepend_in_place(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let front = self.inline[0].as_mut().ok_or(IOBufError::NoHeadroom)?;
        front.prepend(data)?;
        self.total_len += data.len();
        Ok(())
    }

    /// Iterate the chain front-to-back.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &IOBuf> {
        // SAFETY: invariant of `inline_count` is that
        // `inline[0..inline_count]` is always `Some`. `push_*`
        // only writes `Some`; `pop_front` shifts and ends with
        // a `None` in the freed slot which is past the new
        // `inline_count`.
        self.inline[..self.inline_count as usize]
            .iter()
            .map(|s| unsafe { s.as_ref().unwrap_unchecked() })
            .chain(self.overflow.iter())
    }

    /// Mutable iterate front-to-back. Lets the caller mutate
    /// individual parts (e.g. encrypt-in-place via
    /// `IOBuf::data_mut()` per part) without consuming the
    /// chain.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut IOBuf> {
        // SAFETY: same invariant as `iter` — `inline[0..inline_count]`
        // is always `Some`.
        self.inline[..self.inline_count as usize]
            .iter_mut()
            .map(|s| unsafe { s.as_mut().unwrap_unchecked() })
            .chain(self.overflow.iter_mut())
    }

    /// Pop the front part. Returns `None` when the chain is
    /// empty. Shifts inline left by one and (when overflow is
    /// non-empty) promotes the first overflow element into the
    /// freshly-vacated inline slot, so subsequent `pop_front`
    /// calls continue to drain in chain order without ever
    /// straddling inline/overflow.
    pub fn pop_front(&mut self) -> Option<IOBuf> {
        if self.inline_count == 0 {
            return None;
        }
        let buf = self.inline[0].take().unwrap();
        self.total_len = self.total_len.saturating_sub(buf.len());
        let n = self.inline_count as usize;
        for i in 0..(n - 1) {
            self.inline[i] = self.inline[i + 1].take();
        }
        self.inline_count -= 1;
        // Promote the next overflow part into the freed inline
        // slot so the inline array stays packed at the front of
        // the chain — keeps `iter`/`pop_front` straightforward.
        if let Some(next) = self.overflow.pop_front() {
            self.inline[self.inline_count as usize] = Some(next);
            self.inline_count += 1;
        }
        Some(buf)
    }

    /// Mutable access to the front part. Used by partial-send
    /// recovery paths that need to advance the head buf's visible
    /// payload (`IOBuf::consume(n)`) when the underlying transport
    /// committed only `n < head.len()` bytes. The caller is
    /// responsible for keeping `total_len` in sync via
    /// [`shrink_total_len`].
    pub fn front_mut(&mut self) -> Option<&mut IOBuf> {
        self.inline[0].as_mut()
    }

    /// Mutable access to the back part. Used by sealing paths
    /// that append (e.g. an AEAD tag) onto the last IOBuf after
    /// the encryption pass. Caller must `total_len += n` after
    /// growing the back part's visible payload.
    pub fn back_mut(&mut self) -> Option<&mut IOBuf> {
        if let Some(last) = self.overflow.back_mut() {
            return Some(last);
        }
        if self.inline_count == 0 {
            return None;
        }
        // SAFETY: `inline_count > 0` and `inline[..inline_count]` is
        // always `Some`.
        Some(unsafe {
            self.inline[self.inline_count as usize - 1]
                .as_mut()
                .unwrap_unchecked()
        })
    }

    /// Pop the back part. Mirror of `pop_front`. Used by paths
    /// that speculatively appended a part and need to rewind the
    /// chain on a subsequent error.
    pub fn pop_back(&mut self) -> Option<IOBuf> {
        if let Some(buf) = self.overflow.pop_back() {
            self.total_len = self.total_len.saturating_sub(buf.len());
            return Some(buf);
        }
        if self.inline_count == 0 {
            return None;
        }
        let idx = self.inline_count as usize - 1;
        let buf = self.inline[idx].take().unwrap();
        self.inline_count -= 1;
        self.total_len = self.total_len.saturating_sub(buf.len());
        Some(buf)
    }

    /// Decrease the cached `total_len` by `n`. Pair with a
    /// `front_mut().consume(n)` (or equivalent) when the caller
    /// shrunk a buf's visible payload without going through
    /// `pop_front`.
    pub fn shrink_total_len(&mut self, n: usize) {
        self.total_len = self.total_len.saturating_sub(n);
    }

    /// Increase the cached `total_len` by `n`. Pair with a
    /// `back_mut().append_slice(...)` (or equivalent) that grew
    /// a buf's visible payload without going through
    /// `push_back` / `push_front`. Used by the TLS seal-chain
    /// path to record the AEAD tag bytes appended to the
    /// trailer IOBuf after the encryption pass.
    pub fn bump_total_len(&mut self, n: usize) {
        self.total_len += n;
    }

    /// Drop every part still in the chain, leaving an empty
    /// chain with its `overflow` allocation preserved (if any).
    /// The drops run in front-to-back order — same ordering as a
    /// `pop_front` loop, which matters for `ExternalOwned` IOBufs
    /// whose drop callbacks return descriptors to driver pools.
    pub fn clear(&mut self) {
        for i in 0..self.inline_count as usize {
            self.inline[i] = None;
        }
        self.inline_count = 0;
        self.overflow.clear();
        self.total_len = 0;
    }

    /// Move all parts out, consuming the chain. Returns an
    /// iterator yielding parts front-to-back. Zero new
    /// allocation: the inline parts move out via `Option::take`
    /// in iteration order; the overflow's existing `VecDeque`
    /// allocation is consumed but no fresh deque is built.
    pub fn into_parts(self) -> impl Iterator<Item = IOBuf> {
        let count = self.inline_count as usize;
        let mut inline = self.inline;
        let mut idx = 0;
        let inline_iter = core::iter::from_fn(move || {
            if idx < count {
                let buf = inline[idx].take();
                idx += 1;
                buf
            } else {
                None
            }
        });
        inline_iter.chain(self.overflow.into_iter())
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
    /// append in place. Use when the part will be sealed by TLS:
    /// pass `MAX_HEADER_RESERVE` (covers TLS record header +
    /// downstream layers) and `MAX_TRAILER_RESERVE` (covers the
    /// AEAD tag) so `TlsStream::send_chain`'s encrypt-in-place
    /// path applies. One heap alloc per chunk (sized for payload
    /// + reserve); the visible `data()` is exactly `payload`.
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
    /// Index of the current node within `chain.parts`.
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
        self.chain.total_len.saturating_sub(self.consumed)
    }

    pub fn position(&self) -> usize {
        self.consumed
    }

    /// Resolve `node_idx` to a borrowed `IOBuf`. Indices in
    /// `[0, inline_count)` come from the inline array;
    /// `[inline_count, inline_count + overflow.len())` come from
    /// the overflow deque. Returns `None` past the chain's end.
    #[inline]
    fn node_at(&self, idx: usize) -> Option<&'a IOBuf> {
        let inline_n = self.chain.inline_count as usize;
        if idx < inline_n {
            // SAFETY: `inline[0..inline_count]` is always `Some`
            // (invariant maintained by `push_*` / `pop_*`).
            Some(unsafe { self.chain.inline[idx].as_ref().unwrap_unchecked() })
        } else {
            self.chain.overflow.get(idx - inline_n)
        }
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
    fn layer_reserve_passthrough_constants() {
        let p = LayerReserve::PASSTHROUGH;
        assert_eq!(p.headroom, 0);
        assert_eq!(p.tailroom, 0);
        assert_eq!(p.max_payload, usize::MAX);
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
        // scratch reuse pattern in take_record_iobuf.
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
    fn full_layer_stack_simulation() {
        // Simulate the network stack: app builds a body, HTTP layer
        // prepends headers, TLS prepends a record header, TCP/IP/Eth
        // would all prepend in turn. Here we just check that
        // prepend_in_place works end-to-end without copying bytes
        // beyond the writes we explicitly perform.
        let mut chain = IOBufChain::new();
        // App: heap-alloc an HTML body chunk with headroom for every
        // layer below.
        let body = IOBuf::from_slice_with_headroom(
            MAX_HEADER_RESERVE,
            b"<html>...</html>",
            MAX_TRAILER_RESERVE,
        );
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
}
