// crates/util/iobuf — IOBuf primitive for the network stack.
//
// Inspired by folly::IOBuf: a chain of byte segments with reserved
// space at each end ("headroom" / "tailroom") so layers below can
// prepend / append their headers without re-allocating or copying
// the existing payload. Callers walk a chain via a `Cursor` that
// hops node boundaries transparently.
//
// What this buys us in the unikernel stack:
//
//   * App-side: a body is a chain of static literals (zero-copy)
//     and dynamically-rendered owned chunks.
//   * HTTP/1.1: the response status line + headers prepend onto the
//     body chain via `prepend_in_place`, reusing reserved headroom.
//   * TLS: prepends the 5-byte record header and appends the 16-byte
//     AEAD tag in-place.
//   * QUIC: prepends short-header byte + packet number, encrypts in
//     place; the rest of the chain follows the same prepend pattern.
//   * NIC RX: the driver wraps its DMA buffer as an IOBuf with a
//     drop callback that reposts the buffer — zero-copy receive.
//   * NIC TX: a final cursor pass copies bytes straight into the
//     hardware TX descriptor — one memcpy total, no intermediate Vec.
//
// ── The borrowed / owned type split ─────────────────────────────
//
// An IOBuf has two ownership models, and they have different
// thread-safety. Rather than one `!Send` type guarded by discipline,
// the crate splits them — see docs/iobuf-type-model.md:
//
//   * Each storage shape is its own struct in `storage.rs`
//     (`HeapStorage`, `ExternalOwned`, `SharedRegion`, `BorrowedView`),
//     carrying bytes only — the visible `(offset, len)` window lives
//     on the outer type so one storage can feed many views (Arc
//     clones).
//   * `OwnedIOBuf` (in `owned.rs`) is the owning, `Send`-by-derivation
//     tier: an outer struct with `(offset, len)` and a four-variant
//     `OwnedStorage` enum (`Heap`, `External`, `Shared`, `Static`).
//     The cross-core RX path is *typed* `OwnedIOBuf` / `Chain<OwnedIOBuf>`,
//     so a borrowed buffer physically cannot reach it — a compile
//     error, not a human-maintained invariant.
//   * `IOBuf` (in `iobuf.rs`) is a thin two-variant wrapper:
//     `Owned(OwnedIOBuf)` for any owning shape, plus `Borrowed`
//     for non-owning views (the sole `!Send` source). All methods
//     forward to `OwnedIOBuf` in the owned case.
//   * `IOBufRead` is the read surface (`data` / `len` / `headroom` /
//     `tailroom`) shared by both and by `Chain<B>`.
//   * Widening is one-way: `From<OwnedIOBuf> for IOBuf` (infallible).
//     Nothing narrows `IOBuf -> OwnedIOBuf`.
//
// `no_std` and dep-less so it can be pulled into the kernel proper
// (driver layers) without dragging the runtime in.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

// Fixed-size slab pool for IOBuf RX recycling. Self-contained
// lock-free machinery, kept in its own module.
mod pool;
pub use pool::IOBufPool;

// The per-variant storage structs + the debug-mode borrow tracker.
// `OwnedIOBuf` carries an enum over these (Heap/External/Shared/
// Static); `IOBuf::Borrowed` carries a `BorrowedView`.
mod storage;
pub use storage::{BorrowedView, ExternalOwned, HeapStorage, IOBufDropFn, SharedRegion};

// `Chain<B>` — a chain of `B: IOBufRead` segments — plus `Cursor`.
mod chain;
pub use chain::{Chain, Cursor, IOBufChain};

// `IOBuf` — the `!Send` two-tier wrapper (`Owned(OwnedIOBuf)` +
// `Borrowed`) plus its `From<&'static …>` / `From<Vec<u8>>` /
// `From<String>` ergonomic conversions.
mod iobuf;
pub use iobuf::IOBuf;

// `OwnedIOBuf` — the `Send`-by-derivation flat enum over the two
// owning variants. Carries `From<OwnedIOBuf> for IOBuf` widening.
mod owned;
pub use owned::OwnedIOBuf;

// ============================================================================
// IOBufRead — the shared read surface.
// ============================================================================

/// The **read** surface every IOBuf-shaped buffer exposes: the
/// visible payload, its length, and the reserved head/tail room.
///
/// Implemented by `IOBuf` (`!Send`) and `OwnedIOBuf` (`Send`). It is
/// the bound a `Chain<B>` is generic over — `fn consume<B: IOBufRead>(Chain<B>)`
/// accepts both `Chain<IOBuf>` (TX) and `Chain<OwnedIOBuf>` (cross-core RX).
///
/// Deliberately **read-only**: mutating operations (`prepend`,
/// `append`, partial-send `consume`) are *not* here. Cross-core RX
/// consumers happen to be read-only, so `IOBufRead` suffices for the
/// generic chain; TX-side mutation stays concrete-typed on `IOBuf`.
pub trait IOBufRead {
    /// Visible payload bytes.
    fn data(&self) -> &[u8];
    /// Visible payload length in bytes (`== data().len()`).
    fn len(&self) -> usize;
    /// Bytes reserved before the payload — lower layers (TLS, TCP,
    /// IP, Eth) prepend their headers into this space.
    fn headroom(&self) -> usize;
    /// Bytes reserved after the payload — for AEAD tags, trailers.
    fn tailroom(&self) -> usize;
    /// True when the visible payload is empty.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Trivial impl for a `&[u8]` slice — lets `Chain<&'a [u8]>` (and
/// any other read-only chain consumer) accept raw slices alongside
/// `IOBuf` / `OwnedIOBuf`. Headroom / tailroom are 0 (no reserved
/// frame around a borrowed slice). Saves an `unsafe IOBuf::borrow`
/// mint at sites that don't mix borrowed and owned parts —
/// `TcpStream::send_bytes`, TLS send-scratch — letting the lifetime
/// flow through the type system instead.
impl IOBufRead for &[u8] {
    #[inline]
    fn data(&self) -> &[u8] {
        self
    }
    #[inline]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
    #[inline]
    fn headroom(&self) -> usize {
        0
    }
    #[inline]
    fn tailroom(&self) -> usize {
        0
    }
}

// ============================================================================
// IOBufError
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IOBufError {
    NoHeadroom,
    NoTailroom,
    OutOfBounds,
    Immutable,
    /// `clone_shared` was called on a buffer that hadn't been
    /// promoted to `Shared` first. Refcounted clones are explicit
    /// by design — the exclusive-heap TX hot path stays atomic-free.
    NotShared,
}

// ============================================================================
// IOBufWriter — `core::fmt::Write` adapter for IOBuf.
// ============================================================================

/// `core::fmt::Write` adapter for [`IOBuf`]. Appends formatted bytes
/// into the buffer's tailroom; if tailroom runs out mid-render the
/// writer silently truncates (see `overflowed`).
pub struct IOBufWriter<'a> {
    buf: &'a mut IOBuf,
    /// Set when an append inside `write_str` failed (tailroom
    /// exhausted). `core::fmt::Write`'s `Result` doesn't carry a
    /// buffer-out-of-space signal, so callers query this afterward.
    overflowed: bool,
}

impl<'a> IOBufWriter<'a> {
    /// Wrap an `IOBuf` as a `core::fmt::Write`-able sink. Called by
    /// [`IOBuf::writer`]; not part of the public surface, but
    /// `pub(crate)` so the sibling `iobuf` module can construct one
    /// without exposing the private fields.
    pub(crate) fn new(buf: &'a mut IOBuf) -> Self {
        Self {
            buf,
            overflowed: false,
        }
    }

    /// True if any append during this writer's lifetime hit a
    /// tailroom exhaustion. The IOBuf should be treated as truncated.
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
                Err(core::fmt::Error)
            }
        }
    }
}

// ============================================================================
// Tests — cross-type / cross-module integration. Per-type tests
// (IOBuf-only, OwnedIOBuf-only) live in their respective modules.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// `&[u8]` implements `IOBufRead`, so `Chain<&'a [u8]>` works as
    /// a read-only chain holding raw slices. Lifetime flows through
    /// the type system — the chain borrows for `'a`, no `unsafe
    /// IOBuf::borrow` needed.
    #[test]
    fn chain_of_byte_slices_round_trips() {
        let a = b"hello".as_slice();
        let b = b" ".as_slice();
        let c = b"world".as_slice();
        let mut chain: Chain<&[u8]> = Chain::new();
        chain.push_back(a);
        chain.push_back(b);
        chain.push_back(c);
        assert_eq!(chain.total_len(), 11);
        assert_eq!(chain.part_count(), 3);
        let mut out = [0u8; 32];
        let n = chain.cursor().read(&mut out);
        assert_eq!(&out[..n], b"hello world");
    }

    /// Mock-NIC RX-delivery tests for the contract the `NicOps` poll
    /// callback depends on: a driver hands up a received frame as an
    /// **owned** `IOBufChain` whose `ExternalOwned` `IOBuf`, on drop,
    /// reposts the backing buffer via its drop callback — and that
    /// drop may run on a core other than the one that received the
    /// frame.
    ///
    /// The real drivers' drop callbacks touch `target_os = "none"`
    /// hardware state and can't run host-native; this mock
    /// reproduces the *shape* against the same `wrap_owned` /
    /// `IOBufChain` primitives, exercising the drop callback from a
    /// separate thread.
    mod mock_nic_rx {
        use crate::{Chain, IOBufDropFn, OwnedIOBuf};
        use core::ptr::NonNull;
        use std::boxed::Box;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        use std::thread;

        /// Stand-in for a NIC's RX ring: a fixed buffer region plus
        /// the repost counter every real driver bumps, and a record
        /// of the `(base, capacity)` the drop callback was handed.
        struct MockNic {
            region: Box<[u8]>,
            repost_count: AtomicU64,
            last_base: AtomicUsize,
            last_capacity: AtomicUsize,
        }

        /// Drop callback installed on every mock RX `IOBuf`. Mirrors
        /// the real drivers' repost callbacks; panic-safe.
        ///
        /// SAFETY: `ctx` is an `Arc::<MockNic>::into_raw` pointer
        /// installed by `mock_poll_qp`, reclaimed exactly once here.
        unsafe fn mock_repost(base: NonNull<u8>, capacity: u32, ctx: *mut ()) {
            let nic: Arc<MockNic> = unsafe { Arc::from_raw(ctx as *const MockNic) };
            nic.last_base
                .store(base.as_ptr() as usize, Ordering::Relaxed);
            nic.last_capacity
                .store(capacity as usize, Ordering::Relaxed);
            nic.repost_count.fetch_add(1, Ordering::Relaxed);
        }

        /// Simulate a driver's `poll_qp`: wrap the mock device buffer
        /// as a one-part `Chain<OwnedIOBuf>` — the exact shape a real
        /// driver's RX poll now produces — and hand it to `callback`.
        fn mock_poll_qp(
            nic: &Arc<MockNic>,
            frame_len: usize,
            callback: impl FnOnce(Chain<OwnedIOBuf>),
        ) {
            let base = NonNull::new(nic.region.as_ptr() as *mut u8).unwrap();
            let capacity = nic.region.len() as u32;
            let ctx = Arc::into_raw(Arc::clone(nic)) as *mut ();
            // SAFETY: `region` outlives the IOBuf (kept alive by the
            // parked Arc ref); `0 + frame_len <= capacity`;
            // `mock_repost` is sound to invoke once at drop.
            let owned = unsafe {
                OwnedIOBuf::wrap_owned(
                    base,
                    capacity,
                    0,
                    frame_len as u32,
                    mock_repost as IOBufDropFn,
                    ctx,
                )
            };
            callback(Chain::from(owned));
        }

        #[test]
        fn rx_chain_drop_callback_reposts_cross_thread() {
            let nic = Arc::new(MockNic {
                region: std::vec![0u8; 2048].into_boxed_slice(),
                repost_count: AtomicU64::new(0),
                last_base: AtomicUsize::new(0),
                last_capacity: AtomicUsize::new(0),
            });
            let region_base = nic.region.as_ptr() as usize;

            // A `Chain<OwnedIOBuf>` is `Send` *by derivation* — it
            // crosses the thread boundary with no `unsafe impl Send`
            // wrapper, the very thing the type-model split removes
            // from the cross-core RX path.
            let mut captured: Option<Chain<OwnedIOBuf>> = None;
            mock_poll_qp(&nic, 1400, |chain| {
                assert_eq!(
                    chain.part_count(),
                    1,
                    "single-buffer frame is a 1-part chain"
                );
                assert_eq!(chain.total_len(), 1400);
                captured = Some(chain);
            });
            assert_eq!(nic.repost_count.load(Ordering::Relaxed), 0);

            let chain = captured.take().unwrap();
            let worker = thread::spawn(move || {
                drop(chain); // fires `mock_repost` on this thread
            });
            worker.join().unwrap();

            assert_eq!(nic.repost_count.load(Ordering::Relaxed), 1);
            assert_eq!(nic.last_base.load(Ordering::Relaxed), region_base);
            assert_eq!(nic.last_capacity.load(Ordering::Relaxed), 2048);
        }

        #[test]
        fn rx_chain_walk_then_repost_same_thread() {
            let nic = Arc::new(MockNic {
                region: std::vec![7u8; 2048].into_boxed_slice(),
                repost_count: AtomicU64::new(0),
                last_base: AtomicUsize::new(0),
                last_capacity: AtomicUsize::new(0),
            });
            mock_poll_qp(&nic, 64, |chain| {
                let walked: usize = chain.iter().map(|p| p.data().len()).sum();
                assert_eq!(walked, 64);
            });
            assert_eq!(nic.repost_count.load(Ordering::Relaxed), 1);
            assert_eq!(nic.last_capacity.load(Ordering::Relaxed), 2048);
        }
    }

    #[test]
    fn iobuf_writer_renders_into_tailroom() {
        use core::fmt::Write as _;
        let mut buf = IOBuf::new_with_reserved(8, 0, 64);
        assert_eq!(buf.len(), 0);
        write!(buf.writer(), "hello {}", 42).unwrap();
        assert_eq!(buf.data(), b"hello 42");
        buf.prepend(b"REC1").unwrap();
        assert_eq!(buf.data(), b"REC1hello 42");
    }

    #[test]
    fn iobuf_writer_signals_overflow() {
        use core::fmt::Write as _;
        let mut buf = IOBuf::new_with_reserved(0, 0, 4);
        let mut w = buf.writer();
        let _ = write!(w, "ab");
        let r = write!(w, "cdefgh");
        assert!(r.is_err());
        assert!(w.overflowed());
    }
}
