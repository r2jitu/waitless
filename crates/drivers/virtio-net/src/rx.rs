// RX path: per-queue NAPI-style polling, owned-IOBuf delivery
// with a repost-on-drop callback, RX-side IRQ arm + napi rearm,
// and the legacy "batch into a flat buffer" poll variant kept
// for callers that want a copying drain (`poll_batch`).


use core::ptr;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use iobuf::{Chain, IOBufDropFn, OwnedIOBuf};
use kernel_bare::mm::{phys_to_virt, virt_to_phys};

use crate::diag::{RX_BUF_REPOST_COUNT, RX_BYTES_PER_QP, RX_COUNTS};
use crate::irq::IRQ_PENDING;
use crate::tx::{TX_LOCK, tx_drain_qp};
use crate::{
    BUFFER_SIZE, DIAG_QP_CAP, Transport, VIRTIO_NET_HDR_SIZE, ndev, qps, rx_q,
};

/// Maximum frames per batch poll.
pub(crate) const BATCH_SIZE: usize = 32;

/// A batch of received frames. Frames are stored contiguously with
/// a length prefix: [len: u16][frame data][len: u16][frame data]...
pub(crate) struct RxBatch {
    pub data: [u8; BATCH_SIZE * 1600], // worst case: 32 × 1514-byte frames
    pub len: usize,                    // bytes used in data
    pub count: usize,                  // number of frames
}

impl RxBatch {
    pub const fn new() -> Self {
        RxBatch {
            data: [0; BATCH_SIZE * 1600],
            len: 0,
            count: 0,
        }
    }

    /// Iterate over frames in the batch.
    pub fn iter(&self) -> RxBatchIter<'_> {
        RxBatchIter {
            data: &self.data[..self.len],
            pos: 0,
        }
    }
}

pub(crate) struct RxBatchIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for RxBatchIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.pos + 2 > self.data.len() {
            return None;
        }
        let len = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]) as usize;
        self.pos += 2;
        if self.pos + len > self.data.len() {
            return None;
        }
        let frame = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some(frame)
    }
}

/// Poll VirtIO RX queue pair 0 and collect frames into a batch buffer.
pub(crate) fn poll_batch(batch: &mut RxBatch) {
    poll_batch_qp(0, batch);
}

/// Poll a specific queue pair's RX queue into a batch buffer.
pub(crate) fn poll_batch_qp(qp: usize, batch: &mut RxBatch) {
    batch.len = 0;
    batch.count = 0;

    unsafe {
        if let Transport::None = (*ndev()).transport {
            return;
        }
    }

    // Drain TX completions. Tier 1 owns qp per core (no lock needed),
    // Tier 2 has the single shared queue and must serialise.
    let nqp = unsafe { (*ndev()).num_queue_pairs };
    if kernel_bare::percpu::num_cores() <= 1 || (nqp as usize) > 1 {
        tx_drain_qp(qp);
    } else if let Some(_g) = TX_LOCK.try_lock() {
        tx_drain_qp(qp);
    }

    unsafe {
        while batch.count < BATCH_SIZE {
            let (used_id, used_len) = match (*rx_q(qp)).used() {
                Some(v) => v,
                None => break,
            };
            let desc = (*rx_q(qp)).desc(used_id);
            let buf = phys_to_virt(desc.addr);

            if used_len > VIRTIO_NET_HDR_SIZE as u32 {
                let frame_len = (used_len - VIRTIO_NET_HDR_SIZE as u32) as usize;
                if batch.len + 2 + frame_len <= batch.data.len() {
                    let len_bytes = (frame_len as u16).to_le_bytes();
                    batch.data[batch.len] = len_bytes[0];
                    batch.data[batch.len + 1] = len_bytes[1];
                    let frame_data = buf.add(VIRTIO_NET_HDR_SIZE);
                    core::ptr::copy_nonoverlapping(
                        frame_data,
                        batch.data.as_mut_ptr().add(batch.len + 2),
                        frame_len,
                    );
                    batch.len += 2 + frame_len;
                    batch.count += 1;
                }
            }

            // Re-arm RX buffer
            let buf_phys = virt_to_phys(buf);
            (*rx_q(qp)).add_buf(buf_phys, BUFFER_SIZE, 0, 1);
        }

        if batch.count > 0 {
            (*rx_q(0)).kick();
        }
    }
}

pub(crate) fn arm_rx_interrupts() {
    unsafe {
        (*rx_q(0)).enable_interrupts();
    }
}

pub(crate) fn has_pending_rx() -> bool {
    unsafe { (*rx_q(0)).has_used() }
}

/// NAPI re-arm for the event loop: enable RX notifications on the
/// queue pair that `core_id` owns, then re-check for work that arrived
/// in the arm window. Returns true iff the caller should skip HLT and
/// loop back to poll.
///
/// Tier 1 multi-queue: each core owns `rx_queues[core_id]`.
/// Tier 2 / single-queue: every core arms queue 0, and only the core
/// currently acting as distributor (whichever wins the RX_LOCK in the
/// net crate) actually reads from it.
pub(crate) fn rearm_rx_napi(core_id: u32) -> bool {
    unsafe {
        let nqp = (*ndev()).num_queue_pairs;
        let qp = if nqp > 1 && (core_id as u16) < nqp {
            core_id as usize
        } else {
            0
        };
        (*rx_q(qp)).enable_interrupts();
        (*rx_q(qp)).has_used()
    }
}

// ============================================================================
// Owned-IOBuf delivery
// ============================================================================
//
// `poll_qp` walks the used ring and delivers each frame as an
// owned one-part `IOBufChain` wrapping the descriptor buffer
// directly (zero copy). The buffer is re-armed by `virtio_rx_repost`
// — the IOBuf's drop callback — when the chain drops. With item B's
// inline-on-the-polling-core drops that is the same instant the old
// `&[u8]` path re-armed; the owned shape additionally lets the net
// stack retain the chain past the callback (item C).
//
// Kicks are batched within one poll cycle. Each re-arm calls
// `add_buf` and sets `rx_dirty`; the end-of-poll block kicks once
// if any re-arm happened. This caps kicks at one per poll cycle.

/// Re-post `buf_phys` to qp `qp`'s avail ring. Sets `rx_dirty` so
/// the end-of-poll-cycle block kicks the device once for the batch.
///
/// Called from `virtio_rx_repost` (a delivered RX IOBuf's drop
/// callback) and inline from `poll_qp` for runt frames. The
/// `rx_lock` spinlock makes `add_buf`'s single-writer invariant
/// hold even when a chain drops on a core other than the polling
/// core (item C) — it is not lock-free, but a spinlock lock/unlock
/// never panics, so the drop callback stays panic-safe; the
/// contended window is a few avail-ring stores.
#[inline]
unsafe fn rx_repost(qp: usize, buf_phys: u64) {
    let _g = unsafe { (*qps(qp)).rx_lock.lock() };
    let _ = unsafe { (*rx_q(qp)).add_buf(buf_phys, BUFFER_SIZE, 0, 1) };
    unsafe {
        (*qps(qp))
            .rx_dirty
            .store(true, Ordering::Release);
    }
}

/// Drop callback for a delivered virtio-net RX `IOBuf` — returns
/// the descriptor buffer to qp `qp`'s avail ring. Installed by
/// [`poll_qp`] via [`OwnedIOBuf::wrap_owned`]; runs from `IOBuf::drop`,
/// possibly on a core other than the one that received the frame.
///
/// `ctx` is the `qp` index packed as a pointer; `base` is the RX
/// buffer start `wrap_owned` was given. Zeroes the virtio-net
/// header (the device expects a clean slate) and re-adds the
/// buffer.
///
/// Panic-safe: an out-of-range `qp` leaks the buffer rather than
/// panicking — a panic in a `#![no_std]` `Drop` is poison. Not
/// reachable under correct use (`poll_qp` only packs a valid qp);
/// it would arise only from a corrupted `ctx`.
unsafe fn virtio_rx_repost(base: NonNull<u8>, _capacity: u32, ctx: *mut ()) {
    let qp = ctx as usize;
    let nqp = unsafe { (*ndev()).negotiated_queue_pairs as usize };
    if qp >= nqp {
        return; // impossible under correct use — leak, never panic
    }
    let buf = base.as_ptr();
    // SAFETY: `buf` is the RX buffer start; the virtio-net header
    // occupies its first VIRTIO_NET_HDR_SIZE bytes.
    unsafe {
        ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
    }
    // SAFETY: `qp < negotiated_queue_pairs`, so `rx_q(qp)` /
    // `qps(qp)` are in bounds; `add_buf` is serialised by the
    // per-qp `rx_lock` `rx_repost` takes.
    unsafe {
        rx_repost(qp, virt_to_phys(buf));
    }
    if qp < DIAG_QP_CAP {
        RX_BUF_REPOST_COUNT[qp].fetch_add(1, Ordering::Relaxed);
    }
}

/// Harvest one completed RX descriptor from qp `qp`'s used ring,
/// **under `rx_lock`**.
///
/// `Virtqueue::used()` mutates the shared descriptor free-list
/// (`free_head` / `num_free` / `desc.next`) — the very state
/// `add_buf` mutates. Item C lets a delivered chain drop on a core
/// other than the polling one, so `virtio_rx_repost` → `rx_repost`
/// → `add_buf` can run *concurrently* with this RX poll. `add_buf`
/// is `rx_lock`-guarded; `used()` must be too, or the free-list
/// corrupts and RX collapses (the Tier-2 multi-core regression).
///
/// The `desc(used_id)` read is inside the lock for a second reason:
/// `used()` just returned `used_id`'s descriptor to the free-list,
/// so a concurrent `add_buf` could re-grab it and overwrite `.addr`.
/// Reading the buffer address before unlocking pins it.
///
/// Encapsulating "lock → used → desc-read" here means an unlocked
/// `used()` is not a reachable pattern in the RX path. Returns
/// `(used_len, buf_va)` — the descriptor id is not needed
/// downstream (`virtio_rx_repost` re-arms by buffer address). The
/// lock is released before the caller touches the frame: the
/// per-frame callback can drop a chain → `rx_repost` → `rx_lock`,
/// and the spinlock is not reentrant.
///
/// SAFETY: `qp < negotiated_queue_pairs` so `qps(qp)` / `rx_q(qp)`
/// are in bounds; called only from `poll_qp`, which the dispatcher
/// bounds.
#[inline]
unsafe fn rx_used_locked(qp: usize) -> Option<(u32, *mut u8)> {
    let _g = unsafe { (*qps(qp)).rx_lock.lock() };
    let (used_id, used_len) = unsafe { (*rx_q(qp)).used() }?;
    let buf = unsafe { phys_to_virt((*rx_q(qp)).desc(used_id).addr) };
    Some((used_len, buf))
}

/// Per-queue RX poll. Drains the used ring, delivering each frame
/// as an owned one-part [`IOBufChain`] wrapping the descriptor
/// buffer; `virtio_rx_repost` re-arms the descriptor when the
/// chain drops.
pub(crate) fn poll_qp(qp: usize, callback: fn(Chain<OwnedIOBuf>)) -> usize {
    unsafe {
        if let Transport::None = (*ndev()).transport {
            return 0;
        }
    }

    if IRQ_PENDING.swap(false, Ordering::Acquire) {
        // used_idx was cached by irq_handler.
    }

    let nqp = unsafe { (*ndev()).num_queue_pairs };
    if kernel_bare::percpu::num_cores() <= 1 || (nqp as usize) > 1 {
        tx_drain_qp(qp);
    } else if let Some(_g) = TX_LOCK.try_lock() {
        tx_drain_qp(qp);
    }

    let mut count: usize = 0;
    unsafe {
        // `rx_used_locked` harvests each descriptor under `rx_lock`
        // (and reads its buffer address there) so a cross-core
        // `virtio_rx_repost` → `add_buf` cannot corrupt the shared
        // free-list mid-`used()`. The frame is then processed with
        // the lock released — the callback may itself repost.
        while let Some((used_len, buf)) = rx_used_locked(qp) {
            if used_len > VIRTIO_NET_HDR_SIZE as u32 {
                let frame_len = (used_len - VIRTIO_NET_HDR_SIZE as u32) as usize;
                if qp < DIAG_QP_CAP {
                    RX_BYTES_PER_QP[qp].fetch_add(frame_len as u64, Ordering::Relaxed);
                }
                // Wrap the descriptor buffer as an owned one-part
                // IOBufChain — visible payload is the frame past
                // the virtio-net header. `virtio_rx_repost` zeroes
                // the header and re-adds the buffer to the avail
                // ring when the chain's IOBuf drops, so the
                // explicit inline re-arm the `&[u8]` path used now
                // lives entirely in that drop callback.
                //
                // SAFETY: `buf` is a live RX buffer (non-null,
                // BUFFER_SIZE bytes); `frame_len = used_len - HDR`
                // and `used_len <= BUFFER_SIZE`, so `HDR + frame_len
                // <= BUFFER_SIZE` (`offset + len <= capacity`).
                // `virtio_rx_repost` is sound to invoke once at
                // drop and is panic-safe; `qp` packed in `ctx`
                // survives the cross-core move `ExternalOwned`
                // allows.
                let owned = OwnedIOBuf::wrap_owned(
                    NonNull::new_unchecked(buf),
                    BUFFER_SIZE,
                    VIRTIO_NET_HDR_SIZE as u32,
                    frame_len as u32,
                    virtio_rx_repost as IOBufDropFn,
                    qp as *mut (),
                );
                callback(Chain::from(owned));
            } else {
                // Runt frame — no payload past the virtio-net
                // header, so there's no IOBuf to deliver. Re-arm
                // the descriptor inline, mirroring the wrapped
                // path's `virtio_rx_repost`.
                ptr::write_bytes(buf, 0, VIRTIO_NET_HDR_SIZE);
                rx_repost(qp, virt_to_phys(buf));
            }
            count += 1;
        }

        // Kick once at end of cycle if we re-armed anything. The
        // dirty flag is set true by every `rx_repost`; we clear +
        // kick here. Bounded one kick per poll regardless of batch
        // size.
        {
            let _g = (*qps(qp)).rx_lock.lock();
            let was_dirty = (*qps(qp))
                .rx_dirty
                .swap(false, Ordering::AcqRel);
            if was_dirty {
                (*rx_q(qp)).kick();
            }
        }
        if count > 0 && qp < DIAG_QP_CAP {
            RX_COUNTS[qp].fetch_add(count as u64, Ordering::Relaxed);
        }
    }
    count
}

/// All-queues fan-out wrapper.
pub(crate) fn poll(callback: fn(Chain<OwnedIOBuf>)) -> usize {
    let n = unsafe { (*ndev()).negotiated_queue_pairs as usize }.max(1);
    let mut total = 0;
    for qp in 0..n {
        total += poll_qp(qp, callback);
    }
    total
}
