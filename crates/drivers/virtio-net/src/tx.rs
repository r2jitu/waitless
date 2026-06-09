// TX path: per-worker direct-fill pools, virtq submission, TX
// completion drain, slice-shaped convenience send, deferred-kick
// flush helpers, and the small/big TSO pool acquire path.

use core::sync::atomic::{Ordering, compiler_fence};

use kernel_bare::mm::virt_to_phys;
use tx_pool::{POOL_ID_BIG, POOL_ID_SMALL, TxStallBreaker, claim_first_free, decode_token, encode_token};

use crate::diag::{
    TX_BIG_ACQUIRES, TX_BIG_FULL_RETURNS, TX_BYTES_PER_QP, TX_PACKETS_PER_QP, TX_SMALL_ACQUIRES,
    TX_SMALL_FULL_SPINS, TX_SMALL_SCAN_ITERS,
};
use crate::{
    DIAG_QP_CAP, MAX_ETH_FRAME_BIG, MAX_ETH_FRAME_SMALL, TX_POOL_BIG_SIZE, TX_POOL_SMALL_SIZE,
    Transport, TxBufBig, TxBufSmall, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_NONE,
    VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_SIZE, VirtioNetHeader, ndev, tx_q, wpool, worker_qp,
};

/// True when multiple workers feed the same qp — `submit_tx` must
/// take TX_LOCK around the virtq enqueue, and `tx_drain_qp` must
/// take it around the used-ring drain.
#[inline]
pub(crate) fn qp_needs_lock() -> bool {
    let nqp = unsafe { (*ndev()).num_queue_pairs as usize };
    let nw = unsafe { (*ndev()).num_workers };
    nqp == 1 && nw > 1
}

/// TX lock: protects the VirtIO TX queue. Any core can acquire to
/// flush or send. Wraps `()` because the underlying state lives in
/// `(*tx_q(0))` and is mutable through the existing
/// raw-pointer accessors; this lock just provides mutual exclusion.
pub(crate) static TX_LOCK: sync::Spinlock<()> = sync::Spinlock::new(());

/// TX-ring stall circuit breaker (see [`acquire_tx_buf`]) — the shared
/// progress-aware [`TxStallBreaker`] (policy, budgets, and the measured
/// rationale live in `tx_pool::stall`). Progress = the device-written
/// TX `used->idx`, which is exactly what froze in the Apple-HVF h3
/// `/stream` wedge (see reference_hvf_h3_stream_wedge) — so the wedge
/// still trips it — while a saturated-but-draining ring advances it and
/// spins losslessly. One shared cell rather than per-qp: a real stall
/// only ever arises on the single contended/coherence-starved ring, so
/// cross-worker coupling under healthy load (where it's never armed) is
/// a non-issue.
static TX_STALL: TxStallBreaker = TxStallBreaker::new();

// ---- TX drain ---------------------------------------------------------------

/// Drain completed TX descriptors from `qp`'s used ring and mark
/// the corresponding pool slots free. The descriptor's `addr` is
/// the slot's physical address; we identify (worker, pool, slot)
/// via address-range lookup across worker pools.
///
/// On Tier 1 (per-core qp) `qp == worker`, and the descriptors
/// in qp X's used ring all came from worker X's pool — only one
/// worker's pool needs scanning. On Tier 2 (shared qp 0)
/// completions can belong to any worker's pool, so we scan all
/// of them. Cross-worker `_used` writes are safe because
/// `small_used` / `big_used` are `AtomicBool`.
pub(crate) fn tx_drain_qp(qp: usize) {
    let nw = unsafe { (*ndev()).num_workers };
    // Cache (phys range, ptr) per worker pool for fast lookup.
    // 8 workers max in current configurations; if it grows past
    // that, consider sorting by phys address for binary search.
    let small_size = core::mem::size_of::<TxBufSmall>() as u64;
    let big_size = core::mem::size_of::<TxBufBig>() as u64;

    unsafe {
        while let Some((used_id, _used_len)) = (*tx_q(qp)).used() {
            let d = (*tx_q(qp)).desc(used_id);
            let addr = d.addr;
            // Find which worker pool this address falls into. On
            // Tier 1 only worker `qp` will match; on Tier 2 we
            // walk all of them.
            let mut hit = false;
            for w in 0..nw {
                let pool = wpool(w);
                let small_phys = virt_to_phys((*pool).small.as_ptr() as *const u8);
                let small_end = small_phys + (TX_POOL_SMALL_SIZE as u64) * small_size;
                if addr >= small_phys && addr < small_end {
                    let slot = ((addr - small_phys) / small_size) as usize;
                    if slot < TX_POOL_SMALL_SIZE {
                        (*pool).small_used[slot].store(false, Ordering::Release);
                    }
                    hit = true;
                    break;
                }
                let big_ptr = (*pool).big;
                if !big_ptr.is_null() {
                    let big_phys = virt_to_phys(big_ptr as *const u8);
                    let big_end = big_phys + (TX_POOL_BIG_SIZE as u64) * big_size;
                    if addr >= big_phys && addr < big_end {
                        let slot = ((addr - big_phys) / big_size) as usize;
                        if slot < TX_POOL_BIG_SIZE {
                            (*pool).big_used[slot].store(false, Ordering::Release);
                        }
                        hit = true;
                        break;
                    }
                }
            }
            // No match: address didn't come from any pool. Stale
            // / duplicate completion — ignore.
            let _ = hit;
        }
    }
}

// ---- Slice-shaped send convenience ------------------------------------------

/// Slice-shaped send convenience wrapper. Acquires a TX-pool slot
/// from the caller's worker pool, copies `data` into it, and
/// submits via the unified `submit_tx` path. Used by ARP/NDP/etc.
/// callers that don't fill in place.
fn send_slice(data: &[u8], csum: nic_api::CsumOffload) {
    if data.is_empty() {
        return;
    }
    unsafe {
        if let Transport::None = (*ndev()).transport {
            return;
        }
    }
    let frame_len = data.len().min(MAX_ETH_FRAME_SMALL);
    let mut handle = match acquire_tx_buf() {
        Some(h) => h,
        None => return, // no driver
    };
    handle.data_mut()[..frame_len].copy_from_slice(&data[..frame_len]);
    // Same `csum` descriptor a `submit_tx` caller would pass — the
    // slice path is just a memcpy in front of the same submit.
    submit_tx(handle, frame_len, csum);
}

/// Send a slice-shaped frame. Goes through the unified
/// acquire+submit path: pool is per-worker (lock-free slot
/// allocation on both Tier 1 and Tier 2); virtq submission is
/// per-core on Tier 1 and TX_LOCK-serialised on Tier 2.
pub(crate) fn send(data: &[u8], csum: nic_api::CsumOffload) {
    send_slice(data, csum);
}

// ─── Direct-fill (zero-copy) TX path ────────────────────────────────────────
//
// `acquire_tx_buf` hands the caller an `IOBuf::TxBufHandle` whose
// data ptr points straight at a free slot in the per-qp `tx_pool`.
// The caller fills the frame in place (no memcpy through an
// intermediate stack buffer); `submit_tx` enqueues a virtio
// descriptor pointing at the same storage. The slot stays "in
// use" until the device signals descriptor completion via
// `tx_drain_qp`.
//
// Tier 1 (per-core queue pairs) is the supported case: the qp is
// owned by the caller's core, so no lock contention on
// `tx_pool_used` scanning. Tier 2 (shared qp + multi-core) returns
// `None` from `acquire_tx_buf` — the caller falls back to the
// legacy `send(&[u8])` + per-core staging path.

/// Drop callback for an unsubmitted `TxBufHandle`: returns the
/// slot to the pool. Called by `TxBufHandle::drop` when a caller
/// acquires a slot but doesn't go through `submit_tx` (e.g. error
/// path before frame-build completion).
fn release_tx_slot(token: u64) {
    let (worker, slot, pool) = decode_token(token);
    if worker >= unsafe { (*ndev()).num_workers } {
        return;
    }
    match pool {
        POOL_ID_SMALL if slot < TX_POOL_SMALL_SIZE => unsafe {
            (*wpool(worker)).small_used[slot].store(false, Ordering::Release);
        },
        POOL_ID_BIG if slot < TX_POOL_BIG_SIZE => unsafe {
            (*wpool(worker)).big_used[slot].store(false, Ordering::Release);
        },
        _ => {}
    }
}

/// Pick the calling worker's pool index and pre-drain the qp
/// it submits through. Returns `(worker_id, qp)` — `qp` is what
/// the caller drains while spin-waiting for a slot to free.
fn current_worker_and_qp() -> Option<(usize, usize)> {
    if unsafe { matches!((*ndev()).transport, Transport::None) } {
        return None;
    }
    let cc = kernel_bare::percpu::CurrentWorker::enter();
    let worker = cc.id() as usize;
    let qp = worker_qp(worker);
    tx_drain_qp_locked(qp);
    Some((worker, qp))
}

/// `tx_drain_qp` wrapped in TX_LOCK on Tier 2 so concurrent
/// workers don't race the used-ring read. On Tier 1 each worker
/// drains its own qp, no lock needed.
fn tx_drain_qp_locked(qp: usize) {
    if qp_needs_lock() {
        let _g = TX_LOCK.lock();
        tx_drain_qp(qp);
    } else {
        tx_drain_qp(qp);
    }
}

/// Claim a free slot from `worker`'s small pool, accumulating the
/// linear-scan depth into `local_iters`. Returns the slot index or
/// `None` if the pool is full.
///
/// SAFETY: single-writer-per-worker — only this worker claims from its
/// own pool (`claim_first_free`'s required invariant); the slice is
/// formed from the live `wpool(worker)` pointer. Bind the array
/// reference explicitly first so the `[..]` slice isn't an implicit
/// autoref through the raw-pointer deref.
#[inline]
fn claim_small_slot(worker: usize, local_iters: &mut u64) -> Option<usize> {
    let (got, scanned) = unsafe {
        let small_used = &(*wpool(worker)).small_used;
        claim_first_free(&small_used[..TX_POOL_SMALL_SIZE])
    };
    *local_iters += scanned as u64;
    got
}

/// Wrap a claimed small-pool slot as a [`TxBufHandle`] and bump the
/// acquire diagnostics (`local_iters / acquires` is the average scan
/// depth; relaxed ordering since the counters gate no other read).
#[inline]
fn small_slot_handle(worker: usize, slot: usize, local_iters: u64) -> nic_api::TxBufHandle {
    TX_SMALL_SCAN_ITERS.add(local_iters);
    TX_SMALL_ACQUIRES.bump();
    let buf = unsafe { &mut (*wpool(worker)).small[slot] };
    nic_api::TxBufHandle {
        data_ptr: buf.data.as_mut_ptr(),
        data_cap: MAX_ETH_FRAME_SMALL as u32,
        driver_token: encode_token(worker, slot, POOL_ID_SMALL),
        release_fn: release_tx_slot,
    }
}

pub(crate) fn acquire_tx_buf() -> Option<nic_api::TxBufHandle> {
    let (worker, qp) = current_worker_and_qp()?;
    let mut local_iters: u64 = 0;

    // Fast path: a slot is almost always immediately free. Take it before
    // touching the clock / stall cell so the hot path carries zero
    // circuit-breaker overhead.
    if let Some(slot) = claim_small_slot(worker, &mut local_iters) {
        return Some(small_slot_handle(worker, slot, local_iters));
    }

    // Pool full — enter the bounded spin-drain with a stall circuit
    // breaker. Per-worker pool means slot allocation is lock-free
    // regardless of nqp; only the qp drain takes TX_LOCK on Tier 2.
    //
    // Under normal transient saturation a slot frees within a few sweeps
    // (µs) and the spin-drain beats the drop+retransmit cost. But the spin
    // MUST be bounded: if the device stops draining the TX ring, an
    // unbounded spin hard-hangs the whole core synchronously (no executor
    // yield, no serial) — RX, timers, and every other connection starve.
    // That is the Apple-HVF h3-`/stream` wedge: the guest's cacheable read
    // of the TX `used->idx` goes stale, completions are never observed,
    // pool slots never free, and the old unbounded loop spun at ~100% CPU
    // forever (see reference_hvf_h3_stream_wedge).
    //
    // So: run the shared progress-aware breaker (`TxStallBreaker`;
    // policy + budgets + measured rationale live in `tx_pool::stall`).
    // A saturated-but-draining ring (used->idx advancing) spins
    // losslessly; only a frozen ring trips, arming a fast-fail
    // cooldown that keeps each call O(µs) — so retransmission / PTO
    // timers firing into the dead path drain as a brief burst and the
    // event loop stays live. Callers honor the `None` contract: QUIC
    // falls back to a Heap datagram (then `submit_tx` drops on full)
    // and retransmits; TCP resends.
    // Budget 1 ms (not gqi's 5 ms): on this driver's hosts (nested
    // KVM with vhost-net, Apple HVF) multi-ms device pauses are
    // ROUTINE under host oversubscription, and spinning through each
    // one blocks the whole event loop — an interleaved kvm/virtio A/B
    // measured ~4% static64k rps lost at 5 ms. Bailing at 1 ms is
    // cheap: chain sends requeue their unsent tail, and the
    // progress-stamped cooldown self-clears on the first completion.
    const VIRTIO_STALL_BUDGET_US: u64 = 1_000;
    let cycles_per_us = kernel_bare::time::cycles_per_us();
    let got = TX_STALL.spin(
        VIRTIO_STALL_BUDGET_US,
        cycles_per_us,
        kernel_bare::time::now_cycles,
        // Progress = the device-written used->idx on this qp (what the
        // drain consumes to free pool slots). Zero-extended; the
        // breaker only tests equality, so the u16 wrap is fine.
        || unsafe { (*tx_q(qp)).used_idx() as u64 },
        // One lap: count the saturation event, flush deferred kicks so
        // the host can process the pending TX batch, then drain and
        // re-scan (a drain-freed slot is claimed on the same lap).
        || {
            TX_SMALL_FULL_SPINS.bump();
            unsafe {
                (*tx_q(qp)).flush_kick();
            }
            tx_drain_qp_locked(qp);
            compiler_fence(Ordering::SeqCst);
            claim_small_slot(worker, &mut local_iters)
                .map(|slot| small_slot_handle(worker, slot, local_iters))
        },
    );
    if got.is_none() {
        crate::diag::record_tx_drop(
            &crate::diag::COUNTERS.tx_acquire_giveup,
            "tx_acquire_giveup",
            qp as u32,
            0,
        );
    }
    got
}

/// Acquire a big-slot TX buffer (16 KiB capacity) for a TCP TSO
/// super-segment. Returns `None` when TSO isn't negotiated (no
/// big pool allocated) or the pool is full. Caller falls back to
/// `acquire_tx_buf` + per-MSS segmentation when None — TSO pool
/// is small (16 slots) so we don't spin-drain it; per-MSS keeps
/// throughput up under transient TSO-pool saturation.
pub(crate) fn acquire_tx_tso_buf() -> Option<nic_api::TxTsoBufHandle> {
    let (worker, _qp) = current_worker_and_qp()?;
    let big_ptr = unsafe { (*wpool(worker)).big };
    if big_ptr.is_null() {
        return None; // TSO not negotiated for this device
    }
    for slot in 0..TX_POOL_BIG_SIZE {
        unsafe {
            if !(*wpool(worker)).big_used[slot].load(Ordering::Acquire) {
                (*wpool(worker)).big_used[slot].store(true, Ordering::Relaxed);
                TX_BIG_ACQUIRES.bump();
                let buf = &mut *big_ptr.add(slot);
                return Some(nic_api::TxTsoBufHandle(nic_api::TxBufHandle {
                    data_ptr: buf.data.as_mut_ptr(),
                    data_cap: MAX_ETH_FRAME_BIG as u32,
                    driver_token: encode_token(worker, slot, POOL_ID_BIG),
                    release_fn: release_tx_slot,
                }));
            }
        }
    }
    // Big pool full → caller falls back to per-MSS small-pool sends.
    // High counts here mean TSO is being undersized (or the TCP
    // layer is shipping super-segments faster than the device
    // drains them).
    TX_BIG_FULL_RETURNS.bump();
    None
}

pub(crate) fn submit_tx(handle: nic_api::TxBufHandle, frame_len: usize, csum: nic_api::CsumOffload) {
    let (worker, slot, _pool) = decode_token(handle.driver_token);
    // mem::forget skips `Drop`'s `release_fn` — the slot is
    // about to be in-flight, not unused. `tx_drain_qp` returns
    // it to the pool when the device signals completion.
    core::mem::forget(handle);

    // Type-distinct handles guarantee a `TxBufHandle` here came
    // from the small pool (big-pool slots flow through
    // `TxTsoBufHandle` + `submit_tx_tso`). Defensive bound checks
    // for slot/worker index only.
    if slot >= TX_POOL_SMALL_SIZE || worker >= unsafe { (*ndev()).num_workers } {
        crate::diag::record_tx_drop(
            &crate::diag::COUNTERS.tx_bad_token,
            "bad_token",
            worker as u32,
            frame_len as u32,
        );
        return;
    }
    if frame_len == 0 || frame_len > MAX_ETH_FRAME_SMALL {
        unsafe {
            (*wpool(worker)).small_used[slot].store(false, Ordering::Release);
        }
        crate::diag::record_tx_drop(
            &crate::diag::COUNTERS.tx_bad_frame_len,
            "bad_frame_len",
            worker_qp(worker) as u32,
            frame_len as u32,
        );
        return;
    }

    let qp = worker_qp(worker);

    // The caller stamped the pseudo-header partial sum at the L4
    // checksum field; something has to finish it. A device that
    // negotiated VIRTIO_NET_F_CSUM does — NEEDS_CSUM points it at
    // `csum_start + csum_offset`. A device that didn't can't, so
    // we finish the checksum here in software and ship a plain
    // frame. Either way the frame leaves with a correct checksum.
    let offload = csum.is_some() && unsafe { (*ndev()).has_csum };

    unsafe {
        let buf = &mut (*wpool(worker)).small[slot];
        if csum.is_some() && !offload {
            // Software-complete: the L4 segment's checksum field
            // already holds the partial sum, so the RFC-1071 sum
            // over the segment folds it straight into the answer.
            let l4 = csum.start as usize;
            let final_ck =
                net_checksum::internet_checksum(buf.data.as_ptr().add(l4), frame_len - l4);
            let field = l4 + csum.offset as usize;
            buf.data[field] = (final_ck & 0xff) as u8;
            buf.data[field + 1] = (final_ck >> 8) as u8;
        }
        let (flags, csum_start, csum_off) = if offload {
            (VIRTIO_NET_HDR_F_NEEDS_CSUM, csum.start, csum.offset)
        } else {
            (0, 0, 0)
        };
        // Fill virtio_net header. Single-buffer frame
        // (num_buffers = 1); GSO disabled.
        buf.hdr = VirtioNetHeader {
            flags,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start,
            csum_offset: csum_off,
            num_buffers: 1,
        };

        let total_len = VIRTIO_NET_HDR_SIZE as u32 + frame_len as u32;
        let buf_phys = virt_to_phys(buf as *const TxBufSmall as *const u8);

        let submit = |head_check: &dyn Fn() -> i32| -> bool {
            let head = head_check();
            if head < 0 {
                (*wpool(worker)).small_used[slot].store(false, Ordering::Release);
                crate::diag::record_tx_drop(
                    &crate::diag::COUNTERS.tx_submit_failed,
                    "submit_failed",
                    qp as u32,
                    frame_len as u32,
                );
                return false;
            }
            (*tx_q(qp)).kick();
            true
        };
        let ok = if qp_needs_lock() {
            let _g = TX_LOCK.lock();
            submit(&|| (*tx_q(qp)).add_buf(buf_phys, total_len, 1, 0))
        } else {
            submit(&|| (*tx_q(qp)).add_buf(buf_phys, total_len, 1, 0))
        };
        if ok && qp < DIAG_QP_CAP {
            // Per-qp TX packet count — surfaces load distribution
            // across qps. Even-ish counts under multi-core load
            // means worker→qp mapping + RSS are balanced.
            TX_PACKETS_PER_QP[qp].fetch_add(1, Ordering::Relaxed);
            TX_BYTES_PER_QP[qp].fetch_add(frame_len as u64, Ordering::Relaxed);
        }
    }
}

pub(crate) fn tso_available() -> bool {
    unsafe { (*ndev()).has_tso4 }
}

pub(crate) fn submit_tx_tso(
    handle: nic_api::TxTsoBufHandle,
    frame_len: usize,
    hdr_len: u16,
    csum_start: u16,
    gso_size: u16,
) {
    // Type-distinct wrapper guarantees this token came from
    // `acquire_tx_tso_buf` (i.e. POOL_ID_BIG). We still decode
    // it for the worker/slot fields; the pool ID is implied.
    let (worker, slot, _pool) = decode_token(handle.0.driver_token);
    core::mem::forget(handle); // see `submit_tx` for rationale

    if slot >= TX_POOL_BIG_SIZE || worker >= unsafe { (*ndev()).num_workers } {
        crate::diag::record_tx_drop(
            &crate::diag::COUNTERS.tx_bad_token,
            "bad_token",
            worker as u32,
            frame_len as u32,
        );
        return;
    }
    if frame_len == 0 || frame_len > MAX_ETH_FRAME_BIG {
        unsafe {
            (*wpool(worker)).big_used[slot].store(false, Ordering::Release);
        }
        crate::diag::record_tx_drop(
            &crate::diag::COUNTERS.tx_bad_frame_len,
            "bad_frame_len",
            worker_qp(worker) as u32,
            frame_len as u32,
        );
        return;
    }

    let big_ptr = unsafe { (*wpool(worker)).big };
    if big_ptr.is_null() {
        // Pool was deallocated mid-flight (shouldn't happen on
        // a live device). Release the slot bit anyway.
        unsafe {
            (*wpool(worker)).big_used[slot].store(false, Ordering::Release);
        }
        crate::diag::record_tx_drop(
            &crate::diag::COUNTERS.tx_bad_token,
            "big_pool_null",
            worker_qp(worker) as u32,
            frame_len as u32,
        );
        return;
    }

    let qp = worker_qp(worker);

    unsafe {
        let buf = &mut *big_ptr.add(slot);
        // TSO virtio_net_hdr — see virtio spec §5.1.6:
        //   * `flags = NEEDS_CSUM`: device computes the per-segment
        //     TCP checksum at byte offset `csum_start + csum_offset`
        //     of each emitted segment.
        //   * `gso_type = TCPV4`: device segments the payload into
        //     `gso_size`-byte chunks with TCP/IP headers fixed up
        //     per segment.
        //   * `hdr_len`: total L2+L3+L4 header length the device
        //     copies to every segment.
        //   * `csum_start`: offset of the TCP header (start of the
        //     range Poly1305 covers, but here we use it as the
        //     start of the IP checksum scope per the v1 spec).
        //   * `csum_offset = 16`: offset within the TCP header to
        //     the `checksum` field.
        buf.hdr = VirtioNetHeader {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len,
            gso_size,
            csum_start,
            csum_offset: 16,
            num_buffers: 1,
        };

        let total_len = VIRTIO_NET_HDR_SIZE as u32 + frame_len as u32;
        let buf_phys = virt_to_phys(buf as *const TxBufBig as *const u8);
        let submit = || -> bool {
            let head = (*tx_q(qp)).add_buf(buf_phys, total_len, 1, 0);
            if head < 0 {
                (*wpool(worker)).big_used[slot].store(false, Ordering::Release);
                crate::diag::record_tx_drop(
                    &crate::diag::COUNTERS.tx_submit_failed,
                    "submit_failed",
                    qp as u32,
                    frame_len as u32,
                );
                return false;
            }
            (*tx_q(qp)).kick();
            true
        };
        let ok = if qp_needs_lock() {
            let _g = TX_LOCK.lock();
            submit()
        } else {
            submit()
        };
        if ok && qp < DIAG_QP_CAP {
            TX_PACKETS_PER_QP[qp].fetch_add(1, Ordering::Relaxed);
            TX_BYTES_PER_QP[qp].fetch_add(frame_len as u64, Ordering::Relaxed);
        }
    }
}

/// True if any worker has TX work pending. Always `false` — TX
/// goes straight through `acquire_tx_buf`/`submit_tx` now (per-
/// worker pool + virtq submit, with TX_LOCK on Tier 2). The
/// per-core SPSC staging-ring path has been retired; this hook
/// stays in the NicOps vtable so callers compile, but never
/// reports work pending.
pub(crate) fn has_pending_tx() -> bool {
    false
}

/// Flush deferred TX kicks across all qps. Used by callers that
/// just submitted via `acquire_tx_buf`/`submit_tx` and want to
/// ensure the host sees the descriptors before they sleep — e.g.
/// before WFI/HLT, or to break a deferred-kick deadlock during
/// ARP resolution. The legacy "drain per-core staging ring"
/// behaviour is gone with the staging-ring path itself.
pub(crate) fn flush_tx_staging() {
    let nqp = unsafe { (*ndev()).num_queue_pairs as usize };
    if qp_needs_lock() {
        let _g = TX_LOCK.lock();
        for qp in 0..nqp {
            unsafe {
                (*tx_q(qp)).flush_kick();
            }
        }
    } else {
        for qp in 0..nqp {
            unsafe {
                (*tx_q(qp)).flush_kick();
            }
        }
    }
}

/// Enable deferred TX kick mode. After this, kick() on the TX queue
/// is a no-op; the caller must call `flush_tx_kick_if_dirty()` to
/// issue the actual MMIO write. Batches multiple send_segment()
/// calls into one virtio notification, reducing MMIO exits.
pub(crate) fn enable_deferred_tx_kick() {
    let nqp = unsafe { (*ndev()).num_queue_pairs } as usize;
    for qp in 0..nqp {
        unsafe {
            (*tx_q(qp)).set_deferred_kick(true);
        }
    }
}

/// Flush only if dirty. Returns true if a kick was issued.
/// In multi-queue mode, flushes the calling core's TX queue pair.
pub(crate) fn flush_tx_kick_if_dirty() -> bool {
    let nqp = unsafe { (*ndev()).num_queue_pairs };
    if nqp > 1 {
        let core = kernel_bare::cpu_id() as usize;
        let qp = if core < nqp as usize { core } else { 0 };
        unsafe { (*tx_q(qp)).flush_kick_if_dirty() }
    } else {
        unsafe { (*tx_q(0)).flush_kick_if_dirty() }
    }
}

