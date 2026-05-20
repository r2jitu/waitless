// RX dispatch — drains completion rings and delivers frames as
// `Chain<OwnedIOBuf>` to the caller's callback.
//
// Each poll function checks `QUEUE_FORMAT_DQO` once and jumps to the
// per-format implementation in `dqo::poll_qp_inner` / `gqi::poll_qp_inner`.
//
// The callback receives an owned `IOBufChain` per frame:
//   * DQO wraps the device's buf_id RX buffer as an `ExternalOwned`
//     IOBuf — zero copy. The `dqo_repost` drop callback returns
//     buf_id to the data ring when the chain drops, so a consumer
//     may retain the chain past the callback safely; the buffer is
//     never re-armed while a live IOBuf still views it.
//   * GQI cannot lend device QPL pages (strict in-order repost), so
//     it copies each frame into a recycle-pool slab and delivers
//     that; the device page is reposted at the batch boundary.
//
// This replaced an earlier borrowed-`&[u8]` shape that forced a
// synchronous copy at the driver boundary. The earlier *first*
// owned-IOBuf attempt was unsound because it had no auto-repost — a
// stalled consumer could pin a device buffer past the ~23 ms
// ring-wrap window, after which reads observed bytes the device had
// overwritten. `ExternalOwned`'s drop callback closes that hole: the
// buffer always reposts when the chain drops, and never before — so
// re-arm provably cannot race a live consumer.

use core::sync::atomic::Ordering;

use iobuf::{Chain, OwnedIOBuf};

use crate::{MAX_QUEUE_PAIRS, NUM_QP, QUEUE_FORMAT_DQO, dqo, gqi};

/// Drain the RX completion ring for the given queue pair, dispatching
/// to the GQI or DQO datapath based on the negotiated queue format.
fn poll_qp_inner<F: FnMut(Chain<OwnedIOBuf>)>(qp: usize, callback: F) -> u32 {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        dqo::poll_qp_inner(qp, callback)
    } else {
        gqi::poll_qp_inner(qp, callback)
    }
}

pub(crate) fn poll_qp(qp: usize, callback: fn(Chain<OwnedIOBuf>)) -> usize {
    poll_qp_inner(qp, callback) as usize
}

/// Non-per-core poll. Callers (DHCP bring-up, Tier 2 distribute)
/// don't know which RX queue a given packet landed on, so walk
/// every live queue. RSS is active by the time `init()` returns,
/// and DHCP's reply may hash onto any queue — not just qp 0.
pub(crate) fn poll(callback: fn(Chain<OwnedIOBuf>)) -> usize {
    let n = NUM_QP.load(Ordering::Acquire) as usize;
    let mut total: usize = 0;
    for qp in 0..n.min(MAX_QUEUE_PAIRS) {
        total = total.saturating_add(poll_qp_inner(qp, callback) as usize);
    }
    total
}
