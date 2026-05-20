// crates/uni/backend/src/lib.rs — Platform adapter for `uni`.
//
// Single crate with two cfg-gated impls: `unikernel` (bare-metal)
// and `native` (POSIX). Selected by `target_os`. The exported symbol
// surface is the same on both sides so `uni/lib.rs` can unconditionally
// `pub use backend::*;`.

#![cfg_attr(target_os = "none", no_std)]

/// Heap-allocator counters surfaced via `backend::heap_stats()`.
/// Cheap on bare-metal (O(1) read under the talc spinlock); zero on
/// native (libstd's allocator doesn't expose equivalent accounting).
#[derive(Debug, Clone, Copy, Default)]
pub struct HeapStats {
    pub allocated_bytes: usize,
    pub available_bytes: usize,
    pub claimed_bytes: usize,
    pub allocation_count: usize,
    pub fragment_count: usize,
    pub total_allocation_count: u64,
}

/// gve (Google Virtual NIC) driver diagnostic counters, surfaced via
/// `backend::gve_diag()` (and `uni::diagnostics::gve_diag`).
///
/// Real values on bare-metal when the gve driver is linked; all-zero
/// on native (no gve driver) and on bare-metal under virtio-net.
/// This type — and `gve_diag()`'s cfg-split — is what lets an
/// application crate read the gve `/stats` counters *without*
/// depending on the (`os:none`-only) gve driver directly. A direct
/// app→`gve` dep makes the app unbuildable for native;
/// undoing exactly that regression is why this struct exists.
#[derive(Debug, Clone, Copy, Default)]
pub struct GveDiag {
    /// DQO TX completions the device reported as missed.
    pub dqo_tx_miss_compl: u64,
    /// DQO TX completions the device reinjected after a miss.
    pub dqo_tx_reinject_compl: u64,
    /// DQO RX completions skipped (RX-path item I observability).
    pub dqo_rx_compl_skipped: u64,
    /// Status byte of the most recent skipped RX completion.
    pub dqo_rx_last_skip_status: u8,
    /// RX buffers reposted, summed across queue pairs — the
    /// item-B cross-core drop-callback sanity check.
    pub rx_buf_repost_count: u64,
    /// GQI recycle-pool exhaustion events, summed across qps.
    pub gqi_recycle_pool_exhausted: u64,
}

/// TCP/IP-stack diagnostic counters, surfaced via
/// `backend::tcp_diag()` (and `uni::diagnostics::tcp_diag`).
///
/// Real values on bare-metal; all-zero on native (the bare-metal
/// `net` stack — an `os:none` crate — isn't linked there). Same
/// rationale as [`GveDiag`]: an application crate reads these
/// `/stats` counters through this struct instead of reaching into
/// `net::tcp` directly, which would coupling-break its native build.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpDiag {
    /// SYN segments observed by `tcp_receive`.
    pub syn_rx: u64,
    /// SYN-ACK segments emitted in response to a SYN.
    pub synack_tx: u64,
    /// `recv_chunk` calls served zero-copy from the device-buffer
    /// stash (RX-path item H).
    pub rx_chunk_stash_hits: u64,
    /// `recv_chunk` calls served via the copying ring-drain
    /// fallback (RX-path item H).
    pub rx_chunk_ring_drain: u64,
}

#[cfg(not(target_os = "none"))]
mod native;
#[cfg(target_os = "none")]
mod unikernel;

#[cfg(not(target_os = "none"))]
pub use native::*;
#[cfg(target_os = "none")]
pub use unikernel::*;
