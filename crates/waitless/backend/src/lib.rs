// crates/waitless/backend/src/lib.rs — Platform adapter for `waitless`.
//
// Single crate with two cfg-gated impls: `bare` (bare-metal)
// and `native` (POSIX). Selected by `target_os`. The exported symbol
// surface is the same on both sides so `waitless/lib.rs` can unconditionally
// `pub use waitless_backend::*;`.

#![cfg_attr(target_os = "none", no_std)]

/// Heap-allocator counters surfaced via `waitless_backend::heap_stats()`.
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

// `GveDiag` / `TcpDiag` retired. They were plain-struct carriers for
// the gve / TCP counters across the backend seam, consumed by
// `/stats`. The counters now render straight to JSON inside the
// subsystem (`gve::diag` / `tcp::diag`) and cross the seam via the
// `*_obs_json(&mut dyn Write)` accessors — one mechanism, no
// per-subsystem struct. See `docs/observability.md`.

#[cfg(not(target_os = "none"))]
mod native;
#[cfg(target_os = "none")]
mod bare;

#[cfg(not(target_os = "none"))]
pub use native::*;
#[cfg(target_os = "none")]
pub use bare::*;
