// uni-backend/src/lib.rs — Platform adapter for `uni`.
//
// Single crate with two cfg-gated impls: `unikernel` (bare-metal)
// and `native` (POSIX). Selected by `target_os`. The exported symbol
// surface is the same on both sides so `uni/lib.rs` can unconditionally
// `pub use uni_backend::*;`.

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

#[cfg(target_os = "none")]
mod unikernel;
#[cfg(not(target_os = "none"))]
mod native;

#[cfg(target_os = "none")]
pub use unikernel::*;
#[cfg(not(target_os = "none"))]
pub use native::*;
