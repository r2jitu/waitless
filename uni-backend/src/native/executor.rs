// uni-backend/src/native/executor.rs — POSIX side of the runtime backend.
//
// Platform primitives (current_worker, now_ticks) live in
// `uni-platform` and are called directly from uni-percpu / uni-runtime.
// This file exists only to re-export the executor surface for apps.

/// No backend-side init is required on native — `uni_platform`'s
/// thread-local worker id is set per-worker in `native::run` when
/// each worker thread starts.
pub fn init() {}

// ---- Re-exports for app + worker-loop code --------------------------------

pub use uni_runtime::{has_pending, sleep_us, spawn, tick, Sleep};
