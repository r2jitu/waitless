// crates/runtime/executor/src/lib.rs — Shared async runtime.
//
// Layout:
//   * `task` — per-worker task arena + spawn/tick/abort + waker vtable.
//   * `sleep` — per-worker timer wheel + the `Sleep` future that
//     schedules into it. `task::tick` calls into this to advance
//     timers each iteration.
//   * `event`, `launcher`, `select` — small free-standing
//     primitives consumed by the reactors and apps.
//   * `reactor` — UDP / TCP per-worker reactors (the runtime's
//     "meat"; submodule because it's two reactors plus shared
//     helpers).
//
// Rule of thumb for new files here: subdir when >1 file's worth of
// implementation, top-level `.rs` when it's one file's worth.

// `no_std` for the unikernel build; under `cfg(test)` the crate is
// `std` so `rust_test(crate = ":executor")` can run host-native
// unit tests (item-F `recv_chunk` round-trips) with the standard
// libtest harness — the workspace pattern (see `bazel/rules/rust.bzl`).
#![cfg_attr(not(test), no_std)]

extern crate alloc;
pub use net_types as ip;

pub mod diag;
pub mod event;
pub mod launcher;
pub mod reactor;
pub mod select;
mod sleep;
mod task;
pub mod waker_slot;

/// Initialise both the task arena and the timer wheel for `num_workers`
/// slots. BSP-only, after `mm::init()`, before any worker touches the
/// runtime.
pub fn init(num_workers: u32) {
    sleep::init(num_workers);
    task::init(num_workers);
}

pub use sleep::{Sleep, sleep_us};
pub use task::{
    BoxedFuture, SpawnError, TASKS_PER_WORKER, TaskArena, TaskHandle, TaskSlot, drain_all_arenas,
    has_pending, spawn, spawn_boxed, tick,
};
