// uni-runtime/src/lib.rs — Shared async runtime.
//
// Layout:
//   * `task` — per-worker task arena + spawn/tick/abort + waker vtable.
//   * `sleep` — per-worker timer wheel + the `Sleep` future that
//     schedules into it. `task::tick` calls into this to advance
//     timers each iteration.
//   * `event`, `launcher`, `select` — small free-standing
//     primitives consumed by the net reactors and apps.
//   * `net` — UDP / TCP per-worker reactors (the runtime's "meat";
//     submodule because it's two reactors plus shared helpers).
//
// Rule of thumb for new files here: subdir when >1 file's worth of
// implementation, top-level `.rs` when it's one file's worth.

#![no_std]

extern crate alloc;
pub extern crate net_types as ip;

pub mod event;
pub mod launcher;
pub mod net;
pub mod select;
mod sleep;
mod task;

/// Initialise both the task arena and the timer wheel for `num_workers`
/// slots. BSP-only, after `mm::init()`, before any worker touches the
/// runtime.
pub fn init(num_workers: u32) {
    sleep::init(num_workers);
    task::init(num_workers);
}

pub use sleep::{sleep_us, Sleep};
pub use task::{
    drain_all_arenas, has_pending, spawn, spawn_boxed, tick, BoxedFuture, TaskArena,
    TaskHandle, TaskSlot, TASKS_PER_WORKER,
};
