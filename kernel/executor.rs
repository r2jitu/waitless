// kernel/executor.rs — Bare-metal backend for `uni-executor`.

use crate::percpu::{percore, CurrentCore, MAX_CORES, PerCpu};
use crate::timer::{Timer, TimerWheel};

// ---- Per-core wheel storage ------------------------------------------------

struct WheelCell(core::cell::UnsafeCell<TimerWheel>);

// SAFETY: each wheel is touched only by its owning core (proven by
// the `CurrentCore` token in `wheel()`).
unsafe impl Sync for WheelCell {}
unsafe impl Send for WheelCell {}

static WHEELS: PerCpu<WheelCell, MAX_CORES> = PerCpu::new(
    [const { WheelCell(core::cell::UnsafeCell::new(TimerWheel::new())) }; MAX_CORES],
);

fn wheel(cc: &CurrentCore) -> &mut TimerWheel {
    let cell = WHEELS.current(cc);
    // SAFETY: owning-core-only access enforced by `CurrentCore`.
    unsafe { &mut *cell.0.get() }
}

#[inline]
fn now_ticks_us() -> u64 {
    crate::time::now_cycles() / crate::time::cycles_per_us()
}

// ---- uni_executor::Runtime plug-in -----------------------------------------

fn rt_now_ticks() -> u64 {
    now_ticks_us()
}

fn rt_schedule_timer(deadline: u64, func: fn(usize), arg: usize) -> bool {
    let cc = CurrentCore::enter();
    wheel(&cc).insert(Timer { deadline, func, arg })
}

fn rt_cancel_timer(arg: usize) -> bool {
    let cc = CurrentCore::enter();
    wheel(&cc).cancel(arg)
}

static RUNTIME: uni_executor::Runtime = uni_executor::Runtime {
    now_ticks: rt_now_ticks,
    schedule_timer: rt_schedule_timer,
    cancel_timer: rt_cancel_timer,
};

/// Register the bare-metal runtime. Call once, after `percpu::init`.
pub fn init() {
    uni_executor::register(&RUNTIME);
}

// ---- Event-loop integration ------------------------------------------------

/// Drain pending timers into the local wheel, fire expired timers,
/// then poll every ready slot in the worker's arena.
pub fn tick(core_id: u32) -> bool {
    // SAFETY: the event loop only calls `tick` on the running core.
    let cc = unsafe { CurrentCore::from_id_unchecked(core_id) };

    let pc = percore(&cc);
    let w = wheel(&cc);
    let _ = pc.pending_timers.drain_into(w);
    let _ = w.advance(now_ticks_us());

    uni_executor::tick(core_id)
}

/// True if the current core has outstanding async work.
pub fn has_pending(core_id: u32) -> bool {
    // SAFETY: same as `tick`.
    let cc = unsafe { CurrentCore::from_id_unchecked(core_id) };
    if wheel(&cc).count() > 0 {
        return true;
    }
    uni_executor::has_ready(core_id)
}

// ---- Re-exports for app code ----------------------------------------------

pub use uni_executor::{sleep_us, spawn, Sleep};
