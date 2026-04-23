// kernel/executor.rs — Bare-metal backend for `uni-executor`.
//
// The shared async runtime (arena, waker, Sleep) lives in
// `//uni-executor`; `CurrentCore` + `PerCpu` live in `//uni-percpu`.
// This file provides the three `extern "C"` hooks `uni-executor`
// expects:
//
//   * `uni_exec_now_ticks`       → cycle counter / µs
//   * `uni_exec_schedule_timer`  → per-core `kernel::timer::TimerWheel`
//   * `uni_exec_cancel_timer`    → `TimerWheel::cancel`
//
// Worker-id lookups go through `uni_percpu::CurrentCore::enter`,
// which calls the separate `uni_percpu_current_worker` hook supplied
// by `kernel::percpu`.
//
// `tick()` + `has_pending()` are the event-loop integration points
// kept here: `tick` drains the per-core `pending_timers` MPSC,
// advances the wheel (which fires Sleep timers → wakers → slot
// ready bits), then calls the shared `uni_executor::tick`.

use crate::percpu::{percore, CurrentCore, MAX_CORES, PerCpu};
use crate::timer::{Timer, TimerWheel};

// ---- Per-core wheel storage ------------------------------------------------

struct WheelCell(core::cell::UnsafeCell<TimerWheel>);

// SAFETY: each wheel is touched only by its owning core (proven by
// the `CurrentCore` token in `wheel()` below).
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

// ---- Event-loop integration ------------------------------------------------

/// Drain pending timers into the local wheel, fire expired timers
/// (which wake their tasks via the `Sleep` → waker chain), then let
/// `uni_executor` poll every ready slot. Called once per iteration
/// by `kernel::eventloop::run`.
pub fn tick(core_id: u32) -> bool {
    // SAFETY: the event loop only calls `tick` on the running core.
    let cc = unsafe { CurrentCore::from_id_unchecked(core_id) };

    let pc = percore(&cc);
    let w = wheel(&cc);
    let _ = pc.pending_timers.drain_into(w);
    let _ = w.advance(now_ticks_us());

    uni_executor::tick(core_id)
}

/// True if the current core has outstanding async work — either a
/// scheduled timer or a task slot flagged ready. The event loop uses
/// this to pick a timer-bounded idle over the HVF yield-register
/// path when the yield path would otherwise strand us.
pub fn has_pending(core_id: u32) -> bool {
    // SAFETY: same as `tick`.
    let cc = unsafe { CurrentCore::from_id_unchecked(core_id) };
    if wheel(&cc).count() > 0 {
        return true;
    }
    uni_executor::has_ready(core_id)
}

// ---- Backend hooks ---------------------------------------------------------
//
// Linked against the `extern "C"` declarations in
// `//uni-executor/src/lib.rs`. Function-pointer arg uses plain Rust
// ABI (`fn(usize)`), so we can store it in `kernel::timer::Timer`
// directly without a transmute.

#[unsafe(no_mangle)]
pub extern "C" fn uni_exec_now_ticks() -> u64 {
    now_ticks_us()
}

// `func: fn(usize)` is Rust ABI; on every target we support it
// lowers to the same register as a C-ABI fn pointer. The lint is
// about portability we don't need.
#[allow(improper_ctypes_definitions)]
#[unsafe(no_mangle)]
pub extern "C" fn uni_exec_schedule_timer(
    deadline: u64,
    func: fn(usize),
    arg: usize,
) -> bool {
    let cc = CurrentCore::enter();
    wheel(&cc).insert(Timer {
        deadline,
        func,
        arg,
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_exec_cancel_timer(arg: usize) -> bool {
    let cc = CurrentCore::enter();
    wheel(&cc).cancel(arg)
}

// ---- Re-exports for app code ----------------------------------------------

pub use uni_executor::{sleep_us, spawn, Sleep};
