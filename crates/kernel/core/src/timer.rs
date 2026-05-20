// kernel/timer.rs — thin re-export of the shared timer wheel.
//
// `TimerWheel` + `PendingTimers` live in `//crates/runtime/worker` so native
// can share the same O(1) insert / slot-hashed fire + lock-free
// cross-worker MPSC. Callers inside the kernel keep using
// `kernel_bare::timer::…` unchanged.

pub use worker::timer::{Timer, TimerWheel};
