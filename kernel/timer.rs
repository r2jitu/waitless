// kernel/timer.rs — thin re-export of the shared timer wheel.
//
// `TimerWheel` + `PendingTimers` live in `//uni-percpu` so native
// can share the same O(1) insert / slot-hashed fire + lock-free
// cross-worker MPSC. Callers inside the kernel keep using
// `kernel::timer::…` unchanged.

pub use uni_percpu::timer::{Timer, TimerWheel};
