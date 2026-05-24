// crates/runtime/executor/src/diag.rs — observability for the async runtime.
//
// The observability doctrine (`docs/observability.md`) applied to
// the task executor. The per-core event-loop telemetry (loop /
// idle-cycle stats) already lives in `kernel_bare::eventloop` and is
// surfaced as the `/obs` `event_loop` block; the gap the doctrine
// closes here is the per-worker task arena — task lifecycle, and in
// particular the silent `spawn` failure.
//
// `obs` is a leaf crate, so the executor — which sits *below*
// `kernel_core` in the crate graph — can depend on it directly.
// That dependency direction is the whole reason `obs` was hoisted
// out of `kernel_core`.

use core::fmt;

use obs::{Counter, LastEvent, MAX_CORES, ObsRecord, PerCoreCounter};

/// Per-worker count of futures polled. Bumped in `task::tick`
/// every `poll_slot` call — high-frequency, so this is the
/// cache-line-padded `PerCoreCounter` rather than a shared
/// `Counter`. Surfaces "which worker is polling most tasks?"
/// without instrumenting every `Future::poll`.
pub static TASKS_POLLED_PER_WORKER: PerCoreCounter<MAX_CORES> =
    PerCoreCounter::new();

#[inline]
pub fn bump_tasks_polled(worker_id: u32) {
    TASKS_POLLED_PER_WORKER.bump(worker_id);
}

/// One counter per task-lifecycle event.
pub struct Counters {
    /// Futures successfully placed in a worker's task arena.
    pub tasks_spawned: Counter,
    /// `spawn` calls that found the arena full — the future was
    /// **dropped** on the floor. Silent before this counter: a
    /// connection handler or timer that simply never ran. Read
    /// `LAST_SPAWN_FAILURE` for the worker.
    pub spawn_failures: Counter,
    /// Tasks whose future returned `Ready` — ran to completion.
    /// Pair with `tasks_spawned` to watch the live-task count.
    pub tasks_completed: Counter,
    /// Tasks torn down by `TaskHandle::abort` before completing.
    pub tasks_aborted: Counter,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            tasks_spawned: Counter::new(),
            spawn_failures: Counter::new(),
            tasks_completed: Counter::new(),
            tasks_aborted: Counter::new(),
        }
    }
}

/// Process-wide runtime counters.
pub static COUNTERS: Counters = Counters::new();

/// Most recent `spawn` failure — which worker's arena was full.
pub static LAST_SPAWN_FAILURE: LastEvent<SpawnFailRecord> = LastEvent::new();

/// Snapshot payload for `LAST_SPAWN_FAILURE`. The executor has no
/// wall clock of its own, so this carries only the worker id — the
/// `LastEvent` count supplies "how many".
#[derive(Clone, Copy)]
pub struct SpawnFailRecord {
    pub worker_id: u32,
}

impl ObsRecord for SpawnFailRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(w, "\"worker_id\":{}", self.worker_id)
    }
}

/// Record a `spawn` failure: bump `spawn_failures` and snapshot the
/// worker into `LAST_SPAWN_FAILURE`.
pub fn record_spawn_failure(worker_id: u32) {
    COUNTERS.spawn_failures.bump();
    LAST_SPAWN_FAILURE.record(SpawnFailRecord { worker_id });
}

/// Counter `(name, value)` pairs in declaration order.
pub fn snapshot() -> [(&'static str, u64); 4] {
    let c = &COUNTERS;
    [
        ("tasks_spawned", c.tasks_spawned.get()),
        ("spawn_failures", c.spawn_failures.get()),
        ("tasks_completed", c.tasks_completed.get()),
        ("tasks_aborted", c.tasks_aborted.get()),
    ]
}

/// Per-worker `tasks_polled` array as a JSON-list-format string.
/// Surfaced inside the runtime `/obs` block so callers can read
/// the slice without knowing `MAX_WORKERS_DIAG`.
pub fn write_tasks_polled_json(w: &mut dyn fmt::Write) -> fmt::Result {
    w.write_str("[")?;
    for (i, v) in TASKS_POLLED_PER_WORKER.snapshot().iter().enumerate() {
        if i > 0 {
            w.write_str(",")?;
        }
        write!(w, "{v}")?;
    }
    w.write_str("]")
}

/// Render the runtime observability block as a JSON object — the
/// task-lifecycle counters plus the `LAST_SPAWN_FAILURE` snapshot.
/// This is the runtime's `/obs` block.
pub fn write_obs_json(w: &mut dyn fmt::Write) -> fmt::Result {
    w.write_str("{")?;
    for (name, value) in snapshot() {
        write!(w, "\"{name}\":{value},")?;
    }
    w.write_str("\"tasks_polled_per_worker\":")?;
    write_tasks_polled_json(w)?;
    w.write_str(",")?;
    LAST_SPAWN_FAILURE.write_json(w, "last_spawn_failure")?;
    w.write_str("}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn record_spawn_failure_bumps_counter_and_snapshot() {
        let before = COUNTERS.spawn_failures.get();
        record_spawn_failure(3);
        assert_eq!(COUNTERS.spawn_failures.get(), before + 1);
        let (_, last) = LAST_SPAWN_FAILURE.snapshot();
        assert_eq!(last.expect("recorded").worker_id, 3);
    }

    #[test]
    fn write_obs_json_is_one_object() {
        let mut s = String::new();
        write_obs_json(&mut s).unwrap();
        assert!(s.starts_with('{') && s.ends_with('}'));
        assert!(s.contains("\"tasks_spawned\":"));
        assert!(s.contains("\"last_spawn_failure\":{\"count\":"));
    }
}
