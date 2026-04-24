// uni-runtime/src/startup.rs — per-worker startup-hook cursor.
//
// `spawn_on_each_worker(f)` appends `f` to a fixed-size table. Each
// worker's `tick()` calls `pending_range(total, fired)` to decide
// which slots to fire on this tick, and bumps its `fired` cursor
// forward. Hooks registered from *inside* a worker's own boot task
// (e.g. `TcpListener::run` during `uni::run(app)`) advance `total`
// after that worker's first-tick fire; the next tick sees `fired <
// total` and runs just the new hooks.
//
// The logic is trivial but regression-prone — an earlier one-shot
// `STARTUP_FIRED[worker]` flag missed late-registered hooks
// entirely, which silently broke accept-task spawn-on-boot-task. The
// tests below pin the documented behaviour so that bug can't sneak
// back.

/// Maximum number of per-worker startup hooks. Declared here (not in
/// `lib.rs`) so the test file can reference the exact same
/// constant without a cross-file `use` path that would require
/// wiring up the rest of `uni-runtime` for the standalone test
/// compile.
pub const MAX_STARTUP_HOOKS: usize = 8;

/// Given the global hook count and this worker's fired-count cursor,
/// return the slot range the worker should fire on this tick. Any
/// value beyond `MAX_STARTUP_HOOKS` is clamped — once the table is
/// full, further registrations are dropped by the caller, so we
/// never fire past the cap either.
///
/// Empty range = nothing to do (caller skips the loop and doesn't
/// touch the atomic cursor). Caller stores `range.end` back into
/// the fired-count cell after firing.
#[inline]
pub fn pending_range(total: usize, fired: usize) -> core::ops::Range<usize> {
    let clamped = if total > MAX_STARTUP_HOOKS {
        MAX_STARTUP_HOOKS
    } else {
        total
    };
    if fired >= clamped {
        0..0
    } else {
        fired..clamped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_worker_fires_everything_registered_so_far() {
        // A worker that's never ticked sees `fired = 0` and should
        // fire every hook registered at the time of the tick.
        assert_eq!(pending_range(0, 0), 0..0);
        assert_eq!(pending_range(1, 0), 0..1);
        assert_eq!(pending_range(3, 0), 0..3);
    }

    #[test]
    fn already_fired_worker_is_idempotent_when_no_new_hooks() {
        // Worker ticked once with 3 hooks registered; next tick must
        // NOT re-fire them. This is the "one-shot" half of the
        // contract — catches a regression to e.g. always-return
        // `0..total`.
        assert_eq!(pending_range(3, 3), 0..0);
        assert_eq!(pending_range(1, 1), 0..0);
    }

    #[test]
    fn late_registration_fires_only_new_hooks_on_next_tick() {
        // THE key regression case: worker fired 2 hooks, boot task
        // then called `spawn_on_each_worker` once more (total=3).
        // Next tick must fire slot 2 and only slot 2.
        assert_eq!(pending_range(3, 2), 2..3);

        // Two more hooks register between ticks.
        assert_eq!(pending_range(5, 2), 2..5);
    }

    #[test]
    fn clamps_at_max_when_total_overflows_table() {
        // `STARTUP_HOOK_COUNT` uses `fetch_add` with no cap, so
        // callers past the cap increment the counter without
        // storing into the table. Firing must still respect the
        // table size — no out-of-bounds slot access.
        assert_eq!(
            pending_range(MAX_STARTUP_HOOKS + 5, 0),
            0..MAX_STARTUP_HOOKS,
        );

        // fired has already caught up to the cap; extra overflow
        // registrations must not re-open the range.
        assert_eq!(
            pending_range(MAX_STARTUP_HOOKS + 5, MAX_STARTUP_HOOKS),
            0..0,
        );
    }

    #[test]
    fn handles_fired_past_total_gracefully() {
        // Shouldn't happen under `fetch_add`-only semantics, but if
        // someone ever reorders stores and observes `fired > total`
        // for a tick, we must not panic or produce a backwards
        // range (start > end would underflow in the Iterator::skip
        // consumer).
        assert_eq!(pending_range(1, 5), 0..0);
        assert_eq!(pending_range(0, 3), 0..0);
    }
}
