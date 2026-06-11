// crates/proto/quic/src/time.rs — QUIC's single clock seam.
//
// Architecture-audit direction #1 (ambient authority → injected
// capabilities), first increment: every µs-since-boot read in this crate
// goes through here instead of reaching for `tls::ticket::now_us`
// directly. Production behavior is identical (one `#[inline]` forward);
// the value is the seam — host tests can install a mock clock and drive
// PTO / loss-detection / idle-timeout / pacing deterministically, which
// is the precondition for the simulated-world harness (direction #2).

/// Microseconds since boot — the same monotonic reader QUIC has always
/// used (`tls::ticket::now_us`), behind the crate's one clock seam.
#[cfg(all(not(test), target_os = "none"))]
#[inline(always)]
pub(crate) fn now_us() -> u64 {
    tls::ticket::now_us()
}

/// Host (non-bare-metal) builds: the real reader returns a constant 0
/// (`tls::ticket::now_us`'s documented native fallback), which would
/// freeze every time-driven mechanism — notably the egress pacer's
/// token refill — for DEPENDENT crates' tests, where this crate is
/// compiled without `cfg(test)` and the thread-local mock below
/// doesn't exist. Route through the process-global virtual clock
/// instead: identical behavior (0) until a test pins it via
/// [`crate::sim_clock`]. Bare-metal never compiles this arm.
#[cfg(all(not(test), not(target_os = "none")))]
#[inline(always)]
pub(crate) fn now_us() -> u64 {
    host_clock::now_us()
}

#[cfg(test)]
pub(crate) use mock::now_us;

/// Process-global virtual clock for host builds (see [`now_us`]).
/// Monotonic-only mutation (`fetch_max` / `fetch_add`) so parallel
/// host tests sharing the process can each push time forward without
/// ever observing a backward jump.
#[cfg(all(not(test), not(target_os = "none")))]
pub(crate) mod host_clock {
    use core::sync::atomic::{AtomicU64, Ordering};

    static VIRT_US: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn now_us() -> u64 {
        let v = VIRT_US.load(Ordering::Relaxed);
        if v != 0 { v } else { tls::ticket::now_us() }
    }

    /// Raise the virtual instant to at least `us`.
    pub(crate) fn pin_at_least(us: u64) {
        VIRT_US.fetch_max(us, Ordering::Relaxed);
    }

    /// Advance the virtual instant by `d` µs.
    pub(crate) fn advance(d: u64) {
        VIRT_US.fetch_add(d, Ordering::Relaxed);
    }
}

/// Test clock. Defaults to forwarding to the real reader, so tests that
/// don't care about time are unaffected; a test that does calls
/// `mock::set` / `mock::advance` and the whole crate observes the
/// virtual instant. Thread-local, so parallel host tests don't race.
#[cfg(test)]
pub(crate) mod mock {
    use core::cell::Cell;

    std::thread_local! {
        static NOW_US: Cell<Option<u64>> = const { Cell::new(None) };
    }

    pub(crate) fn now_us() -> u64 {
        NOW_US.with(|c| c.get()).unwrap_or_else(tls::ticket::now_us)
    }

    /// Pin the clock to an absolute virtual instant.
    pub(crate) fn set(us: u64) {
        NOW_US.with(|c| c.set(Some(us)));
    }

    /// Advance the (pinned or real-sampled) clock by `d` µs.
    pub(crate) fn advance(d: u64) {
        let cur = now_us();
        NOW_US.with(|c| c.set(Some(cur + d)));
    }
}

#[cfg(test)]
mod tests {
    /// The seam contract: pinned → exactly the virtual instant;
    /// `advance` moves it. (Unpinned forwards to the real reader,
    /// which on a host test is `tls::ticket::now_us`'s documented
    /// native fallback of 0 — not asserted here.)
    #[test]
    fn mock_clock_pins_and_advances() {
        super::mock::set(1_000_000);
        assert_eq!(super::now_us(), 1_000_000);
        super::mock::advance(250_000);
        assert_eq!(super::now_us(), 1_250_000);
    }
}
