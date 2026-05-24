// kernel_core/clock.rs — host-buildable monotonic-clock link seam.
//
// `now_ms()` is the monotonic-millisecond time source for the
// host-buildable crates that sit below `//crates/waitless` and so cannot reach a
// `//crates/kernel/bare` clock directly — chiefly `tcp`, whose RFC 6298
// retransmission timer needs a coarse wall-clock.
//
// It mirrors the `cpu_id` / `rng::fill_bytes` link seams:
//
//   * `target_os = "none"` → resolves, via the `extern "Rust"` symbol
//     `__kernel_bare_now_ms`, to `//crates/kernel/bare`'s real cycle-counter clock
//     (`time::since_boot_us() / 1000`). `kernel_core` is the lower
//     crate and cannot call up into `//crates/kernel/bare`, so it declares the
//     symbol and `//crates/kernel/bare` defines it.
//
//   * host build → a process-global, **test-controllable** counter.
//     This is the deliberate difference from the other two seams: the
//     rng seam is deterministic but not settable, and `cpu_id` is a
//     fixed `0`, but a timer-driven test must be able to *advance*
//     time arbitrarily. So the host backend is a plain `AtomicU64`
//     that `mock::set` / `mock::advance` drive — a test scripts a
//     send, drops the ACK, advances the clock past the RTO, and
//     asserts the retransmit fired.
//
// Milliseconds (not the kernel's raw cycle counter) because every
// consumer — RTO, TIME-WAIT, delayed-ACK — works in the ms/second
// domain. A cycles seam would force a second seam for the arch-
// specific cycles-per-µs conversion; one ms seam is directly usable.

/// Monotonic milliseconds. Never decreases on the bare-metal target;
/// the host backend moves only when a test drives [`mock`].
///
/// Compile-time `cfg`, not a function pointer: the bare-metal path is
/// a single direct call into the seam symbol.
#[cfg(target_os = "none")]
#[inline]
pub fn now_ms() -> u64 {
    unsafe extern "Rust" {
        fn __kernel_bare_now_ms() -> u64;
    }
    // SAFETY: `//crates/kernel/bare` defines this `#[no_mangle]` symbol, and every
    // `os:none` binary that links `kernel_core` also links `//crates/kernel/bare`
    // (it is the foundational crate).
    unsafe { __kernel_bare_now_ms() }
}

/// Host build: the test-controllable mock clock.
#[cfg(not(target_os = "none"))]
#[inline]
pub fn now_ms() -> u64 {
    mock::now_ms()
}

/// Monotonic hardware cycle counter — TSC on x86_64, CNTVCT_EL0 on
/// aarch64. Cheap single-instruction read; intended for in-loop
/// instrumentation of hot paths (e.g. cycles-per-`tcp_receive`).
///
/// On `target_os = "none"` resolves to `//crates/kernel/bare`'s
/// `time::now_cycles` via the `__kernel_bare_now_cycles` link seam.
/// On host builds reads from the same monotonic counter `now_ms`
/// uses (a u64 the test mock advances). Unit-tested code should
/// avoid relying on the *meaning* of the cycle value on host (it's
/// not a real CPU counter there) — diffs are still well-ordered.
#[cfg(target_os = "none")]
#[inline]
pub fn now_cycles() -> u64 {
    unsafe extern "Rust" {
        fn __kernel_bare_now_cycles() -> u64;
    }
    // SAFETY: same link contract as `__kernel_bare_now_ms` above.
    unsafe { __kernel_bare_now_cycles() }
}

/// Host build: mirror `now_ms` for ordering. Cycle deltas are
/// meaningless on host but the value is monotonic, which is all
/// the tests / mock-driven code needs.
#[cfg(not(target_os = "none"))]
#[inline]
pub fn now_cycles() -> u64 {
    mock::now_ms()
}

/// Host-only test clock. Compiled out of every `os:none` build, so
/// production code can neither reach nor advance it — exactly as the
/// rng seam's host stream is unreachable on bare metal.
#[cfg(not(target_os = "none"))]
pub mod mock {
    use core::sync::atomic::{AtomicU64, Ordering};

    /// The host clock, in milliseconds. Starts at 0; only `set` /
    /// `advance` move it.
    static NOW_MS: AtomicU64 = AtomicU64::new(0);

    /// Read the mock clock.
    pub fn now_ms() -> u64 {
        NOW_MS.load(Ordering::Relaxed)
    }

    /// Set the mock clock to an absolute millisecond value.
    pub fn set(ms: u64) {
        NOW_MS.store(ms, Ordering::Relaxed);
    }

    /// Advance the mock clock by `ms` milliseconds.
    pub fn advance(ms: u64) {
        NOW_MS.fetch_add(ms, Ordering::Relaxed);
    }

    /// Reset the mock clock to 0 — a test's setup calls this so a
    /// scenario never inherits time advanced by an earlier one.
    pub fn reset() {
        NOW_MS.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test function: `mock`'s `NOW_MS` is a process-global, so
    // splitting the assertions across `#[test]` fns would race under
    // the parallel test runner. Driven sequentially here, it is
    // deterministic.
    #[test]
    fn mock_clock_resets_advances_and_sets() {
        mock::reset();
        assert_eq!(now_ms(), 0, "a freshly reset clock reads zero");

        mock::advance(250);
        assert_eq!(now_ms(), 250, "advance adds to the current value");
        mock::advance(1_000);
        assert_eq!(now_ms(), 1_250, "successive advances accumulate");

        mock::set(9_000);
        assert_eq!(now_ms(), 9_000, "set jumps to an absolute value");
        mock::set(42);
        assert_eq!(now_ms(), 42, "set is absolute — it can move the clock back");

        mock::reset();
        assert_eq!(now_ms(), 0, "reset returns the clock to zero");
    }
}
