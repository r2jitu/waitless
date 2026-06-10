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

// ── Wall-clock (Unix time) ───────────────────────────────────────────
//
// `now_ms` above is *monotonic* (since-boot) — perfect for RTO / RTT /
// timeouts, but it has no relation to civil time. The wall clock adds a
// real Unix-epoch time source for log timestamps, TLS-ticket absolute
// age, and a cert-expiry self-check. It is read once from the platform
// RTC at boot (`//crates/kernel/bare`), converted to a Unix-epoch base
// via the pure `civil_to_unix_secs` below, and combined with `now_ms`'s
// monotonic offset at read time.

/// Convert a civil UTC date-time to seconds since the Unix epoch
/// (1970-01-01 00:00:00). Pure integer math — the days-from-civil
/// algorithm (H. Hinnant), valid for any Gregorian date the RTC reports
/// (year ≥ 1970 for our use). Leap years and centuries are handled
/// exactly. Host-unit-tested against known epoch values.
pub fn civil_to_unix_secs(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> u64 {
    // Shift March-based so the leap day falls at the end of the year.
    let y = year as i64 - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = month as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + doe - 719468; // days since 1970-01-01
    let secs = days * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
    secs.max(0) as u64
}

/// Wall-clock time in seconds since the Unix epoch, or `0` when no RTC
/// is available (e.g. an aarch64 platform whose RTC we don't map). `0`
/// is an unambiguous "unknown" sentinel — a real boot is never in 1970.
#[cfg(target_os = "none")]
#[inline]
pub fn wall_unix_secs() -> u64 {
    unsafe extern "Rust" {
        fn __kernel_bare_wall_unix_secs() -> u64;
    }
    // SAFETY: `//crates/kernel/bare` defines this symbol, same link
    // contract as `__kernel_bare_now_ms`.
    unsafe { __kernel_bare_wall_unix_secs() }
}

/// Host build: no platform RTC — wall time is unavailable (`0`).
#[cfg(not(target_os = "none"))]
#[inline]
pub fn wall_unix_secs() -> u64 {
    0
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

    #[test]
    fn civil_to_unix_matches_known_epochs() {
        // The Unix epoch itself.
        assert_eq!(civil_to_unix_secs(1970, 1, 1, 0, 0, 0), 0);
        // Y2K midnight UTC.
        assert_eq!(civil_to_unix_secs(2000, 1, 1, 0, 0, 0), 946_684_800);
        // 2021-01-01 00:00:00 UTC.
        assert_eq!(civil_to_unix_secs(2021, 1, 1, 0, 0, 0), 1_609_459_200);
        // The Y2038 boundary: 2038-01-19 03:14:07 UTC = i32::MAX seconds.
        assert_eq!(civil_to_unix_secs(2038, 1, 19, 3, 14, 7), 2_147_483_647);
        // A leap day — 2024-02-29 12:00:00 UTC.
        assert_eq!(civil_to_unix_secs(2024, 2, 29, 12, 0, 0), 1_709_208_000);
        // Time-of-day adds correctly (epoch + 1h 1m 1s).
        assert_eq!(civil_to_unix_secs(1970, 1, 1, 1, 1, 1), 3661);
        // The day after a leap day is contiguous.
        assert_eq!(
            civil_to_unix_secs(2024, 3, 1, 0, 0, 0),
            civil_to_unix_secs(2024, 2, 29, 0, 0, 0) + 86_400,
        );
    }

    #[test]
    fn wall_clock_unavailable_on_host() {
        // No platform RTC on the host build → the `0` sentinel.
        assert_eq!(wall_unix_secs(), 0);
    }
}
