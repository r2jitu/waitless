// kernel_core/obs.rs — shared observability primitives.
//
// Two cold-path types every subsystem (QUIC, NIC, TCP, runtime,
// kernel) uses to make failures diagnosable WITHOUT a redeploy:
//
//   * `Counter`     — "how many times did this happen?"
//   * `LastEvent<T>` — "what did the most recent one look like?"
//
// The pair exists because a bare count is a question, not an
// answer. The QUIC h3-over-gve bug needed three round trips —
// add instrumentation, redeploy to GCE, reproduce — because the
// stack *counted* idle timeouts but discarded the one fact that
// settled it: the connection's last datagram had arrived 81 ms
// into a 30 s idle window, so the timeout was spurious. A counter
// retained "idle_timeouts += 1"; nothing retained the 81 ms. A
// `LastEvent` beside the counter would have.
//
// See `docs/observability.md` for the doctrine these types serve
// and the per-subsystem rollout checklist.
//
// Cost model. `Counter` is one relaxed atomic add — cheap enough
// for warm paths, though not free under many-core contention on a
// single line (see the per-core note on `Counter`). `LastEvent`
// takes a `Spinlock`, so it is COLD PATH ONLY: record connection
// teardowns, protocol errors, anomalies — never per-packet events.

use crate::sync::Spinlock;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

/// A process-wide monotonic event counter.
///
/// One `AtomicU64`, relaxed ordering throughout: increments from
/// any core, reads from the stats endpoint. Reads are intentionally
/// lossy — a snapshot taken mid-increment may miss the last bump or
/// two, which is fine for diagnostics and saves a fence.
///
/// Per-core sharding note: a single shared line is fine for the
/// cold-path counters this doctrine is mostly about (drops, exits,
/// anomalies — rare by construction). A genuinely hot counter
/// (per-packet) that shows up in a profile as cache-line ping-pong
/// is the signal to shard it per-core and sum on read — but that
/// is a deliberate, measured change, not the default. Keep hot
/// counters out of `LastEvent` entirely.
#[repr(transparent)]
pub struct Counter(AtomicU64);

impl Counter {
    /// A fresh counter at zero. `const` so it can live in a `static`.
    pub const fn new() -> Self {
        Counter(AtomicU64::new(0))
    }

    /// Increment by one.
    #[inline]
    pub fn bump(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment by `n` — for byte/quantity counters.
    #[inline]
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    /// Current value. Lossy under concurrent increments by design.
    #[inline]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

/// A "last occurrence" snapshot slot: holds the decisive context of
/// the most recent time some category of event fired, plus a count
/// of how many times it has fired in total.
///
/// `T` is a small `Copy` payload — the invariant inputs a diagnosing
/// engineer would otherwise have to redeploy to capture (see the
/// module comment). Keep it `repr`-plain and a few dozen bytes at
/// most; it is copied in and out under the lock.
///
/// COLD PATH ONLY. `record` takes a `Spinlock`. It is meant for
/// events that are rare by construction — a connection closing, a
/// task exiting, a protocol violation. Never call it per packet.
pub struct LastEvent<T> {
    inner: Spinlock<Cell<T>>,
}

/// Interior of a `LastEvent`. `count == 0` ⇔ `last == None`.
struct Cell<T> {
    count: u64,
    last: Option<T>,
}

impl<T: Copy> LastEvent<T> {
    /// An empty slot — never recorded. `const` so it can live in a
    /// `static` beside the subsystem's counters.
    pub const fn new() -> Self {
        LastEvent {
            inner: Spinlock::new(Cell {
                count: 0,
                last: None,
            }),
        }
    }

    /// Record `ev` as the most recent occurrence and bump the count.
    #[inline]
    pub fn record(&self, ev: T) {
        let mut g = self.inner.lock();
        g.count = g.count.saturating_add(1);
        g.last = Some(ev);
    }

    /// `(count, most_recent)`. `count` is the total number of times
    /// the category fired; `most_recent` is `None` iff `count == 0`.
    pub fn snapshot(&self) -> (u64, Option<T>) {
        let g = self.inner.lock();
        (g.count, g.last)
    }
}

impl<T: Copy> Default for LastEvent<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A snapshot payload that can render itself as JSON. Lets
/// `LastEvent::write_json` emit a record without `obs` knowing the
/// payload's fields — each subsystem owns the field shape.
pub trait ObsRecord {
    /// Write this record's fields as JSON object members — no
    /// enclosing braces, no leading comma. e.g.
    /// `"error_code":256,"reason":"no_error"`. `LastEvent::write_json`
    /// supplies the braces and the `count` member.
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result;
}

impl<T: Copy + ObsRecord> LastEvent<T> {
    /// Render as one JSON object member: `"<name>":{"count":N,...}`.
    /// A slot that never fired renders `"<name>":{"count":0}` — the
    /// shape is uniform so consumers never special-case "absent".
    ///
    /// This is the render half of the doctrine's snapshot/render
    /// convention: a subsystem's stats endpoint calls `write_json`
    /// for each of its `LastEvent`s and `write!`s its `Counter`s
    /// flat. See `docs/observability.md`.
    pub fn write_json(&self, w: &mut dyn fmt::Write, name: &str) -> fmt::Result {
        let (count, last) = self.snapshot();
        write!(w, "\"{name}\":{{\"count\":{count}")?;
        if let Some(ev) = last {
            w.write_str(",")?;
            ev.write_fields(w)?;
        }
        w.write_str("}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn counter_bump_add_get() {
        let c = Counter::new();
        assert_eq!(c.get(), 0);
        c.bump();
        c.bump();
        assert_eq!(c.get(), 2);
        c.add(40);
        assert_eq!(c.get(), 42);
    }

    #[derive(Clone, Copy)]
    struct TestRec {
        code: u64,
        age_us: u64,
    }

    impl ObsRecord for TestRec {
        fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
            write!(w, "\"code\":{},\"age_us\":{}", self.code, self.age_us)
        }
    }

    #[test]
    fn last_event_starts_empty() {
        let ev: LastEvent<TestRec> = LastEvent::new();
        let (count, last) = ev.snapshot();
        assert_eq!(count, 0);
        assert!(last.is_none());
    }

    #[test]
    fn last_event_records_latest_and_counts() {
        let ev: LastEvent<TestRec> = LastEvent::new();
        ev.record(TestRec {
            code: 1,
            age_us: 100,
        });
        ev.record(TestRec {
            code: 2,
            age_us: 200,
        });
        let (count, last) = ev.snapshot();
        assert_eq!(count, 2);
        let last = last.expect("recorded twice");
        // snapshot retains the MOST RECENT occurrence.
        assert_eq!(last.code, 2);
        assert_eq!(last.age_us, 200);
    }

    #[test]
    fn write_json_empty_slot_is_uniform_shape() {
        let ev: LastEvent<TestRec> = LastEvent::new();
        let mut s = String::new();
        ev.write_json(&mut s, "last_thing").unwrap();
        assert_eq!(s, "\"last_thing\":{\"count\":0}");
    }

    #[test]
    fn write_json_renders_fields() {
        let ev: LastEvent<TestRec> = LastEvent::new();
        ev.record(TestRec {
            code: 7,
            age_us: 81_000,
        });
        let mut s = String::new();
        ev.write_json(&mut s, "last_thing").unwrap();
        assert_eq!(
            s,
            "\"last_thing\":{\"count\":1,\"code\":7,\"age_us\":81000}"
        );
    }
}
