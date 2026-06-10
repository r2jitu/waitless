// crates/util/obs — shared observability primitives.
//
// A handful of small primitives every subsystem (QUIC, NIC, TCP,
// runtime, kernel) uses to make failures diagnosable WITHOUT a
// redeploy:
//
//   * `Counter`        — "how many times did this happen?"
//   * `PerCoreCounter` — a per-core-sharded `Counter` for hot paths
//   * `LastEvent<T>`   — "what did the most recent one look like?"
//   * `LatencyHist`    — fixed-bucket latency distribution
//
// `Counter` + `LastEvent` are the core pair. The pair exists
// because a bare count is a question, not an
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
//
// A leaf crate: depends only on `//crates/util/sync`. That is what
// lets crates below `kernel_core` (the async runtime) use it.

#![cfg_attr(not(test), no_std)]

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::Spinlock;

/// Read the CPU cycle counter — `rdtsc` on x86_64, the virtual count
/// `CNTVCT_EL0` on aarch64 (real cycles on GCE; ~24 MHz ticks on native
/// arm64, so use it for *ratios*, not absolute timings). `0` on any other
/// target. The single source of truth for the per-region cycle deltas the
/// `obs`-using crates profile with: it lives here, in the leaf crate they
/// already depend on, so it pulls in no `kernel_core` dependency (proto
/// crates sit above the kernel only via the reactor).
#[inline(always)]
pub fn now_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let v: u64;
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack));
        v
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

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

/// Per-core sharded counter for the genuinely-hot path: each core
/// gets its own cache-line-aligned `AtomicU64`, so writes are
/// uncontended (the line never leaves the writing core's L1).
/// Readers sum across cores. Use when a `Counter` shows up as a
/// cache-line ping-pong in profiles — the obvious cases are
/// per-packet and per-task-poll counters; the rest of the obs
/// doctrine ("single shared Counter is fine") still applies to
/// cold paths.
///
/// `N` is the per-core array width; pass the platform's
/// `MAX_CORE_STATS` (or equivalent ceiling). Cores beyond `N`
/// silently no-op their writes (same shape as `Counter` and the
/// existing per-core stats arrays in `kernel_bare::eventloop`).
///
/// Storage cost is `N * 64` bytes (one cache line per core). At
/// 22 cores that's 1.4 KB per counter — non-trivial vs a single
/// `Counter`, so keep this for genuinely hot paths and not the
/// default.
#[repr(C, align(64))]
pub struct PerCoreCell(AtomicU64);

impl PerCoreCell {
    pub const fn new() -> Self {
        PerCoreCell(AtomicU64::new(0))
    }
}

impl Default for PerCoreCell {
    fn default() -> Self {
        Self::new()
    }
}

// The whole point of `PerCoreCell` is that an array of them places
// each shard on its own cache line. A future field add inside the
// struct (or losing `align(64)`) would silently break that and
// regress the per-core counter perf invariant; pin the layout here.
const _: () = assert!(core::mem::size_of::<PerCoreCell>() == 64);
const _: () = assert!(core::mem::align_of::<PerCoreCell>() == 64);

/// Default per-core array width for shared per-core counters.
/// Matches the platform's `MAX_CORE_STATS` in
/// `kernel_bare::eventloop`; lives here in the `obs` leaf crate so
/// per-core `Counter` consumers
/// (`net::tcp::diag::HASH_FIND_PROBES`,
/// `runtime::executor::diag::TASKS_POLLED_PER_WORKER`) can size
/// their shards from a single source of truth.
///
/// **If you lift this**: also bump `kernel_bare::eventloop::MAX_CORE_STATS`
/// (which controls `CORE_STATS` array width) and
/// `crates/drivers/gve/src/lib.rs::MAX_QUEUE_PAIRS`. The three are
/// independently named for historic reasons but must agree.
pub const MAX_CORES: usize = 22;

pub struct PerCoreCounter<const N: usize> {
    cells: [PerCoreCell; N],
}

impl<const N: usize> PerCoreCounter<N> {
    /// Fresh zero-valued shards. `const` for `static` placement.
    pub const fn new() -> Self {
        PerCoreCounter {
            cells: [const { PerCoreCell::new() }; N],
        }
    }

    /// Increment the calling core's shard by 1.
    #[inline]
    pub fn bump(&self, core: u32) {
        self.add(core, 1);
    }

    /// Increment the calling core's shard by `n`.
    #[inline]
    pub fn add(&self, core: u32, n: u64) {
        if let Some(c) = self.cells.get(core as usize) {
            c.0.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Sum across all shards. Lossy under concurrent writes (same
    /// trade-off as `Counter::get`).
    pub fn sum(&self) -> u64 {
        self.cells
            .iter()
            .map(|c| c.0.load(Ordering::Relaxed))
            .sum()
    }

    /// Per-core snapshot. Caller decides how many entries are
    /// meaningful for the live worker count.
    pub fn snapshot(&self) -> [u64; N] {
        let mut out = [0u64; N];
        for (i, c) in self.cells.iter().enumerate() {
            out[i] = c.0.load(Ordering::Relaxed);
        }
        out
    }
}

impl<const N: usize> Default for PerCoreCounter<N> {
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

/// Number of log2 buckets in a [`LatencyHist`]. Bucket `b` holds
/// samples in `[2^b, 2^(b+1))` of whatever unit the caller records;
/// bucket 0 also catches a sample of `0`. Twenty buckets span 1 ..
/// ~1.05M units — 1 µs .. ~1 s for the QUIC microsecond histograms —
/// and anything larger saturates into the top bucket.
pub const HIST_BUCKETS: usize = 20;

/// A fixed-bucket log2 latency histogram — the performance-pillar
/// counterpart of [`Counter`]. Unit-agnostic: the caller records
/// whatever monotonic quantity it likes (the QUIC stack records
/// microseconds; the unit goes in the field name).
///
/// `record` is one `leading_zeros` plus ~5 relaxed atomics — the
/// cost class of a `Counter`, not of a `LastEvent`. That is what
/// makes it sound on a warm path: per-request, and (deliberately)
/// per-datagram, sampling is fine. What stays forbidden is
/// per-packet allocation, formatting, or locking. See the
/// performance-observability section of `docs/observability.md`.
pub struct LatencyHist {
    buckets: [AtomicU64; HIST_BUCKETS],
    count: AtomicU64,
    /// Sum of all samples, for the mean. Saturates rather than wraps
    /// — at µs scale that is centuries of traffic, but a wrapped mean
    /// would be a silently wrong number, which the doctrine forbids.
    sum: AtomicU64,
    min: AtomicU64,
    max: AtomicU64,
}

/// Plain-data snapshot of a [`LatencyHist`], for tests and rendering.
#[derive(Clone, Copy)]
pub struct HistSnapshot {
    pub count: u64,
    pub sum: u64,
    /// `0` when `count == 0` (the live `min` slot sits at `u64::MAX`).
    pub min: u64,
    pub max: u64,
    pub buckets: [u64; HIST_BUCKETS],
}

impl LatencyHist {
    /// An empty histogram. `const` so it can live in a `static`.
    pub const fn new() -> Self {
        LatencyHist {
            buckets: [const { AtomicU64::new(0) }; HIST_BUCKETS],
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            // Empty `min` sits at the top so the first real sample
            // always wins the `fetch_min`.
            min: AtomicU64::new(u64::MAX),
            max: AtomicU64::new(0),
        }
    }

    /// Record one `sample` (in the caller's unit).
    #[inline]
    pub fn record(&self, sample: u64) {
        // floor(log2(sample)); sample 0 and 1 both land in bucket 0.
        let idx = if sample < 2 {
            0
        } else {
            (63 - sample.leading_zeros() as usize).min(HIST_BUCKETS - 1)
        };
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        let mut s = self.sum.load(Ordering::Relaxed);
        loop {
            let n = s.saturating_add(sample);
            match self
                .sum
                .compare_exchange_weak(s, n, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(cur) => s = cur,
            }
        }
        self.min.fetch_min(sample, Ordering::Relaxed);
        self.max.fetch_max(sample, Ordering::Relaxed);
    }

    /// Read the histogram out as plain data.
    pub fn snapshot(&self) -> HistSnapshot {
        let mut buckets = [0u64; HIST_BUCKETS];
        for (i, b) in self.buckets.iter().enumerate() {
            buckets[i] = b.load(Ordering::Relaxed);
        }
        let count = self.count.load(Ordering::Relaxed);
        HistSnapshot {
            count,
            sum: self.sum.load(Ordering::Relaxed),
            min: if count == 0 {
                0
            } else {
                self.min.load(Ordering::Relaxed)
            },
            max: self.max.load(Ordering::Relaxed),
            buckets,
        }
    }

    /// Render as one JSON object member:
    /// `"<name>":{"count":N,"min":..,"max":..,"mean":..,"p50":..,"p99":..,"buckets":[..]}`.
    /// An empty histogram renders `"<name>":{"count":0}` — the same
    /// uniform shape `LastEvent` uses. `p50`/`p99` are the *lower
    /// bound* of the bucket the percentile falls in: a log2
    /// histogram only resolves to a power of two, so the true value
    /// is "at least this". The raw `buckets` array is emitted too
    /// for consumers that want to compute their own.
    pub fn write_json(&self, w: &mut dyn fmt::Write, name: &str) -> fmt::Result {
        let s = self.snapshot();
        write!(w, "\"{name}\":{{\"count\":{}", s.count)?;
        if s.count > 0 {
            write!(
                w,
                ",\"min\":{},\"max\":{},\"mean\":{},\"p50\":{},\"p99\":{},\"buckets\":[",
                s.min,
                s.max,
                s.sum / s.count,
                percentile_lo(&s.buckets, s.count, 50),
                percentile_lo(&s.buckets, s.count, 99),
            )?;
            for (i, b) in s.buckets.iter().enumerate() {
                if i > 0 {
                    w.write_str(",")?;
                }
                write!(w, "{b}")?;
            }
            w.write_str("]")?;
        }
        w.write_str("}")
    }
}

impl Default for LatencyHist {
    fn default() -> Self {
        Self::new()
    }
}

/// Lower bound of the bucket at which the cumulative count first
/// reaches `pct`% of `total`. Approximate by construction — a log2
/// histogram resolves only to a power of two.
fn percentile_lo(buckets: &[u64; HIST_BUCKETS], total: u64, pct: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    let target = total.saturating_mul(pct) / 100;
    let mut cum = 0u64;
    for (b, &n) in buckets.iter().enumerate() {
        cum += n;
        if cum >= target {
            return if b == 0 { 0 } else { 1u64 << b };
        }
    }
    1u64 << (HIST_BUCKETS - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;

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

    #[test]
    fn hist_buckets_are_floor_log2() {
        let h = LatencyHist::new();
        h.record(0); // bucket 0
        h.record(1); // bucket 0  ([1,2))
        h.record(2); // bucket 1  ([2,4))
        h.record(3); // bucket 1
        h.record(1000); // bucket 9  (2^9=512 ≤ 1000 < 1024)
        let s = h.snapshot();
        assert_eq!(s.count, 5);
        assert_eq!(s.buckets[0], 2);
        assert_eq!(s.buckets[1], 2);
        assert_eq!(s.buckets[9], 1);
        assert_eq!(s.min, 0);
        assert_eq!(s.max, 1000);
        assert_eq!(s.sum, 1006);
    }

    #[test]
    fn hist_oversized_sample_saturates_into_top_bucket() {
        let h = LatencyHist::new();
        h.record(u64::MAX);
        let s = h.snapshot();
        assert_eq!(s.buckets[HIST_BUCKETS - 1], 1);
    }

    #[test]
    fn hist_empty_renders_uniform_shape() {
        let h = LatencyHist::new();
        let mut s = String::new();
        h.write_json(&mut s, "request_latency_us").unwrap();
        assert_eq!(s, "\"request_latency_us\":{\"count\":0}");
    }

    #[test]
    fn hist_percentiles_track_the_distribution() {
        let h = LatencyHist::new();
        // 99 fast samples (~100 µs) + 1 slow one (~9 ms).
        for _ in 0..99 {
            h.record(100);
        }
        h.record(9_000);
        let s = h.snapshot();
        assert_eq!(s.count, 100);
        // p50 sits in the 100 µs bucket (2^6=64 ≤ 100 < 128).
        assert_eq!(percentile_lo(&s.buckets, s.count, 50), 64);
        // p99 still in the fast bucket; the lone slow sample is p100.
        assert_eq!(percentile_lo(&s.buckets, s.count, 99), 64);
        let mut out = String::new();
        h.write_json(&mut out, "request_latency_us").unwrap();
        assert!(out.contains("\"count\":100"));
        assert!(out.contains("\"max\":9000"));
        assert!(out.contains("\"p50\":64"));
    }
}
