// apps/webserver/src/endpoints.rs — machine-facing data +
// diagnostic endpoints (health, /obs aggregate, quic-stats, diag
// dumps, TLS profile).
//
// Split out of `main.rs`; see the crate-root doc comment there for
// the overall app shape.

use core::fmt::Write as _;

use http::Response;

pub(crate) const HEALTH_JSON: &[u8] = b"{\"status\":\"ok\",\"runtime\":\"waitless\",\"version\":\"0.1.0\"}";

/// All-zero bench-throughput body that lives in `.bss` — zero image
/// bytes. A plain `static [u8; N]` is an LLVM `constant` and lands in
/// `.rodata` (in the image) even all-zero; only *writable* zero data
/// goes in `.bss`. `UnsafeCell` makes the global writable-typed — it
/// is never actually written. Same shape as `BootInfoCell` in
/// `boot/entry.rs`.
pub(crate) struct ZeroBody<const N: usize>(core::cell::UnsafeCell<[u8; N]>);

// SAFETY: the buffer is never written — `get()` hands out only shared
// `&[u8]` views — so concurrent multi-core reads are sound.
unsafe impl<const N: usize> Sync for ZeroBody<N> {}

impl<const N: usize> ZeroBody<N> {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new([0u8; N]))
    }

    pub(crate) fn get(&self) -> &[u8] {
        // SAFETY: see the `Sync` impl — read-only, never mutated.
        let arr: &[u8; N] = unsafe { &*self.0.get() };
        arr
    }
}

/// Static bulk-throughput bodies. All-zero payloads sized for bench
/// workloads that measure data-plane throughput (encrypt + TX
/// descriptor + wire) without per-request dynamic rendering.
pub(crate) static STATIC_16K_BYTES: ZeroBody<{ 16 * 1024 }> = ZeroBody::new();
pub(crate) static STATIC_64K_BYTES: ZeroBody<{ 64 * 1024 }> = ZeroBody::new();
pub(crate) static STATIC_256K_BYTES: ZeroBody<{ 256 * 1024 }> = ZeroBody::new();
pub(crate) static STATIC_1M_BYTES: ZeroBody<{ 1024 * 1024 }> = ZeroBody::new();

/// Emit `"name":[v0,v1,...]` into `w` without a leading comma.
/// Caller manages comma separators between fields. `T: Display`
/// covers every numeric width the diagnostics endpoints use
/// (`u64`, `u16`, `u32`, ...) without per-type duplication.
pub(crate) fn emit_json_array<W, T>(w: &mut W, name: &str, slice: &[T])
where
    W: core::fmt::Write,
    T: core::fmt::Display,
{
    let _ = write!(w, "\"{}\":[", name);
    for (i, v) in slice.iter().enumerate() {
        if i > 0 {
            let _ = w.write_str(",");
        }
        let _ = write!(w, "{}", v);
    }
    let _ = w.write_str("]");
}

/// Pearson chi-squared statistic comparing `observed` to a uniform
/// expected distribution: `Σ (O_i − E)² / E` where
/// `E = total / observed.len()`. Returns the statistic ×100 so the
/// consumer can treat it as a fixed-point value (no float pull).
///
/// Interpretation, with `df = observed.len() - 1`:
///   * `chi² < 100·χ²_{0.95, df}`  → consistent with uniform.
///     For df=3 (4 qps): χ²_{0.95, 3} = 7.815, so chi² < 781.
///   * `chi² > 100·χ²_{0.999, df}` → highly skewed.
///     For df=3: χ²_{0.999, 3} = 16.27, so chi² > 1627.
///
/// Caveat: χ² scales linearly with total N, so at bench-scale
/// (10⁷+ packets) every detectable imbalance — even a 1.3× max/min
/// ratio — produces "highly skewed" by this threshold. Pair with
/// [`max_min_ratio_x100`] for a magnitude that doesn't grow with
/// the sample size.
///
/// Returns 0 when there's no traffic (or only one bucket) — readers
/// should treat 0 as "no data", not "perfectly balanced".
pub(crate) fn rss_chi_squared_x100(observed: &[u64]) -> u64 {
    let n = observed.len() as u64;
    if n < 2 {
        return 0;
    }
    let total: u64 = observed.iter().sum();
    if total == 0 {
        return 0;
    }
    let expected = total / n;
    if expected == 0 {
        // Every bucket is fractional; statistic isn't meaningful.
        return 0;
    }
    let mut acc: u64 = 0;
    for &o in observed {
        let diff = o.abs_diff(expected);
        // (diff² / expected) — at bench scale (≤ 10⁷ packets/q),
        // diff² fits in u64 with margin (10¹⁴ vs u64 max 1.8×10¹⁹).
        let term = diff.saturating_mul(diff) / expected;
        acc = acc.saturating_add(term);
    }
    acc.saturating_mul(100)
}

/// Peak-to-trough ratio of `observed` × 100. Returns
/// `max(observed) * 100 / max(min(observed), 1)`. A perfectly
/// uniform distribution returns 100; 200 means the hottest bucket
/// has 2× the load of the coldest. Independent of total volume,
/// so this stays meaningful at any traffic scale (unlike raw
/// chi-squared, which grows linearly with N).
///
/// Returns 0 when `observed` is empty or `max == 0`.
pub(crate) fn max_min_ratio_x100(observed: &[u64]) -> u64 {
    let mut min = u64::MAX;
    let mut max = 0u64;
    for &v in observed {
        if v < min {
            min = v;
        }
        if v > max {
            max = v;
        }
    }
    if max == 0 || min == u64::MAX {
        return 0;
    }
    max.saturating_mul(100) / min.max(1)
}

/// Render the `nic` block of `/obs`: the per-queue *distribution*
/// view — RX frame counts, used-ring cursors, TX packet / byte
/// counts, in-flight depth — plus the RSS-balance metrics derived
/// from it and the TX direct-fill pool saturation counters, then
/// the gve driver's own failure/throughput counters nested under
/// `"gve"`. Lets a monitoring agent see whether:
///   * RSS / per-core dispatch is spreading load evenly
///     (`rx_chi_squared_x100` / `rx_max_min_ratio_x100`, the `tx_`
///     pair — and the raw `rx_frames` / `tx_packets` arrays)
///   * the TX pool is undersized for the offered load
///     (`tx_small_full_spins` climbing)
///   * the linear-scan acquire path is wasting cycles
///     (`tx_small_avg_scan_x100` high relative to the pool size)
///   * TSO super-segments are saturating their pool
///     (`tx_big_full_returns` climbing)
///
/// The distribution arrays are driver-agnostic (gve or virtio-net,
/// whichever is active); the nested `"gve"` block is gve-specific
/// and reads all-zero under virtio-net.
fn write_nic_obs<W: core::fmt::Write>(w: &mut W) {
    let counts = waitless::diagnostics::net_rx_counts();
    let cursors = waitless::diagnostics::net_rx_used_cursors();
    let nqp = waitless::diagnostics::net_num_queue_pairs() as usize;
    let tx = waitless::diagnostics::net_tx_diag();

    // Project the (device_idx, driver_cursor) tuple into separate
    // u16 slices so `emit_json_array` can render them — the helper
    // emits `T: Display` and there's no Display impl for `(u16, u16)`.
    let n = nqp.min(cursors.len());
    let mut used_dev = [0u16; 8];
    let mut used_drv = [0u16; 8];
    for i in 0..n {
        used_dev[i] = cursors[i].0;
        used_drv[i] = cursors[i].1;
    }

    // RSS imbalance metrics. `chi_squared` is the Pearson statistic
    // for "is this consistent with uniform" (good for stat-sig
    // tests), but at bench-scale traffic volumes even a small
    // imbalance produces a huge chi² because the metric grows
    // linearly with N. `max_min_ratio` is the human-readable
    // companion: 100 = perfectly balanced, 200 = hottest qp gets
    // 2× the coldest qp's load, etc. Independent of N. RX side
    // reflects RSS hashing; TX reflects per-core dispatch.
    let rx_slice = &counts[..nqp.min(counts.len())];
    let rx_chi = rss_chi_squared_x100(rx_slice);
    let rx_ratio = max_min_ratio_x100(rx_slice);

    let _ = w.write_str("{");
    emit_json_array(w, "rx_frames", rx_slice);
    let _ = w.write_str(",");
    emit_json_array(w, "rx_used_dev", &used_dev[..n]);
    let _ = w.write_str(",");
    emit_json_array(w, "rx_used_drv", &used_drv[..n]);
    let _ = write!(
        w,
        ",\"num_queue_pairs\":{nqp},\
          \"rx_chi_squared_x100\":{rx_chi},\
          \"rx_max_min_ratio_x100\":{rx_ratio}",
    );

    if let Some(t) = tx {
        // Average scan depth: high values vs `small_pool_size`
        // motivate replacing the linear scan with a freelist.
        // Compute on the read side; emit as a fixed-point ratio
        // (×100) since we don't pull in float formatting.
        let avg_scan_x100 = if t.small_pool_acquires > 0 {
            (t.small_pool_scan_iters * 100) / t.small_pool_acquires
        } else {
            0
        };
        let tx_slice = &t.packets_per_qp[..nqp.min(t.packets_per_qp.len())];
        let inflight_slice = &t.inflight_per_qp[..nqp.min(t.inflight_per_qp.len())];
        let tx_chi = rss_chi_squared_x100(tx_slice);
        let tx_ratio = max_min_ratio_x100(tx_slice);
        let _ = w.write_str(",");
        emit_json_array(w, "tx_packets", tx_slice);
        let _ = w.write_str(",");
        emit_json_array(w, "tx_inflight", inflight_slice);
        let _ = write!(
            w,
            ",\"tx_chi_squared_x100\":{},\
              \"tx_max_min_ratio_x100\":{},\
              \"tx_small_pool_size\":{},\
              \"tx_big_pool_size\":{},\
              \"tx_small_acquires\":{},\
              \"tx_small_scan_iters\":{},\
              \"tx_small_avg_scan_x100\":{},\
              \"tx_small_full_spins\":{},\
              \"tx_big_acquires\":{},\
              \"tx_big_full_returns\":{}",
            tx_chi,
            tx_ratio,
            t.small_pool_size,
            t.big_pool_size,
            t.small_pool_acquires,
            t.small_pool_scan_iters,
            avg_scan_x100,
            t.small_pool_full_spins,
            t.big_pool_acquires,
            t.big_pool_full_returns,
        );
        let tx_bytes = &t.tx_bytes_per_qp[..nqp.min(t.tx_bytes_per_qp.len())];
        let rx_bytes = &t.rx_bytes_per_qp[..nqp.min(t.rx_bytes_per_qp.len())];
        let _ = w.write_str(",");
        emit_json_array(w, "tx_bytes", tx_bytes);
        let _ = w.write_str(",");
        emit_json_array(w, "rx_bytes", rx_bytes);
    }

    // The gve driver's own failure / throughput counters + the
    // `LAST_RX_SKIP` snapshot, nested as `"gve"`.
    let _ = w.write_str(",\"gve\":");
    waitless::diagnostics::nic_obs_json(&mut *w);
    let _ = w.write_str("}");
}

/// Render the `event_loop` block of `/obs`: per-core event-loop
/// occupancy. Captures the numbers most directly relevant to "are
/// we CPU- or network-bound?":
///   * `core_idle_cycles / (busy + idle)` → idle fraction; high =
///     plenty of CPU headroom, low = CPU-bound.
///   * `core_service_work` rate vs `core_loops` rate → fraction of
///     iterations that did real app work (vs poll-only spins
///     ticking the spin-before-HLT window).
///   * `core_idle_enters` → how many HLT/WFI bracketings happened;
///     each costs ~1 µs IRQ round-trip on KVM/HVF. A low rate
///     means we're in steady-state poll mode.
///
/// Per-core arrays so RSS imbalance (one core hot, others idle) is
/// visible. `cycles_per_us` is emitted once so a consumer can
/// convert cycle deltas to µs. All zeros on native (the OS owns
/// scheduling).
fn write_event_loop_obs<W: core::fmt::Write>(w: &mut W) {
    let nc = (waitless::num_workers() as usize).min(8);
    let mut loops = [0u64; 8];
    let mut poll_work = [0u64; 8];
    let mut drain_work = [0u64; 8];
    let mut svc_work = [0u64; 8];
    let mut rt_work = [0u64; 8];
    let mut idle_enters = [0u64; 8];
    let mut busy_cyc = [0u64; 8];
    let mut idle_cyc = [0u64; 8];
    for i in 0..nc {
        let s = waitless::diagnostics::core_stats(i as u32);
        loops[i] = s.0;
        poll_work[i] = s.1;
        drain_work[i] = s.2;
        svc_work[i] = s.3;
        rt_work[i] = s.4;
        idle_enters[i] = s.5;
        busy_cyc[i] = s.6;
        idle_cyc[i] = s.7;
    }
    let _ = w.write_str("{");
    emit_json_array(w, "core_loops", &loops[..nc]);
    let _ = w.write_str(",");
    emit_json_array(w, "core_poll_work", &poll_work[..nc]);
    let _ = w.write_str(",");
    emit_json_array(w, "core_drain_work", &drain_work[..nc]);
    let _ = w.write_str(",");
    emit_json_array(w, "core_service_work", &svc_work[..nc]);
    let _ = w.write_str(",");
    emit_json_array(w, "core_runtime_work", &rt_work[..nc]);
    let _ = w.write_str(",");
    emit_json_array(w, "core_idle_enters", &idle_enters[..nc]);
    let _ = w.write_str(",");
    emit_json_array(w, "core_busy_cycles", &busy_cyc[..nc]);
    let _ = w.write_str(",");
    emit_json_array(w, "core_idle_cycles", &idle_cyc[..nc]);
    let _ = write!(
        w,
        ",\"cycles_per_us\":{}",
        waitless::diagnostics::cycles_per_us()
    );
    let _ = w.write_str("}");
}

// `/heap` retired — the heap statistics moved into `/obs`'s
// `"kernel"` block (`kernel_bare::mm::write_obs_json`), alongside the
// new `heap_oom` counter. `waitless::diagnostics::heap_stats()`
// stays — the shutdown `HEAP_LEAK_CHECK` and the `/diagnostics`
// page still read it directly.

/// The QUIC stack's observability block as JSON — every drop /
/// event counter plus the `LastEvent` snapshots (`last_drop`,
/// `last_conn_close`, `last_conn_exit`). The render lives in
/// `quic::diag::write_obs_json`, so there is exactly one rendering
/// path shared with `/obs`. See `docs/observability.md`.
pub(crate) fn quic_stats_response() -> Response {
    // 4 KiB body region: 45 flat counters (worst-case u64 width)
    // plus three nested snapshot objects, with margin. Slow path,
    // so the reservation is free; rendered in place to skip the
    // String → IOBuf copy.
    let mut body = http::body_iobuf(4096);
    {
        let mut w = body.writer();
        let _ = quic::diag::write_obs_json(&mut w);
    }
    Response::ok(&b"application/json"[..], body)
}

/// Aggregate observability surface — one JSON object per subsystem
/// that has adopted the doctrine, keyed by subsystem name:
/// `{"quic":{…}}`. This is the single clean home for observability
/// data — the per-subsystem failure / performance counters, the NIC
/// per-qp distribution view, and the per-core event-loop occupancy
/// all surface here (see the rollout checklist in
/// `docs/observability.md`). `/quic_stats` is the QUIC-only view of
/// the same `write_obs_json` output.
pub(crate) fn obs_response() -> Response {
    // 16 KiB covers all subsystem blocks (QUIC counters + snapshots
    // + latency histograms, plus tcp / udp / nic / tls / http /
    // http3 / runtime / kernel / net), the NIC per-qp distribution
    // arrays, and the per-core event-loop block, with margin. Slow
    // path, so the reservation is free.
    let mut body = http::body_iobuf(16384);
    {
        let mut w = body.writer();
        let _ = w.write_str("{\"quic\":");
        let _ = quic::diag::write_obs_json(&mut w);
        let _ = w.write_str(",\"tcp\":");
        waitless::diagnostics::tcp_obs_json(&mut w);
        let _ = w.write_str(",\"udp\":");
        waitless::diagnostics::udp_obs_json(&mut w);
        let _ = w.write_str(",\"nic\":");
        write_nic_obs(&mut w);
        let _ = w.write_str(",\"tls\":");
        let _ = tls::diag::write_obs_json(&mut w);
        let _ = w.write_str(",\"http\":");
        let _ = http::diag::write_obs_json(&mut w);
        let _ = w.write_str(",\"http3\":");
        let _ = http3::diag::write_obs_json(&mut w);
        let _ = w.write_str(",\"runtime\":");
        waitless::diagnostics::runtime_obs_json(&mut w);
        let _ = w.write_str(",\"event_loop\":");
        write_event_loop_obs(&mut w);
        let _ = w.write_str(",\"kernel\":");
        waitless::diagnostics::kernel_obs_json(&mut w);
        let _ = w.write_str(",\"net\":");
        waitless::diagnostics::net_obs_json(&mut w);
        let _ = w.write_str("}");
    }
    Response::ok(&b"application/json"[..], body)
}

/// Render the kernel diag-capture buffer (panics + unhandled CPU
/// exceptions) as plain text. Empty body when nothing's been captured.
/// Critical for production GCE deploys where serial-port-output is
/// access-controlled and the in-band channel is the only way to
/// surface a panic from the running unikernel — combine with
/// `curl http://<ip>/diag-panic` to read the trace.
pub(crate) fn diag_panic_response() -> Response {
    // Diag buffer caps at 4 KiB (cf. `kernel::diag::CAPTURE_LEN`); a
    // 4 KiB scratch + small-string prelude lands in one body region
    // without allocating beyond `body_iobuf`.
    const CAP: usize = 4096;
    let mut tmp = alloc::vec![0u8; CAP];
    let n = waitless::diagnostics::diag_snapshot(&mut tmp);
    tmp.truncate(n);
    if n == 0 {
        return Response::ok(
            &b"text/plain; charset=utf-8"[..],
            b"(no panic captured)\n".to_vec(),
        );
    }
    Response::ok(&b"text/plain; charset=utf-8"[..], tmp)
}

/// Dump the gve driver's TX descriptor capture log as plain text.
/// One row per descriptor written, oldest first:
///
///   seq=00000123 qp=0 kind=tso bytes=11 04 11 02 04 12 23 80 00 00 00 12 34 56 78 90
///
/// Empty body when no driver-side log is wired (any backend other
/// than gve, or driver not yet attached). Used to debug gve TSO on
/// GCE where serial-port output is sandboxed and `tcpdump` on the
/// loadgen VM only shows post-hypervisor wire bytes — `/diag-gve`
/// shows what the unikernel actually wrote to the descriptor ring.
pub(crate) fn diag_gve_response() -> Response {
    use core::fmt::Write as _;

    let mut entries: alloc::vec::Vec<waitless::diagnostics::NetTxDescLogEntry> =
        alloc::vec![Default::default(); 32];
    let n = waitless::diagnostics::net_tx_desc_log_snapshot(&mut entries);
    if n == 0 {
        return Response::ok(
            &b"text/plain; charset=utf-8"[..],
            b"(no descriptor log available - driver doesn't surface one or hasn't sent yet)\n"
                .to_vec(),
        );
    }
    entries.truncate(n);

    // ~80 bytes per row × 32 rows = 2.5 KiB; round up.
    const CAP: usize = 4096;
    let mut body = http::body_iobuf(CAP);
    {
        let mut w = body.writer();
        let _ = writeln!(
            w,
            "# gve TX descriptor capture (last {n} entries, oldest first)"
        );
        let _ = writeln!(w, "# kind: 0=STD 1=TSO_PKT 2=SEG");
        for e in &entries {
            let _ = write!(w, "seq={:08} qp={} kind={} bytes=", e.seq, e.qp, e.kind);
            for (i, b) in e.bytes.iter().enumerate() {
                if i > 0 {
                    let _ = w.write_str(" ");
                }
                let _ = write!(w, "{:02x}", b);
            }
            let _ = w.write_str("\n");
        }
    }
    Response::ok(&b"text/plain; charset=utf-8"[..], body)
}

pub(crate) const PROFILE_BUF_LEN: usize = 4096;

pub(crate) fn tls_profile_response() -> Response {
    let mut buf = alloc::vec![0u8; PROFILE_BUF_LEN];
    let n = tls::tls_profile_report(buf.as_mut_slice());
    buf.truncate(n);
    Response::ok(b"text/plain; charset=utf-8", buf)
}
