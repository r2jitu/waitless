# Observability doctrine

Status: doctrine + mechanism landed; QUIC is the reference
implementation. Last updated 2026-05-22.

## Why this exists

A unikernel has no `dmesg`, no `/proc`, no `strace`, no debugger
attach in production. When something goes wrong on a GCE instance
the only things you have are what the running image chose, in
advance, to retain.

The QUIC h3-over-gve bug is the cautionary tale. Diagnosing it took
three round trips — add instrumentation, redeploy to GCE, reproduce —
because the QUIC stack *counted* events but discarded their context.
The decisive clue was that a connection had been reaped by the idle
timer 81 ms after its last datagram, inside a 30 s idle window: the
timeout was spurious. A counter retained `idle_timeouts += 1`.
Nothing retained the 81 ms. Had a snapshot beside that counter held
the last idle-timeout's `last_recv_age` and `idle_window`, the bug
would have been one `curl` away.

The cost this doctrine exists to delete is the *instrument →
redeploy → reproduce* loop. The rule that follows from that: decide
what to retain **before** the incident, because after it you cannot.

## The eight principles

1. **Count the event, capture the last occurrence.** Every counter
   that can fire on an anomaly is paired with a snapshot holding the
   decisive context of its most recent fire. A count says *how
   many*; the snapshot says *what the last one looked like*.

2. **A counter without its invariant inputs is a question, not an
   answer.** Record what the code *tested*, not just the verdict it
   reached. When the idle timer fires, retain `last_recv_age` *and*
   the `idle_window` it was compared against — the h3 bug was
   exactly `81 ms ≥ 30 s` being false yet the conn dying anyway.

3. **Every exit is a traced exit.** Each way a task, loop, or state
   machine can terminate gets its own counter, and the last one
   updates a last-exit snapshot. "It ended" is never silent; "why it
   ended" is never inferred.

4. **Never discard structured peer input you cannot currently use.**
   Error codes, frame types, reason strings, status fields matched
   away with `{ .. }` or `_ =>` are exactly the 3 a.m. clue. Capture
   them into a snapshot even when no code branches on them yet.

5. **Cold path only.** Counters are O(1) relaxed atomics; snapshots
   and detail logging run only on rare events. No per-packet
   allocation, formatting, or locking. `#[cfg]`-gate anything that
   is not free.

6. **A broken assumption is loud.** Most failures are *expected* —
   junk packets, a decrypt that failed against stale keys, a peer
   that closed. Those are counted and snapshotted, queryable at
   leisure via `/obs`; routing them to serial would just be noise.
   But a *genuinely unexpected* condition — an invariant the code
   relies on not holding — is not a statistic. It logs to serial
   immediately and unconditionally, with its context, because a
   counter ticking 0→1 on a dashboard nobody is watching is not a
   signal. Such paths are cold by definition: a "can't happen" that
   happens often was never an invariant, so the serial cost never
   matters. Serial is not the bulk triage surface — `/obs` is — but
   it is exactly right for the rare, loud, this-should-never-happen
   line. (QUIC spells this as the `quic_bug!` macro: ungated serial
   + counter + a `LAST_BUG` snapshot.)

7. **One mechanism, every subsystem.** The counter type, the
   snapshot slot, and the render convention are shared and generic.
   NIC, TCP, runtime, and kernel adopt them unchanged — no
   per-subsystem reinvention, so a reader who understands one
   subsystem's stats understands all of them.

8. **Every signal is reachable without a rebuild.** Counters and
   snapshots are always live and always surfaced through `/obs`.
   Diagnosing a production incident must never require adding
   instrumentation and redeploying — that round trip is the cost
   this doctrine exists to eliminate.

## The mechanism

Three primitives live in [`kernel_core::obs`](../crates/kernel/core/src/obs.rs)
(re-exported as `kernel_bare::obs`). They are deliberately tiny —
the doctrine is a discipline, not a framework. `Counter` and
`LastEvent` serve the failure pillar; `LatencyHist` serves the
performance pillar (see *Performance observability* below).

### `Counter`

A `#[repr(transparent)]` newtype over `AtomicU64`. `bump()`,
`add(n)`, `get()`, all relaxed. `const fn new()` so a counter lives
in a `static`. Reads are intentionally lossy under concurrent
increments — a diagnostics read does not need a fence.

Per-core sharding is *not* the default. A single shared line is
fine for the cold-path counters this doctrine is mostly about
(drops, exits, anomalies — rare by construction). A genuinely hot
per-packet counter that shows up in a profile as cache-line
ping-pong is the signal to shard it per-core and sum on read — but
that is a deliberate, measured change. Hot counters never feed a
`LastEvent`.

### `LastEvent<T>`

A `Spinlock`-guarded slot holding `(count, Option<T>)`. `record(ev)`
bumps the count and stores `ev` as the most recent occurrence;
`snapshot()` returns both. `T` is a small `Copy` payload — the
invariant inputs from principle 2.

It takes a lock, so it is **cold path only**: connection teardowns,
protocol errors, anomalies — never per packet. `count == 0` ⇔ the
slot never fired, so an empty slot is unambiguous.

### `LatencyHist`

A fixed-bucket log2 latency histogram: 20 buckets (bucket `b` =
`[2^b, 2^(b+1))`), plus `count`, `sum`, `min`, `max`. `record` is
one `leading_zeros` and ~5 relaxed atomics — the cost class of a
`Counter`, not of a `LastEvent`. That is what licenses it on a warm
path. Unit-agnostic: the caller records whatever it likes (the QUIC
histograms record microseconds; the unit lives in the field name).

`write_json` renders `count` / `min` / `max` / `mean` / `p50` /
`p99` plus the raw bucket array. The percentiles are the *lower
bound* of the bucket they fall in — a log2 histogram resolves only
to a power of two, so a `p99` is "at least this".

### The snapshot/render convention

A snapshot payload implements `ObsRecord`, whose `write_fields`
emits its fields as JSON object members (no braces, no leading
comma). `LastEvent::write_json(w, name)` wraps that into a uniform
member:

```json
"last_conn_exit":{"count":12,"reason":"idle_timeout","last_recv_age_us":81000,"idle_us":30000000,"local_cid":"a1b2c3d4"}
```

A slot that never fired renders `"last_conn_exit":{"count":0}` — the
shape is uniform, so consumers never special-case "absent".

Each subsystem exposes one `write_obs_json(&mut dyn Write)` that
emits a JSON object: its `Counter`s as flat `"name":value` members,
its `LastEvent`s and `LatencyHist`s via their `write_json`. That
function is the subsystem's entire contribution to the exposure
surface.

## Performance observability

The failure pillar above answers *did it break, and why*. The
performance pillar answers *how long did it take*. Same philosophy —
retain it in advance, one mechanism, surfaced via `/obs` — but a
different cost rule.

Principle 5 keeps the failure pillar cold-path-only: `LastEvent`
snapshots and detail logging fire only on rare events. The
performance pillar deliberately samples *warm* paths — per request,
and where it earns its keep, per datagram. That is sound because a
`LatencyHist::record` is a bounded O(1) op (one `leading_zeros`, a
few relaxed atomics) — the cost class of a `Counter`, not of a
`LastEvent`. What stays forbidden everywhere is per-packet
allocation, formatting, or locking, and any unbounded work.

A latency measurement needs two timestamps and a way to *correlate*
them. The trick is to measure where the correlation is structural,
not bolted on. In QUIC a request and its response are the same
bidirectional stream, keyed by `sid` — so a timestamp stamped on
the inbound datagram, carried to the request's `RecvStream` and
then its `SendStream`, closes the loop at no plumbing cost beyond a
`u64` field. QUIC measures two spans:

- **`inbox_wait_us`** — listener `recv_from` → conn-task dequeue.
  The one genuinely per-datagram sample; isolates scheduling /
  queueing delay.
- **`request_latency_us`** — inbound datagram → response FIN
  encoded. The end-to-end RX→TX path as experienced by a request.

`p50` / `p99` come straight off the histogram on the read side — no
profiler, no sampling agent, live in `/obs`.

## Exposure

All per-subsystem counters and snapshots are surfaced through **one
aggregate endpoint**, `/obs`, whose body is `{"<subsystem>":{…}, …}`
— each subsystem's `write_obs_json` output under its name. Eleven
blocks: the ten doctrine subsystems (`quic`, `tcp`, `udp`, `nic`,
`tls`, `http`, `http3`, `runtime`, `kernel`, `net`) plus the
per-core `event_loop` block. The NIC per-qp distribution view folds
into the `nic` block. Adding a subsystem is one line.

A subsystem may also keep a focused per-subsystem endpoint that
reuses the *same* `write_obs_json` writer — QUIC keeps `/quic_stats`
for that reason. There is no second rendering path.

**The endpoint map** (after the consolidation):

- `/obs` — *the* always-on structured surface: every subsystem's
  counters, `LastEvent` snapshots, and latency histograms; the NIC
  per-qp **distribution** view (RSS balance, TX-pool saturation) in
  the `nic` block; and per-core event-loop occupancy in the
  `event_loop` block.
- `/diag-panic` — the panic / unhandled-exception ring (below).
- `/diag-gve` — the raw gve TX-descriptor capture ring (driver
  debug). `/tls-profile` — the per-stage handshake profiler.
  Both are special-purpose capture tools, deliberately separate.

`/stats` was retired — its per-qp / per-core distribution view (a
different *shape*: arrays, not per-event counters) folded into
`/obs` as the `nic` block's distribution fields and the
`event_loop` block, so there is one observability surface, not two.
`/heap` was retired earlier — its heap statistics are the `kernel`
block of `/obs`. The legacy `GveDiag` / `TcpDiag` seam structs went
with `/stats`: counters now render straight to JSON in the
subsystem, crossing the seam as `write_obs_json` output, never as a
per-subsystem struct.

**The `os:none` seam.** App-reachable crates that build on the host
(`quic`, `tls`, the runtime) plug into `/obs` directly. The
`os:none`-only crates — the `net` stack, the NIC drivers — cannot
be a dependency of the app crate without breaking its native build,
so their `write_obs_json` is forwarded across the `waitless_backend`
cfg-split: a `<sub>_obs_json(&mut dyn Write)` whose `bare` impl
calls the real subsystem and whose `native` impl writes `{}`. The
app calls `waitless::diagnostics::<sub>_obs_json`. TCP is the worked
example (`waitless_backend::tcp_obs_json`).

The `kernel_core::diag` ring is **not** part of this surface and is
deliberately kept separate. It is a 4 KiB *keep-first* buffer whose
one job is to preserve the first panic / unhandled-exception record
so `/diag-panic` can show it. Routing recurring observability detail
through it would crowd out the very fault it exists to capture.
Panics answer "did we crash, and why"; `LastEvent` snapshots answer
"what was the state at the last anomaly" — two jobs, two mechanisms.
(A future enhancement could have the panic handler append a compact
counter summary to the ring; that is out of scope here.)

## Rollout checklist

One row per subsystem. Sessions adopting the doctrine update the
status here. "Adopted" means: cold-path counters use `Counter`,
anomaly/exit counters are paired with `LastEvent` snapshots carrying
their invariant inputs, and a `write_obs_json` is wired into `/obs`.

| Subsystem        | Crate                       | Status   | Notes |
|------------------|-----------------------------|----------|-------|
| QUIC             | `crates/proto/quic`         | ✅ Done   | Reference implementation — see below. |
| TCP              | `crates/net/tcp`            | ✅ Done   | `tcp::diag` — 19 counters, `LAST_RST` / `LAST_TEARDOWN` / `LAST_ACK_UNSENT`; surfaced via the `waitless_backend` seam. |
| UDP              | `crates/net`                | ✅ Done   | `udp::diag` — 6 counters + `LAST_UNDELIVERABLE`; `waitless_backend` seam. |
| NIC / gve driver | `crates/drivers/gve`        | ✅ Done   | `gve::diag` — anomaly counters + `LAST_RX_SKIP`; `waitless_backend` seam. virtio-net driver still bare. |
| IP / ARP / NDP   | `crates/net/stack`          | ✅ Done   | `net_stack::diag` — L2/L3 RX-dispatch drops (`classified_drops` / `unknown_l4`) + `LAST_CLASSIFIED_DROP`; `waitless_backend` seam. |
| TLS              | `crates/proto/tls`          | ✅ Done   | `tls::diag` — handshake-lifecycle counters + `LAST_HANDSHAKE_FAILURE`; app-reachable, no seam. |
| HTTP/1.1         | `crates/proto/http`         | ✅ Done   | `http::diag` — 9 connection/request lifecycle counters + `LAST_REJECT` (smuggling-shaped request → `400`); app-reachable, no seam. |
| HTTP/3           | `crates/proto/http3`        | ✅ Done   | `http3::diag` — 15 request/drop/lifecycle counters + `LAST_DROP`; `h3_drop!` / `h3_event!` gated by the `h3.log=` boot-arg; app-reachable, no seam. |
| Async runtime    | `crates/runtime/executor`   | ✅ Done   | `executor::diag` — task-lifecycle counters + `LAST_SPAWN_FAILURE`; app-reachable via `executor::diag`, no seam. |
| Kernel           | `crates/kernel`             | ✅ Done   | `kernel_bare::mm` — heap stats + `HEAP_OOM` / `LAST_OOM`; `waitless_backend` seam. Panics / exceptions stay in the `diag` ring (`/diag-panic`). |

## Reference implementation: QUIC

`crates/proto/quic` is the worked example. A session adopting the
doctrine for another subsystem should read these and mirror them:

- **`src/diag.rs`** — the `Counters` struct (every field a
  `Counter`), the `LastEvent` snapshot slots, the `LatencyHist`s,
  the record types with their `ObsRecord` impls, the `quic_drop!` /
  `quic_event!` / `quic_bug!` macros, and `write_obs_json`. This is
  the template.
- **`src/conn/rx.rs`** — capturing received `CONNECTION_CLOSE`
  `error_code` / `frame_type` / `reason` that the frame dispatcher
  previously discarded via `{ .. }` (principle 4).
- **`src/endpoint.rs`** — the `conn_task` teardown: every one of its
  loop-exit paths bumps an exit-reason counter and the last one
  records a `ConnExitRecord` carrying `last_recv_age_us` and
  `idle_us` — the invariant inputs the h3 bug needed (principles 2,
  3). Also the `quic_bug!` invariant sites (`rng_failed`) and the
  per-datagram `inbox_wait` sample.
- **`src/streams.rs` + `src/conn/mod.rs`** — the structural
  correlation for `request_latency`: a `rx_us` timestamp threaded
  `Datagram` → `RecvStream` → `SendStream` (shared `sid`), recorded
  at `SendStream::enter_fin_sent`.
- **`apps/webserver/src/endpoints.rs`** — `/quic_stats` and `/obs`,
  both rendering via `quic::diag::write_obs_json`.
