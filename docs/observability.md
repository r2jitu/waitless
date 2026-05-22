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

6. **Serial is a slow human channel, not the triage surface.** The
   GCE serial console is readable in production, but writing to it
   is slow and what comes out is unstructured text. Durable
   diagnostics live in memory — counters and snapshot slots — and
   are surfaced as structured JSON via an HTTP endpoint. Serial
   carries only gated, human-paced lines for interactive debugging
   (`quic.log=events` and friends).

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

Two cold-path primitives live in [`kernel_core::obs`](../crates/kernel/core/src/obs.rs)
(re-exported as `kernel_bare::obs`). They are deliberately tiny —
the doctrine is a discipline, not a framework.

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
its `LastEvent`s via `write_json`. That function is the subsystem's
entire contribution to the exposure surface.

## Exposure

All observability data is surfaced through **one aggregate
endpoint**, `/obs`, whose body is `{"<subsystem>":{…}, …}` — each
subsystem's `write_obs_json` output under its name. Adding a
subsystem to `/obs` is one line. This is the clean home the
scattered ad-hoc endpoints (`/stats`, `/heap`, `/tls-profile`)
migrate into; until they do, they keep working unchanged.

A subsystem may also keep a focused per-subsystem endpoint that
reuses the *same* `write_obs_json` writer — QUIC keeps `/quic_stats`
for that reason. There is no second rendering path.

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
| NIC / gve driver | `crates/drivers/nic`        | ⬜ Pending | `gve_diag` counters exist; fold into the mechanism + `/obs`. |
| TCP / IP stack   | `crates/net`                | ⬜ Pending | `tcp_diag` (`syn_rx`, `synack_tx`, …) exists; same. |
| TLS              | `crates/proto/tls`          | ⬜ Pending | `tls::record` encrypt/decrypt stats; `tls_profile`. |
| Async runtime    | `crates/runtime/executor`   | ⬜ Pending | per-core loop stats (`core_stats`). |
| Kernel           | `crates/kernel`             | ⬜ Pending | heap stats; the `diag` ring stays panic-only. |

## Reference implementation: QUIC

`crates/proto/quic` is the worked example. A session adopting the
doctrine for another subsystem should read these and mirror them:

- **`src/diag.rs`** — the `Counters` struct (every field a
  `Counter`), the `LastEvent` snapshot slots, the snapshot record
  types with their `ObsRecord` impls, and `write_obs_json`. This is
  the template.
- **`src/conn/rx.rs`** — capturing received `CONNECTION_CLOSE`
  `error_code` / `frame_type` / `reason` that the frame dispatcher
  previously discarded via `{ .. }` (principle 4).
- **`src/endpoint.rs`** — the `conn_task` teardown: every one of its
  loop-exit paths bumps an exit-reason counter and the last one
  records a `ConnExitRecord` carrying `last_recv_age_us` and
  `idle_us` — the invariant inputs the h3 bug needed (principles 2,
  3).
- **`apps/webserver/src/endpoints.rs`** — `/quic_stats` and `/obs`,
  both rendering via `quic::diag::write_obs_json`.
