# Architecture audit — fundamental long-term directions

> Written 2026-06-10 from a whole-codebase audit (quality, efficiency, and
> per-subsystem sweeps; every claim below cites a measured incident or a
> verified code location from those passes). Scope: **system-level
> architecture** — the shapes that pay off over years, judged on pure
> architectural value with effort deliberately ignored.
>
> **Status (2026-06-10): all 7 directions have a landed, validated first
> increment** (see the table at the end); #7 is fully complete, the other
> six have a scoped long arc remaining. This doc stays as the living plan
> — the verdict, the seven analyses with their motivating incidents, the
> do-not-change list, and the dependency reasoning are the durable
> content; the per-direction landing detail lives in `git log`, not here.
>
> How this fits the doc set: [`stack-architecture.md`](stack-architecture.md)
> owns the *inter-layer contracts* (buffer currency, stream trait, handler
> API, vtable→trait, the shared CC core) — that plan is correct and mostly
> landed; nothing here re-litigates it. This doc sits one level up: the
> runtime model, the testing model, memory, cross-core structure, and the
> next convergence beyond contracts. [`roadmap.md`](roadmap.md) indexes the
> open items; [`design-history.md`](design-history.md) holds the principles
> these directions must respect.

## Verdict on the current architecture

The big bets are validated and must not be disturbed:

- **The executor-is-the-kernel thesis works** — ~2× tokio measured
  ([`benchmark-results.md`](benchmark-results.md)), and the win is the
  architecture (no syscall boundary), not micro-opts.
- **Shared-nothing per-core scaling works** — 8 cores 99.7–99.8% busy,
  perfectly balanced, zero visible cross-core contention under true
  saturation (the 2026-05-30 GCE decomposition).
- **The IOBuf `Send`-by-derivation buffer currency** is the single best
  property in the stack (stack-architecture's words; agreed — freeze it).
- **Deps-as-features** keeps the TCB honest; unused protocols never compile.

The recurring weakness, across every subsystem audit: **invariants live in
conventions and patches, not in structure**. Cancel-safety holds because a
comment says "a conn never has both futures parked"; flow ownership holds
because RSS usually routes right; memory budgets hold because a 90%-heap
heuristic refuses conns; correctness-under-loss holds because someone rented
a GCE VM and ran netem. Each direction below converts one class of
convention into structure.

---

## 1. Ambient authority → injected capabilities (the enabler)

**The problem as lived.** Environmental dependencies are reached through
globals: three cycle/time readers grew independently (`kernel_core::clock`,
`tls::ticket::now_us` — which QUIC times itself with, a deliberate
kernel-independence hack — and `obs::now_cycles`, deduped 2026-06-09 after
being found verbatim in six crates); RNG, NIC ops, per-core pools, and
launcher tables are process statics; the challenge-ACK rate limiter needed a
`#[cfg(test)]` reset hook because tests can't construct a fresh instance;
`cpu_id()` threads through as ambient identity.

**The change.** Every environmental dependency — **Time, Entropy, Nic, flow
steering, core identity** — becomes a capability handed down at
construction; per-core state becomes per-*instance* state owned by the
worker. The kernel proper shrinks to boot + mm + executor + drivers;
L3/L4/TLS/HTTP become pure libraries over those capabilities. This is the
roadmap's "lift `tcp` above `executor`" taken to its honest end-state, and
it makes the existing native backend a first-class second platform instead
of a stub.

**What it subsumes.** The test-only reset hooks; the time-reader drift; the
"can't run two stacks in one process" limitation; most of the seam work #2
needs.

**First increments.** (a) One `Time` facade with a mockable backend, QUIC
moved onto it (TCP already uses `clock::mock` in tests — QUIC is the
outlier). (b) New leaf state goes on the worker, not in statics — adopt as a
review rule now. (c) Entropy already has the seam (`kernel::rng` behind
fill_bytes) — name it a capability.

## 2. Deterministic simulation testing as the correctness architecture (highest value)

**The problem as lived.** The stack is *agonizingly close* to fully
simulable — sans-io protocol crates, host-testable everything, a clock seam,
a NIC vtable, an in-process packetdrill harness, a `.pkt` DSL — yet
correctness-under-network-conditions still requires renting hardware:
CUBIC-vs-Reno and TLP validation needed GCE + `tc netem`
([`tcp-backlog.md`](tcp-backlog.md) L1/L4); HVF "lies about throughput AND
correctness-under-load" (memory doctrine); the tail-loss RTO bimodality —
*the* loss-recovery discovery of 2026-06 — was only visible on a cloud
deploy; coverage is example-based with no receive-path fuzzing (tcp-backlog
"Test & assurance backlog").

**The change.** With #1 done, build a **simulated world**: virtual time
(sleep = instant advance), a simulated network with seeded
loss/reorder/delay/duplication schedules, N simulated hosts running the
*real* full stack — every run reproducible by seed (FoundationDB /
TigerBeetle precedent). The netem A/B becomes a unit test; RACK's
multi-hole recovery gets property-tested across thousands of loss schedules
per second; retransmit-storm-class bugs surface before deploy. GCE remains
for *performance* truth; correctness truth moves in-repo. Layer parser
fuzzing on top — TLS records, QUIC frames, HPACK are already pure functions
(cargo-fuzz-ready today, no simulation needed).

**What it subsumes.** The netem scripts' raison d'être (kept for hardware
validation only); most "can't validate without GCE" deferrals; the
example-based-coverage gap; the `.pkt` DSL becomes a front-end to it.

**First increments.** (a) Parser fuzz targets (no prerequisites). (b) A
two-endpoint in-process QUIC sim over the existing conn harness with a
scripted lossy pipe — the seed of the full harness. (c) The `Time`
capability from #1.

## 3. Completion-driven reactor — busy-poll becomes a mode, not the model

**The problem as measured.** The poll model is the cost ceiling: NIC
busy-poll is **~39% of saturated cycles**, 89–97% of polls return nothing
(efficiency-audit, 2026-05-30 — its re-prioritized lever #1); idle-HLT had
to be bolted on for the e2 deploy; gve MSI-X is fully supported but unused
*by choice*; DQO silently drops on TX-ring-full (~0.5%/seg → RTO p99
cliffs) because TX has no async backpressure — patched per-driver with
stall breakers. Each is a patch over the same root: the executor's only
event source is "loop again."

**The change.** A unified **completion-source abstraction** — NIC RX/TX
completions, timer expiry, cross-core doorbells, all one interface — that
the executor blocks on, with adaptive busy-poll retained as a latency mode
(NAPI-like: spin while hot, arm interrupts when cold). Tasks park on
completion sources, not per-loop re-polls. This is the deep version of
roadmap Phase 6's "io_uring-style queues" one-liner, and it redefines the
driver contract as submission/completion rings — the right shape for the
planned `NicOps → trait Nic` migration anyway.

**What it subsumes.** The idle-HLT machinery; the per-driver TX-stall
breakers (a full ring parks the sender structurally); the silent DQO drop;
sub-saturation latency/power; the wasted-cycle profile.

**First increments.** (a) Land `trait Nic` with completion-shaped methods.
(b) RX wake-on-packet via MSI-X behind the idle gate (the T7 wake-on-packet
work is the embryo). (c) An async TX-completion waker on DQO (already named
in [`tx-path-optimizations.md`](tx-path-optimizations.md) as the large-body
latency fix).

**Migration recipe for (a)** (sized 2026-06-10 so the next session executes
instead of re-deriving): `NicOps` is a struct of ~25 fn pointers with
exactly three instances (`gve`, `virtio-net`, the null-object backstop in
`nic/src/api.rs`) plus a test shim in `tcp/src/tests.rs`; the facade
(`nic/src/nic.rs`) has 33 `active_ops()` call sites whose field-call shape
(`ops.send(…)`) survives a method-call conversion verbatim. The `Option<fn>`
capability fields become default trait methods returning `None`/`false`.
The link-time registry keeps working: a `&'static dyn Nic` fat pointer to a
per-driver ZST is const-evaluable inside `EthernetDriverReg`. The ONE open
question is performance, not mechanics: dyn dispatch adds one vtable load
to `poll_rx`, which sits on the busy-poll instruction path (~39% of
saturated cycles) — almost certainly invisible, but by this project's own
measured doctrine that claim must be settled by a GCE A/B (`/health` +
`/static-1m`, c3/DQO), not asserted. Do the conversion and the A/B in one
GCE session; keep `(c)` gated on re-profiling there too, since T1–T3's
ACK-clocked backpressure already removed the drop-cliff `(c)` was named
for.

## 4. One reliable-transport engine (finish what net_cc started)

**The problem as lived.** `net_cc` proved CC converges (both transports
delegate; CUBIC landed once for both). But loss recovery is still two
implementations of one machine — and 2026-06-09 demonstrated it: **TCP's
TLP is structurally QUIC's PTO** (implemented fresh anyway); TCP's planned
RACK (L4) is QUIC's existing time-threshold detector; both maintain a
retain-until-ACK store, a scoreboard, recovery episodes, an RTT estimator,
probe timers. stack-architecture says "TCP can't share the code, borrow the
design" — overrule that long-term.

**The change.** A transport-agnostic **loss-recovery core** over an
abstract sent-unit (byte-range for TCP, packet-number for QUIC):
time-ordered scoreboard, RACK reordering window, probe timer, recovery
episodes, feeding the shared CC. RACK and BBR then land *once*. The
retain-until-ACK story unifies on `clone_shared` IOBuf views — QUIC's
2026-06-10 conversion is the template; TCP's rtx queue holding views is the
corollary (its 1 alloc/req and the TSO retain copy fall out by
architecture, not micro-opt — note `RtxPayload::Inline` history: the
*alloc* was measured throughput-neutral, so this is justified on
unification, not speed).

**First increment.** Build TCP's RACK (L4) *as* the shared core from day
one — port QUIC's detector onto the abstract sent-unit, then re-home QUIC
onto it. The next feature pays for the architecture.

## 5. Flow ownership as a first-class plane

**The problem as lived.** "Which core owns this flow, and how do I reach
it?" is re-answered ad hoc per subsystem: PMTUD's ICMP RSS-hashes by its
own header → lands on the wrong core → **dropped** (`pmtu_dropped`;
tcp-backlog T2's named sliver); QUIC CID routing and migration; Tier-2
software RX distribution; the accept-ring handoff; per-IP admission
tracking. Each future case (IP fragments, multipath QUIC, connection
rebalancing) will spawn another patch.

**The change.** A **steering plane**: flow ownership as an explicit
function of flow key, plus one cross-core handoff lane (the `RxInbox`
generalized) with a defined foreign-packet protocol. Shared-nothing stays
absolute — what changes is that the *exceptions* ride one audited mechanism
instead of N bespoke ones.

**First increment.** Route the PMTUD ICMP to the owning core through a
generalized inbox — the smallest real consumer; design the lane for the
general case while landing it.

## 6. Per-connection memory as arenas + per-core heaps

**The problem as measured.** Idle conn = 67 KB across ~6 scattered
allocations + lazy buffers + pool-retained rings — discovered only by
audit, and the audit's own decomposition *mis-attributed 20 KB of it*
(corrected 2026-06-10) because the truth lives in a dozen `new()` bodies;
admission control gates on a "refuse at 90% heap" heuristic; QUIC's
`Connection` carries 14 KB of mostly-`None` key slots invisible until a
struct-size test.

**The change.** A **per-conn arena** (one allocation, typed regions, O(1)
reset on reuse, the exact size visible at one code location) and **per-core
heaps** so memory budgets are per-core arithmetic — admission becomes
`N × arena_size`, fragmentation impossible by construction, and a footprint
regression becomes a diff-visible constant change. Honesty note: the
per-core-heap *throughput* claim was falsified (the magazine A/B was flat);
the justification is isolation, accounting, and OOM containment — not
speed.

**First increments.** (a) Box the QUIC `DirKeys` slots (−9–11 KB/conn,
already a named lever). (b) A `ConnArena` for the newest, most contained
state (the h3 conn) as the pattern-setter.

## 7. Structural cancellation safety in the runtime

**The problem as found (4 instances, one root).** `TcpRecv`/`TcpSendChain`
leave stale wakers on `select`-cancel — the shared-waker invariant is a
comment, with `select.rs` itself saying "TcpRecv::drop would clear a parked
waker there if we add one"; `AsyncEvent` silently overwrites its single
waiter; the sleep wheel's slot-full path lost wakeups (now fire-early); the
launcher had a release/fire race (now leak-on-release). As combinators
multiply, grep-discipline won't hold.

**The change.** **Waker registration becomes an RAII resource** — a
registration whose `Drop` deregisters — everywhere a future parks; plus
honest multi-waiter primitives (or debug-enforced single-waiter ones). This
is what makes "async fn is the only execution model" durable as the API
surface grows.

**First increments.** (a) `Drop`-clears-waker on `TcpRecv`/`RecvChunk`/
`TcpSendChain` (cancel-safety parity — stack-architecture already names
it; sound because the exclusive `&mut TcpStream` borrow means a parked
waker can only be the dropping future's own). (b) `WaitEvent`
Drop-deregistration on `AsyncEvent` — note its single-waiter *overwrite*
is a documented deliberate contract (module header), so the gap is only
the stale-waker-after-cancel case, and a naive "assert on overwrite"
would false-positive on legitimate sequential waits from different
tasks. (c) New park-points use a `WakerSlot`-style RAII helper from day
one.

---

## What NOT to change (measured / deliberate — negative value to revisit)

- Per-core shared-nothing (measured: it's the win).
- The IOBuf type model (freeze per stack-architecture).
- Deps-as-features; the no-syscall / QUIC-structural-advantage thesis.
- Hand-rolled TLS at current scope (audited primitives, KAT-tested).
- `TcpConnection` hot/cold layout split (tested, **rejected**: 3–19% worse).
- Per-stream task spawning for bodyless requests (measured +65% allocs,
  rejected).
- Reno as default CC (CUBIC ≡ Reno on this workload, measured).
- The unified `https` facade (its per-conn cost is #6's to fix, not
  de-unification's).

## Dependency order

```
#1 capabilities ──→ #2 simulation (the payoff)
        │
        └─→ (eases) #6 arenas, #5 steering
#3 completion reactor ──(independent; pairs with trait Nic migration)
#4 transport engine ──(independent; do RACK as its first consumer)
#7 cancel-safety ──(independent; do first — smallest, pays immediately)
```

If only one thing gets long-term investment: **#1 + #2 together**. Every
other direction — and every future transport feature — gets cheaper, safer,
and provable once the whole stack runs reproducibly in a simulated world.
It is the change that compounds.

## Status

Every direction's **first increment landed and is validated** (host
suites + both arches + HVF; the loss/perf-sensitive ones GCE-confirmed),
all on `main` through 2026-06-10. The one-line summary below is the
ledger; the landing detail and rationale live in the referenced commits
and in each direction's section above — this table is deliberately kept
short (it used to carry full paragraphs; that belongs in `git log`).

What remains under each is **long-arc work**, not an unfinished first
step: each is a real subsystem build, scoped in its section, to be
picked up the same one-direction-at-a-time way.

| # | Direction | Shipped (first increment) | Long arc remaining |
|---|---|---|---|
| 1 | Capabilities | `quic::time` mockable seam; Time + Entropy named capabilities + worker-owned-state review rule (design-history) | per-instance worker-owned stacks; kernel shrinks to boot+mm+executor+drivers |
| 2 | Simulation | 3-parser fuzz-smoke; virtual-time loss/PTO suite (caught 2 bugs); 200-seed loss-schedule property suite (netem class, now ~30 ms in-repo) | ✅ two-endpoint sim LANDED 2026-06-11 (the client role now exists): real client vs real server through a seeded lossy pipe under the virtual clock — its first run caught the §4.9.2 client discard deadlock. Remaining arc: scale schedules/scenarios |
| 3 | Completion reactor | `NicOps` → `trait Nic` / `&dyn Nic`; GCE A/B neutral. (c) TX-waker **withdrawn** — re-profile showed 0 ring-full drops, backpressure subsumed it | completion-source abstraction proper; (b) idle-gated MSI-X wake (latency/power) |
| 4 | Transport engine | shared `RecoveryEpisode`; `net_cc::loss::LossParams` detector; QUIC re-homed; **TCP RACK** as 2nd consumer (netem: Δ225 marks, 0 stalls) | adaptive reo_wnd (RFC 8985 S2); BBR (lands once on this core) |
| 5 | Flow steering | cross-core `CtrlMsg` lane; wrong-core PMTUD routing (RSS-active precondition GCE-confirmed) | ownership map if a high-volume consumer arrives; more `CtrlMsg` variants |
| 6 | Memory arenas | DirKeys boxed (`Connection` 17,944→4,008 B) + all clone sites take-and-restore; `ConnArena` (4→1 allocs/conn) | typed arena regions for the dynamic state (stream map, retx, reassembly) — needs allocator plumbing |
| 7 | Cancel-safety | **COMPLETE** — both Drop halves + `WakerSlot`/`Parked` RAII helper; closed a 5th instance (UDP recv had no Drop) | — |
