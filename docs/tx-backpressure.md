# TX Backpressure & Egress Architecture

How the stack stops producing faster than it can transmit — **without spinning,
dropping committed data, or growing memory without bound.** This doc owns the
*backpressure design*: the two distinct sources of "can't send now," the single
place they rendezvous, and the staged path from today's first-caller-wins TX to
a per-core fair-scheduled egress.

> Written 2026-06-06 after the Apple-HVF h3-`/stream` wedge
> ([`reference_hvf_h3_stream_wedge`] in agent memory) exposed that the TX path
> has no real backpressure — a stalled ring spun `acquire_tx_buf` at 100% CPU
> and QUIC spilled unsent packets to the heap without bound.

## How this fits with the other docs

| Locus | Doc |
|---|---|
| inter-layer contracts (`SendProgress`, the shared CC trait) | [`stack-architecture.md`](stack-architecture.md) |
| per-conn data structures, scheduling, **saturation, load shedding** | [`high-concurrency-perf.md`](high-concurrency-perf.md) |
| per-frame TX cost | [`tx-path-optimizations.md`](tx-path-optimizations.md) |
| **the backpressure/egress design itself** | this doc |

`stack-architecture.md` already specifies the *contracts* this design needs —
the `SendProgress { Drained / WouldBlock(BlockReason) / Closed }` signal and the
"one congestion-control / loss-recovery / pacing core" (`CongestionControl`
trait). This doc says how those compose into an end-to-end backpressure chain
and adds the missing piece neither tracker owns: the **per-core egress
scheduler**.

## Two backpressure sources — different layers, different mechanisms

Conflating these is how a stack ends up correct for one and broken for the other.

1. **Slow remote receiver / lossy path** — *per-flow*. This one connection's
   path or peer can't absorb its rate. Mechanism: receiver flow control
   (TCP rwnd / QUIC `MAX_DATA`) + congestion control (cwnd), **ACK-clocked**,
   owned by the connection. Response to congestion: shrink cwnd (+ maybe ECN).

2. **NIC TX saturation from aggregate load** — *shared-resource contention*.
   Each flow individually has window, but N flows collectively oversubscribe one
   egress queue. No per-flow signal sees this; it is a scheduling/fair-queueing
   problem. Response: **lossless backpressure** (park the producers) + a fair
   arbiter deciding whose bytes go first. *Don't drop here* — dropping your own
   committed bytes at the local egress is pure waste (you'd just retransmit);
   local saturation is backpressure, network-path congestion is cwnd's job.

## The invariant

**Buffer in exactly one bounded place; release it only on real progress (ACK).
Everywhere else, propagate backpressure — never absorb it.**

The one buffer is the per-connection **send buffer**, with a hard cap. Bytes
leave it only when *acknowledged* (so "buffered" reflects true unacked
in-flight), never merely when *packetized* — freeing on packetize lets the
producer outrun the wire and lies to it about progress. Everything downstream is
*flow-controlled, not buffered*:

```
 app handler ── write(chunk).await ─────────────┐  parks when send buffer is at cap
      │                                          │  (the ONE producer block point,
      ▼                                          │   serves BOTH sources)
 send buffer (bounded; released on ACK) ─────────┘
      │  packetizer pulls ≤ min(cwnd, peer_fc, ring_space)   ← source #1 gate (per-flow CC)
      ▼
 per-core egress scheduler (DRR fair queue) ─────  ← source #2 gate (shared NIC)
      │  pull-based, lossless; ring full ⇒ stop pulling, flows keep their place
      ▼
 NIC TX ring  (shallow; the scheduler is the only writer)
```

A stalled wire then fills the chain to its caps and the app blocks — **flat
memory, indefinitely.** The app never learns *which* source bit; it just sees
"buffer full, await."

### Memory ceiling & admission control

Backpressure bounds *per-connection* memory: `ring (fixed) + in_flight (≤ cwnd) +
send_buffer (≤ cap)`. Total is `Σ over conns ≈ N × cap`, so the only bound on
*aggregate* memory is bounding **N** — admission control (cap concurrent
streaming conns, or a shared global byte budget with fairness). Under extreme
oversubscription you stop *accepting* rather than degrade everyone. This is also
the DoS ceiling: a slow reader pins ≤ `cap` bytes, and you admit ≤ N of them.

### Egress scheduler design (source #2, the new piece)

A **per-core** Deficit-Round-Robin fair queue owns the core's TX queue (fits the
shared-nothing model: no cross-core locking; cross-core fairness is a flow-steering
/ RSS question, separate). Connections never touch the ring — they register
"ready + weight" with the scheduler, which picks a flow by DRR and pulls **one
packet just-in-time** (freshest cwnd, no stale queued packets) into the ring.
Keep the ring **shallow** and the queue in the scheduler (the BQL/FQ-CoDel
lesson) so bytes sit where they can be reordered/paced/prioritized, not in a dumb
FIFO that adds bufferbloat. Pacing (from `CongestionControl::pacing_rate`) lives
here.

Once a per-core scheduler is the **sole owner** of the ring, the whole
spin/spill/wedge class stops existing by construction — it was a symptom of N
producers racing one ring with no arbiter.

## Staged path

Ordered by foundational-ness; each is separable and testable.

0. **Floor — bound `acquire_tx_buf`.** ✅ *(this branch)* A stall circuit breaker
   so a stuck ring can't hang the core. Scaffolding that holds the roof up until
   (3); deleted once the scheduler owns the ring. See the
   `virtio-net: bound acquire_tx_buf …` commit.
1. **Shared `CongestionControl` core.** ✅ *foundation landed (this branch):*
   [`crates/net/cc`](../crates/net/cc) — the `CongestionControl` trait (exact
   signature from `stack-architecture.md`) + a `NewReno` controller + unit
   tests. *Next:* delegate TCP's embedded `cwnd`/`ssthresh` to it and give QUIC
   its first controller (closes RFC 9002 step 5). Gives the **in-flight bound**
   the bounded send buffer needs.
2. **Bounded, ACK-released send buffers everywhere.** TCP already does this (send
   window + retransmit queue, freed on ACK, ring-full ⇒ park — see
   `net/tcp/src/send.rs`). **QUIC does not** — its stream buffer frees on
   *packetize* and ring-full spills to a `Heap` datagram (unbounded). *Next:*
   release on ACK + gate packetization on cwnd / a fixed in-flight cap; ring-full
   ⇒ stop, no heap spill.
3. **Per-core egress scheduler.** ✅ *foundation landed:*
   [`crates/net/egress`](../crates/net/egress) — a `DeficitRoundRobin` fair
   queue, pull-based + lossless, unit-tested for weighted fairness and
   backpressure retention. ✅ *QUIC arm wired (switchable, default-OFF):*
   [`crates/proto/quic/src/egress.rs`](../crates/proto/quic/src/egress.rs) —
   a per-core DRR owns QUIC **ship ordering**. Connections register a shipper
   + `activate` when they have queued outbound; the per-core `EGRESS_DRAIN`
   event-loop hook is the sole `ship_datagram` caller, granting a bounded
   quantum per round so one bulk flow can't monopolise a core's TX queue.
   Gated by the app's `QUIC_EGRESS_SCHED` flag; OFF ⇒ the byte-for-byte
   inline-ship path. *Next, in order:* (a) just-in-time ring **admission** —
   QUIC acquires its ring slot at *build* time, so today the drain arbitrates
   ship order over already-acquired packets; moving the build into the drain
   ("freshest cwnd, no stale packets") makes it the true ring owner;
   (b) the **TCP arm** (the golden path) behind the same hook;
   (c) a single cross-protocol per-core queue.
4. **Admission control.** Cap concurrency / global byte budget → bounds total
   memory. (Per-IP conn caps exist in the QUIC slot table; generalize.)

## What this branch delivers vs. leaves

**Delivered + tested:** the circuit-breaker floor (0), and the two keystone
primitives as standalone, host-unit-tested, `no_std` crates — `net_cc` (1) and
`net_egress` (3). These are the abstractions `stack-architecture.md` marked "not
started."

**Since wired into the hot path:** `net_cc` now backs TCP's congestion control
(2) and QUIC has its first controller. `net_egress` owns QUIC ship ordering (3,
the QUIC arm) behind the default-OFF `QUIC_EGRESS_SCHED` flag — host-tested,
HVF-validated functional (h3 small + large + conn churn, no panics, heap_oom=0).
A GCE c3/gVNIC h3 A/B (OFF vs ON) found it **throughput-neutral-to-slightly-
negative** (within spot variance; bulk `download_64k` ~2–8 % lower under ON — the
DRR-drain cost) with **no upside** on single-flow benches: as
[`h3-health-cycle-profile.md`](h3-health-cycle-profile.md) found, TX isn't the
throughput lever, and the *fairness* benefit this buys (N flows oversubscribing
one core's TX queue) isn't exercised by a single dominant flow. So it ships
**default-OFF** — a proven opt-in lever, not a default (the per-core-magazine
precedent). Building the primitives in isolation first made each integration a
wiring exercise against a tested core, not a design-and-build in the hot path.

**Still ahead:** the higher-value, higher-risk parts of (3) — just-in-time ring
*admission* (vs today's ship-ordering), the golden-path TCP arm, and a unified
cross-protocol per-core queue — plus admission control (4).

[`reference_hvf_h3_stream_wedge`]: # "agent memory note — the wedge root-cause"
