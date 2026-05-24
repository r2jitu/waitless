# High-Concurrency Performance

A working document for the "how do we serve 10K+ concurrent HTTP/TLS
conns competitively" investigation. Captures the measurements and
fixes from the `bench/pareto-rig` work and ranks the remaining gaps
we believe matter most for the next round.

## How this fits with the other perf docs

The repo has several long-running trackers that each own a slice of
the perf story. This doc focuses on the **high-concurrency cliff**
(10 K + concurrent conns / saturation behaviour) and where it
overlaps with the others, defers to them rather than duplicating
their analyses.

| Doc                                  | What it owns                                                  |
|--------------------------------------|---------------------------------------------------------------|
| [`benchmarking.md`](benchmarking.md) | The bench harness (`bench.py`), GCE bench wrappers, the bench-environment matrix. Read this first for "how do I run a bench." |
| [`rx-path-optimizations.md`](rx-path-optimizations.md) | Per-byte / per-frame RX cost. Memcpy reduction, IOBuf zero-copy, **HW GRO / RSC** (items I–O — directly owns P0 #2 below). |
| [`tx-path-optimizations.md`](tx-path-optimizations.md) | Per-byte / per-frame TX cost. Encrypt-in-place, TSO, header-fusion (items A–G). Already trimmed cycles/poll significantly; further wins here would also lift the saturation point. |
| [`observability.md`](observability.md) | The `Counter` / `LastEvent` / `LatencyHist` primitives and the `/obs` exposure rules. The instrumentation we added (`accept_iterations`, `tick_armed_seen`, `tasks_polled_per_worker`, etc.) follows this doctrine, and the per-core `PerCoreCounter` shard variant introduced here implements the doctrine's "shard hot counters per-core" note. |
| [`tcp-conformance-backlog.md`](tcp-conformance-backlog.md) | TCP RFC gaps (active opens, RFC 7323 window scaling, …). The intrusive-timer-list and accept-ring work below was perf-only; semantics unchanged. |
| [`conformance-roadmap.md`](conformance-roadmap.md) | Conformance-testing strategy + QUIC RFC backlog. |
| [`gvnic.md`](gvnic.md) | gVNIC device behaviour, DQO vs GQI queue formats. |

The high-level rule for "where does this fix belong?":

  * **per-byte / per-packet RX cost** → `rx-path-optimizations.md`
  * **per-byte / per-packet TX cost** → `tx-path-optimizations.md`
  * **per-conn data structures, per-conn scheduling, saturation
    behaviour, load shedding** → this doc
  * **RFC correctness** → `tcp-conformance-backlog.md`

## Goal

Best-in-class concurrent HTTP/TLS throughput on the bare-metal
unikernel — competitive with mature Linux stacks (nginx,
tokio-hyper) at the same conn counts on the same hardware, with
graceful degradation past saturation.

## How to bench

For the full bench harness (`bench.py`, workload matrix,
before/after measurement workflow) see
[`benchmarking.md`](benchmarking.md). The scripts below are the
fast single-cell iteration scripts that grew out of this
investigation, layered on top of that harness.

Three iteration envs, ranked by speed and faithfulness to the
production datapath:

1. **`scripts/local-iterate.sh`** — HVF on Apple Silicon. ~30 s
   cycle, no GCE round-trip. Covers async runtime + TCP + HTTP +
   TLS hot paths. Can't reproduce gVNIC-specific behavior (HVF
   uses a userspace TCP proxy, not virtio).
2. **`scripts/kvm-iterate.sh`** — QEMU/KVM on the GCE `kvm-vm`
   loadgen box. ~45 s cycle. Real Linux host TCP stack, real
   virtio-net + vhost-net multi-queue. **Not** gVNIC, and the
   measurements pick up nested-virt + shared-host-CPU artifacts
   (see "Asymmetric core load" below).
3. **`scripts/c3-bench-once.sh`** — Deploy waitless to a real
   `c3-highcpu-8` GCE instance, drive wrk from `kvm-vm` over the
   VPC. Production-shape datapath (gVNIC, Andromeda). ~5 min for
   the first run (image build + upload); subsequent calls are
   single-curl. Mirrors the `/obs` delta block that the other two
   scripts print, so output is comparable across envs.

`scripts/peer-linux/pareto-bench.sh` exists for full
multi-peer / multi-conn sweeps emitting JSONL the
`chart-pareto.py` script consumes; the three single-shot
iteration scripts above are what we use during code-change
debugging.

## Measurements (May 2026)

### Headline: waitless vs Linux peers on c3+gVNIC

Same hardware (`c3-highcpu-8` + gVNIC), same workload
(`/health-TLS`, `{"status":"ok",…}` JSON body), same `kvm-vm`
driving wrk over the VPC, same dedicated bench peers
([`scripts/peer-linux/peer-deploy.sh`](../scripts/peer-linux/peer-deploy.sh)
provisions `waitless-peer-nginx` and `waitless-peer-tokio`;
waitless runs from
[`scripts/deploy-gcloud.sh deploy`](../scripts/deploy-gcloud.sh)).

**Methodology note.** The first comparison below uses
`wrk -t8 -c<N> -d20s` — eight wrk threads from `kvm-vm` (which
is itself an 8-core c3), twenty-second windows. Earlier
measurements at `-t4 -d8s` were loadgen-bound at high conn
counts (the wrk side ran out of CPU before the server did) and
under-measured peak rps. The `-t8 -d20s` numbers below are the
ones to trust at ≥10 K conns.

**Deep sweep — `wrk -t8 -c<N> -d20s --timeout 10s`:**

| conns  | nginx rps    | tokio-hyper rps | **waitless rps** | nginx p99 | tokio p99 | **waitless p99** |
|--------|--------------|-----------------|-------------------|-----------|-----------|-------------------|
|  8 K   | 276 K        | **469 K**       | —¹                | 777 ms    | **91 ms** | —¹                |
| 16 K   | 220 K        | 375 K           | **366 K**         | 2.13 s    | 1.37 s    | 5.24 s            |
| 24 K   | 190 K        | 276 K           | **298 K**         | 3.46 s    | 3.13 s    | **2.12 s**        |
| 32 K   | 168 K        | **227 K**       | 44 K (cliff)      | 4.50 s    | 4.98 s    | 4.70 s            |
| 40 K   | **78 K**     | 44 K            | 4 K (dead)        | 5.29 s    | 5.59 s    | 2.54 s            |
| 50 K   | collapse     | collapse        | collapse          | —         | —         | —                 |

¹ The waitless deep sweep was run mid-investigation against an
earlier deploy and skipped 8 K. The pattern at 8 K is well-
predicted by the 16 K / 24 K points.

**The real story:**

  * **At 16 K conns waitless matches tokio-hyper on rps (366 K vs
    375 K, within 2 %)** and beats nginx by ~66 %. This is the
    "waitless and tokio are peers" zone.
  * **At 24 K conns waitless edges out tokio (298 K vs 276 K)**
    and has the *lowest p99 of the three* (2.12 s vs nginx's
    3.46 s and tokio's 3.13 s). This is the surprise — the same
    runtime/data-structure work that lifts our floor also gives
    us better tail-latency in this band.
  * **At 32 K conns waitless cliffs hard** (44 K rps vs nginx's
    168 K and tokio's 227 K). nginx and tokio degrade gracefully
    past this point; waitless step-collapses. **This is the
    gap that load shedding (P0 #1) and per-poll cycle reduction
    (P1) close.**
  * **At 50 K conns all three collapse.** No peer implements
    real load shedding by default.

So the gap-to-Linux isn't "waitless is permanently behind"; it
is specifically "waitless cliffs ~24 K → 32 K conns where nginx
and tokio degrade gracefully ~32 K → 50 K." Closing that gap
is the P0 / P1 priority below.

**Why the cliff at 32 K is steeper for waitless than for the
Linux peers:**

  * No load shedding — same root cause for all three, but the
    waitless cliff comes earlier because cache pressure scales
    faster on its per-conn data layout (~80 KB of rings per
    live conn vs nginx's smaller per-conn footprint and tokio's
    chunked allocator).
  * Per-poll cycle cost grows with conn count (TcpConnection
    spans ~3 cache lines; at 32 K conns the per-core working
    set blows past L2). Hot/cold struct split (P1 #4) directly
    targets this.

### Lower-conn sweep — `wrk -t4 -c<N> -d8s` (loadgen-bound at the high end)

For completeness, the smaller `-t4 -d8s` sweep against all
three peers (4 wrk threads from `kvm-vm`, 8 s windows). These
numbers are tighter for the low-conn region (no warm-up noise)
but **loadgen-bound at ≥10 K conns** — wrk on 4 threads runs
out of CPU before the server does, so peak rps is under-reported.
Treat as a snapshot of the "healthy zone" only.

| conns | nginx rps | tokio rps | **waitless rps** | tokio p99  |
|-------|-----------|-----------|-------------------|------------|
|  3 K  | 250 K     | **334 K** | 285 K             | **59 ms**  |
|  6 K  | 199 K     | **263 K** | 226 K             | **481 ms** |
| 10 K  | 147 K     | **197 K** | 170 K             | **1.15 s** |
| 14 K  | 113 K     | **153 K** | 128 K             | **882 ms** |

Same ordering (tokio > waitless > nginx in healthy region), but
the absolute numbers run ~30 % lower than the `-t8 -d20s` deep
sweep above because of loadgen back-pressure. The "headline"
fact that survives both methodologies is **waitless beats
nginx and is roughly on par with tokio** in the healthy region
— and **waitless cliffs earlier** under overload, which is the
real perf gap to close.

The gap-to-tokio at 10 K (~27 K rps) is roughly what we'd recover
by closing the per-poll cycle gap to nginx-level (109 K cy/req →
~85 K cy/req — the P1 items below should land in that range).

### Same waitless run on the kvm-iterate / virtio-net iteration path

For context — the env used for fast iteration during the
investigation. Same waitless binary, different network path
(nested QEMU/KVM + virtio-net on a 4-core kvm-vm vs real
8-core c3+gVNIC):

| conns | rps kvm-iterate (4c) | p99 kvm-iterate |
|-------|-----------------------|-----------------|
| 3 K   | 308 K                 | 180 ms          |
| 6 K   | 223 K                 | 461 ms          |
| 10 K  | 146 K                 | 1.33 s          |
| 14 K  | collapse (~200 rps)   | —               |

**kvm-iterate cliffs hard at 14 K** while **c3+gVNIC degrades to
14 K and only collapses at 18 K** — the 4-core kvm path doubles
the working-set / cache pressure per core (3500 vs 1750 conns/core),
and shared-host vCPU scheduling adds queue-stall bursts. See
"Anatomy of CPU collapse" below for the mechanism.

### Per-core breakdown at 10 K conns

**c3+gVNIC (8 cores):**

```
c0: loops=6.13M poll=147K rt=141K idle=0.8% rt/loop=0.0231
c1: loops=6.08M poll=146K rt=140K idle=0.6% rt/loop=0.0230
c2: loops=6.20M poll=148K rt=141K idle=0.6% rt/loop=0.0228
c3: loops=6.01M poll=146K rt=140K idle=0.7% rt/loop=0.0233
c4: loops=6.20M poll=149K rt=143K idle=0.6% rt/loop=0.0230
c5: loops=6.29M poll=142K rt=136K idle=0.9% rt/loop=0.0217
c6: loops=6.17M poll=147K rt=141K idle=0.7% rt/loop=0.0228
c7: loops=6.31M poll=152K rt=145K idle=0.5% rt/loop=0.0230
```

All 8 cores within 5% of each other on every metric. Idle uniformly
0.5–0.9%. `tasks_polled_per_worker` balanced within 1% (one of the
key counters we added). **No core asymmetry.**

**kvm-iterate (4 cores):**

```
c0: loops=1.19M  rt=4.7K  idle= 0.6% rt/loop=0.0040
c1: loops=1.40M  rt=5.5K  idle= 0.6% rt/loop=0.0039
c2: loops=1.42M  rt=5.3K  idle=21.2% rt/loop=0.0037
c3: loops=1.47M  rt=7.2K  idle=13.2% rt/loop=0.0049
```

c0/c1 pinned at 0.5 % idle while c2/c3 sit at 13–21 % idle —
the asymmetry that drove most of our investigation. **It does
not reproduce on c3**, so this is a kvm-vm host-side artifact
(KVM vCPU placement on a shared c3 host, vhost-net IRQ steering,
or similar). Not a guest-fixable bottleneck.

### Per-request CPU budget

| env       | busy cycles/run | requests/run | cycles/request |
|-----------|----------------|--------------|----------------|
| c3+gVNIC  | ~153 B         | ~1.4 M       | **~109 K**     |
| kvm-vm    | ~76 B          | ~1.2 M       | **~64 K**      |

Real c3 actually spends **70 % more cycles per request** than
the nested-KVM path. Likely candidates: gVNIC's DMA-completion
ring processing, deeper interrupt path, less aggressive
batching. Most of the per-request cost is runtime / NIC / stack
overhead — the handler itself for a `/health` JSON response is
likely under 10 K cycles.

### Asymmetric core load on kvm-vm — root cause

`tasks_polled_per_worker` is **balanced** across kvm-vm's 4 cores
(310–316 K polls, within 1 %). The asymmetry is purely in
**cycles per poll** — ~60 K on c0/c1 vs ~48–54 K on c2/c3,
about 20 % more. Same task volume, same NIC frame distribution
(rx_max_min_ratio_x100 = 102 ≈ 1.02×). Confirmed on c3 that this
disappears entirely. The kvm-vm asymmetry was a measurement
hazard, not a real bug.

## Anatomy of CPU collapse

The cliff isn't gradual — `c3+gVNIC` does 128 K rps at 14 K conns
but **0 rps at 18 K conns**. It's a phase transition, not a smooth
roll-off. The mechanism is a feedback loop with three stages:

### Stage 1 — saturated but stable (≤ 14 K conns on c3)

Per-core CPU is pegged near 100 % busy. Throughput plateaus at
~170 K rps total because no core has slack to do more work. p50
latency grows linearly with conn count (Little's Law):
`latency ≈ conns / rps`. At 10 K conns / 170 K rps = ~60 ms p50.

This is the "knee" — adding more conns no longer increases
throughput, only latency. Service is still healthy from the
client's perspective: every request gets a response, just slower.

### Stage 2 — overload (~14 K ≤ conns < 18 K on c3)

Per-conn latency climbs past wrk's `--timeout 10s`. **Some
clients give up** — wrk closes the slow conn and the server
sees an RST. The handler task that was about to write the
response runs anyway, gets a generation-mismatch error from
the closed slot, drops on the floor. **Every wasted handler
poll burns CPU cycles that did not produce a completed
request.**

This is observable in the counters: `rst_received` ≈ 50% of
conns_established at 10K (already significant) and climbs from
there. Each RST means a request whose work was wasted.

The feedback loop is now armed:

1. Latency high → some requests time out
2. Timeouts → wasted handler cycles
3. Wasted cycles → less effective throughput per CPU second
4. Less effective throughput → queue grows
5. Queue grows → latency higher
6. Go to 1

The loop is slow-moving at this stage; effective throughput
sags from 170 K to 128 K but doesn't crater.

### Stage 3 — collapse (≥ 18 K conns on c3, ≥ 14 K on kvm-vm)

Two new failure modes kick in:

**A. NIC RX backlog overflow.** When the per-core poll loop falls
behind, the virtio-net (or gVNIC) RX descriptor ring fills. The
host has no flow control on a virtual NIC RX path — once the
ring is full, **new packets including SYNs are silently
dropped**. This is the `wrk … connect errors: 4904` symptom: 4904
SYN packets never reached our TCP stack at all, so wrk's
`connect()` timed out.

**B. Working-set blow-up.** Each conn carries:

  * `TcpConnection` slot (~200 B, 3+ cache lines)
  * `rx_ring` (16 KB on first SYN)
  * `rtx_buf` (64 KB on first send)
  * Boxed handler future + its captured state (~1-2 KB)

At 18 K conns / 8 cores = 2.25 K conns/core, working set per
core is ~180 MB just for ring buffers. c3 L2 cache is 1 MB per
core; L3 is 96 MB shared. Per-conn state stops fitting in L2,
then L3. **Per-poll cycle cost rises with conn count** because
every poll incurs more cache misses. This is itself a feedback
loop: more conns → more cache pressure → slower polls → more
queued work → more conns active simultaneously.

The two failure modes compound:

  * NIC drops SYNs → wrk retries → more conn churn
  * Working set blows up → polls slow → more requests time out
  * Timed-out conns RST → server processes RSTs (more wasted work)
  * New SYNs flood (wrk retrying), pool grows further
  * Eventually `pool_exhausted` increments, `alloc_connection`
    returns None, SYNs get RST'd from our side too
  * No request completes within wrk's timeout window
  * **Effective rps → 0**

Once the system enters Stage 3, it does not recover on its own
within a bench run. Stopping the load lets the queue drain;
the server itself never fell over.

### Why kvm-vm cliffs harder than c3

Same workload at 14 K conns: kvm-vm collapses to ~200 rps,
c3+gVNIC still does 128 K rps.

Two reasons:

1. **Fewer cores**: kvm-vm has 4 vCPUs, c3 has 8. At 14 K conns
   that's 3500 conns/core on kvm-vm vs 1750 on c3. Working set
   per core is **2× larger** on kvm-vm — the cache-pressure
   feedback loop above is much more severe.

2. **Shared-host scheduling**: kvm-vm runs on a shared c3 host.
   When other guests on the same host run, our vCPUs get
   descheduled briefly. A descheduled vCPU can't poll its NIC
   ring → packets pile up → on resume the queue is huge → big
   stall. c3-direct doesn't have this layer.

### Why load shedding fixes Stage 3

Refuse new conns once the core is genuinely saturated. Refused
SYNs get no SYN-ACK — wrk sees connect timeout and either retries
(slowly) or fails. Crucially:

  * No new entries pile into the pool past the saturation point
  * Working set stays bounded → per-poll cost stays bounded
  * Existing conns get full per-core service → keep doing ~128 K rps
  * No NIC RX overflow → no SYN drops
  * The feedback loop is **broken** at step 4 (queue can't grow)

Aggregate from operator's view: stable plateau at ~128 K rps with
some fraction of conns refused, instead of the cliff to 0 rps.
The cliff position **does not move** — we still saturate the same
8 cores — but the failure mode flips from "collapse" to "graceful
degradation".

## Load shedding: how to decide without capping throughput

The naive shedder ("refuse when `live_conns_per_core > 2000`")
works but has a real cost: a hardcoded threshold caps the system
**below** its true capacity on lighter workloads (where each conn
costs fewer cycles) and **above** its true capacity on heavier
workloads (where the cliff hits earlier). On a hot path that
varies — `/health` vs `/static-1m` vs an app handler doing real
work — that's a 5–10× spread in per-conn cost. One number can't
fit all.

The fix is to shed based on **capacity utilisation**, not on a
count.

### Signal: per-core CPU idle %

We already record `busy_cycles` / `idle_cycles` per core in
`CORE_STATS` (the data the `event_loop` `/obs` block exposes).
Sampled over a short window (~50 ms), the idle % is a direct
read on "do we have CPU left for another conn?":

  * **idle ≥ 8 %** — core has headroom; accept everything
  * **idle ≤ 1 %** — core is saturated; new conns will degrade
    existing ones; refuse
  * **1 % < idle < 8 %** — the band where we **stay with the
    last decision** (hysteresis prevents flapping)

The 1 % / 8 % numbers come straight from the cliff measurements:
the c3 saturation point sits at ~0.5 % idle, the healthy zone is
above ~12 %. Pick thresholds inside those observed bands with a
small safety margin.

### Why this doesn't cap full potential

The threshold is on **capacity** (idle %), not on **count**. So:

  * **Light workload** (`/health`, ~21 K rps/core): saturates at
    ~1500 conns/core → shed kicks in at 1500
  * **Heavy workload** (`/compute`, much fewer rps/core):
    saturates at ~200 conns/core → shed kicks in at 200
  * **Mixed workload that shifts mid-bench**: as the per-conn
    cost goes up, idle drops, shed engages earlier, automatically
  * **CPU contention from another guest** (kvm-vm artifact):
    available capacity shrinks, shed engages earlier, again
    automatically

We never refuse a conn we **could** have served — by definition
the gate only fires when the core has no spare cycles. The cost
is one cheap "current idle %" read per SYN (a window-bounded
EWMA, no per-SYN atomic chain).

### Hysteresis

Without a gap between the shed-on and shed-off thresholds the
gate oscillates: shed fires at 1 % idle → load drops → idle pops
to 2 % → shed releases → load resumes → idle dips to 0.9 % →
shed fires → ... A 1 %/8 % band with the "stay with last
decision" rule above gives the system time to absorb the change
before re-evaluating. Standard thermostat pattern.

### Where the gate goes

One place: `alloc_connection` in `crates/net/tcp/src/pool.rs` —
the SYN handler's first allocation point. Roughly:

```rust
pub(crate) fn alloc_connection(core: u32) -> Option<usize> {
    if core_overloaded(core) {
        crate::diag::COUNTERS.syn_shed.bump();
        return None;   // SYN dropped, no SYN-ACK
    }
    // ... existing find-free-slot logic ...
}
```

`core_overloaded(core)` reads the most recent idle-window
sample. The sample is updated by a low-priority background task
(or by the per-core event-loop itself, every N iterations) —
each update is a `CORE_STATS` read + an EWMA fold. The cost on
the SYN path is one atomic load.

A refused SYN means **no SYN-ACK**: wrk's connect just times
out. Retried SYNs from the same client succeed when the core is
no longer overloaded. From a TCP-stack viewpoint this is no
different from a SYN arriving during transient packet loss; it's
the correct standard behaviour.

### Beyond per-core idle %

When per-core idle is not enough, two well-known next steps:

  * **CoDel** (Linux's CAKE qdisc, RFC 8290): track the
    accept-to-handler-completion delay; shed when the **minimum**
    over a sliding window exceeds a target. Catches bufferbloat
    that idle % misses (a core can be "busy" doing wasted work on
    timed-out conns and still have low effective throughput).
  * **Adaptive concurrency limits** (Netflix's Vegas / Gradient
    algorithms): run a feedback controller on p99 latency vs a
    target — admit more when latency drops, less when it grows.
    Better for tracking the actual knee of the throughput curve.

Per-core idle is the cheap first cut; CoDel-style is the obvious
follow-up once we measure load shedding's effect on the cliff.

## Fixes shipped (commits on `bench/pareto-rig`)

| # | Commit                                                  | What                                                     | Measured impact                                                                  |
|---|---------------------------------------------------------|----------------------------------------------------------|----------------------------------------------------------------------------------|
| 1 | `boot/x86_64: fix PVH info-pointer register (ESI → EBX)`| Boot stub read PVH start-info from wrong register        | Heap `123 MB → 1019 MB` at `-m 1024`; unblocked >2K conns on kvm-iterate         |
| 2 | `mmu: runtime device-MMIO mapping on x86_64`            | `kernel_bare::mmu` extended to walk active PML4          | Lets `-m 4096` run; virtio-net's 64-bit BAR at 56 TiB now mappable on demand     |
| 3 | `net/tcp: scale per-core 4-tuple hash 256 → 32K`        | Hash overflow killed RX hot path at >256 conns/core      | At 10K conns: rps `86K → 162K` (+89 %)                                            |
| 4 | `net/tcp: fix hash bucket selector + cliff instrumentation` | `>> (64 - 8)` hardcoded; only 256 starting buckets   | Avg probe depth `920 → 1.13` (∆ 800×)                                            |
| 5 | `net/tcp: per-(core,port) accept ring`                  | O(pool_size) scan per accept → O(1) ring pop             | Avg accept iters `1257 → 47` (26×)                                                |
| 6 | `net/tcp: O(1) listener + stale-twin lookup`            | O(pool_size) scan per SYN → O(1) port-map + hash         | Avg SYN-scan iters `1285 → 0` (fallback unused)                                  |
| 7 | `net/tcp: intrusive armed-timer list`                   | Tick walked full pool every ~7 ms → walks armed list     | Tick iters `2358 → 406` (6×); `has_armed_timers` O(N) → O(1)                     |
| — | `runtime/executor: per-worker tasks_polled diagnostic`  | Counter array to detect task work skew                   | Confirmed kvm-vm asymmetry is **not** task distribution                          |

**Aggregate on kvm-iterate, 10 K conns /health-TLS:**

- rps `86 K → 146 K` (+70 %)
- p99 `1.56 s → 1.33 s`
- All four O(pool_size) scans eliminated → cliff is now pure CPU
  saturation, not data-structure waste

## Prioritized gaps

The data-structure scans are fixed. Remaining ceiling is cycles
per poll and graceful degradation past CPU saturation. In rough
order of impact-per-effort, ranked by what we'd ship next.

### P0 — Ship next

1. **Load shedding** _(small, ~50 LOC, this doc)_
   - Capacity-signal-based admission gate in `alloc_connection`
     (see "Load shedding: how to decide" above). Stops the collapse
     past CPU saturation; converts the 14K→18K cliff into a 14K
     plateau with refused conns. Bench impact: stable `~128 K` rps
     under overload instead of collapse to ~0. Production impact:
     bounded p99 during traffic spikes. **Lives here**: this is a
     per-conn-admission concern, not a per-packet one.

2. **RX coalescing (GRO / RSC)** _(medium-large, owned by
   [`rx-path-optimizations.md`](rx-path-optimizations.md))_
   - `init_pci_modern` currently masks off `VIRTIO_NET_F_GUEST_TSO4`
     and friends (see `VIRTIO_NET_RX_OFFLOAD_MASK`) — the comment
     notes our RX path only handles single-descriptor ≤MTU frames.
     Enabling these lets the host coalesce N segments into one
     super-frame, cutting per-packet stack overhead 5–10× on the
     RX hot path. Single biggest expected lift for `cycles/request`
     past the cliff investigation's data-structure wins. **Defer to**
     `rx-path-optimizations.md` items **I + M–O** (virtio-net
     `MRG_RXBUF` + RSC) and **J** (gve DQO_RDA RSC enable). Those
     items pre-existed this investigation — they own the
     implementation; this doc just names them as the highest-impact
     cycles/poll reducer left.

3. ~~**Run Linux peer baseline (nginx + tokio-hyper)**~~ _(✓ done
   May 2026 — see "Headline: waitless vs Linux peers" above)_
   - Confirmed: waitless beats nginx by ~15–20 % rps everywhere
     and trails tokio-hyper by ~17–25 %. The gap-to-tokio
     measures the per-poll cycle headroom available — closing it
     is what the P1 items below are sized to do (`~109 K cy/req`
     → `~85 K cy/req` would put us at parity).

### P1 — Per-poll cycle reduction

4. **`TcpConnection` hot/cold split** _(medium, this doc)_
   - Struct is ~200 B → 3+ cache lines per slot. Every per-conn
     access (`tcp_receive`, `poll_slot`, tick walk) touches all
     of them. Split into a 64 B hot half (state, ports, seq nums,
     deadlines, wakers) and a pointer to a cold half (rings,
     IOBufs, RTT history). Cuts cache-line touches per poll by ~3×.
     **Lives here**: it's a per-conn data-structure layout change,
     same scope as the slot pool itself.

5. **Prefetch slot at `poll_slot` entry** _(tiny, this doc)_
   - One `_mm_prefetch` on the slot before the future runs hides
     L2→L1 latency on the slot's hot half. Free hint. ~5–10 %
     when cache-bound.

6. **AES-GCM TLS cipher** _(medium, partly in
   [`tx-path-optimizations.md`](tx-path-optimizations.md))_
   - We negotiate only `TLS_CHACHA20_POLY1305_SHA256` (~20 cy/B
     measured). AES-GCM-128 with AESNI is 1–3 cy/B — ~10× faster
     bulk encrypt. Bigger payoff on `/static-*` than `/health`;
     /health gets ~10 % rps lift since TLS is only ~10 % of the
     poll budget there. Related: `tx-path-optimizations.md` items
     **C + D** already fused encrypt into the TX-slot to remove
     the post-encrypt memcpy; the cipher choice itself is the
     remaining lever.

### P2 — Bigger architectural wins

7. **Softirq-style inline handler path** _(large)_
   - Trivial handlers (`/health`, `/static-*` with `&'static [u8]`
     bodies, no async work) could run **inline in `tcp_receive`**
     when a request completes — no task wakeup, no scheduler
     round-trip, no waker creation. Sidesteps the async-runtime
     tax for known-cheap endpoints. Expected 2–3× on /health-TLS
     specifically. Large change; sacrifices uniformity.

8. **Concrete handler type (drop `Box<dyn Future>`)** _(medium-large)_
   - Per-conn handler tasks all share one concrete future type for
     a given app. Storing them as `Box<dyn Future>` forces vtable
     dispatch on every poll. A `spawn_typed<F>` path with the
     concrete `F` lets LLVM inline the entire HTTP loop. ~5–10 %.

9. **SYN cookies** _(medium)_
   - Defer slot allocation until the 3-way ACK arrives — currently
     we allocate ~16 KB on every SYN (the rx_ring on first send).
     Encode all needed state in the SYN-ACK sequence number.
     Hardens against SYN floods; modest steady-state win.

### P3 — Foundational

10. **Per-CPU slab allocator** _(large)_
    - Single `Spinlock<Talc>` heap shared across cores. The slot
      pool's preserve-across-reuse covers steady-state, but
      first-time rx_ring/rtx_buf allocation during warmup still
      hits the lock. Per-CPU caches eliminate the contention.

11. **Adaptive concurrency (Netflix RED-style)** _(medium)_
    - Replace P0's fixed-threshold shedding with an EWMA on p99
      latency — when p99 climbs past target, throttle accept
      rate. Tracks the actual saturation point as workloads
      change (vs hardcoded conns/core).

12. **eBPF/XDP-style early filter** _(large, possibly unfeasible)_
    - DDoS / bad-source-IP drop at the NIC RX boundary, before
      the TCP stack runs. Requires a programmable filter point we
      don't have today. Defer until we have a real abuse story.

## Instrumentation kept in `/obs`

Surface that survived from the cliff investigation — cheap
(batched bumps), useful as ongoing health metrics + regression
guards. All in the TCP `/obs` block unless noted. Follows the
`Counter` / `LastEvent` doctrine in
[`observability.md`](observability.md) (and uses the per-core
`PerCoreCounter` shard variant for `hash_find_probes` and
`tasks_polled_per_worker`, the two genuinely per-packet /
per-poll counters that would otherwise ping-pong a cache line
across all cores).

| Counter                                  | Healthy range                                  | What it tells us                                              |
|------------------------------------------|------------------------------------------------|---------------------------------------------------------------|
| `accept_calls`, `accept_iterations`      | iters/call ≤ 5                                 | Accept ring fast-path hit rate                                |
| `linear_find_calls`                      | ≈ 0                                            | TCP hash overflow fallback — fires only when the hash is over capacity (P0 indicator to bump `TCP_HASH_SIZE`) |
| `hash_find_probes`                       | probes/call ≤ 2                                | 4-tuple lookup probe depth (per-core sharded `PerCoreCounter` to avoid cache-line ping-pong; the rendered value is the sum) |
| `tick_calls`, `tick_armed_seen`          | armed/call ≈ live armed-timer count            | Per-tick armed-list walk; every walked slot is armed by construction |
| `syn_scan_calls`                         | ≈ 0                                            | SYN-handler pool-scan fallback — fires only when more than `MAX_LISTENERS_PER_CORE` ports are listening on this core |
| `tasks_polled_per_worker` (runtime block) | balanced across active workers                | Per-core task work distribution (per-core sharded — see above) |

**Use:**

- `accept_iterations / accept_calls` is the accept ring's miss rate; > ~5 means either the ring is overflowing or pushed entries are going stale before pop.
- A non-zero `linear_find_calls` or `syn_scan_calls` means a fallback path is firing; both should stay at zero under healthy load.
- Asymmetric `tasks_polled_per_worker` means work isn't distributed evenly across cores.
- `tick_armed_seen / tick_calls` rising past ~50 % of pool means most conns have armed timers (high retx, abusive client, etc.).
