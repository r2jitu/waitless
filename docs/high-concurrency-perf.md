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
| [`iobuf-type-model.md`](iobuf-type-model.md) | The `iobuf` ownership / `Send` type model (`OwnedIOBuf`, `Chain<B>`, `IOBufRead`, the uniform drop/free contract). |
| [`stack-architecture.md`](stack-architecture.md) | Inter-layer **contracts and stack shape**: the buffer currency, the stream trait, the handler API, NIC/reactor backend abstraction (POD-fn-pointers → traits), and the TCP/TLS/H1 ↔ UDP/QUIC/H3 convergence to one golden path. Owns layer *structure*, not per-byte cost. |

The high-level rule for "where does this fix belong?":

  * **per-byte / per-packet RX cost** → `rx-path-optimizations.md`
  * **per-byte / per-packet TX cost** → `tx-path-optimizations.md`
  * **per-conn data structures, per-conn scheduling, saturation
    behaviour, load shedding** → this doc
  * **inter-layer contracts / stack shape** (buffer currency, stream
    trait, handler API, backend abstraction, two-stacks→one-golden-path
    convergence, API simplification) → `stack-architecture.md`
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
2. **`scripts/kvm-iterate.sh`** — **Iteration env, not a clean
   bench.** QEMU/KVM on the GCE `kvm-vm` (a c3-highcpu-8): the
   guest waitless runs with `-smp 4` (4 vCPU threads) AND wrk
   runs with `-t4` (4 wrk threads) AND vhost-net workers AND the
   host kernel + virtio-net all share the same 8 host cores.
   That's a deliberate shared-host setup — fast cycle time
   (~45 s vs ~5 min for c3-bench-once) at the cost of contention
   between the server and the loadgen. Use kvm-iterate for code-
   change iteration ("did this commit make rps go up or down on
   the same shared-host setup?"), **never for headline numbers**.
   Real Linux host TCP stack and real virtio-net + vhost-net
   multi-queue are the things this env reproduces that HVF
   can't; the absolute rps numbers come from c3-bench-once.
3. **`scripts/c3-bench-once.sh`** — **The clean bench.** Deploys
   waitless to a real `c3-highcpu-8` GCE instance
   (`waitless-webserver` — 8 dedicated cores, gVNIC). Drives wrk
   from `kvm-vm` (a *separate* c3-highcpu-8 — 8 dedicated cores
   for the loadgen). Traffic crosses the VPC over gVNIC. **No
   server↔loadgen CPU sharing.** Production-shape datapath
   (gVNIC, Andromeda). ~5 min for the first run (image build +
   upload); subsequent calls are single-curl. Mirrors the
   `/obs` delta block the other two scripts print so output is
   comparable across envs. The headline measurements below come
   from this env.

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
| 50 K   | 0 rps²       | 0 rps² (49 991 connect errors) | 0 rps to 15 K rps²,³ | — | — | varies (8.58 s on 15 K-rps run) |

¹ The waitless deep sweep was run mid-investigation against an
earlier deploy and skipped 8 K. The pattern at 8 K is well-
predicted by the 16 K / 24 K points.

² **50 K is at the loadgen's edge.** `kvm-vm` is a c3-highcpu-8;
at 50 K concurrent conns wrk needs ~50 K ephemeral source ports
held simultaneously. The ip_local_port_range is set to
`1024-65535` (≈63 K available) but during burst-establishment +
TIME_WAIT recycling the effective pool is smaller, and wrk's
per-thread connect rate caps out before all 50 K reach
ESTABLISHED. The "collapse" we see at 50 K for **nginx**
(0 rps, 0 connect errors but no requests complete) and
**tokio** (49 991 connect errors — only 9 sockets even reached
ESTABLISHED) is a different failure mode from the 32 K-40 K
server-CPU cliff above — it's the wrk-on-c3-highcpu-8 side
running out of TCP resources, not the server collapsing.

³ Earlier in the investigation (2026-05-23 08:24 UTC) a
`-t8 -c50000 -d30s` waitless run against the day-1 deploy
returned **502 776 requests in 34.35 s ≈ 14.6 K rps** with
zero connect errors. We didn't re-run that against nginx /
tokio at the same time, so we don't have an apples-to-apples
50 K data point where the loadgen was fully cooperative.
Treat the 50 K row above as "this loadgen can't drive 50 K
to nginx / tokio reliably," not "the servers collapse at
50 K."

**The real story (focus on the bands where the loadgen is not
the bottleneck — ≤ 40 K conns):**

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
  * **At 50 K conns the loadgen runs out of TCP resources** for
    most runs (see footnote 2). One reproducible-but-not-repeated
    waitless run survived 50 K at ~15 K rps; we don't have
    nginx / tokio comparison numbers in that regime.

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

**These numbers are not directly comparable to the c3+gVNIC
table above** — kvm-iterate runs **the server and the loadgen
on the same 8-core c3-highcpu-8 host** (QEMU vCPU threads,
wrk threads, vhost-net workers, and the host kernel all share
the host CPU). Use them only for *delta* (did a code change
move rps in one direction or the other on this shared-host
setup?), not absolute capacity. The headline table above is
the unshared-hardware truth.

| conns | rps kvm-iterate (4c, shared host) | p99 kvm-iterate |
|-------|-------------------------------------|-----------------|
| 3 K   | 308 K                                | 180 ms          |
| 6 K   | 223 K                                | 461 ms          |
| 10 K  | 146 K                                | 1.33 s          |
| 14 K  | collapse (~200 rps)                  | —               |

**kvm-iterate cliffs hard at 14 K** while **c3+gVNIC degrades to
14 K and only collapses at 18 K**. Three things compound:

  * **4 cores vs 8** — twice the working-set / cache pressure
    per core (3500 vs 1750 conns/core).
  * **Server↔loadgen sharing the same 8 host cores** — when the
    guest waitless is pegged, the wrk threads (and vhost-net
    workers, and the host TCP stack) are competing for the
    same physical cores, so each side's behaviour starves the
    other and the cliff appears earlier than it would on
    separated hardware.
  * **Nested KVM scheduling jitter** — KVM on a shared c3 host
    can deschedule a vCPU briefly when another guest runs,
    making the per-poll wall-clock variance higher than on
    dedicated hardware.

See "Anatomy of CPU collapse" below for the per-stage mechanism.

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
not reproduce on c3+gVNIC** with the server and loadgen on
**separated** c3-highcpu-8 hosts, so this is a kvm-iterate
test-setup artifact. Most-likely cause: wrk on the same
8-core host as the QEMU vCPUs steals from whichever guest
vCPUs the Linux host scheduler picks (typically the
lower-numbered ones first), making them effectively slower
per loop iteration. Secondary contributors: vhost-net IRQ
steering, MSI-X vector affinity. **Not a guest-fixable
bottleneck.** Fixing the test setup (= move wrk to a separate
host, which is what c3-bench-once does) makes it disappear.

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

**B. ~~Working-set blow-up~~ — tested and falsified (2026-05-24).**
This was originally proposed as the second half of the failure
mode: each conn carries `TcpConnection` (~200 B, 3+ cache lines)
+ `rx_ring` (16 KB) + ~~`rtx_buf` (64 KB)~~ → `rtx_queue` (on-demand) + boxed handler future
(~1–2 KB), so at 18 K conns / 8 cores the working set blows past
L2 / L3 and per-poll cycle cost rises with conn count. The
`tcp-hot-cold-split` branch tested this directly — shrunk
`TcpConnection` to a 64 B cache-line hot half + `Box<Cold>` —
and **the cliff position did not move** (same 24 K saturation
point on a side-by-side conn-count sweep, on the same
production-shape `gcp-deploy-bench.sh` harness). Per-packet
cycles were in fact *3–19 % worse* on the split (the Box-deref
penalty dominates the cache-line savings on real production
shapes where the armed-tick list is small, ~2 slots). So the
per-conn working set may be big, but it's not what's driving
the cliff — see "Falsified hypotheses" below for what remains
and the new diagnostic surface added for the next cut.

With hypothesis B falsified the residual collapse mechanism is
narrower than the original write-up implied — failure mode A
(NIC RX overflow → silent SYN drops → retry storms → wasted RSTs
→ `pool_exhausted` → server-side RSTs) is sufficient on its own
to drive rps → 0. The chain that survives:

  * NIC drops SYNs → wrk retries → more conn churn
  * Timed-out conns RST → server processes RSTs (more wasted work)
  * New SYNs flood (wrk retrying), pool grows further
  * Eventually `pool_exhausted` increments, `alloc_connection`
    returns None, SYNs get RST'd from our side too
  * No request completes within wrk's timeout window
  * **Effective rps → 0**

Which suspects remain as plausible **second** drivers (beyond
A) is now an open question — see "Falsified hypotheses + open
suspects" below.

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

## Falsified hypotheses + open suspects (2026-05-24)

`tcp-hot-cold-split` was P0 #2 in an earlier revision of this
doc, the supposed cliff-mover for hypothesis B above. The branch
shipped, was tested rigorously on the production-shape harness,
and **rejected**. Recording the result here so we don't recycle
the same hypothesis.

### What we measured

`gcp-deploy-bench.sh` shape (waitless-webserver + kvm-vm),
`health-tls`, 4 cores, 10 s, `wrk -t4`, side-by-side
main-vs-feature sweep:

| Conns | main rps | feature rps | main cy/pkt | feature cy/pkt |
|------:|---------:|------------:|------------:|----------------:|
|  1 K  | 345 708  | 346 266     | 1 036       | 1 067           |
|  4 K  | 268 726  | 269 013     | 1 291       | 1 418           |
|  8 K  | 214 604  | 216 047     | 1 454       | 1 727           |
| 16 K  | 134 424  | 137 591     |   989       | 1 142           |
| 24 K  |       0  |       0     | —           | —               |

  * rps within ±3 % across the sweep.
  * **Cliff at the same position on both branches** (24 K, not
    18 K, not 32 K — both prior numbers in this doc).
  * Feature is **3–19 % slower per packet** (Box-deref overhead
    on the cold half exceeds any cache savings; grows with conn
    count).
  * Tick-walk savings only **3–5 %** (`next_deadline_ms`
    fast-skip is real but the armed list stays tiny on
    production-shape, ~2 slots, so there's nothing to skip).

### What this rules out

  * **Per-conn `TcpConnection` layout is not the bottleneck.**
    A 64 B hot half + Box cold does not move the cliff. The
    "working-set blow-up" feedback loop in Stage 3 above did
    not survive direct measurement.
  * **The armed-tick walk is already cheap enough.** The 1.8–
    2.8× tick-walk savings observed earlier on kvm-iterate were
    artifacts of that environment — armed lists are tiny here.

### What remains plausible

The 24 K cliff has the *same shape* on both branches, so its
cause is upstream of `TcpConnection` cache footprint. Suspect
list, none yet measured:

  * **SO_REUSEPORT-style conn distribution** breaking down at
    high N — flows piling on a subset of cores.
  * **Accept-ring overflow** at burst-establishment rates
    (`accept_iterations / accept_calls` was a watchpoint earlier;
    still is).
  * **TLS handshake serialization** — the handshake path may
    have a single-flight bottleneck that surfaces above some
    establishment rate.
  * **NIC RX-descriptor pressure** before any code on our side
    runs — SYNs dropping at the gVNIC ring rather than at our
    pool. The doctrine half of P0 #3 (deterministic conn cap)
    only helps if we know the cliff *isn't* upstream of us.
  * **Loadgen-side ceiling** — `kvm-vm`'s ephemeral-port pool
    or conntrack table hitting a wall at ~24 K simultaneous
    flows. Worth ruling out before chasing server-side causes.

### New diagnostic surface

Commit `51914e2` landed the cycle-cost + working-set
instrumentation the cliff investigation needed:

  * `tcp.rx_cycles` / `tcp.rx_calls` — per-packet cycle cost
    on the `tcp_receive` hot path. Derive `cycles_per_packet`.
  * `tcp.tick_cycles` (pairs with the existing
    `tick_armed_seen`) — per-tick cycle cost on the armed-list
    walk. Derive `cycles_per_armed_slot`.
  * `tcp.live_conns` — count of non-Closed / non-Listen slots
    across all cores. The working-set gauge.
  * `tcp.armed_now` — current armed-list length. Validates the
    "armed list stays tiny" finding above on any new workload.

First diagnostic question with the new surface: during a 24 K
cliff bench, does `live_conns` actually reach 24 K, or do SYNs
drop at the NIC (`gve_rx_discards` / virtio equivalent) before
`alloc_connection` ever runs? That answer routes us between the
upstream-of-us suspect list and the server-side one.

## Heap OOM root-cause analysis (2026-05-24)

The "cliff" at 18–24 K conns on c3+gVNIC reaches the heap before
it reaches CPU: `mm::alloc` returns null, the two non-graceful
allocation primitives in the data path
(`crates/proto/tls/src/lib.rs:598` and
`crates/net/tcp/src/pool.rs:146`) panic via Rust's default
alloc-error handler, the `#[panic_handler]` in
`crates/boot/src/entry.rs:51` calls `arch_shutdown`, and GCE marks
the VM `guestTerminate`. A separate branch is making those two
sites graceful. This subsection answers the prior question of
*why* the heap fills at 18 K when the nominal per-conn budget
suggested ~30 K. Short answer: the nominal was wrong by ~2× —
the per-conn slope is ~180 KB, not 98 KB — and on top of that
the close path shreds the heap into a ~170× higher fragment
count, so the actual ceiling is reached well before the
per-conn × conn-count product would predict.

Measurement env: HVF runner with `--ram=768 --cpus=4`. The runner
caps mapped guest RAM at 1 GiB (vm.rs:207 — one L1 block at the
ARM 4 KiB granule), so the absolute conn ceiling on HVF is ~¼
of GCE's; the **shape of the heap-usage curve** is what we read
out. Boot reports `mem: 764 / 768 MB heap`,
`/obs.kernel.heap_claimed_bytes = 802 811 904`.

### H1 — Heap is 3 GB on GCE / 766 MB on HVF: **CONFIRMED, but GCE shape is wrong**

`/obs.kernel` at idle on HVF reports
`heap_allocated_bytes = 6.85 MB`,
`heap_available_bytes = 758.76 MB`,
`heap_claimed_bytes = 765.8 MB` — matches `mem: 764 / 768 MB heap`
on the boot banner. GCE c3 deploy boot log shows `mem: 3011 /
3012 MB heap`.

**But c3-highcpu-8 has 16 GB of RAM** (Google's spec). We are
using **3 of 16 GB**. The 13 GB shortfall is two stacked
boot-time limits:

1. **`boot.S` identity-maps only the first 4 GiB.** `boot_pml4
    → boot_pdpt → boot_pd0..3` covers "4 × 512 × 2MB = 4GB" of
    physical address space (boot.S:77-78, boot.S:144-157). Any
    physical address ≥ 4 GiB is not mapped at boot. GCE puts the
    16 GiB of guest RAM as `[0, 3 GiB)` (below the PCI MMIO
    window at 3-4 GiB) plus `[4 GiB, 16 GiB)` above the hole.
    Only the low ~3 GiB is reachable through the boot map.
2. **`mm::init_heap` defensively skips any `MEM_AVAILABLE`
    region with `base >= 0x1_0000_0000`** (mm.rs:182, comment
    on line 173-184). Even if the boot map did cover more,
    `claim_phys` writes through `hhdm + phys`; without an HHDM
    or identity map for the upper RAM that write would
    triple-fault talc on the first claim. So the 13 GiB above
    4 GiB is silently dropped from the heap-claim loop.

The mm.rs comment on line 180-181 claims "Limine on x86_64 has
its own HHDM that covers the full RAM and doesn't hit this
path." That is **stale** as of this writing — the GCE deploy
target is `//apps/webserver:webserver_iso_x86_64` (Limine ISO,
per `deploy-gcloud.sh`), but the skip at mm.rs:182 fires
regardless of `hhdm_offset`. The boot log proves it: a c3-
highcpu-8 with 16 GiB physical RAM reports
`mem: 3011 / 3012 MB heap`.

So the 3 GB heap on GCE is not a hardware ceiling — it's a
boot-stub / heap-init pair that was sized for the kvm-vm 4 GiB
guest and hasn't been revisited since c3 became the production
shape. Fixing the boot stub to identity-map past 4 GiB (or use
Limine's HHDM properly for `claim_phys`) **multiplies the heap
ceiling by 5×, with no per-conn-slope work**. This dominates
every other ceiling-mover in this investigation.

### H2 — Per-conn nominal is wrong; actual slope is ~182 KB/conn: **CONFIRMED**

Drove HTTPS `/health` against the local HVF for 30 s at multiple
N, sampling `/obs` at t=8 s, 15 s, 23 s into each run. Per-conn
delta vs the idle baseline (`alloc=6.85 MB`, `live_conns=1`):

| N (target) | live_conns | heap_alloc | per-live-conn | tasks_spawned | frag_count |
|-----------:|-----------:|-----------:|--------------:|--------------:|-----------:|
| (idle)     |          1 |   6.85 MB  |          —    |            29 |          9 |
|        100 |        102 |  24.64 MB  | **179.8 KB**  |           130 |          9 |
|        500 |        504 |  96.10 MB  | **181.6 KB**  |           560 |         21 |
|      1 500 |      1 598 | 290.76 MB  | **182.0 KB**  |         2 061 |        104 |
|      2 500 |      2 502 | 451.89 MB  | **182.0 KB**  |         2 530 |         11 |

The slope is flat at ~182 KB/live-conn across two orders of
magnitude. Nominal per-conn from the assignment was 98 KB. The
~84 KB gap is everything the nominal omitted:

| Source                                                        | Bytes |
|---------------------------------------------------------------|------:|
| TCP `rx_ring` (lazy, preserved per slot)                      | 16 KB |
| ~~TCP `rtx_buf` (lazy, preserved per slot)~~ **RETIRED — replaced by `rtx_queue`** | ~~64 KB~~ → on-demand |
| ~~`Box<TlsConnImpl>` (3×inline rx/tx/pt + keys + cfg Arc)~~ **RETIRED rx_buf + pt_buf** — now 4 KB tx_buf + keys + cfg Arc | ~~~38 KB~~ → ~6 KB |
| `TlsStream` `record_scratch` (lazy on scratch fallback; `TLS_RECORD_LEN` ≈ 16 KB) | ~16 KB |
| **Handler future `Box`** — `serve_conn` future state:         |      |
| &nbsp;&nbsp;`req: Request` (16-header array + 256 B path)         | ~5.5 KB |
| &nbsp;&nbsp;`header_storage: [u8; 1024]`                         | 1 KB |
| &nbsp;&nbsp;`TlsStream.tx_scratch: [u8; 2048]`                    | 2 KB |
| &nbsp;&nbsp;`carry: Option<IOBuf>` (only when chunk overruns HEAD) | ~24 B |
| `TcpConnection` slot (in pool segment, ~600 B)                | ~1 KB |
| Talc per-allocation headers + alignment slack                 | ~40 KB |
| **Total**                                                     | **~166 KB** |

The **handler future Box** used to be ~33 KB — half of that was
`serve_conn`'s inline 16 KiB parse buffer. The streaming-parser
refactor (`StreamingRequestParser`) dropped the buffer entirely;
the parser writes directly into the per-conn `Request` fields as
chunk bytes arrive off `recv_chunk`. What's left in the future
state is the `Request` itself, the response-header IOBuf scratch,
and a small `carry: Option<IOBuf>` slot for the rare case where a
chunk carries body bytes / next-pipelined-request bytes past the
HEAD terminator. The Box-per-spawn still pays once per accept
(handler future) and once per TLS conn (`Box<TlsConnImpl>` =
~5 KB metadata + 4 KB inline tx_buf; the former ~34 KB of inline
rx/pt staging buffers retired by the streaming-RX refactor).

Apply 166 KB to GCE's 3 GB heap → **ceiling ≈ 18.5 K conns**
before fragmentation. That's exactly the 18 K end of the
"cliffs at 18–24 K" band; the per-conn slope alone explains the
cliff position.

**Post-`rtx_queue` retirement, the measured slope dropped to 88 KB
at 18 K conns** (A/B against branch baseline 909f570 on 2026-05-28,
both at 18 K live conns, same throughput; full table further down
in "Recommended ceiling-movers" #2). The 67 KB delta vs the
measured baseline matches the retired `rtx_buf` (64 KB) within
talc per-allocation noise. The H2 estimate above (166 KB) ran
~11 KB hot of the measured baseline (155 KB) — probably the lazy
`record_scratch` line didn't fire on every conn within the bench
window; the relative drop is the load-bearing number.

Linear projection on the measured slope: 3 GB / 88 KB ≈ **34 K**
conns vs the 18 K observed on the old slope. Fragmentation will
take some of that back, but the bench above ran the new slope to
exactly the old cliff (18 K conns) and finished with 1.62 GB heap
and 2.83 GB available — nowhere near OOM.

**Follow-on** (this branch, `tls/rx-chunk-streaming`): the TLS RX
streaming refactor retired the 17 KB `rx_buf` + 17 KB `pt_buf` pair
inside `TlsServer`, dropping the `Box<TlsConnImpl>` from ~38 KB to
~5 KB. Projected slope at 18 K conns drops further from 88 KB →
~55 KB (88 − 33). At 3 GB heap the linear projection becomes
~55 K conns. Not re-measured at 18 K yet; the `get_tls` /
`get_tcp` 1c/2c/4c bench on `tls/rx-chunk-streaming` showed flat
throughput vs `main` (deltas within 5% inter-run noise), so the
refactor pays for itself purely as a per-conn slope move with no
throughput cost.

### H3 — Buffers preserved across conn close: **CONFIRMED with twist**

`free_connection` → `reset_preserving` hands `rx_ring` (16 KB) and
the `rtx_queue` deque (idle capacity, tens of bytes) back to the
same slot. Pre-`rtx_queue` retirement, this was an 80 KB
ride-along (the 64 KB `rtx_buf` was the other slot-preserved
block); the queue's per-entry IOBufs are not preserved, only the
deque's small backing vec. For slots that ever transition out of
`Closed`, the 16 KB rx_ring is locked to the slot until pool
shutdown.

But the more interesting load-bearing fact: `live_conns` counts
**every non-Closed / non-Listen state** including the
`TimeWait` 2×MSL hold (60 s, state.rs:184). Draining a 2 500-conn
bench:

| phase                       | live_conns | heap_alloc | alloc_count | fragment_count |
|-----------------------------|-----------:|-----------:|------------:|---------------:|
| peak (t=23 s mid-bench)     |     2 504  |  452.1 MB  |    16 233   |             11 |
| after wrk exits (+3 s)      |     1 132  |  317.3 MB  |    10 792   |      **1 853** |
| after 5 s of 100 fresh conns|     1 133  |  317.3 MB  |    10 790   |          1 857 |

The 1 132 `TIME_WAIT` slots still consume 317 MB — 280 KB each
above the 6.85 MB baseline. (At the time of this measurement, the
preserved per-slot blocks were 80 KB; post-`rtx_queue` retirement
they are ~16 KB. Numbers below predate the queue migration.)
That's more than the 80 KB preserved buffers alone, which
suggests the per-conn handler task hasn't
completed for those slots yet (likely blocked on TLS
`close_notify` or sitting in the recv-loop drain) and is still
holding the ~33 KB future Box + ~12 KB TLS Box + ~16 KB
`record_scratch`. The TLS `record_scratch` IS dropped on conn
close (per `TlsStream`'s `Drop`), but only once the future
itself drops — same epoch as the handler task completing.

Static-analysis correction: `record_scratch` is **not**
preserved-per-slot. It lives inside `TlsStream` which is a
field of the per-conn handler future. When the future returns,
the box drops. So at any moment, it's bounded by live-conn count,
not peak-conn count.

### H4 — talc fragmentation chews the deficit: **CONFIRMED, fires on drain**

`fragment_count` is the load-bearing signal:

| phase                           | fragment_count | (claimed - allocated) - available |
|---------------------------------|---------------:|----------------------------------:|
| idle                            |              9 |                              0 MB |
| steady state (2 500 conns)      |             11 |                              0 MB |
| drain (1 100 TIME_WAIT slots)   |      **1 853** |                              0 MB |
| after 5 s of 100 fresh conns    |          1 857 |                              0 MB |

At steady-state, the per-core "fill segments sequentially" pattern
keeps the heap tightly packed (just 11 holes across 16 K live
allocations). The instant wrk closes its conns the fragment count
goes up 170×. The pattern:

  * Live alloc shape per conn: 16 KB rx_ring, on-demand rtx_queue
    entries (≤ MSS each), ~16 KB record_scratch, ~5 KB TlsConnImpl
    (post rx_buf+pt_buf retirement), ~33 KB future Box. Mixed sizes
    interleaved on the heap.
  * On conn close the future/TLS/record_scratch free at scattered
    offsets, leaving ~16 KB-sized holes around still-live structures.
    Slot-preserved rx_ring doesn't free — it stays with the slot.
    The retired 64 KB `rtx_buf` used to be the other slot-preserved
    block; with `rtx_queue` the only retained per-slot capacity is
    the deque's backing vec (tens of bytes at idle, low KB when
    sending), so the "64 KB hole-around-the-still-live-slot"
    fragmentation pattern is gone.
  * The next batch of accepts allocates new futures + TLS state
    + record_scratch from the segregated-free-list, but the holes
    don't always match the new requests' sizes — slow consolidation.

So the GCE Stage-2/3 collapse mechanism gets worse the moment
wrk's `--timeout` starts firing and conns churn. Each
close→retry cycle adds fragmentation; eventually a 16 KB
record_scratch request can't be satisfied even though
`available_bytes` says there's room.

`(claimed - allocated) - available` stayed at 0 across this
measurement — talc accounts every byte. The fragment count *is*
the deadweight signal; bytes-wise the cost is bounded by talc's
~32 B per-block header (1 853 × 32 ≈ 60 KB direct overhead) but
the structural cost (which large alloc *can't fit anywhere*) is
unbounded.

### H5 — Real memory leak: **REJECTED**

Heap returns to a steady-state baseline modulo H3:

  * t=23 s peak: 452 MB
  * drain (live=1 132): 317 MB (released 135 MB ≈ 1 372 conns × ~100 KB
    of non-preserved per-conn — future Box, TLS state, record_scratch)
  * after 5 s of 100 fresh conns (live=1 133): 317.3 MB — net **+0 MB**

`heap_total_allocation_count` advanced 16 283 → 16 669 (+386 over
the drive-100 phase), so allocator activity continued, but
`heap_allocated_bytes` did not grow. Allocation/deallocation
balance.

### H6 — Multiple-allocator surprises: **REJECTED**

Audit of allocations outside talc's view:

  * Driver DMA buffers (virtio-net, gve): allocated once at boot
    via `alloc_pages` → talc-tracked, counted in
    `heap_allocated_bytes`. ~1 MB total.
  * Page-table pages (x86_64 mmu) and AP stacks (SMP boot):
    same — all through `alloc_pages` → talc.
  * Task arena `TaskArena.slots: [TaskSlot; 4096]` per worker:
    **static BSS**, not heap. The `BoxedFuture` each slot owns
    *is* heap, counted in H2's slope.
  * `TCP_HASH` (32 K entries × 10 B × per-core) and `LISTENERS`,
    `ACCEPT_RINGS`, `TICK_HEAD`: all static BSS, not heap.
  * `TlsConnPool.slots` (per-worker `Vec<Box<TlsConnImpl>>`,
    cap = 16): a small fixed pool that recycles a handful of
    boxes — negligible vs. per-live-conn cost.

Talc's `heap_allocated_bytes` is the authoritative number for
this stack.

### Reconciled accounting at the cliff

GCE c3-highcpu-8, 3 GB usable heap (out of 16 GB physical — see
H1), 8 cores, healthy zone before the cliff (cliff at 18 K conns):

```
Static  (boot) .................   ~7 MB
Per live conn × 18 K × 182 KB ...  3 200 MB              ← the cliff
Talc bookkeeping (~32 B/header) .   ~16 MB
Fragmentation slack (variable) ..  +0 to +200 MB during churn
────────────────────────────────────────────
                                   ≥ 3 200 MB        > 3 GB heap → OOM
```

The per-conn slope alone takes the heap past 3 GB at ~16.5 K
conns. The observed cliff at 18 K conns matches once you account
for some lazy buffers (record_scratch) being deferred until the
first send. Fragmentation is the multiplier on top — when conns
start cycling (loss / timeout / RST) the fragment count balloons
and any individual 16 KB request can hit "can't fit" even before
bytes-allocated exhausts. (Pre-rtx_queue retirement, 64 KB
requests for `rtx_buf` were the other failure point.)

### Recommended ceiling-movers (ranked by ceiling-shift)

The goal is to push the cliff past the current 18–24 K band. The
first item dwarfs everything below it.

0. **Unlock the other 13 GB of RAM on c3 (boot-stub / heap-init
   fix).** The c3-highcpu-8 has 16 GB; we use 3 GB (see H1). Two
   coupled fixes:
   * In `boot.S`, extend the bootstrap identity map past 4 GiB —
     either grow `boot_pdpt` to 16 entries (covers 16 GiB) plus
     16 PDs, or pivot to a single 1 GiB-page-mapped PDPT (cheaper:
     one PDPT × 16 entries with PS=1, no PD tables). Same shim,
     bigger reach.
   * In `mm::init_heap`, drop the `r.base >= 0x1_0000_0000` skip
     once the boot map covers the upper RAM. The skip exists
     because `claim_phys` writes through `hhdm + phys` and would
     fault on an unmapped upper region; with the boot map
     extended (or with proper Limine-HHDM use on the ISO path),
     the writes succeed.
   * Effect at current per-conn slope: **3 GB → 16 GB heap takes
     the cliff from 18 K → ~96 K conns**, before any per-conn
     work below. Even with conservative fragmentation slack the
     cliff lands well past 64 K — into the territory where CPU
     saturation (the original P0 #1–#3 in this doc) is the
     binding constraint again, which is the regime the rest of
     the doc was written for. *This item alone is the largest
     single ceiling-mover in the whole document.*

1. **`serve_conn` parse buffer: 16 KB inline → REMOVED.** (DONE)
   `StreamingRequestParser` reads chunk bytes directly off
   `recv_chunk`'s guard and writes parsed values straight into the
   per-conn `Request` fields — no inline parse buffer in the future
   state. `carry: Option<IOBuf>` (~24 B) handles the rare case
   where a chunk carries body bytes / next-pipelined bytes past the
   HEAD terminator. **Saved 16 KB/conn → cliff moved from ~18 K to
   ~25 K on GCE shape.**

2. **`TcpConnection` rtx_buf → IOBuf-backed `rtx_queue`. (DONE — measured)**
   The fixed 64 KiB `Box<[u8; RTX_BUF_BYTES]>` is gone; the per-conn
   retransmit-coverage path is now a `VecDeque<RtxEntry>` of owned
   IOBufs allocated per send and freed per ACK. Peak per-conn
   footprint scales with the live send window (≤ MSS × in-flight
   segments ≈ ~1.8 KB at a 64 KiB cwnd) rather than the fixed
   64 KiB reservation.

   **Update (2026-05-28, `tcp/rtx-share`):** the share-insertion
   step the SG-TX note below anticipated has **landed**.
   `rtx_on_data_sent` now `IOBuf::share()`s each sent chain part
   into refcount-shared (`Shared(Arc<…>)`) storage and stores that
   in the queue — replacing the `into_owned()`-into-a-staging-`Vec`
   path with a move. The full SG-TX win (the wire DMA reading
   straight from the queue's `Shared` buffer, no TX-frame copy at
   all) still needs scatter-gather descriptors in the driver and
   is not done; what landed eliminates the *staging* memcpy and
   sets up the queue entries as `Shared` Arcs ready for that DMA.

   **Measured (2026-05-28, GCE c3-highcpu-8, `https://…/health`
   wrk -c 18000 -d 30s, peak `/obs` poll). NOTE: measured at the
   `tcp/rtx-iobuf-queue` tip — i.e. PRE share-insertion, with the
   staging `Vec` still in place. The heap/conn figures are
   unaffected by share-insertion (the queue holds the same bytes
   either way); the alloc-count caveat below is what changed and
   is pending a re-measure.**

   | branch                                  | peak heap | live_conns | bytes/conn | req/s   |
   |-----------------------------------------|----------:|-----------:|-----------:|--------:|
   | baseline (909f570, pre-`rtx_queue`)     | 2.79 GB   |     18 001 | **155 KB** | 319 K   |
   | `tcp/rtx-iobuf-queue` tip               | 1.62 GB   |     18 001 | **88 KB**  | 320 K   |

   **Saves 63 KB/conn (matches the ~64 KB structural prediction —
   the residual KB is talc per-block header overhead). Throughput
   flat. Heap savings at 18 K conns: 1.17 GB.** Linear projection:
   3 GB / 88 KB ≈ 34 K-conn cliff vs the 18 K cliff at 155 KB/conn —
   the rest of the items below now bound the next cliff move.

   Caveat (pre-share-insertion measurement):
   `heap_total_allocation_count` jumped 88× (110 K → 9.8 M over
   30 s) — the per-send `Vec<u8>` staging in the old `rtx_retain`
   was the alloc-pressure source. The landed share-insertion
   retires that staging `Vec` on the chain path: each non-`Static`
   sent part now costs one `Arc` allocation (a `/health` response
   is mostly `Static` literals → those parts are free; only a
   rendered/`Heap` body part allocs). Net alloc-count direction
   is plausibly *down* (no per-send `Vec`; `Static` parts free),
   but this is **unmeasured** — a re-run of the 18 K-conn bench on
   `tcp/rtx-share` is the open follow-up to refresh this caveat
   and confirm the alloc-count moved the right way.

3. **`TlsStream.cipher_buf`: 8 KB inline → REMOVED.** (DONE)
   `pump_rx` now pulls ciphertext via `TcpStream::recv_chunk` and
   feeds the record reassembler in place — no per-conn ciphertext
   staging buffer. **Saved 8 KB/conn.**

3b. **`TlsServer.rx_buf` + `pt_buf`: 17 KB + 17 KB inline → REMOVED.** (DONE)
   `process_chunk` walks records directly inside the chunk's
   mutable byte slice — AEAD decrypts in place; no `rx_buf`
   ciphertext staging. Plaintext was initially queued as one owned
   `Vec<u8>` per record (`pending_plaintext: VecDeque<Vec<u8>>`),
   lifted to a Heap `IOBuf` at pop time — since superseded by the
   share-based queue below (`VecDeque<OwnedIOBuf>`). A lazily-allocated
   `rx_partial: Option<Box<[u8]>>` (one max-record-sized box)
   carries straddlers between chunks — unallocated on MSS-aligned
   /health steady state. **Saved ~34 KB/conn at steady state**
   plus one memcpy per inbound record (the prior rx_buf staging
   copy is gone; the into_owned at decrypt time replaces the prior
   pt_buf staging copy with a same-byte-volume but right-sized
   per-record alloc instead of a fixed 17 KB inline buffer).

   **Share-based plaintext queue (DONE — branch `tls/rx-share-queue`):**
   `pending_plaintext` is now `VecDeque<OwnedIOBuf>`. `process_chunk`
   takes the chunk by value (`IOBuf`), decrypts every record in place
   while it holds the chunk exclusively (refcount = 1, so the in-place
   AEAD can't CoW), then `share()`s the chunk once and hands each
   decrypted application-data record a `clone_shared()` + `narrow()`
   view scoped to its plaintext range. Per-record cost drops from
   `Vec alloc + memcpy` to one atomic increment; steady-state cost per
   chunk is 1 Arc alloc + N atomic incr/decr, zero memcpy on the
   plaintext path. This mirrors the rtx queue's share-insertion idiom
   (`rtx_on_data_sent` → `IOBuf::share` per chain part): the RX
   plaintext queue is now a refcounted shadow of the chunk's storage
   just as the rtx queue is of each sent segment. The enabling iobuf
   primitive is `OwnedIOBuf::try_from(IOBuf)` — fallible narrowing
   into the `Send` owning tier. The rx_partial straddler keeps its
   alloc+memcpy (its bytes live in the straddle box, not the chunk, so
   they can't share the chunk's storage); it's rare and bounded to one
   record per chunk transition.

   Trade-off: the chunk's storage (a NIC RX slot for an `External`
   chunk) now stays alive until the last queued view drops, rather
   than freeing the moment the plaintext was copied out. For prompt
   consumers (/health, drain-immediately) the hold is microseconds; a
   slowly-streamed body holds the slot for the body's lifetime. The
   existing `data_mut`-on-aliased-`Shared` CoW is a ready escape hatch
   if a queue-depth cap is ever needed.

   Bench A/B (GCE KVM, c3-highcpu-8, vs base `tls/rx-chunk-streaming`):
   `get_tls` — keep-alive HTTPS, which RX-decrypts the request HEAD
   through the changed `process_chunk` + queue path on every request —
   is flat within run-to-run noise: 129.4k→131.2k (1c),
   233.4k→231.1k (2c), 236.1k→235.4k (4c) req/s; TLS cy/B unchanged
   (8.2/9.3/12.4 ≈ 8.4/9.2/12.3). `allocs/iter` (net heap growth) is
   0.00 before and after — no leak, no regression.

   The bulk-record win (skipped per-record memcpy on 16 KB records)
   could not be measured at the time of this write-up: large uploads
   stalled before producing a throughput number. A `/obs` capture during
   a 256 KB × 16-conn upload pinned the cause — the server went ~99% idle
   (`core_idle_cycles` climbs, `core_busy_cycles` flat), RX flatlined
   (`rx_bytes` +2.8 KB over 16 s), and `http.responses_sent` (13) trailed
   `requests_parsed` (26) with no pool exhaustion (`rx_ring_oom=0`,
   `pool_exhausted=0`, `last_tx_drop=0`). That was a **TCP
   receive-window-update deadlock on large uploads over the streaming
   `recv_chunk` path** — body-size-dependent (32 KB uploads ran clean
   at ~4.1k req/s on the same server, 256 KB / 1 MB wedged) and
   TLS-independent (`upload_256k_tcp`, plain HTTP, stalled identically).
   It was **not** caused by this change: the receive window is accounted
   for inside `do_recv_chunk` / `rx_pop` before the chunk IOBuf is
   handed to the TLS layer, so holding that IOBuf longer in the share
   queue is strictly downstream of the window update.

   **Fixed in `ce562ff` (`net/tcp: answer zero-window persist probes;
   recover stalled RX consumer`).** The diagnosis above was confirmed:
   the zero-copy stash path in `do_recv_chunk` (`pending_chunk.take()`)
   returned without the `maybe_send_window_update` that the ring-drain
   path runs via `rx_pop`, so once the ring filled the window stayed 0,
   and a `recv_chunk` consumer that parked exactly as the ring filled
   never re-woke (no later segment to re-fire its waker). The fix makes
   `maybe_send_window_update` `pub(crate)` and, on **any** inbound
   segment for an Established conn, (a) re-advertises the window across
   the one-MSS SWS boundary and (b) re-fires the parked recv waker if RX
   data is still buffered — so the peer's RFC 9293 §3.8.6.1 persist
   probe becomes the recovery kick, bounding any stall to one persist
   interval. Verified on GCE KVM: 20/20 sequential + 10/10 1 MiB +
   12/12 concurrent 256 KiB TLS POSTs all 200, plain-HTTP 256 KB×16
   upload at ~842 req/s (was a full timeout). The skipped-memcpy win
   is now measurable on the upload workloads but was not re-benched in
   this subsection.

   With throughput unmeasurable, the alloc-count + memcpy reduction
   rests on the architecture: the N per-record `(Vec alloc + memcpy)`
   pairs per chunk are replaced by one Arc alloc + N atomic increments,
   with zero memcpy on the plaintext path.

4. **`Request` headers array: `[Header; 16]` → smaller default + grow.**
   Each `Header = 336 B`, so 16 × 336 = 5.4 KB. Browsers send
   8–12 headers; wrk sends 2–4. Cap at 8 inline + lazy `Vec`
   overflow. **Saves ~2.7 KB/conn.**

5. **Defragmentation pass on slot reuse.**
   At drain time we go from 11 → 1 853 fragments. A "best-fit
   coalesce" hint on every nth `free_connection` (or even just at
   slot recycle time) could keep the fragment_count lower. Talc
   exposes no defrag API today — would need a per-CPU slab for the
   common 16 KB / 64 KB sizes, or migrate to a buddy allocator
   underneath the per-size pools.

Items 1–4 are pure parameter changes, no architectural work,
and stack additively. With items 2 (rtx_queue, measured 155 → 88
KB/conn) and 3b (rx_buf + pt_buf, projected ~33 KB additional)
both landed, the bottom-up slope projection lands around ~55
KB/conn — back-of-envelope **3 GB / 55 KB ≈ 55 K conns**, moving
the cliff well past 24 K so the load-shedding doctrine (P0 #3)
can take over. But item 0 is **5× larger** on its own and is a
one-time boot fix, so it should land first regardless.

The cliff-correlated counters that already exist in `/obs` are
sufficient for tracking this:

  * `kernel.heap_allocated_bytes` / `heap_available_bytes` —
    drives the "are we approaching the wall?" graph.
  * `kernel.heap_fragment_count` — the early-warning signal;
    crosses 1 000 well before bytes-allocated saturates.
  * `tcp.live_conns` × per-conn slope = predicted heap
    consumption; deviation between predicted and observed flags
    a leak or unexpected allocator.
  * `kernel.heap_oom` / `last_oom` — the post-mortem if the
    in-flight graceful-handling branch is reverted.

No new probes worth keeping landed in this investigation — the
existing surface (commits `51914e2` for `live_conns` + the
existing `kernel` block) is sufficient. The HVF `--ram` ceiling
(~1 GB hard cap from the L1-block-size map in vm.rs:207) limits
how high HVF can drive this kind of test; a future
`--ram=2048` etc. would need a multi-block kernel-map change
in `boot.S`.

## Graceful-OOM tolerance audit (2026-05-25, post-fix branch)

The `fix/cliff-graceful-oom` branch made two allocation sites
graceful — the TLS record scratch (`crates/proto/tls/src/lib.rs:598`)
and the TCP pool segment growth (`crates/net/tcp/src/pool.rs:146`).
This subsection answers the next question: **with those two sites
fixed, does the unikernel actually survive a heap-OOM event, or
does it just hit a different panic site instead?** Answer:
**partial — one large panic site remains in the per-conn path** that
will still take the VM down when the heap fills.

### Method

Walk the allocation cascade from "SYN arrives" to "first byte of
response sent," classify every allocation as **GRACEFUL** (uses
`try_reserve_exact` or a manual `alloc::alloc::alloc` + null-check,
returns an error on failure), **PANIC** (uses `Vec::with_capacity`
/ `vec![…]` / `Box::new` / `Box::pin` without a graceful fallback),
or **INFALLIBLE** (allocation is into a static / BSS region; can't
fail). The audit covered `crates/net/tcp`, `crates/proto/tls`,
`crates/proto/http`, `crates/proto/http3`, `crates/runtime`, and
the driver hot paths.

### The conn-accept cascade

Per accepted TCP conn, in order (sizes are the bytes the request
asks the allocator for, including per-allocation overhead estimates
where applicable):

| # | Site | Bytes | Status |
|---|------|------:|--------|
| 1 | `tcp::pool.rs::grow_segment` — pool segment growth | ~64 K | **GRACEFUL** (fix branch) |
| 2 | `tcp::state.rs::ensure_rx_ring` — TCP receive ring | 16 K | **GRACEFUL** (try_reserve_exact, pre-existing) |
| 3 | `reactor/tcp.rs:665` — `Box::pin(handler_future)` | **~33 K** | **PANIC** |
| 4 | `tls::server.rs:355` — `Box::<TlsServer>::new_uninit()` | ~12 K | **PANIC** (mitigated by `TlsConnPool` recycle, cap=16/worker) |
| 5 | `tcp::state.rs::rtx_push` — retransmit queue grow | per-entry | **GRACEFUL** (try_reserve; sets `rtx_alloc_failed`) |
| 6 | `tls::lib.rs:598` — `record_scratch` (TLS app-data send) | ~16 K | **GRACEFUL** (fix branch) |

The fix branch closes #1 and #6. Sites #2 and #5 were already
graceful (TCP rings were the original pattern my fixes mirrored).
Site #4 is mitigated by per-worker pool recycling — after the
first 16 conns per worker (128 across the 8-core c3), every
subsequent accept pops a pre-allocated `Box<TlsServer>` from the
pool, no fresh alloc. So under sustained load, site #4 is a non-issue.

**Site #3 is the residual gap.** Every accepted TCP conn goes
through `Box::pin(async move { body(stream).await })` at
[`crates/runtime/executor/src/reactor/tcp.rs:665`](../crates/runtime/executor/src/reactor/tcp.rs#L665).
That's a ~9 KB heap allocation (the future state includes the
`Request` struct, the 1 KB `header_storage`, the 2 KB
`tx_scratch`, the `carry: Option<IOBuf>` slot, and the handler
body's own captured state — see the "H2" breakdown above; the
16 KiB inline parse buffer and the 8 KB `TlsStream.cipher_buf`
that used to dominate this allocation are both gone —
`StreamingRequestParser` reads chunk bytes directly and
`pump_rx` uses `TcpStream::recv_chunk`). The standard-library `Box::pin`
uses the global allocator and panics on null via
`alloc::alloc::handle_alloc_error`. With the heap exhausted,
this panic fires, runs `#[panic_handler]`, calls
`arch_shutdown`, and the VM goes `guestTerminate` — the
exact failure mode the fix branch was meant to eliminate.

### What the fix branch *does* prevent

Despite the residual gap, the two fixes do narrow the
failure window:

  * **Pool-segment growth failure (site #1) is now graceful.** Hit
    when the per-core slot pool grows past its current capacity
    AND the inner ~64 KB Vec alloc fails. Each fresh batch of 64
    conns/core triggers one such alloc; under cliff conditions
    this is the first big heap request after the small per-conn
    work (rx_ring is 16 KB, smaller chunks fit longer). So the
    fix catches the case where pool growth is the first request
    big enough to exceed available heap.
  * **TLS record scratch failure (site #6) is now graceful.** Hit
    on first app-data send per conn. Conns that successfully
    handshake but fail their first send (because the heap filled
    between handshake and send) now tear down gracefully instead
    of panicking.

What the fixes don't catch is the *common* OOM order — where the
heap fills *during* a burst of accept-loop spawns, with site #3
firing repeatedly across cores. That's the actual cliff
mechanism.

### Per-request panic sites

Once a conn is established, every request handler runs more
allocations. Most are small but still panic-on-OOM. Even with
admission gating at the accept level, a long-lived conn that
sees a transient OOM mid-request would die:

| Site | Bytes | When |
|------|------:|------|
| `tls::record.rs:649` — `vec![0u8; HEADER_LEN + plaintext_len + 1 + TAG_LEN]` | up to 16 K | TLS seal fallback (per-record) |
| `tls::record.rs:695` — `vec![0u8; HEADER_LEN + MAX_INNER_PLAINTEXT + TAG_LEN]` | ~16 K | TLS seal fallback (per-record) |
| `tls::aead.rs:431` — `vec![0u8; total]` | variable | AEAD seal/open |
| `tls::handshake/client_hello.rs:558-612` — several `vec![]` | small | TLS PSK handshake parsing (cold) |
| `http3::server.rs:321` — `vec![0u8; FRAMING_BUF_SIZE]` | 288 | HTTP/3 framing (small) |

The TLS record sites are the largest of these; under sustained
OOM where established conns continue to send, any of these would
panic. Less urgent than site #3 (per-request is much less
frequent than per-conn at the cliff) but worth fixing for
defense in depth.

### Driver path

Audited — clean. All driver-side allocations are once-at-boot:

  * gve / virtio-net DMA buffers and descriptor rings → allocated
    via `mm::alloc_pages` at driver init, never freed, never
    re-allocated on the per-packet path.
  * Page-table pages (x86_64 mmu) and AP stacks (SMP boot) — same.
  * `TaskArena.slots: [TaskSlot; 4096]` per worker — static BSS.
    Spawn IS heap (site #3 above), but the arena that hosts the
    spawned future is not.

No per-packet allocations on the driver hot path; the cliff is
purely the per-conn cascade.

### Gap list — what's needed for true graceful-OOM tolerance

In ranked priority:

1. **Make `Box::pin(handler_future)` graceful at
   `reactor/tcp.rs:665`** _(medium, ~30 LOC)_. The standard
   library doesn't expose a stable `Box::try_new` for arbitrary
   types, but the codebase has a precedent for the manual
   pattern at [`runtime/worker/src/lib.rs:173`](../crates/runtime/worker/src/lib.rs#L173):
   ```rust
   let layout = Layout::new::<F>();
   let raw = unsafe { alloc::alloc::alloc(layout) } as *mut F;
   if raw.is_null() {
       // graceful: don't spawn, drop the stream, count the
       // refused accept.
       return;
   }
   unsafe { raw.write(future); }
   let boxed = unsafe { Box::from_raw(raw) };
   let pinned: Pin<Box<dyn Future<Output = ()>>> = Pin::from(boxed);
   ```
   On failure, drop the `TcpStream` (which closes the conn with
   RST via TCP's existing `Drop` path) and bump a `spawn_oom`
   counter in TCP `/obs`. Wrap as `try_box_pin` in
   `runtime/executor/src/task.rs` so the same pattern can be
   reused at other `Box::pin` sites
   ([`reactor/udp.rs:1069`](../crates/runtime/executor/src/reactor/udp.rs#L1069)
   has the UDP equivalent).

2. **Heap-aware admission cap (P0 #4 below)** — _(small, ~30 LOC)_.
   The actually correct fix at the architecture level. With a
   `MIN_HEAP_HEADROOM_BYTES` check in `alloc_connection`, SYNs
   are refused upstream of the entire cascade so #3 never fires
   under OOM regardless of whether it's been made graceful.
   This + the existing fixes give "stable plateau under
   overload" instead of "graceful conn refusal at heap-OOM."
   The graceful-Box::pin work (item 1) becomes defense-in-depth
   for the case where admission control's predicted-heap
   estimate undershoots the actual.

3. **Make the per-request TLS record allocs graceful** _(small,
   each site ~5 LOC)_. The sites in `tls/record.rs:649` and
   `tls/record.rs:695` and `tls/aead.rs:431` should use
   `Vec::new()` + `try_reserve_exact` + return `Err` paths.
   The TLS send path already propagates `Err` upward; the
   audit just confirmed these sites currently panic on the
   alloc.

4. **Defense in depth: `TlsServer::new_box`** _(small, ~10 LOC)_.
   The `Box::<TlsServer>::new_uninit()` at
   `tls/server.rs:355` panics on OOM. Mitigated by the
   per-worker pool (cap=16 recycled boxes) so it only fires
   during warmup, but a strict graceful build would also fix
   this using the same `alloc::alloc::alloc` + null-check
   pattern.

### What "tolerate OOM" means after items 1+2 land

Item 1 alone gives "any individual conn-accept that hits OOM
gracefully drops the conn instead of taking down the VM" —
the VM survives but new conns get refused per-attempt. Item 2
makes the refusal predictable and counted (`syn_shed` in
TCP `/obs`) rather than racy and concentrated at the alloc
point. Together they deliver the production-ready
"stable plateau under overload" behavior, matching nginx /
tokio-hyper at the same cliff point.

Item 3 makes *existing* conns survive transient OOM during
their own request handling — a strictly weaker property than
the conn-accept survival above, but the right defense-in-depth
once the accept path is solid.

## Load shedding: what role does it play

Load shedding is a **survival** property, not a **protection**
property. It bounds the failure mode under overload — keeps the
server in a known degraded state ("some conns refused, the rest
served at ~128 K rps") instead of an unknown collapsed state
("0 rps, NIC silently dropping SYNs"). It does not:

  * Distinguish attackers from legitimate clients (per-IP limits /
    WAF / SYN cookies do that, not the admission gate).
  * Defend against volumetric attacks (link saturation is an
    upstream-scrubbing problem — Cloudflare / Cloud Armor / etc.).
  * Defend against SYN floods (that's SYN cookies — P2 #9).
  * **Move the saturation point** — that's what RX coalescing
    (P0 #1) and the per-poll cycle items do.

So it is the *floor* in the survival stack: necessary so the
cliff at saturation isn't catastrophic, but smaller in headline
impact than the items that raise where the cliff sits.

### What Linux / nginx / Envoy actually do

Useful reference, because the cheaper-than-it-looks pitfall is
inventing a homemade controller when a validated mechanism
exists:

  * **Linux kernel**: bounded `listen(backlog)` queue; SYN drops
    on overflow (`LINUX_MIB_LISTENOVERFLOWS`). SYN cookies extend
    capacity when the SYN queue fills (they don't shed). CoDel
    qdisc for packet-level AQM. **No CPU-feedback admission gate
    in the kernel.**
  * **nginx**: static caps — `worker_connections`, `limit_conn`,
    `limit_req`. Count-based, not feedback-based.
  * **Envoy / Netflix concurrency-limits**: adaptive concurrency
    on a latency target (Vegas / Gradient) — admit more when p99
    drops, less when it grows.

The validated forms are queue-depth (Linux) and latency-target
(Netflix). Per-core idle % is a homemade variant — cheap to
read, but lagging (it fires after you've already entered the
feedback loop) and noisy (sampled EWMA). Reserve it for "we
tried the validated signals and they cost too much."

### Recommended layering

In ascending sophistication / cost:

1. **Deterministic count cap** (small; ship anytime).
   `alloc_connection` already returns `None` past slot-pool
   exhaustion — make that path *counted* (`syn_shed` counter)
   and add a per-core cap below the pool size so **the cliff is
   bounded by code, not by NIC drops**. Closest analogue:
   Linux's `listen(backlog)`. No controller, no signal — pure
   capacity wall. This is the ship-now form. Bench impact:
   stable plateau at ~128 K rps under overload instead of cliff
   to 0, same as any controller would deliver, with none of the
   tuning surface.
2. **Adaptive controller on a validated signal** (medium; only
   with measurement). Once (1) is in place *and* RX coalescing
   + hot/cold split have landed *and* the cliff still moves with
   workload, pick **one** validated signal — accept-to-completion
   delay (CoDel-style) or p99 latency vs target (Vegas-style) —
   and feed an EWMA into the gate. Aim for the layer that
   matches the *failure shape* (latency tail) rather than a CPU
   symptom.
3. **Per-core idle %** (aspirational; cheap-but-lagging variant
   of (2)). Design notes preserved below in case profiling
   later shows the validated signals cost too much for this
   workload. Don't ship this before (1) and only consider it
   after (2)'s measurement evidence motivates a cheaper signal.

Steps (2) and (3) are P3 territory until measurement says the
fixed cap from (1) is provably insufficient.

### Design notes — adaptive controller on per-core idle % (aspirational)

The remainder of this section is preserved from the original
proposal as design reference if (3) is ever revisited. It is
**not** what we ship first.

#### Signal: per-core CPU idle %

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

#### Why this doesn't cap full potential

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

#### Hysteresis

Without a gap between the shed-on and shed-off thresholds the
gate oscillates: shed fires at 1 % idle → load drops → idle pops
to 2 % → shed releases → load resumes → idle dips to 0.9 % →
shed fires → ... A 1 %/8 % band with the "stay with last
decision" rule above gives the system time to absorb the change
before re-evaluating. Standard thermostat pattern.

#### Where the gate goes

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

#### Sibling signals worth considering instead

If we ever reach for an adaptive controller, these are the
validated alternatives — both are what production stacks
actually ship, and either is preferable to idle % as a first
adaptive signal:

  * **CoDel** (Linux's CAKE qdisc, RFC 8290): track the
    accept-to-handler-completion delay; shed when the **minimum**
    over a sliding window exceeds a target. Catches bufferbloat
    that idle % misses (a core can be "busy" doing wasted work on
    timed-out conns and still have low effective throughput).
  * **Adaptive concurrency limits** (Netflix's Vegas / Gradient
    algorithms): run a feedback controller on p99 latency vs a
    target — admit more when latency drops, less when it grows.
    Better for tracking the actual knee of the throughput curve.

Either of these is the (2) in "Recommended layering" above.
Per-core idle stays an option only as a cheap fallback if
profiling shows the per-request timestamping that CoDel /
Vegas need is itself too expensive on this workload.

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

Prior revision of this section had **two** cliff-mover items
(RX coalescing + the `TcpConnection` hot/cold split) plus a
small deterministic-cap shed. The hot/cold split was **tested
and rejected** — see "Falsified hypotheses + open suspects"
above. P0 is now one cliff-mover, one diagnostic step, and the
small cap shed:

1. **RX coalescing (GRO / RSC)** _(medium-large, owned by
   [`rx-path-optimizations.md`](rx-path-optimizations.md))_
   - `init_pci_modern` currently masks off `VIRTIO_NET_F_GUEST_TSO4`
     and friends (see `VIRTIO_NET_RX_OFFLOAD_MASK`) — the comment
     notes our RX path only handles single-descriptor ≤MTU frames.
     Enabling these lets the host coalesce N segments into one
     super-frame, cutting per-packet stack overhead 5–10× on the
     RX hot path. Single biggest expected lift for `cycles/request`
     past the cliff investigation's data-structure wins, and the
     direct fix for the NIC-RX-overflow half of the Stage-3
     mechanism (fewer frames per byte → ring fills more slowly).
     **Defer to** `rx-path-optimizations.md` items **I + M–O**
     (virtio-net `MRG_RXBUF` + RSC) and **J** (gve DQO_RDA RSC
     enable). Those items pre-existed this investigation — they
     own the implementation; this doc just names them as the
     highest-impact cycles/poll reducer left. Precondition item
     **M** already landed 2026-05-18. The first ship attempt
     (`rx-items-i-j-dqo-rsc`) regressed catastrophically on
     `upload_32k_*` and 4 c `get_tcp`; bisecting I-only vs I+J
     is the next move for that branch.

2. **Diagnose the 24 K cliff with the new `/obs` surface**
   _(diagnostic, no LOC if measurement only)_
   - The Stage-3 cache-pressure hypothesis was falsified by the
     hot/cold split experiment. We don't yet know what *is*
     driving the 24 K cliff. Commit `51914e2` landed
     `rx_cycles` / `tick_cycles` / `live_conns` / `armed_now`
     on `main`; use them. First question: during a 24 K-conn
     bench, does `live_conns` reach 24 K, or do SYNs drop at the
     gVNIC ring before `alloc_connection` ever runs? Cross-check
     against `gve_rx_discards`. The answer routes between the
     server-side suspect list (accept ring, TLS handshake
     serialization, conn distribution) and the upstream-of-us
     suspects (NIC ring, loadgen ephemeral ports). **Do this
     before designing the next cliff-mover** — the wrong
     hypothesis sank the hot/cold split.

3. **Deterministic conn-count cap (minimal load shedding)**
   _(small, ~30 LOC, this doc)_
   - `alloc_connection` already returns `None` past slot-pool
     exhaustion — make that path *counted* (`syn_shed` counter
     in TCP `/obs`) and add a per-core cap *below* slot-pool size
     so the cliff is bounded by code rather than by NIC RX-ring
     SYN drops. No controller, no idle-% sampling, no hysteresis
     — pure capacity wall, the form Linux's `listen(backlog)`
     uses. Bench impact same as the adaptive form would deliver:
     stable plateau under overload instead of collapse to 0.
     **Caveat after the hot/cold split outcome:** this only
     helps if the cliff is server-side (P0 #2 confirms). If
     SYNs are dropping upstream of us, a cap does nothing.
     See "Load shedding: what role does it play" above for the
     design discussion and the deferred adaptive variants.

4. ~~**`TcpConnection` hot/cold split**~~ — **tested and
   rejected 2026-05-24.** Branch `tcp-hot-cold-split` is the
   unmerged record (delete the branch + `snug-flower` worktree
   when convenient). Cliff didn't move; per-packet cycles got
   *worse*. Full data in "Falsified hypotheses + open suspects".

5. ~~**Run Linux peer baseline (nginx + tokio-hyper)**~~ _(✓ done
   May 2026 — see "Headline: waitless vs Linux peers" above)_
   - Confirmed: waitless beats nginx by ~15–20 % rps everywhere
     and trails tokio-hyper by ~17–25 %. Closing the gap-to-tokio
     is what the P1 items below are sized to do (`~109 K cy/req`
     → `~85 K cy/req` would put us at parity).

### P1 — Per-poll cycle reduction

6. **Prefetch slot at `poll_slot` entry** _(tiny, this doc;
   value uncertain after hot/cold split rejection)_
   - One `_mm_prefetch` on the slot before the future runs hides
     L2→L1 latency on the slot. Originally pitched as ~5–10 %
     when cache-bound, paired with the now-rejected hot/cold
     split. With the cache-pressure hypothesis falsified, this
     is unlikely to do much on production-shape — measure with
     `rx_cycles` before / after rather than estimating. Cheap
     enough to try if profiling points here.

7. ~~**AES-GCM TLS cipher**~~ _(✓ done — migrated to
   `TLS_AES_128_GCM_SHA256`)_
   - We now negotiate only `TLS_AES_128_GCM_SHA256` (0x1301), the
     RFC 8446 §9.1 MTI suite. The prior `TLS_CHACHA20_POLY1305_SHA256`
     (~20 cy/B measured) was replaced — AES-GCM-128 with AES-NI /
     FEAT_AES is 1–3 cy/B (the streaming-parser A/B above measures the
     full TLS path at 8–12 cy/B incl. framing/AEAD/copy), and AES-NI is
     present on every deploy target (x86_64 Intel+AMD, aarch64 Apple
     Silicon + modern ARM). See `crates/proto/tls/src/handshake/mod.rs`
     (`cipher_suite::TLS_AES_128_GCM_SHA256`) for the rationale comment.
     Related: `tx-path-optimizations.md` items **C + D** already fused
     encrypt into the TX-slot to remove the post-encrypt memcpy. The
     remaining bulk-encrypt lever now lives in the AEAD implementation
     itself (tx-path doc), not in the cipher choice — that lever is
     pulled.

### P2 — Bigger architectural wins

8. **Softirq-style inline handler path** _(large)_
   - Trivial handlers (`/health`, `/static-*` with `&'static [u8]`
     bodies, no async work) could run **inline in `tcp_receive`**
     when a request completes — no task wakeup, no scheduler
     round-trip, no waker creation. Sidesteps the async-runtime
     tax for known-cheap endpoints. Expected 2–3× on /health-TLS
     specifically. Large change; sacrifices uniformity.

9. **Concrete handler type (drop `Box<dyn Future>`)** _(medium-large)_
   - Per-conn handler tasks all share one concrete future type for
     a given app. Storing them as `Box<dyn Future>` forces vtable
     dispatch on every poll. A `spawn_typed<F>` path with the
     concrete `F` lets LLVM inline the entire HTTP loop. ~5–10 %.
     The per-conn future *shape* (the handler API and how it's
     erased/boxed) is a stack-structure concern — see
     [`stack-architecture.md`](stack-architecture.md)'s "One handler
     API" contract; this item is the perf payoff once that shape is
     pinned down.

10. **SYN cookies** _(medium)_
   - Defer slot allocation until the 3-way ACK arrives — currently
     we allocate ~16 KB on every SYN (the rx_ring on first send).
     Encode all needed state in the SYN-ACK sequence number.
     Hardens against SYN floods; modest steady-state win.

### P3 — Foundational

11. **Per-CPU slab allocator** _(large)_
    - Single `Spinlock<Talc>` heap shared across cores. The slot
      pool's preserve-across-reuse covers steady-state, but
      first-time rx_ring allocation during warmup and per-send
      rtx_queue entry allocs still hit the lock. Per-CPU caches
      eliminate the contention.

12. **Adaptive admission controller (CoDel or Netflix Vegas)** _(medium)_
    - Only after P0 #3's fixed cap is in place *and* measurement
      shows the workload's per-conn cost varies enough that one
      number doesn't fit. Pick a **validated** signal — CoDel's
      accept-to-completion delay minimum, or Vegas's p99 latency
      target — and feed an EWMA into the gate. Tracks the actual
      knee of the throughput curve as workloads change. See
      "Load shedding: what role does it play" → "Recommended
      layering" step (2) above for the full design discussion;
      do NOT reach for per-core idle % as the signal here
      (lagging + noisy + no production precedent).

13. **eBPF/XDP-style early filter** _(large, possibly unfeasible)_
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
| `rx_cycles`, `rx_calls`                  | derive `cycles_per_packet`                     | Direct per-packet cost on the `tcp_receive` hot path (commit `51914e2`; landed for the cliff investigation, kept) |
| `tick_cycles`                            | pair with `tick_armed_seen`                    | Per-tick walk cost; derive `cycles_per_armed_slot` (commit `51914e2`) |
| `live_conns`                             | working-set gauge — should rise to bench target| Count of non-Closed / non-Listen slots, summed across cores. Diagnostic for "are SYNs reaching `alloc_connection` at all?" — if `live_conns << target conns` during a high-N bench, the cliff is upstream of us (NIC ring / loadgen ephemeral ports) (commit `51914e2`) |
| `armed_now`                              | typically ≤ ~10 on production-shape            | Current armed-list length (gauge, not counter). The hot/cold split rejection found this stays tiny in practice — `tick_cycles` is consequently small (commit `51914e2`) |

**Use:**

- `accept_iterations / accept_calls` is the accept ring's miss rate; > ~5 means either the ring is overflowing or pushed entries are going stale before pop.
- A non-zero `linear_find_calls` or `syn_scan_calls` means a fallback path is firing; both should stay at zero under healthy load.
- Asymmetric `tasks_polled_per_worker` means work isn't distributed evenly across cores.
- `tick_armed_seen / tick_calls` rising past ~50 % of pool means most conns have armed timers (high retx, abusive client, etc.).
- `rx_cycles / rx_calls` rising sharply with conn count is the cache-pressure signal the hot/cold split was supposed to flatten — if it ever does grow steeply on a new workload, revisit the rejected hypothesis with fresh evidence.
- `live_conns` not matching the bench target is the first thing to check at a cliff bench (see P0 #2).

## Stack-level GCE A/B — streaming-parser stack (2026-05-27)

`gcp-bench --env kvm --workload get_tcp,get_tls --cores 1,2,4 --duration 30` against a single GCE c3-highcpu-8 spot instance, loopback.

The 30 s duration matters. An initial 10 s pass surfaced what looked like a 5–7 % `get_tls` 2c regression in the streaming tip vs a recv-chunk-migration "peak" of 249 483, which triggered an optimisation round. A 30 s repeat showed that 249 k was a high outlier on a noise band that's ~10 % wide at 10 s; 30 s tightens the band to ~3 % and the gap dissolves.

| Workload | recv-chunk-migration (`11d9fb6`) | streaming + all opts (`a0155e5`) | Δ |
|---|---:|---:|---:|
| `get_tcp` 1c | 228 642 | 227 083 | flat |
| `get_tcp` 2c | 369 006 | 366 956 | flat |
| `get_tcp` 4c | 364 400 (`cli=2.1`) | 365 354 (`cli=2.0`) | flat (client-bound) |
| `get_tls` 1c | 131 031 | 131 252 | flat |
| `get_tls` 2c | 231 221 | **239 537** | **+3.6 %** |
| `get_tls` 4c | 239 491 (`cli=2.5`) | **244 889** (`cli=2.6`) | **+2.3 %** |

Reads:

* **`get_tls` 2c and 4c**: real +2–4 % win — memcpy elimination shows where the workload is compute-balanced (TLS spends most of its time in AEAD; the saved memcpy is the marginal cycle freed).
* **`get_tcp` 4c**: client-bound on the 8-vCPU host. wrk uses 2.0–2.1 cores; server uses 4; vhost-net adds per-queue kthreads. Total ≈ 6+ / 8 cores, no headroom for the load gen to scale further. Both branches plateau at ~365 k req/s — the copy-elimination win can't surface through that ceiling. An 8+ vCPU bench host would let `get_tcp` 4c be a clean measurement.
* **`get_tcp` 1c+2c, `get_tls` 1c**: bandwidth-flat (single-core was never memcpy-bound; 2c TCP carries ~3 % noise across the two 30 s runs of the same commit we did across this session).

End-state vs the pre-stack starting point: TLS up across 2c+4c, everything else flat or client-bound, paid for with the 16 KiB inline parse buffer gone from per-conn future state and the no-delimiter DoS gap closed.

### Optimisations that mattered

Three rounds of optimisation produced the final numbers:

1. **Vectorise the per-state scans** (commit `5182eb2`): replace byte-by-byte `match self.state` dispatch with bulk `iter().position()` + `copy_from_slice`. LLVM emits SIMD scans where the predicate is simple.
2. **Single-byte scan predicates** (commit `8e4cdbd`): switch `Target` / `Version` / `HeaderName` / `HeaderValue` from multi-byte ORs (`b == X || b == Y`) to single-byte (`b == X`). Multi-byte ORs partially defeated LLVM's autovectoriser. Came with a small strictness shift (lone-LF no longer tolerated — RFC 9112 mandates CRLF anyway).
3. **Skip body bookkeeping for CL=0** (commit `5f6d25b`): the GET fast path was calling `body.into_leftover()` and the carry-advance unconditionally; both are dead code when `content_length == 0`. Guarded both with `if content_length > 0`.

### Lessons

* **10 s benches lie**. The 2c TLS variance band was wide enough that a single 10 s run could be ~10 % off steady state. 30 s tightens to ~3 %. Future bench sessions on this stack should use ≥30 s.
* **The "regression"** that drove rounds (2) and (3) was a measurement artefact, not a real cost. Round (1) is the optimisation that actually mattered for the recovered `get_tcp` 2 c win.

### Remote env — production-shape datapath

`gcp-deploy-bench --cores 1,2,4,8 --duration 30 --workload get_tcp,get_tls`: unikernel on its own `waitless-webserver` GCE VM (c3-highcpu-8, gVNIC, real Andromeda network); loadgen on separate `kvm-vm` (n2-highcpu-8). Cross-VM internal-IP traffic — production shape, not loopback.

| Workload | recv-chunk-migration (`11d9fb6`) | streaming + all opts (`b419f11`) | Δ |
|---|---:|---:|---:|
| `get_tcp` 1c | 186 382 | 192 897 | +3.5 % |
| `get_tcp` 2c | 330 298 | 320 307 | −3.0 % |
| `get_tcp` 4c | 540 618 | 549 154 | +1.6 % |
| `get_tcp` 8c | 848 754 (`cli=8.0`) | 848 936 (`cli=8.0`) | flat (loadgen ceiling) |
| `get_tls` 1c | 128 358 | 123 227 | −4.0 % |
| `get_tls` 2c | 208 956 | 202 755 | −3.0 % |
| `get_tls` 4c | 357 260 | 353 193 | −1.1 % |
| `get_tls` 8c | 581 871 (`cli=8.0`) | 580 668 (`cli=8.0`) | flat (loadgen ceiling) |

Reads:

* **Scaling**: both branches scale 4.4×–4.7× from 1c → 8c — the streaming-parser stack matches the recv-chunk-migration baseline's scaling shape on production-shape datapath.
* **8c on both branches plateaus at the loadgen ceiling** (~849 k TCP / ~581 k TLS, `cli=8.0`). Identical numbers on both sides confirm the bottleneck is wrk on `kvm-vm`, not the server stack on `waitless-webserver`.
* **Single-sample 30 s noise floor on remote is wider than on loopback** — the per-cell ±4 % deltas at 1c–4c sit inside that band, sign-flipping across the matrix (TCP wins at 1c+4c, TCP loses at 2c; TLS loses small across 1c–4c). No coherent direction.
* **The eliminated chunk → buf memcpy is too small to surface through real-network jitter at single-sample resolution.** The local-loopback bench (above) shows the saving cleanly because inter-VM RTT noise is absent.

Bottom line — both benches agree: **no production regression**; the architectural wins (16 KiB inline buf gone, no-delimiter DoS gap closed) come at no measurable cost on the production datapath.
