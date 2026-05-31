# Efficiency audit: mem/conn, allocs/req, copies/req, cross-core sync

Audit of the golden data path (IPv4 + TCP + TLS 1.3 + HTTP/1.1 keep-alive,
`GET /health`) against four efficiency axes, with a prioritized plan. Findings
are code-grounded (file:line in the source); the perf trackers
[`rx-path-optimizations.md`](rx-path-optimizations.md),
[`tx-path-optimizations.md`](tx-path-optimizations.md), and
[`high-concurrency-perf.md`](high-concurrency-perf.md) hold the per-item history.

## Update (2026-05-30) — measured: the central thesis was wrong

This audit was written from static code reading. A per-core magazine
allocator was then built to attack the "heap lock = #1 lever" thesis below,
and origin/main was profiled on GCE. **Both the magazine A/B and the
per-stage CPU decomposition falsify the thesis.** The numbers below are raw
`scripts/profile_obs.py` output over `/obs` deltas on **c3-highcpu-8 + gVNIC,
TLS `/health` keep-alive** (use [`obswin.sh`](../scripts/bench/obswin.sh) +
[`twolg.sh`](../scripts/bench/twolg.sh) to reproduce).

**The heap lock is not the bottleneck.** A per-core magazine front-end made
the hot allocs 99.95% lock-free on the contended gve-8c path it was built
for, and bought **~0 throughput** (gve-8c OFF 576K vs ON 570K/565K). The
"+67% `tcp_send` tax at 8c" is real micro-overhead but not throughput-
limiting. Magazine kept default-OFF; not landing.

**The architecture is already shared-nothing, and it scales.** Under TRUE
saturation (2× loadgen, ~950K rps TLS, 28.7M reqs, **idle 0%**): all 8 cores
99.7–99.8% busy, perfectly balanced, **1.0 rx_call/req + 1.0 send_call/req**,
zero visible cross-core contention. So 0-allocs/req is *not* the lever — the
serve path that contains the alloc is a small slice:

| stage (saturated, 24,192 cy/req total) | share |
|---|---|
| **NIC driver** (gVNIC RX/TX poll+flush) | **38.9%** |
| async-dispatch residual (recv-plumbing + future poll) | 22.1% |
| TLS (encrypt 9.5 + decrypt 7.1) | 16.6% |
| http parse/handler/build | 9.7% |
| **tcp_send (incl. the 1 alloc)** | **6.0%** |
| tcp_receive + tcp_tick | 6.7% |

**The NIC poll busy-spins.** event-loop loops/req: 30.9 under-loaded
(96.8% return no RX frame) → 9.4 saturated (89.3% empty). At half-load the
cores are still pinned 99.8% busy on empty polls — "idle 0%" means the poll
loop never sleeps, *not* that all cycles are useful work.

**Re-prioritized levers** (this supersedes "two levers, one nexus" below):
1. **NIC poll discipline** — stop busy-spinning empty polls (adaptive /
   event-driven poll, sleep-with-doorbell-wake). Reclaims wasted cycles at
   sub-saturation; cuts latency + power.
2. **async-dispatch residual (~22%) + gVNIC driver (~39%)** under saturation
   — structural (softirq-inline / async-flatten / driver batching), matching
   the `reference_tls_perf_levers` conclusion that this needs a big
   structural lever, not micro-opts.
3. **Stop the allocs/copies/heap-lock micro-work** — Tier-1 below targets a
   slice measured at <10% of cycles. Allocs/req=0 already landed (`1d46f90`)
   and is fine to keep, but it is not a throughput lever.

Everything below is the original 2026-05-28 static audit, kept for the
code-grounded findings (RX zero-copy, the sub-MSS TX fallback, mem/conn
slopes) — but read its "highest impact" / "heap lock" framing as **corrected
by this block**.

## Current state

| Axis | Current (golden path) | Optimal? | Gap |
|---|---|---|---|
| **Mem / connection** | ~31 KB idle / ~50 KB active established TLS conn (rx_ring 16 KB + handler future ~9.5 KB + `TlsConnImpl` ~5.3 KB; +record_scratch 16 KB lazy when active) | Close, but rx_ring + header arrays are oversized for small requests | ~16 KB/conn reclaimable |
| **Allocs / request** | **1 alloc + 1 free** — the response header's `into_owned()` copy in `rtx_push` (RFC 6298 retain of the borrowed header) | No — reachable **0/req** | 1 alloc, and it's heap-lock-contended (~1,245 cy) |
| **Copies / request** | **RX: 0 structural** (zero-copy `pending_chunk` move + in-place AEAD decrypt + in-place parse). **TX: 3 structural** (+1 inherent header format) | RX optimal; TX not — sub-MSS misses the TSO direct-encrypt path | 2–3 TX copies removable |
| **Cross-core sync** | Per-core sharded executor + conns; accept handoff and ACK→send-waker wake are **same-core**. ⚠️ *Claimed the global heap spinlock was the one true contention point — **falsified**, see the 2026-05-30 update: GCE-measured shared-nothing, 8 cores 99.8% balanced, no cross-core contention.* | **Yes, already** | The +67% send tax is real micro-overhead but not throughput-limiting (magazine A/B flat) |

**What's already optimal (do not re-touch):** RX is essentially zero-copy on the
golden path; the `rtx_queue` `VecDeque` migration (155→88 KB/conn) is done; the
TCP hot/cold struct split was tried and *rejected* (made per-packet 3–19%
slower); the accept path and steady-state wakes are same-core (no shared queue,
no round-robin atomic, no cross-core IPI — the `NEXT_TARGET_VCPU` in MEMORY is
HVF-runner-only). On c3/gVNIC we run Tier 1 (per-core RX queues) — the Tier-2
`RX_LOCK`/distributor/`RxInbox` only fires on single-queue GQI (n2/e2).

## The synthesis — two levers, one nexus

> ⚠️ **Superseded by the 2026-05-30 update.** The "per-core slab is the #1
> lever" claim below was the hypothesis the magazine was built to test; it
> was measured FALSE (flat throughput, heap lock not the bottleneck). Kept
> verbatim as the pre-measurement reasoning.

Three of the four axes converge:

- **The per-core slab allocator** is the #1 lever for **allocs/req** *and*
  **cross-core sync**. The global `static HEAP: Spinlock<Talc>`
  (`kernel/bare/mm.rs`) is the sole per-request, single-cache-line, held-region
  contention point — ~8M lock acquisitions/s at 8c × 1M rps — and it is the
  measured cause of the +67% `tcp_send` cy/req from 4→8c and the sub-linear
  scaling (TLS 1.49× vs tokio 1.70× for 4→8c) that *narrows* the tokio gap at
  scale. A per-core magazine front-end makes the common allocs uncontended.

- **The sub-MSS TX send path is the nexus of three problems at once.** For a
  small `/health` response, `try_send_tso` returns `None` (`send.rs`,
  `min_payload <= mss` — gve silently drops sub-MSS TSO frames), so the response
  takes the **scratch-seal fallback**, which incurs, per request:
  1. the **1 alloc/req** (`rtx_on_data_sent` → `rtx_push` → `into_owned()` of the
     borrowed header, `state.rs:724`),
  2. **2 of the 3 TX copies** (chain → `record_scratch`, then `record_scratch` →
     NIC slot),
  3. a **heap-lock acquisition** (the alloc above).

  Sealing small records **directly into the NIC TX slot** (a non-TSO direct-fill
  seal — the slot-fill machinery already exists for `try_send_tso`) and
  retaining a `clone_shared` view for rtx (instead of `into_owned`) collapses all
  three: 1 in-place seal, 0 extra copies, 0 allocs on this path.

So the high-leverage work is small: **the slab** (global) + **the sub-MSS TX
fast path** (the nexus). The mem/conn work is independent and matters only at
very high connection counts.

## Prioritized plan

### Tier 1 — cross-dimension levers (highest impact)

> **1. — DONE, NEGATIVE RESULT (2026-05-30).** The magazine was built, boot-
> fixed, thrash-fixed, and validated correct (gve-8c hit-rate 99.95%, no
> thrash) — but bought **~0 throughput** (gve-8c OFF 576K vs ON 570K/565K).
> The expected "+67% tax removed → tokio gap 1.7×→2.3–2.5×" did **not**
> materialise because the heap lock was never the throughput bottleneck (see
> the 2026-05-30 update). Kept default-OFF on `bool_flag`; not landing on
> main. The branch `perf/tls-beat-tokio` (cd35f87) preserves it for
> reference. Original plan text follows.

**1. Per-core slab / magazine allocator front-end.** *Axes: cross-core sync #1,
allocs/req.* Per-core, per-size-class free-lists serve the hot path lock-free;
only batch refill/flush touch the global talc (which stays the backing store —
cross-core frees are fine, blocks are fungible within a class). Expected: remove
the +67% 8c send-path tax → restore near-linear scaling → **widen the high-core
tokio gap from ~1.7× back toward ~2.3–2.5×** and lower the cores needed for 1M
TLS. **Risk: high** — the kernel allocator is correctness-critical and only
testable on HVF (boot+serve) + GCE (no native coverage); talc fragmentation
accounting (`heap_stats`, OOM path) must stay coherent. **Validate:** unit-test
the magazine/size-class logic; HVF 30-conn burst + soak; GCE 4c vs 8c A/B on
`tcp_send` cy/req + TLS scaling.

**2. Sub-MSS TX direct-fill seal + shareable retain.** *Axes: copies/req,
allocs/req, cross-core sync.* (a) Add a non-TSO direct-fill seal: acquire a
regular TX slot (`nic::acquire_tx_buf`), expose its payload region to
`seal_app_data` (as `try_send_tso` already does), seal in place, submit via the
normal path — removes the chain→scratch and scratch→slot copies (~430 B/req).
(b) Seal into a pooled `share()`-able `OwnedIOBuf` so the rtx queue retains a
`clone_shared` (1 atomic, 0 copy/alloc) instead of `into_owned` — removes the
last alloc/req (→ **0 allocs/req**) and the last reducible copy. **Risk: medium**
— TX-path correctness + the rtx retain-until-ACK lifetime (a pooled slab or a
small per-conn ring of sealed buffers, freed on ACK). **Validate:** tcp_test rtx
coverage; HVF functional; GCE allocs/req (expect 1→0) + send-path cy/req.

> **Status (2026-05-29).**
> - **2(b) DONE — allocs/req 1 → 0** (landed `1d46f90`). A per-conn reusable
>   inline retransmit-retain buffer (`RtxPayload::Inline`) replaces the borrowed
>   header/record `into_owned` copy; GCE-validated 1.00 → 0.000 on /health plain
>   and TLS. (Implemented as a copy-into-reusable-buffer rather than
>   `clone_shared`, but same net effect: no per-request heap alloc.)
> - **2(a) BLOCKED on gve — the direct-fill seal can't reduce the copies on the
>   GCE deploy.** It was implemented and GCE-tested: `direct_fill_sends = 0`
>   because **gve does not expose a regular direct-fill TX slot**
>   (`nic::acquire_tx_buf` returns `None` — gve's regular sends use the
>   stack-staged `build_and_send_frame` fallback; only the *TSO big-pool* slot is
>   exposed, and TSO drops sub-MSS frames). So sealing a small record straight
>   into a wire slot isn't possible on gve, and the sub-MSS scratch copies
>   persist. The slot-based attempt was reverted (clean no-op, not worth dead
>   code). Reducing these copies on gve would need either a *seal-into-the-
>   stack-frame* variant of `build_and_send_frame` (saves ~1 copy — below the
>   ~15–20% run-to-run noise, so low value), or a NIC/queue format that exposes
>   `acquire_tx_buf` (gve DQO_RDA in principle, "not advertised in our deploy
>   path"). Deferred as low-value until one of those holds. Note: the copies are
>   below-noise for throughput anyway (the win was the alloc/lock-acq, now done).

### Tier 2 — mem/connection (matters at 50K+ idle keep-alive conns)

> Prereq: **ceiling-mover #0** in `high-concurrency-perf.md` — unlock the other
> ~13 GB of c3 RAM (boot-stub / `mm::init_heap` fix). That is ~5× larger than all
> per-conn slope work combined and raises the *total* heap ceiling; land it first.

**3. rx_ring 16 KB → tiered (default 4–8 KB, grow lazily).** −8–12 KB/conn
(~400–600 MB at 50K). The 16 KB was sized to hold one max TLS record for large
*uploads*; the golden small-request path never needs it. **Risk: medium** —
`rcv_wnd`/SWS window logic assumes the ring size; needs tcp_test + an upload
regression. *Single biggest always-present block.*

**4. `Request` headers `[Header;16]` (5.4 KB) → 8 inline + lazy overflow.**
−3–4 KB/conn, always-present (helps idle conns). **Risk: low** — contained in
`http/request.rs`; streaming-parser append must handle overflow.

**5. Pool/shrink the TLS scratch buffers.** `record_scratch` (16 KB) and
`rx_partial` (16 KB) per-worker-pooled instead of per-conn (−16 KB/active-conn);
`tx_scratch` (2 KB) and `tx_buf` (4 KB→2 KB) shrink/pool (−4 KB/conn). **Risk:
medium** — the buffers are held `&mut self` across `.await` to prevent aliasing
under TX backpressure; a pool needs a drop-returned borrow guard.

### Tier 3 — second-order cross-core (do *after* the slab, so wins are measurable)

**6. Per-request shared `Counter`s → `PerCoreCounter`.** HTTP
(`requests_parsed`, `parse/handler/build_cycles`), TLS record stats
(`TLS_*_BYTES/RECORDS/CYCLES`), executor (`tasks_spawned/completed`) are single
shared `AtomicU64`s bumped per-request — cache-line ping-pong, below the
heap-lock noise floor today but the next tier once the slab lands. The
`PerCoreCounter` primitive already exists. **Risk: low** (additive, sum-on-read;
thread `current_worker()` to bump sites).

**7. Pad the gVNIC per-QP counters.** `[AtomicU64; 22]` in `gve` diag is not
cache-line-padded → QP indices 0–7 share one line → **false sharing at packet
rate** on TX/RX. Use a padded cell (like `obs::PerCoreCell`). **Risk: low**
(layout only).

## Doc corrections found by this audit

- **`tx-path-optimizations.md` is stale and should be fixed:** (a) its
  Allocations table lists `rx_buf` and `pt_buf` `Box<[u8;4096]>` allocated in
  `TlsServer::new` — both were **removed** (only `tx_buf` remains); the "11
  allocs for /diagnostics" figure depends on this and is wrong. (b) It implies
  the steady-state TX path is 2 copies/byte — true only for **>MSS** (TSO)
  responses; **sub-MSS responses like `/health` take a 3-memcpy fallback** that
  the doc never calls out (this audit's #1 TX finding). (c) The rtx whole-part
  `into_owned` optimization (commit `e284d00`) isn't reflected in the per-record
  alloc accounting.
- `high-concurrency-perf.md`'s ~55 KB/conn is an *active* upper bound; the idle
  keep-alive floor is ~31 KB (record_scratch/rx_partial are lazy and unallocated
  on the MSS-aligned `/health` steady state).
- RX-path doc claims all verify against current code (in-place AEAD,
  share-based plaintext queue, streaming parser, zero rx_ring on the fast path).

## Measurement status

Dynamically confirmed: allocs/req = 1 (`/obs` heap counter); heap-lock
contention (+67% send cy/req 4→8c); sub-linear scaling (1.49×). Code-confirmed
(static, high confidence): the single alloc site; RX zero-copy; the sub-MSS TX
3-copy fallback; same-core accept/wake; the heap lock as sole true-contention
point. Each Tier-1/2 lever is independently A/B-able on GCE when implemented
(allocs/req via `/obs`; cy/req + scaling via `scripts/profile_obs.py` +
`twolg.sh`; mem/conn via `heap_allocated_bytes / live_conns` at high
concurrency) — no further measurement is needed *before* implementing; validate
*per lever* after.
