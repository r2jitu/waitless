# Waitless docs

Design notes, performance trackers, and reference for the Waitless unikernel
network stack.

**New here?** Start with [`networking.md`](networking.md) (how the stack
dispatches packets today) and [`stack-architecture.md`](stack-architecture.md)
(the layer contracts and where the stack is headed), then
[`crates.md`](crates.md) (where the code lives). **What's next** is in
[`roadmap.md`](roadmap.md); **how the shipped stack was built** is in
[`design-history.md`](design-history.md).

## Architecture & contracts

| Doc | What it owns |
|-----|--------------|
| [`stack-architecture.md`](stack-architecture.md) | Inter-layer contracts and stack shape — the buffer currency, the stream trait, the handler API, the NIC/reactor backend abstraction, the **shared TCP+QUIC congestion-control / loss-recovery / pacing core**, and the two-stacks → one-golden-path convergence. The design/proposal lens; owns *structure*, not per-byte cost. |
| [`networking.md`](networking.md) | The RX/TX dispatch model as it works *today*: Tier 1 (per-core queue) vs Tier 2 (rotating distributor). The current-reality counterpart to `stack-architecture.md`. |
| [`iobuf-type-model.md`](iobuf-type-model.md) | The `iobuf` ownership / `Send` type model (`OwnedIOBuf`, `Chain<B>`, `IOBufRead`, the uniform drop/free + refcount-share contracts). |

## Performance

The perf docs route work by *cost locus* — see **[`high-concurrency-perf.md`](high-concurrency-perf.md) → "How this fits with the other perf docs"** for the authoritative "where does this fix belong?" rule.

| Doc | What it owns |
|-----|--------------|
| [`high-concurrency-perf.md`](high-concurrency-perf.md) | The 10 K+ concurrent-conn cliff: saturation behaviour, heap/OOM analysis, load shedding, per-conn data structures. Hosts the perf-doc routing taxonomy. |
| [`efficiency-audit.md`](efficiency-audit.md) | Cross-cutting audit of the four efficiency axes — mem/conn, allocs/req, copies/req, cross-core sync — with a prioritized plan. Synthesis across the rx/tx trackers + the per-core slab + the sub-MSS TX nexus; the "what to optimize next and why" doc. |
| [`rx-path-optimizations.md`](rx-path-optimizations.md) | Per-byte / per-frame **RX** cost: memcpy reduction, IOBuf zero-copy, HW GRO/RSC. (Items A–O + progress log.) |
| [`tx-path-optimizations.md`](tx-path-optimizations.md) | Per-byte / per-frame **TX** cost: encrypt-in-place, TSO, header fusion, UDP-GSO. (Items A–R + progress log.) |
| [`observability.md`](observability.md) | The `/obs` instrumentation doctrine and primitives (`Counter`, `PerCoreCounter`, `LastEvent`, `LatencyHist`). |
| [`gvnic.md`](gvnic.md) | gVNIC device behaviour and the DQO_RDA vs GQI_QPL queue formats. |

## Conformance

| Doc | What it owns |
|-----|--------------|
| [`tcp-conformance-backlog.md`](tcp-conformance-backlog.md) | TCP RFC gaps (SACK, out-of-order reassembly, MSS clamp, …), the **performance-parity-with-Linux** inventory (Reno-vs-CUBIC/BBR, ABC, pacing, RACK-TLP, buffer autotuning), and what's been closed (window scaling ✅). |
| [`conformance-roadmap.md`](conformance-roadmap.md) | Conformance-testing strategy + the QUIC RFC 9000/9002 backlog. |

## Reference & how-to

| Doc | What it owns |
|-----|--------------|
| [`benchmarking.md`](benchmarking.md) | How to run benches: `bench.py`, the GCE wrappers, the env matrix and workloads. Read first for "how do I bench?" |
| [`benchmark-results.md`](benchmark-results.md) | Published results: Waitless vs **tokio-hyper** on GCE c3/gVNIC (≈ 2–3× throughput, ~2× lower latency) and *why* (tokio-hyper's ~61 % kernel/syscall time). The "show me the numbers" doc. |
| [`crates.md`](crates.md) | The crate map: tiers, dependency layering, and the `crates/` layout. |
| [`consuming-as-a-library.md`](consuming-as-a-library.md) | Using Waitless as a Bazel dependency — the `MODULE.bazel` / `BUILD.bazel` boilerplate an app needs. |

## Roadmap & history

| Doc | What it owns |
|-----|--------------|
| [`roadmap.md`](roadmap.md) | What's next: the current frontier, Phase 6 advanced features, and deferred/parked items. |
| [`design-history.md`](design-history.md) | How the shipped stack was built — the phase-by-phase decisions and rationale (append-only record; formerly the root `ROADMAP.md`). |

---

**Doc conventions.** The rx/tx trackers keep an **append-only progress log** and
cite Bazel labels as-of-when-the-work-landed (not retro-rewritten), so older
entries may reference pre-`crates/` paths. Cross-doc references use stable
anchors (section names / item IDs), not line numbers. When you change a
*current-state* fact (a cipher, a memcpy count, a "current path"), grep the
sibling docs — the same fact is described from several angles and drifts easily.
