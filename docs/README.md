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
| [`streaming-response.md`](streaming-response.md) | Write-as-you-read streaming response bodies: the `(&mut Request, &mut Response)` handler API + per-transport `ResponseSink` backpressure (h1 RefCell-duplex / h2 demux TX queue / h3 QUIC stream flow control). The implemented half of stack-architecture's handler-API contract. |
| [`tx-backpressure.md`](tx-backpressure.md) | TX backpressure & egress architecture: the two backpressure sources (per-flow CC vs shared-NIC saturation), the one ACK-released send buffer, and the staged path to a per-core DRR egress scheduler (`net_cc` / `net_egress`). |

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
| [`quic-golden.md`](quic-golden.md) | The QUIC golden-path throughput campaign: the pacing-cap bulk fix (~8–10× h3 downloads), HW UDP-GSO on DQO, the upload-reassembly cliff fix, HW UDP-RX-GRO ruled out, and the cross-env (c3/DQO, n2/GQI, kvm/virtio, HVF) before/after matrix. The QUIC results/narrative doc; per-mechanism plan state lives in the rx/tx trackers + gvnic. |

## Conformance

One **work-queue backlog per protocol** the server speaks;
`conformance-roadmap.md` is the shared test strategy + per-RFC *status* view
that ties them together.

| Doc | What it owns |
|-----|--------------|
| [`conformance-roadmap.md`](conformance-roadmap.md) | Conformance-testing strategy (the in-process harness pattern), the sequencing, and the per-RFC **status** view (Have/Missing/test) for **TCP** (Part 2) and the **QUIC transport** (Part 3, RFC 9000/9001/9002). Status view; the work queues are the per-protocol backlogs below. |
| [`tcp-backlog.md`](tcp-backlog.md) | **TCP** RFC gaps (SACK, out-of-order reassembly, MSS clamp, …), the **performance-parity-with-Linux** inventory (Reno-vs-CUBIC/BBR, ABC, pacing, RACK-TLP, buffer autotuning), and what's been closed (window scaling ✅, ABC ✅). |
| [`tls-backlog.md`](tls-backlog.md) | **TLS 1.3** gaps (HelloRetryRequest, key update, ticket-key rotation, cipher/curve breadth, production RNG, 0-RTT-deferred) — consolidated from scattered comments. |
| [`http2-backlog.md`](http2-backlog.md) | **HTTP/2** — build plan + the hardening/DoS/conformance tail. Not started; the build companion (crate decision, reuse map, multiplexing design). |
| [`http3-backlog.md`](http3-backlog.md) | **HTTP/3** (RFC 9114) + **QPACK** (RFC 9204) app-layer gaps (QPACK dynamic table, SETTINGS, error codes/GOAWAY, request-mapping conformance). |

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
