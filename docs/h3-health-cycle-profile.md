# h3 /health — per-request cycle deep dive

Goal: find where the CPU goes per h3 `GET /health` request, to settle whether
any single server-side hotspot caps throughput. Method: fine-grained cycle
brackets (`*_cycles` counters in `quic::diag` / `http3::diag`, read via `/obs`
deltas), run under QEMU/KVM on the kvm-vm (real x86 TSC, `cycles_per_us≈2699`,
virtio-net) driven by `loadgen h3-health`. Cycle *ratios within the async
runtime* transfer to GCE; the NIC fraction does not (virtio ≫ gve, and `busy`
includes the event-loop empty-poll spin).

## Per-request decomposition (within the async runtime, ~47–53K cyc ≈ 17–20 µs)

| phase | % of runtime | what it is |
|---|---|---|
| `flush_tx` (TX packet build) | **~28%** | frame assembly + pacing + all-PN-space scan + AEAD-seal + HP; ~2.5 `flush_outbound` calls/req |
| residual "glue" (unattributed) | **~37%** | executor/scheduling (2.4 task-polls/req) + recv read-loop + Request/Response struct build + write_response framing + discard_recv + progress event |
| `process_rx` (RX decrypt+dispatch) | ~15% | per inbound datagram (1.5/req) |
| `ship` (virtio TX submit) | ~8% | descriptor fill + doorbell |
| **crypto** (AEAD open+seal + HP) | **~8%** | stitched AES-128-GCM — *negligible* |
| **QPACK** (decode + encode) | **~7%** | header (de)compression — *negligible* |
| stream lifecycle (`reap` + `ensure_send_stream`) | ~6% | pooled (`send_pool`/`recv_pool`) — cheap |

Per-request counts (from `/obs`): 1.5 inbound datagrams, 2.0 outbound, 1.5
AEAD-opens, 2.0 AEAD-seals, **2.5 `flush_outbound` calls**, 2.4 task-polls,
1 recv-stream + 1 send-stream created & reaped, 1 conn-task iteration.

## Findings

1. **The "obvious" costs are negligible.** Crypto (~8%) + QPACK (~7%) ≈ 15%
   combined. This is *why* the crypto swap (stitched GCM), the VAES idea, and
   the packet-count micro-opts (delayed-ACK, no-op-flush) never moved
   throughput — they target tiny slices.
2. **Stream lifecycle is cheap (~6%).** The per-conn send/recv pools recycle
   the stream structs + buffers; `ensure_send_stream` is ~0.4%, `reap` ~1.4%
   (the latter is a small `Vec` alloc + a streams scan).
3. **The cost is diffuse per-request orchestration**, concentrated in two
   buckets: the TX packet-build machinery (`flush_tx`, ~28%, amplified by 2.5
   `flush_outbound` calls/req) and a ~37% executor/handler/recv/framing
   "glue" with **no single hotspot**. Everything else is spread thin.

Conclusion: there is **no single dominant server-side hotspot** to optimize —
the ~17–20 µs/req is the cumulative cost of a correct layered QUIC + h3 + async
pipeline. This matches the earlier black-box result (h3 /health ~230 K is
robust to crypto/packet/conn-cap levers; server RX→TX `request_latency` ≈ 64 µs
P50 is already small vs the ~280 µs client-observed, network+client-dominated).

## Where a lever *could* exist (modest, given the diffuse profile)

- **Cut `flush_outbound` calls/req (2.5 → ~1).** The response flush is the only
  one that must build a packet; the post-`process_datagram` flush is already a
  near-no-op (established fast path), and credit/other flushes could fold into
  the response. Targets the largest single bucket (~28%) but the *real*
  response packet-build is inherent, so the win is bounded.
- **Slim the `flush_outbound` established-1-RTT path** (skip dead per-call work:
  redundant `apply_peer_flow_control`, the full multi-space scan, pacing
  recompute when nothing is paced). Shaves the per-call cost of the ~2.5 calls.
- The ~37% "glue" is the async pipeline itself (task hops, struct construction,
  recv loop). Reducing it is an architectural change (e.g. fusing the
  conn-task and h3-handler-task) — high risk, low confidence, and the
  black-box latency decomposition says the server is already near its floor.

The instrumentation (`*_cycles` counters) is kept as permanent observability,
parallel to the existing tcp/tls/http cycle brackets; overhead is <1% (a
handful of `rdtsc` reads per request).

## Optimization pass — ideas attempted (one-by-one, keep-if-improvement)

| # | idea | result | kept? |
|---|---|---|---|
| 5 | `reap_finished_streams`: per-call heap `Vec` → stack array | `reap_cycles/req` 2025-2809 → 1236 (alloc removed); failed=0 | **kept** (`cc74890`) |
| 2 | skip the per-datagram flush when it's a no-op | `flush_calls/req` 2.5 → 2.0 (empty flushes skipped); dgrams unchanged | **kept** (`a47251f`) |
| 4 | gate the 1-RTT CRYPTO pop (skip 1 KiB memset+pop/pkt) | `flush_tx/req` ~15.0K → ~14.0K (sub-noise); failed=0 | **kept** (`bc0adfd`) |
| 1 | inline-until-pending handler dispatch | analyzed, **not pursued** (below) | — |
| 3 | cross-connection TX batching | analyzed, **not pursued** (= pending #43) | — |

**GCE c3/gve A/B of the kept set (#5+#2+#4) vs main** — h3 /health par=64, 3
runs each, failed=0: branch median **234.9 K** (230.3/234.9/236.7) vs main
median **233.1 K** (233.1/226.0/233.3) = **+0.8%, within the ±15% spot noise**.
So the three are **provable per-request work reductions** (kvm cycle counters
confirm: 1 fewer heap alloc/req, 0.5 fewer `flush_outbound` entries/req, a
1 KiB memset+pop dropped per emitted packet) but **throughput-neutral** on the
noise-limited /health benchmark — efficiency/density wins, not a throughput
lever. Kept because each is correct, low-risk, and improves the metric it
targets; reverting would discard real (if sub-noise) work cuts.

**#1 and #3 — analyzed, not implemented** (unsuitable for a try-and-revert
loop): #1's handler is a long-lived spawned future (the `accept_stream` loop),
so "inline-until-pending" means the conn task owns + hand-polls it — bypassing
the executor's Waker contract and breaking streaming/upload handlers that
genuinely `await` (single-waiter `progress` event, task #30). The profile also
shows the executor is already efficient (2.45 polls/req, 1.0 conn-iter/req) and
the hop is ~10-15 µs. #3 is the same restructure as the pending `net_egress`
per-core-TX-queue work. Both: large + invariant-breaking for a profile-bounded
upside. Net: per-request micro-opts banked; architectural levers left open.

## Decisive prototype — "is the architecture the limiter?" → NO

Hypothesis: the layered h3 pipeline (handler task + QPACK + `Request`/`Response`
+ streams) is overly complicated and that's what caps throughput. Test: a
throwaway flag (`H3_HEALTH_FAST_PATH`, reverted) that answers an h3 request
with a fixed /health 200 **inline in the accept loop**, skipping the recv
read-loop + QPACK-decode + `Request`/`Response` + routing + the generic
handler — i.e. collapsing the whole http3 per-request pipeline (it keeps only
QUIC RX-decrypt → `write_response` QPACK-encode/framing → SendStream → seal →
ship, plus the conn_task↔handler hop).

Result: kvm cyc/req confirmed the bypass (`qpack_decode` → 0, `serve` → 0,
runtime ~50-58K → **44.8K**, ~15-20% less server CPU/req). But **GCE c3/gve
throughput was UNCHANGED: 231.3 K median (228.9/231.3/232.1) vs the 233.1 K
baseline** — identical within noise, despite ~20% less server CPU.

**Conclusion: the architecture's per-request complexity is NOT the throughput
limiter.** Removing ~all of it bought 0 throughput. The ~233 K h3 /health
ceiling is set by **closed-loop latency (network RTT ~280 µs) × connection
count, co-limited by the QUIC-client (loadgen) cost** — not server CPU or
pipeline depth. This is *why* every CPU micro-opt was throughput-neutral: there
is no server-CPU headroom to reclaim because CPU is not the bind. A simpler
server design would land at the same number. (The architecture IS heavier than
h1's inline path, but that weight isn't what caps this benchmark.) To raise the
number you must lower per-request *latency* (RTT/transport) or offer more clean
concurrency than a single QUIC-generating loadgen can.
