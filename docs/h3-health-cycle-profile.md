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
