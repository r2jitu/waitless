# h3 /health — per-request cost, root-caused

**Question:** why does HTTP/3 `GET /health` (a ~60-byte keep-alive request/response)
top out well below HTTP/1.1 on this server? (Measured h1 ~419K / h2 ~387K / h3 ~250K rps.)

**Answer (validated on GCE c3-highcpu-4 / gVNIC):** at saturation **both protocols
peg all cores at 100% CPU**, and **h3 costs ~2.1× the CPU per request of h1**
(~16.2 µs vs ~7.7 µs) — which is exactly the throughput ratio. The gap is the
**intrinsic per-request cost of QUIC + HTTP/3** (per-packet AEAD on request *and*
response, QPACK, the async conn-task↔handler orchestration, H3 framing), *not* any
one hotspot and *not* a server defect. It sits near the ~1.4–1.6× floor the
literature reports for a correct userspace QUIC+H3 stack once syscalls and TX
offload are removed (which this unikernel already does). **There is no cheap
server-side throughput lever; closing it further needs a structural cut in
per-request processing.**

---

## The root cause: CPU-bound at saturation, ~2× CPU/req

Measured at *saturating* concurrency (par=256 — not par=64, which is below h3's
knee and gave a misleading "latency-bound" read, see the log):

| par=256 | rps | device pps | pkts/req | cores busy | cyc/loop | CPU/req |
|---|---|---|---|---|---|---|
| **h1** | ~520 K | 1.03 M | 2.00 | 100 % | 2,293 | **~7.7 µs** |
| **h3** | ~247 K | 866 K | 3.50 | 100 % | **238,510** | **~16.2 µs** |

Both are genuinely **CPU-bound on real work, not empty-poll spin** — ruled out via
`core_loops`/`core_poll_work`: h1's loops average 2.3 K cycles (95% cheap empty
laps), but h3's are **238 K cycles** (~5 requests of real work per loop). CPU/req =
`4 cores × 2.699e9 cyc/s ÷ rps`: h1 ≈ 20.7 K cyc, h3 ≈ 43.9 K cyc. **Ratio 2.12 =
the throughput ratio (520 ÷ 247).** It is *not* a device packet-rate wall — h1
connection-scaling pushes the NIC to 1.06 M pps, well past h3's 866 K.

## Why it's not the "obvious" things

Per-request cycle decomposition (rdtsc brackets, read via `/obs` deltas; ratios
transfer from kvm, the NIC fraction doesn't):

| phase | % of per-req cyc | note |
|---|---|---|
| `flush_tx` (TX packet build) | ~28 % | frame assembly + pacing + AEAD-seal + HP |
| residual "glue" (executor + recv-loop + Request/Response + framing) | ~37 % | **no single hotspot** |
| `process_rx` (decrypt + dispatch) | ~15 % | per inbound datagram |
| `ship` (driver TX submit) | ~8 % | descriptor + doorbell |
| **crypto** (AEAD open+seal + HP) | **~8 %** | stitched AES-GCM — *negligible* |
| **QPACK** (decode + encode) | **~7 %** | *negligible* |
| stream lifecycle (reap + setup) | ~6 % | pooled, cheap |

So the 2× is **diffuse orchestration**, not crypto/QPACK/allocs. This was confirmed
by *refutation*, not just profiling — every CPU/packet lever was A/B'd and moved
throughput within noise:

- **Architecture isn't the limiter:** a throwaway fast-path answering /health inline
  (skipping recv-loop + QPACK + Request/Response + routing) cut ~20% server CPU/req
  → **0 throughput change**.
- **Packets/req (TX side) isn't the lever:** coalescing the standalone outbound ACK
  into the response (2.0 → 1.0 outbound pkts/req, confirmed by `pkts_ack_only`) was
  throughput-neutral at 100% CPU — the ACK is a cheap ~36 B seal.
- The cross-task hop, per-IP cap, reap-alloc, delayed-ACK, no-op-flush, and the
  `BTreeMap`→ring swap were all real work-cuts but throughput-neutral.

## The one real lever found — and why it isn't shipped

**RX-side** packet reduction is different from TX: an inbound packet runs the *whole*
RX pipeline (NIC-poll → listener/SlotTable demux → inbox → AEAD-open → range-ACK
processing), far heavier than a TX seal. Sending the QUIC **ACK-Frequency**
extension (`ACK_FREQUENCY`) to make the peer ACK less dropped server RX 1.5 → 1.05
pkts/req and lifted **/health par=256 ~247–254 K → ~284 K (+12–15 %, 3 runs)** — the
only lever to move throughput at saturation, corroborating the literature (userspace
ACK processing is QUIC's #1 receiver cost).

**But the aggressive static config 44×-collapsed multi-window uploads** (peer ACKing
every ~10 ms → SRTT inflation → pacing-rate collapse → flow-control credit
starvation; 64 KiB single-window uploads fine, 1 MiB broke). Aggressive ACK reduction
helps request/response but starves bulk-receive, and no static value wins both — the
safe form is *adaptive* (restore frequent ACKs when an inbound bulk stream is
detected), which is fragile to tune. **Reverted; the +12–15 % finding is banked here.**

## What was kept

All throughput-neutral on /health but legitimate efficiency / code-quality wins,
GCE-validated:

- **ACK-coalescing** (`APP_ACK_ELICIT_THRESHOLD = 8`): 1 packet per small response
  (like h1/h2), halving egress pps; RFC 9000 §13.2.1-compliant, upload-safe.
- **`SentPackets` ring** replacing the per-space `BTreeMap` of unacked packets:
  O(1) insert/remove, alloc-free, O(range) ACK removal (helps the bulk path).
- Diagnostic counters `pkts_ack_only` / `pkts_no_stream` (egress-composition obs)
  and the per-phase `*_cycles` brackets (permanent, <1% overhead).

## Practical takeaways

- **gve has no hardware UDP receive coalescing** (verified in upstream source:
  `gve_rx_complete_rsc` is `/* Only TCP */`; no `NETIF_F_GRO_HW`). The changelog's
  "HW GRO for DQO" is TCP-RSC + kernel *software* UDP-GRO, which a direct-descriptor
  unikernel can't consume. So no RX-GRO amortization is available on GCE.
- The h3 stack is near its floor for this workload. For a *realistic* deployment
  (many independent clients, not a few QUIC-saturating loadgens) the client-side half
  of the latency gap largely disappears, so production h3 sits closer to h1 than this
  micro-benchmark suggests.

---

## Investigation log (superseded hypotheses + dead ends, kept for the record)

The path to the answer, so the dead ends aren't re-walked:

1. **"Latency-bound, not CPU" (SUPERSEDED).** Measuring at par=64 (below h3's
   saturation knee) showed cores ~30% idle → looked latency/transport-bound. Wrong
   operating point: at par≥256 the cores are 100% CPU-bound. *That's why this doc's
   conclusion changed.*
2. **"Device pps wall" (REFUTED).** h1 and h3 both sat at ~840 K pps at par=64 — a
   coincidence; h1 connection-scaling reaches 1.06 M pps, so 840 K isn't a wall.
3. **"Packets/req drives the 2×" (REFUTED).** The arithmetic fit (1.75× pkts/req ×
   1.19× cpu/pkt ≈ 2.08), but cutting outbound packets 2.0→1.0 at 100% CPU bought ~0
   throughput. The packet count was a red herring; the per-request *processing* is the
   cost.
4. **Adaptive ACK-Frequency** — real +12–15% but upload-unsafe; deferred (above).
5. **Hardware UDP-GRO via a different NIC** — theoretically the right
   RX-amortization, but GCE offers only gVNIC and writing an Intel-VF/ConnectX driver
   dwarfs the ~0.5× remaining gap.

Two external reviews independently converged on the same conclusion: ~2× is the
practical floor; the remaining gap is the intrinsic tax of QUIC's authenticated
headers, AEAD state, and packet-number tracking vs TCP's sequence-number bump.
