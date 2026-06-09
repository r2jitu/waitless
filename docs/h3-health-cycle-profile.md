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

## ROOT CAUSE of the h1/h2-vs-h3 gap: per-request latency, not CPU

> ⚠️ **SUPERSEDED — read "CORRECTED ROOT CAUSE" below.** This section's
> "latency-bound, not CPU" conclusion was an artifact of measuring at par=64
> (below h3's saturation knee). At the true ceiling (par≥256) both protocols
> are 100% CPU-bound; h3 costs ~2× the CPU/req. Kept for the investigation
> record, not as the answer.

Two more experiments closed it out:

- **Client scaling (loadgen-limited?):** scaled the client 8→16→20 cores (1→3
  c3/n2 loadgen VMs). h3 /health plateaued at ~245-250 K with server busy
  *pinned* at ~76-79% at every level (512 conns made it worse). **Not
  loadgen-limited; not CPU-saturated.**
- **Hop elimination (the cross-task hop?):** a throwaway that drives the h3
  handler future *inline* in the conn task (no spawn, no `progress`-event wake
  — `tasks_polled` confirmed the hop was gone). GCE: **236.6 K vs 233 K
  baseline — unchanged.** So the conn_task↔handler hop is **not** it either.

The decider was measuring **server busy% for both protocols at par=64**:

| | rps | server busy | implied latency (conns/rps) |
|---|---|---|---|
| **h1** | 420,917 | **66.0%** | ~152 µs |
| **h3** | 235,713 | **69.2%** | ~271 µs |

**Neither protocol is CPU-bound — both sit at ~66-69% busy.** So /health is
**latency-bound** (closed-loop: throughput = concurrency ÷ per-request-latency),
and **h3's per-request latency (~271 µs) is ~1.8× h1's (~152 µs) — exactly the
throughput ratio.** That is the root cause: the gap is **latency, not
throughput/CPU capacity.** Every CPU lever (micro-opts, fast-path pipeline
removal, hop elimination, more loadgens) failed because the cores are already
~30% idle waiting on the closed-loop round trip — there is no CPU to reclaim.

h3's extra ~120 µs of latency splits roughly in half:
- **Server-side (~50 µs):** the QUIC RX→TX path is ~64 µs (`request_latency_us`
  P50) vs h1's small inline cost — QUIC per-packet decrypt/HP/ACK/flow-control
  + the **listener→conn-task inbox demux** (`inbox_wait` ~32 µs), where h1's
  `serve_conn` reads its TCP stream directly in one task.
- **Client/transport-side (~70 µs):** the QUIC *client* (loadgen) is heavier
  per request than a TCP client, and the UDP datagram path differs.

So even a perfect (0 µs) server would only close ~half the gap (→ ~290 K); the
rest is the QUIC client + transport, which the server cannot fix. The h3 stack
is near its floor for this closed-loop, single-small-response benchmark; the
gap to h1/h2 is intrinsic to QUIC's per-request latency, not a server defect.

## CORRECTED ROOT CAUSE: at saturation h3 is CPU-bound at ~2× the CPU/req of h1

The "latency-bound, near its floor, no server-side lever" conclusion above was
an **artifact of measuring at par=64 — below h3's saturation knee.** "Why can't
concurrency offset the latency?" forced the real answer, measured this time at
saturating concurrency (par=256, c3-highcpu-4/gve, single loadgen, windowed
`/obs` deltas). Three facts settle it.

**1. Concurrency *does* offset latency — until the cores saturate, then it
can't.** h1 scales 419 K (par64) → 529 K (par256) then plateaus; h3 scales
238 K → ~247 K and plateaus by ~par128. The plateau is where cores hit 100 %.

**2. At the plateau BOTH protocols peg all 4 cores at 100 % — on real work,
not empty-poll spin.** This is the key correction. Per-core `core_busy_cycles`
windowed delta = 100 % for both at par=256. The empty-poll trap is ruled out by
`core_loops`/`core_poll_work`:

| par=256 | rps | device pps | pkts/req | busy | cyc/loop | work-loops | CPU/req |
|---|---|---|---|---|---|---|---|
| **h1** | ~520 K | 1.03 M | 2.00 | 100 % | 2,293 | 5 % | **~7.7 µs** |
| **h3** | ~247 K | 866 K | 3.50 | 100 % | **238,510** | 46 % | **~16.2 µs** |

An empty poll is a few hundred cycles (h1's 2.3 K average, dominated by 95 %
empty laps, proves it). h3's loops are **238 K cycles each** — ~5 requests of
genuine work per loop. So h3's 100 % is real per-request work. CPU/req =
`4 cores × 2.699e9 cyc/s ÷ rps`: h1 ≈ 20.7 K cyc (7.7 µs), h3 ≈ 43.9 K cyc
(16.2 µs). **Ratio 2.12 = exactly the throughput ratio (520 ÷ 247 = 2.11).**

**3. It is NOT a device packet-rate wall.** The earlier "both at ~840 K pps"
(par=64) was a coincidence: h1 connection-scaling drives device pps to
**1.06 M** (par256) — well past 840 K — before h1 itself plateaus. The device
does ≥1.06 M pps; h3's ~866 K-pps ceiling is its *own* CPU limit, not the NIC's.

**So the root cause is: each h3 request costs ~2× the server CPU of an h1
request, so the CPU-bound throughput ceiling is ~2× lower.** The remaining
question — and the part this section originally got wrong — is *what* that 2×
CPU/req is spent on.

### The packets/req hypothesis — and why it's WRONG (measured)

The tempting decomposition was **(a) 1.75× more packets/req** (h3 3.5 vs h1
2.0) × **(b) ~1.19× CPU/packet** (QUIC per-packet AEAD/HP/framing) = 2.08 ≈ the
2.1×. The arithmetic fits, so I tested the (a) half directly. h3's +1.0
outbound packet/req is **not** the response (~250 B fits one packet) and **not**
MAX_STREAMS (deferring that changed nothing); instrumenting with `pkts_ack_only`
/ `pkts_no_stream` showed it is a **standalone pure ACK** (1.0/req): the
conn-task's RX flush hits the "≥2 ack-eliciting" rule (`app_ack_due`)
microseconds *before* the separate handler task produces the response, so the
ACK can't piggyback.

Raising the ACK threshold (`APP_ACK_ELICIT_THRESHOLD` 2 → 8) makes the imminent
response win the race and carry the ACK: **outbound packets dropped 2.0 → 1.0/req,
pure-ACK 1.0 → 0.0** (hard `/obs` counters), uploads stayed correct (failed=0,
no stall). **But throughput at par=256 was flat: 247 K → 254 K (within the
±15 % spot noise), still 100 % CPU.** Halving the outbound packets at 100 % CPU
bought ~0 throughput — because the standalone ACK is a *cheap* ~36 B packet, so
its seal/ship is a tiny slice of per-request CPU.

**Conclusion: packets/req is NOT what makes h3 cost 2× the CPU.** The packet-
count decomposition was a coincidental fit. The real 2× is the **diffuse
per-request QUIC + h3 *processing*** — per-packet AEAD-open on the request and
AEAD-seal on the response, QPACK decode/encode, the async conn-task↔handler
orchestration, and H3 framing — none of which the packet count touches. This is
the same "no single hotspot, diffuse orchestration" the cycle decomposition
found earlier (§ Per-request decomposition), now confirmed at *saturation* with
the packet-count red herring ruled out.

So the par=64 "throughput-neutral to every lever" result was NOT just a
wrong-operating-point artifact: even at saturation, cutting per-request packets
is throughput-neutral. **There is no cheap server-side throughput lever for h3
/health — the ~2× CPU/req gap is intrinsic to QUIC+HTTP/3's per-request work.**
Moving it needs a structural reduction in per-request processing (e.g. fewer
AEAD passes, lighter framing), not packet-count or ACK-timing tweaks.

### What was kept

The ACK-coalescing (`APP_ACK_ELICIT_THRESHOLD` = 8) is kept as an **efficiency**
improvement, not a throughput one: it halves h3 small-response egress packets
(1 packet/response, like h1/h2), is RFC 9000 §13.2.1-compliant (the "every 2"
is a SHOULD; `max_ack_delay` still bounds it), reduces NIC egress pps and the
standalone-ACK amplification under real multi-client load, and is upload-safe
(1 MiB / 8 MiB h3 uploads complete failed=0, `handler_stuck`/`idle_timeouts`/
loss all 0). The `pkts_ack_only` / `pkts_no_stream` counters are kept as
permanent obs. The MAX_STREAMS-deferral experiment was reverted (ineffective).

### RX-side ACK reduction IS a real lever — but it's TX vs RX, not packets-in-general

The "no packet-count lever" conclusion above is for the **TX** direction. The
**RX** direction is different. Prototyped the QUIC ACK-Frequency extension
(`draft-ietf-quic-ack-frequency`): the server sends an `ACK_FREQUENCY` frame
asking the peer (quinn — it advertises `min_ack_delay`) to ACK far less often,
cutting the ~0.5 standalone client-ACK datagrams/req. Result: **server RX dropped
1.50 → 1.05 packets/req and /health par=256 rose ~247–254 K → ~284 K (+12–15 %,
3 consistent runs)** — the FIRST lever in this whole investigation to move
throughput at saturation. Why RX ≠ TX: a TX ACK is a cheap ~36 B *seal*, but an
inbound ACK runs the **entire RX pipeline** — NIC poll, listener→conn `SlotTable`
demux + inbox hop, AEAD-open, frame parse, and **range-ACK processing**
(`BTreeMap<pn,SentPacket>` lookup/prune + RTT/cc update). Cutting inbound packets
removes all of that; cutting an outbound ACK removes only a seal.

**But the aggressive static config broke bulk uploads** (1 MiB: ~1952 → ~60
completed, failed=0/no-loss — complete-but-44×-slow; 64 KiB fine). A peer ACKing
only every ~10 ms gates the multi-window upload's pacing/credit loop (suspected
SRTT inflation → `pacing_rate` collapse → credit starvation; couldn't confirm —
`/obs` has no per-conn RTT). Aggressive ACK reduction helps request/response but
starves bulk-receive, and no single static value wins both. The safe form is
*adaptive* (send aggressive ACK_FREQUENCY at handshake, then a corrective one
restoring frequent ACKs when a large inbound stream is detected) — real but
fragile to tune. **Reverted** the ACK_FREQUENCY commit; the +12–15 % finding is
banked here. (An external review independently rated ACK-Frequency low-ROI for a
single small request/response — it under-weighted that quinn does send a
standalone ACK/2-responses here, but it's right that the win is workload-specific
and not worth the upload fragility.)
