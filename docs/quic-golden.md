# QUIC golden-path revamp — zero-copy, GSO/GRO, crypto

Goal: make QUIC/HTTP3 a throughput-competitive golden path alongside TCP/TLS/HTTP1.1,
across gve-DQO (c3), gve-GQI (n2), virtio-net (kvm-qemu + HVF), without regressing
TCP/TLS, unifying the TX-offload machinery for maintainability.

## Baseline (branch `quic-golden` @ `8db3efe`, heap QUIC — the #55 fix)

### c3-highcpu-4, gve DQO, single quinn loadgen on kvm-vm
| workload | QUIC h3 | TCP/TLS (wrk) |
|---|---|---|
| /health par=1 | 11,190 rps | — |
| /health par=4 | 42,822 rps | — |
| /health par=32 | 169,705 rps | — |
| /health par=128 | 175,144 rps (ceiling) | — |
| /health -c4000 | — | **570,890 rps** |
| /static-64k par=1 | 244 rps (~125 Mbps/conn) | — |
| /static-256k par=1 | 61 rps (~125 Mbps/conn) | — |
| /static-1m par=1 | 15.2 rps (~122 Mbps/conn) | — |
| /static-1m -c64 | — | **2,282 rps / 2.23 GB/s** |

Profile (/obs delta over the bulk sweep): `datagrams_sent ≈ aead_seal_packets`
(1 seal + 1 descriptor per packet, **no batching**); avg sealed packet **1067 B**
(vs ~16 KB TLS record → ~15× more AEAD ops/byte).

**Diagnosis:**
- **Bulk** QUIC is flat ~125 Mbps/conn = the low-RTT 100 Mbps pacing cap (#50 band-aid),
  not the true ceiling. GSO (one descriptor for N packets) + lifting the cap = the bulk win.
- **Small-resp** QUIC tops out ~175K (par≥32) = per-packet crypto (AEAD+HP) + async/framing
  overhead. GSO does not help single-packet responses; crypto batching + async flattening do.

### n2 (gve GQI) baseline
- /health par=1: ~10,200 rps (per-packet path).

## Findings

### HW UDP-GSO: unsupported on GQI, SUPPORTED on DQO (corrected — see "GSO/GRO" below)
> CORRECTION: this de-risk tested GQI and the conclusion was wrongly generalized
> to all of gve. Per Google's gve CHANGELOG, UDP-GSO is a DQO feature; it works
> on c3/DQO (validated). The GQI result below stands (GQI genuinely can't).

Enabled the fully-implemented GQI UDP-GSO path and ran h3 bulk: **completed=0**;
client tcpdump showed **only small control packets (45/87 B), zero ~1171 B
segmented data** — the device silently drops the UDP-segmentation descriptor
(matches the code note: upstream Linux gve doesn't advertise
`NETIF_F_GSO_UDP_L4`). `/health` per-packet was unaffected (10.2K rps). So the
GSO TX encoder is correct but **gve cannot hardware-segment UDP** → `udp_gso`
stays off on gve. (Encoder retained for any USO-capable NIC, e.g. modern
virtio — to be tested on kvm-qemu.)

Consequence: the bulk win on gve cannot come from descriptor batching. The
baseline bulk (125 Mbps) was the **100 Mbps low-RTT pacing cap**, far below
both line rate and the per-packet CPU ceiling — so the lever is raising the
cap and letting cwnd + ring back-pressure bound the burst. QUIC bulk on gve
will still be per-packet-CPU-bound (no TSO equivalent), so it improves but
won't match TCP's TSO line rate; honest target = the per-packet CPU ceiling.

## After — bulk via raised pacing cap (cap=4 Gbps, burst=16; GSO off on gve)

### c3/DQO (headline)
| workload | before | after |
|---|---|---|
| h3 /static-1m p1 | 122 Mbps | **1.26 Gbps (10.3×)** |
| h3 /static-1m p4 | — | 2.92 Gbps (agg) |
| h3 /static-1m p16 | — | 3.66 Gbps (agg) |
| h3 /health p1 | 11,190 | 11,150 (neutral) |
| TCP /health c4000 | 570,890 | **572,927 (no regress)** |
| TCP /static-1m c64 | 2.23 GB/s | **2.39 GB/s (no regress)** |

loss ~0.13% (recovered, +2 PTO, 0 failed).

### n2/GQI
| workload | before | after |
|---|---|---|
| h3 /static-64k p1 | ~125 Mbps | 755 Mbps |
| h3 /static-256k p1 | ~125 Mbps | 880 Mbps |
| h3 /static-1m p1 | ~125 Mbps | **1.19 Gbps (9.5×)** |
| h3 /static-1m p16 | — | 4.3 Gbps (agg) |
| h3 /health p1 | ~10,200 | 9,500 (neutral) |

loss ~0.004%, 0 failed.

Single-conn plateaus ~1.2 Gbps = the per-packet CPU ceiling (no TSO equivalent
for QUIC on gve). TCP/TLS golden path unchanged on both formats.

### kvm-qemu (virtio-net + vhost-net, real KVM)
| workload | after |
|---|---|
| h3 /static-1m p1 | **1.02 Gbps (8×)** |
| h3 /static-1m p4 | 2.35 Gbps (agg) |
| h3 /health p1 | 8,543 |
| TCP /static-64k c1000 | 2.24 GB/s |

loss ~0% recovered, 0 failed. virtio-net does not negotiate USO (word-1
feature) so GSO is unavailable here too → same pacing path; bulk win applies.

### HVF (Apple Silicon, virtio-net userspace proxy)
Functional (proxy-bound, not a throughput env per doctrine): boots; TCP/TLS
/health 77K; **h3 /health 200 (54 B) + /static-64k 200 (full 65536, multi-packet,
no wedge)**. QUIC works with the change; arm64 build verified.

## Full before→after matrix (h3 /static-1m single-conn bulk)
| env | NIC | before | after | TCP/TLS no-regress |
|---|---|---|---|---|
| c3 | gve DQO | 122 Mbps | **1.26 Gbps (10.3×)** | /health 570→573K, bulk 2.23→2.39 GB/s |
| n2 | gve GQI | 125 Mbps | **1.19 Gbps (9.5×)** | (QUIC-layer change; TCP path untouched) |
| kvm | virtio-net | ~125 Mbps¹ | **1.02 Gbps (8×)** | TCP 2.24 GB/s static-64k |
| HVF | virtio (proxy) | — | h3 functional ✓ | TLS 77K |

¹ kvm baseline = same 100 Mbps low-RTT cap (env-agnostic QUIC-layer limiter).
Single-conn plateaus ~1–1.3 Gbps = the per-packet CPU ceiling on every NIC.

## GSO / GRO — DQO supports both; GQI/virtio/HVF do not (CORRECTED)
Per Google's gve CHANGELOG (v1.4.10): "Enable support for UDP GSO when using
DQO format" + "Optimize and enable HW GRO for DQO" — **UDP segmentation/
coalescing is DQO-only**. (An earlier de-risk here tested GQI, which genuinely
doesn't support it, and wrongly generalized to all of gve — corrected.)
- **TX GSO on DQO (c3): WORKS, enabled.** The DQO device segments the UDP
  super-buffer host-side (it picks UDP from the IP proto byte, so the TSO
  descriptor path applies verbatim). GCE-validated: tcpdump shows the device
  emitting 1122 B segmented packets (33,992 of them) + the client HW-GRO'ing
  them back into ~18 KB jumbos; 0 failed. Single-conn /static-1m unchanged
  (1.25 Gbps — the per-conn ceiling is per-packet crypto/encode, which GSO
  doesn't touch); aggregate +6–11% from freed descriptor/doorbell CPU (partly
  spot noise). It's the right architecture + frees CPU under load.
- **GQI (n2): not supported** (de-risked: h3 bulk completed=0, zero segmented
  data) → per-datagram path. virtio: no USO negotiated → per-datagram. HVF:
  proxy → per-datagram. `udp_gso_enabled()` is per-format (DQO-only).
- **RX GRO:** DQO supports HW UDP RX coalescing (the kvm-vm client demonstrated
  it — received 18 KB coalesced UDP). Our DQO RX already enables RSC (T4,
  +14-19% TCP upload). Extending/verifying it for QUIC UDP uploads is a
  characterized follow-up (downloads — the headline — don't exercise server RX
  beyond ACKs).

→ Optimal path: DQO uses HW UDP-GSO + the raised pacing cap; GQI/virtio/HVF use
per-datagram + the pacing cap. Single-conn bulk is crypto-bound (~1.2 Gbps) on
all, so GSO's win is aggregate/CPU, not single-conn.

## Completion
- **Optimal path validated in all four scenarios** (c3/DQO, n2/GQI, kvm/virtio,
  HVF) — bulk ~8–10× via the pacing cap; HVF functional.
- **TCP/TLS golden not regressed** (c3 /health 570→540–573K = within the ~15-20%
  spot variance, code path untouched; bulk 2.23→2.39 GB/s; kvm 2.24 GB/s).
- **Logic unified:** `write_udp_tx_headers` shared by the per-datagram and GSO
  send paths; pacing/segment-size consts centralized in `conn/tx.rs`.

## Upload / echo direction (server RX) — the reassembly cliff

The download work above never exercised server RX beyond ACKs. Adding
the `h3-upload` (RX-isolated) and `h3-echo` (bidirectional) loadgen
workloads surfaced a hard upload cliff on GCE: uploads ≤ 64 KiB ran at
line rate, but ≥ 256 KiB collapsed to ~0.2 req/s — one body, then the
connection idle-timed-out.

**Root cause (NOT flow control, despite the 256 KiB coincidence):** the
per-stream out-of-order reassembly buffer was capped at a fixed 16 KiB
(`gap_budget`). On GCE's burst-reorder path a large upload puts >16 KiB
of bytes out of order at once; frames past the cap were silently
dropped — but `conn::rx` had already processed those packets and ACK'd
them, so quinn never retransmitted the gap. The recv handler then spun
on `conn.recv` forever (`/obs handler_stuck`) until the 30 s idle timer
killed the conn. 64 KiB stayed under the cap, masking the bug as a size
cliff that *looked* like the old 256 KiB window.

**Fix** (2 commits):
1. Bound out-of-order reassembly by the receive flow-control window
   (`recv_max`, already enforced in `conn::rx` before ingest) instead
   of the fixed 16 KiB — the peer can't send past the window it was
   granted, so the gap buffer is naturally bounded. Drop `gap_budget`.
2. Raise the initial recv window 256 KiB/1 MiB → 2 MiB/8 MiB (so a
   typical upload fits without a mid-body MAX_STREAM_DATA round-trip) +
   flush replenished credit right after the handler consumes, so an
   upload past one window can't deadlock waiting to piggyback credit on
   an inbound packet a blocked peer won't send.

### c3/DQO upload + echo (before → after)
| workload | before (p1) | after p1 | after p4 |
|---|---|---|---|
| h3 upload /discard 64 KiB | 1,770 rps (~0.93 Gb/s) | 1,770 | 4,766 |
| h3 upload /discard 256 KiB | **0.2 rps (handler_stuck)** | **518 (~1.06 Gb/s)** | **1,329 (~2.79 Gb/s)** |
| h3 upload /discard 1 MiB | (stuck) | **136 (~1.14 Gb/s)** | **338 (~2.83 Gb/s)** |
| h3 echo /echo 64 KiB | (stuck >64 K) | 977 (~0.51 Gb/s RX+TX) | 2,589 |
| h3 echo /echo 256 KiB | (stuck) | 256 (~0.54 Gb/s) | 800 |
| h3 echo /echo 1 MiB | (stuck) | 73 (~0.61 Gb/s) | 180 |

All `failed=0`; `/obs` delta over a 1 MiB×p4 upload: `handler_stuck +0`,
`other_wire +0` (no FC drops). TCP/TLS h1 /health unchanged at
**435,293 rps** (the change is confined to the QUIC RX reassembly path).

A regression test (`recv_out_of_order_past_16k_then_fills`) covers the
>16 KiB out-of-order fold-in.

### n2/GQI upload — env-agnostic confirmation
The fix is in `proto/quic`, so it holds identically on the other gve
format (redeployed n2-highcpu-8, GQI): 256 KiB upload 494 rps p1
(~1.03 Gb/s) / 1,627 p4; 1 MiB 131 p1 / 378 p4; echo 256 KiB 252 p1,
1 MiB 69 p1; all `failed=0`. Cliff gone on both gve formats.

### HW UDP-RX-GRO: not available on gve, and wouldn't help — VERIFIED
Checked against the **official Google gve driver source**
(`GoogleCloudPlatform/compute-virtual-ethernet-linux`), not just our
header:
- `gve_adminq_create_rx_queue` has exactly one coalescing field —
  `enable_rsc` (offset 50). No UDP-GRO / UDP-coalesce / GSO field
  exists. Our `init.rs` is byte-exact and complete.
- `gve_rx_compl_desc_dqo` carries only `rsc` (1 bit) + `rsc_seg_len`
  ("Segment length for **RSC** packets") — RSC is TCP segment
  coalescing (LRO). There is **no UDP coalescing metadata**; upstream
  relies on the kernel's *software* GRO for UDP, not a device offload.
- Measured on c3/DQO with RSC enabled: **packets/datagram = 1.000** —
  the device delivers UDP 1:1, exactly as the descriptor predicts.

And it couldn't move the needle even if it existed. Upload-RX CPU
profile (c3/DQO, 1 MiB×p4, `/obs` cycle counters): **94.9% of busy
cycles is per-packet QUIC work** (`runtime_cycles`: AEAD-open + frame
parse + ACK), only **5.1% is NIC/classify/inbox** — the per-datagram
portion any GRO scheme could touch. A 1 MiB×p4 upload runs **1.28 M
AEAD-opens for 1.78 GB** (~1390 B/pkt); coalescing datagrams can't
reduce the per-packet AEAD count. This is the exact mirror of the
TX-GSO finding (no single-conn win; QUIC crypto is per-packet). So the
RX path is left as-is: already zero-copy (items A–L), TCP-RSC-enabled,
and now reassembly-correct + AEAD-open-bound at ~1 Gb/s/conn.

## G4 — narrowing the h3 gap: response coalescing + stitched AEAD (DONE, branch `quic-crypto-batch`)

G4 turned out to have TWO distinct levers — one for small responses, one for
bulk:

**(1) Small responses — packet coalescing (not crypto).** The keyed ciphers
are already cached per-`DirKeys`, so the cost wasn't key setup; it was
**packets per request**. Profiling h3 /health (c3/DQO, c64):

| proto | /health rps (c64) | vs h1 |
|---|---|---|
| h1.1 | ~419 K | 1.00× |
| h2 | ~387 K | 0.92× |
| h3 (before) | ~174 K | 0.41× |
| **h3 (after G4)** | **~223 K** | **0.53×** |

`/obs` showed a buffered h3 response cost **5.0 sealed packets + 5.0 flushes +
5.0 datagrams per request** (vs ~1 TLS record for h1/h2) — because
`write_response` emitted HEADERS, DATA, and FIN as three separate
flush-and-drain calls, and the encoder popped only one stream chunk per
packet. Fix (2 commits): a non-flushing `QuicConn::queue_iobuf` so the
response queues HEADERS+DATA+FIN before a single `close_stream` flush, plus
draining multiple queued chunks per stream into each packet. Result: the
response coalesces to **one packet**, per-request packets/seals/flushes
**5.0 → 2.5**, h3 /health **+28%** (174 K → 223 K). The `res.write` streaming
path keeps per-write flush for backpressure.

**(2) Bulk — stitched AES-GCM (crypto WAS a real lever after all).** QUIC's
packet AEAD used RustCrypto `aes_gcm::Aes128Gcm` (non-stitched: separate
AES-CTR then GHASH — measurably slower, RustCrypto/AEADs#243), while TLS
already used the in-tree `waitless_aes_gcm::Aes128GcmFast` (8-block batched,
*stitched* CTR+GHASH, AES-NI 8-way + Gueron-2010 deferred reduction). So h3
paid a QUIC-only crypto tax on every byte. Pointing `DirKeys` at the same
stitched crate TLS uses:

| h3 bulk | coalescing-only | + stitched GCM |
|---|---|---|
| /static-64k c1 | 1,449 (0.76 Gb/s) | **2,519 (1.32 Gb/s, +74%)** |
| /static-64k c64 | 7,664 | **11,789 (+54%)** |
| 1 MiB upload p1 / p4 | 722 / 998 | **1,382 / 2,902 (~+90% / +190%)** |

Small /health stays ~223 K (crypto isn't the bottleneck at ~80 B); TCP/TLS
unchanged (already on the fast crate); real quinn client interops (the
stitched output is NIST-KAT- + cross-checked against RustCrypto).

**Residual / next levers.** The remaining h3<h1 gap is per-packet overhead
(QUIC seals/HP per packet where TCP+TLS amortizes over larger records) plus
the ~2 inbound-ACK packets/req. Lever (a) — **fold the ACK into the response
packet** — was implemented (commit `d7a8dcc`, "delayed/piggybacked 1-RTT ACK
+ multi-range ACK frames") and **settles the packet-count question**: a
delayed ACK (RFC 9000 §13.2.1; piggyback, with a >=2-packet + 25 ms
`max_ack_delay` safety net) plus proper multi-range ACK encoding (§19.3 — so
deferral doesn't under-acknowledge an upload) cut h3 /health outbound
**packets/req 2.5 -> 2.0** (hard `/obs` counter). But throughput moved only
**223K -> 231K rps — within the GCE spot noise floor**, i.e. throughput-neutral,
and 1 MiB echo uploads stayed `failed=0` with no retransmit storm. **So
packets/req is NOT the h3 /health throughput bottleneck** — 20% fewer packets
bought ~0% throughput. The residual h3<h2 gap (231K vs 387K) is therefore
diffuse QUIC transport cost (per-packet AEAD+HP, the UDP datagram path, QUIC
FC accounting), not a single fixable lever — matching the analogous "diffuse,
below the noise floor" findings for the TLS and h1-vs-h2 gaps. The delayed/
range ACK is kept for correctness (proper §19.3 ranges) + the real 20%
packet/CPU reduction, not as a throughput win. Remaining lever: (b)
**VAES/AVX-512** AES-GCM (4 AES blocks/instruction on ZMM, up to ~3.8× over
AES-NI — Intel ISA-L, Go #42726) for bulk; blocked on enabling AVX-512 XSAVE
state in the kernel boot path (`limine_entry.rs` XCR0 mask) — a larger effort,
and bulk is already egress-bandwidth-capped so the ROI is unclear.

## h3 /health bottleneck — profiled to root cause (branch `quic-h3-health-profile`)

Added per-phase cycle brackets to the QUIC hot path (`process_rx_cycles`,
`flush_tx_cycles`; commit `02daacb`) and decomposed h3 /health on c3/DQO via
`/obs` deltas + a 2-loadgen rig (kvm-vm + waitless-peer-nginx):

- **Server-bound at ~230K rps, NOT loadgen-bound.** A single 8-core loadgen
  saturates at ~235K generating QUIC (92% busy) — so the naive "h3 224K vs h1
  419K" looked like a loadgen artifact. But **two loadgens sum to the SAME
  ~236K** (128 conns) and 256 conns also ~230K: adding client capacity doesn't
  raise it ⇒ the server is the bottleneck.
- **Latency-bound (Little's Law), not CPU-bound.** At the cap all 4 cores are
  balanced at **~74% busy with ~26% idle that won't fill**, and throughput is
  flat from 128→256 conns while P99 grows 486µs→1515µs. QUIC is per-core
  shared-nothing (per-worker `SlotTable`+inboxes, no global lock — endpoint.rs),
  so this is per-connection *service latency* capping each closed-loop conn's
  request rate, not a lock or aggregate CPU.
- **Per-request CPU split (cyc, % of busy): NIC 12% / quic process_rx 13% /
  quic flush_tx 27% / h3+executor+stream+ship residual 48%.** Crypto is minor;
  the cost is per-request *orchestration*, dominated by the cross-task hops
  (conn task → per-stream h3 handler task → conn task) on the critical path.

**Fix landed on the branch (commit `dcf2cbd`): skip the no-op flush.** Since
the delayed ACK holds the request's ACK to piggyback the response, the
post-`process_datagram` flush usually emits nothing yet still heap-allocated a
~1500 B datagram + ran the full encode scan. Added an established-steady-state
fast path (`has_one_rtt_to_send`, the exact complement of
`encode_one_rtt_packet`'s 8 emission branches; gated on Established + both
lower spaces discarded) that returns before the buffer acquire. Result
(c3/DQO): **flush_tx 12.9K → 7.8K cyc/req (−40%)**, flush_tx share 27%→25%;
h3 1 MiB upload `failed=0` (predicate correct, no stall); h1 unaffected.
Throughput flat within spot noise — expected, since the cap is latency, not
CPU. The fix is a real per-request CPU/density win, not a /health throughput
lever.

**Per-IP connection cap — fixed for NAT / max-concurrency (commit `5137066`),
but NOT the throughput limiter.** The per-source-IP slot cap (was 64/worker)
charged *all* connections, so a single public IP — every client behind a NAT /
CGNAT / VPN egress shares one — was capped at ~64/worker × cores live conns,
rejecting real users while the table sat empty. Fixed by scoping the cap to
*unvalidated (half-open)* conns only: once a conn completes QUIC address
validation (`path_validated`), `SlotTable::mark_validated` drops it from the
per-IP count, so validated conns are bounded only by the global per-worker
budget (raised 1024→8192, grow-on-demand). Half-open per-IP cap 64→256.
**GCE-validated: correct (h3 upload + handshakes `failed=0`), but it did NOT
raise the /health ceiling** — with one IP's conns admitted past the old cap,
2-loadgen 256-conn = 231K / 512-conn = 210K, server busy *falling* 74%→71%→68%
as conns rise (more parked time, not more work). Confirms the cap wasn't the
bottleneck; the latency bound is. Kept as a real NAT-robustness / max-
concurrency-design fix, not a throughput lever.

**Inline-dispatch lever — investigated and FALSIFIED by latency decomposition.**
The hypothesis was that the conn_task→handler cross-task hop added ~100 µs to
each request (the h3-vs-h1 P50 delta of ~125 µs). The server's own
`request_latency_us` histogram (listener-recv → response encoded+shipped, the
full server-side path *including* the hop) settles it: **P50 64 µs / mean
120 µs**, of which **`inbox_wait_us` is P50 32 µs / mean 52 µs** (datagram
queued behind other work — load-dependent, not a fixed hop). So the entire
server contribution is ~64 µs and the conn_task→handler hop is only ~10–15 µs
of it; the ~280 µs the client sees is dominated by network RTT + the heavier
QUIC client (the loadgen saturates generating QUIC at ~235 K — it, plus path
RTT, sets the observed latency, not a server stall). Reading the code also
corrected the model: h3 requests are *already* dispatched inline within
`handle_conn` (task #30's per-request spawn was reverted — the conn's
`progress` `AsyncEvent` is single-waiter), and the handler ships its own
response (`drain_outbound`), so there is no spawn-per-request and no
wait-for-conn_task-to-ship hop to remove. Inline-merging the generic async
handler into the conn task would shave ~10–15 µs (<5 %, below the ±15 % spot
floor) while fighting the deliberate wire/handler isolation (a slow handler
must not stall wire service) and the single-waiter event — a bad trade. Not
pursued. **Net: the h3 /health server path is already near its floor (~64 µs
RX→TX); the residual gap to h1 is the QUIC client cost + per-packet transport,
not a fixable server-side hop.**

## Characterized future work (profile-justified, not core to this goal)
- Remaining small-resp h3 gap: PROVEN (commits `d7a8dcc` packets/req delta +
  `dcf2cbd`/`02daacb` cycle profile) to be **latency-bound per-request
  orchestration** (cross-task hops), not packet count or crypto. Packet/CPU
  micro-opts are density wins, throughput-neutral within noise. The throughput
  lever is the inline-dispatch critical-path change above. This per-packet cost
  is also the ceiling that caps single-conn bulk at ~1.2 Gbps.
- **Server-RX HW UDP-GRO on DQO**: investigated + ruled out (see
  "HW UDP-RX-GRO" above) — no gve knob exists (RSC is TCP-only, verified
  against the upstream driver) and the per-datagram NIC portion it could
  touch is only ~5% of upload CPU. Not pursued.
