# Benchmark results: Waitless vs tokio-hyper

Waitless is a bare-metal Rust unikernel: no OS, no syscalls — the async
executor *is* the kernel, and it polls the NIC's queues directly. This page
measures what that architecture buys against **tokio-hyper**, the mainstream
production Rust async HTTP stack (tokio + hyper + rustls), on identical cloud
hardware.

It's the most apples-to-apples comparison we can make: same language, same
async model, same TLS-library lineage — the *only* real difference is that one
runs on Linux and one runs on bare metal. (For the comparison against the same
app compiled to run on native Linux/POSIX, see the
[Performance section of the README](../README.md#performance); for how to run
benches, see [`benchmarking.md`](benchmarking.md).)

## TL;DR

Latest run (2026-06, **8-vCPU `c3-highcpu-8`** + gVNIC, both servers on matched
hardware, two `c3-highcpu-8` load generators, byte-identical `/health`,
measured back-to-back):

| Workload | **Waitless** | tokio-hyper | Ratio |
|---|--:|--:|:-:|
| HTTPS / TLS 1.3 req/s          | **1.13 M** | 0.59 M | **≈ 1.9×** |
| HTTPS p50 latency (same load)  | **283 µs** | 644 µs | **≈ 2.3× lower** |
| HTTP/1.1 plain req/s           | **0.86 M** | 0.63 M | **≈ 1.4×** |

The HTTPS throughput + latency are measured at a saturating-but-symmetric load
(~400 connections, both load generators balanced); the plain figure is under
high concurrency (16 K connections). The earlier **4-vCPU `c3`** run is
consistent after core scaling: HTTPS ≈ 610–730 K (Waitless) vs ≈ 338 K
(tokio-hyper), plain ≈ 1.0–1.2 M vs ≈ 398 K.

### HTTPS throughput vs concurrency (Waitless, 8-vCPU c3)

| Concurrent connections | ~400 | ~2,000 | ~8,000 | ~16,000 |
|---|--:|--:|--:|--:|
| HTTPS req/s | 1.13 M | 1.07 M | 0.83 M | 0.24 M |
| p50 latency | 283 µs | 1.7 ms | 1.2–4.9 ms | overload |

Waitless sustains >1 M req/s through ~2 K connections and ~830 K through ~8 K,
then **degrades past ~10 K simultaneous TLS connections** — at 16 K the run is
overload for both servers (asymmetric load-generator splits, multi-ms tails;
tokio-hyper's TLS holds ~0.49 M there while Waitless drops to ~0.24 M). That
high-TLS-connection-count ceiling is a known limit (per-connection handshake +
buffer memory pressure); see the roadmap's per-connection memory-arena work.
Plain HTTP and moderate-concurrency TLS are unaffected.

The ranges are **real run-to-run variance** (~15–20 %) from SPOT-instance
placement on shared hardware — see [Caveats](#caveats). Within a single session
the 3-run spread is ±1 %; *across* re-deploys the same image landed anywhere
from ~600 K to ~730 K TLS. The **ratio** (~2×) is the robust result, because
tokio-hyper is verified CPU-bound (below) and both were benched back-to-back on
the same load generators.

Latency at moderate load (200 connections, neither server saturated), TLS 1.3:

| | p50 | p99 |
|---|--:|--:|
| **Waitless** | **270 µs** | **566 µs** |
| tokio-hyper | 587 µs | 1.09 ms |

At this load tokio-hyper is already at ~97 % of its ceiling while Waitless is at
<50 % of its — so Waitless delivers ~2× lower latency *and* ~2× more headroom.

## Why — the syscall tax

Profiled at saturation, **tokio-hyper spends ≈ 61 % of its CPU in the kernel**
(`vmstat` system time) and only ≈ 38 % in user code, at 99 % CPU utilization.
That kernel time *is* the POSIX boundary: `epoll`, `recv`/`send` syscalls, the
in-kernel TCP/IP stack, and the user↔kernel copy on every packet.

Waitless has no kernel to call. Its TCP, TLS 1.3, and HTTP/1.1 stacks live in
the same address space as the request handler, inside one cooperative async
executor that polls the gVNIC RX/TX queues directly — no syscall, no ring
transition, no context switch, no kernel-boundary copy on the request path.
Deleting that ≈ 61 % is most of what shows up as the ~2× gap.

Where Waitless's *own* per-request cycles go (4 vCPU, TLS, saturated, from the
`/obs` cycle counters — see [`observability.md`](observability.md); roughly,
these also move with placement):

| Bucket | ~Share | What it is |
|---|--:|---|
| Transport (TCP RX + send + gVNIC driver) | ~37 % | the bare-metal packet path |
| Async-runtime plumbing | ~28 % | recv-chunk pump + task poll/dispatch |
| TLS 1.3 AES-GCM | ~23 % | record encrypt + decrypt |
| HTTP/1.1 parse + response build | ~12 % | |

No syscall line in that table — that's the point. (Crypto being only ~23 % is
why the TLS penalty is modest.)

## Scaling to 8 vCPU

The lead persists when both servers are doubled to 8 vCPU — Waitless TLS
~990 K rps vs tokio-hyper ~490–570 K, plain ~1.2 M (still loadgen-capped) vs
~650 K, i.e. **roughly 2× again**. These are single runs and subject to the
same placement variance, so treat them as indicative rather than precise.
Waitless's TLS path scaled ~1.35× from 4→8 vCPU (sub-linear — there is
multi-core contention to chase); the plain path is loadgen-capped at both
sizes.

## Setup & methodology

- **Hardware:** GCE `c3-highcpu-4` / `c3-highcpu-8`, gVNIC, `us-west1-c`, SPOT.
  Same VM shape for both servers in each comparison. (`c3-highcpu-4` is now the
  default deploy shape — `scripts/deploy-gcloud.sh` — since 4 vCPU already
  clears 1 M rps plain.)
- **Servers:** Waitless (this repo, bare-metal unikernel image) vs
  `tokio-hyper` — a release build on Debian, tokio multi-threaded runtime (one
  worker thread per vCPU), rustls. Both serve the **byte-identical** `/health`
  JSON, verified for parity.
- **Load:** `wrk -t8 -c8000` (keep-alive) from one or two separate
  `c3-highcpu-8` GCE VMs over the VPC — no loopback shortcut for either server.
- **Server-bound, not loadgen-bound.** A single 8-vCPU `wrk` host tops out near
  ~800 K rps plain / ~580 K TLS — *below* what Waitless sustains, so a
  one-loadgen run measures the load generator. (A flattering fact: a 4-vCPU
  Waitless out-serves what an 8-vCPU `wrk` client can generate.) tokio-hyper
  saturates its cores well under that ceiling — it's CPU-bound at one loadgen,
  so adding a second only adds contention; Waitless needs two. Each server is
  therefore reported at *its own* saturation, verified with `/obs` `idle≈0` and
  cross-checked against the server's own `requests_parsed` counter (a hard
  server-side count, not a wrk estimate).
- **Reproduce:** [`scripts/bench/twolg.sh <server-ip> <label> <proto>`](../scripts/bench/twolg.sh)
  drives both loadgens and sums throughput; per-request CPU via
  [`scripts/profile_obs.py`](../scripts/profile_obs.py) against two `/obs`
  snapshots.

## What the throughput gap is *not*

It is **not** primarily a clever waitless optimization. While chasing it we
removed a redundant per-request heap allocation in the TCP retransmit path
(2 → 1 allocs/req; ~40 % off the send-path cycles — commit `e284d00`). A
same-session A/B at saturation showed that change is a real *per-request*
saving but its *throughput* effect (~6 % of the cycle budget) is **smaller than
the ~15–20 % placement variance** — i.e. a legitimate micro-optimization, not
the reason Waitless wins. The win is the architecture (no syscalls), which is
why it's ~2× and not ~1.06×.

## Caveats — read these

- **Run-to-run variance is ~15–20 %** on SPOT shared-tenant hardware: the same
  image re-deployed landed at 729 K TLS one session and ~610 K the next. We
  report ranges and lean on the *ratio* (measured back-to-back, same loadgens,
  tokio-hyper verified CPU-bound) rather than any single absolute.
- **Small-response keep-alive `/health`** — this measures per-request
  *overhead*, the regime where the syscall tax dominates. Bulk transfer or
  compute-heavy handlers spend their time elsewhere and will narrow the gap.
- **Low-RTT LAN/datacenter path** — these runs are co-located VMs on one
  VPC (sub-millisecond RTT), where TCP congestion control barely engages
  and our no-syscall architecture wins ~2×. On a **high-RTT or lossy WAN
  path the comparison narrows or inverts**: tokio-hyper inherits the Linux
  kernel's mature CC and loss recovery (CUBIC/BBR, packet pacing,
  RACK-TLP, ABC), whereas our hand-rolled stack is RFC 5681 Reno with no
  pacing and RTO/3-dup-ACK recovery only. Those gaps — the cost side of
  the no-kernel architecture — are inventoried under *Performance parity
  with the Linux TCP stack* in
  [`tcp-backlog.md`](tcp-backlog.md). This page
  measures the regime where we win; it is not a WAN claim.
- **Plain-HTTP Waitless figures are lower bounds** — we could not fully saturate
  Waitless's plain path within the GCE vCPU quota (two load generators).
- **8-vCPU figures are single runs**; the tokio-hyper 8-vCPU number is
  additionally conservative (measured under two-loadgen contention).
- **tokio-hyper is an idiomatic baseline** (release, rustls, multi-thread
  runtime), not a hand-tuned record-chaser — a reasonable stand-in for "a
  competent Rust async server on Linux."


## Efficiency baselines (folded from the 2026-06 efficiency audit)

> `efficiency-audit.md` retired 2026-06-10; its full narrative (the
> 2026-05-28 static audit, the 2026-05-30 falsification pass, the
> 2026-06-09 re-measurement) is in git history. This section keeps the
> standing measured baselines + the do-not-redo findings. Dated numbers
> are snapshots — re-measure before trusting an absolute.

### Measurement traps (don't repeat them)

A multi-URL `curl -o /dev/null url url …` does **not** issue one request
per URL against this server, and the bench harness's `allocs/iter` is a
*net live-count* delta (allocs − frees ≈ 0 in steady state), not
cumulative — both produced bogus "0 allocs/req" readings. Count
client-verified keep-alive responses against the cumulative `/obs`
`heap_total_allocation_count`.

### Allocs/request (measured, client-verified; HVF/virtio)

| Path | allocs/req | What they are (code-traced) |
|---|---|---|
| h1-TLS `GET /health` | **1.00** | the rtx retain — `rtx_push`'s `into_owned()` of the sealed record, freed on ACK. (`RtxPayload::Inline` reached 0/req, measured throughput-neutral, deliberately reverted) |
| h1-TLS `/static-16k` | **2.02** | + 1 TSO-record retain |
| h1-TLS `/static-1m` | **81** | ≈ 1 retain per 16 KiB TSO record + record chunking |
| h2 `GET /health` | **1.25** | (`de60f15`) header_block pools through StreamOut retirement; Borrowed-IOBuf flush |
| h3 `GET /health` | **6.0** | (`68080c5`, was 8.4) stream-retx now `clone_shared` views; remaining: BTreeMap node churn + DATA-header IOBuf |

RX is structurally zero-copy / zero-alloc on all paths (chunk move →
in-place AEAD → in-place parse).

### Memory per connection (measured + compiler-exact decomposition)

- **Idle system heap**: 1.86 MB / 374 live allocations after boot (HVF,
  1 core). Dominant per-core statics: `TCP_HASH` 328 KB, accept rings
  66 KB; NIC queue DMA ~1.5–2.5 MiB/QP.
- **h1-TLS conn (deployed `https` facade)**: **≈ 67 KB idle established**
  / ≈ 84 KB after the first request (+16.4 KB lazy `record_scratch`).
  Decomposition: rx_ring 16.4 KB + `TlsConnImpl` 7.9 KB + serve-task
  future ~20.4 KB + ~22 KB unattributed (likely `rx_partial`
  materialized by a handshake-flight straddle). ⚠ `H2Conn` heap is
  h2-ALPN-only — attributing it to every TLS conn was a measured,
  corrected mistake.
- **h3/QUIC conn**: `Connection` 17,944 → **4,008 B** after the DirKeys
  boxing (`b513437`); the four per-conn Rcs co-allocate into one
  4,080-B `ConnArena` (`b055a26`, 4 → 1 allocs/conn).
- **TCP slot**: `TcpConnection` = 384 B; pool segment 24.6 KB / 64
  slots, lazy.
- **No unbounded growth paths**: every queue is capped (OOO 16 KB/conn,
  retx ≤ cwnd ≤ 2 MiB, CRYPTO reassembly 64 KB, h2 1 MiB recv / 256 KiB
  send per stream, QUIC 2 MiB/stream / 8 MiB/conn / 256 MiB global,
  conn inbox 256 datagrams, per-IP half-open 256, refuse-at-90%-heap).

### Single-loadgen workload snapshot (GCE 2026-06-09, c3-highcpu-4 DQO)

| Workload | 1c | 2c | 4c | Notes |
|---|---|---|---|---|
| `get_tcp` (plain /health) | 182.5K | 327.2K | 536.9K | |
| `get_tls` (TLS /health, 32c) | 114.9K | 207.1K | 357.1K | cy/B 9.8–10.0 |
| `get_h1` | 347.4K | 428.5K | 482.6K | 4c **client-bound** |
| `get_h2` | 324.3K | 419.1K | 482.0K | h1-parity; client-bound |
| `get_h3` | 185.5K | 237.6K | 301.9K | ≈ 0.63× h1 |
| `get_tcp_fresh` (conn/s) | 36.4K | 64.1K | 99.2K | |
| `get_tls_fresh` (full hs/s) | 3.8K | 5.2K | 6.2K | |
| `download_64k_tls` | 23.6K | 35.6K | 36.5K | **NIC-bound ≥2c** (2.3–2.4 GB/s) |
| `download_64k_quic` | 10.0K | 12.1K | 13.2K | 659–864 MB/s |
| `upload_32k_tls` | 41.3K | 52.8K | 54.2K | 1.4–1.8 GB/s RX |
| `get_tcp_single` (1-conn RTT) | p50 49 µs | 48 µs | 49 µs | |

The 4c h1/h2 numbers are a floor (single loadgen saturates first); the
two-loadgen saturated reference is the TL;DR table above.

### The falsified thesis (do-not-redo)

The audit's original "global heap lock = #1 lever" thesis was **measured
false**: a per-core magazine allocator made the hot allocs 99.95%
lock-free on the contended gve-8c path and bought **~0 throughput**
(576K OFF vs 570K ON; branch `perf/tls-beat-tokio` preserves it).
Under true saturation all 8 cores are 99.7–99.8% busy, perfectly
balanced — already shared-nothing. Saturated cycle split: NIC driver
~39%, async-dispatch ~22%, TLS ~17%, HTTP ~10%, tcp_send (incl. the
1 alloc) 6%. Alloc/copy micro-work targets <10% of cycles — efficiency
wins, not throughput levers.

### What's already optimal (do not re-touch)

RX zero-copy; the rtx_queue `VecDeque` migration (155→88 KB/conn); the
TCP hot/cold struct split was tried and **rejected** (3–19% worse);
accept + steady-state wakes are same-core; c3/gVNIC runs Tier 1
(per-core RX queues).

### Open efficiency levers (allocs/bytes, not throughput)

- **rx_ring 16 KB → tiered** (default 4–8 KB, grow lazily): −8–12
  KB/conn; `OOO_MAX_BYTES` is tied to it. Biggest always-present block.
- **`[Header;16]` 5.4 KB → 8 inline + overflow**: −3–4 KB/conn, also a
  per-stream cost in every spawned h2/h3 handler task.
- **Pool/shrink the TLS scratches** (`record_scratch`/`rx_partial`
  16 KB): held `&mut` across `.await` → needs a drop-returned guard.
- **Per-request shared `Counter`s → `PerCoreCounter`**; pad the gve
  per-QP counter array (false sharing at packet rate). Low risk.
- **ConnArena long arc**: typed arena regions for the dynamic conn
  state — architecture-audit #6.
