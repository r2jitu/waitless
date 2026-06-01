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

On a 4-vCPU GCE `c3` VM with gVNIC, serving a byte-identical `/health`
response, each server measured **at its own CPU-bound ceiling**:

| Workload | Waitless | tokio-hyper | Speedup |
|---|--:|--:|:-:|
| HTTP/1.1 plain | **≈ 1.0–1.2 M rps** \* | ≈ 398 K rps | **≈ 2.5–3×** |
| HTTPS / TLS 1.3 | **≈ 610–730 K rps** | ≈ 338 K rps | **≈ 1.8–2.2×** |

\* lower bound — Waitless's plain path was still loadgen-limited even with two
8-vCPU load generators; tokio-hyper saturated its 4 cores at ~398 K.

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
