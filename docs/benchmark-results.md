# Benchmark results: Waitless vs tokio-hyper

Waitless is a bare-metal Rust unikernel: no OS, no syscalls — the async
executor *is* the kernel, and it polls the NIC's queues directly. This page
measures what that architecture buys against **tokio-hyper**, the mainstream
production Rust async HTTP stack (tokio + hyper + rustls), on identical cloud
hardware.

It's the most apples-to-apples comparison we can make: same language, same
async model, same TLS library lineage — the *only* real difference is that one
runs on Linux and one runs on bare metal. (For the comparison against a raw
native-Linux baseline server, see the
[Performance section of the README](../README.md#performance); for how to run
benches, see [`benchmarking.md`](benchmarking.md).)

## TL;DR

On a 4-vCPU GCE `c3` VM with gVNIC, serving a byte-identical `/health`
response, each server measured **at its own CPU-bound ceiling**:

| Workload | Waitless | tokio-hyper | Speedup |
|---|--:|--:|:-:|
| HTTP/1.1 plain | **≈ 1,170,000 rps** \* | 398,000 rps | **≈ 2.9×** |
| HTTPS / TLS 1.3 | **729,000 rps** | 338,000 rps | **≈ 2.2×** |

\* lower bound — Waitless was still loadgen-limited even with two 8-vCPU load
generators; tokio-hyper saturated its 4 cores at 398 K.

Latency at moderate load (200 connections, neither server saturated), TLS 1.3:

| | p50 | p99 |
|---|--:|--:|
| **Waitless** | **270 µs** | **566 µs** |
| tokio-hyper | 587 µs | 1.09 ms |

Waitless serves ~2× lower latency *and*, at this load, sits at <50 % of its
ceiling while tokio-hyper is already at ~97 % of its.

## Why — the syscall tax

Profiled at saturation, **tokio-hyper spends ≈ 61 % of its CPU in the kernel**
(`vmstat` system time) and only ≈ 38 % in user code, at 99 % CPU utilization.
That kernel time *is* the POSIX boundary: `epoll`, `recv`/`send` syscalls, the
in-kernel TCP/IP stack, and the user↔kernel copy on every packet.

Waitless has no kernel to call. Its TCP, TLS 1.3, and HTTP/1.1 stacks live in
the same address space as the request handler, inside one cooperative async
executor that polls the gVNIC RX/TX queues directly — no syscall, no ring
transition, no context switch, no kernel-boundary copy on the request path.
Deleting that ≈ 61 % is most of what shows up as the 2–3× throughput gap.

Where Waitless's *own* per-request cycles go (4 vCPU, TLS, saturated, from the
`/obs` cycle counters — see [`observability.md`](observability.md)):

| Bucket | Share | What it is |
|---|--:|---|
| Transport (TCP RX + send + gVNIC driver) | ≈ 37 % | the bare-metal packet path |
| Async-runtime plumbing | ≈ 28 % | recv-chunk pump + task poll/dispatch |
| TLS 1.3 AES-GCM | ≈ 23 % | record encrypt + decrypt |
| HTTP/1.1 parse + response build | ≈ 12 % | |

Crypto being only ~23 % is why the TLS penalty is modest (729 K vs 1.17 M).
There is no syscall line in that table — that's the point.

## Scaling to 8 vCPU

The lead holds when both servers are doubled to 8 vCPU:

| Workload | Waitless | tokio-hyper | Speedup |
|---|--:|--:|:-:|
| HTTP/1.1 plain | ≈ 1,200,000 rps \* | ≈ 650,000 rps | ≈ 1.85× |
| HTTPS / TLS 1.3 | 991,000 rps | ≈ 490,000 rps † | ≈ 2.0× |

\* loadgen-capped lower bound (same ~1.2 M ceiling as 4 vCPU — two load
generators can't saturate Waitless's plain path).
† tokio-hyper at 8 vCPU was measured under two-loadgen contention and is likely
understated; treat as indicative.

## Setup & methodology

- **Hardware:** GCE `c3-highcpu-4` / `c3-highcpu-8`, gVNIC, `us-west1-c`, SPOT.
  Same VM shape for both servers in each comparison.
- **Servers:** Waitless (this repo, bare-metal unikernel image) vs
  `tokio-hyper` — a release build on Debian, tokio multi-threaded runtime (one
  worker thread per vCPU), rustls. Both serve the **byte-identical** `/health`
  JSON, verified for parity.
- **Load:** `wrk -t8 -c8000` (keep-alive) from one or two separate
  `c3-highcpu-8` GCE VMs over the VPC — no loopback shortcut for either server.
- **Server-bound, not loadgen-bound.** A single 8-vCPU `wrk` host tops out near
  ~800 K rps plain / ~580 K TLS, which is *below* what Waitless sustains — so a
  one-loadgen run measures the load generator, not Waitless. tokio-hyper
  saturates its cores well under that ceiling (CPU-bound at one loadgen);
  Waitless needs two. Each server is therefore reported at *its own*
  saturation. Waitless throughput is cross-checked against the server's own
  `/obs` `requests_parsed` counter (e.g. the 8 vCPU TLS run parsed 29.8 M
  requests in 30 s = ~990 K rps — a hard server-side count, not a wrk estimate).
- **Reproduce:** [`scripts/bench/twolg.sh <server-ip> <label> <proto>`](../scripts/bench/twolg.sh)
  drives both loadgens and sums throughput; per-request CPU via
  [`scripts/profile_obs.py`](../scripts/profile_obs.py) against two `/obs`
  snapshots.

## Caveats — read these

- **Small-response keep-alive `/health`.** This measures per-request
  *overhead*, the regime where the syscall tax dominates. Bulk transfer or
  compute-heavy handlers spend their time elsewhere and will narrow the gap.
- **Plain-HTTP Waitless figures are lower bounds** — we could not fully
  saturate Waitless's plain path within the GCE vCPU quota (two load
  generators). The TLS figures are clean server ceilings.
- **4-vCPU throughput is a 3-run median** and was stable to ±1 %. The 8-vCPU
  figures are single runs; the tokio-hyper 8-vCPU number is conservative
  (contention-suppressed).
- **SPOT, shared-tenant hardware.** Absolute numbers vary run-to-run; the
  *ratios* (measured back-to-back, same loadgens, same parity response, with
  tokio-hyper verified CPU-bound) are the robust result.
- **tokio-hyper is an idiomatic baseline**, not a hand-tuned record-chaser — a
  reasonable stand-in for "a competent Rust async server on Linux."
