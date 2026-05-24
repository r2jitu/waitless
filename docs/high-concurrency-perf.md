# High-Concurrency Performance

A working document for the "how do we serve 10K+ concurrent HTTP/TLS
conns competitively" investigation. Captures the measurements and
fixes from the `bench/pareto-rig` work and ranks the remaining gaps
we believe matter most for the next round.

## Goal

Best-in-class concurrent HTTP/TLS throughput on the bare-metal
unikernel — competitive with mature Linux stacks (nginx,
tokio-hyper) at the same conn counts on the same hardware, with
graceful degradation past saturation.

## How to bench

Three iteration envs, ranked by speed and faithfulness to the
production datapath:

1. **`scripts/local-iterate.sh`** — HVF on Apple Silicon. ~30 s
   cycle, no GCE round-trip. Covers async runtime + TCP + HTTP +
   TLS hot paths. Can't reproduce gVNIC-specific behavior (HVF
   uses a userspace TCP proxy, not virtio).
2. **`scripts/kvm-iterate.sh`** — QEMU/KVM on the GCE `kvm-vm`
   loadgen box. ~45 s cycle. Real Linux host TCP stack, real
   virtio-net + vhost-net multi-queue. **Not** gVNIC, and the
   measurements pick up nested-virt + shared-host-CPU artifacts
   (see "Asymmetric core load" below).
3. **`scripts/c3-bench-once.sh`** — Deploy waitless to a real
   `c3-highcpu-8` GCE instance, drive wrk from `kvm-vm` over the
   VPC. Production-shape datapath (gVNIC, Andromeda). ~5 min for
   the first run (image build + upload); subsequent calls are
   single-curl. Mirrors the `/obs` delta block that the other two
   scripts print, so output is comparable across envs.

`scripts/peer-linux/pareto-bench.sh` exists for full
multi-peer / multi-conn sweeps emitting JSONL the
`chart-pareto.py` script consumes; the three single-shot
iteration scripts above are what we use during code-change
debugging.

## Measurements (May 2026)

### Headline /health-TLS sweep — 8 s per cell

| conns | rps c3+gVNIC (8c) | rps kvm-iterate (4c) | p99 c3 | p99 kvm |
|-------|-------------------|-----------------------|--------|---------|
| 3 K   | 285 K             | 308 K                 | 217 ms | 180 ms  |
| 6 K   | 226 K             | 223 K                 | 664 ms | 461 ms  |
| 10 K  | 170 K             | 146 K                 | 1.55 s | 1.33 s  |
| 14 K  | **128 K**         | collapse (~200 rps)   | 2.07 s | —       |
| 18 K  | collapse          | —                     | —      | —       |
| 28 K  | collapse          | —                     | —      | —       |

Read as: **kvm-iterate cliffs hard at 14 K**, while **c3+gVNIC
degrades gracefully to 14 K and only collapses at 18 K**. The
kvm-iterate collapse is a stricter cliff because the 4 cores
share a busy host; the 8 c3 cores spread the saturation more
evenly.

### Per-core breakdown at 10 K conns

**c3+gVNIC (8 cores):**

```
c0: loops=6.13M poll=147K rt=141K idle=0.8% rt/loop=0.0231
c1: loops=6.08M poll=146K rt=140K idle=0.6% rt/loop=0.0230
c2: loops=6.20M poll=148K rt=141K idle=0.6% rt/loop=0.0228
c3: loops=6.01M poll=146K rt=140K idle=0.7% rt/loop=0.0233
c4: loops=6.20M poll=149K rt=143K idle=0.6% rt/loop=0.0230
c5: loops=6.29M poll=142K rt=136K idle=0.9% rt/loop=0.0217
c6: loops=6.17M poll=147K rt=141K idle=0.7% rt/loop=0.0228
c7: loops=6.31M poll=152K rt=145K idle=0.5% rt/loop=0.0230
```

All 8 cores within 5% of each other on every metric. Idle uniformly
0.5–0.9%. `tasks_polled_per_worker` balanced within 1% (one of the
key counters we added). **No core asymmetry.**

**kvm-iterate (4 cores):**

```
c0: loops=1.19M  rt=4.7K  idle= 0.6% rt/loop=0.0040
c1: loops=1.40M  rt=5.5K  idle= 0.6% rt/loop=0.0039
c2: loops=1.42M  rt=5.3K  idle=21.2% rt/loop=0.0037
c3: loops=1.47M  rt=7.2K  idle=13.2% rt/loop=0.0049
```

c0/c1 pinned at 0.5 % idle while c2/c3 sit at 13–21 % idle —
the asymmetry that drove most of our investigation. **It does
not reproduce on c3**, so this is a kvm-vm host-side artifact
(KVM vCPU placement on a shared c3 host, vhost-net IRQ steering,
or similar). Not a guest-fixable bottleneck.

### Per-request CPU budget

| env       | busy cycles/run | requests/run | cycles/request |
|-----------|----------------|--------------|----------------|
| c3+gVNIC  | ~153 B         | ~1.4 M       | **~109 K**     |
| kvm-vm    | ~76 B          | ~1.2 M       | **~64 K**      |

Real c3 actually spends **70 % more cycles per request** than
the nested-KVM path. Likely candidates: gVNIC's DMA-completion
ring processing, deeper interrupt path, less aggressive
batching. Most of the per-request cost is runtime / NIC / stack
overhead — the handler itself for a `/health` JSON response is
likely under 10 K cycles.

### Asymmetric core load on kvm-vm — root cause

`tasks_polled_per_worker` is **balanced** across kvm-vm's 4 cores
(310–316 K polls, within 1 %). The asymmetry is purely in
**cycles per poll** — ~60 K on c0/c1 vs ~48–54 K on c2/c3,
about 20 % more. Same task volume, same NIC frame distribution
(rx_max_min_ratio_x100 = 102 ≈ 1.02×). Confirmed on c3 that this
disappears entirely. The kvm-vm asymmetry was a measurement
hazard, not a real bug.

## Fixes shipped (commits on `bench/pareto-rig`)

| # | Commit                                                  | What                                                     | Measured impact                                                                  |
|---|---------------------------------------------------------|----------------------------------------------------------|----------------------------------------------------------------------------------|
| 1 | `boot/x86_64: fix PVH info-pointer register (ESI → EBX)`| Boot stub read PVH start-info from wrong register        | Heap `123 MB → 1019 MB` at `-m 1024`; unblocked >2K conns on kvm-iterate         |
| 2 | `mmu: runtime device-MMIO mapping on x86_64`            | `kernel_bare::mmu` extended to walk active PML4          | Lets `-m 4096` run; virtio-net's 64-bit BAR at 56 TiB now mappable on demand     |
| 3 | `net/tcp: scale per-core 4-tuple hash 256 → 32K`        | Hash overflow killed RX hot path at >256 conns/core      | At 10K conns: rps `86K → 162K` (+89 %)                                            |
| 4 | `net/tcp: fix hash bucket selector + cliff instrumentation` | `>> (64 - 8)` hardcoded; only 256 starting buckets   | Avg probe depth `920 → 1.13` (∆ 800×)                                            |
| 5 | `net/tcp: per-(core,port) accept ring`                  | O(pool_size) scan per accept → O(1) ring pop             | Avg accept iters `1257 → 47` (26×)                                                |
| 6 | `net/tcp: O(1) listener + stale-twin lookup`            | O(pool_size) scan per SYN → O(1) port-map + hash         | Avg SYN-scan iters `1285 → 0` (fallback unused)                                  |
| 7 | `net/tcp: intrusive armed-timer list`                   | Tick walked full pool every ~7 ms → walks armed list     | Tick iters `2358 → 406` (6×); `has_armed_timers` O(N) → O(1)                     |
| — | `runtime/executor: per-worker tasks_polled diagnostic`  | Counter array to detect task work skew                   | Confirmed kvm-vm asymmetry is **not** task distribution                          |

**Aggregate on kvm-iterate, 10 K conns /health-TLS:**

- rps `86 K → 146 K` (+70 %)
- p99 `1.56 s → 1.33 s`
- All four O(pool_size) scans eliminated → cliff is now pure CPU
  saturation, not data-structure waste

## Prioritized gaps

The data-structure scans are fixed. Remaining ceiling is cycles
per poll and graceful degradation past CPU saturation. In rough
order of impact-per-effort, ranked by what we'd ship next.

### P0 — Ship next

1. **Load shedding** _(small, ~50 LOC)_
   - Drop SYNs when `live_conns_per_core > threshold` (suggest
     ~2000 from current data). Stops the collapse past CPU
     saturation; converts the 14K→18K cliff into a 14K plateau
     with refused conns. Bench impact: stable `~128 K` rps under
     overload instead of collapse to ~0. Production impact:
     bounded p99 during traffic spikes.

2. **RX coalescing (GRO equivalent)** _(medium, ~200 LOC)_
   - `init_pci_modern` currently masks off `VIRTIO_NET_F_GUEST_TSO4`
     and friends (see `VIRTIO_NET_RX_OFFLOAD_MASK`) — the comment
     notes our RX path only handles single-descriptor ≤MTU frames.
     Enabling these lets the host coalesce N segments into one
     super-frame, cutting per-packet stack overhead 5–10× on the
     RX hot path. Single biggest expected lift for `cycles/request`.

3. **Run Linux peer baseline (nginx + tokio-hyper)** _(operational,
   not code)_
   - Same c3 hardware, same conn sweep, same /health-TLS profile.
     Until we have this we don't know if 170 K rps is competitive
     or 2× behind. Required to size the rest of the roadmap honestly.
     Bench infra already deployed (`scripts/peer-linux/*`), just
     needs an hour of running. **Do this first.**

### P1 — Per-poll cycle reduction

4. **`TcpConnection` hot/cold split** _(medium)_
   - Struct is ~200 B → 3+ cache lines per slot. Every per-conn
     access (`tcp_receive`, `poll_slot`, tick walk) touches all
     of them. Split into a 64 B hot half (state, ports, seq nums,
     deadlines, wakers) and a pointer to a cold half (rings,
     IOBufs, RTT history). Cuts cache-line touches per poll by ~3×.

5. **Prefetch slot at `poll_slot` entry** _(tiny)_
   - One `_mm_prefetch` on the slot before the future runs hides
     L2→L1 latency on the slot's hot half. Free hint. ~5–10 %
     when cache-bound.

6. **AES-GCM TLS cipher** _(medium)_
   - We negotiate only `TLS_CHACHA20_POLY1305_SHA256` (~20 cy/B
     measured). AES-GCM-128 with AESNI is 1–3 cy/B — ~10× faster
     bulk encrypt. Bigger payoff on `/static-*` than `/health`;
     /health gets ~10 % rps lift since TLS is only ~10 % of the
     poll budget there.

### P2 — Bigger architectural wins

7. **Softirq-style inline handler path** _(large)_
   - Trivial handlers (`/health`, `/static-*` with `&'static [u8]`
     bodies, no async work) could run **inline in `tcp_receive`**
     when a request completes — no task wakeup, no scheduler
     round-trip, no waker creation. Sidesteps the async-runtime
     tax for known-cheap endpoints. Expected 2–3× on /health-TLS
     specifically. Large change; sacrifices uniformity.

8. **Concrete handler type (drop `Box<dyn Future>`)** _(medium-large)_
   - Per-conn handler tasks all share one concrete future type for
     a given app. Storing them as `Box<dyn Future>` forces vtable
     dispatch on every poll. A `spawn_typed<F>` path with the
     concrete `F` lets LLVM inline the entire HTTP loop. ~5–10 %.

9. **SYN cookies** _(medium)_
   - Defer slot allocation until the 3-way ACK arrives — currently
     we allocate ~16 KB on every SYN (the rx_ring on first send).
     Encode all needed state in the SYN-ACK sequence number.
     Hardens against SYN floods; modest steady-state win.

### P3 — Foundational

10. **Per-CPU slab allocator** _(large)_
    - Single `Spinlock<Talc>` heap shared across cores. The slot
      pool's preserve-across-reuse covers steady-state, but
      first-time rx_ring/rtx_buf allocation during warmup still
      hits the lock. Per-CPU caches eliminate the contention.

11. **Adaptive concurrency (Netflix RED-style)** _(medium)_
    - Replace P0's fixed-threshold shedding with an EWMA on p99
      latency — when p99 climbs past target, throttle accept
      rate. Tracks the actual saturation point as workloads
      change (vs hardcoded conns/core).

12. **eBPF/XDP-style early filter** _(large, possibly unfeasible)_
    - DDoS / bad-source-IP drop at the NIC RX boundary, before
      the TCP stack runs. Requires a programmable filter point we
      don't have today. Defer until we have a real abuse story.

## Instrumentation kept in `/obs`

Surface that survived from the cliff investigation — cheap
(batched bumps), useful as ongoing health metrics + regression
guards. All in the TCP `/obs` block unless noted.

| Counter                                    | Healthy range                                  | What it tells us                                              |
|--------------------------------------------|------------------------------------------------|---------------------------------------------------------------|
| `accept_calls`, `accept_iterations`        | iters/call ≤ 5                                 | Accept ring fast-path hit rate                                |
| `linear_find_calls`, `linear_find_iterations` | calls ≈ 0                                   | TCP hash overflow fallback — should never fire under load    |
| `hash_find_probes`                          | probes/call ≤ 2                               | 4-tuple lookup probe depth (open-addressed)                  |
| `tick_calls`, `tick_iterations`, `tick_armed_seen` | iters/call ≈ 10 % of live conns/core   | Per-tick armed-list walk; iters == armed_seen always now     |
| `syn_scan_calls`, `syn_scan_iterations`     | calls ≈ 0                                     | SYN-handler pool-scan fallback — fires only when listener_map full |
| `tasks_polled_per_worker` (runtime block)   | balanced across active workers                 | Per-core task work distribution                              |

**Use:**

- `iterations / calls` is the average scan depth — should be O(1)-ish on healthy paths.
- A non-zero `linear_find_calls` means the TCP hash overflowed — bump `TCP_HASH_SIZE`.
- Asymmetric `tasks_polled_per_worker` means work isn't distributed evenly across cores.
- `tick_iterations / tick_calls` rising past ~50 % of pool means most conns have armed timers (high retx, abusive client, etc.).
