# Unikernel Next-Gen Roadmap

A cutting-edge, lean unikernel: modern protocols only (QUIC/HTTP3, IPv6),
cooperative multi-core, zero legacy overhead. Each feature is compile-time
optional via Bazel deps — you pick exactly what you need.

## Design Principles

- **Modern over legacy**: QUIC over TCP, IPv6 over IPv4, NDP over ARP
- **Deps as feature selection**: app declares what it needs via Bazel deps — unused protocols never compile
- **No preemption, no locks**: cooperative scheduling, lock-free data structures only
- **Lean by default**: start from zero, add only what's needed

---

## Architecture: Deps-as-Features

No `--cfg` flags or feature matrices. Each protocol is a separate Bazel
`rust_library` target. The app's `deps` list determines what gets compiled.
Transitive deps pull in exactly what's needed; `--gc-sections` strips the rest.

```
//net:ethernet     <- always (virtio-net frames)
//net:arp          <- ipv4 needs this
//net:ipv4         <- tcp, udp-over-ipv4
//net:ipv6         <- quic, udp-over-ipv6
//net:ndp          <- ipv6 needs this (replaces ARP)
//net:tcp          <- uni:http needs this
//net:udp          <- quic needs this
//net:quic         <- uni:http3 needs this (+ tls)
//uni:http         <- HTTP/1.1 server (deps: tcp)
//uni:http3        <- HTTP/3 server (deps: quic)
//kernel:smp       <- multi-core support (optional)
```

Example apps:
```python
# Modern: HTTP/3 + QUIC + IPv6 (no TCP, no ARP, no IPv4)
rust_library(name = "app", deps = ["//uni:http3"])

# Legacy: HTTP/1.1 + TCP + IPv4
rust_library(name = "app", deps = ["//uni:http"])

# Both: serve HTTP/1.1 and HTTP/3 side by side
rust_library(name = "app", deps = ["//uni:http", "//uni:http3"])
```

---

## Phase 1: Infrastructure

### 1a. Restructure net/ into per-protocol targets

Split the monolithic `//net` crate. Extract shared types first, break
circular dependencies, then new protocols get their own targets.

- [x] Break circular dependency: ethernet.rs no longer dispatches to arp/ipv4
- [x] `//net:types` — standalone crate (MacAddr, Ipv4Addr, byte order, checksums)
- [x] `//net:net` depends on `//net:types` via extern crate
- [ ] `//net:ethernet` (ethernet.rs — deps: types)
- [ ] `//net:arp` (arp.rs — deps: types, ethernet)
- [ ] `//net:ipv4` (ipv4.rs — deps: types, ethernet, arp)
- [ ] `//net:tcp` (tcp.rs — deps: types, ipv4)
- [ ] `//net:dhcp` (dhcp.rs — deps: types, ipv4, ethernet)
- [ ] `//net` umbrella alias for the full legacy stack

**Tests:**
- [x] Unit: byte order roundtrips, address types, RFC 1071 checksums (8 tests)
- [x] Integration: existing HTTP smoke tests pass on x86_64 + aarch64
- [ ] Unit: ethernet frame parse/build
- [ ] Unit: ARP request/reply encode/decode
- [ ] Unit: TCP segment parse
- [ ] Unit: DHCP option parsing

**Try it:**
```bash
bazel test //net:types_test         # 8 unit tests (host-native)
bazel test //apps/webserver:test    # regression check (QEMU)
```

### 1b. Add crate_universe for crates.io dependencies

Required for pulling in crypto (`ring`), QUIC (`quiche`/`quinn`), etc.

- [x] Add `crate_universe` to MODULE.bazel (annotation-based, no Cargo.toml)
- [x] Verified bitflags resolves and compiles for x86_64-unknown-none
- [ ] Fix aarch64-unknown-none platform gap in rules_rust (not in triple_mappings.bzl)
- [ ] Use a crates.io dep in the unikernel and boot it

**Known issue:** `aarch64-unknown-none` is not in rules_rust 0.56.0's
platform registry. Crate_universe marks crates as incompatible for that
target. Needs fix before Phase 3 (QUIC/TLS deps on aarch64).

**Try it:**
```bash
bazel build --config=x86_64-qemu @crates//:bitflags   # resolves + compiles
```

---

## Phase 2: Multi-Core Event-Driven OS

This is essentially an OS-level async runtime — like tokio, but we ARE
the kernel. No syscalls, no epoll indirection, no context switches.

Every core is a worker. No dedicated cores, no preemption, no scheduler.
Same event loop: poll -> process -> steal -> sleep.

### Platform compatibility matrix

| Feature | QEMU x86_64 | QEMU aarch64 (TCG) | VZ.framework |
|---------|-------------|---------------------|--------------|
| SMP | Yes (`-smp N`) | Yes (`-smp N`) | Yes (`cpuCount`) |
| Multi-queue | Yes (`mq=on,queues=N`) | Yes (same) | No (single queue) |
| MSI-X | Yes (APIC routing) | Partial (no ITS, use GICv2M) | No (INTx only) |
| RSS | Yes (in-QEMU or eBPF) | Yes (same) | No (needs multi-queue) |
| Per-core timers | Yes (APIC timer) | Yes (CNTV_EL0) | Yes (CNTV_EL0, quirky) |
| IPI | Yes (APIC ICR) | Yes (GIC SGI) | Yes (GIC SGI) |
| Per-core IRQ routing | Yes (MSI-X -> LAPIC) | Partial (MSI->SPI->IROUTER) | No (all to one core) |

**Key finding: VZ lacks multi-queue + MSI-X.** The per-core queue pair
model only works on QEMU. VZ needs software distribution (Tier 2).

### Two-tier IO strategy

**Tier 1 — Hardware distribution (QEMU with multi-queue + MSI-X):**
Each core owns a VirtIO queue pair. RSS distributes packets by flow
hash. MSI-X routes interrupts to the owning core. No software routing.
Zero contention, zero software overhead.

**Tier 2 — Software distribution (VZ, or any single-queue platform):**
Core 0 owns the single RX/TX VirtIO queue pair. On VZ, INTx always
routes to core 0, so it is always the core that wakes on RX interrupts.

**RX distribution**: core 0 drains the entire RX queue in one batch,
classifies packets by flow hash, and enqueues them to target cores'
work queues. One IPI per core that received packets (not per packet)
amortizes the IPI cost.

```rust
// Tier 2: batched single-queue RX distribution (runs on core 0)
fn poll_single_rx_queue() {
    let mut wakeup = [false; MAX_CORES];
    // Drain entire RX queue in one batch — classify and enqueue ALL packets
    while let Some(pkt) = rx_queue.poll() {
        let flow = hash(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port);
        let target_core = flow % num_cores;
        // Enqueue to target core's inbox (SPSC: core 0 writes, target reads).
        // Don't process inline — keep poll fast so all packets get distributed.
        cores[target_core].inbox.push(Task::Packet(pkt));
        wakeup[target_core] = true;
    }
    // One IPI per remote core that has new work (not per packet)
    for core in 1..num_cores {  // skip self (core 0)
        if wakeup[core] && cores[core].sleeping {
            send_ipi(core);
        }
    }
}
```

**TX path**: the single VirtIO TX ring is NOT thread-safe. Each core
has a per-core TX staging buffer (regular memory, no contention).
Core 0 drains all per-core TX staging buffers into the VirtIO TX ring
during its poll phase. Other cores write to their staging buffer and
set a flag; core 0 flushes on next poll. No locks needed.

```rust
// Per-core TX staging (any core writes to its own, core 0 flushes all)
fn tx_send(pkt: &[u8]) {
    my_core.tx_staging.push(pkt);  // lock-free, only this core writes
    TX_PENDING.store(true, Relaxed);
}

// Core 0 flushes during poll
fn flush_all_tx_staging() {
    if !TX_PENDING.swap(false, Relaxed) { return; }
    for core in 0..num_cores {
        while let Some(pkt) = cores[core].tx_staging.pop() {
            virtio_tx_queue.submit(pkt);
        }
    }
    virtio_tx_queue.notify();
}
```

**Tier 2 throughput ceiling**: core 0 handles all RX distribution and
TX flushing. Under extreme packet rates, core 0 becomes the bottleneck.
This is inherent to single-queue hardware — no software design can
avoid it. Tier 2 is for VZ (dev/test). Production targets Tier 1.

**Detection at boot**: check if `VIRTIO_NET_F_MQ` is offered. If yes ->
Tier 1 (per-core queues). If no -> Tier 2 (software distribution).
Same event loop code, different poll implementation.

### Architecture: per-core event loop (batched tasks between polls)

```rust
const TASK_BATCH: usize = 32;  // max tasks between polls

// Every core runs this — identical loop
loop {
    // 1. Poll IO sources (non-blocking, tier-aware)
    match tier {
        Tier1 => {
            poll_virtio_net_rx(&my_rx_queue);  // each core polls own queue
            // TX: each core owns its own VirtIO TX queue, send directly
        }
        Tier2 if my_core == 0 => {
            poll_single_rx_queue();   // core 0: drain + distribute to all cores
            flush_all_tx_staging();   // core 0: drain per-core TX staging -> VirtIO TX
        }
        Tier2 => {}  // non-core-0: no VirtIO queue to poll; work arrives via IPI
    }
    // Drain cross-core inbox into local pinned queue (Tier 2: packets from core 0)
    while let Some(task) = my_inbox.pop() {
        my_pinned_queue.push(task);
    }
    poll_virtio_blk(&my_blk_queue);     // storage completions (future)
    poll_timers(&my_timer_wheel);       // drain pending_timers MPSC, fire expired

    // 2. Process pinned tasks first (connection-bound, latency-sensitive)
    //    Then stealable tasks. Batch up to TASK_BATCH before re-polling.
    for _ in 0..TASK_BATCH {
        if let Some(task) = my_pinned_queue.pop() {
            task.run();
        } else if let Some(task) = my_stealable_deque.pop() {
            task.run();
        } else {
            break;
        }
    }

    // 3. If both queues empty, try to steal (stealable deques only)
    if my_pinned_queue.is_empty() && my_stealable_deque.is_empty() {
        if let Some(task) = steal_stealable_from_busiest() {
            task.run();
            continue;  // back to poll after stolen work
        }
        // 4. Nothing to do — sleep until interrupt
        wfi();  // wake on virtio IRQ, IPI, or timer
    }
}
```

**Tier-aware polling**: in Tier 1, each core polls its own VirtIO queue.
In Tier 2, only core 0 touches VirtIO — other cores receive work via
their pinned queues (populated by core 0's distribution) and wake via IPI.

**Two-queue processing**: pinned tasks first (connection work is
latency-sensitive), then stealable tasks. Batch up to 32 between polls —
amortizes poll cost under load, exits early when idle.

### Interrupt handling — just a wakeup, never real work

Interrupts follow the NAPI / "interrupt coalescing" pattern:

```rust
// The ENTIRE interrupt handler — nothing more
fn irq_handler() {
    // Mark this core as "has pending work" (single atomic store)
    PENDING.store(true, Relaxed);
    // Return immediately — WFI will wake, event loop will poll
}
```

The handler NEVER touches packets, connection state, or queues.
It's a wakeup signal, ~3 instructions. All real work happens in the
cooperative event loop's poll phase. Benefits:
- No locks or allocation in interrupt context
- No reentrancy concerns (handler is trivial)
- Batching: one interrupt can wake a core that then drains multiple
  packets in a single poll pass (interrupt coalescing for free)

Idle -> wake flow:
```
Core sleeping (WFI/HLT) — zero CPU usage
  | VirtIO RX interrupt fires (MSI-X routes to this core)
IRQ handler: set PENDING=true, return
  | Core wakes from WFI
Event loop resumes: poll() drains all available packets
  | Queue empty + no tasks + nothing to steal
Back to WFI — zero CPU until next interrupt
```

Cores NEVER spin. When there's no work, they sleep (WFI on ARM,
HLT on x86). Wake cost is one interrupt latency (~microseconds).

### Per-core state + work queue

```rust
struct PerCore {
    inbox: SpscRing,             // Tier 2: core 0 pushes packets here; this core drains
    pinned_queue: SpscRing,      // connection-bound tasks, only this core reads/writes
    stealable_deque: ChaseLevDeque,  // pure-compute tasks, thieves steal from here
    timer_wheel: TimerWheel,     // only this core polls; fires enqueue tasks locally
    pending_timers: MpscQueue,   // any core can push timers; this core drains into wheel
    tx_staging: SpscRing,        // this core's outbound TX packets (Tier 2)
    connections: ConnPool,       // connections owned by this core
    listener: ListenerState,     // per-core accept state for incoming connections
}
```

**Three queues per core** — each with strict ownership rules:

- **`inbox`** (SPSC ring): Tier 2 cross-core delivery. Core 0 is the
  only writer (RX distribution). Owning core is the only reader. Drained
  into `pinned_queue` at start of each poll cycle. Unused in Tier 1.
- **`pinned_queue`** (SPSC ring): only the owning core pushes and pops.
  No atomics, no stealing. Connection-bound tasks go here.
- **`stealable_deque`** (Chase-Lev): owner pushes/pops one end (LIFO,
  cache-friendly), thieves steal from the other end (FIFO, single CAS).
  Pure-compute tasks go here. Thieves only see this deque.

A Chase-Lev deque can't selectively skip tasks — a steal CAS gets
whatever's at the bottom. Separate queues ensure thieves never touch
pinned tasks and cross-core delivery never corrupts local state.

Owner processes: drain inbox -> pinned tasks -> stealable tasks.
Thieves only touch the stealable deque.

### Task classification: pinned vs stealable

Not all tasks can be stolen. Tasks that touch connection state must run
on the owning core. Tasks that are pure compute can run anywhere.

- **Pinned tasks**: access connection buffers, TCP state, timers.
  Examples: parse HTTP request, advance TCP state machine, write response
  to connection's TX buffer. Must run on the owning core — NOT stealable.
- **Stealable tasks**: pure computation, no connection state access.
  Examples: TLS encrypt/decrypt, QUIC packet encryption, gzip compression,
  template rendering. Can safely run on any core.

```rust
enum Task {
    Pinned(PinnedTask),     // only owning core can run
    Stealable(StealTask),   // any core can run
}
```

Thieves only steal `Stealable` tasks from other cores' deques. `Pinned`
tasks are invisible to thieves. For a simple HTTP server, most tasks are
pinned (responses are cheap). Work stealing becomes valuable for
CPU-heavy operations: TLS/QUIC crypto, compression, complex rendering.

### Connection pinning

- **Connections pinned to cores** via RSS hash(src_ip, dst_ip, src_port,
  dst_port). All packets for a connection arrive on the same core's queue.
  Connection state (buffers, timers) stays local — no migration needed.
- **Per-core listeners**: `server.run(port)` replicates listener state on
  all cores. When a SYN arrives on core N (via RSS hash), core N creates
  the connection locally. No shared listening socket. Same pattern as
  Linux `SO_REUSEPORT` — each core accepts independently.

### Timers and cross-core timer creation

- **Timers are per-core**: each connection's timers live on the owning
  core's timer wheel. They fire locally and enqueue tasks locally.
- **Cross-core timer creation**: a stolen task running on core B may need
  to arm a timer for a connection owned by core A. It pushes the timer
  to core A's `pending_timers` MPSC queue (lock-free, any core can push).
  Core A drains `pending_timers` into its timer wheel during `poll_timers()`.
  No IPI needed — the timer will fire on core A's next poll cycle.

```rust
fn poll_timers(&mut self) {
    // 1. Drain remotely-submitted timers into my wheel
    while let Some(timer) = self.pending_timers.pop() {
        self.timer_wheel.insert(timer);
    }
    // 2. Fire expired timers — connection-bound, so pinned queue
    while let Some(task) = self.timer_wheel.poll() {
        self.pinned_queue.push(task);
    }
}
```

### Work stealing

- **Work stealing steals stealable tasks only**: an idle core peeks at
  other cores' deques via atomic tail-steal (single CAS). It runs the
  stolen task to completion, then returns to its own work. Connection
  state doesn't move — the task is pure compute.
- **IPI**: wake a sleeping core when stealing finds work.

### Why imbalance self-corrects (no migration needed)

- RSS distributes NEW connections across cores by port hash — natural spread
- Closed connections free up the core they were pinned to
- HTTP request tasks are short-lived (microseconds) — queues drain fast
- Work stealing handles transient bursts (hot connection on one core)
- **Persistent imbalance** would require one connection dominating traffic
  AND generating CPU-heavy tasks. Unlikely for a webserver. Escape hatch:
  reprogram RSS indirection table (future optimization, not day-1).

### Synchronization points (minimal but real)

**No synchronization needed:**
- Connection state: lives on ONE core (pinned by RSS hash), no sharing
- VirtIO queues: per-core in Tier 1, core-0-owned in Tier 2
- Timer wheels: per-core, only owning core reads
- Routing table: write-once at boot, read-only after

**Minimal synchronization required:**
- **Work stealing**: one atomic CAS per steal attempt (Chase-Lev deque).
  Only on the steal path — owner push/pop is non-atomic.
- **Pending timers MPSC queue**: atomic push (any core), non-atomic pop
  (only owning core). Lock-free, bounded cost.
- **ARP/NDP cache**: entries expire and refresh. Double-buffer pattern —
  two fixed-size tables, writer fills the inactive one, atomically swaps
  an index (`AtomicU8::store`). Readers load index and read. No allocation,
  no free, no grace period. ARP updates are rare (seconds), so the copy
  cost is negligible. Both tables are always valid (one current, one stale).
- **Inbox + TX staging** (Tier 2): SPSC rings. Core 0 writes to other
  cores' inboxes (one writer, one reader). Each core writes its own TX
  staging (one writer), core 0 reads (one reader). Acquire/release on
  index updates, no CAS.
- **Shutdown flag**: one `AtomicBool`, checked in event loop. Set by
  whichever core detects 0x03 on serial, then IPI all cores to wake.
- **DHCP lease state**: single-writer (core 0 handles DHCP). IP address
  change requires updating all cores. Use same atomic-swap pattern as ARP.

### Task model evolution: closures -> async/await

**Start with closures**: tasks are simple `fn()` closures. Packet arrives
-> enqueue closure that processes it. No allocator pressure, no Pin/Waker.
Design the work queue interface generically (`trait Task { fn run(self); }`)
so it can accept futures later.

**Evolve toward async/await**: implement Rust `Future` support.
- `Reactor`: converts VirtIO interrupts -> `Waker` notifications
- `Spawner`: `spawn(async { ... })` enqueues a future as a task
- App code becomes:
  ```rust
  async fn handle(stream: TcpStream) {
      let req = stream.read().await;   // yields, core does other work
      stream.write(&response).await;
  }
  ```
- Compiler generates state machines — no heap alloc per yield point
- The event loop doesn't change: poll -> run task -> repeat.
  "Run task" just means `future.poll()` instead of `closure()`.

This is the same progression tokio took: simple executor first,
async/await support layered on when the foundation is solid.

### MSI-X interrupt affinity (Tier 1)

Each VirtIO queue gets its own MSI-X vector, pinned to its owning core:
```
Core 0 owns: net RX/TX queue 0, blk queue 0 -> MSI-X vectors 0,1,2
Core 1 owns: net RX/TX queue 1, blk queue 1 -> MSI-X vectors 3,4,5
Core N owns: ...
```

Setup sequence (during multi-queue init):
1. Negotiate `VIRTIO_NET_F_MQ` (multi-queue feature)
2. Create N queue pairs (one per core)
3. Allocate MSI-X vectors (one per queue)
4. Program each vector's affinity -> owning core
   - x86: APIC destination field in MSI-X table entry -> direct to LAPIC
   - ARM (KVM): GICv3 ITS maps MSI-X -> LPI -> target core
   - ARM (TCG): no ITS — use GICv2M (`-machine virt,its=off`).
     MSI-X write -> GICv2M -> SPI. Route SPI via GICD_IROUTERn -> core.

### Adding new device types

The event loop is extensible — adding storage is just:
```rust
poll_virtio_blk(&my_blk_queue);  // add one line to the loop
```
No architectural changes. Each device type follows the same pattern:
per-core queue pair, hardware RSS/MSI-X distribution, poll in the loop.

### 2a. SMP boot

Boot sequence: core 0 completes ALL initialization (memory, devices,
network config) BEFORE starting secondary cores. No boot barrier needed —
secondary cores simply don't exist until core 0 calls PSCI CPU_ON /
INIT-SIPI-SIPI after init is done.

- [ ] Core 0: complete all init (mm, devices, DHCP, VirtIO queues)
- [ ] Core 0: allocate per-core state for all cores (stacks, queues, timers)
- [ ] aarch64: start APs via PSCI CPU_ON (after init complete)
- [ ] x86_64: start APs via INIT-SIPI-SIPI (after init complete)
- [ ] Each AP: init own GIC redistributor / APIC, enter event loop
- [ ] Per-core stack allocation (fixed-size, allocated by core 0 at boot)
- [ ] Per-core Chase-Lev deque
- [ ] Per-core timer wheel + pending_timers MPSC queue
- [ ] Per-core TX staging buffer (Tier 2)
- [ ] Per-core heap slab (bump allocator for task-scoped allocations)
- [ ] x86_64: APIC init (replace legacy PIC for multi-core)
- [ ] aarch64: per-core GIC redistributor init
- [ ] Graceful shutdown: serial 0x03 detected -> set AtomicBool -> IPI all cores

**Tests:**
- [ ] Integration: `test_smp_boot` — boot with `-smp 4`, verify all 4 cores reach event loop (each prints "core N online")
- [ ] Integration: `test_per_core_state` — verify each core has independent stack, timer, queue
- [ ] Integration: `test_ipi` — core 0 sends SGI/IPI to core 1, core 1 acknowledges via serial
- [ ] Run on QEMU aarch64 AND x86_64

**Try it:**
```bash
bazel test //apps/test_smp:test                # serial: "core 0 online" .. "core 3 online"
bazel test //apps/test_smp:test --config=qemu  # same on QEMU
# Webserver still runs single-core here — cores boot but networking is next
```

### 2b. Tier 1: multi-queue + MSI-X (QEMU)

- [ ] Negotiate `VIRTIO_NET_F_MQ` feature bit
- [ ] Create N queue pairs (one per core)
- [ ] MSI-X setup: allocate vectors, program MSI-X table
- [ ] MSI-X affinity: route each vector to owning core (APIC / GICv2M)
- [ ] RSS configuration: program indirection table + hash key
- [ ] Per-core RX/TX poll in event loop
- [ ] Log which core handles each HTTP request
- [ ] QEMU flags: `-smp N`, `mq=on,queues=N,vectors=2N+2`
- [ ] Extend bench.sh: compare 1-core vs 2-core vs 4-core throughput

**Tests:**
- [ ] Integration: `test_multiqueue` — boot with `-smp 4, mq=on,queues=4`, verify 4 queue pairs negotiated
- [ ] Integration: `test_msix_affinity` — verify MSI-X vectors route to correct cores
- [ ] Integration: `test_rss_distribution` — send from multiple source ports, verify packets land on different cores
- [ ] Integration: HTTP smoke tests with `-smp 4` (regression)

**Try it (the big milestone):**
```bash
# Webserver on 4 cores — serial shows requests handled by different cores
bazel run //apps/webserver:run   # with -smp 4 in run script
# Benchmark: compare 1 vs 4 cores
UNIKERNEL_CPUS=1 ./scripts/bench.sh   # baseline
UNIKERNEL_CPUS=4 ./scripts/bench.sh   # expect ~linear scaling
# Watch serial output for "core 2: GET /health from 10.0.2.2:54321"
```

### 2c. Tier 2: software distribution (VZ + single-queue)

- [ ] Detect single-queue at boot (`VIRTIO_NET_F_MQ` not offered)
- [ ] Flow hash function: hash(src_ip, dst_ip, src_port, dst_port)
- [ ] Per-core inbox (SPSC: core 0 writes, owning core reads) for RX delivery
- [ ] Batched RX distribution: drain entire RX queue, classify, enqueue to inbox
- [ ] Batched IPI: one IPI per core that received packets (not per packet)
- [ ] Per-core TX staging buffers (SPSC rings in regular memory)
- [ ] Core 0 TX flush: drain all per-core TX staging into VirtIO TX ring
- [ ] Tier auto-detection: MQ offered -> Tier 1, else -> Tier 2

**Tests:**
- [ ] Integration: `test_tier2_distribution` — boot VZ (or QEMU without MQ), verify software distribution active
- [ ] Integration: `test_tier_autodetect` — verify Tier 1 on QEMU with MQ, Tier 2 on QEMU without MQ

**Try it:**
```bash
UNIKERNEL_CPUS=4 ./scripts/bench.sh   # VZ flavor shows multi-core perf
# Serial: "Tier 2: software distribution (single-queue detected)"
# Serial: "core 0: distributed 12 packets (3 to core 1, 4 to core 2, 5 to core 3)"
```

### 2d. Work stealing

- [ ] Per-core SPSC ring for pinned tasks (no atomics on fast path)
- [ ] Per-core Chase-Lev deque for stealable tasks (owner LIFO, thieves FIFO CAS)
- [ ] Event loop: drain pinned queue first, then stealable deque
- [ ] Thieves only access other cores' stealable deques (never pinned queues)
- [ ] Steal from busiest core (check stealable deque depths)
- [ ] IPI to wake sleeping core when work is available

**Tests:**
- [ ] Unit: SPSC ring ops (push, pop, full, empty)
- [ ] Unit: Chase-Lev deque ops (push, pop, steal, boundary conditions)
- [ ] Unit: concurrent steal (multiple thieves, verify no lost/duplicated items)
- [ ] Integration: `test_work_stealing` — load one core with stealable tasks, verify idle cores steal
- [ ] Integration: `test_pinned_not_stolen` — pinned tasks stay on owning core under load

### 2e. Per-core timer wheels

- [ ] Timer wheel data structure (per-core, only owning core reads)
- [ ] Insert / fire / cancel operations
- [ ] `pending_timers` MPSC queue: stolen tasks push timers for remote connections
- [ ] `poll_timers()`: drain pending_timers into wheel, then fire expired
- [ ] Timer-driven wakeup (per-core architectural timer)

**Tests:**
- [ ] Unit: timer wheel insert, fire ordering, cancel
- [ ] Unit: MPSC pending_timers push from multiple cores, drain on owner
- [ ] Integration: `test_timer_fire` — set timers on different cores, verify correct fire times
- [ ] Integration: `test_cross_core_timer` — stolen task arms timer on remote core, verify it fires

### 2f. Task trait + closure-based tasks

- [ ] `trait Task { fn run(self); }` interface
- [ ] Closure wrapper implementing Task
- [ ] Event loop processes tasks via trait

### 2g. Async/await support (future evolution)

- [ ] `Reactor`: VirtIO interrupts -> `Waker` notifications
- [ ] `Spawner`: `spawn(async { ... })` enqueues future as task
- [ ] Event loop: `future.poll()` instead of `closure()`
- [ ] Pin/Waker integration

### 2h. Performance regression tests

- [ ] Single-core baseline (must not regress)
- [ ] Multi-core throughput scaling (expect ~linear with core count)
- [ ] p99 latency under load (must not spike with more cores)
- [ ] Tier 1 vs Tier 2 comparison

---

## Phase 3: UDP + Minimal QUIC

### 3a. UDP module (net/udp.rs)

Simple — no state machine, no connection tracking:
```rust
pub fn send(src_port: u16, dst_ip: Ipv4Addr, dst_port: u16, data: &[u8])
pub fn recv(buf: &mut [u8]) -> Option<(Ipv4Addr, u16, usize)>
```
Maybe 100 lines. Sits between IPv4 and QUIC.

- [ ] UDP send/receive implementation
- [ ] Checksum calculation
- [ ] `//net:udp` Bazel target (deps: ipv4)

**Tests:**
- [ ] Unit: UDP header checksum, parse/build
- [ ] Integration: send/receive UDP packets through QEMU (netcat or custom tool)

**Try it:**
```bash
bazel test //net:udp_test                      # unit tests
# From host while QEMU runs:
echo "hello" | nc -u localhost 5000            # send UDP to unikernel
# Serial: "UDP recv: 5 bytes from 10.0.2.2:xxxxx"
```

### 3b. TLS 1.3 crypto

QUIC mandates TLS 1.3. Options:
- **`ring`** — AWS's crypto library, `no_std` compatible core
- **`rustls`** — higher level, may need `alloc` but not `std`
- **Manual**: implement TLS 1.3 handshake + AES-GCM using `ring` primitives

Minimum viable: one cipher suite (TLS_AES_128_GCM_SHA256), server-only,
no client certs, no 0-RTT.

- [ ] Select and integrate crypto library via crate_universe
- [ ] TLS 1.3 handshake (server-side)
- [ ] AES-128-GCM encrypt/decrypt
- [ ] Certificate handling (self-signed for dev)

**Tests:**
- [ ] Unit: TLS record parsing, handshake state machine
- [ ] Integration: TLS handshake completes with external client

### 3c. QUIC implementation

Options:
1. **`quiche`** (Cloudflare) — C library with Rust bindings, battle-tested
2. **`quinn`** — pure Rust, needs tokio/async
3. **Minimal hand-written** — only what a server needs

Recommendation: start with `quiche` (proven, `no_std`-friendly C core),
migrate to pure Rust later if desired.

Minimal server-side QUIC needs:
- Initial handshake (1-RTT)
- Stream multiplexing
- Loss detection + retransmission
- Flow control
- Connection close

Skip: 0-RTT, connection migration, path validation, PMTUD.

- [ ] Select QUIC implementation (quiche vs quinn vs hand-written)
- [ ] Integrate via crate_universe or vendor
- [ ] QUIC handshake (server-side, 1-RTT)
- [ ] Stream multiplexing
- [ ] Loss detection + retransmission
- [ ] Flow control
- [ ] Connection close
- [ ] `//net:quic` Bazel target (deps: udp, tls)

**Tests:**
- [ ] Unit: QUIC packet number decode, frame parsing
- [ ] Integration: QUIC handshake with external client (curl --http3 or quiche-client)

**Try it:**
```bash
# QUIC handshake from host to unikernel
quiche-client --no-verify https://localhost:4433/health
# Serial: "QUIC: handshake complete, 1 stream"
```

---

## Phase 4: HTTP/3

### 4a. QPACK header compression

Simplified static-table-only QPACK — no dynamic table needed for a
simple server. ~200 lines.

- [ ] QPACK static table encoder/decoder
- [ ] Skip dynamic table (unnecessary for simple server)

**Tests:**
- [ ] Unit: QPACK encode/decode round-trip

### 4b. HTTP/3 frame parsing

H3 frames over QUIC streams. Simpler than HTTP/2 — no TCP head-of-line
blocking, no flow control at H3 level (QUIC handles it).

- [ ] H3 frame parser (HEADERS, DATA, SETTINGS)
- [ ] H3 frame builder

**Tests:**
- [ ] Unit: H3 frame parse/build round-trip

### 4c. uni::http3 module

Same API pattern as uni::http:
```rust
pub struct H3Server { ... }
impl H3Server {
    pub fn route(&mut self, path: &[u8], handler: Handler);
    pub fn run(&mut self, port: u16);
}
```

App code barely changes:
```rust
#[uni::main]
fn main() {
    let mut server = H3Server::new();
    server.route(b"/health", handle_health);
    server.run(443);
}
```

- [ ] `H3Server` struct with route/run API
- [ ] Request/response handling over QUIC streams
- [ ] `//uni:http3` Bazel target (deps: quic)
- [ ] Example app using `//uni:http3`

**Tests:**
- [ ] Integration: HTTP/3 request/response with curl --http3
- [ ] Integration: HTTP smoke tests (GET /, GET /health, GET /404) over HTTP/3

**Try it:**
```bash
# HTTP/3 request from host to unikernel
curl --http3 -k https://localhost:8443/health
# Response: {"status": "ok"}
# Serial: "H3: GET /health from [::1]:xxxxx (QUIC stream 0)"
# Benchmark comparison:
./scripts/bench.sh   # now includes HTTP/1.1 vs HTTP/3 comparison
```

---

## Phase 5: IPv6 + NDP (drop IPv4/ARP)

### 5a. IPv6 (net/ipv6.rs)

Simpler header than IPv4 (no checksum, no fragmentation at network layer).
~150 lines.

- [ ] IPv6 header parse/build
- [ ] `//net:ipv6` Bazel target (deps: ethernet)

**Tests:**
- [ ] Unit: IPv6 header parse/build
- [ ] Integration: ping6 from host to VM

### 5b. NDP — Neighbor Discovery Protocol (net/ndp.rs)

Replaces ARP. Uses ICMPv6:
- Neighbor Solicitation/Advertisement (like ARP request/reply)
- Router Solicitation/Advertisement (for gateway discovery)
- ~200 lines

- [ ] Neighbor Solicitation/Advertisement
- [ ] Router Solicitation/Advertisement
- [ ] `//net:ndp` Bazel target (deps: ipv6)

**Tests:**
- [ ] Unit: NDP message encode/decode
- [ ] Integration: neighbor discovery completes in QEMU

### 5c. Stateless autoconfiguration (SLAAC)

Replaces DHCP for IPv6. Generate address from MAC + router prefix.
~50 lines. Much simpler than DHCP.

- [ ] SLAAC address generation from MAC + router prefix
- [ ] Router advertisement processing

**Tests:**
- [ ] Unit: SLAAC address generation
- [ ] Integration: HTTP over IPv6 end-to-end

**Try it:**
```bash
# IPv6 ping from host to unikernel
ping6 fe80::...%tap0
# HTTP over IPv6
curl -6 http://[fe80::...%tap0]:80/health
# Serial: "SLAAC: configured fe80::5054:ff:fe12:3456"
# Serial: "NDP: neighbor solicitation from fe80::1"
```

---

## Phase 6: Advanced Features (future)

### Virtio-vsock

Replace virtio-net for VM<->host communication. No Ethernet/IP overhead.
Pairs with VZ.framework for ultra-low-latency host communication.

- [ ] virtio-vsock driver
- [ ] Host communication API

### eBPF packet filter

Programmable packet processing in the unikernel. Run user-supplied
eBPF programs for custom filtering/routing.

- [ ] eBPF bytecode interpreter
- [ ] Packet filter hook points

### io_uring-style submission queues

Replace poll-based I/O with submission/completion queues.
Natural fit for QUIC's async nature.

- [ ] Submission/completion ring buffers
- [ ] Async I/O API

---

## Test Infrastructure

### Current state

- 4 HTTP smoke tests (test_native.sh, test_qemu.sh, test_vz.sh, test_iso.sh)
- 1 benchmark script (bench.sh)
- Zero unit tests, zero multi-core tests

### Test architecture

**Layer 1 — Native unit tests (`bazel test`, runs on host):**
Pure logic extracted into hardware-independent functions. Standard `#[test]`.
Structure code so protocol logic is in pure functions: `&[u8]` -> parsed structs.

```python
rust_test(name = "ethernet_test", crate = ":ethernet")
```

**Layer 2 — In-kernel integration tests (QEMU boot tests):**
Separate test apps that boot QEMU, exercise features, report via serial.

```python
rust_library(name = "app", srcs = ["main.rs"], deps = ["//uni", "//kernel"])
unikernel_binary(name = "test_smp", app = ":app")
sh_test(name = "test", srcs = ["test.sh"], data = [":test_smp.elf"])
```

### Naming convention

- Unit tests: `bazel test //net:ethernet_test`, `//kernel:mm_test`
- Integration tests: `bazel test //apps/test_smp:test`
- Configs: `--config=qemu`, `--config=vz`, `--config=x86_64-qemu`

---

## Implementation Priority

| Phase | Effort | Impact | Dependencies |
|-------|--------|--------|-------------|
| 1a. Per-protocol net/ targets | Small | Clean architecture | None |
| 1b. crate_universe | Small | Enables crates.io deps | None |
| 2a. SMP boot (AP spin-up) | Medium | Foundation for all multi-core | None |
| 2b. Tier 1: multi-queue + MSI-X | Large | Per-core queues (QEMU) | 2a |
| 2c. Tier 2: software distribution | Medium | Multi-core on VZ | 2a |
| 2d-h. Work stealing + async | Medium | Multi-core efficiency | 2a-c |
| 3a. UDP | Small | Enables QUIC | None |
| 3b. TLS 1.3 | Medium | Required for QUIC | 1b |
| 3c. QUIC | Large | Modern transport | 3a, 3b |
| 4. HTTP/3 | Medium | Modern HTTP | 3c |
| 5. IPv6 + NDP | Medium | Drop IPv4 legacy | None |

**Suggested order: 1a -> 1b -> 3a -> 2a -> 2b -> 2c -> 3b -> 3c -> 4 -> 5 -> 2d-h**

Start with infrastructure (per-protocol targets, crate_universe), then
UDP (simple win), then multi-core in stages: SMP boot first (foundation),
then Tier 1 multi-queue (QEMU), then Tier 2 software distribution (VZ).
QUIC/HTTP3 can leverage multi-core. IPv6 last (cleanest — drops legacy).
Async/await evolution is last (build on proven foundation).
