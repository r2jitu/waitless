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
- [x] `//net:ethernet` (deps: types, drivers)
- [x] `//net:arp` (deps: types, ethernet, drivers)
- [x] `//net:ipv4` (deps: types, ethernet, arp) — returns `Ipv4Packet`, no dispatch
- [x] `//net:tcp` (deps: types, ipv4, kernel)
- [x] `//net:udp` (deps: types, ipv4)
- [x] `//net:dhcp` (deps: types, ethernet, arp, ipv4, drivers, kernel)
- [x] `//net:net` umbrella — thin dispatch + poll (~30 lines)
- [x] `arch_udelay` moved to `kernel/time.rs`
- [ ] Split `//uni` into per-feature targets (deferred — tied to Phase 2 event loop)

**Tests:**
- [x] Unit: byte order roundtrips, address types, RFC 1071 checksums (9 tests)
- [x] Integration: existing HTTP + UDP smoke tests pass on x86_64 + aarch64
- [x] Unit: ethernet frame parse/build (2 tests)
- [x] Unit: ARP request encoding, reply decoding (2 tests)
- [x] Unit: IPv4 header parse, checksum, version rejection (3 tests)
- [x] Unit: TCP SYN segment parse, flag decode (2 tests)
- [x] Unit: DHCP magic cookie, option parsing, end marker (3 tests)

**Try it:**
```bash
bazel test //net:types_test //net:protocol_tests  # 21 unit tests (host-native)
bazel test //apps/webserver:test                  # HTTP + UDP echo (QEMU)
```

### 1b. Add crate_universe for crates.io dependencies

Required for pulling in crypto (`ring`), QUIC (`quiche`/`quinn`), etc.

- [x] Add `crate_universe` to MODULE.bazel (annotation-based, no Cargo.toml)
- [x] Verified bitflags resolves and compiles for x86_64-unknown-none
- [x] Fix aarch64-unknown-none platform gap (patched rules_rust triple_mappings.bzl)
- [x] Use a crates.io dep in the unikernel and boot it (bitflags in net/tcp.rs)

**Try it:**
```bash
bazel build --config=aarch64-qemu @crates//:bitflags   # compiles for bare-metal aarch64
bazel build --config=x86_64-qemu @crates//:bitflags    # compiles for bare-metal x86_64
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

- [x] Core 0: complete all init (mm, devices, DHCP, VirtIO queues)
- [x] Core 0: allocate per-core stacks (64KB each via alloc_pages)
- [x] aarch64: start APs via PSCI CPU_ON (after init complete)
- [x] AP trampoline (boot.S): EL2->EL1 drop, MMU enable, VBAR, stack, jump to Rust
- [x] aarch64: per-core GIC redistributor init (init_ap)
- [x] FDT parser: count cpu@N nodes for CPU count
- [x] UNIKERNEL_CPUS env var for configurable SMP count in QEMU
- [x] x86_64: extend boot page tables to 4GB (covers APIC MMIO at 0xFEE00000)
- [x] x86_64: APIC detected + logged (SVR enable deferred to avoid PIC conflict)
- [x] x86_64: ACPI MADT parsing (kernel/x86_64/acpi.rs, detects 4 CPUs)
- [x] x86_64: INIT-SIPI-SIPI infrastructure ready (kernel/x86_64/smp.rs + ap_boot.S)
- [x] Per-core Chase-Lev deque (kernel/deque.rs, 8 unit tests)
- [x] Per-core timer wheel + pending_timers MPSC queue (kernel/timer.rs, 6 tests)
- [x] Per-core TX staging buffer (kernel/percpu.rs TxStaging)
- [x] PerCore struct tying all data structures together
- [x] Per-core heap slab (kernel/bump.rs, 64KB bump allocator, 5 tests)
- [x] Graceful shutdown: AtomicBool + SGI to wake APs + PSCI CPU_OFF

**Tests:**
- [x] Integration: boot with `-smp 4`, all 4 cores print "core N online" (aarch64 QEMU)
- [x] Integration: `test_smp_boot` — automated test parsing serial for core count
- [x] Integration: `test_per_core_state` — verify each core has independent inbox, TX staging, ID
- [x] Integration: `test_ipi` — core 0 sends SGI to core 1, core 1 acknowledges (GICv2 + GICv3)
- [x] x86_64: AP trampoline working (16-bit→32-bit→64-bit, absolute call to Rust)
- [x] x86_64: 4 cores online via INIT-SIPI-SIPI (per-core serialized startup)

**Try it:**
```bash
bazel test //apps/test_smp:test                # serial: "core 0 online" .. "core 3 online"
bazel test //apps/test_smp:test --config=qemu  # same on QEMU
# Webserver still runs single-core here — cores boot but networking is next
```

### 2b. Tier 1: multi-queue + MSI-X

- [x] Negotiate `VIRTIO_NET_F_MQ` feature bit (modern PCI + MMIO paths)
- [x] Create N queue pairs (one per core) via `max_virtqueue_pairs` device config
- [x] Control VQ + `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET` command to activate N pairs after DHCP
- [x] MSI-X setup on x86_64 ModernPCI: parse capability, write table, enable
- [x] MSI-X per-core affinity on x86_64: each RX vector → owning vCPU's LAPIC (ACPI topology)
- [x] Per-core RX poll in event loop: each core polls `rx_queues[core_id]` with NAPI rearm
- [x] Per-core TX path: deferred kick, `flush_tx_kick_if_dirty()` uses per-core TX queue
- [x] Tier auto-detection (runtime branch on `has_mq && num_queue_pairs > 1`)
- [x] bench.py `QemuEnv` / `KvmEnv` pass `mq=on,vectors=2N+2` + `queues=N` (tap/vhost)
- [x] bench.py compares 1-core vs N-core throughput by default
- [x] HVF runner (Apple Silicon native): multi-queue Tier 1 via SO_REUSEPORT UDP siblings + TCP accept dispatcher
- [x] Local `scripts/run-local.sh`: pass `mq=on,queues=N,vectors=2N+2` when `UNIKERNEL_CPUS > 1`

**Not implemented / deferred:**
- [ ] **aarch64 QEMU MSI routing** — virtio-mmio driver creates N queue pairs but only
      registers an IRQ for queue 0 (single SPI from FDT `interrupts`). Multi-queue still
      works functionally because the event loop spins before HLTing (`IDLE_SPIN_BEFORE_HLT`),
      but non-core-0 cores don't wake *directly* on their own queue. aarch64 TCG multi-core
      bench (`qemu-arm`) is single-core-only in `bench.py` anyway. Fix requires GICv2M or
      ITS integration; parked behind HVF (which already has full Tier 1 via the native runner).
- [ ] **Explicit RSS** — no `VIRTIO_NET_F_RSS` / indirection table. QEMU's virtio-net
      automatically flow-hashes across queue pairs when `mq=on`, which is what we currently
      rely on. Good enough until we see a workload that proves otherwise.

**Tests:**
- [x] Integration: x86_64 QEMU TCG + KVM boot with `-smp 4, mq=on, queues=4`, 4 pairs negotiated
      (verified via serial log "virtio_net: multi-queue: 4 queue pairs")
- [x] Integration: HTTP + UDP smoke tests with `-smp 4` across x86_64 TCG, x86_64 KVM, HVF
- [x] Integration: `/compute` scales near-linearly with core count on x86_64 MTTCG (4 cores)

**Try it (the big milestone):**
```bash
# Webserver on 4 cores — each core owns its own virtio queue pair
UNIKERNEL_CPUS=4 ./scripts/run-local.sh
# Serial: "virtio_net: MSI-X enabled (4 RX vectors)"
#         "virtio_net: MQ activated"
#         "[net] Tier 1: per-core RX queues (4 queue pairs)"

# Compare 1 vs 4 cores
python3 scripts/bench.py --env hvf --cores 1,4           # HVF on Apple Silicon
python3 scripts/bench.py --env qemu --cores 1,4          # x86_64 TCG
python3 scripts/bench.py --env kvm  --cores 1,4          # x86_64 KVM (GCP)
```

### 2c. Tier 2: software distribution (VZ + single-queue)

- [x] HTTP + UDP tests pass with -smp 4 on both arches (regression verified)
- [x] Detect single-queue at boot (always Tier 2 when `num_cores > 1`; MQ not yet supported)
- [x] Flow hash function: FNV-1a hash(src_ip, dst_ip, src_port, dst_port) % num_cores
- [x] Per-core RX inbox (RxInbox: 64-slot packet pool + SPSC index ring)
- [x] Batched RX distribution: core 0 drains RX, classifies by protocol+flow, enqueues to inbox
- [x] Batched IPI: one IPI per core that received packets (not per packet)
- [x] Per-core TX staging buffers (TxStaging: 32-slot pool, SPSC ring)
- [x] Core 0 TX flush: drains all per-core TX staging via TX_PENDING atomic flag
- [x] AP event loop: drain inbox → process → HLT/WFI (replaces idle loop)
- [x] Stack-allocated TX buffers in ethernet/ipv4 (safe for multi-core)
- [x] AP poll function hook (kernel::percpu::set_ap_poll_fn with volatile read)
- [x] x86_64: AP loads BSP GDT + IDT, APIC EOI for IPI vectors
- [x] TCP connection pinning: per-core pools (32 slots/core), flow hash distribution
- [x] Per-core HTTP service: each core has listener + active connections (SO_REUSEPORT)
- [x] Per-core TLS via GS_BASE (x86_64) / TPIDR_EL1 (aarch64) → fast cpu_id()
- [x] SEV/WFE inter-core signaling on aarch64 (replaces GIC SGI IPI on hot path)
- [x] MTTCG data race fixes (atomic counters, boot-time MAC init)
- [x] Unified kernel event loop: all cores run identical poll→drain→service→idle
- [x] Rotating distributor with test-then-CAS RX lock
- [x] Direct RX distribution (no batch buffer copy)
- [x] Try-lock direct TX send (bypass staging when uncontended)
- [x] Graduated idle backoff (reduce MTTCG wasted wakeups)
- [x] Tier auto-detection: `net::poll()` branches on `drivers::virtio_net::num_queue_pairs()`
      — MQ negotiated → Tier 1 path (`poll_tier1`), else → Tier 2 (`poll_tier2`).

**Historical note (VZ.framework):** Tier 2 was originally built to get multi-core working
under VZ.framework, which has no multi-queue and forces all INTx to core 0. VZ is no
longer the local dev runner on Apple Silicon (the native HVF runner in `tools/hvf-runner`
replaced it; see MEMORY.md). Tier 2 is still the code path for any single-queue platform.

**Tests:**
- [x] Integration: HTTP + UDP tests pass with -smp 4 on both arches
- [x] Integration: serial output shows "Tier 2: software distribution (N cores)"
- [ ] Integration: `test_tier2_distribution` — dedicated test verifying per-core packet processing

**Try it:**
```bash
UNIKERNEL_CPUS=4 bazel test --config=aarch64-qemu //apps/webserver:test --test_env=UNIKERNEL_CPUS=4
UNIKERNEL_CPUS=4 bazel test --config=x86_64-qemu //apps/webserver:test --test_env=UNIKERNEL_CPUS=4
# Serial: "[net] Tier 2: software distribution (4 cores)"
# UDP multi-core benchmark:
./scripts/bench_udp.sh
```

### 2d. Work stealing

- [x] Per-core SPSC ring for pinned tasks/inbox/TX staging (kernel/spsc.rs, 5 tests)
- [x] Per-core Chase-Lev deque for stealable tasks (kernel/deque.rs)
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

- [x] UDP send/receive implementation (net/udp.rs)
- [x] Checksum calculation (reuses tcp_checksum with proto=17)
- [x] Port-based dispatch: bind(port, handler), up to 8 handlers
- [x] ipv4_receive dispatches PROTO_UDP to udp_receive
- [x] `//net:udp` as separate Bazel target (deps: types, from_bytes, ipv4, kernel)

**Tests:**
- [x] Unit: UDP checksum computation + verification
- [x] Integration: UDP echo test through QEMU (python3 socket, both arches)

**Try it:**
```bash
bazel test //net:types_test                          # unit tests (includes UDP checksum)
bazel test --config=x86_64-qemu //apps/webserver:test  # HTTP + UDP echo (x86_64)
bazel test --config=aarch64-qemu //apps/webserver:test # HTTP + UDP echo (aarch64)
```

### 3b. TLS 1.3 crypto — audited stack on bare metal

QUIC mandates TLS 1.3. Path taken (2026-04-14): pull rustls 0.23 +
the rustls-rustcrypto pure-Rust crypto provider via crate_universe,
fix the `cpufeatures`/LLVM SIMD-legalisation issue once with target-
feature flags so all of RustCrypto's audited AEADs (aes-gcm,
chacha20poly1305, polyval, poly1305) build cleanly for
`x86_64-unknown-none`. No hand-rolled crypto in production
codepaths.

Cipher suite shipped: `TLS_CHACHA20_POLY1305_SHA256`. AES-GCM is
also available via the same provider — we just narrow the
`ServerConfig` cipher suite list to ChaCha20-Poly1305 for now.

#### What ships

- [x] **cpufeatures fix.** Per-crate `crate.annotation` in
      `MODULE.bazel` passes
      `-Ctarget-feature=-soft-float,+sse,+sse2,+sse3,+ssse3,+sse4.1,
       +sse4.2,+avx,+avx2,+aes,+pclmul,+fma,+bmi1,+bmi2`
      to every crypto crate that uses SIMD intrinsics
      (aes / aes-gcm / chacha20 / chacha20poly1305 / ghash / poly1305 /
      polyval / curve25519-dalek / rsa / rustls-rustcrypto). The
      kernel already enables SSE at boot (`limine_boot.S` sets
      `CR4.OSFXSR|OSXMMEXCPT`) and our cooperative scheduler never
      preempts, so kernel-side SIMD is safe with no FXSAVE/XSAVE.
      x86_64-v3 (Haswell, 2013) is the baseline we assume — matches
      every cloud VM we'd ever run on. Unblocks
      `aes-gcm`/`polyval`/`poly1305` from "Do not know how to split
      the result of this operator!" LLVM bailouts
      (rust-lang/rust#87642, #92760, #136544).
- [x] **RustCrypto primitives** via crate_universe: `sha2`, `hmac`,
      `hkdf`, `aes-gcm`, `chacha20poly1305`, `chacha20`,
      `x25519-dalek`, `p256`, `ed25519-dalek`, `rand_core`. All build
      on both `x86_64-unknown-none` and `aarch64-unknown-none` after
      the cpufeatures fix + a `curve25519-dalek` build-script
      override (`CARGO_CFG_CURVE25519_DALEK_BACKEND=serial`).
- [x] **`kernel::rng`** — kernel-backed RNG providing
      `fill_bytes(&mut [u8])`. Seed = 256 cycle-counter reads
      (TSC / CNTVCT_EL0) + best-effort `RDRAND` mix-in, hashed
      through SHA-256 with a domain-separation tag. Expansion via a
      single ChaCha20 stream cipher keyed from the seed (same
      pattern as Linux's `getrandom(2)`).
- [x] **`getrandom 0.2` custom backend.** `kernel::rng` registers
      itself via `register_custom_getrandom!` so `rand_core::OsRng`
      and every consumer of it (RustCrypto, x25519-dalek,
      rustls-rustcrypto sign/kx) work without a syscall. Workspace
      dep declares `getrandom = { default-features = false, features = ["custom"] }`.
- [x] **`#[global_allocator]`** in `kernel::mm::GLOBAL_ALLOCATOR`
      forwarding to `kmalloc`/`kfree`. Living in the kernel crate
      (rather than `uni`) means `boot/limine` and any other crate
      depending only on `kernel` also gets a working `alloc::*`
      without extra wiring. `#[used]` keeps the linker from GC'ing
      it. Native builds use libstd's default.
- [x] **`//net:tls_crypto`** — thin byte-slice wrapper over
      `chacha20poly1305::ChaCha20Poly1305`. Hides `generic-array`
      types from downstream callers; gives us one place to
      negotiate the AEAD if QUIC later picks a different suite.
- [x] **`//net:tls`** — sans-io key schedule + transcript hashing:
      `HKDF-Expand-Label`, `Derive-Secret`, `Transcript` (running
      SHA-256 with snapshots), `TrafficKey` (seal/open with per-seq
      nonce from RFC 8446 §5.3), `KeySchedule` walking early →
      handshake → application stages, `X25519ServerKey` for KX.
      Built on sha2/hmac/hkdf/x25519-dalek + `//net:tls_crypto`.
      Exists alongside `rustls` for QUIC's own packet-protection
      key derivation later (QUIC reuses HKDF-Expand-Label with
      different labels) and for any sans-io callers that don't want
      to drag in the full rustls state machine.
- [x] **`//net:tls_handshake`** — handshake message framing, strict
      `ClientHello` parser (supported_versions, supported_groups,
      key_share), `build_server_hello()`. Zero external deps,
      5 host unit tests. Useful for low-level debugging /
      interop bring-up; not used by the rustls path.
- [x] **`rustls 0.23.38`** + **`rustls-rustcrypto 0.0.2-alpha`**
      via crate_universe. Built with
      `default-features = false, features = ["logging", "custom-provider"]`
      and `default-features = false, features = ["alloc", "zeroize"]`
      respectively. Both compile cleanly for both bare-metal targets.
      No `[patch.crates-io]` needed — the once_cell `std` gotcha the
      research warned about doesn't trip rustls 0.23.38 in practice
      with our feature combination.
- [x] **Pre-generated dev cert**:
      `apps/webserver/dev_certs/dev_cert.{der,pem}` +
      `dev_key.{der,pem}` (Ed25519, 10y validity, SAN covers
      `unikernel.local`/`localhost`/`127.0.0.1`/`10.0.2.15`). DER for
      `include_bytes!()` use inside the unikernel, PEM for
      host-side `curl --cacert` / `openssl s_client`. Regen via
      `dev_certs/regen.sh`.
- [x] **`//apps/test_tls`** — in-kernel integration test. Boots
      via HVF, runs **9 stages** end-to-end:
      `aead_roundtrip`, `aead_tamper_detect`, `x25519_roundtrip`,
      `hkdf_expand_label`, `key_schedule_cascade`,
      `traffic_key_record`, `traffic_key_per_seq_nonce`,
      `rustls_server_config` (loads the dev cert via the
      rustls-rustcrypto provider and instantiates a
      `rustls::ServerConfig` via the no_std `builder_with_details`
      API), `kernel_rng_fill_bytes`. **All 9 pass on bare metal.**

#### Still to do for a working HTTPS server

- [ ] **TLS-over-TCP I/O glue.** Wrap rustls's `ServerConnection`
      around a `net::tcp::TcpStream`: shovel inbound bytes into
      `read_tls()`, drain plaintext via `reader().read()`, push
      handler bytes into `writer().write()`, drain encrypted output
      via `write_tls()`. ~150 lines, mostly buffer plumbing. No new
      crypto.
- [ ] **`uni::http` over TLS.** Add a `TlsListener` / `TlsStream`
      wrapper analogous to `TcpListener` / `TcpStream`. The HTTP
      server changes one line (`server.run(443)` against the
      wrapped listener).
- [ ] **External-client interop**: `curl --cacert dev_cert.pem
      --tlsv1.3 https://unikernel.local:8443/health` succeeds, and
      `openssl s_client -tls1_3 -groups X25519` completes the
      handshake. This is the acceptance test for "TLS works".

**Try it:**
```bash
# Host unit tests
bazel test //net:tls_crypto_test //net:tls_handshake_test
# Bare-metal integration test (runs full key schedule, AEAD
# round-trip, X25519 KX, kernel rng, AND instantiates a real
# rustls::ServerConfig from the dev cert):
bazel build --config=aarch64-hvf //apps/test_tls:test_tls.img
bazel-bin/tools/hvf-runner/run-hvf bazel-bin/apps/test_tls/test_tls.img
# Serial: "TLS TESTS: ALL PASSED"
```

### 3c. QUIC implementation — **blocked on upstream no_std support**

**Status (2026-04-14): blocked. Use audited TLS-over-TCP first; revisit
QUIC after `quinn-proto` lands no_std support or we explicitly fork.**

Decision: do not roll our own QUIC implementation. The 9000-series RFCs
add up to ~600 pages of state machine that we won't deliver to parity.

**Investigated candidates (rejected):**

- **`quinn-proto 0.11.14`** — sans-io core of quinn, in theory the best
  fit because it doesn't depend on tokio. In practice `src/lib.rs:23`
  has unconditional `use std::{...}` and `use std::time::{Duration,
  Instant, SystemTime, UNIX_EPOCH}`. There is no `std` feature flag
  in `Cargo.toml.orig` to disable. `quinn-rs/quinn#579` ("no_std
  support") is open with no merged work. **Cannot build on
  `*-unknown-none` without a substantial fork** that swaps
  `std::time::Instant` for a project-supplied clock and removes
  `io::Error` propagation.
- **`quiche`** (Cloudflare) — uses BoringSSL via the `boring` C/cmake
  crate. The 2020 bare-metal fork (`cloudflare/quiche#252`) is 4+
  years stale, and the maintainers have explicitly said they're
  "very unlikely to support other TLS libraries". Dead end.
- **`s2n-quic`** (AWS) — hard tokio + s2n-tls (C) deps throughout. No
  no_std story.
- **`neqo`** (Mozilla) — hard NSS dep (large C/C++ codebase, needs
  POSIX). Skip.
- **`ngtcp2`** (C) + **`picotls`** (C) — smallest C footprint of the
  C options and wolfSSL has a documented bare-metal config. Heavy
  integration: C toolchain, FFI, cross-compiled wolfSSL build. No
  mature Rust bindings. Punt unless pure-Rust paths fail completely.
- **`mvfst` / `msquic`** — both depend on Schannel/OpenSSL/fizz +
  C++ runtime + platform abstractions. Too heavy for a unikernel.

**Recommended path forward:**

1. Ship audited TLS-over-TCP first (see 3b). HTTPS on TCP is real and
   useful and uses the same rustls + RustCrypto + kernel::rng stack.
2. **Revisit quinn-proto** in 3-6 months: track `quinn-rs/quinn#579`
   for upstream movement on no_std. The blockers are well-scoped
   (Instant, io::Error) and quinn maintainers seem amenable in
   principle, just unprioritised.
3. **Or**: maintain a vendored fork of `quinn-proto` with a small
   no_std patch (replace `std::time::Instant` with a
   project-supplied trait, remove `io::Error` propagation in favour
   of `quinn-proto`'s own error type). Estimated: 200-500 lines of
   patch surface, ongoing rebase cost on every quinn release. Not
   recommended unless we need HTTP/3 urgently.

**Tasks (deferred):**

- [ ] Wait for `quinn-proto` no_std support OR vendor a patched fork
- [ ] `//net:quic` wrapper crate around `quinn-proto`
- [ ] HTTP/3 — defer until QUIC works
- [ ] External-client interop via `curl --http3` / `h2load --h3`

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

## Deferred work (paused, recorded)

Items that came up during development and were deliberately deferred
in favour of forward progress. Each has a short "why now" trigger.

### Production RNG

The current `kernel::rng` is a jitter-entropy collector +
single-shot ChaCha20 expansion. Sufficient for dev/CI/TLS handshake
correctness; **not** a CSPRNG suitable for production. To upgrade:

- [ ] Formal entropy-rate estimate for the cycle-counter source on
      our actual targets (Apple Silicon, GCP N2, x86_64-v3 baseline).
      Run `dieharder` / NIST STS against a captured stream.
- [ ] Periodic reseed: every N seconds OR every M bytes consumed,
      mix in fresh jitter samples + RDRAND/RNDR samples + any
      virtio-rng device output if present.
- [ ] Detect and use `virtio-rng` (PCI / MMIO) as a high-bandwidth
      source when the host exposes one.
- [ ] aarch64 RNDR (FEAT_RNG) detection + use, not just CNTVCT.
- [ ] Replace `RDRAND` standalone trust with mixing-only (per
      intel-sa-00329 best practice).

**Trigger**: before any production deployment that handles real
cert generation, real session tickets, or real client auth.

### Production certificate path

Today we ship a checked-in dev cert (`apps/webserver/dev_certs/`).
Production needs:

- [ ] Boot-time generation of an ephemeral Ed25519 keypair from
      `kernel::rng` and a self-signed cert built with a minimal
      X.509 DER builder (or a vendored trim of `rcgen`'s no_std
      surface).
- [ ] Optionally: bundle a real cert chain via `include_bytes!`
      from a build-time fetch (e.g. an ACME issuance pipeline that
      stamps the binary), with the private key encrypted at rest
      and decrypted at boot via a kernel-supplied passphrase.
- [ ] Decision: ephemeral self-signed (simplest, breaks pinning) vs
      bundled chain (production-realistic, requires build-time
      cert management).

**Trigger**: when we want a public-facing TLS endpoint.

### x86_64 SSE / AVX baseline via custom target JSON

The cpufeatures fix is currently a **per-crate** rustc_flags
annotation in `MODULE.bazel`. Every new crypto crate that hits
LLVM's "Do not know how to split the result of this operator!"
needs to be added to the annotation list. A cleaner long-term
approach is a custom `x86_64-unikernel.json` Rust target spec that
sets `features: "+sse,+sse2,+sse3,+ssse3,+sse4.1,+sse4.2,+aes,
+pclmul,+avx,+avx2,+fma,+bmi1,+bmi2"` as the baseline.

- [ ] Write `bazel/targets/x86_64-unikernel.json` based on
      `x86_64-unknown-none` with the SSE/AVX baseline.
- [ ] Update the rust toolchain registration in MODULE.bazel to
      register the new triple.
- [ ] Drop the per-crate rustc_flags annotations.
- [ ] Verify `bazel test //... --config=x86_64-qemu` still passes.

**Trigger**: when the per-crate annotation list has more than 10-12
crates, or when adding a crate requires a third "look up which
intrinsic is failing" debugging session.

### rustls-rustcrypto upstream stability

`rustls-rustcrypto = "0.0.2-alpha"` is marked **PROTOTYPE**, **DO NOT
USE IN PRODUCTION** by upstream. Currently fine for our dev/CI
work because:
- It targets rustls 0.23.x (current stable line).
- Its dep versions (`aes-gcm 0.10`, `chacha20poly1305 0.10`,
  `sha2 0.10`, `x25519-dalek 2`, `ed25519-dalek 2`, `p256 0.13`)
  match what we already build.
- We're not running it in adversarial environments.

- [ ] Track upstream `RustCrypto/rustls-rustcrypto` for a 0.1.0
      stable release.
- [ ] If upstream stalls, evaluate vendoring + maintaining a fork
      with our specific subset (TLS_CHACHA20_POLY1305_SHA256 +
      X25519 + Ed25519 server cert only, no RSA, no P-384, no
      anything else). Drops a lot of code.
- [ ] If `rustls`'s own pluggable provider story matures (e.g. the
      proposed `rustls::crypto::CryptoProvider` ergonomics
      improvements land), revisit whether we even need
      `rustls-rustcrypto` as a separate crate vs. wiring our own
      provider directly to RustCrypto primitives.

**Trigger**: before any external-facing production deployment.

### TLS panic-strategy host unit tests

`rust_test` on a crate with external deps (sha2, hmac, hkdf,
rustls, ...) fails to build because the deps are compiled with
`-Cpanic=abort` (kernel global policy via `.bazelrc`'s
`extra_rustc_flags`) but the test harness needs `-Cpanic=unwind`.
Currently, `//net:tls`, `//net:tls_crypto`, and `//net:tcp` (and
any future crate with crypto deps) cannot have host-native unit
tests. Coverage lives in bare-metal integration tests like
`//apps/test_tls`.

- [ ] Investigate `cfg(rustls_no_panic)` style tricks, or rebuild
      the test harness with `panic=abort`.
- [ ] OR: per-target rustc_flags override that compiles deps with
      `panic=unwind` only when used by a test target.
- [ ] OR: a `[patch.crates-io]`-style override in MODULE.bazel
      that recompiles the relevant crates with `panic=unwind` in
      the test exec config.

**Trigger**: when an integration test caught something that a
host unit test would have caught faster — currently no incidents.

### Real `TimeProvider` for rustls

`apps/test_tls` uses a `NoTimeProvider` that returns Unix epoch
(0). This works because we don't validate cert expiry on the
server side (we don't auth client certs) and don't issue session
tickets. Required when:

- [ ] We start auth'ing clients (need to validate their cert
      `notBefore` / `notAfter`).
- [ ] We start issuing session tickets (need a real wall clock
      for ticket lifetime).
- [ ] We want to detect our own cert expiring.

Implementation: read CNTVCT_EL0 / TSC, multiply by frequency to get
nanoseconds since boot, add a boot-time wall-clock estimate (PSCI
on aarch64, ACPI/CMOS on x86_64). ~30 lines.

### Sans-io key schedule / hand-rolled handshake (`//net:tls`,
### `//net:tls_handshake`)

We have both `//net:tls` (sans-io key schedule on top of RustCrypto
primitives) AND `rustls`. They overlap. Decision required:

- **Keep both**: `//net:tls` is the key-schedule code QUIC will
  reuse for packet protection (`HKDF-Expand-Label` with QUIC
  labels). `//net:tls_handshake` is useful for low-level debugging /
  interop bring-up. `rustls` is the production handshake.
- **Drop `//net:tls_handshake`** once rustls-over-TCP is in place
  and we don't need a parallel hand-rolled implementation for
  debugging.
- **Drop `//net:tls`** entirely once QUIC is in place and we either
  pull a quinn-proto fork's key schedule or write a minimal HKDF-
  based one inside the QUIC crate.

Default: keep both for now, revisit when QUIC starts.

**Trigger**: at the start of QUIC integration, when we know which
key-schedule API quinn-proto / our fork wants.

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

**Suggested order: 1a -> 1b -> 3a -> 2a -> 2c -> 2b -> 3b -> 3c -> 4 -> 5 -> 2d-h**
(2c before 2b: software distribution works on all platforms without driver changes)

Start with infrastructure (per-protocol targets, crate_universe), then
UDP (simple win), then multi-core in stages: SMP boot first (foundation),
then Tier 1 multi-queue (QEMU), then Tier 2 software distribution (VZ).
QUIC/HTTP3 can leverage multi-core. IPv6 last (cleanest — drops legacy).
Async/await evolution is last (build on proven foundation).
