# Unikernel Next-Gen Roadmap

A cutting-edge, lean unikernel: modern protocols only (QUIC/HTTP3, IPv6),
cooperative multi-core, zero legacy overhead. Each feature is compile-time
optional via Bazel deps — you pick exactly what you need.

## Design Principles

- **The executor IS the kernel**: `async fn` is the *only* execution
  model, not a layer on top of a callback loop. No tokio, no smol, no
  two-layer scheduling. QUIC connections, TLS handshakes, and HTTP
  handlers are all `async fn`s polled directly by the per-core event
  loop. No other Rust stack makes this claim — Tokio/smol run above
  Linux, Embassy is single-threaded microcontroller-tuned, Hermit
  targets libstd. The combination of multi-core + lock-free + no_std
  + async-as-scheduler is the differentiation thesis.
- **QUIC over TCP as structural advantage, not just modernity**: TCP
  has decades of kernel offload (TSO/GSO/kTLS) that a userspace server
  fights against. QUIC is userspace by definition — every byte crosses
  the syscall boundary on Linux. A unikernel eliminates that boundary
  specifically for QUIC. This is the one workload where unikernels
  have a measurable structural advantage on commodity hardware, not
  just a vibes-based one.
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
//crates/net:ethernet         <- always (virtio-net frames)
//crates/net:arp              <- ipv4 needs this
//crates/net:ipv4             <- tcp, udp-over-ipv4
//crates/net:ipv6             <- quic, udp-over-ipv6
//crates/net:ndp              <- ipv6 needs this (replaces ARP)
//crates/net/tcp              <- transport/http needs this
//crates/net:udp              <- quic needs this
//crates/proto/quic       <- transport/http3 needs this (+ tls)
//crates/proto/http       <- HTTP/1.1 server (deps: tcp)
//crates/proto/http3      <- HTTP/3 server (deps: quic)
```

Example apps:
```python
# Modern: HTTP/3 + QUIC + IPv6 (no TCP, no ARP, no IPv4)
rust_library(name = "app", deps = ["//crates/proto/http3"])

# Legacy: HTTP/1.1 + TCP + IPv4
rust_library(name = "app", deps = ["//crates/proto/http"])

# Both: serve HTTP/1.1 and HTTP/3 side by side
rust_library(name = "app", deps = [
    "//crates/proto/http",
    "//crates/proto/http3",
])
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
bazel test //crates/net:types_test //crates/net:protocol_tests  # 21 unit tests (host-native)
bazel test //apps/webserver:test                                # HTTP + UDP echo (QEMU)
```

### 1b. Add crate_universe for crates.io dependencies

Required for pulling in crypto (`ring`), QUIC (`quiche`/`quinn`), etc.

- [x] Add `crate_universe` to MODULE.bazel (annotation-based, no Cargo.toml)
- [x] Verified bitflags resolves and compiles for x86_64-unknown-none
- [x] Fix aarch64-unknown-none platform gap (patched rules_rust triple_mappings.bzl)
- [x] Use a crates.io dep in the unikernel and boot it (bitflags in net/tcp.rs)

**Try it:**
```bash
bazel build --platforms=//bazel/platforms:aarch64_unikernel @crates//:bitflags   # bare-metal aarch64
bazel build --platforms=//bazel/platforms:x86_64_unikernel  @crates//:bitflags   # bare-metal x86_64
```

---

## Phase 2: Multi-Core Event-Driven OS

This is essentially an OS-level async runtime — like tokio, but we ARE
the kernel. No syscalls, no epoll indirection, no context switches.

Every core is a worker. No dedicated cores, no preemption, no scheduler.
Same event loop: poll -> process -> steal -> sleep.

### North Star: async runtime foundation, then QUIC on top

Phase 2a-c shipped a callback-based event loop that scales multi-core
HTTP and TLS. That shape does not scale to QUIC. Every QUIC connection
has N concurrent streams, loss-detection timers, pacing timers, key
updates, and a handshake flight interleaving on one connection state.
Expressing that as callbacks produces the `Arc<Mutex<Connection>>`
mess that quinn and msquic carry around. `async fn` with `.await` is
the clean expression — and the compiler generates the state machine
for free.

**Ordering decision (2026-04-15)**: a minimal async runtime (§2f task
trait + §2g Waker/executor, ~300 LOC together) lands **before** QUIC
(§3c), not after. Rationale:

- Doing QUIC first as a hand-rolled state machine and later retrofitting
  async = rewrite the biggest chunk of code in the repo twice.
- Doing a "complete" async runtime first with no consumer = guess at
  what primitives QUIC needs, build the wrong thing, over-engineer.
- Doing a **minimum** runtime first (spawn, Timer, UdpRecv) and then
  writing QUIC as its first real consumer = runtime evolves to fit
  the workload; no wasted code on either side.

**Scope discipline**: async adoption is opt-in per protocol. The
existing TCP/TLS/HTTP callback path keeps running unchanged. QUIC
uses async from day 1. TCP/TLS/HTTP migrate only if/when there's a
concrete win. This avoids a "port everything" detour blocking QUIC.

Work stealing (§2d), perf regression tests (§2h), and full TCP/HTTP
async migration stay parked until after QUIC is end-to-end.

### Platform compatibility matrix

| Feature | QEMU x86_64 | QEMU aarch64 (TCG) | HVF (macOS arm64) |
|---------|-------------|---------------------|--------------------|
| SMP | Yes (`-smp N`) | Yes (`-smp N`) | Yes (`--cpus N`) |
| Multi-queue | Yes (`mq=on,queues=N`) | Yes (same) | Yes (`num_queue_pairs`) |
| MSI-X | Yes (APIC routing) | Partial (no ITS, use GICv2M) | Yes (GICv3) |
| RSS | Yes (in-QEMU or eBPF) | Yes (same) | Software (host-fd poll per vCPU) |
| Per-core timers | Yes (APIC timer) | Yes (CNTV_EL0) | Yes (CNTV_EL0) |
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
bazel test //apps/test_smp:test_qemu_aarch64   # serial: "core 0 online" .. "core 3 online"
bazel test //apps/test_smp:test_qemu_x86_64    # same on x86_64 QEMU
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
- [x] `bazel run //apps/webserver:webserver`: pass `mq=on,queues=N,vectors=2N+2` when `UNIKERNEL_CPUS > 1`

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
UNIKERNEL_CPUS=4 bazel run //apps/webserver:webserver
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
UNIKERNEL_CPUS=4 bazel test //apps/webserver:test_qemu_aarch64 --test_env=UNIKERNEL_CPUS=4
UNIKERNEL_CPUS=4 bazel test //apps/webserver:test_qemu_x86_64  --test_env=UNIKERNEL_CPUS=4
# Serial: "[net] Tier 2: software distribution (4 cores)"
# UDP multi-core benchmark:
./scripts/bench_udp.sh
```

### 2d. Work stealing — parked (post-QUIC optimization)

Deferred until after QUIC is end-to-end. Work stealing is a
CPU-heavy-task optimization (TLS encrypt, QUIC crypto, compression).
For a webserver where most tasks are connection-bound and short-lived,
RSS flow-hash pinning already distributes load well. Re-evaluate once
QUIC ships and we have a concrete workload showing imbalance.

Data structures are already in tree (deque + SPSC ring), so pulling
this forward later is pure event-loop wiring.

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

### 2f. Task arena + event-loop integration — first cut shipped

Per-core slot arena + `spawn` + event-loop hook. Collapsed with §2g
because using `Future` directly (instead of inventing a separate
`Task` trait with the same shape) is simpler.

- [x] Per-core task slot arena ([kernel/executor.rs](kernel/executor.rs)):
      fixed `[TaskSlot; 64]` per core, slot = `{ ready: AtomicBool,
      used: AtomicBool, future: UnsafeCell<Option<Pin<Box<dyn
      Future<Output=()>>>>> }`. Waker identity = `*const TaskSlot`
      into static `ARENAS`, no `Arc`.
- [x] `spawn<F: Future<Output=()> + 'static>(f: F)` onto current
      core's arena. CAS on `used` serialises spawn; `Err(())` when
      full.
- [x] Event loop integration: [kernel/eventloop.rs](kernel/eventloop.rs)
      calls `executor::tick(core_id)` after `SERVICE` — drains the
      per-core `pending_timers` MPSC into the wheel, advances the
      wheel, then polls every ready slot.
- [ ] `yield_now()` — defer until a concrete user needs it.

**Tests:**
- [x] Integration: [apps/test_async](apps/test_async) green on HVF,
      QEMU aarch64, QEMU x86_64. Spawns an async task that sleeps
      50ms, nested-spawns, sleeps 10ms, shuts down.
- [ ] Unit: arena spawn/free/reclaim semantics (host).

### 2g. Async/await (`Future` + `Waker` + minimal executor) — first cut shipped

Same file as §2f. Enough to write QUIC-flavoured `async fn` for the
primitives QUIC needs; more reactor primitives land as QUIC demands.

- [x] `RawWakerVTable` (clone/wake/wake_by_ref/drop) that flips the
      target slot's `ready` atomic. Waker data = `*const TaskSlot`
      directly, ~20 lines unsafe. Same-core wake is a release store;
      cross-core wake is deferred (sleeping target notices on its
      next `idle_bounded` tick).
- [x] `spawn<F: Future<Output=()> + 'static>(f: F)` boxes the future
      into the per-core arena via the global talc heap.
- [x] Reactor: `Sleep::until(deadline).await` / `sleep_us(us)` —
      parks the task's waker in the per-core timer wheel, cancels
      on `Drop` so a stale fire can't hit a reused slot.
- [x] Reactor: `UdpSocket::recv_from(&mut buf).await`
      (`UdpSocket::run(|sock| async ...)` is the typical entry
      point; bind+spawn-per-worker happen together).
- [x] Reactor: `TcpListener::accept().await` /
      `TcpStream::{recv,send}.await`. `uni_http::listen` migrated
      to async handlers (`AsyncFn(&Request) -> Response`).
- [x] Event loop shim: tick drains the wheel, scans ready slots, calls
      `future.as_mut().poll(&mut cx)`. No change to poll/drain/idle.
- [x] Smoke test: `apps/test_async` — spawn + timer + nested-spawn +
      graceful shutdown. Exercises the full stack.
- [x] Perf: timer wheel fast-paths empty state in
      [kernel/timer.rs](kernel/timer.rs) — first `advance()` after
      boot would otherwise walk ~10⁶ empty ticks (µs-since-boot).

**Explicit non-goals:**
- Porting TCP/TLS/HTTP to async (they work; migrate only if a win).
- `select!`/`join!` macros (QUIC will need concurrent awaits; use
  explicit `poll` on sub-futures until we have a clear pattern).
- `Send + Sync` bounds (per-core affinity is the whole point).
- Async-debugging tooling (stuck-poll diagnostics, task dumps) —
  add when we get burned.
- Cross-core IPI on wake — target core picks up the wake on its next
  `idle_bounded` timer tick; bounded-latency, not zero-latency.

**Tests:**
- [x] Integration: `apps/test_async` end-to-end on HVF + QEMU.
      Native deferred (kernel::executor is bare-metal-only today).
- [ ] Unit (host): Waker clone/wake correctness under miri.
- [ ] Integration: spawn 1000 `Timer::sleep_until` tasks, verify all
      fire within ±1ms of deadline.

**Try it:**
```bash
bazel test //apps/test_async:test_hvf
bazel test //apps/test_async:test_qemu_aarch64 //apps/test_async:test_qemu_x86_64
# Serial: "test_async: task woke up" → "test_async: nested task done"
```

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
bazel test //crates/net:types_test               # unit tests (includes UDP checksum)
bazel test //apps/webserver:test_qemu_x86_64     # HTTP + UDP echo (x86_64)
bazel test //apps/webserver:test_qemu_aarch64    # HTTP + UDP echo (aarch64)
```

### 3b. TLS 1.3 — hand-rolled, sans-io, audited primitives

QUIC mandates TLS 1.3. **Path actually taken** (2026-04-15 pivot
from the original rustls plan): roll our own TLS 1.3 server state
machine on top of the audited RustCrypto primitives (sha2 / hmac /
hkdf / chacha20poly1305 / x25519-dalek / p256). No `rustls`
dependency. Reasons documented in `Cargo.toml`'s big comment
block: rustls's `Vec<u8>` / `Arc<...>` / dyn-trait architecture
is pure overhead under our per-core lock-free model, and
`rustls-rustcrypto 0.0.2-alpha` is explicitly marked "DO NOT USE
IN PRODUCTION." Owning the protocol logic is also the right
shape for QUIC, which reuses HKDF-Expand-Label with different
labels and bypasses rustls's record layer entirely.

Cipher suite shipped: `TLS_CHACHA20_POLY1305_SHA256`. KX:
X25519 only. Server cert: ECDSA P-256 + SHA-256 (ed25519 was
tried first but Chromium-family browsers and macOS LibreSSL
refuse it for server auth — see commit `6cc283a`).

#### What ships

- [x] **cpufeatures / LLVM SIMD-legalisation fix.** Per-crate
      `crate.annotation` in `MODULE.bazel` passes
      `-Ctarget-feature=-soft-float,+sse,+sse2,+sse3,+ssse3,+sse4.1,
       +sse4.2,+avx,+avx2,+aes,+pclmul,+fma,+bmi1,+bmi2`
      to every crypto crate that uses SIMD intrinsics or hits the
      LLVM bailout via `u128` math (aes / aes-gcm / chacha20 /
      chacha20poly1305 / ghash / poly1305 / polyval / p256 /
      primeorder / elliptic-curve / crypto-bigint /
      curve25519-dalek). x86_64-v3 (Haswell, 2013) baseline.
      Unblocks "Do not know how to split the result of this
      operator!" LLVM bailouts (rust-lang/rust#87642, #92760,
      #136544).
- [x] **`chacha20_force_soft` / `poly1305_force_soft`** annotations
      for those two crates only. Their x86 SIMD backends produce
      incorrect output on `x86_64-unknown-none` (caught by a
      `aead_rfc8439_known_answer` test in `apps/test_tls`). The
      software backends are audited constant-time Rust and ~3-5x
      slower; well worth the cost for correctness. aarch64
      unaffected. Filed under "investigate when we next bump
      chacha20/poly1305 versions."
- [x] **x86_64 boot CR4 / XCR0 setup.** `boot/x86_64/boot.S`,
      `ap_boot.S`, and `limine_entry.rs` set `OSFXSR | OSXMMEXCPT`
      unconditionally and gate `OSXSAVE | XSETBV` behind
      `CPUID.01h:ECX.XSAVE`. Without this, p256's d*G scalar
      multiplication at `TlsServerConfig` init time `#UD`-trapped
      on `qemu64` and even on real KVM `-cpu host` because we
      compile with `+avx,+avx2`. CPUID-safe so the same kernel
      still boots on pre-XSAVE CPU models.
- [x] **RustCrypto primitives** via crate_universe: `sha2`, `hmac`,
      `hkdf`, `chacha20poly1305`, `chacha20`, `poly1305`,
      `x25519-dalek`, `p256`, `rand_core`, `getrandom`. All build
      on `x86_64-unknown-none`, `aarch64-unknown-none`, and the
      hosted native targets after the fixes above. ed25519-dalek
      was dropped when the dev cert switched to P-256.
- [x] **`kernel::rng`** — kernel-backed RNG providing
      `fill_bytes(&mut [u8])`. Seed = 256 cycle-counter reads
      (TSC / CNTVCT_EL0) + best-effort `RDRAND` mix-in, hashed
      through SHA-256 with a domain-separation tag. Expansion via a
      single ChaCha20 stream cipher keyed from the seed.
      Registered as the `getrandom 0.2` custom backend so every
      `rand_core::OsRng` consumer works without a syscall.
- [x] **`#[global_allocator]`** in `kernel::mm::GLOBAL_ALLOCATOR`
      forwarding to `kmalloc`/`kfree`. Native (POSIX) builds get a
      ~30-line `LibcAllocator` shim in `bazel/rules/native_main.rs`
      so the same TLS code links against `malloc`/`free`/
      `posix_memalign` on hosted targets.
- [x] **`//net:tls_crypto`** — thin byte-slice wrapper over
      `chacha20poly1305::ChaCha20Poly1305`. Hides `generic-array`
      types from downstream callers; one place to negotiate the
      AEAD if QUIC later picks a different suite.
- [x] **`//net:tls`** — sans-io key schedule + transcript hashing:
      `HKDF-Expand-Label`, `Derive-Secret`, `Transcript` (running
      SHA-256 with snapshots), `TrafficKey` (seal/open with per-seq
      nonce from RFC 8446 §5.3), `KeySchedule` walking early →
      handshake → application stages, `X25519ServerKey` for KX.
      Will be reused by QUIC for its packet-protection key
      derivation (same HKDF-Expand-Label cascade with different
      labels per RFC 9001 §5).
- [x] **`//net:tls_handshake`** — handshake message framing,
      strict `ClientHello` parser (supported_versions,
      supported_groups, signature_algorithms, key_share),
      builders for `ServerHello` / `EncryptedExtensions` /
      `Certificate` / `CertificateVerify` / `Finished`, plus the
      "TLS 1.3, server CertificateVerify" sign-content helper.
      Pure byte-slice parsing/encoding, no crypto, host-testable.
- [x] **`//net:tls_record`** — record layer: AEAD seal/open with a
      `TrafficKey` (per-record nonce, AAD = record header).
      Zero allocation, fixed-size buffers.
- [x] **`//net:tls_server`** — full TLS 1.3 server state machine
      gluing it all together. `WaitClientHello` →
      `WaitClientFinished` → `Established` → `Closed`. Drives
      `do_client_hello` (parse CH → emit SH + CCS + sealed
      EncExt/Cert/CertVerify/Finished), `do_client_finished`
      (drain CCS, decrypt+verify Finished), `do_app_data`
      (decrypt → app, encrypt → client). Caches a pre-built
      `SigningKey` in `TlsServerConfig` to avoid re-running `d*G`
      per handshake (1.9× speedup, commit `532ac16`). Compiles
      and runs on both bare-metal and hosted targets — same code
      backs the unikernel and the `webserver_native` binary.
- [x] **Per-stage handshake profiler** (`net::tls_server::profile`).
      Always-on cycle-counter accumulator with 10 stages (Parse /
      ServerHello / Ecdhe / HkdfHs / EncExt / Cert / CvSign /
      CvSeal / Finished / HkdfAp). `report()` formats a plain-text
      dump (total_us / mean_ns / worst_ns / pct columns) which
      the webserver exposes at `GET /tls_profile`. Reset via
      `GET /tls_profile_reset`. Inlines a single-instruction
      `now_cycles()` (`rdtsc` / `mrs cntvct_el0`) so per-stage
      sampling is ~25 ns total per handshake.
- [x] **`close_notify`** RFC 8446 §6.1 alert on connection close
      so OpenSSL clients don't log "unexpected eof" on every
      response. Sealed under the current server application
      traffic key, then TCP FIN.
- [x] **Dual HTTP + HTTPS listeners** on a single `Server`.
      `server.listen(80); server.listen_tls(443, &cfg);`
      shares routes and state across both. Pattern matches
      Actix's `bind()` / `bind_rustls()`.
- [x] **TCP fixes for the handshake hot path**:
      `TCP_NODELAY` on `accept()` in the native backend +
      immediate ACK in the unikernel TCP stack instead of
      deferred-piggyback (commit `b98b3e1`). The Nagle + Linux
      delayed-ACK interaction was capping `tls_handshake_max` at
      ~20 hs/s on GCP KVM; after the fix the same bench reports
      ~1612 hs/s 1c → 2703 hs/s 3c.
- [x] **HVF runner inline accept + flow-hash steering**
      (commits `d98307e`, `d7b113a`). Removed the dedicated TCP
      accept thread in `tools/hvf-runner` so per-vCPU `vcpu_poll`
      drains listen fds inline. ~2× handshake rate at HVF 2c.
- [x] **Native (POSIX) TLS** — same `//net:tls_server` runs on
      `webserver_native`. Removed `//kernel` dep from
      `//net:tls_server`; native uses libc `getentropy` for
      ephemeral seeds, `core::arch::asm!` for cycle counters
      (commit `fe66ae6`). Allows apples-to-apples bench
      comparisons of HVF vs native on the same TLS code.
- [x] **Pre-generated dev cert**:
      `apps/webserver/dev_certs/dev_cert.{der,pem}` +
      `dev_key.{der,pem}` (ECDSA P-256 + SHA-256, 10y validity,
      SAN covers `unikernel.local` / `localhost` / `127.0.0.1` /
      `10.0.2.15`). DER for `include_bytes!()`, PEM for host-side
      `curl --cacert` / `openssl s_client`. Regen via
      `dev_certs/regen.sh`.
- [x] **`//apps/test_tls`** — in-kernel integration test. Boots
      via HVF / QEMU TCG / KVM, runs **12 stages** end-to-end:
      `aead_roundtrip`, `aead_tamper_detect`,
      `aead_roundtrip_large` (600-byte multi-block AEAD path),
      `aead_rfc8439_known_answer` (RFC 8439 §2.8.2 byte-pinned
      ct + tag), `x25519_roundtrip`, `hkdf_expand_label`,
      `key_schedule_cascade`, `traffic_key_record`,
      `traffic_key_per_seq_nonce`, `kernel_rng_fill_bytes`,
      `rfc8448_handshake_secrets`, `rfc8448_application_secrets`
      (RFC 8448 §3 known-answer for the full key cascade).
      **All 12 pass on aarch64 HVF and x86_64 TCG / KVM.**
- [x] **Bench coverage**: `health_tls_c1` (1 keep-alive conn,
      record-layer hot path), `health_tls_max`
      (`32 × cpus` keep-alive conns), `tls_handshake_max`
      (4 × cpus client workers via Python multiprocessing,
      fresh handshake per request, SO_LINGER=0 + warmup +
      stable rate window). Workloads work on QEMU TCG / KVM /
      HVF / native via `bench.py`, including remote runs via
      `gcp-bench.sh`.
- [x] **External-client interop**: handshake completes against
      `curl` (LibreSSL 3.3.6), `openssl s_client -tls1_3 -brief`
      (OpenSSL 3.x), and Python `ssl` (TLS 1.3 enforced via
      `ctx.minimum_version = TLSv1_3`). Verified on aarch64 HVF,
      x86_64 KVM (GCP), x86_64 TCG (macOS), and native macOS /
      Linux.

**Try it:**
```bash
# In-kernel integration test (12 primitives + RFC vectors)
bazel test //apps/test_tls:test_hvf
# Serial: "TLS TESTS: ALL PASSED"

# Live TLS server on the unikernel
bazel run //apps/webserver:webserver_native    # native (POSIX)
bazel run //apps/webserver:webserver_hvf       # HVF arm64
curl -k https://localhost:8443/health
echo | openssl s_client -connect localhost:8443 -tls1_3 -brief

# Per-stage handshake profile after a few connections
curl -sk https://localhost:8443/tls_profile

# Bench (single-host)
python3 scripts/bench.py --env hvf,native --cores 1,2,3 \
    --workload health_tls_c1,health_tls_max,tls_handshake_max

# Bench (remote GCP KVM)
./scripts/gcp-bench.sh --env kvm,native --cores 1,2,3
```

#### Still to do (deferred TLS work)

- [ ] **Session resumption** (PSK + session tickets, RFC 8446
      §2.2). Skips the entire ECDSA sign + Certificate flight on
      resumed connections; ~7× handshake-rate win on resumed
      vs fresh. Roughly a day of state-machine work — the
      profiler already pinpoints `cv_sign` at ~70 % of handshake
      time, so this is the next big lever before QUIC. Tracked
      separately in "Deferred work" below.
- [ ] **Faster ECDSA P-256** — pure-Rust `p256` is the bottleneck
      after the SigningKey cache fix. Options: switch to
      `fiat-p256` (formally verified, ~2× faster, no C deps),
      or eat the build-system pain of `ring` (asm, ~5-10×
      faster). Re-evaluate once session resumption is in place;
      it might not matter.
- [ ] **AES-128-GCM** as a second cipher suite. Not strictly
      needed (every modern client supports ChaCha20-Poly1305),
      but would let us exercise PMULL on aarch64 and AES-NI on
      x86_64 if a peak-throughput workload ever demands it.

### 3c. QUIC implementation — roll our own on `//net:tls_server` + the async runtime

**Status (2026-04-15)**: not started, gated on Phase 2f+2g (the async
runtime foundation — see "North Star" at the top of Phase 2). Phase
3b shipped the TLS 1.3 prereq. QUIC will be the **first real consumer
of the async runtime** — each connection is an `async fn handle_quic(
conn: QuicConn)` with `.await` on UDP recv, stream readable, and
loss/pacing timers. This is exactly the design QUIC was shaped for,
and it's why we're going async-first rather than writing QUIC as yet
another hand-rolled state machine on top of a callback loop.

Decision: roll our own QUIC implementation. We're not going to
ship parity with quinn — the 9000-series RFCs add up to ~600
pages of state machine — but every off-the-shelf option is
a worse fit than what we can write specifically for our
per-core lock-free event loop.

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

**Why own-QUIC fits this unikernel better than any of the above.**

The general-purpose QUIC implementations (quinn, quiche, s2n-quic,
neqo) all carry design assumptions that are actively wrong for a
unikernel with cooperative per-core event loops:

- They assume **preemptive threading** and wrap connection state in
  `Arc<Mutex<...>>` so it can migrate between worker threads. We
  already pin every TCP/UDP connection to a single core via flow
  hash (`net/lib.rs:flow_hash` → `poll_tier1` / `poll_tier2`), so
  the `Arc<Mutex<>>` is pure overhead.
- They assume **generic async runtimes** (tokio, futures) and box
  every future so it can be `.await`-ed from any executor. Our
  event loop already owns the connection; we can call the state
  machine inline from the poll callback with no indirection.
- They assume **abstracted I/O** via sans-io buffer APIs because
  they have to be portable to `epoll` / `kqueue` / `io_uring` /
  Windows IOCP. We have exactly one I/O backend (virtio-net RX/TX
  queues for the unikernel, libc sockets for native) and we own
  it end-to-end.
- They assume **general-purpose crypto provider indirection** (the
  `rustls::CryptoProvider` trait, quinn's `ClientConfig` /
  `ServerConfig` boxes). We ship exactly one cipher suite
  (`TLS_CHACHA20_POLY1305_SHA256`) and one kx group (X25519), so
  we call `chacha20poly1305_seal` / `open` directly via
  `//net:tls_crypto`.

Our purpose-built QUIC implementation can:

- Store connection state inline in a per-core connection pool,
  same pattern as `//net:tcp` (per-core `[ConnSlot; N]` arrays,
  flow-hash-routed, no shared mutexes).
- Drive the state machine from `net::poll()` at the exact moment
  a UDP datagram arrives, on the owning core, with zero cross-core
  traffic for the hot path.
- Integrate directly with our event loop's NAPI-style idle/wake
  (WFI + RX interrupt) — "async" isn't a layer, it's the one and
  only execution model.
- Share record-layer code with the existing TLS-over-TCP path
  (`//net:tls_crypto`'s `chacha20poly1305_seal`/`open`), since
  QUIC packet protection is the same AEAD after the handshake.
- **Reuse `//net:tls_server` for the TLS handshake.** It's
  already sans-io and exposes traffic secrets at well-defined
  state transitions (handshake_secret / application_secret).
  We add a "QUIC mode" that wraps the TLS handshake messages in
  CRYPTO frames instead of TLS records, and surfaces the
  derived secrets to the QUIC packet-protection layer. Same key
  schedule, same code paths — no second TLS implementation.

The trade-off is surface area. Scope discipline is critical:

**In scope (v1):**
- TLS 1.3 handshake driven by `//net:tls_server` over QUIC
  CRYPTO frames (extracts handshake / application traffic
  secrets at the state-machine boundaries we already mark in
  `do_client_hello` / `do_client_finished`)
- Initial / Handshake / 1-RTT packet number spaces
- STREAM frames (server-initiated only initially)
- ACK, CONNECTION_CLOSE, PING
- Loss detection with fixed RTO (not pacing/BBR)
- Server-side 1-RTT key update

**Out of scope (v1):**
- 0-RTT
- Connection migration
- Path validation / PMTUD
- Datagram extension
- Version negotiation
- Retry tokens
- ECN
- Qlog tracing
- Client-side (we're a server)

**Tasks (live):**

- [x] **Prerequisite: §2f + §2g async runtime foundation.** QUIC
      connections will be `async fn` from day 1 — they `.await`
      UDP recv, timer fire, and stream readable. Done: runtime
      foundation + `UdpSocket::run` / `TcpListener::run` /
      `Sleep::until` reactors green on both backends.
- [ ] **`//net:tls_server` "QUIC mode"** — extension of the
      existing state machine that emits handshake messages as
      raw bytes (no TLS record framing) for QUIC's CRYPTO
      frames, and exposes the derived traffic secrets to the
      caller at the same state transitions we already use
      internally. ~150 lines of glue, no new TLS logic.
- [ ] **`//net:quic_wire`** — QUIC long/short header parsing,
      packet number decoding, variable-length integers (RFC 9000
      §16-17). Self-contained parsing, host-testable.
- [ ] **`//net:quic_crypto`** — packet protection using
      `//net:tls_crypto`'s AEAD + `//net:tls`'s
      `HKDF-Expand-Label`. QUIC reuses the same key cascade with
      different labels (RFC 9001 §5); we already have it.
- [ ] **`//net:quic`** — connection state machine, Initial →
      Handshake → 1-RTT progression, STREAM/ACK frame handling.
      Per-core connection pool indexed by Connection ID.
- [ ] **`//uni:http3`** — HTTP/3 over QUIC streams
      (HEADERS + DATA frames, static QPACK table only).
- [ ] **External-client interop**: `curl --http3 --cacert
      dev_cert.pem https://unikernel.local:8443/health`
      succeeds. Acceptance test for "QUIC works."

**Fallback**: if the own-QUIC implementation stalls (complexity or
scope creep), the Hermit / libstd option in "Deferred work" is the
escape hatch. It unlocks `quinn-proto` unchanged at the cost of the
bazel+nightly migration.

---

## Phase 4: HTTP/3 — shipped

### 4a. QPACK header compression — done

Static-only QPACK in `//uni-http3/src/qpack.rs`, with the 99-entry
static table from RFC 9204 Appendix A in `static_table.rs`. Encoder
picks the smallest legal representation per field
(indexed → name-ref → literal-name); decoder handles all three plus
Huffman-coded values via `huffman.rs` (RFC 7541 Appendix B static
code).

- [x] QPACK static-table encoder + decoder
- [x] Skip dynamic table (`SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`)
- [x] Huffman decode (RFC 7541 known-answer tests pass)

### 4b. HTTP/3 frame parsing — done

`//uni-http3/src/frame.rs`. DATA / HEADERS / SETTINGS / GOAWAY
parsed; reserved frame types parse to `Skipped { ty }` and consume
their announced length so callers don't choke on grease frames.

- [x] H3 frame parser (DATA, HEADERS, SETTINGS, GOAWAY)
- [x] H3 frame builder (`write_frame` + `write_empty_settings`)
- [x] Unit: H3 frame parse/build round-trip

### 4c. //uni-http3 module — done

Mirrors `//uni-http`'s `listen(port, handler)` shape, not the
`route + run` shape originally sketched: the app keeps **one**
`AsyncFn(&Request) -> Response` closure that serves HTTP/1.1,
HTTPS/1.1 and HTTP/3 simultaneously — see `apps/webserver/src/main.rs`.

- [x] `//uni-http3` Bazel target (deps: //uni-http, //uni-quic)
- [x] H3Server: control stream + per-request stream dispatch
- [x] Request/response over QUIC bidi streams; QPACK encode + decode
- [x] `apps/webserver` serves HTTP/3 alongside HTTP/1.1 + HTTPS
- [x] Alt-Svc auto-emitted from HTTPS responses **only when** H3
      successfully bound (avoids poisoning browser alt-svc cache)
- [x] Integration: GET / + /health + /xyz over HTTP/3 verified via
      aioquic (`scripts/test_helpers.h3_get`) and curl/ngtcp2

**Try it (works today):**
```bash
$(brew --prefix curl)/bin/curl --http3-only -k \
    https://127.0.0.1:8443/health
# {"status":"ok","runtime":"unikernel","version":"0.1.0"}
```

---

## Phase 5: IPv6 + NDP

The "drop IPv4/ARP" framing in the original roadmap is an
end-state aspiration; in practice the unikernel runs in
environments where the HVF runner / GCE / Docker still default
to IPv4 NAT, so the working build is dual-stack with a path to
v6-only when deployment substrates support it.

### 5a. IPv6 (net/ipv6.rs) — done

Pure wire-format crate `//net:ipv6` (host-testable as a leaf — no
ethernet/driver dep). 40-byte fixed header, no checksum, no IHL.
`ipv6_build` / `ipv6_receive` + `pseudo_checksum` for the L4
upper layers.

- [x] IPv6 header parse + build
- [x] `Ipv6Addr` type with EUI-64, solicited-node, multicast-MAC
      helpers (RFC 4291 + RFC 2464)
- [x] Pseudo-header checksum (RFC 8200 §8.1)
- [x] Unit tests: build/parse round-trip, version + truncation
      rejection, checksum verification
- [ ] End-to-end ping6 — needs HVF runner IPv6 packet relay
      (tooling work in `tools/hvf-runner`); QEMU bridged net
      already exercises this path on Linux

### 5b. NDP — Neighbor Discovery Protocol — done (parsers + service)

`//net:icmpv6` covers ICMPv6 + NDP wire format; `//net:net`
handles inbound NS/RA/Echo on the BSP. `//net:ndp` was renamed
`//net:icmpv6` to reflect that the same module covers Echo
Request/Reply alongside the NDP messages — they all share the
ICMPv6 framing + pseudo-checksum.

- [x] Neighbor Solicitation/Advertisement (build + parse + reply)
- [x] Router Solicitation (sent at bring-up to ff02::2)
- [x] Router Advertisement parsing (drives SLAAC)
- [x] Echo Request/Reply (replies to ping6)
- [x] `//net:icmpv6` Bazel target (deps: ipv6, types)
- [x] Unit tests: NA layout + flags, NS round-trip, RA prefix
      extraction, Echo Reply checksum verification
- [ ] Outbound NDP cache for server-initiated unicast IPv6 —
      not needed for receive-path replies (we reuse the inbound
      Ethernet src MAC); becomes necessary once dual-stack TCP /
      UDP land

### 5c. Stateless autoconfiguration (SLAAC) — done

Builds a global IPv6 address from a Router Advertisement's
Prefix Information option + the EUI-64 interface ID. Logs:

    [net] ipv6 link-local fe80::5054:ff:fe12:3456
    [net] ipv6 SLAAC: configured 2001:0db8:0000:0000::5054:ff:fe12:3456

- [x] SLAAC address generation from MAC + router prefix
- [x] Router Advertisement processing (single-prefix MVP — first
      RA with `A=1` and `prefix_length == 64` wins)
- [x] Unit test: SLAAC happy path via parsed RA + prefix
- [ ] Multi-prefix tracking (multiple globals) — future expansion

### 5d. Dual-stack TCP / UDP — done (sockets layer)

End-to-end: an inbound TCP/UDP packet — v4 or v6 — flows
through the same TCB pool, hash table, runtime reactor, and
user handler. The HVF runner still only relays IPv4, so the v6
path isn't exercised on macOS today, but a deployment with v6
L2 connectivity (QEMU bridged net, GCE with v6 enabled) gets
v6 sockets without any further code changes.

- [x] `IpAddr::{V4, V6}` enum + `tcp_checksum_v6` /
      `tcp_checksum_any` family-dispatched checksums
      (`net/types.rs`).
- [x] `//net:ndp` — Spinlock'd MAC cache mirroring `:arp`,
      populated by receive-path snoops; FIFO eviction.
- [x] `//net:ipv6_send` — `ipv6_send` (NDP-resolves dst MAC,
      drops on miss) + `ipv6_send_to_mac` (response-path
      bypass). Both build the v6 header via `:ipv6` and ship via
      `ethernet_send`. Replaces the bespoke helpers `net/lib.rs`
      had.
- [x] `TcpConnection.remote_ip / local_ip: IpAddr`,
      `tcp_hash_key` folds v6 octets to 32 bits + sets a
      family-disjoint bit, `send_segment` / `send_rst`
      dispatch via `ipv4_send` / `ipv6_send::ipv6_send`.
      `tcp_receive(src: IpAddr, dst: IpAddr, ...)` is the
      single entry point.
- [x] `udp::udp_receive(src: IpAddr, dst: IpAddr, ...)` +
      `send_to_addr(IpAddr, ...)`. The `UdpBackend` vtable's
      `send` now takes `IpAddr` so the bare-metal and native
      backends share one signature.
- [x] `uni-runtime::ip` re-export of `net_types::{IpAddr,
      Ipv4Addr, Ipv6Addr}`. `UdpSocket::send_to(IpAddr, ...)`,
      `recv_from() -> (IpAddr, u16, usize)`,
      `UdpClient::connect(IpAddr, ...)`,
      `peer() -> (IpAddr, u16)`, plus the in-place / try-recv
      flavours. `deliver_udp(port, src: IpAddr, ...)`.
- [x] `net/lib.rs` `ipv6_receive_frame` dispatches `next_header
      ∈ {TCP, UDP}` into the L4 entry points with `IpAddr::V6`.
      ARP-snoop-on-receive's IPv6 counterpart `ndp_learn` runs
      on every inbound v6 frame.
- [x] `apps/webserver` (UDP echo, gateway), `uni-quic`
      (`Datagram.src_ip`, `peer_ip` Cell), DHCP (`BROADCAST_IP`
      + `handle_reply`), and native backend (`udp_send`,
      `deliver_udp`) all updated to `IpAddr`. v6 destinations
      drop in the native backend (host-side test runner is
      IPv4-only).

End-to-end regression after the refactor: HTTPS GET, curl
`--http3` GET, and UDP echo all still return 200/OK against
the running unikernel; 16-test suite green; bare-metal builds
(arm64 + x86_64) clean.

**Outstanding follow-ups:**

- [x] Active Neighbor Solicitation when the NDP cache misses
      on outbound unicast — `ipv6_send` now fires an NS to the
      destination's solicited-node multicast on miss, then drops
      the original (TCP retransmit / UDP best-effort handles the
      retry once the NA arrives). Mirrors `ipv4_send`'s ARP-miss
      behaviour line for line.

### 5e. HVF runner IPv6 — done (modulo SLAAC RA)

Unikernel-side IPv6 (Phase 5a–5d) plus the runner-side AF_INET6
socket bridge for TCP and UDP. End-to-end verified via
`apps/webserver/test.py` (`test_http_health_v6`,
`test_https_health_v6`, `test_udp_echo_v6`) and
`curl -6 https://[::1]:18443/health`.

- [x] `0x86dd` arm in `handle_guest_tx`. IPv6 frames are no
      longer dropped at the runner.
- [x] `GW_IPV6` constant — gateway's link-local, derived from
      `GW_MAC` via modified EUI-64. Same convention as the
      kernel uses for its own LL.
- [x] NDP responder. When the VM solicits `GW_IPV6` (which it
      does as soon as a TCP/UDP send tries to resolve the
      gateway), the runner replies with NA carrying `GW_MAC`.
      Mirrors `handle_arp` for v4.
- [x] ICMPv6 Echo bouncer. `ping6 fe80::a8bb:ccff:fedd:eeff`
      from inside the VM gets replies — exercises the kernel's
      Echo Reply path end-to-end without needing a real peer.
- [x] **AF_INET6 socket-bridge for TCP / UDP.** `bind_listen_v6`
      / `open_udp_sibling_v6` open a parallel `[::1]:host_port`
      socket per `-p tcp:` / `-p udp:` mapping with
      `IPV6_V6ONLY=1`. The single shared `IpFamily` tag rides
      through `TcpListen` → `ProxyConn` and `UdpRelay`, so
      reply frames go through the v6 frame builders
      (`build_tcp_frame_v6_fixed`, `build_udp_frame_v6`,
      `write_tcp_frame_v6_around_payload`) automatically.
- [ ] Optional: emit unsolicited Router Advertisement so the
      VM picks up a SLAAC global. Without this the SLAAC code
      path stays cold in HVF deployments (it works in real LAN
      / QEMU bridged scenarios where a router actually sends
      RAs).

**Try it (today, after Phase 5a–5c):**
```bash
# Boot logs:
[net] ipv6 link-local fe80::5054:ff:fe12:3456
# After RA arrival on a network with `radvd`:
[net] ipv6 SLAAC: configured <prefix>::5054:ff:fe12:3456

# `ping6 <unikernel-ll>` works once the HVF runner relays IPv6
# (or against a QEMU bridged-net deployment today).
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
- [ ] Verify `bazel test --test_tag_filters=qemu_x86_64 //...` still passes.

**Trigger**: when the per-crate annotation list has more than 10-12
crates, or when adding a crate requires a third "look up which
intrinsic is failing" debugging session.

### Session resumption (TLS 1.3 PSK + session tickets)

Profiler shows `cv_sign` (ECDSA P-256 sign) at ~70 % of
handshake wall time on every platform. Session resumption
(RFC 8446 §2.2) skips the entire signature path on resumed
connections — the server just HMACs a PSK binder and
re-derives the key schedule. Resumed handshakes drop from
~226 µs → ~30 µs (~7×).

Implementation cost: moderate. Roughly one focused day:

- [ ] `NewSessionTicket` post-handshake message: encrypt
      `(resumption_master_secret, ticket_age_add, max_early_data,
      issued_at)` under a server-held ticket key, ship to client.
- [ ] `pre_shared_key` extension parsing in `ClientHello`:
      decrypt the ticket, validate freshness, validate the PSK
      binder HMAC.
- [ ] State-machine branch in `do_client_hello`: if PSK accepted,
      skip Certificate + CertificateVerify in the server flight
      and derive the application traffic secrets from the PSK
      instead of from a fresh ECDHE.
- [ ] Ticket key rotation. For dev cert / test purposes a static
      key is fine; production needs a rotating keyring with
      old-key acceptance window so tickets survive key rolls.
- [ ] Bench: extend `tls_handshake_max` to optionally reuse
      a session, or add `tls_resume_max` as a separate workload.

**Trigger**: before QUIC if we want resumed-connection latency
on the TLS-over-TCP path. After QUIC if we want it on the QUIC
path too (QUIC reuses TLS 1.3 tickets with QUIC-specific
extensions, RFC 9001 §4.6).

### Faster ECDSA P-256

After session resumption, the next cv_sign optimisation lever is
swapping the `p256` crate for something faster. Options:

- [ ] **`fiat-p256`**: formally verified, hand-optimised pure
      Rust. ~2× faster than stock `p256`. Cleanest build, no C
      deps. Requires API wrapping for our ECDSA + signature DER
      surface.
- [ ] **`ring`**: assembly P-256 (BoringSSL provenance), 5-10×
      faster. Big build-system pain — `ring`'s `.S` files +
      perl-based pipeline + cc-rs interactions don't love
      bazel-on-`*-unknown-none`. Same toolchain wrapper issues we
      hit trying to enable sha2-asm.
- [ ] **Custom NEON / AVX P-256 field arithmetic**: weeks of
      work, not justified for a hobby kernel.

**Trigger**: when session resumption is in place and we want the
cold-handshake number to come down further too.

### TLS panic-strategy host unit tests

`rust_test` on a crate with external deps (sha2, hmac, hkdf,
chacha20poly1305, p256, ...) fails to build because the deps are
compiled with `-Cpanic=abort` (kernel global policy via
`.bazelrc`'s `extra_rustc_flags`) but the test harness needs
`-Cpanic=unwind`. Currently, `//net:tls`, `//net:tls_crypto`,
`//net:tls_record`, `//net:tls_server`, and `//net:tcp` cannot
have host-native unit tests. Coverage lives in bare-metal
integration tests like `//apps/test_tls` (12 stages including
RFC 8439 AEAD known-answer and RFC 8448 §3 key-schedule
known-answer vectors).

- [ ] Investigate per-target rustc_flags override that compiles
      deps with `panic=unwind` only when used by a test target.
- [ ] OR: a `[patch.crates-io]`-style override in MODULE.bazel
      that recompiles the relevant crates with `panic=unwind` in
      the test exec config.

**Trigger**: when an integration test caught something that a
host unit test would have caught faster — currently no incidents
(the RFC 8448 / RFC 8439 known-answer vectors in `//apps/test_tls`
catch correctness bugs at boot, including the recent
`x86_64-unknown-none` ChaCha20/Poly1305 SIMD codegen bug).

### Real wall-clock time source

We don't currently expose wall-clock time anywhere in the
kernel. Cycle counters (TSC / CNTVCT_EL0) give monotonic ticks
since boot via `kernel::time::now_cycles()` — enough for the
TLS profiler and any future loss-detection RTO timer in QUIC,
but not for anything that needs an absolute "what time is it":

- [ ] Cert `notBefore` / `notAfter` validation (only matters
      when we add client cert auth, which we don't have).
- [ ] Session ticket lifetimes (matters when session resumption
      lands).
- [ ] Detecting our own cert expiring at boot.
- [ ] QUIC's `key_update` interval guidance (RFC 9001 §6).

Implementation: read CNTVCT_EL0 / TSC, multiply by frequency to
get nanoseconds since boot, add a boot-time wall-clock estimate
(PSCI on aarch64, ACPI/CMOS on x86_64). ~30 lines.

**Trigger**: when session resumption or QUIC needs it.

### Option: switch to `x86_64-unknown-hermit` to unlock full libstd

Parked as a viable-but-not-chosen pivot (2026-04-14 spike). The idea:
target `x86_64-unknown-hermit` / `aarch64-unknown-hermit` instead of
`*-unknown-none`, build std from source via `-Z build-std`, supply
the `sys_*` C-ABI symbols that `hermit-abi` declares from a tiny
in-kernel shim. Unlocks full libstd including `rustls::ServerConnection`,
`quinn-proto` unchanged, `parking_lot`, `tracing`, `std::time::Instant`,
`std::io::Error`, and every other std-gated crate.

**Spike findings (`/tmp/hermit_spike/`, throwaway cargo project):**

- Builds a binary linking `rustls 0.23.38` + `rustls-rustcrypto 0.0.2-alpha`
  + `quinn-proto 0.11.14` + all RustCrypto AEADs + all of std in
  ~40s from a clean cache on nightly rustc. Final ELF is 862 KB,
  597 KB of `.text`, zero undefined symbols.
- **Exactly 16 `sys_*` / libc symbols** need implementing, and the
  list does NOT grow when rustls or quinn-proto are added to the
  graph — they're fully covered by Instant + Mutex + RwLock + heap
  + stdout paths that hello-world already exercises:
  - libc: `memcpy`, `memmove`, `memset`, `memcmp`, `strlen`
  - allocator: `sys_malloc`, `sys_free`, `sys_realloc`
  - time: `sys_clock_gettime`
  - random: `sys_read_entropy`
  - futex: `sys_futex_wait`, `sys_futex_wake`
  - i/o + lifecycle: `sys_write`, `sys_writev`, `sys_exit`, `sys_abort`
- **Bonus**: the cpufeatures/LLVM SIMD-legalisation issue disappears
  entirely. The hermit target spec already has `+sse,+sse2,+avx,+avx2,...`
  in its baseline, so `polyval`/`poly1305`/`chacha20` AVX2 intrinsics
  compile without any per-crate annotations. We'd delete the
  `X86_CRYPTO_FEATURES` block from `MODULE.bazel`.
- **Measured effort for the shim**: ~220 lines of Rust forwarding to
  our existing `kernel::mm::kmalloc/kfree`, `kernel::rng::fill_bytes`,
  `kernel::serial`, and `kernel::arch::shutdown`. Futex is the only
  non-trivial piece (~50 lines using SEV/WFE on aarch64, IPI on
  x86_64). **~1-2 days** of focused code, not 2-4 weeks.

**The remaining unknown is bazel + `-Z build-std` integration**.
`rules_rust` supports `build_std` via an experimental attribute but
the ergonomics of mixing a nightly toolchain into our existing
stable-pinned bazel workspace are not measured. Estimated a few
more days.

**Why we're NOT doing this right now:** the user prefers to
prototype our own QUIC implementation on top of the existing
`#![no_std]` stack (`//net:tls_server` + our own `net::tcp` /
`net::udp`), treating Hermit as a fallback if the own-QUIC path
stalls. Note also that since the Hermit spike was run, we
dropped rustls + rustls-rustcrypto entirely (commit `110cd0a`)
and shipped a hand-rolled `//net:tls_server` instead — so the
"Hermit unlocks rustls" framing is less compelling than it was
in April 2026. The remaining draw is `quinn-proto` unchanged.

Revisit Hermit if: (a) we hit an ecosystem wall that requires
std (`thiserror`, `tracing`, `parking_lot`, `tokio`, …),
(b) the bazel+nightly cost seems worth the ecosystem unlock, or
(c) the own-QUIC work is too slow.

**Trigger for revisit**: any of the three above.

### Cooperative-drain shutdown phase

Today's `shutdown_and_drop` (in `uni/src/lib.rs`) is force-abort:
listeners drop → `drain_all_arenas` force-drops every live future
→ `shutdown_all_tcp` RSTs every active conn → power off. Clean (the
`HEAP_LEAK_CHECK ok` test in `apps/webserver:test_hvf` proves
zero-leak under traffic) but it truncates in-flight work — a
handler half-way through `stream.send(...)` gets force-dropped and
the peer sees RST mid-response.

A cleanest design adds a *cooperative drain phase* before the
forced abort:

- [ ] Per-listener "stop accepting" flag — listener's accept future
      resolves to a sentinel that callers treat as graceful close.
- [ ] Bounded drain window (~1-2 s configurable). Cores keep
      ticking so in-flight handler tasks complete naturally;
      `shutdown_and_drop` waits for `has_pending(worker_id)` to go
      false on every worker, with deadline.
- [ ] Explicit multi-core barrier. Today the BSP trusts that APs
      are past their eventloop break by the time `on_shutdown`
      runs (relies on the post-loop `spin_loop()`). A real barrier
      (atomic counter + per-core "drained" ack) would make the
      contract explicit.
- [ ] Idempotent shutdown. `shutdown_and_drop` should tolerate
      being called twice (e.g., signal racing the boot completion).

**Trigger**: when traffic patterns include long-running RPCs we
don't want to truncate (current workloads — HTTP/1.1 ~ms-scale —
don't stress this). QUIC streams will benefit since clean
CONNECTION_CLOSE is preferred over UDP-level forget.

### Lift `net_tcp` / `net_udp` above `uni_runtime` (app-space L4)

Today TCP and UDP implementations live *below* `uni_runtime` in the
crate DAG: `net_tcp` / `net_udp` register a `TcpBackend` /
`UdpBackend` vtable
([uni-runtime/src/net/tcp.rs](uni-runtime/src/net/tcp.rs),
[udp.rs](uni-runtime/src/net/udp.rs)) at boot from
[net/src/lib.rs](net/src/lib.rs)'s `init_stack`. Apps see only
`uni_runtime::net::TcpListener` / `UdpSocket`. Lifting the
implementations *above* `uni_runtime` — alongside `uni-tls` /
`uni-http` — would complete the "everything above the NIC is a
library" story and let apps swap in alternative L4 stacks
(smoltcp, custom congestion control, research stacks).

**What's already done:** the vtable seam exists. App code is
already decoupled from `net_tcp` internals — moving the
implementation up the DAG is symbolic from the API perspective,
load-bearing only for *who controls the implementation*.

**What the move would actually require:**

- [ ] Promote `net_tcp` → `uni-tcp` and `net_udp` → `uni-udp`
      above `uni_runtime`. Both crates are already `#![no_std]`
      with no `uni_drivers` dep; the `uni_kernel::cpu_id` /
      `rng::fill_bytes` / `percpu::PerCpu` calls have
      `uni_worker` equivalents in use across `uni_runtime::net`.
- [ ] Move the bare-metal `BARE_TCP_BACKEND` /
      `BARE_UDP_BACKEND` registration out of `net/src/lib.rs`
      into `uni_tcp::install()` / `uni_udp::install()` (mirrors
      `uni_tls::install()` style). App calls `install()` from
      its boot sequence.
- [ ] Define one new `Ipv4Send` vtable that the platform
      registers and `uni-tcp` / `uni-udp` call instead of
      `ipv4_send` directly. Keeps IPv4/ARP/Ethernet below the
      line as the "platform's wire glue"; only L4 lifts.
- [ ] Move the `tcp_dispatch` / `udp_dispatch` registry hooks
      ([net/src/lib.rs:25-38](net/src/lib.rs#L25-L38)) into the
      lifted crates so they self-register against
      `protocol::Registry`.
- [ ] Re-validate the full bench matrix (1c/2c/3c × HVF/KVM/
      native × `health_max` / `tls_handshake_max` /
      `gateway_max` / `compute_max` / `udp_peak`). The hot path
      already crosses the vtable; no new indirection on RX/TX,
      but the per-core `POOLS` / `TCP_HASH` layout is tuned
      enough to warrant verification. **Discipline: lift, don't
      refactor** — moving the crates is the work, redesigning
      the per-core ownership model is not.

Estimated effort: ~1.5–2 focused days (crates + Bazel + bench
re-run).

**Trigger**: either of —

- (a) `uni-quic` design wants to share `net_tcp`'s per-core
  conn pool / generation-handle / waker scaffolding with QUIC.
  At that point lifting both becomes structural rather than
  aesthetic, and the right time to do it is as part of QUIC's
  build-out, not a standalone refactor.
- (b) A concrete consumer shows up that wants to swap L4 —
  smoltcp port, BBR/CUBIC A/B, research stack experiment.
  Then the seam has a real user pulling on it.

Until one of those fires, the existing vtable boundary at
[uni-runtime/src/net/tcp.rs:205](uni-runtime/src/net/tcp.rs#L205)
is paying the dividend that matters most (app-side decoupling),
and the unmet 20 % is speculative.

### Bare-metal TCP corners (LastAck wait, TIME_WAIT, FIN retransmit)

`net/src/tcp.rs::close()`'s `CloseWait` branch sends FIN+ACK and
frees immediately — no `LastAck` wait. Active close in
`FinWait1`/`FinWait2` transitions straight to `Closed` on peer FIN
— no `TIME_WAIT`. There is no FIN retransmit timer.

On a local LAN / VM-NAT (loss-free) this is invisible. On a lossy
WAN: a single dropped FIN strands the conn until the peer's
keepalive fires; a delayed segment from a just-closed 4-tuple
could be misinterpreted by a fresh connection that reuses the
same ports.

Implementation requires integrating the kernel timer wheel into
TCP's sync packet handlers (callback fires → state-machine tick
on the owning core), with generation-aware cancel on slot reuse:

- [ ] `CloseWait → LastAck` transition + retransmit timer.
- [ ] `FinWait*` peer-FIN → `TimeWait` with 2×MSL drop timer.
- [ ] Bounded FIN retransmit (e.g., 5 retries with exponential
      backoff) before forcing close.
- [ ] Lossy-network test fixture (drop N% of egress packets in
      the bare-metal driver test seam).

**Trigger**: WAN deployments, OR when QUIC lands and we want
parity-class TCP behavior so apples-to-apples bench comparisons
are honest. Probably ~1-2 days plus the test infrastructure.

### Optional macOS delayed-ACK regression check

`net/tcp.rs` used to defer ACKs to piggyback on the next outbound
data segment, with a comment claiming this avoided ~250 ms stalls
on macOS keep-alive flows under HVF. Switched to immediate ACKs
in commit `b98b3e1` to fix a Nagle-induced ~40 ms-per-RTT stall
on the GCP KVM handshake path, and verified no regression on HVF
(`health_max` 190 k → 182 k req/s, well within run-to-run noise).

If the original macOS issue ever resurfaces:

- [ ] Replace the immediate-ACK with a real timer-based ACK
      coalescer: defer up to N ms or up to M unacked bytes,
      whichever comes first. Standard TCP delayed-ACK semantics,
      not "wait for app-level data."
- [ ] Reproduce the 250 ms stall the old comment claims to have
      seen so we have a regression test.

**Trigger**: if `health_max` / `health_tls_max` on HVF ever
shows the 250 ms p99 the deferred-ACK code was guarding against.

---

## Phase 6: Advanced Features (future)

### Virtio-vsock

Replace virtio-net for VM<->host communication. No Ethernet/IP
overhead. Useful for HVF / QEMU-on-macOS ultra-low-latency host
communication.

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
- Integration tests: `bazel test //apps/test_smp:test_qemu_aarch64`
  (per-variant; see `bazel/rules/variants.bzl`). Filter the full
  matrix via `--test_tag_filters=hvf` / `=qemu` / `=qemu_x86_64`.

---

## Implementation Priority

| Phase | Status | Effort | Impact | Dependencies |
|-------|--------|--------|--------|-------------|
| 1a. Per-protocol net/ targets | ✅ done | Small | Clean architecture | None |
| 1b. crate_universe | ✅ done | Small | Enables crates.io deps | None |
| 2a. SMP boot (AP spin-up) | ✅ done | Medium | Foundation for all multi-core | None |
| 2b. Tier 1: multi-queue + MSI-X | ✅ done | Large | Per-core queues (QEMU + HVF) | 2a |
| 2c. Tier 2: software distribution | ✅ done | Medium | Multi-core on single-queue platforms | 2a |
| 2f. Task arena + event-loop integration | ✅ done | Small | Foundation for async | 2a-c |
| 2g. Async/await (Future + Waker + executor + UDP/TCP reactors) | ✅ done | Medium | The differentiation thesis | 2f |
| 3a. UDP | ✅ done | Small | Enables QUIC | None |
| 3b. TLS 1.3 (hand-rolled) | ✅ done | Large | Required for QUIC | 1b |
| 3c. QUIC (as `async fn`) | next | Large | Modern transport + runtime consumer | 3a, 3b, 2g |
| 4. HTTP/3 | not started | Medium | Modern HTTP | 3c |
| 5. IPv6 + NDP | not started | Medium | Drop IPv4 legacy | None |
| 2d. Work stealing | parked (post-QUIC) | Medium | CPU-task efficiency | 2a-c |
| 2e. Timer wheel event-loop wiring | absorbed into 2g | Small | Async timers | 2a |
| 2h. Perf regression tests | parked (post-QUIC) | Medium | Prevent regressions | 2a-c |

**Where we are now (2026-05-02):** all QUIC prerequisites are in.
Phase 3b (TLS 1.3) shipped, phases 2f+2g (async runtime + UDP/TCP
reactors) shipped including the `UdpRecv::recv_from` and
`TcpListener::accept`/`TcpStream` reactors that 3b's plan deferred
to "alongside QUIC" — they're already done. Highlights since the
April 2026 status:

- `//uni-runtime` async executor with chunked launcher table,
  per-worker arenas, generation-aware handles.
- `UdpSocket::run` / `TcpListener::run` reactors on bare-metal
  AND native, both backends sharing a single `TcpBackend` /
  `UdpBackend` vtable.
- `uni_http::listen` and `listen_https` now take any
  `AsyncFn(&Request) -> Response` — handlers can `.await`.
- Native gateway workload at 89 k req/s 1c, HVF at 73 k 1c
  (post `gateway_max conns_per_core: 1500` bump).
- Graceful shutdown: `drain_all_arenas` reclaims in-flight task
  storage, `shutdown_all_tcp` emits one RST per active conn,
  `HEAP_LEAK_CHECK ok` asserted under traffic.

**Next on deck:** Phase **3c** (QUIC as `async fn`). Every
prerequisite — async runtime, UDP socket API, TLS 1.3 server
state machine — is in place; QUIC starts on a clean foundation.

**Optional pre-QUIC**: TLS session resumption (1 focused day; see
"Deferred work — Session resumption"). Drops resumed-handshake
latency ~7×, and resumed handshakes are exactly what QUIC's
`pre_shared_key` extension reuses, so doing it on the TCP path
first is free leverage on QUIC later. Skip if eager to start QUIC.

Revised order for what's left:
`3c (QUIC) → 4 (HTTP/3) → 5 (IPv6/NDP) → 2d/2h (work stealing
+ perf tests, post-QUIC)`.

**The thesis we're committing to**: `async fn` is the *only* execution
model, not a layer. Tokio/smol run above Linux; Embassy is
single-core microcontroller; Hermit targets libstd. A multi-core,
lock-free, no_std, QUIC-first Rust runtime where the executor IS the
kernel has no prior art. That's the differentiation bet — and it
compounds with the architectural decisions already shipped (per-core
lock-free queues, flow-hash connection pinning, hand-rolled TLS 1.3,
native HVF runner). Each of those ingredients has some equivalent
elsewhere; the combination does not.
