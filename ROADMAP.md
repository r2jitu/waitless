# Unikernel Next-Gen Roadmap

A cutting-edge, lean unikernel: modern protocols only (QUIC/HTTP3, IPv6),
cooperative multi-core, zero legacy overhead. Each feature is compile-time
optional via Bazel deps — you pick exactly what you need.

## Design Principles

- **Modern over legacy**: QUIC over TCP, IPv6 over IPv4, NDP over ARP
- **Deps as feature selection**: app declares what it needs via Bazel deps — unused protocols never compile
- **No preemption, no locks**: cooperative per-core work queues with work stealing
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

Split the current monolithic `//net` crate into individual targets.
The existing `//net` target becomes an alias or umbrella for the legacy stack.
New protocol targets (udp, ipv6, ndp, quic) are added as new crates.

- [ ] `//net:ethernet` (ethernet.rs, types.rs — shared by all)
- [ ] `//net:arp` (arp.rs — deps: ethernet)
- [ ] `//net:ipv4` (ipv4.rs — deps: ethernet, arp)
- [ ] `//net:tcp` (tcp.rs — deps: ipv4)
- [ ] `//net:dhcp` (dhcp.rs — deps: ipv4, ethernet)
- [ ] `//net` umbrella alias for the full legacy stack

**Tests:**
- [ ] Unit: ethernet frame parse/build
- [ ] Unit: ARP request/reply encode/decode
- [ ] Unit: IPv4 header checksum
- [ ] Unit: TCP segment parse
- [ ] Unit: DHCP option parsing
- [ ] Integration: existing HTTP smoke tests still pass (no regression)

### 1b. Add crate_universe for crates.io dependencies

Required for pulling in crypto (`ring`), QUIC (`quiche`/`quinn`), etc.

- [ ] Add `crates_repository` to MODULE.bazel
- [ ] Test with a simple `no_std` dep (e.g., `bitflags` or `heapless`)
- [ ] Verify build + boot smoke test passes

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
One core polls the single RX queue (not dedicated — it also does work).
Incoming packets are classified by flow hash and dispatched to the
owning core's work queue. The polling core rotates — whoever wakes
first from WFI on the net IRQ polls that batch.

```rust
// Tier 2: single-queue software distribution
fn poll_single_rx_queue() {
    while let Some(pkt) = rx_queue.poll() {
        let flow = hash(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port);
        let target_core = flow % num_cores;
        if target_core == my_core {
            process_packet(pkt);          // Handle locally
        } else {
            cores[target_core].queue.push(Task::Packet(pkt));
            if cores[target_core].sleeping {
                send_ipi(target_core);    // Wake the target
            }
        }
    }
}
```

**Detection at boot**: check if `VIRTIO_NET_F_MQ` is offered. If yes ->
Tier 1 (per-core queues). If no -> Tier 2 (software distribution).
Same event loop code, different poll implementation.

### Architecture: per-core event loop (poll after every task)

```rust
// Every core runs this — identical loop
loop {
    // 1. Poll MY queues — each core owns its own hardware queue pair
    //    No contention, no try-lock needed
    poll_virtio_net_rx(&my_rx_queue);   // network packets
    poll_virtio_blk(&my_blk_queue);     // storage completions (future)
    poll_timers(&my_timer_wheel);       // expired timers

    // 2. Process one task from my work queue
    if let Some(task) = my_queue.pop() {
        task.run();
        continue;  // poll again immediately — keeps IO responsive
    }
    // 3. Steal work if idle (tasks only, not connections)
    if let Some(task) = steal_from_busiest() {
        task.run();
        continue;  // poll again after stolen task
    }
    // 4. Nothing to do — sleep until interrupt
    wfi();  // wake on virtio IRQ, IPI, or timer
}
```

Every core polls, every core processes, every core can steal. Polling
happens after every task completion, ensuring IO is serviced promptly.

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

### Work queue + stealing

```rust
struct PerCore {
    queue: WorkQueue,         // lock-free SPSC ring
    timer_wheel: TimerWheel,  // per-core deadlines
    connections: ConnPool,    // connections owned by this core
}
```

- **Connections pinned to cores** via RSS hash(src_ip, dst_ip, src_port,
  dst_port). All packets for a connection arrive on the same core's queue.
  Connection state (buffers, timers) stays local — no migration needed.
- **Timers are per-core**: each connection's timers live on the owning
  core's timer wheel. They fire locally and enqueue tasks locally.
  A thief might steal the resulting task, but the timer itself stays put.
- **Work stealing steals tasks, not connections**: an idle core peeks at
  other cores' queues via atomic tail-steal (single CAS). It runs the
  stolen task (e.g., "generate HTTP response") to completion, then returns
  to its own work. Connection state doesn't move.
- **IPI**: wake a sleeping core when stealing finds work.

### Why imbalance self-corrects (no migration needed)

- RSS distributes NEW connections across cores by port hash — natural spread
- Closed connections free up the core they were pinned to
- HTTP request tasks are short-lived (microseconds) — queues drain fast
- Work stealing handles transient bursts (hot connection on one core)
- **Persistent imbalance** would require one connection dominating traffic
  AND generating CPU-heavy tasks. Unlikely for a webserver. Escape hatch:
  reprogram RSS indirection table (future optimization, not day-1).

### Why no synchronization

- Connection state lives on ONE core (pinned by RSS hash)
- VirtIO queues are per-core (no shared queue contention)
- Global state (ARP cache, routing table) is write-once at boot
- TX: each core has its own TX queue (virtio multi-queue)
- Only sync point: work stealing (one atomic CAS per steal attempt)
- Timer wheels are per-core (no global timer queue)

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

- [ ] aarch64 AP startup via PSCI CPU_ON
- [ ] x86_64 AP startup via INIT-SIPI-SIPI (APIC)
- [ ] Per-core stack allocation (fixed-size, allocated at boot)
- [ ] Per-core work queue (lock-free ring buffer)
- [ ] Per-core timer wheel
- [ ] Per-core heap slab (local allocations, no contention)
- [ ] Core 0 bootstraps, then becomes a regular worker
- [ ] x86_64: APIC init (replace legacy PIC for multi-core)
- [ ] aarch64: per-core GIC redistributor init

**Tests:**
- [ ] Integration: `test_smp_boot` — boot with `-smp 4`, verify all 4 cores reach event loop (each prints "core N online")
- [ ] Integration: `test_per_core_state` — verify each core has independent stack, timer, queue
- [ ] Integration: `test_ipi` — core 0 sends SGI/IPI to core 1, core 1 acknowledges via serial
- [ ] Run on QEMU aarch64 AND x86_64

### 2b. Tier 1: multi-queue + MSI-X (QEMU)

- [ ] Negotiate `VIRTIO_NET_F_MQ` feature bit
- [ ] Create N queue pairs (one per core)
- [ ] MSI-X setup: allocate vectors, program MSI-X table
- [ ] MSI-X affinity: route each vector to owning core (APIC / GICv2M)
- [ ] RSS configuration: program indirection table + hash key
- [ ] Per-core RX/TX poll in event loop
- [ ] QEMU flags: `-smp N`, `mq=on,queues=N,vectors=2N+2`

**Tests:**
- [ ] Integration: `test_multiqueue` — boot with `-smp 4, mq=on,queues=4`, verify 4 queue pairs negotiated
- [ ] Integration: `test_msix_affinity` — verify MSI-X vectors route to correct cores
- [ ] Integration: `test_rss_distribution` — send from multiple source ports, verify packets land on different cores
- [ ] Integration: HTTP smoke tests with `-smp 4` (regression)

### 2c. Tier 2: software distribution (VZ + single-queue)

- [ ] Detect single-queue at boot (`VIRTIO_NET_F_MQ` not offered)
- [ ] Flow hash function: hash(src_ip, dst_ip, src_port, dst_port)
- [ ] Software packet dispatch: classify + enqueue to target core
- [ ] IPI to wake target core when dispatching cross-core
- [ ] Tier auto-detection: MQ offered -> Tier 1, else -> Tier 2

**Tests:**
- [ ] Integration: `test_tier2_distribution` — boot VZ (or QEMU without MQ), verify software distribution active
- [ ] Integration: `test_tier_autodetect` — verify Tier 1 on QEMU with MQ, Tier 2 on QEMU without MQ

### 2d. Work stealing

- [ ] Lock-free SPSC work queue (per-core)
- [ ] Atomic tail-steal (single CAS) for cross-core stealing
- [ ] Steal from busiest core (check queue depths)
- [ ] IPI to wake sleeping core when work is available

**Tests:**
- [ ] Unit: ring buffer SPSC ops (push, pop, boundary conditions)
- [ ] Unit: steal protocol (push N items, steal from other end, verify no lost items)
- [ ] Integration: `test_work_stealing` — load one core, verify idle cores steal tasks

### 2e. Per-core timer wheels

- [ ] Timer wheel data structure (per-core)
- [ ] Insert / fire / cancel operations
- [ ] Poll timers in event loop
- [ ] Timer-driven wakeup (per-core architectural timer)

**Tests:**
- [ ] Unit: timer wheel insert, fire ordering, cancel
- [ ] Integration: `test_timer_fire` — set timers on different cores, verify correct fire times

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
