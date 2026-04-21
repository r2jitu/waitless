# Init Redesign Plan

Prerequisite work to prepare the codebase for **ROADMAP §2f/§2g
(async runtime)** and **ROADMAP §3c (QUIC)**. Restructures the
init sequence, module boundaries, and global state into shapes
that those phases can build on cleanly.

**Not a new feature delivery.** Every phase is refactor + API
reshaping. Feature work resumes at ROADMAP §2f once this plan
completes.

---

## Status

**Started:** not yet (as of 2026-04-20)
**Prerequisite commits landed:** `b50f3a4` (uni::App framework)
through `70a6f4a` (apps/hello minimal example)
**Blocks:** ROADMAP §2f (task arena), §2g (async executor), §3c (QUIC)

See the [Progress tracker](#progress-tracker) below for phase-by-
phase status.

---

## Why this plan exists

The current kernel init sequence auto-initializes every subsystem
regardless of whether the app uses it, AND every binary links
every subsystem regardless of whether the app references it:

- **Runtime cost:** DHCP retries on boot, ~several MB of TCP
  connection pool reserved at boot, event-loop slots bound to
  subsystems the app didn't ask for.
- **Binary size:** a minimal HTTP hello world is 1.9 MB on
  aarch64 HVF because the full TLS stack (~900 KB of RustCrypto),
  DHCP, and multi-driver NIC dispatch are always linked. Measured:
  `hello.img` ≈ `webserver.img`, delta only ~16 KB.
- **Architectural debt:** 8 scattered globals for network state,
  46 `static mut` across 16 files, drivers with 9 separate atomics
  for one device's state. Hard to reason about, hard to test.

Once ROADMAP §2g lands an async executor, all of this becomes
harder to refactor — the executor hangs off of structure that
already exists. The cost of doing it in the wrong shape first is
rewriting twice. This plan gets the shape right first.

---

## Design principles

### 1. One anchor per subsystem

The `uni::App` prototype established the pattern: one global slot
(`APP_SLOT`) holds a `Box<dyn App>`; all app state is reachable
through it. This plan applies the same principle everywhere:

- `Net::enable()` populates `NET: static Option<Box<Net>>`
- Each NIC driver crate has one `InitOnce<Driver>` anchor
- `Smp::enable()` populates `SMP: static Option<SmpState>`
- Arch tables (GDT / IDT / TSS) collapse to one `InitOnce` each

**Rule:** if a subsystem has 3+ statics, consolidate to one anchor.

### 2. The crate IS the API

Each crate's public surface is one or two types + their methods.
Implementation details stay inside. Extension across crate
boundaries happens via extension traits, not by exposing internals.

### 3. No hidden dependencies

A crate's API must be usable without knowing about anyone else's
globals. If a function requires some other subsystem to have been
initialized, that's expressed in the type system — e.g., by
taking `&Net` as a parameter, which can only come from
`Net::enable()`.

### 4. POSIX shapes aren't destiny

This is a unikernel — no protection boundary, no syscall cost, no
kernel/user copy enforcement. We don't owe backwards compatibility
to the `listen/accept/recv/send` programming model.

Three concrete consequences:

1. **Hide accept loops behind handlers.** Apps shouldn't write
   `loop { stream = listener.accept(); ... }`. The framework runs
   the loop.
2. **Primitives are poll-based with explicit Wakers.** Every
   transport primitive exposes `try_recv(buf) -> Option<usize>`
   and `register_waker(&Waker)`. Sync and async both wrap these.
3. **Transport agnostic at the protocol layer.** `uni-http`
   doesn't know about TCP specifically; it takes a listener
   that implements a trait. Swappable for QUIC at HTTP/3.

### 5. Every phase makes async easier

Phases 0-8 are evaluated against: **"does this make ROADMAP
§2g's async executor easier or harder?"** Each phase contributes
one of:

- Poll-based primitive APIs that Futures wrap cleanly
- Per-connection / per-request state structured for Waker parking
- Capability tokens that become executor "context" objects
- Per-core arenas that match §2f's task-slot layout

The "Async prep" note on each phase spells out what it adds.

### 6. Perf invariant: neutral-or-better per phase

**No phase lands if it regresses benchmarks by more than 2% on
HVF single-core.** See [Benchmark protocol](#benchmark-protocol)
for exact workloads and thresholds. Anti-regression mitigations
baked in per-phase:

- Hot-path per-core arrays stay `InitOnce<PerCore<…>>` statics
  with direct addressing; `Net` owns them logically, not
  physically.
- NIC driver dispatch compiles to direct calls in the common
  "one driver linked" case; trait-object fallback only when
  multiple drivers are present.
- Async polling is Waker-driven (phase 9+), matching today's
  callback dispatch cost within ~5 ns.

---

## Target crate layout

```
uni                    — App trait, uni::run, log, boot_info, #[uni::boot]
uni-kernel             — primitives: Spinlock, InitOnce, AtomicFn, PerCpu,
                         eventloop, mm, time, percpu
uni-net                — L3: NIC driver trait, ARP, IPv4, protocol registry,
                         Net capability
uni-udp                — UDP datagram API (thin layer on Net)
uni-tcp                — TCP stack as a library (TcpStack::enable(&net))
uni-http               — HTTP/1.1 over a transport (takes &TcpStack)
uni-tls                — TLS 1.3 extension trait + config
uni-dhcp               — DHCP client (Net::enable_dhcp)
uni-net-static         — static IP config (Net::enable_static)
uni-driver-virtio-net  — driver crate
uni-driver-gvnic       — driver crate
uni-driver-nic-all     — meta: both drivers + boot-time dispatch

(ROADMAP §3c adds uni-quic and §4c adds uni-http3 on top of this.)
```

Dependency graph:

```
uni-kernel
    ↑
  uni ←─── uni-net ←── uni-udp, uni-tcp
                   ↑                  ↑
                uni-driver-*       uni-http ←─── uni-tls
                                      ↑
apps/webserver: uni, uni-http, uni-tls, uni-dhcp, uni-driver-nic-all
apps/hello:     uni, uni-http, uni-net-static, uni-driver-virtio-net
apps/compute:   uni
```

---

## API boundary per crate

One or two types + their methods. Internals stay internal.

### `uni` (core)

```rust
pub trait App: 'static {}
pub fn run<A: App>(app: A);
pub fn log(bytes: &[u8]);
pub fn config_port(default: u16) -> u16;
pub fn boot_info() -> &'static BootInfo;

pub struct BootInfo {
    pub ram_bytes: usize,
    pub num_cpus: u32,
    pub boot_args: &'static str,
    pub nics: &'static [NicInfo],
    pub rtc_epoch: Option<u64>,
}

#[uni::boot] // proc macro
fn boot() { uni::run(MyApp::new()); }
```

### `uni-net`

```rust
pub struct Net { /* opaque */ }

impl Net {
    pub fn local_ip(&self) -> Ipv4Addr;
    pub fn mac(&self) -> [u8; 6];
    // Protocol layers register here; not a user API:
    pub(crate) fn register_protocol(&self, proto: u8, rx: fn(Ipv4Packet));
}

pub trait NicDriver {
    fn probe() -> Option<NicHandle>;
    fn poll_rx(&self, cb: impl FnMut(&[u8])) -> usize;  // async-ready: returns immediately
    fn send(&self, frame: &[u8]) -> Result<(), NicError>;
    fn register_rx_waker(&self, waker: &Waker);         // stub in Phase 3, live in Phase 9
}

// Link-time driver registration
#[macro_export]
macro_rules! register_driver { ($ty:ty) => { ... } }
```

`Net::enable_dhcp` and `Net::enable_static` live in sibling crates
(`uni-dhcp` / `uni-net-static`) as extension traits. `uni-net` has
no dep on either.

### `uni-tcp`

```rust
pub struct TcpStack { /* opaque — conn pool, hash tables */ }

impl TcpStack {
    pub fn enable(net: &Net) -> Self;          // allocates conn pool, registers IP proto 6
    pub fn listen(&self, port: u16) -> TcpListener;
}

pub struct TcpListener { /* handler-based, no accept() */ }

impl TcpListener {
    // Sync version:
    pub fn serve(&self, handler: impl Fn(TcpStream) + Send + Sync + 'static);
    // Async version (Phase 9+):
    pub fn accept(&self) -> impl Future<Output = TcpStream>;
}

pub struct TcpStream { /* poll-based primitive */ }

impl TcpStream {
    pub fn try_recv(&mut self, buf: &mut [u8]) -> Option<usize>;
    pub fn try_send(&mut self, data: &[u8]) -> Option<usize>;
    pub fn register_rx_waker(&mut self, waker: &Waker);
    pub fn register_tx_waker(&mut self, waker: &Waker);
    // Async adapters (Phase 9+):
    pub fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = usize>;
    pub fn send(&mut self, data: &[u8]) -> impl Future<Output = usize>;
}
```

### `uni-http`

```rust
pub struct Server { /* opaque */ }

impl Server {
    pub fn new_boxed(tcp: &TcpStack) -> Box<Self>;  // takes TCP, not Net
    pub fn route(&mut self, path: &[u8], handler: Handler);
    pub fn default_handler(&mut self, handler: Handler);
    pub fn listen(&mut self, port: u16);
}

pub type Handler = fn(&Request) -> Response;
// Async handler (Phase 9+): async fn(&Request) -> Response
```

### `uni-tls` (extension trait)

```rust
pub struct TlsServerConfig { /* opaque */ }

pub trait TlsExt {
    fn listen_tls(&mut self, port: u16, cfg: TlsServerConfig);
}

impl TlsExt for uni_http::Server { ... }
```

Apps do `use uni_tls::TlsExt;` to activate. Without the import
(and dep), the method doesn't exist — TLS code isn't linked.

---

## Migration phases

| Phase | Scope | Effort | Async prep | Perf |
|---|---|---|---|---|
| 0 | `uni::boot_info()` | 1-2 d | BootInfo will be passed to runtime init | Neutral |
| 1 | `Net::enable()` + flag-day global collapse | 6-7 d | Protocol registry + poll-based NIC trait | Neutral (mitigations below) |
| 2 | `uni-tcp` carveout with handler-not-loop API | 3-4 d | Handler shape = async fn shape | Neutral |
| 3 | NIC driver carveouts + state consolidation | 3-4 d | `register_rx_waker` stub becomes live in Phase 9 | Neutral |
| 4 | `uni-tls` carveout | 4-5 d | Already sans-io, async-ready | Neutral |
| 5 | DHCP + static-IP carveouts | 3 d | — | Neutral |
| 6 | Event-loop hooks (`on_idle`, `on_tick`) | 2-3 d | Hooks become async task primitives | Neutral |
| 7 | SMP opt-in | 3-5 d | Per-core executor already fits this | Neutral or better (single-core saves init) |
| 8 | `static mut` sweep + virtio-console consolidation | 3-5 d | Cleaner state for Waker slots to live in | Neutral |

Total: ~27-36 days focused work. Each phase is an independent PR;
each validates against benchmarks before merging.

**After Phase 8:** ROADMAP §2f task arena + §2g async executor +
§3c QUIC resume on the clean foundation.

### Phase 0: `uni::boot_info()`

Populate a `BootInfo` struct in `kernel::entry` after ACPI/FDT
parsing + NIC discovery. Expose via `uni::boot_info()`. Apps
optionally use it in `new()`.

**Async prep:** the future async executor's init takes
`&BootInfo` to size per-core task arenas based on actual CPU
count rather than `MAX_CORES`.

**Perf impact:** zero (data populated at boot, read on demand).

### Phase 1: `Net::enable()` + flag-day global collapse

One big PR that:

1. Introduces `Net::enable_dhcp()` / `Net::enable_static(cfg)`.
2. Deletes kernel-level auto-init of DHCP/ARP/IP/TCP.
3. Moves scattered globals into `Net`:
   - `net::types::CONFIG` → `Net.config`
   - `net::udp::HANDLER_*` → `Net.udp_handlers`
   - `net::dhcp::DHCP_STATE` → `Net.dhcp_state` (behind `uni-dhcp` cfg)
   - `uni::http::SERVER_PTR` / `TLS_CONFIG_PTR` → fields on Server
   - `net::lib::{MULTICORE_INIT, WAKEUP, RX_LOCK, JUST_DISTRIBUTED}`
     → `Net.dispatcher`
4. Wraps hot-path per-core arrays in `InitOnce<PerCore<…>>` so
   memory isn't reserved until `Net::enable()` runs.
5. Introduces the protocol registry (`Net::register_protocol`) —
   TCP and UDP both use it from day one.
6. Defines `NicDriver` trait with poll-based `poll_rx` and
   `register_rx_waker` (latter is a no-op stub until Phase 9).
7. Migrates all 4 in-tree apps.

**Async prep:** the protocol registry is the async reactor's RX
dispatch point. `register_rx_waker` slot exists from day one;
Phase 9 wires it up.

**Perf impact:** must be neutral. Mitigations:
- Hot-path per-core arrays (`TCP_POOLS`, `ARP_FAST`) stay
  statically addressable; `Net` references them, doesn't mediate
  access.
- `Net::current()` loaded once at the top of hot paths, cached
  locally.
- Protocol registry: 8-entry array, direct indexed lookup, ~1 ns
  per packet. Validated before merge.

### Phase 2: `uni-tcp` carveout with handler-not-loop API

Split `net::tcp` into a separate crate. Reshape the public API to
handler-based:

```rust
// Old:
let listener = TcpListener::bind(port)?;
loop { let stream = listener.accept()?; ... }

// New:
let listener = tcp.listen(port);
listener.serve(|stream| { ... });  // framework runs the accept loop
```

**Async prep:** `serve(handler)` naturally becomes
`serve(async move |stream| { ... })` in Phase 9. The sync
version is just `executor.block_on(...)`.

`try_recv` / `try_send` primitives become the raw interface;
async `recv` / `send` are thin Future wrappers in Phase 9.

**Perf impact:** neutral. Handler dispatch is already what HTTP
does internally; TCP joining that pattern removes one layer of
indirection (was: TCP stream → accept loop → HTTP handler; now:
TCP stream → handler directly).

### Phase 3: NIC driver carveouts + state consolidation

Split `drivers/virtio_net.rs` and `drivers/gvnic.rs` into
separate crates. Each driver crate collapses its 6-9 scattered
statics into one `InitOnce<Driver>` anchor implementing
`uni_net::NicDriver`.

`uni-driver-nic-all` is a meta-crate depending on both drivers
plus the boot-time dispatch logic.

**Async prep:** `NicDriver::register_rx_waker(&Waker)` is now a
real slot in each driver. Phase 9 wakes the network executor
when an RX IRQ fires.

**Perf impact:** neutral. Single-driver deployments get direct
calls (no vtable); multi-driver deployments get one indirect
call per packet (~1 ns, below bench-noise floor). Driver state
consolidation doesn't change access patterns — hot-path atomics
stay where they were, just moved from separate statics into
fields of one `Driver` struct at the same cache-line positions.

### Phase 4: `uni-tls` carveout

Move `net/tls_*` into a new `uni-tls` crate. Introduce `TlsExt`
extension trait. `uni-http::Server` stays TLS-unaware — apps
opt into TLS by importing `uni-tls`.

**Async prep:** TLS state machine is already sans-io; Phase 9
wraps `tls.advance(cfg)` in an async frame. No additional prep.

**Perf impact:** neutral for TLS workloads (same code path).
~900 KB binary size savings for non-TLS apps (hello drops from
1.9 MB to ~1 MB).

### Phase 5: DHCP + static-IP carveouts

`net/dhcp.rs` → `uni-dhcp`. New `uni-net-static`. Core TCP/IP
stays in `uni-net`. `Net::enable_dhcp()` / `Net::enable_static(cfg)`
are extension traits on Net.

**Async prep:** DHCP state machine becomes async-friendly —
`uni-dhcp` can ship both sync (loop until lease) and async
(Future<Output = Lease>) in Phase 9.

**Perf impact:** neutral.

### Phase 6: Event-loop hooks

`uni::on_idle(f)`, `uni::on_tick(f)` for apps that inject
background work. Current `kernel::eventloop` has 8 hardcoded
callback slots; these add 2 app-facing ones.

**Async prep:** these become `Timer::every(duration).stream()`
and similar in Phase 9. The hooks are fallbacks for sync apps;
async apps use reactor primitives directly.

**Perf impact:** additive, neutral.

### Phase 7: SMP opt-in

`uni::smp::enable()` brings up APs; otherwise they stay parked.
Single-core apps drop SMP bring-up code and the per-core arena
machinery falls out of the binary.

**Async prep:** per-core task arenas (ROADMAP §2f) assume SMP
bring-up has happened OR opts into single-core mode. Capability
handle returned by `Smp::enable()` becomes executor context.

**Perf impact:** neutral when enabled; better for single-core
apps (shorter boot, smaller binary).

### Phase 8: `static mut` sweep + virtio-console consolidation

46 `static mut` across 16 files → 0. Each case migrates to:

- `InitOnce<T>` (publish-once)
- `Spinlock<T>` (shared mutable)
- `UnsafeCell<T>` + `unsafe impl Sync` (single-threaded by contract)

Also: `drivers/virtio_console.rs` 12 statics → one `InitOnce<VirtioConsole>`.

**Async prep:** clean state representation for async to hang
Waker slots off of.

**Perf impact:** neutral. `InitOnce::get()` is an atomic load,
same cost as direct static access after first init.

---

## Progress tracker

Update this table as phases land. Perf numbers from HVF 1-core on
Apple Silicon (M-series).

### Baseline (pre-redesign, commit 70a6f4a)

Measured 2026-04-20 via `python3 scripts/bench.py --env hvf --cores 1`:

| Workload | Baseline | Notes |
|---|---|---|
| health_c1         | 35,500 req/s | Single-flow HTTP latency floor |
| compute_c1        | 6,500 req/s  | Single-flow CPU-bound |
| health_max        | 194,000 req/s | **Keep-alive HTTP throughput** |
| compute_max       | 8,000 req/s  | Multi-conn CPU-bound |
| udp_sync          | 32,000 pkt/s | Single-flow UDP echo |
| udp_peak          | 184,000 pkt/s | **Max UDP datagram rate** |
| health_tls_c1     | 28,000 req/s | Single-flow TLS latency |
| health_tls_max    | 124,000 req/s | **Keep-alive TLS throughput** |
| tls_handshake_max | 3,300 hs/s   | Full-handshake TLS rate |

Bolded entries are the three workloads that most commonly regress
under refactors. These are the primary gates.

### Binary sizes (baseline)

Measured at commit 70a6f4a:

| App | `.img` (HVF aarch64) | `_native` (POSIX) |
|---|---|---|
| hello     | 1.9 MB | 192 KB |
| webserver | 2.0 MB | 196 KB |

### Per-phase tracker

| Phase | Status | Before | After | Binary delta | Notes |
|---|---|---|---|---|---|
| 0 | ⏳ not started | — | — | — | |
| 1 | ⏳ not started | — | — | — | |
| 2 | ⏳ not started | — | — | — | |
| 3 | ⏳ not started | — | — | — | |
| 4 | ⏳ not started | — | — | — | |
| 5 | ⏳ not started | — | — | — | |
| 6 | ⏳ not started | — | — | — | |
| 7 | ⏳ not started | — | — | — | |
| 8 | ⏳ not started | — | — | — | |

Status legend: ⏳ not started, 🟡 in progress, 🟢 complete,
🔴 blocked (perf regression or design issue).

---

## Benchmark protocol

### Running the suite

```bash
# Before starting a phase:
git checkout <phase-base-commit>
python3 scripts/bench.py --env hvf --cores 1 > bench-phase-N-before.txt

# After the phase's PR:
git checkout <phase-head-commit>
python3 scripts/bench.py --env hvf --cores 1 > bench-phase-N-after.txt

# Compare:
diff bench-phase-N-before.txt bench-phase-N-after.txt
```

### Pass criteria per phase

All of:

1. **`bazel test //kernel/... //net/... --config=hvf //apps/webserver:test`
   all green.**
2. **Per-workload regression ≤ 2%** vs. the phase's baseline. Bolded
   workloads (`health_max`, `udp_peak`, `health_tls_max`) are hard
   gates; others have a ±2% tolerance for HVF scheduling noise.
3. **Binary size regression ≤ 50 KB** for `apps/hello`, `≤ 100 KB`
   for `apps/webserver`. Phase 4 should show a ~900 KB REDUCTION
   for hello (no TLS); other phases should be approximately
   neutral.
4. **Zero increase in `static_mut` count** (target trajectory is
   downward toward zero by end of Phase 8).

Any phase that can't hit pass criteria is stop-the-line: fix the
design before merging.

### Measuring binary size

```bash
bazel build --config=hvf //apps/hello:hello //apps/webserver:webserver
ls -l bazel-bin/apps/hello/hello.img bazel-bin/apps/webserver/webserver.img
```

### Measuring `static_mut` count

```bash
# From repo root:
rg --stats '^\s*static mut\s+\w+' kernel/ uni/ net/ drivers/ apps/ boot/
# Target trajectory:
#   Today:        46
#   After Phase 8: 0
```

---

## Hand-off to ROADMAP

After Phase 8 lands, this plan is complete. Next planned work:

- **ROADMAP §2f** — Task trait + pinned task slots (~300 LOC)
- **ROADMAP §2g** — Async/await (`Future` + `Waker` + minimal
  executor)
- **ROADMAP §3c** — QUIC end-to-end (the first real async consumer)
- **ROADMAP §4** — HTTP/3
- **ROADMAP §5** — IPv6 + NDP

The "async prep" notes on each init-redesign phase document
exactly what each phase contributes to §2g's executor landing
cleanly on the restructured codebase.

---

## When to start

None of the triggers in the earlier plan version are active as of
2026-04-20 (no RAM budget pressure, no compute-only workload, no
out-of-tree apps). This plan sits ready to pick up when one of the
following becomes pressing:

- Starting ROADMAP §2f/§2g async work — this plan is prerequisite
- Starting ROADMAP §3c QUIC work — same
- Wanting sub-1 MB binaries for a specific deployment
- Noticing that `static mut` tech debt is growing

When any of those fire, the first session's prompt is:

```
Implement the init redesign, starting with Phase 0. Plan:
docs/init-redesign.md. Bench baseline is captured in the
plan's Progress tracker. Each phase is an independent PR;
each PR must pass the Benchmark protocol's criteria before
merging. Update the Progress tracker as each phase lands.
```

---

## Appendix: target app shapes after Phase 8

### `apps/compute/main.rs` (hypothetical pure-compute)

```rust
#![no_std]
extern crate uni;

struct ComputeApp;
impl uni::App for ComputeApp {}

#[uni::boot]
fn boot() {
    uni::log(b"compute app\n");
    loop { core::hint::black_box(fibonacci(40)); }
}
```

Deps: `["//uni"]`. Binary: ~400 KB.

### `apps/hello/main.rs` (after plan)

```rust
#![no_std]
extern crate alloc;
extern crate uni;

use uni_http::{Server, Request, Response};
use uni_net::Net;
use uni_net_static::{StaticIpConfig, NetStaticExt};
use uni_tcp::TcpStack;

struct HelloApp {
    _server: alloc::boxed::Box<Server>,
    _tcp: TcpStack,
    _net: Net,
}
impl uni::App for HelloApp {}

impl HelloApp {
    fn new() -> Self {
        let net = Net::enable_static(StaticIpConfig {
            ip: [10, 0, 2, 15].into(),
            gateway: [10, 0, 2, 2].into(),
            netmask: [255, 255, 255, 0].into(),
        }).unwrap();
        let tcp = TcpStack::enable(&net);

        let mut server = Server::new_boxed(&tcp);
        server.default_handler(|_| Response::ok(b"text/plain", b"Hello!\n"));
        server.listen(uni::config_port(80));

        HelloApp { _server: server, _tcp: tcp, _net: net }
    }
}

#[uni::boot]
fn boot() { uni::run(HelloApp::new()); }
```

Deps: `["//uni", "//uni-http", "//uni-tcp", "//uni-net-static",
"//uni-driver-virtio-net"]`. Binary: ~1 MB.

### `apps/webserver/main.rs` (after plan)

```rust
#![no_std]
extern crate alloc;
extern crate uni;

use uni_http::{Server, Request, Response};
use uni_net::Net;
use uni_dhcp::NetDhcpExt;
use uni_tcp::TcpStack;
use uni_tls::{TlsServerConfig, TlsExt};
use uni_udp::UdpSocket;

struct WebServerApp {
    _server: alloc::boxed::Box<Server>,
    _tcp: TcpStack,
    _net: Net,
}
impl uni::App for WebServerApp {}

impl WebServerApp {
    fn new() -> Self {
        let net = Net::enable_dhcp().expect("DHCP failed");
        let tcp = TcpStack::enable(&net);

        let udp = net.bind_udp(7);
        udp.on_recv(udp_echo);

        let mut server = Server::new_boxed(&tcp);
        server.default_handler(handle_request);
        server.listen(uni::config_port(80));

        if let Some(cfg) = TlsServerConfig::from_dev_cert(DEV_CERT, DEV_KEY) {
            server.listen_tls(uni::config_port(443), cfg);
        }

        WebServerApp { _server: server, _tcp: tcp, _net: net }
    }
}

#[uni::boot]
fn boot() { uni::run(WebServerApp::new()); }
```

Deps: `["//uni", "//uni-http", "//uni-tls", "//uni-tcp",
"//uni-udp", "//uni-dhcp", "//uni-driver-nic-all"]`. Binary: ~2 MB.

---

## After async lands (ROADMAP §2g complete)

This section describes the target shape AFTER ROADMAP §2g lands,
for reference. NOT part of this plan's scope.

```rust
#[uni::boot]
async fn boot() {
    let net = Net::enable_dhcp().await.expect("DHCP failed");
    let tcp = TcpStack::enable(&net);

    let server = Server::new(&tcp)
        .default_handler(async |req| Response::ok(b"text/plain", b"Hi!\n"))
        .listen(80);

    server.serve().await;  // runs until shutdown
}
```

The transition from Phase 8 shape to async shape is small — the
phases in this plan deliberately choose handler-based,
poll-primitive APIs that wrap into async cleanly without
restructuring the type system again.
