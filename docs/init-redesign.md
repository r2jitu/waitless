# Init Redesign Plan

Prerequisite work to prepare the codebase for **ROADMAP §2f/§2g
(async runtime)** and **ROADMAP §3c (QUIC)**. Restructures init,
module boundaries, and global state into shapes those phases can
build on cleanly.

**Not a new feature delivery.** Every phase is refactor + API
reshaping. Feature work resumes at ROADMAP §2f once this plan
completes.

---

## Status

**Started:** not yet.
**Prerequisites landed:** `b50f3a4` (uni::App) through `70a6f4a`
(apps/hello). Bench baseline captured below.
**Blocks:** ROADMAP §2f/§2g/§3c.

---

## Why this plan exists

The kernel auto-initializes every subsystem whether or not the app
needs it, AND every binary links every subsystem whether or not
the app references it:

- **Runtime cost:** DHCP retries, MB of TCP pool reserved at boot,
  8 scattered globals per subsystem.
- **Binary size:** hello world is 1.9 MB because the full TLS
  stack (~900 KB) + drivers + DHCP are always linked. `hello.img`
  ≈ `webserver.img` (delta ~16 KB).
- **Architectural debt:** 46 `static mut` across 16 files; driver
  state scattered across up to 9 separate atomics.

Once ROADMAP §2g lands an async executor, this becomes harder —
async code will hang off whatever shape exists. The cost of doing
it in the wrong shape first is rewriting twice. This plan gets the
shape right first.

---

## Design principles

### 1. One anchor per subsystem
Each subsystem with 3+ statics collapses to one `InitOnce<Anchor>`.
The `APP_SLOT` / `Box<dyn App>` pattern from `b50f3a4` is the template.

### 2. The crate IS the API
One or two public types per crate; implementation details stay
inside. Cross-crate extension happens via plain functions, not
extension traits (which hide methods from rustdoc).

### 3. Explicit dependencies in the type system
If a function requires some subsystem to be up, that's a parameter
(like `&Net`), not a global. Capability tokens proxy for side
effects but are visible in the signature.

### 4. POSIX shapes aren't destiny
No protection boundary, no syscall cost — don't owe backwards
compat to `listen/accept/recv/send`. Prefer:
- **Handler APIs over accept loops.** Framework runs the loop;
  app declares per-connection/per-request handlers.
- **Poll primitives over blocking calls.** `try_recv(buf) -> Option<usize>`
  as the core; sync/async versions both wrap it.
- **Transport-agnostic at the protocol layer.** `uni-http`
  doesn't know about TCP specifically; takes a trait-bounded
  transport. QUIC slots in the same way.

### 5. Each phase makes async easier
Every decision evaluated against "does this help §2g land
cleanly?" Target contributions:
- Poll-based primitive APIs
- Per-core arenas matching §2f's task-slot layout
- Capability tokens that become executor context objects

**Caveat:** phases 0-8 deliver *structural* shape (modular crates,
consolidated state, handler APIs). They don't speculate on §2g's
Waker design. §2g adds Waker hooks when it knows what it needs.

### 6. Perf invariant: neutral-or-better per phase
No phase lands if it regresses benchmarks by more than 2% (hard
gate on `health_max`, `udp_peak`, `health_tls_max`; others ±2%
tolerance for HVF noise). Mitigations documented per phase.

---

## Target crate layout (6 crates, not 13)

```
uni                    — core: App trait, uni::run, log, boot_info, #[uni::boot]
uni-net                — L3 + TCP + UDP + ARP + DHCP + static-IP
                         (internal submodules; one public boundary)
uni-http               — HTTP/1.1 over a transport
uni-tls                — TLS 1.3 config + wrapping functions
uni-driver-virtio-net  — VirtIO ethernet driver (QEMU, HVF, most VMs)
uni-driver-gve         — Google Virtual Ethernet driver (GCE) — renamed from gvnic
```

**Why 6, not 13:** earlier drafts split `uni-udp`, `uni-tcp`,
`uni-dhcp`, `uni-net-static` as separate crates. Each is 100-300
LOC — workspace overhead outweighs the "include what you use"
benefit at that grain. The big size wins come from:
- `uni-tls` (~900 KB — huge)
- Per-driver crates (~100 KB each)
- Deleting `uni-net` entirely for compute-only apps

Those benefits are captured by the 6-crate split. Finer grain
adds `Cargo.toml`/`BUILD.bazel`/rust-analyzer overhead without
proportional payoff.

Dependency graph:

```
uni ←── uni-net ←── uni-driver-virtio-net, uni-driver-gve
           ↑
        uni-http ←── uni-tls
```

Apps depend on the minimum they need:

| App | Deps | Binary target |
|---|---|---|
| compute | `uni` | ~400 KB |
| hello (plain HTTP) | `uni`, `uni-http`, `uni-driver-virtio-net` | ~1 MB |
| webserver (HTTP + TLS) | `uni`, `uni-http`, `uni-tls`, `uni-driver-{virtio-net,gve}` | ~2 MB |

---

## API boundaries

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
```

**Native:** works identically; `boot_info()` populates RAM/CPU from
sysctl on native.

### `uni-net`

```rust
pub struct Net { /* opaque */ }

// Constructor lives in uni-net; config comes in as an enum so
// DHCP vs static-IP is runtime-chosen without a separate crate.
pub enum NetBringUp {
    Dhcp,
    Static { ip: Ipv4Addr, gateway: Ipv4Addr, netmask: Ipv4Addr },
}

impl Net {
    pub fn enable(cfg: NetBringUp) -> Result<Net, NetError>;
    pub fn local_ip(&self) -> Ipv4Addr;
    pub fn listen_tcp(&self, port: u16) -> TcpListener;
    pub fn bind_udp(&self, port: u16) -> UdpSocket;
}

pub struct TcpListener { /* handler-based */ }
impl TcpListener {
    pub fn serve(&self, handler: impl Fn(TcpStream) + Send + Sync + 'static);
    // Async wrapper in §2g: `pub async fn accept(&self) -> TcpStream`
}

pub struct TcpStream { /* poll-based core */ }
impl TcpStream {
    pub fn try_recv(&mut self, buf: &mut [u8]) -> Option<usize>;
    pub fn try_send(&mut self, data: &[u8]) -> Option<usize>;
    // §2g wraps as async recv/send.
}
```

**Ethernet driver registration:** drivers implement the
`EthernetDriver` trait (defined in `uni-net`) and register at
link time by placing a registration struct in a dedicated linker
section (`.uni_drivers_ethernet`). `Net::enable` walks the
section to discover linked drivers and probes them in order.
See [Driver registration mechanism](#driver-registration-mechanism)
below for the full pattern.

**Native:** `Net` on native is a thin `libc::socket` wrapper;
same public API, different internal implementation via
`#[cfg(platform_native)]`.

### `uni-http`

```rust
pub struct Server { /* opaque */ }
impl Server {
    pub fn new_boxed(net: &Net) -> Box<Self>;
    pub fn route(&mut self, path: &[u8], handler: Handler);
    pub fn default_handler(&mut self, handler: Handler);
    pub fn listen(&mut self, port: u16);
}

pub type Handler = fn(&Request) -> Response;
// Request/Response types elided; unchanged from today
```

**Native:** uses `uni-net`'s native libc-socket backend
transparently.

### `uni-tls`

```rust
pub struct TlsServerConfig { /* opaque */ }
impl TlsServerConfig {
    pub fn from_dev_cert(cert_der: &[u8], pkcs8_key: &[u8]) -> Option<Self>;
}

// Plain function — not an extension trait.
pub fn listen_tls(server: &mut Server, port: u16, cfg: TlsServerConfig);
```

Apps write `uni_tls::listen_tls(&mut server, 443, cfg)`.
Cross-crate extension without trait gymnastics.

**Native:** pure crypto + state machine; identical on both
platforms.

### Driver crates

```rust
pub struct VirtioNetDriver;
impl uni_net::EthernetDriver for VirtioNetDriver { /* ... */ }
uni_net::register_ethernet_driver!(VirtioNetDriver);
```

**Native:** these crates have no native backend — they're
unikernel-only. Their `BUILD.bazel` uses a `select({})` to become
an empty target on native, so `uni-http` on native doesn't
transitively pull them.

---

## Driver registration mechanism

Driver crates plug into `uni-net` via dedicated linker sections —
same pattern Linux uses for `module_init`, FreeBSD for
`DRIVER_MODULE`, and embedded Rust for interrupt handlers. Each
driver crate places a `static` registration struct in a section
named after its subsystem. `uni-net::Net::enable` walks the
section at boot to discover linked drivers.

### Terminology: ethernet, not NIC

We name the trait `EthernetDriver` (not `NicDriver`) because the
trait's contract is specifically **ethernet frames in, ethernet
frames out**. Both virtio-net and gVNIC/gVE present as virtualized
ethernet NICs — they emit ethernet frames (14-byte header,
src/dst MAC, EtherType, payload). If we ever added wifi or
another L2, it'd need a separate trait (different frame format,
different state semantics like association / authentication),
not a unified "NIC" abstraction trying to cover both.

Naming by L2 protocol also clarifies the caller relationship:
`net/ethernet.rs` is the consumer; `EthernetDriver` implementers
are the producers. "NIC" is too vague — could be ethernet, wifi,
loopback, or virtual.

### Section naming: subsystem-scoped, not generic

Each subsystem owns its own section, named `.uni_drivers_<kind>`
or equivalent. For ethernet drivers that's `.uni_drivers_ethernet`.
The suffix matters: it leaves the naming open for future
subsystems without requiring a refactor.

Not planned but enabled by the naming:

| Subsystem | Section | If ever added |
|---|---|---|
| Ethernet drivers | `.uni_drivers_ethernet` | Phase 5 below |
| Block storage | `.uni_drivers_block` | future |
| Filesystems | `.uni_filesystems` | future |
| IP protocols | `.uni_protocols` | possibly Phase 2 |
| WiFi (if ever) | `.uni_drivers_wifi` | hypothetical |

Each has its own registration type (`EthernetDriverReg`, future
`BlockDriverReg`, etc.) and its own macro
(`register_ethernet_driver!`, future `register_block_driver!`).
Type safety stays local to the subsystem; no shared cross-type
section.

**This plan only implements `.uni_drivers_ethernet`.** The other
sections are future work if/when those subsystems materialize.
Naming is reserved now to avoid a rename later.

### How it works for ethernet drivers

```rust
// uni-net/src/driver.rs

pub trait EthernetDriver: 'static + Sync {
    fn name(&self) -> &'static str;
    fn probe(&self) -> Option<NicHandle>;
    fn send(&self, h: &NicHandle, frame: &[u8]) -> Result<(), NicError>;
    fn poll_rx(&self, h: &NicHandle, cb: &mut dyn FnMut(&[u8])) -> usize;
}

#[repr(C)]
pub struct EthernetDriverReg {
    pub driver: &'static dyn EthernetDriver,
}

#[macro_export]
macro_rules! register_ethernet_driver {
    ($driver:expr) => {
        #[unsafe(link_section = ".uni_drivers_ethernet")]
        #[used]
        static ETHERNET_DRIVER_REG: $crate::EthernetDriverReg = $crate::EthernetDriverReg {
            driver: &$driver,
        };
    };
}

// Walker — the one unsafe block. Generalizes to future subsystems
// via the same pattern (different section name + type).
extern "Rust" {
    static __start_uni_drivers_ethernet: EthernetDriverReg;
    static __stop_uni_drivers_ethernet: EthernetDriverReg;
}

fn linked_ethernet_drivers() -> &'static [EthernetDriverReg] {
    unsafe {
        let start = &__start_uni_drivers_ethernet as *const EthernetDriverReg;
        let end = &__stop_uni_drivers_ethernet as *const EthernetDriverReg;
        let count = end.offset_from(start) as usize;
        core::slice::from_raw_parts(start, count)
    }
}

impl Net {
    pub fn enable(cfg: NetBringUp) -> Result<Net, NetError> {
        let drivers = linked_ethernet_drivers();
        if drivers.is_empty() {
            return Err(NetError::NoDriver);
        }
        for reg in drivers {
            if let Some(handle) = reg.driver.probe() {
                return build_net(reg.driver, handle, cfg);
            }
        }
        Err(NetError::NoNic)
    }
}
```

### Linker script addition

Each target-specific linker script gets:

```
.uni_drivers_ethernet : ALIGN(8) {
    __start_uni_drivers_ethernet = .;
    KEEP(*(.uni_drivers_ethernet))
    __stop_uni_drivers_ethernet = .;
}
```

`KEEP` preserves entries even with no incoming symbol references.
`__start_*` / `__stop_*` are linker-auto-generated boundaries.

Affected scripts (all exist today):
- `bazel/toolchain/unikernel_x86_64.ld`
- `bazel/toolchain/unikernel_aarch64.ld`
- `bazel/toolchain/unikernel_limine.ld`

Each gets ~5 lines. If a future subsystem is added, that subsystem
adds its own section to the same scripts. No churn to the pattern.

### Why this approach

- **Zero runtime registration overhead.** The "registry" IS the
  ELF section. No `Vec<Box<dyn Driver>>`, no ctor machinery.
- **Automatic opt-in.** If the crate isn't in `deps`, its
  registration struct isn't linked, isn't in the section, isn't
  probed. No code changes needed when dropping a driver.
- **Compatible with `*-unknown-none`.** No reliance on C-style
  constructors firing at process start (which our target doesn't
  do without explicit boot code).
- **One unsafe block per subsystem.** Section-boundary walk is
  documented + small. Everything else (trait impls, registration
  macro) is safe Rust.
- **Empty section is empty.** Compute-only app with no driver
  crates linked: `__start_* == __stop_*`, `linked_ethernet_drivers()`
  returns empty slice, `Net::enable` returns `NoDriver`
  immediately. Zero wasted bytes.

### Why NOT a single generic `.uni_drivers` section

Earlier draft used `.uni_drivers` (no suffix). Problem: it's
generic-sounding but has subsystem-specific contents. If a
future `BlockDriver` also targets `.uni_drivers`, the section
would mix types and every consumer would need runtime
discriminators. Type safety per subsystem breaks.

Per-subsystem sections preserve type safety at the cost of one
linker-script line per subsystem. That's the right trade.

---

## Migration phases (in execution order)

Phases numbered to match execution order. Effort + async-prep +
perf + test notes per phase.

### Phase 0: `uni::boot_info()`

Populate a `BootInfo` struct in `kernel::entry` after ACPI/FDT
parsing + NIC discovery. Expose via `uni::boot_info()`. Apps
optionally use it in their constructors.

- **Effort:** 1-2 d
- **Async prep:** §2g's executor takes `&BootInfo` at init for
  per-core sizing
- **Perf:** neutral (data populated at boot, read on demand)
- **Test:** add a host-native unit test that constructs a
  `BootInfo` with representative values and asserts accessors;
  add a webserver integration check that logs `boot_info()` and
  greps the serial output

### Phase 1: Error types

Design a shared error hierarchy before any crate splits. Defining
errors up-front means later crate carveouts don't each invent
incompatible enums that have to be unified later.

Add `uni-kernel::error` (or similar) with:

```rust
pub enum NetError { NoNic, Dhcp(DhcpError), Driver(&'static str), ... }
pub enum DhcpError { Timeout, BadReply, NoOffer, ... }
pub enum NicError { ... }
pub enum TlsError { ... }  // already exists in net/tls_server.rs
```

Document `From` impls between them (`From<DhcpError> for NetError`,
`From<NicError> for NetError`).

- **Effort:** 1-2 d
- **Async prep:** errors flow through `Result<T, _>` async
  signatures naturally
- **Perf:** neutral (just types + impls)
- **Test:** unit tests for `From` chains; ensure size_of each
  error is ≤ 2 pointers to avoid bloating `Result<_, E>` call sites

### Phase 2: `Net` structural prep (no API change yet)

Sub-phase that sets up the protocol registry and hot-path
`InitOnce<PerCore<…>>` wrappers without changing any public API.
Auto-init still runs; `Net::enable_*` doesn't exist yet.

What this does:
- Wrap `net::tcp::CONNECTIONS`, `net::arp::ARP_FAST`,
  `net::ipv4::IP_ID_PERCORE` in `InitOnce<PerCore<…>>`. Memory
  isn't reserved at kernel boot; it's claimed on first call from
  `net::init_stack()` (which auto-init still invokes).
- Introduce `net::protocol::Registry` — a small struct with
  `register(proto: u8, handler: fn(pkt))` method. Have TCP and
  UDP register through it instead of hardcoded dispatch in
  `net::lib::net_receive()`.

No user-visible change. Pure internal refactor.

- **Effort:** 2 d
- **Async prep:** the protocol registry is the dispatch point
  async RX will hook
- **Perf:** neutral — must verify. Risk: `InitOnce::get()` is
  an atomic load instead of static-address dereference.
  Mitigation: amortize per hot function (`let pools = CONNECTIONS.get()`
  at the top, subsequent accesses direct). Validate with
  `health_max` + `udp_peak` benchmarks.
- **Test:** unit test the protocol registry (register, receive,
  unregister). `static_mut` count shouldn't change.

### Phase 3: `Net::enable_*` + migrate apps

Introduce the `Net::enable(NetBringUp)` API. Auto-init still runs
as fallback for apps that don't call it. Migrate in-tree apps
(webserver, hello) to use `Net::enable` explicitly.

Test apps (test_smp, test_percpu, test_tls) don't need networking
— no change.

- **Effort:** 2 d
- **Async prep:** `Net` now owns protocol registry from Phase 2
- **Perf:** neutral — `Net::enable` is boot-path only
- **Test:** integration test that `Net::enable(NetBringUp::Static { ... })`
  skips DHCP; integration test that omitting it falls back to
  auto-init (the existing behavior)

### Phase 4: Delete auto-init, consolidate globals into `Net`

Remove the kernel-level auto-init path. Move the remaining
scattered globals into `Net`:

- `net::types::CONFIG` → `Net.config`
- `net::udp::HANDLER_*` → `Net.udp_handlers`
- `net::dhcp::DHCP_STATE` → `Net.dhcp_state`
- `net::lib::{MULTICORE_INIT, WAKEUP, RX_LOCK, JUST_DISTRIBUTED}`
  → `Net.dispatcher`
- `uni::http::SERVER_PTR` / `TLS_CONFIG_PTR` → fields on `Server`
  / `TlsServerConfig`

After this phase, apps that don't call `Net::enable` get no
network. 8 global slots collapse to 1 (`NET: static Option<Box<Net>>`).

- **Effort:** 2-3 d
- **Async prep:** Net is the single anchor; async executor's
  network bindings reach state through `Net::current()`
- **Perf:** neutral. Hot-path arrays still `InitOnce<PerCore<…>>`
  from Phase 2; Net just holds a `&'static` reference.
- **Test:** run webserver integration test; check that
  `NET.is_none()` before `Net::enable` returns and after app
  exits; unit test: `Net::enable` twice returns `Err`

### Phase 5: Ethernet driver carveouts + state consolidation

Splits `drivers/virtio_net.rs` and `drivers/gvnic.rs` into
`uni-driver-virtio-net` and `uni-driver-gve` crates. Each driver
crate collapses its scattered state into ONE `InitOnce<Driver>`
anchor implementing `EthernetDriver`, and registers itself via
`uni_net::register_ethernet_driver!(Driver)`.

**gvnic → gve rename, as part of this phase.** `drivers/gvnic.rs`
is Google's driver; Linux calls it `gve` (Google Virtual
Ethernet), and Google uses "gve" for the driver and "gVNIC" for
the product. To match Linux convention and avoid conflating the
driver with the NIC, the file becomes `gve.rs` and the crate
becomes `uni-driver-gve`. `uni-driver-virtio-net` keeps its name
(matches VirtIO spec terminology).

**Prerequisites (land as part of this phase, BEFORE carving):**

1. `EthernetDriver` trait + `EthernetDriverReg` + `register_ethernet_driver!`
   macro land in `uni-net`. See the
   [Driver registration mechanism](#driver-registration-mechanism)
   section above for the concrete code.
2. `.uni_drivers_ethernet` section added to all three unikernel linker
   scripts (`unikernel_x86_64.ld`, `unikernel_aarch64.ld`,
   `unikernel_limine.ld`) — ~5 lines each.
3. `Net::enable` walks the section to find drivers.

With those in place, carving each driver is a move-and-register
operation: move files into the new crate, impl `EthernetDriver`,
add one `register_ethernet_driver!` line at module root.

No `register_rx_waker` stub on the trait — §2g adds that when
it designs the Waker layer.

Multi-driver shape: apps depend on both driver crates directly.
First-success-wins in `Net::enable`'s probe order. No meta-crate
needed.

- **Effort:** 3-4 d
- **Async prep:** driver state is now in a clean struct; §2g
  can add Waker hooks as fields later without touching the
  public EthernetDriver trait
- **Perf:** neutral. Single-driver apps get direct calls
  through the section walk's single indirect call per packet
  (~1-2 ns, below bench-noise floor). Multi-driver apps pay
  same per-packet cost (one `&dyn EthernetDriver` call). Must
  confirm with isolated micro-bench: 1M calls of
  `driver.send(&frame)` with one vs. multiple drivers linked,
  compare to today's direct-dispatch baseline.
- **Test:** `register_ethernet_driver!` macro unit tests (section
  boundary detection with 0 / 1 / 2 registered drivers);
  verify `Net::enable` returns `NoDriver` cleanly when zero
  crates linked; verify single-driver app probes successfully;
  verify two-driver app probes in link order.

### Phase 6: `uni-tls` carveout

Move `net/tls_*` into a new `uni-tls` crate. Expose TLS via a
plain function `uni_tls::listen_tls(&mut Server, port, cfg)` —
not an extension trait.

Apps that don't need TLS drop `uni-tls` from deps. Hello becomes
~1 MB (down from 1.9 MB).

- **Effort:** 4 d
- **Async prep:** TLS state machine is sans-io; §2g wraps
  `tls.advance()` in an async frame
- **Perf:** neutral for TLS workloads (same code path). ~900 KB
  binary reduction for non-TLS apps — biggest single binary win.
- **Test:** the existing TLS integration test (apps/test_tls)
  stays valid; webserver integration test keeps running;
  verify `bazel build //apps/hello:hello --config=hvf` succeeds
  without uni-tls dep

### Phase 7: `static_mut` sweep + virtio-console consolidation

46 `static mut` → 0. Each migrates to:
- `InitOnce<T>` (publish-once)
- `Spinlock<T>` (shared mutable)
- `UnsafeCell<T>` + `unsafe impl Sync` (single-threaded by contract)

Includes `drivers/virtio_console.rs`'s 12 statics → one
`InitOnce<VirtioConsole>`.

- **Effort:** 3-4 d
- **Async prep:** clean state layout for §2g to hang Waker slots
  off of
- **Perf:** neutral. `InitOnce::get()` is an atomic load; same
  cost as static access after first init.
- **Test:** CI check that `rg '^\s*static mut' src/` returns 0.
  Each converted file keeps its existing tests; add specific
  tests for formerly-unsafe invariants where practical (e.g.,
  "GDT entries don't change after `init`")

### Phase 8: Event-loop hooks + opt-in SMP

Combined because they're both additive event-loop extensions.

- `uni::on_idle(f)` and `uni::on_tick(f)` for apps injecting
  background work
- `uni::smp::enable()` brings up APs; otherwise they stay parked.
  Single-core apps drop SMP bring-up from the boot path and arch
  multi-core machinery from the binary.

- **Effort:** 4-5 d
- **Async prep:** hooks become §2g reactor primitives
- **Perf:** additive-neutral for enabled; single-core apps save
  boot time (not measured by current bench)
- **Test:** integration test for single-core boot skipping AP
  bring-up (measure boot-log milestones); unit test for
  multiple `on_tick` callbacks composing

---

## Progress tracker

### Baseline (commit 70a6f4a, 2026-04-20)

Measured via `python3 scripts/bench.py --env hvf --cores 1`:

| Workload | Baseline | Gate |
|---|---|---|
| health_c1 | 35,500 req/s | ±2% |
| compute_c1 | 6,500 req/s | ±2% |
| **health_max** | **194,000 req/s** | **hard, ±2%** |
| compute_max | 8,000 req/s | ±2% |
| udp_sync | 32,000 pkt/s | ±2% |
| **udp_peak** | **184,000 pkt/s** | **hard, ±2%** |
| health_tls_c1 | 28,000 req/s | ±2% |
| **health_tls_max** | **124,000 req/s** | **hard, ±2%** |
| tls_handshake_max | 3,300 hs/s | ±2% |

Binary sizes (HVF `.img`): hello 1.9 MB, webserver 2.0 MB.
`static_mut` count: 46 across 16 files.

### Per-phase status

| # | Phase | Status | Regression | Bin Δ | Notes |
|---|---|---|---|---|---|
| 0 | boot_info | ⏳ | — | — | |
| 1 | error types | ⏳ | — | — | |
| 2 | Net structural prep | ⏳ | — | — | |
| 3 | Net::enable | ⏳ | — | — | |
| 4 | delete auto-init | ⏳ | — | — | |
| 5 | NIC driver carveouts | ⏳ | — | — | |
| 6 | uni-tls carveout | ⏳ | — | -900 KB expected | |
| 7 | static_mut sweep | ⏳ | — | — | |
| 8 | hooks + SMP opt-in | ⏳ | — | — | |

Status legend: ⏳ not started · 🟡 in progress · 🟢 complete · 🔴 blocked

---

## Validation protocol

Each phase's PR must include:

### Benchmark diff

```bash
# Before starting phase:
git checkout <phase-base>
python3 scripts/bench.py --env hvf --cores 1 > bench-phaseN-before.txt

# After phase:
python3 scripts/bench.py --env hvf --cores 1 > bench-phaseN-after.txt
diff bench-phaseN-before.txt bench-phaseN-after.txt
```

**Hard gate:** `health_max`, `udp_peak`, `health_tls_max` regressions
> 2% are stop-the-line.

### Targeted micro-benchmarks

Phases with localized perf risk add a dedicated micro-bench:

- **Phase 2:** `InitOnce::get()` × 1M vs. direct-static access.
  Threshold: ≤ 3ns/iter difference.
- **Phase 5:** `EthernetDriver::send()` indirect vs. direct. Single-
  driver link: zero delta expected. Multi-driver: ≤ 2ns/iter.

These are Rust `#[bench]`-style tests under `bazel test`, not
scripts/bench.

### Test coverage

Each phase's section above includes a **Test:** line. PRs must
include those tests or a written rationale for omission.

### Binary size

```bash
bazel build --config=hvf //apps/hello:hello //apps/webserver:webserver
ls -l bazel-bin/apps/{hello,webserver}/*.img
```

Size regressions: hello ≤ 50 KB, webserver ≤ 100 KB, except
Phase 6 which should REDUCE hello by ~900 KB.

### `static_mut` trajectory

```bash
rg --stats '^\s*static mut\s+\w+' kernel/ uni/ net/ drivers/ apps/ boot/
# Phase 0-6: non-increasing
# Phase 7: drops to 0
```

---

## Hand-off to ROADMAP

After Phase 8, feature work resumes:

- **ROADMAP §2f** — Task trait + pinned task slots
- **ROADMAP §2g** — Async/await executor (the big one)
- **ROADMAP §3c** — QUIC (§2g's first real consumer)
- **ROADMAP §4** — HTTP/3
- **ROADMAP §5** — IPv6 + NDP

The async-prep notes on each phase document exactly what this
plan contributes to §2g.

---

## When to start

Triggers (none active as of 2026-04-20):
- Starting ROADMAP §2f/§2g async work
- Binary-size pressure on a specific deployment
- A compute-only app materializing
- `static_mut` tech debt causing concrete issues

Session prompt to start:

```
Implement the init redesign starting with Phase 0. Plan:
docs/init-redesign.md. Baseline bench numbers + per-phase
tracker at the bottom of the plan. Each phase is an independent
PR; each must pass the Validation protocol before merging.
Update the Progress tracker table as phases land.
```

---

## Appendix: target app shapes after Phase 8

### `apps/hello/main.rs`

```rust
#![no_std]
extern crate alloc;
extern crate uni;
use uni::http::{Server, Request, Response};
use uni_net::{Net, NetBringUp, Ipv4Addr};

struct HelloApp {
    _server: alloc::boxed::Box<Server>,
    _net: Net,
}
impl uni::App for HelloApp {}

impl HelloApp {
    fn new() -> Self {
        let net = Net::enable(NetBringUp::Static {
            ip: Ipv4Addr([10, 0, 2, 15]),
            gateway: Ipv4Addr([10, 0, 2, 2]),
            netmask: Ipv4Addr([255, 255, 255, 0]),
        }).unwrap();

        let mut server = Server::new_boxed(&net);
        server.default_handler(|_| Response::ok(b"text/plain", b"Hello!\n"));
        server.listen(uni::config_port(80));

        HelloApp { _server: server, _net: net }
    }
}

#[uni::boot]
fn boot() { uni::run(HelloApp::new()); }
```

Deps: `uni`, `uni-net`, `uni-http`, `uni-driver-virtio-net`.
Binary: ~1 MB.

### `apps/webserver/main.rs`

```rust
let net = Net::enable(NetBringUp::Dhcp).expect("DHCP failed");
let mut server = Server::new_boxed(&net);
server.default_handler(handle_request);
server.listen(uni::config_port(80));
if let Some(cfg) = TlsServerConfig::from_dev_cert(CERT, KEY) {
    uni_tls::listen_tls(&mut server, uni::config_port(443), cfg);
}
```

Deps: all 6 crates. Binary: ~2 MB.

---

## Post-plan: what async looks like (ROADMAP §2g territory)

For reference — NOT part of this plan's scope.

### User-facing shape: async lifecycle on the App trait

The kernel's scheduler becomes an async runtime in §2g, so the
App trait grows async lifecycle methods. User code keeps the same
structural shape we landed on in this plan:

```rust
struct HelloApp {
    server: alloc::boxed::Box<Server>,
    net: Net,
}

impl uni::App for HelloApp {
    async fn start(&mut self) {
        // Spawn the HTTP server as a persistent background task.
        // `uni::spawn` adds it to the executor's task arena; the
        // runtime polls all spawned tasks until they complete or
        // shutdown fires.
        uni::spawn(self.server.serve(80));
    }

    async fn stop(&mut self) {
        // Graceful drain: close the listener, let in-flight
        // requests finish. Executor polls this to completion
        // before calling Drop.
        self.server.shutdown().await;
    }
}

impl HelloApp {
    fn new() -> Self {
        let net = Net::enable(NetBringUp::Dhcp).expect("DHCP failed");
        let server = Server::new_boxed(&net);
        HelloApp { server, net }
    }
}

#[uni::boot]
fn boot() {
    uni::run(HelloApp::new());
}
```

The App trait's async methods default to empty, so simple apps
(plain marker impl + `new` + Drop) still work unchanged:

```rust
// Trait sketch (§2g lands this):
pub trait App: 'static {
    fn start(&mut self) -> impl Future<Output = ()> + Send { async {} }
    fn stop(&mut self) -> impl Future<Output = ()> + Send { async {} }
}
```

### Runtime lifecycle

The four-stage runtime model:

```
1. Sync boot (BSP):
      uni_main() → uni::run(MyApp::new())
         → APP_SLOT ← Box<app>

2. Runtime polls lifecycle:
      app.start().await       ← on executor; can spawn tasks

3. Runtime drives task arena:
      loop { arena.poll_all(); if shutdown { break } }
      ← spawned server task, timer tasks, etc. run here

4. Shutdown signaled:
      app.stop().await         ← graceful drain, await in-flight
      drop(app)                ← field Drop cascade
```

`start` spawns persistent tasks and returns. `stop` awaits them
to drain. Drop runs after `stop` completes, using the ordering
Phase 8 already established.

### Why `start`/`stop`, not `boot().await`

Embassy/Tokio conventions put everything inside an `async fn main`
that runs until done. That shape works but loses the App trait we
invested in:

- `serve(80).await` at top level = no typed app handle; no
  structured lifecycle transitions; multiple services need explicit
  `join!`/`select!`
- `App::start`/`stop` = typed app as the central anchor;
  transitions are named events; multiple services compose via
  `uni::spawn` within `start`

The `App` trait with async lifecycle methods preserves everything
Phases 0-8 built. `serve(80).await` is an internal building block
that lives *inside* a `start` method or a spawned task, not at
the top level of user code.

### What §2g adds on top of Phase 8

- Task arena + `uni::spawn(fn)` (ROADMAP §2f)
- Executor driving `app.start().await` / `app.stop().await`
- Waker hooks on poll-based primitives Phases 2-6 already delivered
- `#[uni::boot]` macro gains an async-aware `uni::run` variant;
  the user's `fn boot()` stays sync (just constructs + hands off)

No restructuring of types, no new module boundaries — async is
additive on top of the structural shape this plan delivers.
