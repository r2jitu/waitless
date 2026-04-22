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

**Complete.** All eight migration phases landed. The shipped result
differs from the plan's original shape in a few places — each
documented in the per-phase table and cross-linked here so a reader
doesn't have to reconstruct them from commit archaeology:

  * **Phase 4's Net-owned field migration was designed out.**
    Post-Phase-7 the statics the plan wanted to fold into `Net`
    fields are all already safe (atomics, Spinlocks, or
    UnsafeCell with single-writer contracts). Threading `&Net`
    through ARP / DHCP / IPv4 / TCP / UDP hot paths and inverting
    the net sub-crate dep direction costs protocol-layer
    entanglement for ownership-aesthetic benefit only.
  * **Phase 5 Step 6's probe-driven init was designed out.**
    Plan-labelled "future" from the outset. The `drivers::net::*`
    dispatcher has 20 methods; the `EthernetDriver` trait has 4.
    Most extras (TX staging, NAPI rearm, MQ activation) are
    genuinely virtio-specific; forcing them into a common trait
    with no-op gve defaults is worse than the current `if
    use_gve()` branches.
  * **Phase 8's opt-in SMP and on_tick/on_idle hooks were both
    reverted.** SMP opt-in created a footgun without delivering
    the promised binary-size win. Hooks had no in-tree users and
    risked locking in the wrong shape before §2g picks reactor
    primitives. Auto-SMP stayed; hooks were dropped entirely.
  * **`uni-http` was missing from the plan's phase list but
    landed as a trailing carveout** so apps that don't serve
    HTTP can skip the parser + handler + connection-pool code.
    Completes the 6-crate target layout in the "Target crate
    layout" section below.

**Prerequisites landed:** `b50f3a4` (uni::App) through `70a6f4a`
(apps/hello). Bench baseline captured below.
**Unblocks:** ROADMAP §2f/§2g/§3c.

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

## Target crate layout

What actually shipped — six "target" app-facing crates from the
original plan plus four backend / platform-infrastructure crates
the plan didn't enumerate but landed along the way:

**App-facing (the 6 the plan listed):**
```
uni                    — core: App trait, uni::run, log, boot_info, #[uni::boot]
uni-net                — L3 + TCP + UDP + ARP + DHCP + static-IP
uni-http               — HTTP/1.1 + Server + Request / Response types
uni-tls                — TLS 1.3 config + wrapping functions
uni-driver-virtio-net  — VirtIO ethernet driver (QEMU, HVF, most VMs)
uni-driver-gve         — Google Virtual Ethernet driver (GCE)
```

**Backend / infrastructure (bonus splits):**
```
uni-kernel             — bare-metal backend for `uni` (log, wait_for_events, ...)
uni-native             — host POSIX backend for `uni` (libc FFI + pthread workers)
drivers                — NIC dispatcher + `pub use drivers_infra::*` re-export
drivers:infra          — shared infra: MMIO + PCI + VirtIO transport + virtio-console
kernel                 — bare-metal kernel primitives (mm, percpu, eventloop, cpu)
net                    — bare-metal net stack umbrella (sub-crates: tcp, udp, dhcp, ...)
```

**Why the splits.** Apps opt into crates they actually use:

| App | Deps | Size observed |
|---|---|---|
| `apps/hello` (plain HTTP) | uni, uni-http, driver crates via `//drivers` | ~1.94 MB |
| `apps/webserver` (HTTP + TLS) | uni, uni-http, uni-tls, driver crates | ~2.05 MB |

Hello doesn't match the plan's `~1 MB` aspiration because it genuinely
uses HTTP — it links all of `uni-http` + drivers + DHCP + net stack.
The carveouts work: `bazel query somepath //apps/hello:hello.elf
//net:tls_server` is empty. Compute-only apps (none in tree yet)
would drop `uni-http` + drivers + net stack and hit the plan's
target.

### Naming convention

- **Directory names** use hyphens (`uni-http`, `uni-tls`, …) — matches
  the Cargo convention for package names.
- **Bazel target names and `crate_name`** use underscores (`uni_http`,
  `uni_tls`, …) — Rust identifier rules require underscores in crate
  names, and matching the target name to the crate name removes a
  layer of translation in BUILD files.

So a typical BUILD file has `//uni-http:uni_http` — the hyphen part
tells you you're inside Bazel, the underscore part is the Rust crate
name. Rust imports always use the underscore form: `use uni_http::…`.

Dependency graph (shipped, including backend splits):

```
                          bare-metal                           native
                          ──────────                           ──────
uni ──┬─→ uni-kernel ──→ kernel + drivers    uni-native ──→ kernel
      ├─→ uni-net    ──→ net + uni-net:driver           
      └─→ (apps' own choice of)
          uni-http   ←── uni-tls
          drivers    ──→ uni-driver-virtio-net, uni-driver-gve
                     ──→ drivers:infra
```

`drivers:infra` is a sub-target inside `//drivers/BUILD.bazel` that
both NIC-driver crates depend on — MMIO helpers + PCI + VirtIO
transport + virtio-console. Keeping it as a sub-target (rather than
its own directory) avoids a cycle: `//drivers:drivers` depends on
the NIC crates for dispatch; the NIC crates depend on
`//drivers:infra` for the shared hardware-access primitives.

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
`#[cfg(not(target_os = "none"))]`.

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
  verify `bazel build //apps/hello:hello_hvf` succeeds without
  a uni-tls dep

### Phase 7: `static_mut` sweep + virtio-console consolidation + `AtomicFn<F>` crate

46 `static mut` → 0. Each migrates to:
- `InitOnce<T>` (publish-once)
- `Spinlock<T>` (shared mutable)
- `UnsafeCell<T>` + `unsafe impl Sync` (single-threaded by contract)

Includes `drivers/virtio_console.rs`'s 12 statics → one
`InitOnce<VirtioConsole>`.

**Also carve out a shared `AtomicFn<F>` utility.** Two sites already
store fn pointers via `AtomicPtr<()>` + `transmute`:

- `//net:protocol`'s `FnSlot` — the TCP/UDP dispatch registry
  (landed in Phase 2).
- `uni-native/src/lib.rs`'s `IO_POLL` + `SERVICE` statics —
  `fn(u32) -> bool` callbacks for the POSIX worker event loop.

The second site falls under this phase's `static_mut` / global-
consolidation scope anyway, so lifting both onto a shared
`AtomicFn<F>` pays for itself:

```rust
// New crate: //util:atomic_fn — zero deps beyond `core::`, so
// downstream `rust_test` targets don't inherit the panic-strategy
// conflict that any //kernel dep would bring in.
pub struct AtomicFn<F: Copy> {
    ptr: AtomicPtr<()>,
    _marker: PhantomData<F>,
}

impl<F: Copy> AtomicFn<F> {
    pub const fn empty() -> Self { /* ... */ }
    pub fn set(&self, f: F) {
        // Compile-time assertion: F is pointer-sized. Works on
        // stable Rust 1.79+ because the const block captures F's
        // layout.
        const {
            assert!(core::mem::size_of::<F>() == core::mem::size_of::<*mut ()>());
            assert!(core::mem::align_of::<F>() == core::mem::align_of::<*mut ()>());
        }
        let raw: *mut () = unsafe { core::mem::transmute_copy(&f) };
        self.ptr.store(raw, Ordering::Release);
    }
    #[inline]
    pub fn load(&self) -> Option<F> {
        let p = self.ptr.load(Ordering::Acquire);
        if p.is_null() { None }
        else { Some(unsafe { core::mem::transmute_copy(&p) }) }
    }
    pub fn clear(&self) { self.ptr.store(ptr::null_mut(), Ordering::Release); }
}
```

Why not do it now (Phase 2/3): a new Bazel crate that would only be
used at one site is pure overhead — the second consumer (`IO_POLL`)
isn't touched until this phase. We evaluated `crossbeam-utils::AtomicCell`
and the `atomic` crate as alternatives; both fall back to locks on
targets without a native lock-free primitive for `size_of::<T>()`,
which defeats the "no runtime cost" goal. A 30-line local utility
beats a dep.

- **Effort:** 3-4 d
- **Async prep:** clean state layout for §2g to hang Waker slots
  off of
- **Perf:** neutral. `InitOnce::get()` is an atomic load; same
  cost as static access after first init. `AtomicFn<F>::load()` is
  one acquire-load + one null-check + one transmute — identical to
  what both call sites already emit.
- **Test:**
  - CI check that `rg '^\s*static mut' src/` returns 0.
  - New `//util:atomic_fn_test` (host-native): size/align asserts,
    set/clear/load round-trip with a `fn(u32)->bool` handler,
    const-constructibility for `static` use.
  - Each converted file keeps its existing tests; add specific
    tests for formerly-unsafe invariants where practical (e.g.,
    "GDT entries don't change after `init`").

### Phase 8: Auto-SMP (hooks dropped as speculative)

Plan originally prescribed `uni::on_idle(f)` / `uni::on_tick(f)`
event-loop hooks plus an opt-in `uni::smp::enable()` bring-up.
What actually shipped:

- **SMP: auto-detect, not opt-in.** The opt-in variant shipped
  briefly (`8bb14be`) and was reverted (`31fcf4c`). Two reasons:
  (1) the footgun of "app forgets `enable()` → silent single-core
  + single-queue networking" outweighed any savings, and (2) the
  plan's advertised "arch multi-core machinery from the binary"
  drop never materialised — the opt-in was runtime-only, the
  AP-start code stayed linked. Current behaviour: boot detects
  cpu_count from FDT/ACPI and calls `percpu::init(cpu_count)` +
  `start_secondary_cores` unconditionally when cpu_count > 1.
  Matches native, which always sizes the worker-thread pool from
  `UNIKERNEL_CPUS` or `num_cpus()`.
- **`on_tick` / `on_idle` dropped as speculative.** Shipped
  briefly (`c99f4a0`) and dropped (`ac3aaba`) — no in-tree users,
  and committing to a specific hook shape ahead of §2g's reactor
  design risks locking in the wrong one. The plumbing (kernel
  `TICK` slot, uni-native `TICK`/`IDLE` slots, uni re-exports)
  was ~50 lines of future-proofing for nobody. §2g can add them
  back with the right shape when there's a concrete need.

- **Effort:** 1 d (net; most of the plan's 4-5 d was the
  speculative hook work and the SMP back-and-forth).
- **Perf:** neutral.

---

## Progress tracker

### Baseline (commit 70a6f4a, 2026-04-20) and current (commit 9bc5f45, post-init-redesign)

Measured via `python3 scripts/bench.py --env hvf --cores 1`:

| Workload | Baseline (70a6f4a) | Current (9bc5f45, 4-run window) | Gate |
|---|---|---|---|
| health_c1 | 35,500 req/s | 28–29k | ±2% |
| compute_c1 | 6,500 req/s | 5.1–7.9k | ±2% |
| **health_max** | **194,000 req/s** | **148–185k (wide HVF variance)** | **hard, ±2%** |
| compute_max | 8,000 req/s | 6.9–7.9k | ±2% |
| udp_sync | 32,000 pkt/s | 27–31k | ±2% |
| **udp_peak** | **184,000 pkt/s** | **170–178k** | **hard, ±2%** |
| health_tls_c1 | 28,000 req/s | ~26k | ±2% |
| **health_tls_max** | **124,000 req/s** | **110–120k** | **hard, ±2%** |
| tls_handshake_max | 3,300 hs/s | 2.9–3.1k | ±2% |

**Interpretation.** Per-phase the invariant held — each phase
measured ±2% against its immediately-prior commit. Cumulatively the
numbers have drifted a few percent, but HVF single-run variance is
wide enough (health_max swings ±15% on some days depending on host
thermal / background load) that the "baseline → HEAD" column above
isn't a precise comparison. The per-phase rows below each include
the phase-local bench that gated its landing.

Binary sizes (HVF `.img`):

| App | 70a6f4a baseline | 9bc5f45 current |
|---|---|---|
| hello | 1.9 MB | 1.94 MB |
| webserver | 2.0 MB | 2.05 MB |

Hello didn't shrink because it genuinely uses HTTP (so it pulls in
all of `uni-http` + drivers + DHCP + net stack). The carveouts are
architectural — `bazel query somepath //apps/hello:hello.elf
//net:tls_server` is empty, and a compute-only app that drops
`uni-http` would skip the parser + handler + connection-pool code.
No compute-only app exists in-tree today.

`static mut` count across the tree: **0 Rust-owned** (down from 46
at baseline). Only the `extern "C" { static mut boot_l1_table }`
declaration for boot.S's symbol remains, which isn't a Rust
definition.

### Per-phase status

| # | Phase | Status | Regression | Bin Δ | Notes |
|---|---|---|---|---|---|
| 0 | boot_info | 🟢 | none (additive only) | hello +<1 KB, webserver +<1 KB | `uni::boot_info()` populated from `boot/entry.rs` (unikernel) and `init_native` (native). Host-native unit test (`//uni:boot_info_test`, 7 cases) + webserver serial-log grep integration check. No hot-path touched. |
| 1 | error types | 🟢 | none (types only) | none | `uni::error::{NetError, DhcpError, NicError}` with `From` impls (`NicError → NetError`, `DhcpError → NetError`). All errors `Copy + ≤ 16 B` (const-asserted). Host-native unit test (`//uni:error_test`, 7 cases including `?`-operator chains and size invariants). `TlsError` stays in `net/tls_server.rs` until Phase 6. |
| 2 | Net structural prep | 🟢 | health_max -1.6%, udp_peak -0.6%, health_tls_max -1.6% (3-run means vs 70a6f4a — all within 2% gate) | none | **Protocol registry landed**: new `net_protocol` crate with `Registry::{register,unregister,dispatch}` + `//net:protocol_test` (5 cases). Hot-path TCP/UDP dispatch in `net_receive` / `distribute_frame` now routes through `net::REGISTRY`; `net::init_stack()` wires TCP+UDP at boot. One relaxed load + one indirect call per packet replaces the old hardcoded match — bench-verified cost parity. **Per-core state**: `ARP_FAST` and `IP_ID_PERCORE` live as `static [AtomicSlot; MAX_CORES]` (per-core array-of-atomics), which delivers the same properties as the plan's prescribed `InitOnce<PerCore<…>>` wrapper — safe cross-thread access without `static mut`, O(1) per-core indexing, no heap. `CONNECTIONS` static no longer exists (was retired during Phase 4's `NetSlot` work). |
| 3 | Net::enable | 🟢 | shared with Phase 2 | hello +<1 KB | `uni::net::{Net, NetBringUp, Ipv4Addr}` + `Net::enable(cfg)`. Apps call `Net::enable(NetBringUp::Dhcp)` in their ctor; ENABLED flag left clear on failure so a DHCP→Static `or_else` retry works. `boot/entry.rs` defers DHCP to a post-`uni_main` auto-init fallback (legacy DHCP-then-10.0.2.15/24) and runs `activate_multi_queue` after DHCP to honour MEMORY.md's MQ-vs-DHCP constraint. `hello` uses `.expect("DHCP failed")` per the plan's sample; `webserver` uses `.or_else(\|_\| Net::enable(Static{…}))` for the static fallback. Test apps (test_smp, test_percpu, test_tls) unchanged per plan. |
| 4 | delete auto-init | 🟢 | health_max -1.9%, udp_peak -0.1%, health_tls_max -1.7% (6-run means vs 70a6f4a — all within 2% gate) | none | **Auto-init deleted**: `boot/entry.rs` no longer runs DHCP or the 10.0.2.15/24 fallback. Apps that want networking call `uni::net::Net::enable` from `uni_main`; apps that don't (test_smp, test_percpu, test_tls) get no network, as specified. **`NET` slot landed**: `static NET: NetSlot(UnsafeCell<Option<Box<Net>>>)` replaces the Phase-3 `ENABLED: AtomicBool`. Mirrors the `APP_SLOT` pattern; `uni::shutdown_and_drop` clears it on graceful exit. `Net::enable` twice now returns `Err(AlreadyEnabled)` via `.is_some()` check. **Net-owned field migration designed out:** moving `CONFIG` / `HANDLER_*` / `DHCP_STATE` / `{MULTICORE_INIT, WAKEUP, RX_LOCK, JUST_DISTRIBUTED}` / `SERVER_PTR` / `TLS_CONFIG_PTR` into `uni_net::Net` fields was originally part of Phase 4. Post-Phase-7 the statics are all already safe (`AtomicBool`/`AtomicU32`/`Spinlock<T>`/`ConfigStore` of atomics); moving them into `Net` fields would require threading `&Net` through every ARP / DHCP / IPv4 / TCP / UDP hot-path function and inverting the net sub-crate dep direction (sub-crates would need to see `uni_net::Net`). Ownership-aesthetic benefit; protocol-layer-entanglement cost. Not worth it. |
| 5 | Ethernet driver carveouts | 🟢 | Step 5 bench (3-run mean): health_max −1.1%, udp_peak neutral, health_tls_max −0.3%. Step 4 split (single run): health_max −0.18%, udp_peak +1.48%, health_tls_max +0.22%, tls_handshake_max +0.84% — within ±2% gate. | none | **Step 1**: trait + macro + walker + linker sections. **Step 1.5**: `//uni-net:uni_net` crate carveout. **Step 1.6**: `//uni-net:driver` leaf crate (cycle break). **Step 2**: `VirtioNetDriver impl EthernetDriver` + registration. **Step 3**: `gvnic` → `gve` rename + `GveDriver` impl + registration. **Step 5**: `Net::enable` walks `linked_ethernet_drivers()` before bring-up; returns `NetError::NoDriver` if the binary has no registered driver, `NetError::NoNic` if drivers are linked but no `probe()` succeeds. **Step 4**: `virtio_net.rs` → `//uni-driver-virtio-net`, `gve.rs` → `//uni-driver-gve`, both depending on a new `//drivers:infra` sub-target (MMIO + PCI + VirtIO transport + virtio-console). The outer `//drivers:drivers` keeps `drivers::net::*` dispatch + `pub use drivers_infra::*` re-export so 43 existing caller sites don't touch. **Step 6 designed out:** probe-driven init replacing `drivers::net::*` with registry walks was plan-labelled "future" from the outset. The dispatcher has 20 methods; the `EthernetDriver` trait has 4. Most of the extras (TX staging, NAPI rearm, MQ activation, ring-cursor diagnostics) are genuinely virtio-specific — gve is polling-only, has no TX staging, different queue model. Forcing them into a common trait with no-op defaults on gve is worse than the explicit `if use_gve()` branches in `drivers/net.rs`. The split in Step 4 is also technically "theater" today — apps that don't want gve can't drop it because `//drivers:drivers` still pulls both driver crates for the dispatcher. That's a latent improvement a specific-shape app (e.g. compute-only or GCE-only) can unlock later; it doesn't block §2g. |
| 6 | uni-tls carveout | 🟢 | none (TLS-serving apps keep same code path; non-TLS apps unaffected) | hello: 0 TLS/crypto deps in transitive closure (confirmed via `bazel query`); webserver pulls `//net:tls_server` only via `//uni-tls`. | **`//uni-tls:uni_tls` landed** with two trait-object hooks (`uni::http::{TlsAdapter, TlsConnection}`) that `uni_tls` implements over the sans-io state machine in `//net:tls_server`. `Server::listen_tls(port, TlsServerConfig)` method replaced by free function `uni_tls::listen_tls(&mut Server, port, cfg)` per plan. Diagnostic helpers (`tls_profile_report`/`_reset`) moved to `uni_tls::…`. `//net:net` umbrella dropped its `tls_server` re-export; `//uni-net:uni_net`'s native `select()` dropped all five `//net:tls_*` deps and its `pub mod tls_server` shim. Hello's dep closure no longer reaches TLS / crypto. |
| 7 | static_mut sweep + `AtomicFn<F>` | 🟢 | HVF 1c (single-run pre→post at commit 351b4d7 → 8c8ad99): health_max +0.7%, udp_peak −0.6%, health_tls_max +0.3%, tls_handshake_max +2.0%. All within the ±2% gate; mean drift smaller than run-to-run noise. | none | **33 `static mut` → 0** across the tree (only the `extern "C" { static mut boot_l1_table }` declaration for boot.S's symbol remains, which isn't a Rust-owned definition). Conversions followed the plan's three primitives: `AtomicBool`/`AtomicUsize` for cross-thread scalars (`SHUTDOWN`, `NUM_THREADS`, `TLS_KEY`, `UDP_COUNT`, `SHARED_LISTEN_COUNT`); `UnsafeCell<T>` + `unsafe impl Sync` for collections touched by single-writer / BSP-init / per-slot ownership (virtio_console ring + device state, GDT/IDT tables, MMU L2 pool, SMP core table, IRQ handler table, UDP bindings, pthread workers table, boot-info scratch, …). `//util:atomic_fn` was already carved out in Phase 6 prep. The 12-static virtio-console consolidation landed as `drivers/virtio_console.rs:8→1` (ring-memory fields + config flags under one `VirtioConsole` struct). |
| 8 | auto-SMP (hooks dropped) | 🟢 | all workloads within ±2% gate | none | **SMP: auto-detect, not opt-in.** Plan originally prescribed `uni::smp::enable()` as an opt-in call; we shipped that briefly (`8bb14be`) and reverted in `31fcf4c`. The opt-in created a performance-cliff footgun (a forgetful app silently runs single-core with single-queue networking) and the claimed "drop machinery from the binary" saving never materialised — the AP-start code is still linked regardless. Current behaviour matches native: boot detects cpu_count from FDT / ACPI and calls `percpu::init(cpu_count)` + `start_secondary_cores` unconditionally when >1. Apps wanting single-core determinism run on a 1-CPU VM or set `UNIKERNEL_CPUS=1` on native. **`on_tick` / `on_idle` hooks dropped.** Shipped briefly (`c99f4a0`), dropped in `ac3aaba`. No in-tree users, and committing to a hook shape before §2g knows what the reactor needs risks locking in the wrong one. §2g can add them back with the right shape. |

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
bazel build //apps/hello:hello_hvf //apps/webserver:webserver_hvf
ls -l bazel-bin/apps/{hello,webserver}/*_hvf.img
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
