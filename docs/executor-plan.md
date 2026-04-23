# Async Runtime: Finishing the Foundation

Trackable plan for the work between **"async runtime first cut
shipped"** ([ROADMAP §2f+§2g](../ROADMAP.md) — landed in commit
`2cd9c9c`) and **"start writing QUIC"** ([ROADMAP §3c](../ROADMAP.md)).

Not a feature delivery — this plan finishes the refactor arc that
`//uni-runtime` + `//uni-percpu` started, then lands the last
reactor primitives QUIC needs before §3c can begin. Every phase is
small enough to land independently; the ROADMAP owns the §3c QUIC
implementation itself.

---

## Status

**In progress.**

| Phase | Status | Commit |
|---|---|---|
| P0. `//uni-runtime` with shared arena / Waker / Sleep | 🟢 done | `509a6af` |
| P1. `//uni-percpu` — `CurrentCore` + `PerCpu<T, N>` shared | 🟢 done | `a506a52` |
| P2. `TimerWheel` + `PendingTimers` shared | 🟢 done | `9e0095f` |
| P2.5. `InitOnce<T>` shared, `uni/src/boot_info.rs` dedup | 🟢 done | `e52ce2a` |
| P3. Runtime fn-pointer struct — drop `extern "C"` hooks | 🟢 done | `082b8eb`, `375e99f` |
| P4. `UdpSocket::recv_from().await` reactor | 🟢 done | `bb0dc1a`..HEAD |
| P5. `TcpListener::accept().await` reactor (bare-metal; native stub) | 🟡 partial | `fa534ec`..HEAD |

After P4, ROADMAP §3c starts. Everything after that lives in the
ROADMAP, not here.

### P3 design note

First attempt used `InitOnce<&'static dyn Runtime>` with a
`trait Runtime`. That broke `apps/webserver:test_hvf` in a
non-obvious way: `kernel::runtime::init()` at boot → webserver's
virtio-net IRQ delivery stopped firing. No panic, just silent
wedge. Root cause never isolated — suspected fat-pointer write
ordering vs. GIC / IRQ state, but no hard evidence.

Landed in two steps. First shipped a POD `struct Runtime` of
Rust-ABI fn pointers published via `AtomicPtr<Runtime>`, which
eliminated `dyn Trait`, `InitOnce`, `extern "C"`, and the
`#[allow(improper_ctypes)]` dance. Then, for the platform
primitives that are build-time-selected (`current_worker`,
`now_ticks`), swapped the `AtomicPtr` indirection for direct
cfg-gated calls inside a new leaf `//uni-platform` crate:

```rust
// bare-metal side: inline asm reads TPIDR_EL1 / rdtsc.
// native side: std thread-local + Instant.
let id   = uni_platform::current_worker();
let now  = uni_platform::now_ticks();
```

Backend init publishes whatever per-worker state `uni-platform`
depends on (x86 TSC rate after PIT calibration; a thread-local set
at each native worker's startup). Register-style hooks stay for
**stateful** dispatch where the upper crate really plugs over
live-at-runtime backends (e.g., `uni_net_driver::NicOps`).

---

## Context — what's already shipped

The async runtime has a cross-platform shape that the remaining
work refines:

```
//uni-runtime        — TaskSlot arena, RawWakerVTable, Sleep, spawn, tick, has_ready
//uni-percpu          — CurrentCore (ZST token), PerCpu<T, N>, MAX_WORKERS
//kernel/src/executor.rs  — bare-metal backend: hooks + tick wrapper + WHEELS
//uni-backend/src/native/executor.rs — native backend: hooks + tick wrapper + per-worker timers
//apps/test_async     — smoke test; 4 variants green (HVF, QEMU ×2, native)
```

Each backend currently provides three `extern "C"` hooks:

```rust
unsafe extern "C" {
    fn uni_exec_now_ticks() -> u64;
    fn uni_exec_schedule_timer(deadline: u64, func: fn(usize), arg: usize) -> bool;
    fn uni_exec_cancel_timer(arg: usize) -> bool;
}
```

…plus one `uni_percpu_current_worker` hook in `//uni-percpu`. Both
extern blocks need `#[allow(improper_ctypes)]` because `fn(usize)`
is Rust ABI inside a C-ABI extern block (lint is cosmetic — we own
both sides). P3 eliminated all three `extern "C"` hooks and the
follow-up removed the `AtomicPtr<Runtime>` plug-in entirely for the
platform primitives — `uni_platform::{current_worker,now_ticks}`
are direct cfg-gated calls.

Design principles inherited from the landed work:

1. **Per-worker affinity, no migration.** A task spawned on worker
   N polls on worker N. Waker identity is a raw `*const TaskSlot`
   into static storage.
2. **Backends provide the bits that truly differ.** Time source
   and worker id differ. The arena, Waker vtable, and Sleep future
   are identical across platforms.
3. **"Share when a second consumer shows up, not before."** Don't
   build abstractions for hypothetical native features.

---

## Phase 2 — share `TimerWheel` + `PendingTimers`

### Why

Native currently uses `Vec<NativeTimer>` with O(n) cancel and no
cross-worker submission path. The kernel's
[`kernel::timer::TimerWheel`](../uni-percpu/src/timer.rs) gives O(1) insert
+ slot-hashed fire; [`PendingTimers`](../uni-percpu/src/timer.rs) is a
lock-free MPSC for cross-worker scheduling. Moving both into
`//uni-percpu` (or a new `//uni-timer` crate — bikeshed, see below)
makes the native backend's `uni_exec_schedule_timer` the same
3-line wrapper the kernel has. Second current consumer, measurable
native improvement — clears the bar the percpu carve-out already
cleared.

### Crate placement

Two options, either fine:

* **Add to `//uni-percpu`.** Consolidates per-worker primitives;
  one crate is cheaper than two.
* **New `//uni-timer` crate.** Cleaner single-purpose, decouples
  timer evolution from percpu.

Recommend `//uni-percpu` until a third primitive argues for a
split.

### Steps

1. **Move `uni-percpu/src/timer.rs` contents to `//uni-percpu` (~290 LOC).**
   Keep `kernel::timer` as a re-export for existing callers:
   ```rust
   // uni-percpu/src/timer.rs
   pub use uni_percpu::timer::{Timer, TimerWheel, PendingTimers};
   ```
   `Timer::func` is `fn(usize)` (Rust ABI) — unchanged.

2. **`kernel/src/executor.rs` is unchanged.** It uses
   `kernel::timer::{Timer, TimerWheel}` which now points at the
   shared impl.

3. **Native backend swaps storage.** In
   [uni-backend/src/native/executor.rs](../uni-backend/src/native/executor.rs):
   ```rust
   // before (today, landed in a506a52):
   struct TimerList(UnsafeCell<Vec<NativeTimer>>);
   static TIMERS: PerCpu<TimerList, MAX_WORKERS> = ...;

   // after:
   struct WheelCell(UnsafeCell<TimerWheel>);
   static WHEELS: PerCpu<WheelCell, MAX_WORKERS> = ...;

   fn wheel(cc: &CurrentCore) -> &mut TimerWheel {
       unsafe { &mut *WHEELS.current(cc).0.get() }
   }

   #[unsafe(no_mangle)]
   pub extern "C" fn uni_exec_schedule_timer(
       deadline: u64, func: fn(usize), arg: usize,
   ) -> bool {
       let cc = CurrentCore::enter();
       wheel(&cc).insert(Timer { deadline, func, arg })
   }
   ```
   `advance` becomes `wheel(&cc).advance(now_us())` — a single
   call, identical to the kernel's idle path.

4. **Unit tests.** `TimerWheel` already has tests at
   `uni-percpu/src/timer.rs`; they move with the code. They're host-native
   tests, so they run on any platform after the move.

### Acceptance

- [ ] `bazel test //uni-percpu:timer_test` green (host-native)
- [ ] `bazel test //apps/test_async:test_native` green
- [ ] `bazel test //apps/test_async:test_hvf` green
- [ ] `bazel test //apps/test_async:test_qemu_aarch64 //apps/test_async:test_qemu_x86_64` green
- [ ] `bazel test //apps/webserver:test_hvf` green (regression)

### Estimated effort

1 hour.

---

## Phase 3 — Runtime trait: drop `extern "C"` hooks

### Why

Three `extern "C"` hooks + two `#[allow(improper_ctypes)]`
annotations + one per-crate `pub extern "C" fn` wiring block per
backend. Not load-bearing — every hook takes primitives or Rust
fn-pointers. The `extern "C"` boundary is ceremony that a
Rust-native trait removes.

Benefits:

- **Zero `extern "C"` in the executor stack.** Pure Rust ABI end
  to end. Drops both `#[allow]` annotations.
- **Testing seam.** A `MockRuntime` lets host unit tests exercise
  arena + Waker semantics without dragging in the kernel or libc.
  Currently our only test coverage is integration (`apps/test_async`).
- **Extensibility.** Adding a new hook (e.g., `remote_wake_hint`
  for cross-worker IPI, P4's prerequisite) becomes "add a trait
  method with a default impl"; the compiler enforces every backend
  overrides the required methods.

### Shape

```rust
// uni-runtime/src/lib.rs (replaces the extern "C" block)
pub trait Runtime: Sync {
    fn now_ticks(&self) -> u64;
    fn schedule_timer(&self, deadline: u64, func: fn(usize), arg: usize) -> bool;
    fn cancel_timer(&self, arg: usize) -> bool;

    // Default no-op impls so backends without the capability
    // compile without forced boilerplate.
    fn advance_timers(&self, _worker_id: u32) {}
    fn has_pending_timers(&self, _worker_id: u32) -> bool { false }
    fn remote_wake_hint(&self, _worker_id: u32) {}  // future: cross-worker IPI
}

pub fn register(rt: &'static dyn Runtime) { ... }
fn runtime() -> &'static dyn Runtime { ... }   // crate-private
```

`uni-percpu`'s `uni_percpu_current_worker` hook stays as a plain
`extern "C" fn` returning `u32` — zero ABI concerns (primitive
return, no fn pointers), and `CurrentCore::enter()` needs to be
callable before `register()` runs. Keeping percpu decoupled from
runtime registration preserves boot-ordering freedom.

### Registration mechanism

`core` has no `OnceLock`. Two options:

1. **Bring in a crate.** `spin::Once` is well-tested, ~200 LOC
   pulled in.
2. **Write a minimal `Once` in-tree.** 30 LOC: `AtomicU8` state
   machine (UNINIT → INITING → READY), `UnsafeCell<MaybeUninit<T>>`.
   `spin`-free, avoids a new dep.

Recommend option 2 — the unikernel already has a local
`kernel::once::Once`, we can either relocate it into `//uni-percpu`
or copy the pattern into `//uni-runtime`.

### Backend shape

```rust
// kernel/src/executor.rs
struct KernelRuntime;
static KERNEL_RT: KernelRuntime = KernelRuntime;

impl Runtime for KernelRuntime {
    fn now_ticks(&self) -> u64 { /* cycles / cycles_per_us */ }
    fn schedule_timer(&self, deadline: u64, func: fn(usize), arg: usize) -> bool {
        let cc = CurrentCore::enter();
        wheel(&cc).insert(Timer { deadline, func, arg })
    }
    // ... cancel_timer, advance_timers, has_pending_timers ...
}

pub fn init() { uni_percpu::register(&KERNEL_RT); }
```

`init()` called from `boot/src/entry.rs` right after `percpu::init`.
Same pattern for `uni-backend` (registered from `uni_backend::native::run`).

### Steps

1. **Add `trait Runtime` + `Once` + `register` + `runtime()` to
   `//uni-runtime`.** Keep old `extern "C"` hooks working during
   the transition (call-through from trait methods) so no backend
   breaks mid-refactor.
2. **Migrate bare-metal backend.** Add `impl Runtime for
   KernelRuntime`, add `init()` call from `boot/src/entry.rs`. Remove
   the three `#[unsafe(no_mangle)] pub extern "C" fn uni_exec_*`
   symbols.
3. **Migrate native backend.** Same shape, registration from
   `uni_backend::native::run`.
4. **Delete the `extern "C"` block from `//uni-runtime` and both
   `#[allow(improper_ctypes)]` annotations.** Replace call sites
   with `runtime().now_ticks()` etc.
5. **Add `MockRuntime` + host unit tests for arena/Waker
   semantics.** First host-native tests in the executor stack.

### Acceptance

- [ ] All existing test_async variants + test_percpu + webserver
      regressions pass.
- [ ] No `extern "C"` blocks in `//uni-runtime`; no
      `#[allow(improper_ctypes)]` anywhere in the executor stack.
- [ ] At least one new `#[test]` in `//uni-runtime` exercising
      arena + Waker via `MockRuntime`.

### Estimated effort

2 hours.

---

## Phase 4 — `UdpSocket::recv_from().await` reactor (shipped)

QUIC's first `.await` is a UDP datagram. Shipped API:

```rust
UdpSocket::bind(7)?.run(|sock| async move {
    let mut buf = [0u8; 1500];
    loop {
        let (src_ip, src_port, n) = sock.recv_from(&mut buf).await;
        uni::udp_send(src_ip, 7, src_port, &buf[..n]);
    }
});
```

`run` consumes the socket and arranges the async body to be spawned
on every worker. "Bind without spawning per worker" and "spawn on
the wrong number of workers" are both impossible by construction —
the per-worker pattern can't be misused by accident. Lower-level
`bind` + `recv_from` is still available for custom lifecycles.

**Reactor** lives in `uni-runtime/src/net.rs`. Each of the 8 socket
slots owns a `PerCpu<WorkerInbox, MAX_WORKERS>`: every worker has
its own 4-slot SPSC ring of 1500-byte datagram slots + a
`SpinLock<Option<Waker>>`. Inbound datagrams push to the inbox of
the worker that received them; `recv_from` pulls from the calling
worker's inbox — no cross-core contention on the hot path. Static
footprint: ~384 KB.

**Per-worker dispatch preserves multi-core distribution.** Bare-metal
Tier 1 MQ distributes RX across cores by flow hash; native
SO_REUSEPORT does the same across worker threads. The reactor
preserves that fan-out to the async handler — one long-lived task
per worker pulling its own stream, which is the pattern QUIC's
per-connection dispatch needs.

**Cancellation safety:** `UdpRecv::poll` does fast-path pop BEFORE
waker register, then re-checks AFTER register. Closes the
delivery-vs-registration race in both directions; dropping
`UdpRecv` mid-await consumes no datagram. `UdpRecv` is `!Send`
via `PhantomData<*mut ()>` so the future can't migrate across
workers mid-await.

**Delivery wiring:**

- Bare-metal: `net::udp::udp_receive` calls
  `uni_runtime::net::deliver_udp` first; legacy `HANDLER_FNS`
  callback registry is the fallback (DHCP still uses it).
- Native: `drain_udp_sibling` calls `deliver_udp` first; legacy
  `udp_bind(port, handler)` callback is the fallback. The POSIX
  backend registers a `register_backend_bind` hook that opens
  SO_REUSEPORT sibling fds when `UdpSocket::bind` runs.

**Per-worker spawn mechanism.** `UdpSocket::run` stores a
type-erased launcher closure in a per-port table. A single
`spawn_on_each_worker` hook, registered lazily on the first `run`
call, walks the table on each worker's first `tick()` and fires
every live launcher — each launcher calls `spawn(body(sock))` on
the calling worker. `spawn_on_each_worker` is also exposed
publicly for apps that want the primitive without `UdpSocket`
semantics.

**Validation:** `apps/webserver:test_udp_echo` uses
`UdpSocket::bind(7).run(...)` end-to-end; passes on HVF, QEMU ×2,
and native. `apps/test_async` has a bind/drop smoke for the
registry mechanics.

---

## Phase 5 — `TcpListener::accept().await` reactor

**Bare-metal: shipped.** Native: stubbed (bind succeeds, accept
stays Pending) pending a full native impl that defers kqueue/epoll
listen-fd handling to the reactor. See the design note below.

```rust
uni::runtime::TcpListener::bind(80)?.run(|stream| async move {
    // Handle one connection. `stream` is a RawTcpStream — wrap in
    // `uni::TcpStream` for the typed recv/send API.
    let stream = uni::TcpStream::from_raw(stream);
    let mut buf = [0u8; 1024];
    let _n = stream.recv(&mut buf);
    stream.send(b"HTTP/1.1 200 OK\r\n\r\nhi");
    stream.close();
});
```

`run` consumes the listener, spawns one long-lived accept-loop task
per worker; each accepted connection becomes its own task. The
per-worker model preserves NIC flow-hash distribution — conns
handshaked on core N are accepted on core N.

**Backend model.** Different from UDP because the backend (not the
reactor) owns the accept queue. `TcpListener::accept` simply polls
the backend's `tcp_backend_accept(port)` hook; the reactor layer
only wakes the awaiting task when the backend signals "accept-able
now" via `deliver_tcp_ready(port)`.

**Bare-metal wiring.** `net::tcp`'s SYN-ACK-ACK completion site
transitions a conn to `Established`, then calls
`deliver_tcp_ready(port)` on the core that owns the conn slot.
`tcp_backend_accept` scans the current core's pool for an
`Established + !accepted` conn on the matching port. Registration
happens in `net::init_stack` (triggered by `Net::enable` during app
boot).

**Launcher table consolidation.** UDP's per-run launcher table
generalised into a shared `NET_LAUNCHERS` covering both protocols.
UDP `run_loop`, TCP `run`, and any future reactor all register into
the same 16-slot table. A single `spawn_on_each_worker` hook (now
accumulating thanks to `fa534ec`) fires every launcher on each
worker's first tick.

**Validation.** Bare-metal path is exercised transitively by any app
that opens a TcpListener; a standalone smoke in `test_async` is
deferred because it would require pulling a NIC driver + DHCP into
the test. The proper integration cover arrives when `uni_http::
Server` migrates to `TcpListener::run(|stream| …)` — that's the
follow-up that also unlocks async HTTP handlers (per-request
`.await` for TLS, downstream calls, etc.). Not strictly required
for QUIC (§3c) since QUIC has its own server.

**Deferred native impl.** Full native TCP async accept requires
opening SO_REUSEPORT listen fds per worker, tagging them in the
native backend so the kqueue/epoll dispatcher recognises them,
calling `deliver_tcp_ready(port)` on fire instead of accepting
inline, and routing `tcp_backend_accept(port)` through the
per-worker listen-fd table. The current native hooks are no-op
stubs so `TcpListener::bind` succeeds (matching bare-metal's
surface) but accept stays Pending — apps needing TCP accept on
native should stay on `uni_http::Server`.

---

## Phase 5 — *(historical plan notes below)* `TcpListener::accept().await` reactor

### Why / whether

Nice to have for migrating HTTP to async (so the same `async fn
handle(conn)` runs on both backends). **Not required for QUIC.**
Skip unless a concrete win emerges — HTTP/1.1 works fine in its
current callback form.

**Trigger to do it:** when HTTP/1.1 needs a change that would be
easier in async form (timeouts mid-request, concurrent worker-local
request pipelining, etc.), OR when we want to port one of the
existing `apps/` HTTP handlers to demonstrate the async path.

### Estimated effort

~1 day, same shape as P4 but with TCP state machine complexity.

---

## Progress tracker

Status legend: ⏳ not started · 🟡 in progress · 🟢 complete · 🔴 blocked

| # | Phase | Status | Primary files | Lines Δ |
|---|---|---|---|---|
| P0 | `//uni-runtime` — shared arena / Waker / Sleep | 🟢 | `uni-runtime/**`, `kernel/src/executor.rs`, `uni-backend/src/native/executor.rs` | +506 / -375 |
| P1 | `//uni-percpu` — `CurrentCore` + `PerCpu` | 🟢 | `uni-percpu/**`, `kernel/src/percpu.rs` | +321 / -272 |
| P2 | Share `TimerWheel` + `PendingTimers` | 🟢 | `uni-percpu/src/timer.rs`, `uni-backend/src/native/executor.rs` | +435 / -451 |
| P2.5 | Share `InitOnce<T>` | 🟢 | `uni-percpu/src/once.rs`, `uni/src/boot_info.rs` | +201 / -263 |
| P3 | `Runtime` fn-pointer struct — drop `extern "C"` | 🟢 | `uni-percpu/src/lib.rs`, both backends | `082b8eb`, `375e99f` |
| P4 | `UdpRecv::recv_from().await` | ⏳ | new `uni-runtime/src/net.rs`, both backends' UDP paths | ~+200 |
| P5 | `TcpListener::accept().await` *(optional)* | ⏳ | new, both backends' TCP paths | ~+200 |
| →§3c | **Hand-off: QUIC starts** | — | see [ROADMAP §3c](../ROADMAP.md) | — |

---

## Validation protocol

After each phase:

```bash
# All four test_async variants + regressions.
bazel test --cache_test_results=no \
  //apps/test_async:test_native \
  //apps/test_async:test_hvf \
  //apps/test_async:test_qemu_aarch64 \
  //apps/test_async:test_qemu_x86_64 \
  //apps/test_percpu:test_hvf \
  //apps/webserver:test_hvf \
  //kernel:timer_test \
  //kernel:spsc_test \
  //kernel:deque_test \
  //kernel:sync_test

# Native runnable (human-check):
bazel run //apps/test_async:test_async_native
# Expect: boot → spawn ok → task started → task woke up → nested done
```

A phase is complete only when all of those are green AND the
phase's own acceptance checklist is ticked.

---

## Design invariants (do not break)

1. **Task affinity.** A task spawned on worker N polls on worker
   N. `spawn(f)` uses the current worker's `CurrentCore`.
2. **Waker pointer is `*const TaskSlot` into static storage.** No
   `Arc`, no refcount, clone is bit-copy, drop is no-op. Every
   slot is in the `ARENAS` `PerCpu<TaskArena, MAX_WORKERS>`.
3. **Per-worker state is owning-worker-only.** Timer wheels,
   arenas — `CurrentCore` token is the only synchronisation. No
   `Mutex`, no `RwLock` on hot paths.
4. **Cross-worker wake is bounded, not zero-latency.** The target
   worker observes a wake on its next idle tick (1 ms on
   bare-metal, 10 ms on native). Good enough for everything
   shipped; add IPI in Phase 4+ if QUIC's tail-latency profile
   demands it.

---

## Hand-off to ROADMAP

When P4 lands (UDP reactor), [ROADMAP §3c](../ROADMAP.md) begins:

- `//net:tls_server` "QUIC mode" — extract handshake messages as
  raw bytes for CRYPTO frames.
- `//net:quic_wire` — long / short header parsing, varints.
- `//net:quic_crypto` — packet protection via
  `//net:tls_crypto`'s AEAD + `//net:tls`'s HKDF.
- `//net:quic` — connection state machine as `async fn
  handle_quic(conn)` using the reactor primitives from P4.
- `//uni:http3` — HEADERS + DATA over QUIC streams.

The remaining deferred pieces (LAPIC one-shot timer on x86,
cross-worker IPI, work stealing) stay in the ROADMAP's
"Deferred work" section and surface only if profiling says so.
