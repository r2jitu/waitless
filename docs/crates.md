# Crate taxonomy

Three tiers, named for `include-what-you-use` consumption from
external Bazel modules and (eventually) crates.io.

## Tier 1 — public API

User-facing crates. An app depends on these directly.

| Target            | Crate name   | What it is                                           |
|-------------------|--------------|------------------------------------------------------|
| `//uni`           | `uni`        | Main API: `App`, `TcpListener`, `udp_*`, `#[boot]`   |
| `//uni-net`       | `uni_net`    | `Net::enable(Dhcp \| Static)`, `NicOps` registry, err |
| `//uni-http`      | `uni_http`   | Minimal HTTP/1.1 server + routing                    |
| `//uni-tls`       | `uni_tls`    | TLS termination wrapper                              |
| `//uni/macros`    | `uni_macros` | Proc macros (`#[uni::boot]`)                         |

## Tier 2 — platform + runtime

Selected by cfg. `uni` re-exports from here; apps don't touch them
directly.

| Target                      | Crate name              | What it is                                    |
|-----------------------------|-------------------------|-----------------------------------------------|
| `//uni-backend`             | `uni_backend`           | Platform adapter (bare / native)              |
| `//uni-runtime`             | `uni_runtime`           | Async executor (TaskSlot + Sleep)             |
| `//uni-percpu`              | `uni_percpu`            | `PerCpu<T, N>`, `TimerWheel`                  |
| `//uni-platform`            | `uni_platform`          | Leaf: `current_worker()`, `now_ticks()`       |
| `//uni-driver-virtio-net`   | `uni_driver_virtio_net` | virtio-net NIC driver                         |
| `//uni-driver-gve`          | `uni_driver_gve`        | GCE gVNIC NIC driver                          |

## Tier 3 — bare-metal internals

Implementation; selected in on `target_os = "none"`. Exposed
only via `uni-backend`.

| Target            | Crate name           | What it is                     |
|-------------------|----------------------|--------------------------------|
| `//kernel`        | `uni_kernel`         | MMU, APIC/GIC, SMP, heap, IRQ  |
| `//drivers`       | `uni_drivers`        | NIC dispatcher + shared MMIO   |
| `//drivers:infra` | `drivers_infra`      | PCI, VirtIO transport, console |
| `//net`           | `uni_net_stack`      | TCP/UDP/TLS/DHCP umbrella      |
| `//net:<proto>`   | `net_<proto>`        | Per-protocol leaf crates       |
| `//boot:*`        | (target-only)        | Linker-symbol providers        |
| `//util/atomic_fn`| `atomic_fn`          | Typed atomic fn-pointer cell   |

## Layout convention

Every crate uses `<crate>/src/` for source files (Cargo convention).
BUILD.bazel sits at the crate root alongside `src/`.

## Fn-pointer dispatch model

Stateful cross-tier dispatch goes through a POD struct of Rust-ABI
fn pointers published via `AtomicPtr` at boot. Callers do one
`Acquire` load + one direct call per hook — no trait objects,
no vtables, no `extern "C"`. Used where the upper crate really is
plugging over multiple live-at-runtime backends:

- `uni_net_driver::NicOps` — NIC driver ops (`send`, `poll_rx`,
  etc.). `ACTIVE_OPS` starts pointing at a `NULL_OPS` backstop so
  dispatchers never have to null-check.

Platform primitives that are build-time-selected (`current_worker`,
`now_ticks`) live in `uni-platform` as cfg-gated direct calls, not
register-style hooks. Backends populate any per-worker state
`uni-platform` depends on (TPIDR_EL1 / GS_BASE on bare-metal, a
thread-local on native) during boot. See
[executor-plan.md](executor-plan.md) §P3 design note.
