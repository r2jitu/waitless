# Waitless

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Waitless is a bare-metal unikernel** — a Rust application that boots on real
(or virtual) hardware as the *entire* software stack. There is no Linux
underneath, no kernel/user split, and no syscalls. The network stack, TLS,
HTTP, and your request handlers all run in a single address space, at one
privilege level, driven by one cooperative `async` runtime.

The payoff is measurable: on identical Google Compute Engine hardware with the
same NIC, the demo web server serves **up to 2× the requests per second of
native Linux** — see [Performance](#performance). Not because the drivers are
better (Linux's are vastly more mature) but because the architecture deletes
the syscall boundary, the user/kernel copies, and the context switches
outright.

Waitless targets **x86_64** and **ARM64**, and runs under QEMU, Apple
Hypervisor.framework (HVF), a Limine ISO (BIOS/UEFI), and Google Compute
Engine.

## Highlights

- **No OS underneath.** Boots straight into your app. I/O is direct function
  calls, not syscalls — no ring transitions, no context switches, no copies
  across a kernel boundary.
- **Async *is* the scheduler.** `async fn` is the only execution model; a
  per-core cooperative executor polls connection handlers directly. No
  preemption, no locks, no second scheduling layer.
- **Networking, hand-rolled in `#![no_std]` Rust.** Ethernet, ARP/NDP,
  IPv4/IPv6, UDP, a conformance-tracked TCP, and a from-scratch TLS 1.3 server
  with HTTP/1.1 — with HTTP/3 over QUIC underway.
- **Two architectures, four ways to run.** x86_64 and aarch64, on QEMU,
  Apple's hypervisor, a bootable ISO, and GCE — the same app, no source
  changes.
- **Composable by Bazel deps.** An app pulls in only the protocols and drivers
  it uses; unused code never compiles into the image.
- **Faster than Linux on the same hardware.** [Up to +102 % requests/sec](#performance)
  against native Linux on an identical GCE VM and NIC.

## Quick Start

```bash
# Prerequisites: Bazel and QEMU.
#   macOS:  brew install bazel qemu
#   Linux:  your distro's bazel (or bazelisk) + qemu-system packages

# Boot the demo web server as a unikernel:
bazel run //apps/webserver:webserver_hvf          # macOS — Apple Hypervisor
bazel run //apps/webserver:webserver_qemu_x86_64  # elsewhere — QEMU

# Then, from another terminal:
curl http://localhost:8080/health
```

## Performance

Both targets run on GCE `n2-highcpu-4` VMs with **gVNIC** (4 queue pairs), in
the same `us-west1-a` zone, benched from a separate VM over the VPC
(`wrk -t4 -d15s`). Same NIC, same queue count, same client — Waitless gets no
loopback shortcut and no lighter network stack underneath. And **Linux runs
its mature in-tree `gve` driver** (thousands of lines, years of tuning);
**Waitless runs the from-scratch gVNIC driver in
[`crates/drivers/gve/`](crates/drivers/gve/)**. Linux should win on driver
maturity alone. It doesn't.

| Workload            | Native Linux | **Waitless** | Δ |
|---------------------|-------------:|-------------:|:-:|
| `/health`      c128 |    278,000   |  **499,000** | **+79 %**  |
| `/health`      c256 |    255,000   |  **514,000** | **+102 %** |
| `/compute`     c100 |     28,700   |   **32,900** | **+15 %**  |
| `health_tls_max`    |    183,700   |  **294,500** | **+60 %**  |
| `udp_peak` (pkt/s)  |    566,500   |  **787,000** | **+39 %**  |

Waitless wins every workload because the architecture pays off more than
driver polish does. No POSIX syscalls, no user/kernel boundary copies, no
context switches — the HTTP handler, the TCP state machine, and the NIC queue
all run in the same address space on the same core. gVNIC's Toeplitz RSS gives
per-core RX queues with zero software distribution, and TCP 4-tuple lookups
are O(1) via a per-core open-addressed hash table. `/health` doubles at `c256`
because the per-packet overhead gap widens as the connection count grows.

Reproduce with `scripts/bench.py`; see [docs/benchmarking.md](docs/benchmarking.md)
for the full methodology.

## Build Configurations

`waitless_binary(name, app)` generates one runnable target per runner — pick
the variant by name, no `--config=` flags needed (see
[`bazel/rules/variants.bzl`](bazel/rules/variants.bzl)):

```bash
bazel run //apps/webserver:webserver_hvf            # aarch64 · Apple Hypervisor (macOS)
bazel run //apps/webserver:webserver_qemu_aarch64   # aarch64 · QEMU
bazel run //apps/webserver:webserver_qemu_x86_64    # x86_64  · QEMU
bazel run //apps/webserver:webserver_iso_x86_64     # x86_64  · Limine ISO (BIOS/UEFI) via QEMU
bazel run //apps/webserver:webserver_native         # POSIX sockets · no VM
```

The `*_native` variant builds the same app against host POSIX sockets — handy
for fast iteration and debugging without a hypervisor.

## Testing

```bash
# Full matrix — every applicable variant of every app. HVF tests auto-skip on Linux.
bazel test //...

# Filter by runner.
bazel test --test_tag_filters=hvf    //...
bazel test --test_tag_filters=qemu   //...
bazel test --test_tag_filters=native //...

# A single variant.
bazel test //apps/webserver:test_hvf
```

## Architecture

```
┌──────────────────────────────────────┐
│           Application                │  apps/webserver/
│         #[waitless::init]            │
├──────────────────────────────────────┤
│   Userspace protos (above facade)    │  crates/proto/{tls, http,
│                                      │                    quic, http3}
├──────────────────────────────────────┤
│ Facade (waitless — kernel↔userspace) │  crates/waitless/ + nested
│                                      │  macros, net, backend
├──────────────────────────────────────┤
│       Network Stack (below facade)   │  crates/net/ (TCP, UDP, IPv4/6,
│                                      │              ARP, NDP, DHCP, ...)
├──────────────────────────────────────┤
│     Drivers (NIC + bus)              │  crates/drivers/ (bus, nic/{api,
│                                      │                   nic}, virtio-net, gve)
├──────────────────────────────────────┤
│     Runtime substrate                │  crates/runtime/{platform, worker,
│                                      │                  executor}
├──────────────────────────────────────┤
│       Kernel (serial, mm, SMP...)    │  crates/kernel/{core, bare}
├──────────────────────────────────────┤
│        Boot / Entry                  │  crates/boot/
└──────────────────────────────────────┘
         x86_64          aarch64
     (Multiboot2/PVH)  (Linux Image/DTB)
```

SMP comes up via Limine's MP request on x86_64; under Tier 1 polling there is
one TX + RX queue pair per vCPU, with Toeplitz-hashed RSS on gVNIC so each
core's flows stay on that core. See [docs/crates.md](docs/crates.md) for the
full crate taxonomy and the kernel↔userspace facade boundary.

## Writing an Application

A Waitless app is a `#![no_std]` Rust crate with an `async` entry point. Here
is [`apps/hello`](apps/hello) in full — bring up the network, serve one route:

```rust
#![no_std]
extern crate alloc;

use http::{Request, Response};
use waitless::net::Net;

async fn hello(_: &Request, _: &mut http::BodyReader<'_, waitless::runtime::TcpStream>) -> Response {
    Response::ok(b"text/plain", b"Hello from bare metal!\n")
}

#[waitless::init]
async fn init() {
    Net::up().await.expect("Net::up failed");
    http::listen(80, hello).expect("http bind");
}
```

`#[waitless::init]` marks the async entry point the runtime polls once the
kernel, drivers, and network are up. The crate's `BUILD.bazel` wires it to the
`waitless_binary` rule:

```python
load("@rules_rust//rust:defs.bzl", "rust_library")
load("//bazel/rules:waitless.bzl", "port_fwd", "waitless_binary")

rust_library(
    name = "app",
    srcs = ["src/main.rs"],
    crate_root = "src/main.rs",
    deps = [
        "//crates/proto/http",
        "//crates/waitless",
    ],
)

waitless_binary(
    name = "hello",
    app = ":app",
    drivers = ["//crates/drivers/virtio-net"],
    port_forwards = [port_fwd("tcp", guest = 80, host = 8080)],
)
```

For a fuller example — HTTPS, multiple routes, HTTP/3, live diagnostics — see
[`apps/webserver`](apps/webserver).

## Using Waitless in another project

The `apps/` in this repo are examples; a real application lives in its own
repository and depends on Waitless as a **Bazel module**. Point your app's
`MODULE.bazel` at a Waitless checkout — `local_path_override` is simplest for
a sibling checkout:

```python
module(name = "website", version = "0.0.0")

bazel_dep(name = "waitless", version = "0.1.0")
local_path_override(
    module_name = "waitless",
    path = "../waitless",
)
```

The app's `BUILD.bazel` then loads the rule from `@waitless` and builds
exactly like an in-tree app — the only difference is the `@waitless` prefix on
labels that resolve into the dependency:

```python
load("@rules_rust//rust:defs.bzl", "rust_library")
load("@waitless//bazel/rules:waitless.bzl", "port_fwd", "waitless_binary")

rust_library(
    name = "app",
    srcs = ["src/main.rs"],
    crate_root = "src/main.rs",
    deps = [
        "@waitless//crates/proto/http",
        "@waitless//crates/waitless",
    ],
)

waitless_binary(
    name = "website",
    app = ":app",
    drivers = ["@waitless//crates/drivers/virtio-net"],
    port_forwards = [port_fwd("tcp", guest = 80, host = 8080)],
)
```

A consuming module must also re-declare a few **root-module-only** Bazel
settings that don't propagate through the module graph — the `rules_rust`
version and patches, and the Rust toolchain tags.
[**docs/consuming-as-a-library.md**](docs/consuming-as-a-library.md) is the
complete, copy-pasteable checklist.

## Project Layout

```
waitless/
├── apps/
│   ├── hello/         Minimal HTTP hello-world (~25 LOC)
│   └── webserver/     Full demo — HTTP, HTTPS, HTTP/3, live diagnostics
├── crates/
│   ├── waitless/      Facade — the API apps program against (+ macros, net, backend)
│   ├── proto/         Userspace protocols — http, http3, quic, tls
│   ├── net/           Network stack — Ethernet, ARP, NDP, IPv4/6, TCP, UDP, DHCP
│   ├── drivers/       NIC + bus drivers — virtio-net, gve (gVNIC)
│   ├── runtime/       Async substrate — executor, worker, platform
│   ├── kernel/        Kernel library — serial, memory, SMP, per-core state
│   ├── crypto/        AEAD helpers
│   ├── util/          Zero-copy buffers and lock-free primitives
│   └── boot/          Arch entry, page tables, the Limine boot protocol
├── bazel/             Toolchains, platforms, and the waitless_binary rule
├── docs/              Architecture and subsystem deep-dives
├── scripts/           Benchmark, deploy, and dev tooling
└── tools/hvf-runner/  Native macOS/arm64 HVF runner used by the dev loop
```

## Documentation

- [docs/crates.md](docs/crates.md) — crate taxonomy and the kernel↔userspace facade boundary
- [docs/networking.md](docs/networking.md) — the network stack, end to end
- [docs/consuming-as-a-library.md](docs/consuming-as-a-library.md) — building an app against Waitless
- [docs/benchmarking.md](docs/benchmarking.md) — how the performance numbers are measured
- [docs/gvnic.md](docs/gvnic.md) — the from-scratch Google Virtual NIC driver
- [docs/iobuf-type-model.md](docs/iobuf-type-model.md) · [rx-path](docs/rx-path-optimizations.md) · [tx-path](docs/tx-path-optimizations.md) — zero-copy datapath internals
- [ROADMAP.md](ROADMAP.md) — where Waitless is headed: QUIC/HTTP3, IPv6, the async runtime

## Deploying to GCE

```bash
# Builds the image and creates the instance.
./scripts/deploy-gcloud.sh deploy

# Defaults: n2-highcpu-4 + gVNIC + queue-count=4. Override via env:
WAITLESS_GCE_MACHINE=n2-standard-2 QUEUE_COUNT=2 ./scripts/deploy-gcloud.sh deploy

# Tail the serial console; stop / delete the instance.
./scripts/deploy-gcloud.sh logs
./scripts/deploy-gcloud.sh purge
```

## Status

Waitless is a research project, not production software. It implements enough
of TCP/IP, TLS 1.3, and HTTP to run — and benchmark — a real web server, but
the API is unstable, it is the work of a single author, and the checked-in dev
certificate and several defaults are explicitly development-only. Issues,
questions, and contributions are welcome; the build is plain `bazel test //...`.

## License

Waitless is dual-licensed under either of

- Apache License, Version 2.0 — [LICENSE-APACHE](LICENSE-APACHE)
- MIT license — [LICENSE-MIT](LICENSE-MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in Waitless by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.
