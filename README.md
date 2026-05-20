# UniKernel

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Author**: Jitu Das

A bare-metal unikernel written in Rust that boots directly into an application with no OS, no syscalls, and no context switches. All I/O is handled via direct in-process function calls.

Runs on **x86_64** and **ARM64 (aarch64)** via QEMU, Apple Hypervisor.framework (HVF), Limine ISO (BIOS/UEFI), and Google Compute Engine.

## Architecture

```
┌──────────────────────────────────────┐
│           Application                │  apps/webserver/
│         #[uni::init]                 │
├──────────────────────────────────────┤
│   Userspace protos (above facade)    │  crates/proto/{tls, http,
│                                      │                    quic, http3}
├──────────────────────────────────────┤
│    Facade (uni — kernel↔userspace)   │  crates/uni/{uni, macros, net,
│                                      │              backend}
├──────────────────────────────────────┤
│       Network Stack (below facade)   │  crates/net/ (TCP, UDP, IPv4/6,
│                                      │              ARP, NDP, DHCP, ...)
├──────────────────────────────────────┤
│     Drivers (NIC + bus)              │  crates/drivers/ (bus, nic-api,
│                                      │                   nic, virtio-net, gve)
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

See [docs/crates.md](docs/crates.md) for the full crate taxonomy,
naming rules, and the kernel↔userspace facade boundary.

SMP via Limine's MP request on x86_64; one TX + RX queue pair per
vCPU under Tier 1 polling, with Toeplitz-hashed RSS on gVNIC so
each core's flows stay on that core. TCP 4-tuple lookups are
O(1) via a per-core open-addressed hash table.

## Quick Start

```bash
# Prerequisites (macOS)
brew install bazel qemu

# Build and run (auto-detects host architecture)
bazel run //apps/webserver:webserver

# Test
curl http://localhost:8080/health
```

## Build Configurations

Every `unikernel_binary(name, app)` generates one runnable target per
runner (see `bazel/rules/variants.bzl`); pick the one you want by
target name — no `--config=` flags required.

```bash
# Unikernel (bare-metal) — each variant is a self-contained launcher.
bazel run //apps/webserver:webserver_hvf            # aarch64 HVF runner (macOS)
bazel run //apps/webserver:webserver_qemu_aarch64   # aarch64 QEMU TCG
bazel run //apps/webserver:webserver_qemu_x86_64   # x86_64 QEMU TCG
bazel run //apps/webserver:webserver_iso            # x86_64 Limine ISO via QEMU

# Native (POSIX sockets, no VM) — built under the outer host platform.
bazel run //apps/webserver:webserver_native
```

## Testing

```bash
# Full matrix: runs every applicable variant per app. HVF auto-skips on Linux.
bazel test //...

# Filter by runner — all HVF tests, all qemu tests (both arches), etc.
bazel test --test_tag_filters=hvf          //...
bazel test --test_tag_filters=qemu         //...
bazel test --test_tag_filters=qemu_x86_64  //...
bazel test --test_tag_filters=native       //...

# Single variant of one app.
bazel test //apps/webserver:test_hvf
```

## Writing an Application

The minimal example — a single-route HTTP server that responds with
plain text (see [apps/hello](apps/hello) for the full source):

```rust
#![no_std]
extern crate alloc;
extern crate uni;
use uni::http::{Request, Response, Server};

struct HelloApp { _server: alloc::boxed::Box<Server> }

impl uni::App for HelloApp {}

impl HelloApp {
    fn new() -> Self {
        let mut server = Server::new_boxed();
        server.default_handler(hello);
        server.listen(uni::config_port(80));
        HelloApp { _server: server }
    }
}

fn hello(_: &Request) -> Response {
    Response::ok(b"text/plain", b"Hello from bare metal!\n")
}

#[uni::init]
fn init() {
    uni::run(HelloApp::new());
}
```

For a richer example with HTTPS, multiple routes, and diagnostic
endpoints, see [apps/webserver](apps/webserver).

```python
# apps/myapp/BUILD.bazel
load("@rules_rust//rust:defs.bzl", "rust_library")
load("//bazel/rules:unikernel.bzl", "unikernel_binary")
load("//bazel/rules:rust.bzl", "UNIKERNEL_RUSTC_FLAGS")

rust_library(
    name = "app",
    srcs = ["main.rs"],
    deps = ["//uni"],
    rustc_flags = UNIKERNEL_RUSTC_FLAGS,
)

unikernel_binary(
    name = "myapp",
    app = ":app",
)
```

## Project Layout

```
unikernel/
├── apps/hello/             Minimal HTTP hello-world example (~30 LOC)
├── apps/webserver/         Full demo: HTTP + HTTPS + diagnostics
├── uni/                    Platform abstraction crate
│   ├── lib.rs              TcpListener, TcpStream, log, config
│   ├── http.rs             HTTP/1.1 server (+ TLS wrapper)
│   ├── unikernel.rs        Unikernel backend (serial, idle)
│   ├── native.rs           Native POSIX backend (sockets)
│   └── macros/             #[uni::init] proc macro
├── net/                    Network stack crate
│   ├── ethernet.rs, arp.rs, ipv4.rs, udp.rs, dhcp.rs
│   ├── tcp.rs              TCP + per-core 4-tuple hash table
│   ├── tls_server.rs       TLS 1.3 state machine (hand-rolled)
│   └── tls_handshake.rs    ECDSA P-256 + X25519 + ChaCha20-Poly1305
├── drivers/                Device driver crate
│   ├── pci.rs              PCI bus scan, BAR assignment
│   ├── virtio.rs           VirtIO transport (modern PCI + MMIO)
│   ├── virtio_net.rs       VirtIO-net driver (TX/RX, legacy MQ)
│   ├── virtio_console.rs   VirtIO console (HVF)
│   ├── gvnic.rs            Google Virtual NIC driver (GQI_QPL + RSS)
│   └── net.rs              Runtime NIC dispatch (gVNIC → virtio fallback)
├── kernel/                 Kernel library crate (clean Rust)
│   ├── serial.rs, mm.rs, percpu.rs, eventloop.rs, sync.rs
│   ├── exceptions.rs       GIC interrupt controller (aarch64)
│   └── x86_64/             GDT, IDT, APIC, SMP bring-up (Limine MP)
├── boot/
│   ├── entry.rs            Kernel init sequence
│   ├── limine_entry.rs     Limine boot protocol + AP trampoline
│   ├── x86_64/boot.S       Multiboot2/PVH entry, page tables, long mode
│   └── aarch64/boot.S      ARM64 Image header, relocations, MMU
├── tools/hvf-runner/       Native HVF runner (macOS arm64 dev loop)
├── bazel/                  Toolchain + platform configs
└── scripts/                bench.py, gcp-bench.sh, deploy-gcloud.sh, ...
```

## Performance

### Apples-to-apples vs native Linux, same network path

Both targets on GCE `n2-highcpu-4` VMs with **gVNIC** (4 queue
pairs), same `us-west1-a` zone, benched from a separate VM over
the VPC (`wrk -t4 -d15s` from `kvm-vm`). Same NIC, same queue
count, same wrk client — the unikernel isn't getting a loopback
shortcut or a lighter network stack underneath.

Crucially, **Linux is running its mature in-tree `gve` driver**
(`drivers/net/ethernet/google/gve/`, thousands of lines, years
of tuning); **the unikernel is running the from-scratch gVNIC
driver in [`drivers/gvnic.rs`](drivers/gvnic.rs)**. Linux should
win on driver maturity alone. It doesn't.

| Workload            | Native Linux | **Unikernel** | Δ |
|---------------------|-------------:|--------------:|:-:|
| `/health`      c128 |    278,000   |  **499,000**  | **+79 %** |
| `/health`      c256 |    255,000   |  **514,000**  | **+102 %** |
| `/compute`     c100 |     28,700   |   **32,900**  | **+15 %** |
| `health_tls_max`    |    183,700   |  **294,500**  | **+60 %** |
| `udp_peak` (pkt/s)  |    566,500   |  **787,000**  | **+39 %** |

The unikernel wins every workload because the architecture pays
off more than driver polish does. No POSIX syscalls, no
user/kernel boundary copies, no context switches — the HTTP
handler, TCP state machine, and NIC queue all run in the same
address space on the same core. gVNIC's Toeplitz RSS gives us
per-core RX queues with zero software distribution, and the
TCP 4-tuple lookup is O(1) via a per-core open-addressed hash.
`/health` doubles at `c256` because the per-packet overhead
gap widens as the connection count grows.

Earlier numbers that showed native at ~497 k rps were measured
on `kvm-vm` localhost (kernel-to-kernel socket, no NIC, no
Ethernet framing). That's not a fair comparison; over a real
network path, native pays its full POSIX + general-purpose-TCP
overhead and the unikernel pulls ahead.

### Alternate NICs on GCE

Same `n2-highcpu-4` host, `/health 4t/c128`:

| NIC                       | rps | notes |
|---------------------------|----:|-------|
| virtio-net                | — (bench fails) | GCE's legacy virtio backend stalls under `wrk -c128` bursts |
| gVNIC, `queue-count=2`    | 411,000 | one physical core effectively — HT pair shares L1 |
| **gVNIC, `queue-count=4`**| **499,000** | one queue per vCPU; Toeplitz RSS; TCP hash table |

### Running the benchmark

From a VM in the same region as the deployed unikernel:

```bash
python3 scripts/bench.py --env remote --target 10.138.x.y \
    --cores 4 --duration 15
```

`scripts/gcp-bench.sh` wraps this for the kvm-vm path and
also runs the nested-KVM / native reference targets.

## Deploying to GCE

```bash
# From your workstation — builds image + creates instance
./scripts/deploy-gcloud.sh deploy

# Defaults: n2-highcpu-4 + gVNIC + queue-count=4. Override via env:
UNIKERNEL_GCE_MACHINE=n2-standard-2 QUEUE_COUNT=2 \
    ./scripts/deploy-gcloud.sh deploy

# Tail the serial console (boot log ends with `Entering event loop.`)
./scripts/deploy-gcloud.sh logs

# Stop / delete
./scripts/deploy-gcloud.sh purge
```
