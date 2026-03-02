# UniKernel

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Author**: Jitu Das

A bare-metal unikernel written in C++ that boots directly into an application with no OS, no syscalls, and no context switches. All I/O is handled via direct in-process function calls.

Runs on both **x86_64** and **ARM64 (aarch64)** via QEMU.

## Architecture

```
┌─────────────────────────────────────┐
│           Application               │  apps/webserver/
│         (uni_main())                │
├─────────────────────────────────────┤
│         Network Stack               │  net/ (TCP, IPv4, ARP, DHCP, HTTP)
├─────────────────────────────────────┤
│       virtio-net Driver             │  drivers/virtio_net.cc
│         PCI Driver                  │  drivers/pci.cc
├─────────────────────────────────────┤
│       Kernel Subsystems             │  kernel/ (MM, GDT, IDT, serial)
├─────────────────────────────────────┤
│        Boot / HAL                   │  kernel/boot.S, kernel/arch.h
└─────────────────────────────────────┘
         x86_64          aarch64
     (Multiboot2/PVH)  (QEMU virt DTB)
```

### Boot Flow

**x86_64**: QEMU loads the ELF kernel via the PVH (Xen) boot path. The kernel starts in 32-bit protected mode, sets up 4-level page tables (1 GB identity-mapped with 2 MB pages), enables PAE and long mode, loads a 64-bit GDT, and far-jumps into 64-bit code before calling `kernel_main()`.

**aarch64**: QEMU loads the ELF kernel directly. The kernel starts at EL1, sets up 4 KB page table entries covering 1 GB of physical memory, enables the MMU and caches, then calls `kernel_main()`.

### Subsystems

| Subsystem | Files | Notes |
|-----------|-------|-------|
| Serial output | `kernel/serial.cc` | UART 16550 (x86) / PL011 (ARM64) |
| Memory manager | `kernel/mm.cc` | Physical page allocator; parses PVH/multiboot2 or uses 128 MB fallback |
| GDT / IDT | `kernel/gdt.cc`, `kernel/idt.cc` | x86_64 only |
| Exception vectors | `kernel/aarch64/exceptions.cc` | aarch64 only |
| PCI bus scan | `drivers/pci.cc` | Config Mechanism #1 (x86), ECAM at 0x4010000000 (ARM64) |
| PCI BAR allocation | `drivers/pci.cc` | ARM64 only — no firmware to assign BARs with `-kernel` |
| virtio-net | `drivers/virtio_net.cc` | Split virtqueue, virtio 1.0 legacy |
| Ethernet / ARP | `net/ethernet.cc`, `net/arp.cc` | |
| IPv4 / UDP | `net/ipv4.cc` | |
| DHCP | `net/dhcp.cc` | DORA sequence |
| TCP | `net/tcp.cc` | Connection-oriented, single-threaded |
| HTTP | `net/http.cc` | Minimal HTTP/1.1 server |

## Build

### Prerequisites

```bash
# macOS (Homebrew)
brew install bazel qemu
```

The build uses a hermetic Bazel C++ toolchain with `musl-libc` for both x86_64 and aarch64 cross-compilation. No host compiler is required beyond what Bazel downloads.

### x86_64

```bash
bazel build //apps/webserver:webserver.elf
```

### ARM64 (aarch64)

```bash
bazel build --config=aarch64 //apps/webserver:webserver.elf
```

## Run

### bazel run (recommended)

Build and launch QEMU in one command:

```bash
# x86_64 (default)
bazel run //apps/webserver:run

# ARM64 / Apple Silicon
bazel run --config=aarch64 //apps/webserver:run
```

Architecture detection is automatic — `run-local.sh` reads `uname -m` and selects the right QEMU binary. On Apple Silicon, it tries HVF acceleration first and falls back to TCG `cortex-a57`.

### Script directly

```bash
./scripts/run-local.sh                      # auto-build + run (x86_64)
./scripts/run-local.sh path/to/kernel.elf  # run a pre-built ELF
```

Once booted, test the HTTP server:

```bash
curl http://localhost:8080/
curl http://localhost:8080/health
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `UNIKERNEL_MEMORY` | `128` | VM RAM in MB |
| `UNIKERNEL_CPUS` | `1` | vCPU count |
| `UNIKERNEL_PORT` | `8080` | Host port forwarded to VM port 80 |

## Testing

The integration test boots the webserver in QEMU and verifies HTTP endpoint responses:

```bash
# x86_64 (default)
bazel test //apps/webserver:integration_test

# aarch64
bazel test --config=aarch64 //apps/webserver:integration_test
```

Requirements: `qemu-system-{x86_64,aarch64}` (`brew install qemu`). If the QEMU binary is not found the test exits 0 (skip, not fail).

### What is tested

| Test | What it covers |
|------|---------------|
| `integration_test` | Boots webserver in QEMU; verifies `GET /` → 200, `GET /health` → 200, `GET /xyz` → 404, `POST /` → 200 |

## Writing an Application

Implement the `uni_main()` function and link against the unikernel library:

```cpp
// apps/myapp/main.cc
#include "unikernel/unikernel.h"
#include "net/http.h"

extern "C" int uni_main() {
    net::http::serve(80, [](const net::http::Request& req,
                             net::http::Response& resp) {
        resp.status = 200;
        resp.body   = "Hello from bare metal!\n";
    });
    return 0;
}
```

```python
# apps/myapp/BUILD.bazel
cc_binary(
    name = "myapp.elf",
    srcs = ["main.cc"],
    deps = [
        "//kernel:kernel",
        "//net:http",
    ],
    linkopts = ["-T$(location //bazel/toolchain:unikernel.ld)"],
)
```

## Project Layout

```
unikernel/
├── apps/
│   └── webserver/          # Example HTTP server application
├── bazel/
│   └── toolchain/          # Hermetic C++ cross-compilation toolchain
│       ├── cc_toolchain_config.bzl
│       └── unikernel.ld    # Linker script
├── drivers/
│   ├── pci.{h,cc}          # PCI bus enumeration and BAR allocation
│   ├── virtio.{h,cc}       # virtio split virtqueue primitives
│   └── virtio_net.{h,cc}   # virtio-net NIC driver
├── include/
│   └── unikernel/          # Public API headers
├── kernel/
│   ├── aarch64/            # ARM64-specific boot and exception handling
│   ├── boot.S              # x86_64 32→64-bit boot entry (Multiboot2 + PVH)
│   ├── entry.cc            # C++ kernel_main(): subsystem init sequence
│   ├── mm.{h,cc}           # Physical memory manager
│   ├── gdt.{h,cc}          # Global Descriptor Table (x86_64)
│   ├── idt.{h,cc}          # Interrupt Descriptor Table (x86_64)
│   └── serial.{h,cc}       # Serial console (UART)
├── net/
│   ├── ethernet.{h,cc}     # Ethernet frame TX/RX
│   ├── arp.{h,cc}          # ARP request/reply
│   ├── ipv4.{h,cc}         # IPv4 send/receive
│   ├── dhcp.{h,cc}         # DHCP client
│   ├── tcp.{h,cc}          # TCP stack
│   └── http.{h,cc}         # HTTP/1.1 server
└── scripts/
    └── run-local.sh        # QEMU launcher script
```

## Design Notes

- **No OS primitives**: no heap allocator beyond a simple bump allocator, no threads, no file system, no virtual memory beyond the 1 GB identity map.
- **Single address space**: the kernel and application share the same privilege level and address space. All function calls are direct.
- **ARM64 BAR allocation**: QEMU's `-kernel` flag does not invoke firmware, so PCI BARs are unassigned. The kernel allocates BARs from the PCIe resource windows specified in the QEMU virt DTB (`ranges` property).
- **ARM64 I/O ports → MMIO**: ARM64 has no I/O port instructions. virtio-net BAR0 (I/O space) is accessed at `0x3EFF0000 + port` (the PCIe I/O window CPU base from DTB).
- **`-mstrict-align`**: the ARM64 toolchain uses `-mstrict-align` to prevent the compiler from generating unaligned load/store instructions, which fault in QEMU's TCG soft-emulation even with `SCTLR_EL1.A=0`.
