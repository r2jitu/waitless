# UniKernel

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Author**: Jitu Das

A bare-metal unikernel written in Rust that boots directly into an application with no OS, no syscalls, and no context switches. All I/O is handled via direct in-process function calls.

Runs on **x86_64** and **ARM64 (aarch64)** via QEMU, Apple Hypervisor.framework (HVF), and Limine ISO.

## Architecture

```
┌─────────────────────────────────────┐
│           Application               │  apps/webserver/
│         #[uni::main]                │
├─────────────────────────────────────┤
│    Platform Abstraction (uni)       │  uni/ (HTTP, TCP, logging)
├─────────────────────────────────────┤
│       Network Stack (net)           │  net/ (TCP, IPv4, ARP, DHCP, Ethernet)
├─────────────────────────────────────┤
│     Drivers (virtio-net, PCI)       │  drivers/ (PCI, VirtIO, VirtIO-net)
├─────────────────────────────────────┤
│       Kernel (serial, mm, ...)      │  kernel/ (types, serial, mm, fdt, mmu,
│                                     │          exceptions, x86_64 gdt/idt)
├─────────────────────────────────────┤
│        Boot / Entry                 │  boot/ (entry.rs, limine, boot.S)
└─────────────────────────────────────┘
         x86_64          aarch64
     (Multiboot2/PVH)  (Linux Image/DTB)
```

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

```bash
# Unikernel (bare-metal)
bazel build --config=hvf  //apps/webserver:webserver.img    # ARM64 HVF runner (macOS)
bazel build --config=qemu //apps/webserver:webserver.elf    # QEMU (host arch)
bazel build --config=x86_64-qemu //apps/webserver:webserver.elf

# Native (POSIX sockets, no VM)
bazel build --config=aarch64-macos //apps/webserver:webserver_native
bazel build --config=x86_64-linux  //apps/webserver:webserver_native

# Limine ISO (BIOS + UEFI)
bazel build --config=x86_64-iso //apps/webserver:webserver.iso
```

## Testing

```bash
bazel test //apps/webserver:test                        # native (no VM)
bazel test --config=hvf  //apps/webserver:test          # HVF runner (macOS arm64)
bazel test --config=qemu //apps/webserver:test          # QEMU (host arch)
bazel test --config=x86_64-qemu //apps/webserver:test   # QEMU x86_64
```

## Writing an Application

```rust
#![no_std]
extern crate uni;
use uni::http::{Request, Response, Server};

#[uni::main]
fn main() {
    let mut server = /* ... */;
    server.default_handler(|req: &Request| {
        Response::ok(b"text/plain", b"Hello from bare metal!")
    });
    server.run(uni::config_port(80));
}
```

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
├── apps/webserver/         Application (HTTP server example)
├── uni/                    Platform abstraction crate
│   ├── lib.rs              TcpListener, TcpStream, log, config
│   ├── http.rs             HTTP/1.1 server
│   ├── unikernel.rs        Unikernel backend (serial, idle)
│   ├── native.rs           Native POSIX backend (sockets)
│   └── macros/             #[uni::main] proc macro
├── net/                    Network stack crate
│   ├── ethernet.rs, arp.rs, ipv4.rs, tcp.rs, dhcp.rs
│   └── types.rs            MacAddr, Ipv4Addr, checksum
├── drivers/                Device driver crate
│   ├── pci.rs              PCI bus scan, BAR assignment
│   ├── virtio.rs           VirtIO transport (modern PCI + MMIO)
│   ├── virtio_net.rs       Network device (TX/RX, IRQ)
│   └── virtio_console.rs   VirtIO console device (PCI-based platforms)
├── kernel/                 Kernel library crate (clean Rust)
│   ├── serial.rs           UART (COM1 / PL011 / VirtIO console)
│   ├── mm.rs               Physical frame allocator + heap
│   ├── fdt.rs              Device tree parser (aarch64)
│   ├── mmu.rs              Page table management
│   ├── exceptions.rs       GIC interrupt controller (aarch64)
│   └── x86_64/             GDT, IDT, PIC (x86_64)
├── boot/                   Boot/entry code (unsafe, asm, #[no_mangle])
│   ├── entry.rs            Kernel init sequence + global_asm!(boot.S)
│   ├── limine_entry.rs     Limine boot protocol
│   ├── libc.rs             memcpy/memset (compiler intrinsics)
│   ├── x86_64/boot.S       Multiboot2/PVH entry, page tables, long mode
│   ├── x86_64/idt_stubs.S  256 ISR stubs
│   └── aarch64/boot.S      ARM64 Image header, relocations, MMU
├── bazel/
│   ├── rules/              unikernel_binary() macro, runner scripts
│   ├── toolchain/          CC toolchain config, linker scripts
│   └── platforms/          Platform definitions
└── scripts/                Benchmark, deployment, test helpers
```

## Benchmarks

```bash
./scripts/bench.sh
```

Measures throughput and latency across the HVF runner, QEMU TCG, Docker/Linux, and native macOS.
