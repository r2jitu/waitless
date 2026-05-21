# Crate taxonomy

Canonical reference for the crate organization of this repository. Every
library crate is a Bazel `rust_library` target; the apps under `apps/`
build via the `unikernel_binary` macro on top of them. There are no
Cargo crates in the bare-metal build — see [§Publishing](#publishing).

## Repo layout

```
apps/        unikernel binaries (built via the unikernel_binary rule)
bazel/       build infrastructure
crates/      all library crates, grouped by domain
docs/        this directory
scripts/     dev, deploy, and bench scripts
tools/       host CLIs (hvf-runner)
```

The `crates/` tree:

```
crates/
  util/        atomic-fn/  tagged-treiber/  iobuf/
  crypto/      aes-gcm/
  runtime/     platform/  worker/  executor/
  kernel/      core/  bare/
  boot/        entry, limine, mem_stubs, multiboot   (shared Bazel package)
  drivers/     bus/  nic/  virtio-net/  gve/
               nic/ is a shared package: targets :api (the trait) + :nic (dispatch)
  net/         tcp/  stack/                           (own dirs)
               +  shared package: types, checksum, from_bytes, ethernet,
                  ethernet_send, arp, ipv4, ipv6, icmpv6, ndp, mac_resolve,
                  ipv6_send, classify, udp, dhcp
  proto/       tls/  quic/  http/  http3/
  uni/         macros/  net/  backend/        (uni is the facade and
                                                the parent of its
                                                three satellites)
```

(`tests/integration/` at repo root holds the boot-and-verify
integration tests — `async/`, `percpu/`, `smp/`, `tls/` — that used
to live alongside the real apps under `apps/`.)

## Naming rules

1. **Directory tree.** Crates live at `crates/<domain>/<name>/` for
   most crates. Domains: `util crypto runtime kernel boot drivers net
   proto`. The `uni` facade is special — it's BOTH a crate (at
   `crates/uni/`) AND the parent of its three satellites
   (`crates/uni/{macros, net, backend}/`). The satellites exist
   solely to support uni (proc-macro pairing, cfg-gated net
   re-export, cfg-gated platform impl), so nesting them under uni
   honestly reflects that relationship. Kebab-case throughout.
2. **Bazel target.** Default target = directory name. `//crates/net/tcp`
   is shorthand for `//crates/net/tcp:tcp`. No hyphenated explicit
   target names — the target's `name = "..."` always matches its
   directory's last path component.
3. **Rust `crate_name`.** Just the leaf name (`tcp`, `tls`, `iobuf`,
   `gve`). Qualify with one domain word only when the bare name would
   shadow `std`/`core` or collide with a common external crate. Current
   qualified names: `net_types`, `net_checksum`, `net_from_bytes`,
   `net_classify`, `kernel_core`, `net_stack`. The uni facade
   family keeps the `uni_` prefix as a meaningful "satellite of uni"
   marker: `uni`, `uni_macros`, `uni_net`. Two further carve-outs
   for external/internal collisions: `uni_aes_gcm` (RustCrypto's
   `aes-gcm` crate is pulled in via `@crates//:aes-gcm`). The kernel's
   os:none half is `kernel_bare`, chosen for sibling symmetry with
   `kernel_core` (a bare `kernel` name would be too overloaded).
4. **Cargo package name** (publishable leaves only, if/when published):
   chosen at publish time for crates.io availability. Internal name is
   unchanged. See [§Publishing](#publishing).

## When a crate gets its own directory

Own directory iff **any** of: already multi-file, large enough to want
submodules, or publish-targeted. Otherwise small/single-file/cohesive
crates **share a Bazel package** — one `BUILD.bazel`, one shared
`src/`, one `rust_library` target per crate.

Applied:
- `crates/net/` — 15 small wire-format / per-protocol crates share a
  package. The heavy crates (`tcp/`, `stack/`) live in subdirectories.
- `crates/boot/` — 4 link-time-symbol providers (`entry`, `limine`,
  `mem_stubs`, `multiboot`) share one package; none has meaningful
  logic of its own.
- `crates/drivers/nic/` — `:api` (the `EthernetDriver` trait + the
  `ACTIVE_OPS` registry) and `:nic` (the dispatch shim) live as two
  targets in one package. They're two halves of the same thing.

Everywhere else is one crate per directory.

Within a shared package, each `.rs` file in `src/` is its own crate;
the `BUILD.bazel` is the authoritative list. The `rust-project.json`
generator (`@rules_rust//tools/rust_analyzer`) emits one entry per
`rust_library`, so rust-analyzer sees each as a distinct crate
regardless of source layout.

## Layering

The build graph is acyclic. Crates are listed below by tier; a crate
in tier N depends only on crates in tier < N. First-party deps only —
external `@crates//:...` deps are omitted for readability.

### Tier 0 — pure leaves (no first-party deps)

| Crate | Where | What |
| --- | --- | --- |
| `atomic_fn` | `util/atomic-fn` | Typed atomic function-pointer cell |
| `tagged_treiber` | `util/tagged-treiber` | Lock-free Treiber stack with ABA-protection tag |
| `platform` | `runtime/platform` | `current_worker()`, `now_ticks()` (cfg-gated leaf) |
| `net_types` | `net/` (shared) | Wire-format type defs (load-bearing — see [cycle break](#why-net_types-is-a-separate-crate-the-cycle-break)) |
| `net_from_bytes` | `net/` (shared) | `try_ref_from(&[u8])` for packed packet headers |
| `uni_aes_gcm` | `crypto/aes-gcm` | Hand-rolled AES-128-GCM (external `aes` only) |

### Tier 1 — primitives

| Crate | Deps |
| --- | --- |
| `iobuf` | `tagged_treiber` |
| `worker` | `platform` |
| `net_checksum` | `net_types` |
| `ethernet` | `net_from_bytes`, `net_types` |
| `ipv6` | `net_from_bytes`, `net_types` |
| `icmpv6` | `net_checksum`, `net_types` |

### Tier 2 — runtime substrate

| Crate | Deps |
| --- | --- |
| `nic_api` | `iobuf` |
| `executor` | `net_types`, `iobuf`, `nic_api`, `platform`, `worker` |

### Tier 3 — kernel core + kernel-dependent leaves

| Crate | Deps |
| --- | --- |
| `kernel_core` | `net_types`, `iobuf`, `executor`, `worker`, `atomic_fn`, `tagged_treiber` |
| `nic` | `nic_api` |
| `ethernet_send` | `ethernet`, `net_types`, `nic` |
| `ipv4` | `net_checksum`, `net_from_bytes`, `net_types`, `kernel_core` |
| `ndp` | `net_types`, `kernel_core` |
| `net_classify` | `ethernet`, `ipv4`, `ipv6`, `net_types` |

### Tier 4 — bare kernel + L3 helpers

| Crate | Deps |
| --- | --- |
| `kernel_bare` | `net_types`, `kernel_core`, `iobuf`, `executor`, `worker`, `platform`, `atomic_fn`, `tagged_treiber` |
| `arp` | `ethernet`, `ethernet_send`, `net_from_bytes`, `net_types`, `nic`, `kernel_core`, `iobuf` |
| `mac_resolve` | `arp`, `ndp`, `net_types` |
| `ipv6_send` | `ethernet`, `ethernet_send`, `icmpv6`, `ipv6`, `ndp`, `net_types` |

### Tier 5 — stateful protocols + bus

| Crate | Deps |
| --- | --- |
| `tcp` | `net_checksum`, `ethernet`, `net_from_bytes`, `ipv4`, `ipv6`, `ipv6_send`, `mac_resolve`, `net_types`, `nic`, `nic_api`, `kernel_core`, `iobuf`, `executor`, `worker` |
| `udp` | same as `tcp` minus `kernel_core` and `worker` |
| `dhcp` | `arp`, `ethernet`, `net_from_bytes`, `ipv4`, `net_types`, `kernel_bare`, `executor` |
| `bus` | `kernel_bare` |

### Tier 6 — net stack umbrella + NIC drivers

| Crate | Deps |
| --- | --- |
| `net_stack` | `arp`, `net_classify`, `dhcp`, `ethernet`, `ethernet_send`, `icmpv6`, `ipv4`, `ipv6`, `ipv6_send`, `ndp`, `tcp`, `net_types`, `udp`, `nic`, `kernel_bare`, `iobuf`, `executor` |
| `gve` | `bus`, `kernel_bare`, `iobuf`, `nic_api` |
| `virtio_net` | `bus`, `kernel_bare`, `net_checksum`, `iobuf`, `nic_api` |

### Tier 7 — facade plumbing

| Crate | Deps |
| --- | --- |
| `uni_net` (`uni/net`) | `nic_api`; on `os:none` also `net_stack`. Defines `NetError`/`DhcpError` here (the facade-level errors); `NicError` re-exported from `nic_api`. |
| `uni_macros` | proc-macro; no runtime deps |

### Tier 8 — facade backend

| Crate | Deps |
| --- | --- |
| `uni_backend` (`uni/backend`) | `iobuf`, `worker`, `platform`, `executor`, `nic_api`; on `os:none` also `nic`, `kernel_bare`, `net_stack`, `tcp`, `gve` |

### Tier 9 — facade

| Crate | Deps |
| --- | --- |
| `uni` | `uni_backend`, `uni_net`, `executor`, `worker`; on `os:none` also `kernel_bare`; proc-macro `uni_macros` |

### Tiers 10–13 — userspace network protocols

| Crate | Tier | Deps |
| --- | --- | --- |
| `http` | 10 | `uni`, `iobuf`, `worker` |
| `tls` | 11 | `uni`, `uni_aes_gcm`, `http`, `iobuf`, `worker`; on `os:none` also `kernel_bare` |
| `quic` | 12 | `uni`, `iobuf`, `nic_api`, `executor`, `tls` |
| `http3` | 13 | `uni`, `http`, `quic` |

### Tier 14 — boot entries + apps

`crates/boot/entry` consumes the kernel, drivers, net stack, and `uni`
to assemble the bare-metal entrypoint. Apps under `apps/` depend on
`uni` plus the protocols they choose (`http`, `tls`, `quic`, `http3`).

## Three architectural cuts worth understanding

### Why `net_types` is a separate crate (the cycle break)

`kernel_bare`'s `percpu::RxChain` carries a `ParsedL3` value, so the
kernel must depend on something in the net domain. The rest of `net`
depends on `kernel_core` (for `Spinlock`, the per-core IP-ID counter,
etc.). If `net` were a single crate, `kernel_bare → net → kernel_core`
would close into a cycle with `kernel_bare`'s `kernel_core` dependency.

`net_types` is the cut: a zero-dep leaf containing just the wire-format
type definitions the kernel needs. Everything else in `net` is above
`kernel_core` in the tier ordering and can depend on it freely.

**Structural, not aesthetic. Don't merge `net_types` into anything.**

### Why `kernel_core` is split from `kernel_bare`

`kernel_core` is the host-testable pure-logic half: lock-free data
structures, sync primitives, per-core types, the timer wheel, the RNG
trait. Builds on the host; runs `rust_test` targets there.

`kernel_bare` (`crates/kernel/bare`) is the `os:none` half: MMU,
interrupts, APIC/GIC, SMP bring-up, serial — anything that touches
hardware or arch-specific code. Unbuildable on the host
(`target_compatible_with = ["@platforms//os:none"]`).

`kernel_bare` re-exports the public modules of `kernel_core`, so
consumers write `kernel_bare::percpu::...` and don't see the split.

### The NIC driver dispatch chain

```
                     ┌──────────────────────┐
                     │       nic_api        │  EthernetDriver trait
                     │  (drivers/nic:api)   │  + ACTIVE_OPS slot
                     └──────────┬───────────┘
                ┌───────────────┼────────────────┐
                ▼               ▼                ▼
          ┌──────────┐    ┌──────────┐    ┌──────────┐
          │   nic    │    │virtio_net│    │   gve    │   each driver
          │ dispatch │    │          │    │          │   registers into
          └──────────┘    └──────────┘    └──────────┘   ACTIVE_OPS at boot
                ▲
                │
       (called by net_stack, tcp, udp, arp, ethernet_send, …)
```

The split exists so the TX-side network crates (`tcp`, `udp`, `arp`,
`ethernet_send`, `net_stack`) can call `nic::send(...)` without
depending on the `os:none` driver implementations. They link against
`nic` (dispatch shim) and `nic_api` (trait), both
host-buildable.

## What goes above vs below the facade

The `uni` facade is the kernel↔userspace boundary, structurally
equivalent to the syscall surface in a conventional OS. The rule:

- **Below the facade** (`net/`, `drivers/`, `kernel/`): crates that
  *implement* an I/O primitive exposed by the facade, plus everything
  they need to do their job. Lives in the RX/TX pipeline, runs in the
  poll loop, can't sensibly be a library over a socket.
- **Above the facade** (`proto/`): crates that *consume* an I/O
  primitive — sans-io state machines fed by the facade's `TcpListener`
  / `UdpSocket`. Built on the facade like an app would be.

This is why `tcp` lives below but `quic` lives above, even though OSI
puts them at the same layer. The split is implementation-strategy,
not OSI-layer: TCP needs RX-path integration for performance; QUIC
runs as a sans-io library over UDP datagrams (as every real-world
QUIC implementation does). Same split a conventional OS makes between
in-kernel TCP/UDP/IP and userspace TLS/QUIC libraries.

**Edge case: `dhcp` is below the facade despite being a
UDP-consuming protocol**, because it runs during stack bring-up
before the facade exists and builds its datagrams directly from the
wire-format crates. Don't "fix" this by moving it up.

## Publishing

Framework crates (`uni`, `tls`, `http`, `quic`, …) are not on
crates.io and won't be — they're welded to the `unikernel_binary`
build and not consumable standalone; the protocol crates are coupled
internally. crates.io is a library registry, not the right venue for
this project. The project itself lives at GitHub.

Four leaves are *structured* to allow publishing if a specific reason
arises: `atomic_fn`, `tagged_treiber`, `iobuf`, `uni_aes_gcm`. Each is
zero-or-one first-party dep, host-buildable, and host-tested.
Publishing any would require adding a `Cargo.toml` alongside its
`BUILD.bazel`, joining the workspace `Cargo.toml`, and picking a
crates.io-available package name at publish time (e.g. `uni_aes_gcm`
would publish as `aes-gcm-batched` or similar; RustCrypto already owns
`aes-gcm`). The decision is deferred; `uni_aes_gcm` carries a
crypto-maintainer duty of care beyond the others if ever published.
