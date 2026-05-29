# Waitless Roadmap

What's next for the Waitless network stack. The shipped stack — the async
runtime, TLS 1.3, UDP/QUIC, HTTP/3, IPv6/NDP — is **done**; its design and
rationale are recorded in [`design-history.md`](design-history.md), and current
state is indexed in [`README.md`](README.md).

Granular live work lives in the backlog trackers, not here:

- QUIC RFC 9000/9002 — [`conformance-roadmap.md`](conformance-roadmap.md)
- TCP RFC gaps — [`tcp-conformance-backlog.md`](tcp-conformance-backlog.md)
- Per-byte RX/TX cost — [`rx-path-optimizations.md`](rx-path-optimizations.md) / [`tx-path-optimizations.md`](tx-path-optimizations.md)
- Inter-layer API contracts / the two-stacks → one-golden-path direction — [`stack-architecture.md`](stack-architecture.md)

This doc is the higher-level "what major work remains" view that ties those together.

## Current frontier

Phases 1–5 shipped; no headline phase remains. The open work is **correctness
depth and performance**, not new subsystems:

- **QUIC loss recovery + congestion control (RFC 9002)** — the PTO timer, RTT
  estimator, and loss detection landed; **frame retransmission** and a
  **congestion controller** remain → [`conformance-roadmap.md`](conformance-roadmap.md) step 5.
- **TCP conformance** — window scaling (RFC 7323), SACK, … → [`tcp-conformance-backlog.md`](tcp-conformance-backlog.md).
- **RX/TX datapath** — RX offload (HW GRO/RSC), conn-state / conn-future pools, owned-UDP zero-copy → [`rx-path-optimizations.md`](rx-path-optimizations.md) / [`tx-path-optimizations.md`](tx-path-optimizations.md).
- **Inter-layer contracts** — converging the TCP/TLS/HTTP-1.1 and UDP/QUIC/HTTP-3 stacks onto one golden path (the `ByteStream` trait, the owned buffer currency, the NIC/reactor vtable→trait migrations) → [`stack-architecture.md`](stack-architecture.md).

## Phase 6 — advanced features (future)

Net-new subsystems, none started.

### Virtio-vsock

Replace virtio-net for VM↔host communication. No Ethernet/IP overhead. Useful
for HVF / QEMU-on-macOS ultra-low-latency host communication.

- [ ] virtio-vsock driver
- [ ] Host communication API

### eBPF packet filter

Programmable packet processing in the unikernel. Run user-supplied eBPF
programs for custom filtering/routing.

- [ ] eBPF bytecode interpreter
- [ ] Packet filter hook points

### io_uring-style submission queues

Replace poll-based I/O with submission/completion queues. Natural fit for
QUIC's async nature.

- [ ] Submission/completion ring buffers
- [ ] Async I/O API

## Deferred & parked

Items deferred during development, each with a "why now" trigger. The detailed
write-ups — and the deferred items that have since *shipped* (production cert
path, session resumption, the h3-on-gve fix, bare-metal TCP corners) — live in
[`design-history.md`](design-history.md) under "Deferred work".

- **Production RNG** — the dev `kernel::rng` (jitter entropy + ChaCha20 expansion) is not a production CSPRNG; needs an entropy-rate estimate, periodic reseed, and virtio-rng / aarch64 RNDR sources. *Trigger: before any production deploy handling real cert generation, tickets, or client auth.*
- **x86_64 SSE/AVX baseline target JSON** — replace the per-crate crypto `rustc_flags` annotations in `MODULE.bazel` with one custom target spec. *Trigger: when the annotation list exceeds ~10–12 crates.* (May partly overlap the landed hard-float target — verify scope first.)
- **Faster ECDSA P-256** — `cv_sign` is the cold-handshake hotspot; `fiat-p256` (~2×) or `ring` (5–10×, build-system pain) are the levers. *Trigger: to cut cold-handshake latency now that session resumption has landed.*
- **Real wall-clock time source** — only monotonic ticks today; ~30 lines for absolute time. *Trigger: cert validity windows / ticket lifetimes / QUIC key-update guidance.*
- **TLS panic-strategy host unit tests** — crates with `-Cpanic=abort` deps can't host-test; coverage currently lives in bare-metal integration tests. *Trigger: when an integration test catches something a host unit test would have caught faster.*
- **Cooperative-drain shutdown** — today's shutdown force-aborts in-flight handlers (peer sees RST mid-response); add a bounded cooperative drain phase. *Trigger: long-running RPCs, or QUIC clean CONNECTION_CLOSE.*
- **Lift `tcp` / `udp` above `executor`** — make L4 an app-space library (swap in smoltcp / custom congestion control). The vtable seam already exists; "lift, don't refactor." Closely tied to the NIC/reactor backend-trait migration in [`stack-architecture.md`](stack-architecture.md). *Trigger: QUIC wants to share `tcp`'s per-core scaffolding, or a consumer wants to swap L4.*
- **Hermit pivot option** — target `x86_64-unknown-hermit` + build-std to unlock libstd (quinn-proto unchanged). Spiked (~16 syscalls, ~1–2 days of shim); parked in favour of the own-QUIC path. *Trigger: an ecosystem wall that requires std, or the own-QUIC work stalls.*
- **macOS delayed-ACK regression check** — immediate-ACK shipped (fixed a GCP KVM handshake stall); only re-add a timer-based ACK coalescer if the macOS ~250 ms keep-alive p99 resurfaces. *Trigger: HVF `health_max` shows that p99.*
- **Work stealing (2d)** and **perf regression tests (2h)** — parked Phase-2 items → see `design-history.md` Phase 2.

## The bet

`async fn` as the *only* execution model — the executor **is** the kernel —
with a QUIC-first, `no_std`, per-core lock-free design that has no prior art in
combination (Tokio/smol run above Linux; Embassy is single-core; Hermit targets
libstd). The full thesis is in [`design-history.md`](design-history.md)
(Design Principles) and [`stack-architecture.md`](stack-architecture.md).
