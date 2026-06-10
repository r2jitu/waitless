# Waitless Roadmap

What's next for the Waitless network stack. The shipped stack — the async
runtime, TLS 1.3, UDP/QUIC, HTTP/3, IPv6/NDP — is **done**; its design and
rationale are recorded in [`design-history.md`](design-history.md), and current
state is indexed in [`README.md`](README.md).

Granular live work lives in the backlog trackers, not here:

- QUIC RFC 9000/9002 — [`conformance-roadmap.md`](conformance-roadmap.md)
- TCP RFC gaps — [`tcp-backlog.md`](tcp-backlog.md)
- Per-byte RX/TX cost — [`rx-path-optimizations.md`](rx-path-optimizations.md) / [`tx-path-optimizations.md`](tx-path-optimizations.md)
- Inter-layer API contracts / the two-stacks → one-golden-path direction — [`stack-architecture.md`](stack-architecture.md)

This doc is the higher-level "what major work remains" view that ties those together.

## Current frontier

Phases 1–5 shipped; no headline phase remains. The open work is **correctness
depth and performance**, not new subsystems:

- **QUIC loss recovery + congestion control (RFC 9002)** — ✅ landed: the PTO
  timer (with exponential backoff), RTT estimator, loss detection,
  STREAM-frame retransmission, and a NewReno congestion controller (cwnd-gated
  packetization + pacing) all ship → [`conformance-roadmap.md`](conformance-roadmap.md)
  step 5. The controller landed as the **shared TCP+QUIC congestion core**
  (`crates/net/cc` — the `CongestionControl` trait + NewReno), and **both
  transports now delegate to it** (TCP's hand-rolled RFC 5681 cwnd replaced
  2026-06-08, netem + GCE validated). The remaining transport work is the
  CUBIC/BBR algorithms + a TCP-side pacer →
  [`stack-architecture.md`](stack-architecture.md) *Transport reliability*. One
  QUIC residual: CRYPTO-frame retx still rides a bare PTO PING.
- **TCP conformance + Linux performance parity** — window scaling (RFC 7323), ABC, and peer-MSS honor (the 5G/NAT64 cert-flight fix) ✅ shipped & validated; SACK, out-of-order reassembly, and the Linux-parity gaps (Reno→CUBIC/BBR, pacing, RACK-TLP) remain → [`tcp-backlog.md`](tcp-backlog.md).
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

- **Production RNG** — ✅ *substantially hardened (2026-06-09):* `kernel::rng` (SHA-256 Hash_DRBG; ChaCha20 was replaced earlier) now does **periodic reseed** (fold fresh jitter + HW entropy into the seed every 1 MiB of output — SP 800-90A reseed: bounded output/seed, ongoing entropy, self-healing) and mixes **multiple hardware sources** (RDSEED + RDRAND on x86_64, `RNDR`/FEAT_RNG on aarch64 where implemented; all best-effort + folded, never trusted alone). Both-arch handshake validated (HVF + QEMU-x86 `-cpu max`). A **min-entropy estimate** now lands too (2026-06-09): `kernel_core::entropy_health` runs the NIST SP 800-90B startup health tests (Repetition Count + Adaptive Proportion) and the Most-Common-Value min-entropy estimator over the cold-boot jitter samples (pure integer fixed-point math, host-unit-tested), surfaced on `/obs` as `rng_min_entropy_mbits` / `rng_rct_pass` / `rng_apt_pass`. *Remaining:* a virtio-rng / RNDRRS health-checked collector, and a *formally-analysed* per-target bound (the MCV estimate is the standard runtime estimator, not a certified offline analysis). *Trigger: a security audit requiring a certified min-entropy bound, or a target with neither HW RNG nor trustworthy jitter.*
- **x86_64 SSE/AVX baseline target JSON** — replace the per-crate crypto `rustc_flags` annotations in `MODULE.bazel` with one custom target spec. *Trigger: when the annotation list exceeds ~10–12 crates.* (May partly overlap the landed hard-float target — verify scope first.)
- **Faster ECDSA P-256** — `cv_sign` is the cold-handshake hotspot; `fiat-p256` (~2×) or `ring` (5–10×, build-system pain) are the levers. *Trigger: to cut cold-handshake latency now that session resumption has landed.*
- **Real wall-clock time source** — ✅ *done (2026-06-09):* `kernel_core::clock::wall_unix_secs()` — the platform RTC read once at boot (x86 CMOS ports 0x70/0x71, BCD/12h-aware) → Unix-epoch base + monotonic offset; `civil_to_unix_secs` date math is host-unit-tested; on `/obs` as `wall_unix_secs`. aarch64 reports unavailable (`0`) for now (no PL031 mapped / HVF emulates none). *Remaining: an aarch64 PL031 backend once a platform maps it.*
- **TLS panic-strategy host unit tests** — crates with `-Cpanic=abort` deps can't host-test; coverage currently lives in bare-metal integration tests. *Trigger: when an integration test catches something a host unit test would have caught faster.*
- **Cooperative-drain shutdown** — today's shutdown force-aborts in-flight handlers (peer sees RST mid-response); add a bounded cooperative drain phase. *Trigger: long-running RPCs, or QUIC clean CONNECTION_CLOSE.*
- **Lift `tcp` / `udp` above `executor`** — make L4 an app-space library (swap in smoltcp / custom congestion control). The vtable seam already exists; "lift, don't refactor." Closely tied to the NIC/reactor backend-trait migration and the **shared TCP+QUIC congestion core** (`crates/net/cc` — the `CongestionControl` trait + NewReno, now backing **both** transports; what remains is CUBIC/BBR + TCP-side pacing, written once) in [`stack-architecture.md`](stack-architecture.md). *Trigger: QUIC wants to share `tcp`'s per-core scaffolding or needs its RFC 9002 controller, or a consumer wants to swap L4.*
- ✅ **Per-core egress scheduler — shipped (2026-06).** The DRR fair queue now owns QUIC's steady-state TX (build-at-drain, per-packet zero-copy, +3.9% h3 rps) and lives in its only consumer as `proto/quic/src/drr.rs`; TCP deliberately stays direct-submit ("the convergence — and where it stops" in [`tx-backpressure.md`](tx-backpressure.md)).
- **Hermit pivot option** — target `x86_64-unknown-hermit` + build-std to unlock libstd (quinn-proto unchanged). Spiked (~16 syscalls, ~1–2 days of shim); parked in favour of the own-QUIC path. *Trigger: an ecosystem wall that requires std, or the own-QUIC work stalls.*
- **macOS delayed-ACK regression check** — immediate-ACK shipped (fixed a GCP KVM handshake stall); only re-add a timer-based ACK coalescer if the macOS ~250 ms keep-alive p99 resurfaces. *Trigger: HVF `health_max` shows that p99.*
- **Work stealing (2d)** and **perf regression tests (2h)** — parked Phase-2 items → see `design-history.md` Phase 2.

## The bet

`async fn` as the *only* execution model — the executor **is** the kernel —
with a QUIC-first, `no_std`, per-core lock-free design that has no prior art in
combination (Tokio/smol run above Linux; Embassy is single-core; Hermit targets
libstd). The full thesis is in [`design-history.md`](design-history.md)
(Design Principles) and [`stack-architecture.md`](stack-architecture.md).
