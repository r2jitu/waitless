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
- System-level long-term directions (capabilities, deterministic simulation, completion-driven reactor, transport engine, flow steering, memory arenas, structural cancel-safety) — [`architecture-audit.md`](architecture-audit.md)

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
  2026-06-08, netem + GCE validated). **CUBIC (RFC 8312) now also lives on the
  shared trait** (`net_cc::Cubic` — cubic window law + TCP-friendly floor +
  fast convergence, fixed-point), selectable per flow via a `Controller` enum
  but **default-Reno** until a GCE/netem throughput A/B justifies flipping it.
  The remaining transport work is BBR + a TCP-side pacer →
  [`stack-architecture.md`](stack-architecture.md) *Transport reliability*.
- **TCP conformance + Linux performance parity** — window scaling (RFC 7323),
  ABC, peer-MSS honor + PMTUD (the 5G/NAT64 cert-flight fix), SACK (RFC 2018 +
  RFC 6675 sender), out-of-order reassembly, CUBIC (RFC 8312), the Tail
  Loss Probe (RFC 8985 — eliminates the tail-loss RTO stall, GCE-validated),
  and RACK time-based loss detection (RFC 8985, consuming the shared
  `net_cc::loss` core) ✅ all shipped & validated. Remaining Linux-parity
  gaps: **BBR**, a **TCP-side pacer**, RACK's **adaptive reo_wnd**
  (min_rtt/4 + DSACK growth), and **Timestamps/PAWS** (RFC 7323) →
  [`tcp-backlog.md`](tcp-backlog.md).
- **RX/TX datapath** — RX offload (HW GRO/RSC), conn-state / conn-future pools, owned-UDP zero-copy → [`rx-path-optimizations.md`](rx-path-optimizations.md) / [`tx-path-optimizations.md`](tx-path-optimizations.md).
- **Inter-layer contracts** — converging the TCP/TLS/HTTP-1.1 and UDP/QUIC/HTTP-3 stacks onto one golden path (the `ByteStream` trait, the owned buffer currency, the NIC/reactor vtable→trait migrations) → [`stack-architecture.md`](stack-architecture.md).

## Known gaps & open items — at a glance

The single index of what's *not* done. The per-subsystem backlogs hold the
detail (the "doc" column); this table is the cross-cutting view so a reader
needn't open six files to see the open set. Severity: **S0** correctness/
safety reachable in normal operation, **S1** impact under adverse/hostile
conditions, **S2** performance ceiling or feature breadth, **S3** low-impact
/ near-non-goal. Items marked † were surfaced by the 2026-06-09 whole-codebase
audit and are documented here (some also in their backlog).

| Area | Open item | Sev | Doc |
|---|---|---|---|
| TCP CC | **BBR** + a **TCP-side pacer** | S2 | tcp-backlog L1/L3 |
| TCP loss | RACK **adaptive reo_wnd** (min_rtt/4, DSACK-grown) — detection itself ✅ landed on the shared `net_cc::loss` core | S2 | tcp-backlog L4 |
| TCP | **Timestamps + PAWS** (RFC 7323) — deliberately deferred | S2 | tcp-backlog T6 |
| TCP CUBIC | under TCP, CUBIC uses SRTT not min-RTT (TCP passes `min_us=0`) † | S2 | tcp-backlog L1 |
| TCP PMTUD | cross-core route of the ICMP report to the flow's core; no immediate re-send of the in-flight oversized segment (waits for RTO/TLP) | S2 | tcp-backlog T2 |
| TCP | **FinWait2 / half-closed** has no time-based idle reap (only reclaimed on pool-full) † | S2 | tcp-backlog |
| L3 (IPv4) | inbound **IP fragments** aren't reassembled (a non-first fragment is fed to L4); no inbound IP/TCP **checksum verify** (relies on NIC RX-csum offload) † | S1 | networking |
| L3 (NDP/ARP) | learn-only: no active solicitation on miss, no RFC 4861 reachability state, FIFO eviction only † | S3 | networking |
| QUIC | ~~peer `ack_delay_exponent` / `max_ack_delay` unparsed~~ ✅ closed 2026-06-10 (parsed + validated + honored in RTT/PTO); still unparsed: `max_udp_payload_size`, `disable_active_migration`, `active_connection_id_limit` | S3 | conformance-roadmap |
| QUIC | **RESET_STREAM / STOP_SENDING** not generated/honored (per-stream abort) † | S1 | conformance-roadmap |
| QUIC | **CID rotation** (NEW/RETIRE_CONNECTION_ID) + WE-initiated PATH_CHALLENGE on a migrated path | S2 | conformance-roadmap |
| QUIC | CONNECTION_CLOSE emitted in only the highest-keys PN space (RFC 9000 §10.2.3) † | S3 | conformance-roadmap |
| QUIC interop | QUIC Interop Runner (external Docker) not wired | S2 | conformance-roadmap |
| TLS | ~~record sequence had no nonce-reuse guard~~ ✅ closed 2026-06-10 (`SEAL_RECORD_LIMIT` 2^24/key — `seal_app_data` refuses → conn closes; KeyUpdate-instead remains TL-2) | S3 | tls-backlog |
| TLS | HelloRetryRequest, full key-update, ticket-key rotation, cipher/curve breadth, 0-RTT (replay-sensitive) | S2 | tls-backlog |
| TLS | AES round-keys not zeroized on drop (single-tenant bare-metal) † | S3 | tls-backlog |
| HTTP/2 | **h2spec** run (external tool); §7 error-code audit; two-GOAWAY drain; ~~receive-window overrun not strictly rejected~~ ✅ closed 2026-06-10 (stream-level debit-on-DATA → RST FLOW_CONTROL_ERROR; conn-level unreachable under credit-on-arrival — H2-14); request **trailers** dropped (no §8.1.2 validation) † | S1/S2 | http2-backlog |
| HTTP/3 | QPACK dynamic table; `SETTINGS_MAX_FIELD_SECTION_SIZE` parsed but unenforced †; header truncation past the slot cap † | S2 | http3-backlog |
| HPACK/QPACK | field-huffman 16 KiB scratch → a >16 KiB literal returns a mis-named `BadPadding` (a resource limit reported as a wire error) † | S3 | http2/http3-backlog |
| Drivers | virtio-net **MMIO** path negotiates `MRG_RXBUF` but its RX can't handle multi-buffer frames (the modern-PCI path strips it) — unsafe-but-benign on current hosts † | S1 | rx-path-optimizations |
| Drivers | gve **DQO cross-core RX repost** ordering (a higher-slot doorbell can race a lower-slot descriptor write — needs a contiguous-publish cursor) † | S1 | gvnic |
| Kernel | x86 BSP boot stack (`limine_stack`, 256 KiB in `.bss`) has **no guard page** — overflow corrupts adjacent `.bss` silently (AP stacks are guarded; found 2026-06-10 via an 11 KiB future overflow) | S1 | — |
| Kernel | aarch64 `CNTFRQ_EL0` trusted as a single source — a 0/sub-MHz emulator value silently corrupts every cycle budget † | S3 | — |
| Kernel | aarch64 **PL031 RTC** backend (wall-clock returns 0 on aarch64) | S3 | roadmap (deferred) |
| Runtime | `TcpRecv`/`TcpSendChain` have no `Drop` → a cancelled (`select`/`timeout`) future leaves a stale waker (relies on the "never both recv+recv_chunk parked" convention) † | S2 | stack-architecture |
| Runtime | `AsyncEvent` is single-waiter (second waker silently overwrites); native idle worker wakes on a 10 ms kqueue timeout | S3 | stack-architecture |

Refactor opportunities the audit logged but didn't action (each tracked in
its area's notes): split the 1.7-KLOC `tcp/state.rs` retransmit/timer cluster
into its own module; factor the `net_cc` one-reduction-per-episode recovery
hold shared by NewReno+CUBIC; a shared `SegmentMeta`/4-tuple builder in TCP;
generic TCP/UDP fanout-handle machinery in the reactor; consolidate the
reactor's bespoke waker-spinlock onto `util/sync::Spinlock`.

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

- **Production RNG** — ✅ *substantially hardened (2026-06-09)* — SHA-256 Hash_DRBG with SP 800-90A periodic reseed + multi-source HW + a SP 800-90B startup health/min-entropy estimate on `/obs`; full write-up in [`design-history.md`](design-history.md). *Remaining:* a virtio-rng / RNDRRS collector + a certified offline min-entropy bound. *Trigger: a security audit requiring a certified bound, or a target with neither HW RNG nor trustworthy jitter.*
- **x86_64 SSE/AVX baseline target JSON** — replace the per-crate crypto `rustc_flags` annotations in `MODULE.bazel` with one custom target spec. *Trigger: when the annotation list exceeds ~10–12 crates.* (May partly overlap the landed hard-float target — verify scope first.)
- **Faster ECDSA P-256** — `cv_sign` is the cold-handshake hotspot; `fiat-p256` (~2×) or `ring` (5–10×, build-system pain) are the levers. *Trigger: to cut cold-handshake latency now that session resumption has landed.*
- **Real wall-clock time source** — ✅ *done (2026-06-09)* — `kernel_core::clock::wall_unix_secs()` from the x86 CMOS RTC at boot; detail in [`design-history.md`](design-history.md). *Remaining: an aarch64 PL031 backend once a platform maps it.*
- **TLS panic-strategy host unit tests** — crates with `-Cpanic=abort` deps can't host-test; coverage currently lives in bare-metal integration tests. *Trigger: when an integration test catches something a host unit test would have caught faster.*
- **Cooperative-drain shutdown** — ✅ *done (2026-06-09)* — bounded `DRAIN_GRACE_MS` (750 ms) in-flight drain then power-off + per-conn RST sweep; composes with the prompt-RST design; detail in [`design-history.md`](design-history.md). *Remaining: a QUIC clean CONNECTION_CLOSE on drain.*
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
