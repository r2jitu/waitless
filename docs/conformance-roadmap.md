# Conformance — test strategy + RFC status/roadmap (TCP & QUIC)

Status: in progress (steps 1-5 complete). Last updated 2026-06-07
(TCP window scaling + ABC shipped — see [`tcp-backlog.md`](tcp-backlog.md);
QUIC RFC 9002 frame retx + congestion controller now landed — the shared
`net_cc` NewReno controller is wired into QUIC, and STREAM + CRYPTO frame
retransmission are both done).

This doc keeps the conformance-testing **strategy** (the in-process
harness pattern), the **sequencing**, and the per-RFC **status** view
(Have/Missing/test coverage) for the TCP and QUIC engines — Part 2 (TCP)
and Part 3 (QUIC transport, RFC 9000/9001/9002). The prioritized
**work-queue backlogs** live per-protocol in their own files:
[`tcp-backlog.md`](tcp-backlog.md) (TCP +
Linux-parity), [`tls-backlog.md`](tls-backlog.md) (TLS 1.3),
[`http2-backlog.md`](http2-backlog.md) (HTTP/2, not started), and
[`http3-backlog.md`](http3-backlog.md) (HTTP/3 + QPACK app layer). Status
view here; work queue there.

## Purpose

Two intertwined goals:

1. **Conformance testing** — a repeatable, host-native way to assert
   the TCP and QUIC engines behave per spec on scripted inputs.
2. **RFC compliance** — close the gap between today's deliberately
   minimal stacks and the MUST-level requirements of the relevant
   RFCs.

They are intertwined because most of the RFC gaps below are *missing
behaviour* (no retransmission, no congestion control). You cannot
conformance-test behaviour that does not exist — so the harness's job
for those items is **test-first feature development**, not checking an
existing implementation.

## Status today (2026-05-22)

Steps 1-4 of the sequencing below are **complete**. The in-process
harness, a test-controllable clock, TCP retransmission, the
connection-lifecycle corners, and RFC 5681 congestion control all
now exist.

Landed:

- `tcp` is host-buildable. `//crates/net/tcp:tcp_test` is a
  packetdrill-style harness: it drives scripted TCP segments into the
  real `tcp_receive` against a mock `NicOps` that captures every
  transmitted frame, then asserts on the captured output. It covers
  the handshake trio, the receiver-side set, the RFC 6298 set, the
  connection-lifecycle corners (LastAck, FIN retransmit, TimeWait),
  and the RFC 5681 controller. The harness lives in
  `crates/net/tcp/src/tests.rs`, and includes a deterministic
  egress-drop fixture for the loss-driven scenarios.
- A `now_ms()` compile-time clock seam (`kernel_core::clock`) with a
  test-controllable host mock — the prerequisite for every
  timer-driven test.
- TCP RFC 6298 retransmission: a per-conn retransmit ring, the RTO
  timer wired into the poll loop, exponential backoff, and the
  SRTT/RTTVAR estimator. A lost outbound segment is now resent.
- TCP connection-lifecycle corners: `CloseWait → LastAck` with a
  bounded FIN-retransmit timer, `FinWait* → TimeWait` with a 2×MSL
  drop. They ride the same per-core poll-scan as the RTO timer
  (`on_tcp_tick`).
- TCP RFC 5681 congestion control: `cwnd`/`ssthresh`, slow start,
  AIMD congestion avoidance, and three-dup-ACK fast retransmit /
  fast recovery — and a send path that paces transmission against
  `min(cwnd, rwnd)`, with a zero-window persist timer and the
  SND.WL1/WL2 window-update rule.
- `quic` already host-builds; `//crates/proto/quic:quic_test`
  includes `end_to_end_self_handshake`, which drives a synthetic
  Initial through the receive path.
- `net_classify` (RX parse) is host-tested via
  `//crates/net:classify_test`.

QUIC loss recovery + congestion (step 5) has since landed too — STREAM
retx, CRYPTO-frame retx (RFC 9002 §6.2), the shared `net_cc` NewReno
controller wired into QUIC, and PTO backoff. What remains is the
feature-breadth items (SACK, Timestamps/PAWS, and the Linux
performance-parity gaps) — steps 6 onward — plus delegating TCP onto the
shared `net_cc` core. Window scaling (RFC 7323) is done. See
[`tcp-backlog.md`](tcp-backlog.md).

## Part 1 — Conformance-test strategy

### There is no drop-in suite

No external TCP conformance suite runs against this stack, for two
independent reasons:

- **Driving model.** packetdrill needs the POSIX socket API + a TUN
  device; gVisor's *packetimpact* needs a DUT agent (`posix_server`
  over gRPC). This is a bare-metal unikernel with no syscalls — neither
  harness has anything to attach to. That is why the in-process
  harness exists.
- **Missing features.** Every general suite assumes SACK, TCP
  timestamps, and RFC-standard RTO (window scaling we now have). The
  stack still lacks most of those, so the Linux packetdrill corpus would
  fail on absent features rather than real bugs.

The conclusion: we write our own scenarios. We can still borrow
mature *assets* — see below.

### The in-process harness (primary)

`#[cfg(test)] mod tests` in `net/src/tcp.rs`:

- `tcp_receive` is the real RX entry point; the send path is the real
  TX code. Only the NIC is mocked (`MOCK_OPS` captures TX frames into
  a `Vec`).
- Scenarios script inbound segments (`Seg`), drive them, and assert on
  captured frames + connection state.
- Process-global per-core pools force serialisation: `TEST_LOCK` plus
  a distinct 4-tuple per test.

This is the right tool for RFC-level behaviour: it sees internal
state, runs in milliseconds, and (once the clock seam lands) controls
time deterministically.

### Borrowing the packetdrill DSL ✅ first cut landed

A small packetdrill-style `.pkt` interpreter now feeds the `tcp_test`
harness (`run_pkt` in `tests.rs`): line-based `listen` / `send` / `recv`
/ `recv-none` / `advance <N>ms` directives, `|`-joined flags, and
numeric exprs with `$isn` capture (so a script completes a handshake
despite the random server ISN) + `+N` offsets. Two scenarios
(`pkt_handshake_and_data`, `pkt_advance_and_recv_none`) are written
entirely in the DSL. Benefits — readable scripts, and the ability to
*cherry-pick* feature-agnostic corpus cases (handshake, RST, FIN,
duplicate-data). Still room to grow: a standalone `.pkt`-file runner,
and directives for SACK / timestamps once those land.

### Black-box axis (secondary, for QUIC)

The **QUIC Interop Runner** is a real, maintained suite with
loss-recovery and congestion test cases. It is *interop* testing —
real network, real time, a deployable server endpoint with
qlog/keylog — not in-process. It cannot inspect internal state or
control the clock, but it validates against other implementations.
Reasonable as a later cross-check once `quic` loss recovery is
wired; not a substitute for the in-process tests.

Booting the unikernel under QEMU with a tap and firing crafted packets
(scapy / a Rust injector) is possible but has the same limitations as
any black-box approach — no clock control, no state inspection — so it
stays a smoke-test axis, not the conformance vehicle.

### Test-infrastructure backlog

- ✅ **Clock seam** — `kernel_core::clock::now_ms()` mirrors the
  `cpu_id` / `rng::fill_bytes` seams, with a test-controllable host
  mock (`mock::set` / `advance` / `reset`). Landed in step 2. (A
  millisecond monotonic clock, not raw `now_cycles()`: every timer
  consumer works in the ms/second domain and a cycles seam would need
  a second seam for the arch-specific cycles-per-µs conversion.)
- **Wider TCP scenario matrix** — the receiver-side set landed in
  step 1; still open is the item-M `tcp_receive` super-segment test
  (`docs/rx-path-optimizations.md`).
- **Deeper assertions** — today's scenarios check flags/ports/ack.
  Also validate the TCP checksum, the IP header, and that delivered
  data actually lands in the RX ring (`accept` + `recv`).
- **`.pkt` interpreter** — as above.

## Part 2 — TCP RFC roadmap

Each item: **Have** / **Missing** / **Conformance test**. "MUST
violation" marks a current spec breach, not merely an absent
optional feature.

### RFC 9293 — core TCP (obsoletes 793)

- **Have**: full state set (`Closed`…`TimeWait`), three-way handshake,
  in-order data transfer, FIN/close, RST generation + RFC 5961 RST
  acceptance check, per-core connection pool.
- **Missing**: the MSS option is never sent or parsed, the ACK field
  is not range-checked, and a SYN on a synchronized connection is
  mishandled — see `tcp-backlog.md` (T1, T2, T4). No
  delayed-ACK coalescing (we ACK immediately — correct, just not
  optimal). Zero-window persist is now implemented; the TIME-WAIT /
  FIN-WAIT timeouts are closed too — see the lifecycle-corners note.
- **Conformance test**: done — the receiver-side scenarios
  (retransmitted SYN / stale-twin cleanup, duplicate/old data →
  immediate dup-ACK, out-of-order segment, RST at/off `rcv_nxt`)
  landed in the harness as step 1, and the connection-lifecycle
  scenarios (LastAck, FIN retransmit, TimeWait) followed.

### RFC 9293 — connection-lifecycle corners (LastAck / TimeWait)

- **Have**: `close()` on a peer-closed connection enters `LastAck`
  and waits for the ACK; active close reaches `TimeWait` on the
  peer FIN and holds for 2×MSL; an unacknowledged FIN is
  retransmitted with exponential backoff and the connection is
  forced shut after a bounded retry count. The timers ride the
  per-core poll-scan (`on_tcp_tick`).
- **Missing**: nothing material — simultaneous close shortcuts
  `FinWait1 → TimeWait` rather than passing through a distinct
  `Closing` state, which is a benign simplification for a
  server-role stack.
- **Conformance test**: done — `CloseWait → LastAck`, the LastAck
  ACK completion, FIN retransmit on loss (both close directions)
  and bounded give-up, `FinWait* → TimeWait`, the 2×MSL drop, and
  the retransmitted-FIN re-ACK. The loss scenarios use the
  harness's deterministic egress-drop fixture.

### RFC 6298 — retransmission timeout

- **Have**: the full mechanism. A per-conn retransmit ring holds the
  unacked window; an RTO timer (`on_tcp_tick`, driven by the net poll
  loop, with an event-loop idle hook so an idle core does not strand
  it) retransmits the oldest unacked segment and backs the RTO off
  exponentially (§5.5); the SRTT/RTTVAR estimator (§2.2/§2.3) makes
  the RTO adaptive, with Karn's algorithm on the RTT samples. The
  former MUST violation is closed.
- **Missing**: SYN-ACK retransmission (a retransmitted client SYN
  already re-drives the SYN-ACK, so this is cosmetic); the FIN is
  covered by the lifecycle timer. The retransmit ring is now sized
  to a full 64 KiB receive window, so an unacked window can no
  longer outgrow it.
- **Conformance test**: done — `tcp_test` scripts a send, drops the
  ACK, advances the mock clock past the RTO, and asserts the
  retransmit fires and the RTO doubles; a second case asserts an ACK
  stops the timer; a third asserts SRTT/RTTVAR track RFC 6298 §2.

### RFC 5681 — congestion control

- **Have**: the full mechanism. `cwnd`/`ssthresh` on the TCB, opened
  at the RFC 6928 IW10 initial window; slow start, congestion avoidance,
  RTO collapse, three-dup-ACK fast retransmit / fast recovery — and
  the send path now paces transmission against `min(cwnd, rwnd)`:
  `async_try_send_chain` (and the TSO fast path) cap in-flight bytes
  at the usable window, queue the remainder, and resume on the ACK
  that reopens it. The peer's receive window is tracked under the
  RFC 9293 SND.WL1/WL2 rule; a zero-window stall is recovered by the
  §3.8.6.1 persist timer. The former "controller computed but
  ignored" gap is closed.
- **Missing**: nothing for RFC 5681 *conformance*. But this is the Reno
  baseline only — the performance features Linux layers on top (CUBIC/BBR,
  ABC, pacing, RACK-TLP) are real gaps on adverse paths, inventoried under
  *Performance parity with the Linux TCP stack* in
  [`tcp-backlog.md`](tcp-backlog.md).
- **Conformance test**: done — pure controller-arithmetic scenarios
  plus harness scenarios for the windowed send path (cwnd cap,
  closed-window stall + ACK-driven resume, rwnd cap, slow-start
  ramp), zero-window persist, and TSO retransmit coverage.

### RFC 2018 — selective acknowledgement (SACK)

- **Have**: nothing — neither the `SACK-permitted` SYN option nor SACK
  blocks.
- **Missing**: option negotiation, the out-of-order reassembly queue
  SACK reports against, SACK-block generation, and (sender side)
  SACK-aware loss recovery (RFC 6675).
- **Conformance test**: deferred until the reassembly queue exists;
  then script out-of-order arrival and assert correct SACK blocks.

### RFC 7323 — window scaling + timestamps

- **Have**: Window Scale (done, `bd89169`). `snd_wnd` is `u32`; the
  peer's scale shift is parsed from its SYN and applied to every
  post-handshake window update; the SYN-ACK echoes a Window-Scale
  option advertising `rcv_wscale = 0`. GCE-validated ~4–5× on sustained
  high-RTT downloads.
- **Missing**: the `Timestamps` SYN option (TSval/TSecr) and PAWS.
  `rcv_wnd` stays `u16` by design — we advertise `rcv_wscale = 0`, so
  our own receive window is ≤ 64 KiB (a server mostly sends; the
  symmetric upload-side limit is tracked as L5 in the backlog).
- **Conformance test**: window-scaling negotiation, the scaled update,
  the no-offer path, and the §2.3 shift clamp are covered by four
  `tcp_test` scenarios. Timestamps/PAWS tests pending the feature.

### RFC 5961 — blind in-window attack hardening

- **Have**: partial — `tcp_receive` already applies the RFC 5961 §3.2
  strict-sequence check before accepting a RST.
- **Missing**: the §4 (SYN) and §5 (data) challenge-ACK mechanism, and
  the challenge-ACK rate limit.
- **Conformance test**: script an in-window-but-not-exact RST / SYN and
  assert a challenge ACK rather than a state change.

### Smaller core items

The TIME-WAIT timer and the zero-window persist timer are done. The
remaining smaller items — MSS-option handling, ACK-field validation,
ECN (RFC 3168), Nagle (RFC 9293 §3.7.4), a delayed-ACK coalescer —
are tracked, prioritized, in
[`tcp-backlog.md`](tcp-backlog.md).

## Part 3 — QUIC RFC roadmap

QUIC is in markedly better shape than TCP: built sans-io, already
host-tested, and the RFC 9002 *data model* is present. This part covers
the **transport** (RFC 9000/9001/9002); the **HTTP/3 application layer**
on top (RFC 9114 framing + RFC 9204 QPACK) is tracked in
[`http3-backlog.md`](http3-backlog.md).

### RFC 9000 — QUIC transport

- **Have**: long/short header parsing, connection IDs, the connection
  state machine, frame encode/decode, streams, the UDP endpoint
  routing datagrams to connection tasks. **Receive-side flow control**:
  advertised initial limits plus reactive MAX_STREAM_DATA / MAX_DATA
  crediting that slides each window forward as the app drains, so an
  upload runs past the initial window (`conn/tx.rs` pull-emission +
  `RecvStream::recv_max` / `Connection::data_consumed`; validated by a
  1.5 MiB h3 upload). `quic_test` covers wire formats, frame
  round-trips, packet-number decode, and the MAX_* frame writers.
- **Have (send-side flow control)**: enforced — `conn/tx.rs`'s
  packetization gates STREAM emission on the peer's `peer_max_data`
  (conn level) and per-stream `peer_max_stream_data`, so a large
  response can't outrun the peer's advertised credit.
- **Missing**: connection migration and the full transport-parameter
  set. Lost MAX_* frames aren't retransmitted (shared with the
  frame-retx gap below); a newer credit supersedes a lost one as
  consumption advances.
- **Conformance test**: extend `quic_test` with scripted-packet
  cases — the harness already exists; this is additive.

### RFC 9001 — using TLS with QUIC

- **Have**: the TLS 1.3 handshake over CRYPTO frames, Initial-secret
  derivation, header protection, AEAD. `end_to_end_self_handshake`
  exercises the whole pipeline.
- ✅ **Key update (RFC 9001 §6)** — **done**. Receive side promotes the
  pre-derived next-phase keys on a KEY_PHASE flip (`rotate_recv_keys`,
  one-rotation prev-key window for reordering); send side now rotates in
  lock-step (`rotate_send_keys` derives next-gen send keys from
  `server_app_secret`, toggles `send_key_phase`, stamps the 1-RTT
  KEY_PHASE bit). Unit-tested
  (`key_update_rotates_send_keys_and_toggles_phase`).
- ✅ **Path validation + connection migration** (RFC 9000 §8.2.2 / §9.3)
  — **done (auth-gated)**. A received PATH_CHALLENGE is echoed in a
  PATH_RESPONSE, and the TX peer address now follows the peer's source
  across a NAT rebind / network change — but **only after a packet from
  the new source authenticates** (`Connection::authenticated_pkts`,
  bumped past the AEAD `?`; `is_path_migration` gate in the conn task).
  This *fixed a real traffic-redirection*: the old code followed the
  source of every unauthenticated datagram, so a spoof of the cleartext
  DCID could redirect our traffic. Unit-tested
  (`path_migration_gate_classifies_new_sources`); /obs `path_migrations`.
  **Remaining hardening**: we don't yet *initiate* our own PATH_CHALLENGE
  to probe the new path before fully committing (RFC 9000 §9.3.1
  anti-amplification on the unvalidated path) + CID rotation.
- **Optional / not a correctness gap**: Retry-token handling — we don't
  send Retry packets; we use the RFC 9000 §8.1 3× anti-amplification
  limit (the baseline mechanism) instead, which is conformant. Retry is
  an additional optional DoS hardening, not required.
- **Conformance test**: scripted Initial / Retry / key-update cases in
  `quic_test`.

### RFC 9002 — loss detection + congestion control

- **Have**: the data model — `sent_packets`, `SentPacket`
  (`ack_eliciting` / `in_flight` / `byte_count`), the RFC 9002 §5 RTT
  estimator — plus, as of `conn/loss.rs`, packet- and time-threshold
  loss detection and the PTO timer (`pto_deadline_us`, raced against a
  sleep in `endpoint.rs`'s conn task; `send_pto_probe` emits a PING).
  **STREAM-frame retransmission**: each sealed packet retains a
  `StreamRetx` copy of its STREAM payload (`SentPacket.stream_frames`);
  `detect_loss` moves a lost packet's frames to `Connection::retx_queue`
  and `encode_one_rtt_packet` drains that before fresh data — `pop_chunk`
  hands out an owned copy precisely so the offset bytes survive for replay
  (RFC 9000 §13.3). **Congestion control**: the shared `net_cc` NewReno
  controller (`Connection::cc`) is wired in — `bytes_in_flight` (driven by
  `record_sent_packet` / `process_ack` / `detect_loss`) gates packetization
  against `cc.window()`, `on_ack` grows it, `on_loss` halves it once per
  episode, and the PTO path collapses it on persistent congestion (see
  Missing). The `SentPacket.in_flight` / `byte_count` fields are now live,
  not `#[allow(dead_code)]`. **PTO backoff**: `pto_period_us` shifts the
  base left by `pto_count` (`base << pto_count.min(10)`), so an
  unresponsive peer probes at a geometrically increasing interval.
- ✅ **CRYPTO-frame retransmission** (RFC 9002 §6.2) — **done**. Each
  sealed Initial/Handshake packet retains its CRYPTO fragment
  (`CryptoRetx{level, offset, data}`); `detect_loss` re-queues a lost
  packet's fragments into `crypto_retx_queue`, and `flush_outbound`
  re-emits each at its original offset/space before fresh handshake
  CRYPTO — so handshake-packet loss is recovered by resending the bytes,
  not just by the PTO PING. Unit-tested
  (`lost_crypto_fragment_is_requeued_for_retransmission`); `/obs`
  `crypto_frames_retransmitted`. **Remaining**: the wider loss-recovery
  audit items (ECN, the §7.6.1 lost-time-span persistent-congestion
  test — we trigger collapse off `pto_count` instead).
  **Note (shared core, QUIC-wired only)**: the controller landed as the
  **shared TCP+QUIC `net_cc` core** (`crates/net/cc`, the `CongestionControl`
  trait + NewReno) — but it is wired into **QUIC only** today. TCP still
  uses its own embedded `cwnd`/`ssthresh`; delegating TCP onto the trait,
  and the CUBIC/BBR + pacer that serve TCP's L1/L3 Linux-parity gaps, are
  the remaining work — see *Transport reliability* in
  [`stack-architecture.md`](stack-architecture.md) and *Performance parity*
  in [`tcp-backlog.md`](tcp-backlog.md). Conversely QUIC's threshold loss
  detector + token-bucket pacer are already the reference TCP's L4 wants.
- **Conformance test**: host-testable directly in `quic_test`; the
  loss-detection + RTT half already rides the clock seam, and `net_cc`'s
  NewReno is host-unit-tested in `crates/net/cc`. What remains is scripted
  retx / cwnd-gate cases on the existing detection.

## Part 4 — Sequencing

Dependency-ordered. Each step is test-first on the harness.

1. ✅ **Receiver-side TCP scenarios** — retransmitted SYN,
   duplicate/old data, out-of-order, RST edge cases. No new feature;
   pure coverage.
2. ✅ **Clock seam** — `kernel_core::clock::now_ms()`, a
   test-controllable monotonic-millisecond seam. Unblocks every
   timer-driven test.
3. ✅ **TCP RFC 6298 (RTO)** — RTT estimator, RTO + backoff, the
   per-conn retransmit ring, the retransmission timer.
4. ✅ **TCP RFC 5681 (congestion)** — `cwnd`/`ssthresh`, slow-start,
   congestion avoidance, fast retransmit / fast recovery. (Plus the
   connection-lifecycle corners — LastAck, TimeWait, FIN retransmit
   — which slotted in alongside.) The cwnd-paced send window —
   windowed `async_try_send_chain` + zero-window persist + TSO
   retransmit coverage — followed and is merged to main.
5. ✅ **QUIC RFC 9002 loss recovery + congestion** — the PTO timer (with
   exponential backoff), RTT estimator, loss detection, STREAM-frame
   retransmission, and the shared `net_cc` NewReno congestion controller
   (cwnd-gated packetization + pacing) have all landed. The one residual
   is CRYPTO-frame retx via the PTO probe (still a bare PING).
6. **TCP RFC 7323 (window scaling + timestamps)** — widen `rcv_wnd`,
   negotiate and apply the options, PAWS.
7. **TCP RFC 2018 (SACK)** — reassembly queue, SACK blocks, RFC 6675
   loss recovery.
8. **Smaller core items + RFC 5961 challenge ACKs** — checklist.
9. **`.pkt` interpreter** — once the scenario count justifies the DSL.
10. **QUIC Interop Runner** — cross-implementation validation, after
    step 5.

Steps 1–5 are complete (step 5's residual is CRYPTO-frame retx). Steps
6–8 are feature breadth; 9–10 are tooling. The remaining headline
transport work is now the *shared-core* follow-through — delegating TCP
onto the `net_cc` trait and the CUBIC/BBR + TCP-pacing parity gaps — not
QUIC loss recovery.

## Non-goals

- The full Linux packetdrill corpus — most of it assumes features this
  stack will not implement soon.
- A client-side TCP implementation — the stack is server-side; tests
  and RFC coverage target the server role.
- Exotic options (TCP-AO, MPTCP, TCP Fast Open) — out of scope.
