# TCP / QUIC conformance + RFC-compliance roadmap

Status: in progress (steps 1-4 complete). Last updated 2026-05-28
(QUIC RFC 9002 statuses re-verified against `conn/loss.rs` /
`streams.rs`; frame retx + congestion controller still open).

The prioritized TCP gap backlog now lives in
[`tcp-conformance-backlog.md`](tcp-conformance-backlog.md); this doc
keeps the conformance-testing strategy and the QUIC roadmap.

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

What remains: QUIC loss recovery + congestion (step 5) and the
feature-breadth items (SACK, Timestamps/PAWS, and the Linux
performance-parity gaps) — steps 6 onward. Window scaling (RFC 7323) is
done. See [`tcp-conformance-backlog.md`](tcp-conformance-backlog.md).

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

### Borrowing the packetdrill DSL

Worth doing once the scenario count grows: a small interpreter for the
packetdrill `.pkt` script language feeding the harness. Benefits — a
documented DSL, readable scripts, and the ability to *cherry-pick*
individual corpus scripts that are feature-agnostic (basic handshake,
RST, FIN, simple duplicate-data). The bulk of the Linux corpus stays
out of scope; scripts that need SACK / timestamps do not apply until
those features land (window-scaling scripts now do).

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
  mishandled — see `tcp-conformance-backlog.md` (T1, T2, T4). No
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
  [`tcp-conformance-backlog.md`](tcp-conformance-backlog.md).
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
[`tcp-conformance-backlog.md`](tcp-conformance-backlog.md).

## Part 3 — QUIC RFC roadmap

QUIC is in markedly better shape than TCP: built sans-io, already
host-tested, and the RFC 9002 *data model* is present.

### RFC 9000 — QUIC transport

- **Have**: long/short header parsing, connection IDs, the connection
  state machine, frame encode/decode, streams, the UDP endpoint
  routing datagrams to connection tasks. `quic_test` covers wire
  formats, frame round-trips, and packet-number decode.
- **Missing**: audit needed for flow control (MAX_DATA /
  MAX_STREAM_DATA), connection migration, and the full transport-
  parameter set.
- **Conformance test**: extend `quic_test` with scripted-packet
  cases — the harness already exists; this is additive.

### RFC 9001 — using TLS with QUIC

- **Have**: the TLS 1.3 handshake over CRYPTO frames, Initial-secret
  derivation, header protection, AEAD. `end_to_end_self_handshake`
  exercises the whole pipeline.
- **Missing**: audit retry-token handling and key-update (RFC 9001
  §6).
- **Conformance test**: scripted Initial / Retry / key-update cases in
  `quic_test`.

### RFC 9002 — loss detection + congestion control

- **Have**: the data model — `sent_packets`, `SentPacket`
  (`ack_eliciting` / `in_flight`), the RFC 9002 §5 RTT estimator —
  plus, as of `conn/loss.rs`, packet- and time-threshold loss
  detection and the PTO timer (`pto_deadline_us`, raced against a
  sleep in `endpoint.rs`'s conn task; `send_pto_probe` emits a PING).
- **Missing**: frame retransmission — `detect_loss` declares packets
  lost and drops them, but the lost CRYPTO/STREAM frames are never
  re-queued (`send_pto_probe` sends a bare PING, not the lost data),
  so recovery still leans on client retransmits. The blocker is on
  the send side: `SendStream.send_offset` advances irreversibly as
  `pop_chunk_into` ships each chunk and the head IOBuf is dropped, so
  there is no replay-from-offset path to resend a lost STREAM frame.
  There is no congestion controller — `SentPacket.in_flight` /
  `byte_count` are recorded but `#[allow(dead_code)]`, reserved for it
  (`conn/mod.rs`) — and the PTO period has no exponential backoff
  (`PTO * 2^pto_count`). [`stack-architecture.md`](stack-architecture.md)
  cites this gap (and the h3 content-length policy) as a correctness
  item owned here; any `SendStream` redesign there must leave room for
  replay-from-offset. **Build the controller as the shared TCP+QUIC
  congestion core**, not QUIC-only: the same CUBIC/BBR + pacer serve
  TCP's L1/L3 Linux-parity gaps, and TCP's RFC 5681 controller is the
  reference to extract from — see *Transport reliability* in
  [`stack-architecture.md`](stack-architecture.md). Conversely QUIC's
  threshold loss detector is already the RACK model TCP's L4 wants.
- **Conformance test**: host-testable directly in `quic_test`; the
  loss-detection + RTT half already rides the clock seam. What
  remains is "wire frame retx + a controller onto the existing
  detection".

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
5. **QUIC RFC 9002 loss recovery + congestion** — the PTO timer, RTT
   estimator, and loss detection have landed; what remains is frame
   retransmission and a congestion controller.
6. **TCP RFC 7323 (window scaling + timestamps)** — widen `rcv_wnd`,
   negotiate and apply the options, PAWS.
7. **TCP RFC 2018 (SACK)** — reassembly queue, SACK blocks, RFC 6675
   loss recovery.
8. **Smaller core items + RFC 5961 challenge ACKs** — checklist.
9. **`.pkt` interpreter** — once the scenario count justifies the DSL.
10. **QUIC Interop Runner** — cross-implementation validation, after
    step 5.

Steps 1–4 are complete. Step 5 (QUIC loss recovery + congestion) is
the remaining headline correctness work; 6–8 are feature breadth;
9–10 are tooling.

## Non-goals

- The full Linux packetdrill corpus — most of it assumes features this
  stack will not implement soon.
- A client-side TCP implementation — the stack is server-side; tests
  and RFC coverage target the server role.
- Exotic options (TCP-AO, MPTCP, TCP Fast Open) — out of scope.
