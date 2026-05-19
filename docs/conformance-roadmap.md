# TCP / QUIC conformance + RFC-compliance roadmap

Status: planning. Last updated 2026-05-19.

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

## Status today (2026-05-19)

Landed (`main`, commits `c36c24f..bc8d01a`):

- `net_tcp` is host-buildable. `//net:tcp_test` is a packetdrill-style
  harness: it drives scripted TCP segments into the real `tcp_receive`
  against a mock `NicOps` that captures every transmitted frame, then
  asserts on the captured output. Three scenarios: SYN→SYN-ACK,
  in-order data→ACK, FIN→ACK. Harness lives in `net/src/tcp.rs`'s
  `#[cfg(test)] mod tests`.
- `uni-quic` already host-builds; `//uni-quic:uni_quic_test` includes
  `end_to_end_self_handshake`, which drives a synthetic Initial
  through the receive path.
- `classify` (RX parse) is host-tested via `//net:net_rx_test`.

So the *receive path and the in-process drive/capture loop both
exist*. What is missing is breadth of scenarios, a controllable clock,
and — for retransmission and congestion — the features themselves.

## Part 1 — Conformance-test strategy

### There is no drop-in suite

No external TCP conformance suite runs against this stack, for two
independent reasons:

- **Driving model.** packetdrill needs the POSIX socket API + a TUN
  device; gVisor's *packetimpact* needs a DUT agent (`posix_server`
  over gRPC). This is a bare-metal unikernel with no syscalls — neither
  harness has anything to attach to. That is why the in-process
  harness exists.
- **Missing features.** Every general suite assumes window scaling,
  SACK, TCP timestamps, and RFC-standard RTO. The stack has none of
  those, so the Linux packetdrill corpus would fail on absent features
  rather than real bugs.

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
out of scope; scripts that need window scaling / SACK / timestamps do
not apply until those features land.

### Black-box axis (secondary, for QUIC)

The **QUIC Interop Runner** is a real, maintained suite with
loss-recovery and congestion test cases. It is *interop* testing —
real network, real time, a deployable server endpoint with
qlog/keylog — not in-process. It cannot inspect internal state or
control the clock, but it validates against other implementations.
Reasonable as a later cross-check once `uni-quic` loss recovery is
wired; not a substitute for the in-process tests.

Booting the unikernel under QEMU with a tap and firing crafted packets
(scapy / a Rust injector) is possible but has the same limitations as
any black-box approach — no clock control, no state inspection — so it
stays a smoke-test axis, not the conformance vehicle.

### Test-infrastructure backlog

- **`now_cycles()` compile-time seam** — mirror the `cpu_id` /
  `rng::fill_bytes` seams in `kernel_core`. Prerequisite for *every*
  timer-driven test (RTO, delayed-ACK, TIME-WAIT, QUIC PTO). Highest
  priority — nothing in Part 2/3 below that involves a timer can be
  tested deterministically without it.
- **Wider TCP scenario matrix** — out-of-order, RST edge cases, the
  item-M `tcp_receive` super-segment test
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
- **Missing**: retransmission (see RFC 6298 — **MUST violation**);
  TIME-WAIT and FIN-WAIT timeouts (no timer — orphaned connections
  leak); the MSS option is never *sent* (`send_segment` hard-codes a
  20-byte header); zero-window persist relies on the peer's persist
  timer; no delayed-ACK coalescing (we ACK immediately — correct, just
  not optimal).
- **Conformance test**: receiver-side scenarios are testable *now* —
  retransmitted SYN (stale-twin cleanup), duplicate/old data →
  immediate dup-ACK, out-of-order segment handling, RST at/off
  `rcv_nxt`. Add these to the harness first; they need no new feature.

### RFC 6298 — retransmission timeout

- **Have**: nothing. The stack has no RTO timer; a lost *outbound*
  segment is never retransmitted (the code admits this). It relies on
  the peer retransmitting. **MUST violation** — and a real correctness
  gap on lossy paths.
- **Missing**: the RTT estimator (SRTT/RTTVAR), the RTO computation +
  backoff, a per-connection retransmission timer, and the unacked-
  segment queue an RTO needs to retransmit *from*.
- **Conformance test**: build it test-first on the harness + the clock
  seam — script a send, drop the ACK, advance the clock past the RTO,
  assert the segment is retransmitted; assert exponential backoff;
  assert SRTT/RTTVAR track per RFC 6298 §2.

### RFC 5681 — congestion control

- **Have**: nothing. No `cwnd`, no slow-start, no congestion
  avoidance, no fast retransmit / fast recovery. The server sends what
  fits the peer's advertised window.
- **Missing**: the full controller — `cwnd`/`ssthresh`, slow-start,
  AIMD congestion avoidance, the three-dup-ACK fast-retransmit trigger
  and fast recovery (RFC 5681 §3.2).
- **Conformance test**: depends on RFC 6298 landing first (fast
  retransmit is a retransmission path). On the harness: script a loss,
  feed three duplicate ACKs, assert fast retransmit fires and
  `cwnd`/`ssthresh` move per spec.

### RFC 2018 — selective acknowledgement (SACK)

- **Have**: nothing — neither the `SACK-permitted` SYN option nor SACK
  blocks.
- **Missing**: option negotiation, the out-of-order reassembly queue
  SACK reports against, SACK-block generation, and (sender side)
  SACK-aware loss recovery (RFC 6675).
- **Conformance test**: deferred until the reassembly queue exists;
  then script out-of-order arrival and assert correct SACK blocks.

### RFC 7323 — window scaling + timestamps

- **Have**: nothing. `rcv_wnd` is a `u16`; no scale option, no
  timestamp option.
- **Missing**: the `Window Scale` and `Timestamps` SYN options, the
  scale shift applied to all window arithmetic, and PAWS.
- **Conformance test**: assert the options are echoed on the SYN-ACK
  and that windows past 64 KiB are interpreted with the negotiated
  shift. Note `rcv_wnd: u16` must widen first — a small but
  cross-cutting change.

### RFC 5961 — blind in-window attack hardening

- **Have**: partial — `tcp_receive` already applies the RFC 5961 §3.2
  strict-sequence check before accepting a RST.
- **Missing**: the §4 (SYN) and §5 (data) challenge-ACK mechanism, and
  the challenge-ACK rate limit.
- **Conformance test**: script an in-window-but-not-exact RST / SYN and
  assert a challenge ACK rather than a state change.

### Smaller core items

MSS-option emission, a TIME-WAIT 2 MSL timer, the zero-window persist
timer, ECN (RFC 3168), and Nagle (RFC 9293 §3.7.4) — each small,
each gated on the clock seam where a timer is involved. Track them as
a checklist once the big three (6298 / 5681 / core 9293 receiver
tests) are moving.

## Part 3 — QUIC RFC roadmap

QUIC is in markedly better shape than TCP: built sans-io, already
host-tested, and the RFC 9002 *data model* is present.

### RFC 9000 — QUIC transport

- **Have**: long/short header parsing, connection IDs, the connection
  state machine, frame encode/decode, streams, the UDP endpoint
  routing datagrams to connection tasks. `uni_quic_test` covers wire
  formats, frame round-trips, and packet-number decode.
- **Missing**: audit needed for flow control (MAX_DATA /
  MAX_STREAM_DATA), connection migration, and the full transport-
  parameter set.
- **Conformance test**: extend `uni_quic_test` with scripted-packet
  cases — the harness already exists; this is additive.

### RFC 9001 — using TLS with QUIC

- **Have**: the TLS 1.3 handshake over CRYPTO frames, Initial-secret
  derivation, header protection, AEAD. `end_to_end_self_handshake`
  exercises the whole pipeline.
- **Missing**: audit retry-token handling and key-update (RFC 9001
  §6).
- **Conformance test**: scripted Initial / Retry / key-update cases in
  `uni_quic_test`.

### RFC 9002 — loss detection + congestion control

- **Have**: the data model — `sent_packets`, `SentPacket`
  (`ack_eliciting` / `in_flight`), the RFC 9002 §5 RTT estimator, and
  the per-space PTO anchors. This is real scaffolding.
- **Missing**: the PTO/loss-detection *timers* are not wired
  (`conn.rs` notes it relies on client retransmits today), and there
  is no congestion controller.
- **Conformance test**: this is "wire the timer + a controller onto
  existing scaffolding" — host-testable directly in `uni_quic_test`
  once the clock seam exists. Smaller than the TCP equivalent because
  the bookkeeping is already there.

## Part 4 — Sequencing

Dependency-ordered. Each step is test-first on the harness.

1. **Receiver-side TCP scenarios** — retransmitted SYN, duplicate/old
   data, out-of-order, RST edge cases. No new feature; pure coverage.
2. **`now_cycles()` clock seam** — unblocks every timer-driven test.
3. **TCP RFC 6298 (RTO)** — RTT estimator, RTO + backoff, the unacked
   queue, the retransmission timer.
4. **TCP RFC 5681 (congestion)** — `cwnd`/`ssthresh`, slow-start,
   congestion avoidance, fast retransmit / fast recovery.
5. **QUIC RFC 9002 loss recovery + congestion** — wire the PTO timer
   and a controller onto the existing data model.
6. **TCP RFC 7323 (window scaling + timestamps)** — widen `rcv_wnd`,
   negotiate and apply the options, PAWS.
7. **TCP RFC 2018 (SACK)** — reassembly queue, SACK blocks, RFC 6675
   loss recovery.
8. **Smaller core items + RFC 5961 challenge ACKs** — checklist.
9. **`.pkt` interpreter** — once the scenario count justifies the DSL.
10. **QUIC Interop Runner** — cross-implementation validation, after
    step 5.

Steps 1–2 are infrastructure and land first. Steps 3–5 are the
headline correctness work (retransmission + congestion, both stacks).
6–8 are feature breadth. 9–10 are tooling.

## Non-goals

- The full Linux packetdrill corpus — most of it assumes features this
  stack will not implement soon.
- A client-side TCP implementation — the stack is server-side; tests
  and RFC coverage target the server role.
- Exotic options (TCP-AO, MPTCP, TCP Fast Open) — out of scope.
