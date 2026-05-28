# TCP RFC conformance — status and prioritized backlog

Last updated 2026-05-22.

This is the authoritative list of *pending* TCP conformance work, in
priority order. For the conformance-testing strategy and the QUIC
roadmap see [`conformance-roadmap.md`](conformance-roadmap.md).

## Current state

The TCP stack (`crates/net/tcp/`) is a **server-role** implementation:
passive open only, no `connect()` / `SYN-SENT`. Within that scope it
implements and host-tests:

- RFC 9293 — the three-way handshake, the connection lifecycle
  (`Established`/`CloseWait`/`LastAck`/`FinWait1-2`/`TimeWait`), the
  2×MSL drop, FIN retransmission, the SND.WL1/WL2 window-update rule.
- RFC 6298 — RTO retransmission, the SRTT/RTTVAR estimator,
  exponential backoff, Karn's algorithm.
- RFC 5681 — slow start, AIMD, fast retransmit / fast recovery, and
  a send path that paces against `min(cwnd, rwnd)`.
- RFC 9293 §3.8.6.1 — zero-window persist probing.
- RFC 5961 §3.2 — strict-sequence RST acceptance.
- RFC 1122 §4.2.2.16 — receiver silly-window-syndrome avoidance.

Validation: `//crates/net/tcp:tcp_test` is a 48-scenario in-process
packetdrill-style harness (scripted segments → real `tcp_receive` →
assertions on captured TX), plus production interop (`dev.r2jitu.com`
serves real browsers / curl / openssl).

**The stack is not fully RFC-conformant.** The harness is
example-based and covers only implemented paths; the gaps below are
known by code inspection, not by a failing test. There is no
requirement-coverage matrix and no receive-path fuzzing yet — see
*Test & assurance backlog*.

## How to read the priorities

- **P0** — a correctness bug reachable by a well-behaved peer or a
  common network condition (reordering, a smaller path MTU). Fix next.
- **P1** — real impact under adverse conditions (packet loss, hostile
  or malformed traffic), or a narrower-trigger correctness bug.
- **P2** — feature breadth: performance ceilings on WAN / high-BDP
  paths; deliberate omissions worth closing.
- **P3** — optional, low-impact, or near a non-goal.

Effort: **S** ≈ hours, **M** ≈ a few days, **L** ≈ a week+.

---

## P0 — correctness bugs reachable in normal operation

### T1 — The ACK field is not validated against the send window — ✅ done

**Status.** Done and merged to main — `tcp_receive` now applies the
RFC 9293 §3.10.7.4 acceptability rule. Kept here for the record; the
rest of the entry describes the gap that was closed.

**What.** `tcp_receive`'s generic ACK branch did `c.snd_una = ack`
unconditionally. There was no `SND.UNA < SEG.ACK <= SND.NXT` check.

**RFC.** RFC 9293 §3.10.7.4: an ACK above `SND.NXT` MUST be answered
with an ACK and the segment dropped; an ACK at or below `SND.UNA` is
ignored.

**Triggers when.** A plain **reordered or duplicated old ACK** —
common on real paths — has `ack < snd_una`, so it drives `snd_una`
*backwards*; `rtx_on_ack` then computes a wrapped, huge `acked`,
flushes the whole retransmit ring, and desyncs the connection. A
forged ACK from an off-path attacker who guessed the 4-tuple does the
same on purpose (RFC 5961 §5 territory).

**Fix.** In the ACK branch, before touching `snd_una`: ignore
`SEG.ACK <= SND.UNA`; for `SEG.ACK > SND.NXT` send a bare ACK and drop;
otherwise accept. **Effort: S.**

**Test.** Harness scenario: deliver an old ACK (`ack < snd_una`) and a
future ACK (`ack > snd_nxt`); assert `snd_una` is unchanged and the
retransmit ring is intact, and that the future ACK elicits a bare ACK.

### T2 — Received MSS option ignored; send MSS hardcoded; no PMTUD

**What.** The SYN handler never parses the peer's `MSS` option and
`send_segment` never emits one (`data_offset` is hardcoded to a
20-byte header). The send MSS is the constant `MSS_V4`/`MSS_V6`
(1460/1440). There is no Path MTU Discovery.

**RFC.** RFC 9293 §3.7.1: a TCP SHOULD send the MSS option, and MUST
assume the 536 (IPv4) / 1220 (IPv6) default when it receives none.

**Triggers when.** Any path with an MTU below 1500 — tunnels, PPPoE,
some VPNs, IPv6's 1280-byte minimum. Our 1460-byte segments are then
dropped or fragmented, and with no PMTUD the connection **blackholes**
for any multi-segment response. A one-segment `/health` reply
survives; a real page does not.

**Fix (cheap 80%).** Parse the inbound SYN's MSS option and clamp the
per-conn send MSS to it; emit our own MSS option in the SYN-ACK. Needs
a small TCP-options parse/emit path (none exists today). Full PMTUD
(RFC 8201 / RFC 1191, or PLPMTUD RFC 8899) is a larger follow-up; the
MSS clamp removes the common-case blackhole. **Effort: M.**

**Test.** Scenario: SYN carrying `MSS=1300`; assert the SYN-ACK echoes
an MSS option and that subsequent data segments are ≤ 1300 bytes.

---

## P1 — real impact under loss or hostile traffic

### T3 — No out-of-order reassembly queue

**What.** A data segment with a gap before it (`seq > rcv_nxt`) is
dropped, not buffered. Pinned by `out_of_order_segment_is_not_buffered`.

**RFC.** RFC 9293 permits dropping out-of-order segments but
recommends queuing them; every modern stack does.

**Triggers when.** Any packet loss or reordering. One lost segment
makes the receiver discard *every* later segment in the same window;
the sender must RTO-retransmit and re-send the whole tail. Throughput
collapses toward one segment per RTT on a lossy WAN. Invisible on a
clean LAN / datacenter path.

**Fix.** A per-conn out-of-order segment queue, drained into `rx_ring`
as the gap fills. This is the prerequisite for SACK (T7). **Effort: L.**

**Test.** Deliver segments out of order; assert all bytes are
ultimately delivered in sequence and the gap-filling segment releases
the queued tail.

### T4 — A SYN on a synchronized connection corrupts the pool

**What.** The SYN handler treats only non-`Established` slots as a
"stale twin." A SYN arriving on a live `Established` 4-tuple leaves the
old TCB intact *and* allocates a second TCB for the same 4-tuple; the
hash insert then points at the new one and **orphans the live
connection** (its slot leaks — the pool-exhaustion reclaim only scans
closing states).

**RFC.** RFC 9293 §3.10.7.4 (SYN in a synchronized state); RFC 5961
§4 — a SYN in the window should elicit a challenge ACK, not a
state change.

**Triggers when.** A duplicate/retransmitted SYN, a NAT rebinding onto
a live 4-tuple, or a blind-injection attempt.

**Fix.** Detect a SYN whose 4-tuple matches an `Established` TCB;
respond per RFC 5961 §4 (challenge ACK) rather than allocating a new
TCB. Pairs naturally with T5. **Effort: S–M.**

**Test.** Handshake to `Established`, deliver a fresh SYN on the same
4-tuple; assert a single challenge ACK, no new TCB, the original
connection still delivers data.

### T5 — RFC 5961 §4/§5 challenge ACKs and rate limiting

**What.** Only the §3.2 RST check is implemented. There is no
challenge-ACK path for an in-window-but-not-exact SYN (§4) or for
blind data injection (§5), and no challenge-ACK rate limit.

**RFC.** RFC 5961 §4, §5.

**Triggers when.** Off-path blind-injection attempts against a
public-facing server. Lower urgency than T1–T4 (it is hardening, not
an everyday-breakage bug), but it is the standard mitigation for a
server on the open internet.

**Fix.** Add the challenge-ACK responses and a per-core token-bucket
rate limit. **Effort: M.**

**Test.** Script in-window-but-off-`rcv_nxt` SYN / data; assert a
challenge ACK and no state change; assert the rate limit caps the
challenge-ACK rate.

---

## P2 — performance ceilings / feature breadth

### T6 — Window scaling + timestamps (RFC 7323)

**What.** `rcv_wnd` / `snd_wnd` are `u16`; no `Window Scale` or
`Timestamps` option, no PAWS.

**Triggers when.** High bandwidth-delay-product paths. The 64 KiB
window caps a single connection's throughput at `64 KiB / RTT` — e.g.
~1.3 MB/s at a 50 ms WAN RTT, regardless of link speed.

**Fix.** Widen `rcv_wnd`/`snd_wnd` to `u32` (the queue's
`rtx_bytes_in_flight` is already `u32`, so the retx-coverage path
takes no fixed-size cap with it); negotiate and apply the scale
shift; add Timestamps + PAWS. Cross-cutting — touches all window
arithmetic. **Effort: L.**

**Test.** Assert the options are echoed on the SYN-ACK and that a
post-scale window past 64 KiB is honored.

### T7 — SACK (RFC 2018) + RFC 6675 loss recovery

**What.** No `SACK-Permitted` negotiation, no SACK blocks, no
SACK-driven loss recovery.

**Triggers when.** Multi-segment loss — recovery falls back to
RTO/fast-retransmit one hole at a time instead of retransmitting only
the missing ranges.

**Fix.** Depends on T3 (the reassembly queue is what SACK blocks are
generated from). Add option negotiation, block generation, and
sender-side RFC 6675. **Effort: L.**

**Test.** Out-of-order arrival → assert correct SACK blocks; scripted
multi-hole loss → assert only the holes are retransmitted.

### T8 — An out-of-window segment should be ACKed, not dropped silently

**What.** A data segment ahead of the receive window is dropped with
no response. RFC 9293 §3.10.7.4 step 1 calls for an ACK so the peer
re-synchronizes promptly.

**Fix.** Send a bare ACK for an unacceptable segment. Small; related
to T3. **Effort: S.**

---

## P3 — optional / low impact

- **T9 — Nagle's algorithm (RFC 9293 §3.7.4).** The send path emits
  partial segments freely. For a bulk-response HTTP server this barely
  matters (responses are MSS-full); worth a deliberate decision —
  implement Nagle, or document the non-Nagle choice. **S.**
- **T10 — Delayed-ACK coalescer.** We ACK every segment immediately
  (a deliberate choice — it unbroke TLS-handshake latency). Conformant,
  but doubles the segment count on a pure-receive stream. A timer-based
  coalescer is the proper fix. **M.**
- **T11 — ECN (RFC 3168).** No ECE/CWR handling. **M.**
- **T12 — TCP keepalive (RFC 9293 §3.8.4).** A MAY; unnecessary for a
  request/response server. **M.**
- **T13 — SYN-ACK retransmission timer.** A retransmitted client SYN
  already re-drives the SYN-ACK, so a dedicated timer is cosmetic. **S.**

---

## Test & assurance backlog

The harness proves the scenarios we wrote pass; it does not measure
RFC coverage. To raise assurance:

- **Deeper assertions.** Today's scenarios check flags / ports / seq /
  ack. Also verify the TCP + IP checksums and that delivered payload
  actually lands in `rx_ring` (drive `accept` + `recv`).
- **Receive-path fuzzing.** `tcp_receive` parses attacker-controlled
  header bytes and has no fuzz coverage. A `cargo-fuzz`-style target
  over the host build would catch panics / desyncs.
- **RFC requirement → test traceability matrix.** Enumerate the
  MUST/SHOULD clauses and mark each tested / untested / not-implemented,
  so the real coverage is visible rather than inferred.
- **Interop under loss.** Run against a Linux peer behind `netem`
  loss/reorder — this is where T3 (no reassembly) will show starkly.
- **`.pkt` interpreter.** A small packetdrill-DSL front-end once the
  scenario count justifies it; lets feature-agnostic corpus scripts be
  cherry-picked.

## Deliberate non-goals

Not pending — explicitly out of scope:

- **Client-side TCP** — active open, `SYN-SENT`. The stack is
  server-role; conformance targets the server role only.
- **Exotic options** — TCP-AO, MPTCP, TCP Fast Open.
- **The full Linux packetdrill corpus** — most of it assumes window
  scaling / SACK / timestamps.

## Suggested sequence

Dependency-ordered, test-first per item:

1. ✅ **T1** (ACK validation) — done.
2. **T2** (MSS option + clamp) — removes the sub-1500-MTU blackhole.
3. **T4 + T5** (SYN-on-sync + RFC 5961 challenge ACKs) — one coherent
   hardening change.
4. **T3** (out-of-order reassembly) — the big one; unblocks T7/T8.
5. **T8** (ACK out-of-window segments) — falls out of T3.
6. **T6** (window scaling + timestamps).
7. **T7** (SACK / RFC 6675).
8. **T9–T13** — checklist, as priorities allow.

Test-infrastructure items (fuzzing, traceability matrix, deeper
assertions) are worth interleaving — they make every step above
verifiable rather than asserted.
