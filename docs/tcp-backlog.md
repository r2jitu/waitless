# TCP backlog — RFC conformance + Linux performance parity

Last updated 2026-06-09.

The authoritative TCP work queue: *pending* RFC-conformance gaps (T-items)
and the performance features Linux's kernel TCP has that ours doesn't
(L-items), in priority order. The per-RFC *status* view (Have/Missing/test
coverage) and the conformance-testing strategy + QUIC roadmap live in
[`conformance-roadmap.md`](conformance-roadmap.md); this is the work queue.

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
  a send path that paces against `min(cwnd, rwnd)`. The initial window
  is RFC 6928 IW10, and slow start byte-counts per RFC 3465 (ABC). (This
  is the Reno-family baseline; the further performance features Linux
  layers on top — CUBIC/BBR, packet pacing, RACK-TLP — are inventoried
  under *Performance parity with the Linux TCP stack*.)
- RFC 7323 — Window Scale: `snd_wnd` is `u32`, the peer's scale shift is
  parsed from its SYN and applied to every post-handshake window update,
  and the SYN-ACK echoes a Window-Scale option (we advertise
  `rcv_wscale = 0` — our 16 KiB RX ring needs none, so our *own* receive
  window stays ≤ 64 KiB by choice; the win is download-side). Lifts the
  64 KiB/RTT send ceiling — GCE-validated ~4–5× on sustained high-RTT
  downloads. Timestamps + PAWS are *not* done (see T6).
- RFC 9293 §3.8.6.1 — zero-window persist, both roles: as sender we
  probe a peer's shut window (exponential backoff, give-up after
  `PERSIST_MAX_PROBES`); as receiver we answer an inbound bare probe
  and re-fire a stalled `recv` waker (ce562ff).
- RFC 5961 §3.2 — strict-sequence RST acceptance.
- RFC 1122 §4.2.2.16 — receiver silly-window-syndrome avoidance: a
  window-update ACK when an app drain reopens the window past one MSS,
  fired both on the drain and on any inbound segment (ce562ff).

Validation: `//crates/net/tcp:tcp_test` is a 68-scenario in-process
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

> **Status (2026-06-09):** the receive half is ✅ done (`74e53e1`): the
> SYN's MSS option is parsed (`parse_syn_options`) and the negotiated
> `snd_mss = min(local, peer).max(536)` drives every segmentation site
> including retransmit re-segmentation. It fixed a live production
> failure — a 5G/NAT64 path MSS-clamped the SYN to ~1220, our 1460-byte
> TLS cert flight was silently dropped, and cold (incognito) h2 loads
> stalled deterministically. Still open, tracked as the follow-up
> hardening task: *sending* our MSS option in the SYN-ACK (peers
> currently assume 536 toward us, shrinking upload segments) and PMTUD
> (ICMP Packet-Too-Big) for the advertise-large-but-path-small case.


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

### T4 — A SYN on a synchronized connection corrupts the pool ✅ done

**Status.** Fixed. The SYN handler now probes the 4-tuple hash once; a
SYN matching an `Established` TCB sends a (rate-limited) RFC 5961 §4
challenge ACK and drops the SYN, leaving the live connection intact —
no second TCB, no orphan. A legitimate restart answers the challenge
with an RST (in-window → tears down → client re-SYNs). See
`syn_on_established_conn_elicits_a_challenge_ack` in `tests.rs`.

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

### T5 — RFC 5961 §4/§5 challenge ACKs and rate limiting ✅ done (§7 rate limit + §4/§3.10.7.4 routed; §5-in-window deferred)

**Status.** A per-core token-bucket challenge-ACK rate limit
(`CHALLENGE_ACK_RATE`/`CHALLENGE_ACK_BURST`, RFC 5961 §7) now gates the
two challenge-ACK triggers we emit: the SYN-on-`Established` path (§4,
T4) and the RFC 9293 §3.10.7.4 out-of-window-ACK path. Both route
through `send_challenge_ack`, counted via `challenge_ack_sent` /
`challenge_ack_throttled` on `/obs`. See
`challenge_acks_are_rate_limited` in `tests.rs`. **Deferred:** the §5
in-window-but-off-`rcv_nxt` *data*-injection challenge (we still drop
such data silently, which is safe, just not the proactive challenge) —
folds into T3 out-of-order reassembly, which needs the in-window
classification anyway.

**What (original).** Only the §3.2 RST check is implemented. There is no
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

### T6 — Window scaling ✅ done; Timestamps + PAWS still pending (RFC 7323)

**Status — Window Scale: done and merged (`bd89169`).** `snd_wnd` is now
`u32`; the peer's scale shift is parsed from its SYN (`parse_window_scale`,
clamped at 14 per §2.3) and applied to every post-handshake window update;
the SYN-ACK echoes a Window-Scale option only when the peer offered one,
advertising `rcv_wscale = 0` (our 16 KiB RX ring needs no scaling, so our
*own* receive window stays ≤ 64 KiB by design — a server mostly sends).
Four `tcp_test` scenarios cover negotiation, the scaled update, the
no-offer path, and the §2.3 clamp. **GCE-validated:** `ss` confirms
`wscale:0,7` on the wire; a sustained 20 MB keep-alive transfer over
`tc netem` ran **18.9 → 81.9 Mbps at 25 ms (4.3×)** and **9.5 → 46.2 Mbps
at 50 ms (4.9×)**, with window-scaling-off sitting exactly on the
64 KiB/RTT cap. (A *cold* single 1 MB transfer improved only ~12–28 % —
slow-start/`cwnd` is the binding limit there, not `rwnd`; see *ABC* and
*initial window* under Linux-parity. So window scaling is the lever for
sustained / warm-connection transfers, not cold small ones.)

**Pending — Timestamps + PAWS.** No `Timestamps` option, so no RTTM
sample per ACK and no Protect-Against-Wrapped-Sequences. Lower priority
than the loss/CC items: it improves RTT estimation and guards seq wrap
on very-high-bandwidth long-lived flows.

**Triggers when.** PAWS matters on >1 Gbps long-lived single flows where
the 32-bit sequence space can wrap within 2×MSL; Timestamps sharpen the
RTO on paths with variable RTT.

**Fix.** Add the `Timestamps` SYN option + per-segment TSval/TSecr, feed
TSecr into the RTT estimator, and add the PAWS drop check.
`rcv_wnd` stays `u16` (we advertise `rcv_wscale = 0`). **Effort: M.**

**Test.** Assert Timestamps are echoed; a wrapped-sequence old segment is
dropped by PAWS; the RTT estimator consumes TSecr.

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

## Performance parity with the Linux TCP stack

The items above are mostly *RFC conformance* — correctness clauses we
don't yet meet. This section is different: it inventories **performance
features the Linux kernel TCP stack implements that ours does not**.
None of these are conformance bugs — our stack is RFC 5681 / RFC 6298
compliant — but they are the reason a mature kernel out-performs a
hand-rolled stack on adverse (WAN, lossy, high-BDP) paths, and they are
exactly what a `tokio-hyper`/`nginx`/any-Linux server gets *for free* by
riding the kernel. They belong here so the "gaps vs Linux" picture is
complete rather than implicit. (Window scaling — T6 — and ABC — L2 —
*were* on this list and are now done; the rest remain.)

Why it matters for our benchmark story: on low-RTT LAN/datacenter paths
(where [`benchmark-results.md`](benchmark-results.md) measures) congestion
control barely engages and our no-syscall architecture wins ~2×. On
high-RTT or lossy paths these gaps bind, and the comparison narrows or
inverts — Linux's CC/loss-recovery is decades deep.

**The shared TCP+QUIC congestion core now exists (QUIC-wired); the TCP
half is what remains.** The `CongestionControl` trait + a NewReno
implementation landed in `crates/net/cc` and are **wired into QUIC** (its
RFC 9002 controller) — but TCP still runs its own embedded `cwnd`/`ssthresh`
methods. So the moves here are: (a) delegate TCP onto the shared trait, then
(b) write L1 (CUBIC/BBR) + L3 (pacing) *once* on it for both transports.
QUIC already provides the reference for the pieces TCP wants — its
threshold loss detector is the RACK model L4 needs, and its token-bucket
pacer (`crates/proto/quic/src/conn/tx.rs`) is prior art for L3 — but neither
is wired into TCP yet. The plan lives in
[`stack-architecture.md`](stack-architecture.md) → *Transport reliability
— one congestion-control / loss-recovery / pacing core*.

### L1 — Congestion control is Reno only (no CUBIC / BBR)

**What.** Our controller is classic RFC 5681 Reno: slow start + AIMD
(halve on loss, +1 MSS/RTT in avoidance). Linux defaults to **CUBIC**
(cubic window growth — far more aggressive recovery on high-BDP paths)
and ships **BBR** (model-based, rate/RTT estimation, loss-agnostic).

**Triggers when.** High-BDP paths and any path with non-congestive loss.
Reno's `cwnd ÷ 2` per loss + linear reopen badly underfills a fat pipe;
CUBIC reopens cubically, BBR ignores loss as a signal entirely. The gap
widens with bandwidth × RTT.

**Fix.** The shared `CongestionControl` trait already exists
(`crates/net/cc`, QUIC-wired — see
[`stack-architecture.md`](stack-architecture.md) → Transport reliability);
delegate TCP onto it behind the roadmap's "Lift `tcp` above `executor`"
seam, then write CUBIC once for both TCP and QUIC. CUBIC is the pragmatic
first algorithm — it genuinely doesn't exist yet (only NewReno/Reno does).
**Effort: L.**

### L2 — Appropriate Byte Counting (ABC, RFC 3465) — ✅ done

**Status — done and merged.** `cwnd_on_ack`'s slow-start branch now
grows `cwnd` by the *bytes* the ACK acknowledged, capped at `L = 2·SMSS`
per ACK (RFC 3465 §2.3), instead of the old flat `min(acked, SMSS)`.

**What it fixed.** The old "count ACKs" rule grew `cwnd` by one SMSS per
ACK; under the delayed-ACK receivers that dominate the internet (1 ACK
per 2 segments) that is one SMSS per *two* segments → slow start grew
~1.5×/RTT instead of the 2× it intends — the measured "~3× below
textbook" on cold single-conn high-RTT downloads (the slow-start ramp,
not `rwnd`, bounds those). Byte counting restores the full 2× regardless
of how the receiver batches ACKs; the `2·SMSS` cap bounds the burst a
stretch-/post-idle ACK can release (we don't pace — L3 — so this cap is
the burst guard).

**Test.** `slow_start_grows_cwnd_by_bytes_acked_abc` asserts a 2-segment
ACK opens `cwnd` by 2·SMSS and a stretch-ACK is capped at 2·SMSS.
Congestion avoidance is unchanged (still the RFC 5681 `SMSS²/cwnd`
approximation — the byte-counting CA accumulator is a separate, lower-
value follow-up; the cold-transfer gap is entirely slow start).

**GCE-validated.** A controlled single-build-line A/B on e2-small (deploy
ABC, measure; revert *only* the `min(2·SMSS)` → `min(SMSS)` line, redeploy,
measure — same `tc netem` path, 12 cold fresh-connection trials, median):

| RTT | object | ABC | baseline | gain |
|---|---|--:|--:|:-:|
| 25 ms | `/static-256k` | 8.16 | 6.77 Mbps | +20 % |
| 25 ms | `/static-1m` | 20.29 | 15.50 Mbps | +31 % |
| 50 ms | `/static-256k` | 4.14 | 3.45 Mbps | +20 % |
| 50 ms | `/static-1m` | 10.67 | 7.91 Mbps | +35 % |

Matches the ~28 % theory (≈7 vs ≈9 slow-start RTTs for 1 MB); the larger
`/static-1m` gain confirms the ramp compounds over more RTTs.

### L3 — No packet pacing

**What.** The send path bursts a full `cwnd`/window worth of segments
back-to-back. Linux paces — spreads a window over the RTT (fq qdisc;
mandatory under BBR).

**Triggers when.** Bursts overrun shallow bottleneck buffers → loss.
This is the safety machinery that lets Linux servers run a large initial
window (Google IW32, Cloudflare ~30) without burst-loss — and the reason
we *don't* raise our IW past 10 (see roadmap / the IW trade-off):
un-paced, a larger IW is a burst-loss bet against constrained clients.

**Fix.** A per-conn pacing timer / token bucket gating `async_try_send_chain`.
QUIC's token-bucket pacer (`crates/proto/quic/src/conn/tx.rs`, driving
`net_cc`'s `pacing_rate()`) is the prior art to port. Pairs with BBR (L1).
**Effort: M.**

### L4 — Loss recovery is RTO + 3-dup-ACK only (no RACK-TLP, no SACK)

**What.** We detect loss via 3 duplicate ACKs (fast retransmit) or the
RTO. No SACK (T7), no **RACK-TLP** (RFC 8985 — time-based loss detection
+ Tail Loss Probe), which is Linux's default loss detector since 4.18.

**Triggers when.** Tail loss (the last segments of a response) and
multi-hole loss. Without TLP a lost tail waits a full RTO (~200 ms+)
instead of a probe-timeout (~2·RTT); without SACK, multi-hole recovery
re-sends more than the holes. Both punish exactly the small-response
HTTP pattern this server is built for, on a lossy path.

**Fix.** RACK-TLP needs per-segment send timestamps (the retransmit ring
can carry them); QUIC's RFC 9002 packet-/time-threshold loss detector
(`crates/proto/quic/src/conn/loss.rs`) is already the RACK model to mirror.
SACK is T7 (needs the T3 reassembly queue). **Effort: L.**

### L5 — No receive/send buffer autotuning

**What.** The per-conn RX ring is a fixed 16 KiB and we advertise
`rcv_wscale = 0`, so our *receive* window is hard-capped at ≤ 64 KiB.
Linux autotunes `tcp_rmem`/`tcp_wmem` per connection (up to megabytes)
from the measured BDP.

**Triggers when.** Large *uploads* to us over a high-BDP path — the
client is throttled to 64 KiB/RTT inbound. Deliberate today (a server
mostly sends; large uploads are rare), but it's the symmetric twin of
the send-side cap T6 just removed, and worth recording as a known limit.

**Fix.** A growable RX ring + non-zero `rcv_wscale` advertised in the
SYN-ACK. Only worth it if upload-heavy workloads appear. **Effort: M.**

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
- **The full Linux packetdrill corpus** — most of it assumes SACK /
  timestamps (window scaling we now have).

## Suggested sequence

Dependency-ordered, test-first per item:

1. ✅ **T1** (ACK validation) — done.
2. ✅ **T6 window scaling** (RFC 7323 Window Scale) — done & GCE-validated.
   Timestamps + PAWS remain (the rest of T6).
3. ✅ **T2** (peer-MSS honor + clamp) — done (`74e53e1`); fixed the live
   5G/NAT64 cert-flight blackhole. SYN-ACK MSS advertise + PMTUD remain
   (follow-up hardening).
4. **T4 + T5** (SYN-on-sync + RFC 5961 challenge ACKs) — one coherent
   hardening change.
5. **T3** (out-of-order reassembly) — the big one; unblocks T7/T8.
6. **T8** (ACK out-of-window segments) — falls out of T3.
7. **T7** (SACK / RFC 6675).
8. ✅ **L2** (ABC) — done; closed the measured ~3× cold-transfer
   slow-start gap (slow start now byte-counts, capped at 2·SMSS).
9. **L1 / L3 / L4** (CUBIC, pacing, RACK-TLP) — the deeper CC/loss-recovery
   parity work; gated on the L4 vtable seam and SACK (T7).
10. **T9–T13**, **L5**, Timestamps/PAWS — checklist, as priorities allow.

Test-infrastructure items (fuzzing, traceability matrix, deeper
assertions) are worth interleaving — they make every step above
verifiable rather than asserted.
