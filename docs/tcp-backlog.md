# TCP backlog — RFC conformance + Linux performance parity

Last updated 2026-06-09.

The authoritative TCP work queue: *pending* RFC-conformance gaps (T-items)
and the performance features Linux's kernel TCP has that ours doesn't
(L-items), in priority order. The per-RFC *status* view (Have/Missing/test
coverage) and the conformance-testing strategy + QUIC roadmap live in
[`conformance-roadmap.md`](conformance-roadmap.md); this is the work queue.

Finished items are collapsed to one-line ledger entries with their commit
ref — the implementation narrative lives in git log. Only the *open* work
and any deliberate-deferral rationale is carried in full below.

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

### T1 — ACK field validated against the send window — ✅ done (main)

RFC 9293 §3.10.7.4 acceptability rule enforced in `tcp_receive`'s ACK
branch. Security rationale: an old/reordered or forged ACK previously
drove `snd_una` backwards and flushed the retransmit ring (RFC 5961 §5
blind-injection territory) — do not regress the `SND.UNA < SEG.ACK <=
SND.NXT` guard.

### T2 — MSS option honored from SYN + SYN-ACK advertise + PMTUD — ✅ done (`74e53e1`, `be7ad67`)

Parse the peer SYN's MSS → `snd_mss = min(local, peer).max(536)` at every
segmentation site; advertise our own MSS in the SYN-ACK; decode ICMP
PTB/Frag-Needed (RFC 1191 / 8201) and lower `snd_mss` with RFC 5927
anti-spoof. Fixed a live 5G/NAT64 cert-flight blackhole.

**Open (PMTUD slivers, both minor):**
1. The MTU update applies on the *receiving* core only — an ICMP error
   RSS-hashes by its own header, so on a multi-queue NIC it's often
   delivered to a core that doesn't own the flow and dropped
   (`pmtu_dropped`); routing it to the owning core is a follow-up.
2. `note_path_mtu` lowers `snd_mss` but does **not** immediately re-send
   the already-in-flight oversized segment that triggered the ICMP — it
   waits for the RTO/TLP to re-segment at the new MSS (one recovery cycle
   of delay per MTU drop).

---

## P1 — real impact under loss or hostile traffic

### T3 — Out-of-order reassembly queue — ✅ done

Bounded per-conn `OooQueue` (`state.rs`, 32 segs / 16 KiB) buffers gapped
segments and `drain_ooo` releases the contiguous prefix as the gap fills;
an OOO arrival elicits an immediate dup-ACK (RFC 5681 §4.2). Unblocked
SACK (T7) and the in-window classification (T8).

**Open:** GCE/netem loss-path *throughput* validation still pending (the
win is invisible on a clean LAN; correctness is unit-pinned).

### T4 — SYN on a synchronized connection — ✅ done

SYN matching an `Established` 4-tuple now sends a (rate-limited) RFC 5961
§4 challenge ACK and drops the SYN, leaving the live TCB intact — no
second TCB, no orphaned slot leak.

### T5 — RFC 5961 challenge ACKs + rate limiting — ✅ done (§7 rate limit + §4/§3.10.7.4 routed)

Per-core token-bucket challenge-ACK rate limit (RFC 5961 §7) gating the
SYN-on-`Established` (§4) and out-of-window-ACK (§3.10.7.4) paths via
`send_challenge_ack`.

**Open (deferred):** the §5 in-window-but-off-`rcv_nxt` *data*-injection
challenge — we still drop such data silently (safe, just not the proactive
challenge). Folds into T3's in-window classification, so close it there.

---

## P2 — performance ceilings / feature breadth

### T6 — Window scaling — ✅ done (`bd89169`); Timestamps + PAWS still pending (RFC 7323)

Window Scale done & GCE-validated (`snd_wnd` is `u32`, peer scale parsed
and applied, SYN-ACK echoes our `rcv_wscale = 0`); ~4.3–4.9× on sustained
high-RTT keep-alive transfers.

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

### T7 — SACK (RFC 2018) + RFC 6675 loss recovery — ✅ done (correctness)

Receiver side: `SACK-Permitted` negotiated, ACKs carry SACK blocks built
from the T3 OOO queue (hot-path-neutral — no option unless `sack_ok &&
!ooo.is_empty()`). Sender side: parse peer SACK blocks, mark the
retransmit queue, and on 3rd-dup-ACK fast retransmit fill every un-SACKed
hole below the highest SACK in one pass; RTO clears the scoreboard
(reneging safety).

**Open:** GCE/netem multi-hole-loss *throughput* A/B still pending
(correctness is unit-pinned, like T3).

### T8 — Out-of-window segment ACKed, not dropped silently — ✅ done

Fell out of T3: the reassembly branch sends a bare ACK for every future
data segment (queued or too-far-ahead); a behind-window segment already
drew a dup-ACK. So every data segment now produces an ACK.

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

### L1 — CUBIC — ✅ done + GCE-validated (Reno stays default — no win on this workload); BBR still open

`net_cc::Cubic` (RFC 8312, fixed-point) selectable behind the `Controller`
enum, shared by TCP and QUIC. **`DEFAULT_ALGORITHM = Reno`** — the GCE/netem
A/B showed CUBIC ≡ Reno on this workload (≤1 MB objects finish within a few
RTTs of first loss, before CUBIC's curve diverges; the binding limit is L4
tail-loss RTO, which is CC-independent), so the default flip is **not
data-justified**. CUBIC stays available; revisit if a bulk-transfer workload
appears or after L4 lets the curves be measured without the RTO confound.

**Open — BBR.** Model-based (delivery-rate + min-RTT estimation,
loss-agnostic). A larger, separate effort on the same trait seam.
**Effort: L.**

### L2 — Appropriate Byte Counting (ABC, RFC 3465) — ✅ done

Slow start now grows `cwnd` by *bytes* acked, capped at `L = 2·SMSS` per
ACK (RFC 3465 §2.3), restoring the full 2×/RTT ramp under delayed-ACK
receivers; GCE-validated +20–35 % on cold high-RTT downloads. Congestion
avoidance unchanged (byte-counting CA accumulator is a separate, lower-value
follow-up — the cold-transfer gap is entirely slow start).

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

### L4 — TLP + RACK time-detection — ✅ done + GCE-validated (the tail-loss-RTO fix)

TLP (probe timer at `PTO = 2·SRTT`, capped at 2 probes, not a congestion
signal) eliminated the multi-second tail-loss-RTO stalls — GCE/netem 1 %
loss: stalls 7→0 (25 ms) / 10→1 (50 ms), median ×3.2–3.9, clean-path
neutral. RACK time-based detection consumes the shared `net_cc::loss`
core QUIC runs on (`9/8·SRTT` reordering window, per-conn RACK timer); the
packet threshold is disabled for TCP (ids are byte offsets — count-based
stays RFC 6675's job).

**Open (follow-up).** RFC 8985's *adaptive* reo_wnd (start `min_rtt/4`,
grow on DSACK-detected spurious marks) — deliberately not landed; the
conservative QUIC-proven `9/8·SRTT` window is used instead. **Effort: S.**

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
3. ✅ **T2** (peer-MSS honor + clamp + SYN-ACK advertise + PMTUD) — done
   (`74e53e1`, `be7ad67`). PMTUD core-routing/in-flight-resegment slivers remain.
4. ✅ **T4 + T5** (SYN-on-sync + RFC 5961 challenge ACKs + §7 rate limit) —
   done. §5 in-window data challenge deferred into T3.
5. ✅ **T3** (out-of-order reassembly) — done; unblocked T7/T8. Netem
   throughput A/B pending.
6. ✅ **T8** (ACK out-of-window segments) — done; fell out of T3.
7. ✅ **T7** (SACK / RFC 6675) — done (correctness). Netem A/B pending.
8. ✅ **L2** (ABC) — done; closed the measured ~3× cold-transfer
   slow-start gap (slow start now byte-counts, capped at 2·SMSS).
9. **L1 / L3 / L4** (CUBIC, pacing, RACK-TLP) — L1 CUBIC + L4 TLP/RACK
   done; **L3 pacing** + **L1 BBR** + **L4 adaptive reo_wnd** remain (the
   deeper CC/loss-recovery parity work).
10. **T9–T13**, **L5**, Timestamps/PAWS — checklist, as priorities allow.

Test-infrastructure items (fuzzing, traceability matrix, deeper
assertions) are worth interleaving — they make every step above
verifiable rather than asserted.
