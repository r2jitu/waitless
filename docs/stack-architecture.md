# Stack Architecture & Inter-Layer API Design

A design/architecture tracker for the **shape of the network stack** — the
contracts between layers (NIC → TCP/UDP → reactor → TLS/QUIC → HTTP) and the
plan to collapse the two parallel datapaths into **one golden path** with cheap
diminished alternatives.

Unlike its siblings, this doc owns no cost axis. It owns the **seams**: the
buffer currency, the stream trait, the handler API, and the
POD-function-pointer-vs-trait question at the NIC and reactor boundaries. "Less
code is easier to optimize and maintain"; the per-byte/per-frame optimization
work lives in the cost trackers, and the right long-term *contracts* live here.

> Written 2026-05-28 from a full read of the RX/TX paths. Cites current
> `//crates/...` labels (post the May-2026 crate move — see
> [`crates.md`](crates.md)). Where a recommendation has an owner in a cost
> tracker, this doc names the exact item and **defers** rather than restating.

## How this fits with the other docs

The repo's perf trackers route fixes by *cost locus*
([`high-concurrency-perf.md`](high-concurrency-perf.md) §"How this fits"). This
doc adds the **structure/contract locus**. The reciprocal rule:

| Locus | Doc |
|---|---|
| per-byte / per-frame RX cost | [`rx-path-optimizations.md`](rx-path-optimizations.md) |
| per-byte / per-frame TX cost | [`tx-path-optimizations.md`](tx-path-optimizations.md) |
| per-conn data structures, scheduling, saturation, load shedding | [`high-concurrency-perf.md`](high-concurrency-perf.md) |
| the iobuf ownership/`Send` type model | [`iobuf-type-model.md`](iobuf-type-model.md) |
| RFC correctness (TCP / QUIC) | [`tcp-backlog.md`](tcp-backlog.md), [`conformance-roadmap.md`](conformance-roadmap.md) |
| **inter-layer contracts: buffer currency, stream trait, handler API, NIC/reactor backend abstraction, two-stacks→one-golden-path convergence, API simplification** | **this doc** |

Deferral discipline: a contract change here that has a measured per-conn /
heap-slope / saturation consequence is **named here and measured there** (the
named-item handoff pattern in high-concurrency-perf.md's "Prioritized gaps"). This doc proposes
*shapes*; the cost docs prove *what they cost*.

## The thesis: two parallel stacks → one golden path

The stack is not one datapath with options. It is **two datapaths**, and only
one is in good shape:

| | Stack A (TCP side) | Stack B (UDP side) |
|---|---|---|
| Path | NIC → TCP → reactor → TLS → HTTP/1.1 | NIC → UDP → reactor → QUIC → HTTP/3 |
| RX buffer | **owned `Chain<OwnedIOBuf>`**, zero-copy, retainable | **borrowed `&[u8]`**, must be consumed synchronously |
| RX copies to app | 1 (0 on the `recv_chunk` stash fast path) | 4–5 (inbox → conn inbox → RecvStream → h3 chunk → h3 scratch) |
| byte-sequence type | `Chain<IOBuf>` + `Cursor` | `VecDeque<IOBuf>` + hand-rolled `head_consumed` cursor |
| stream abstraction | `HttpStream` trait (clean, generic) | shared `ResponseSink`/`BodyReader` at the handler seam (`NullStream` deleted, 2026-06); transport internals still sid-keyed — the `ByteStream` trait (Contract 2) remains open |
| HTTP body | streamed lazily through `BodyReader` | streamed both directions (2026-06): bounded request-body streaming + `res.write()` response streaming under QUIC stream flow control |
| handler signature | unified `(&mut Request, &mut Response<'_>)` | same — converged (streaming-response, 2026-06) |

Stack B is the stated differentiator (QUIC-over-async — see
[`conformance-roadmap.md`](conformance-roadmap.md)), yet it runs the slower,
copy-heavy, un-abstracted path. **The simplification is to converge B onto A's
contracts.** "One golden path" is not TCP *or* QUIC — it is both transports
riding the same three contracts:

1. **One buffer currency** — `OwnedIOBuf` / `Chain` / `Cursor`, owned and
   zero-copy, both directions, both transports.
2. **One stream trait** — `recv_chunk() → guard` / `send(&mut IOBufChain)` /
   `finish()`, implemented by TCP, TLS, **and** QUIC streams.
3. **One handler API** — `(&Request, &mut BodyReader<impl ByteStream>)` for both
   HTTP versions; no `NullStream`.

The diminished alternatives then fall out as *variations on the golden path*
(hardware-forced copies in GQI/DQO, the copy-into-buffer `recv`), not as
parallel implementations.

**Maturity, not just code quality.** Stack A isn't only better-factored — it's
the production path: **IPv4 + TCP + TLS + HTTP/1.1** carries today's traffic.
Stack B (**IPv6 + UDP + QUIC + HTTP/3**) is the differentiator still under
construction. "Converge B onto A" is therefore doubly motivated — A is the proven
shape *and* the shipping one. Locking the contracts now (especially the stream
trait) is about keeping H3 from ossifying a divergent API before it's finished;
it is **not** a claim that H3 is golden today.

Much of contract 1 is **already landed** (the iobuf type model, the share-based
RX/rtx queues, the whole zero-copy RX path A→H). The net-new work is contract 2,
the handler half of contract 3, the backend-abstraction migrations, and a small
amount of genuine dead-code deletion. Each is routed below.

---

## Contract 1 — One buffer currency (iobuf)

### What is already landed (cite, don't re-propose)

- The **`Send`-by-derivation type model** — `OwnedIOBuf`, generic `Chain<B>`,
  the `IOBufRead` trait, the uniform `IOBufDropFn` free model — landed
  2026-05-16; owned by [`iobuf-type-model.md`](iobuf-type-model.md).
  `Chain<OwnedIOBuf>` being `Send` *by derivation* (no `unsafe impl Send`) is
  the single best property in the stack and is the foundation everything below
  rests on. **Freeze it.** Any cross-cutting work here cites that doc for the
  ownership model rather than reasoning about it afresh.
- The **share-insertion idiom** for refcounted buffers — landed on both the TCP
  rtx queue (`tcp/rtx-share`) and the TLS plaintext queue (`tls/rx-share-queue`)
  — see those branches' ceiling-mover entries in high-concurrency-perf.md. The primitives are
  `IOBuf::share()` / `clone_shared()` / `narrow()` / `OwnedIOBuf::try_from`. The
  refcounted-RX work below is an **extension of this idiom to Stack B**, not a
  new mechanism.
- The whole **zero-copy RX path** (rx-path-optimizations.md items A–H, landed)
  and the **direct-fill TX path** (tx-path-optimizations.md items A, B, P, Q,
  landed). The current per-byte cost is 1 memcpy on each side of Stack A; this
  doc does not relitigate that.

### Net-new: unify the "sequence of bytes" type

There are three ways to express "a sequence of byte buffers":

- `Chain<IOBuf>` + `Cursor` — Stack A (TCP/HTTP TX, NIC RX). The golden type.
- `VecDeque<IOBuf>` + a hand-rolled `head_consumed`/`advance_head` cursor —
  QUIC `SendStream.outbound` (`//crates/proto/quic/src/streams.rs`).
- `VecDeque<OwnedIOBuf>` — TLS `pending_plaintext`
  (`//crates/proto/tls/src/server.rs`).

The per-packet `Vec` *churn* that used to live on the QUIC TX path is already
gone (tx items O, Q). What remains is a **data-structure unification**, not a
perf win: make QUIC's `SendStream.outbound` an `IOBufChain` drained by
`iobuf::Cursor`, deleting the hand-rolled cursor; and let TLS hold its decrypted
records as a `Chain` (see contract 2's chain-shaped `pop_plaintext`). The value
is one fewer cursor implementation and a type that lines up trivially with the
`send(&mut IOBufChain)` half of the stream trait.

- **Status**: [ ] not started. **Where**: `quic/src/streams.rs` (cursor),
  `tls/src/server.rs` (`pending_plaintext`). **Win**: deletes one bespoke
  cursor; aligns QUIC/TLS with the stream trait. **Effort**: low–medium.
  **Risk**: low (mechanical). **Cite**: tx items O/Q (the alloc churn is already
  removed, so frame this as maintainability, not memcpy).

> ⚠️ **A `Chain` is not always one frame.** RSC/GRO super-segments
> (rx-path-optimizations.md items I, M (landed), N) make a chain potentially
> *multi-buffer*: the TCP/IP RX path already accepts a coalesced chain whose
> logical length exceeds one MSS. Any code that treats `Chain` as "exactly one
> MTU frame" is wrong. Honor the multi-buffer contract; defer the RSC mechanics
> to the rx doc.

### Decision deferred to the TX doc: `prepend_in_place` for L2–L4 framing

`Chain::prepend_in_place` is **not** dead — it backs the small TLS-record / H3-
frame header prepend and `body_iobuf` headroom, and has tests. What's true is
narrower: the **L2–L4 frame-header TX path** does *not* use it. It stamps
headers into a `&mut [u8]` slot via `fill_header` (`fill_tcp_frame_headers`,
`fill_udp_frame_headers`, and per-layer `ethernet/ipv4/ipv6::fill_header`), with
a v4 memmove and magic `CsumOffload` offsets duplicated per call site.

There is a real choice — unify the L2–L4 path onto the `Chain`-headroom model
(killing the `fill_tcp`/`fill_udp` fork) vs keep the `fill_header`-into-slot
model (tx items A, P). **This is a TX-cost decision; it belongs to**
[`tx-path-optimizations.md`](tx-path-optimizations.md) (items A, P, and the
2026-05-09 "chain prepend supersedes body_iobuf headroom" note). This doc only
flags that the duplication is the same shape as the `fill_tcp`/`fill_udp` twin
and should be decided once.

The **IPv4/IPv6 wire-format fork** is the same story one layer down —
`flow_hash_v4`/`flow_hash_v6`, `l4_pseudo_partial` v4/v6, the v4-only TX payload
memmove, and the legacy `ipv4_send`/`ipv6_send → ethernet_send` control-plane
frame builder (the second "put a frame on the wire" implementation, used by
ARP/NDP). It is real duplication, but it's L3/per-frame, not an inter-layer
contract → defer to [`tx-path-optimizations.md`](tx-path-optimizations.md) /
[`networking.md`](networking.md). Flagged here only so the map is complete.
**IPv4 stays** — it's the production L3 (see the thesis); the data plane must
never reach the legacy `ethernet_send` chain, which stays control-plane-only.

### Dead-API cleanup → iobuf-type-model doc

The audit found several iobuf methods with zero production consumers; deleting
them is a clean win. The authoritative inventory lives in
[`iobuf-type-model.md`](iobuf-type-model.md)'s "Dead / latent surface" section
(don't duplicate the list here — it drifts). Noted only so the cross-cutting
"freeze the core, trim the edges" goal is recorded.

---

## Contract 2 — One stream trait (the keystone)

This is the highest-value, longest-lived, net-new API in the audit, and the one
that gets harder to change the longer h3 ships with a stub.

### Current state

- `HttpStream` (`//crates/proto/http/src/stream.rs`) is the shared byte-I/O
  trait — but only Stack A fits it. It is `&mut self`, one-object-per-connection.
- QUIC is `&self`, sid-multiplexed (one `QuicConn` multiplexes N streams), so h3
  **bypasses the trait** and does real I/O through `QuicConn::{accept_stream,
  recv(sid,&mut [u8]), send_iobuf, close_stream}`
  (`//crates/proto/quic/src/endpoint.rs`). (The `NullStream` stub it once used
  to satisfy the trait was deleted when streaming-response landed, 2026-06; the
  trait bypass itself — Contract 2 — is still open.)
- **Layering inversion — RESOLVED (2026-06-09):** `HttpStream::recv_chunk`
  used to return a type *defined in the reactor*
  (`waitless::runtime::RecvChunkGuard`), so `proto/http`'s transport-agnostic
  trait and `proto/tls` reached *down* into a specific transport crate for
  their read type. The guard is a pure `IOBuf` wrapper, so it now lives in
  `iobuf` itself (the existing buffer leaf — no new `net_io` crate needed);
  the reactor re-exports it for compatibility, and `MAX_L2_HEADROOM` moved to
  `nic_api` next to the TX-handle contract it describes. The reactor location
  had been a deliberate workaround (rx item G) for the `proto/tls →
  runtime/executor` dependency direction; homing the types in crates *below*
  all parties resolves what item G worked around.

### Target

A per-stream byte-I/O trait in a **new low crate** (`net_io`), depended on by the
reactor, `proto/tls`, `proto/quic`, and `proto/http` alike:

```rust
// net_io — owns its own read guard, not the reactor's
pub struct ReadChunk<'a> { buf: IOBuf, _borrow: PhantomData<&'a mut ()> }
impl ReadChunk<'_> {
    pub fn data(&self) -> &[u8];
    pub fn data_mut(&mut self) -> Option<&mut [u8]>;          // in-place decrypt
    pub fn into_owned(self) -> IOBuf;
    pub fn into_remainder(self, consumed: usize) -> Result<Option<IOBuf>, IOBufError>;
}

pub trait ByteStream {
    async fn recv_chunk(&mut self) -> Option<ReadChunk<'_>>;
    async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), StreamError>;
    async fn finish(&mut self) -> Result<(), StreamError>;    // FIN / close_notify / QUIC stream FIN
}
```

- `TcpStream` and `TlsStream` implement it directly (they nearly do today).
- QUIC gets a **per-stream handle** `QuicStream { conn, sid, progress }` that
  implements `ByteStream`. Multiplexing/accept stays version-specific (h3's conn
  loop calls `accept_stream() → QuicStream`); only *per-stream byte I/O* becomes
  shared.
- `NullStream` is deleted.

This keeps `HttpStream`'s connection==stream conflation (correct for TCP) and
moves multiplexing *above* the trait, which is the only structural reason QUIC
didn't fit.

- **Status**: ✅ *the wins are met; the trait itself is deferred as low-value*
  (assessed 2026-06-09). Every benefit this contract was meant to unlock has
  landed by other routes:
  - **layering inversion removed** + **`NullStream` deleted** — via the
    seam-type cleanup (`RecvChunkGuard` → `iobuf`, `MAX_L2_HEADROOM` →
    `nic_api`; no new `net-io` crate needed);
  - **handler-API unified** — every transport's handler is now the *identical*
    `AsyncFn(&mut Request, &mut Response) -> Result<(), ()>` (streaming-response),
    reading via the shared `BodySource`/`BodyReader` and writing via the shared
    `ResponseSink`; h3 supplies thin `H3BodySource`/`H3Sink` adapters exactly as
    h1 supplies `CellSource`/`CellSink`;
  - **h3 streaming** — done.

  What the `ByteStream` trait would *additionally* buy is unifying the **raw
  per-stream byte-I/O call** (`recv_chunk`/`send`/`finish`) beneath the HTTP
  framing. But the three serve loops (`http::serve_conn` over `HttpStream`,
  `http2::serve_conn` with frame demux + HPACK + per-stream FC, `http3`'s
  accept-loop + `handle_request(conn, sid)`) differ for *intrinsic*
  multiplexing reasons — conn==stream vs frame-multiplexed vs QUIC-sid — that a
  byte-I/O trait does **not** merge; and the per-transport framing adapters
  (`CellSink` chunked / `H2Sink` DATA / `H3Sink` DATA+QPACK) stay separate
  regardless. So the trait would re-home `RecvChunkGuard` a second time and add
  a `QuicStream` newtype to unify three already-one-line call sites, touching
  the h3 hot path for a lateral gain. Deferred unless a concrete consumer (an
  alternate runtime backend implementing the trait, or a fourth transport)
  makes the shared surface pay. The seam types are in place if that day comes.

### Respect the guard façade as the stable boundary

The rx doc designed the guard to be exactly this seam. The Phase-4 "in-place TLS
RX decrypt" follow-up (rx-path-optimizations.md, "Out of scope / known limitations") and the UDP IOBuf inbox
(item L, below) both keep the guard/inbox *shape* fixed and only change the
wrapped payload (`Borrowed` → `Chain<ExternalOwned>` / refcounted slot). The
chain-shaped `pop_plaintext` and refcounted QUIC RX recommendations here adopt
that boundary — `recv_chunk` keeps returning a guard; only what it wraps
changes. Do not redefine the façade.

### QUIC refcounted RX → owned by rx item L

Making QUIC zero-copy on RX (collapsing the 4–5 copies toward TLS's 1) requires
owned UDP delivery: `udp_receive(Chain<OwnedIOBuf>)`, and the reactor pushing a
refcounted `OwnedIOBuf` (a `share()` of the device slot) into QUIC's `ConnInbox`
instead of a copied `Vec`. **This is already owned by
[`rx-path-optimizations.md`](rx-path-optimizations.md) item L** ("UDP datagram
inbox — IOBuf-carrying slot"), which explicitly extends to the
QUIC AEAD. This doc does not re-propose it; the stream trait above is what makes
the *post-AEAD* delivery to h3 zero-copy on top of item L.

> Slot-lifetime hazard (defer to high-conc): holding NIC RX slots alive across
> QUIC reassembly lengthens slot lifetime, the same trade the share-queue
> already accepted (high-concurrency-perf.md's `tls/rx-share-queue` entry) and a potential
> amplifier of the H3/H4 heap-fragmentation story. Any owned-UDP work must A/B
> the per-conn heap slope there; the CoW-on-aliased-`Shared` escape hatch
> noted in that entry applies if a queue-depth cap is needed.

---

## Contract 3 — One handler API

### Current fork

```rust
// HTTP/1.1: borrows the request
H: AsyncFn(&Request, &mut BodyReader<'_, S>) -> Response
// HTTP/3: owns it, and demands Clone
H: AsyncFn(Request, &mut BodyReader<'_, NullStream>) -> Response + Clone
```

These don't unify, so every app writes a `handle_request_h3` adapter and makes
its real handler generic over `S` purely as glue.

### Target

Standardize on `(&Request, &mut BodyReader<'_, impl ByteStream>) -> Response`
for both versions (h3 already owns its `Request` locally — it passes `&req`,
dropping the by-value + `Clone` fork). With contract 2 in place and `NullStream`
gone, the same handler serves plain-TCP, TLS, and QUIC with no adapter.

The other half — making h3 **stream** its body through `BodyReader` instead of
buffering the whole body (the 16 KiB `RECV_CAP`) and replaying it — is the
**"HTTP/3 streaming body" follow-up already owned by**
[`rx-path-optimizations.md`](rx-path-optimizations.md). Contract
2 is its precondition (h3 needs a real `recv_chunk`). Cite it; don't restate it.

- **Status**: [ ] not started (handler-API half). **Where**: `proto/http`,
  `proto/http3`, app handlers. **Win**: one handler signature; deletes the
  per-app adapter. **Effort**: low once contract 2 lands. **Risk**: low.

### Shared `http-core` + a correctness nit

h1 and h3 share `Request`/`Response`/`BodyReader` value types but **duplicate**:
three integer-itoa impls, two method-decode tables, and the always-present
header set (h1 emits bytes; h3 builds a QPACK `&[(name,value)]`). A small
`http-core` with one itoa, one method table, and one `Response::headers()`
iterator both serializers consume removes the forks. Modest LOC; the real win is
a single authoritative request/response model.

That model must also pick **one content-length policy**: h3 ignores the declared
`content-length` and substitutes the reassembled `data.len()`
(`//crates/proto/http3/src/server.rs`), while h1 trusts the header. This is a
behavioral divergence, not just duplication — decide it in the shared model.

---

## Backend abstraction — POD function-pointers → traits

Two boundaries are hand-rolled vtables (a `struct` of `fn` pointers, half of them
`Option<fn>`). Both reimplement trait-object dispatch manually and pay for it in
boilerplate and lost type-safety.

### NIC: `NicOps` → `trait Nic`

`NicOps` (`//crates/drivers/nic/src/api.rs`) is a POD of bare `fn` pointers with
no `&self`, so every caller re-implements the "if `Some` call else fall back"
dance and all driver state lives in module statics + `AtomicPtr` games. Make it
`trait Nic: Sync` held as `&'static dyn Nic`: mandatory methods stop being
`Option`, optional capabilities get default impls (`fn tso(&self) -> bool {
false }`), and drivers hang state on `&self`. As leaf as the current struct
crate, so the "drivers don't inherit the net stack" property is preserved.

Two riders:
- **RX callback `fn(Chain) → &mut dyn FnMut(Chain)`.** The internal driver loops
  are *already* generic (`poll_qp_inner<F: FnMut>`); only the trait erases to
  bare `fn`, which forces the consumer through `cpu_id()` + thread-locals and
  forces the two near-identical RX trampolines (`net_receive`/`distribute_frame`).
  Honor the multi-buffer chain contract here (RSC).
- **Checksum capability.** The `send()`-side L4-checksum contract was *already*
  unified (tx-path-optimizations.md, 2026-05-19: guest stamps the
  pseudo-header-partial, the driver finishes it; `NicOps::csum_tx_offload` and
  `net_l4_tx` were deleted). The residual is that gve finishes the checksum
  *only* via hardware offload — it has no software-fallback pass — relying on the
  unstated assumption that gVNIC always offloads. Make that assumption explicit
  (a `tx_csum()` capability or a documented "driver always finishes it"
  invariant). Not unsound today; just undocumented.

- **Status**: [ ] not started. **Where**: `drivers/nic`, `drivers/gve`,
  `drivers/virtio-net`. **Win**: deletes the `Option<fn>` unwrapping at every
  call + the null-object `NULL_OPS`; gives drivers a home for state. **Effort**:
  medium. **Risk**: medium (touches every driver). **Coordinate**: rx item K
  reshapes the same RX surface; the iobuf type already fixed the buffer type
  (cite iobuf-type-model.md). The TX-submit-surface collapse is a separate TX
  decision — see below.

> The TX submit surface (`submit_tx` / `submit_tx_tso` / `submit_tx_udp_gso` +
> three `#[repr(transparent)]` handle types) is wide, but the three distinct
> handles are a **deliberate compile-time safety decision** — they make a
> pool/descriptor mismatch a type error, replacing a prior runtime pool-ID check
> (api.rs rationale). Collapsing them to one `submit_tx(handle, len, &TxMeta)`
> is a real ergonomic option, but it **trades away that guarantee** and must
> preserve it another way (e.g. a `PoolClass` phantom on one handle). This is a
> TX-cost/ergonomics decision and belongs to
> [`tx-path-optimizations.md`](tx-path-optimizations.md) (items B, G, and item R
> "UDP GSO on DQO"). **Note: UDP-GSO is not dead code** — it ships on GQI and is
> a planned DQO extension (tx item R); the QUIC reactor simply does not route
> through it yet (it sends per-datagram via `submit_tx`).

### Reactor: `TcpBackend` / `UdpBackend` → traits with an associated `Conn`

`TcpBackend` (18 fn-pointer fields, 5 `Option`) and `UdpBackend` are the same
pathology one layer up. Converting to `&'static dyn` traits gives
compiler-checked completeness and default methods for the optional hooks — and,
crucially, an **associated `Conn` type** that kills the `*mut () + u16
generation` handle pattern. That generation check is currently duplicated ~15
times across the TCP hooks, with subtly different "stale ⇒ closed" semantics per
hook; an associated `Conn` (a generational `Key { core, slot, gen }`) plus one
`resolve(key) -> Option<&mut ConnState>` centralizes it and closes the public
`from_raw` handle-minting hole.

- **Status**: [ ] not started. **Where**: `runtime/executor/src/reactor`,
  `net/tcp`, `net/src` udp, the native backend. **Win**: one decode+generation
  gate instead of 15; removes `*mut()`/`PhantomData<*mut()>` plumbing from the
  future types. **Effort**: medium. **Risk**: medium.
  **Coordinate**: the per-accept `Box::pin` site is named in the graceful-OOM
  gap list in high-concurrency-perf.md (item 1, the `try_box_pin` fix) —
  don't reintroduce a non-graceful `Box::pin` when restructuring the spawn path.
  The generation-mismatch wasted-poll is Stage-2 fuel (its §"Stage 2 — overload"); collapsing
  it is structurally good, but its *saturation* effect is high-conc's to measure.

---

## Backpressure — one `SendProgress` contract

TCP's `async_try_send_chain` returns `Result<usize, TcpSendError>` where `Ok(0)`
overloads three meanings (window closed / cwnd-or-inflight full / drained zero of
a zero-length chain) and can't tell a higher layer *why* it blocked. `UdpSocket::
send_to` simply swallows TX-full errors. Unify on one explicit type across TCP
and UDP so QUIC's congestion controller can observe it:

```rust
enum SendProgress { Drained(NonZeroUsize), WouldBlock(BlockReason), Closed }
enum BlockReason { ReceiveWindow, Congestion, TxQueueFull }
```

This is the one place TCP internals (cwnd vs rwnd) are deliberately hidden but a
higher layer has a legitimate need for a coarse hint.

- **Status**: [ ] not started. **Where**: `net/tcp/src/send.rs`,
  `runtime/executor/src/reactor`, udp `send_to`. **Win**: unambiguous
  backpressure; QUIC CC signal; the zero-length edge stops masquerading as
  backpressure. **Effort**: low–medium. **Risk**: medium.

> ⚠️ **Regression hazard to preserve.** A TCP receive-window-update deadlock on
> large uploads over the streaming `recv_chunk` path was fixed in `ce562ff`: the
> zero-copy stash path in `do_recv_chunk` (`pending_chunk.take()`) skipped the
> `maybe_send_window_update` that the ring-drain path runs via `rx_pop`, so once
> the ring filled the window stayed 0 and a parked `recv_chunk` consumer never
> re-woke. The fix re-advertises the window and re-fires the recv waker on **any**
> inbound segment for an Established conn (so the peer's persist probe becomes the
> recovery kick). Any work that touches `do_recv_chunk`/`rx_pop` (this backpressure
> change, or the recv collapse below) must **preserve** that recovery — don't
> regress the window-update-and-waker-refire-on-any-segment behavior.

---

## Transport reliability — one congestion-control / loss-recovery / pacing core

The three contracts above converge the **data plane** (buffers, streams,
handlers). Congestion control, loss recovery, and pacing are a separate
**transport-reliability plane** — and they are about to be built twice unless the
share is planned now. State today:

- **TCP** has a working RFC 5681 controller (slow start, AIMD, fast retransmit,
  RTO) plus RFC 3465 ABC, and it now **delegates to the shared `net_cc::Controller`**
  (`cc: net_cc::Controller` set in `congestion_init`; `cwnd_on_ack` drives
  `cc.on_ack` in `net/tcp/src/state.rs`).
- **QUIC** has the RFC 9002 **loss detector** (packet-threshold + `9/8·RTT`
  time-threshold — i.e. RACK), the RTT estimator, and the PTO timer
  (`proto/quic/src/conn/loss.rs`), **plus a wired `net_cc::NewReno` congestion
  controller** — `on_ack`/`on_loss`/`on_rto` drive `cwnd`, and the cwnd gate is
  enforced on the send path (`conn/tx.rs`, `conn/loss.rs`). It also re-queues
  lost STREAM frames for retransmission and runs a timer-driven token-bucket
  pacer. See [`quic-golden.md`](quic-golden.md) +
  [`tx-backpressure.md`](tx-backpressure.md) for the landed detail.
- The CC code now lives in the **shared `net_cc` crate**, and **both transports
  delegate to `net_cc::Controller`** today — the extraction is done.

Three of the [`tcp-backlog.md`](tcp-backlog.md)
Linux-parity items (L1 BBR, L3 pacing, L4 RACK-TLP) are the TCP half of
remaining performance work (CUBIC has landed).

### What converges (build once, drive from both)

- **The congestion controller (the big one).** RFC 9002's recommended QUIC CC is
  NewReno — the same slow-start + AIMD + recovery math as TCP Reno; CUBIC and BBR
  are transport-agnostic window algorithms. Extract a `congestion` module with a
  controller trait both transports drive:

  ```rust
  trait CongestionControl {
      fn on_ack(&mut self, bytes_acked: u32, in_flight: u32, rtt: Rtt);
      fn on_loss(&mut self, bytes_lost: u32, persistent: bool);
      fn on_rto(&mut self);          // TCP RTO / QUIC PTO-confirmed loss
      fn window(&self) -> u32;       // cwnd, in bytes
      fn pacing_rate(&self) -> u64;  // bytes/s, for the shared pacer
  }
  ```
  Reno/CUBIC/BBR are then written once. `TcpConnection` keeps `cwnd`/`ssthresh`
  delegated to the trait; QUIC's `Connection` gets its first controller for free.
  This is the seam the roadmap's "lift `tcp` above `executor` → swap in custom
  congestion control" anticipates.

- **The pacer (L3).** Both want pacing (QUIC's spec effectively requires it,
  RFC 9002 §7.7; TCP needs it before any initial-window raise — see the IW
  trade-off). QUIC already has a timer-driven token-bucket pacer at
  `cc.pacing_rate()` (`conn/tx.rs`; see [`quic-golden.md`](quic-golden.md)); the
  remaining work is **extracting it** so one shared pacer driven by
  `pacing_rate()` serves both send paths.

- **Loss detection — the arrow runs QUIC → TCP.** QUIC's `detect_loss`
  (packet/time-threshold) is already a working RACK; TCP's L4 (RACK-TLP) is the
  same algorithm family. TCP can't share the *code* directly (it tracks byte
  ranges and needs a SACK scoreboard first — L4 depends on SACK/T7), but it
  should borrow QUIC's design rather than reinvent it.

- **The `SendProgress` / `BlockReason::Congestion` signal** (backpressure section
  above) is already specified "so QUIC's congestion controller can observe it" —
  the one place a higher layer legitimately sees CC state. Build it as part of
  this.

### What does NOT converge (don't force it)

- **ABC (RFC 3465)** — a TCP-specific fix for *ACK-counting* under delayed ACKs.
  QUIC CC increases the window by *bytes acknowledged* by construction
  (RFC 9002 §7.3.1) — byte-counting by design, it never had the bug. The ABC win
  is TCP-only; nothing ports.
- **Receive-window / buffer autotuning (L5)** vs QUIC **flow control**
  (`MAX_DATA` / `MAX_STREAM_DATA`) — different mechanisms; keep them separate.
- **RTT estimators** — TCP (RFC 6298) and QUIC (RFC 9002, with `ack_delay` /
  `min_rtt`) differ enough that sharing is low-value; leave them per-transport.

### Sequencing implication

Both stacks now delegate to the shared `net_cc::NewReno` (QUIC closed RFC 9002
step 5; TCP's hand-rolled RFC 5681 cwnd was replaced 2026-06-08, netem + GCE
validated). **Do the remaining CC work as one shared module, not twice** — the
controller core and trait already exist in `net_cc`; what remains is
BBR (CUBIC done, Reno default until a netem A/B flips it) + a TCP-side pacer
(QUIC's RFC 9002 token-bucket pacer landed 2026-06). Gate the L1
work behind the `SendProgress` contract (so the CC has a clean backpressure
signal) and, for the L4 half, behind SACK (T7).

- **Status**: [~] foundation landed. The shared module exists —
  [`crates/net/cc`](../crates/net/cc) has the `CongestionControl` trait (this
  exact signature) + a `NewReno` controller + unit tests; see
  [`tx-backpressure.md`](tx-backpressure.md) (stage 1) for how it fits the
  end-to-end backpressure chain. **Done since**: `net/tcp/src/state.rs` delegates its
  `cwnd`/`ssthresh` to it (`congestion_init`, 2026-06-08) and
  `proto/quic/src/conn` adopted it + the RFC 9002 pacer. **Pending**: BBR
  (CUBIC done, Reno default until a netem A/B flips it) + a TCP-side pacer.
  **Win**: BBR + pacing written once; QUIC gets its first controller; the
  L1/L3 Linux-parity gap closes for both transports together. **Effort**:
  large (the wiring; the controller core is done). **Risk**: medium — CC is
  subtle; keep the existing TCP controller's `tcp_test` scenarios
  (`cwnd_on_ack` / RTO collapse / fast retransmit / slow-start ABC) green
  through the extraction.

---

## The golden-path doctrine

Each kept alternative should be a *thin variation on the golden path* that shares
its core — not a parallel implementation. The golden path is Stack A's shape; the
diminished alternatives are mostly hardware-forced.

| Layer | Golden path | Kept alternatives (cheap because…) |
|---|---|---|
| NIC RX | zero-copy `wrap_owned` device buffer | GQI copy-to-slab (HW forces in-order repost; already shares `pool.rs`) |
| NIC TX | direct-fill `TxBufHandle` | DQO bounce-copy slice send (HW stall forced it — note: DQO is the *preferred* c3+ backend yet runs the slowest TX; track in tx doc) |
| per-driver code | shared TX-pool module (token codec + slot allocator) | gqi/dqo/virtio as thin per-format shims (see the shared-`TaggedTreiberStack` follow-up in rx-path-optimizations.md) |
| TCP recv | `recv_chunk` (zero-copy) | `recv`/`recv_exact` as a copy adapter on the guard |
| reactor I/O | `recv_chunk` + `send(chain)` | `send_bytes` (slice), `try_send_tso` (specialist) |
| TLS TX | TSO encrypt-in-slot | scratch-buffer fallback (shares the `seal_chain` core) |
| QUIC TX | `IOBufChain` → encode-in-place into TX slot | `Heap` datagram fallback |
| HTTP | stream through `BodyReader` over `impl ByteStream` | — (h3 joins the golden path) |

### Collapse recv/recv_chunk — but engage the landed design

`recv` and `recv_chunk` share one waker slot and one `has_data` probe and differ
only in a `chunk_wanted` bit. The cleanest end state is one primitive
(`recv_chunk`), with `recv(buf)` expressed as a copy adapter on the guard. **But
this engages a landed decision, not a clean slate** (rx item F): the doc states
the shared recv-waker is safe *because* "a conn never has both a recv and a
recv_chunk future parked at once," and the ring-drain copy path is "never
deprecatable." So the recommendation is narrower than "delete one":

1. The shared-waker invariant is documented but **unenforced** — `select`
   cancellation can leave a stale waker because `TcpRecv`/`TcpSendChain` lack the
   `Drop`-clears-waker that `RecvChunk` has. Add those `Drop` impls (cancel-safety
   parity) so the invariant is structural, not by-convention.
2. Keep the ring-drain fallback (it's load-bearing for the non-stash case); make
   it the body of the copy adapter rather than a separate parked future.

This removes the `chunk_wanted` gating and the dual delivery branches without
claiming the ring path is removable.

- **Status**: [ ] not started. **Where**: `net/tcp/src/{receive,listener}.rs`,
  `runtime/executor/src/reactor/tcp.rs`. **Risk**: medium — must preserve the
  `ce562ff` window-update/waker-refire recovery (see the regression hazard above).
  **Defer**: the saturation effect to high-conc; the ring-necessity argument to
  rx item F.

---

## Simplification / dead-code (Phase 0)

Genuinely-dead, deletable now, zero behavior change. This **derisks** every
contract change above by shrinking the surface they touch.

- **Dead iobuf API** (listed under contract 1) → owned by
  [`iobuf-type-model.md`](iobuf-type-model.md).
- **`NicError`** — never returned on the data path; backpressure is encoded as
  `Option::None`/silent drop. Reduce to what's actually used.
- **Dead TLS scaffolding** — `State::Failed` (never assigned), the `error` field
  (never read), `HandshakeError::AeadFailed` (never constructed).
- **`replay.rs` 48 KiB static** is dead weight on TLS-over-TCP builds (only the
  QUIC 0-RTT path uses it). Relocate to `proto/quic` or feature-gate. *(Net-new;
  not owned by a cost tracker.)*

**Not dead, do not delete:**
- **UDP-GSO** — shipped on GQI, planned for DQO (tx item R). It is unreachable
  *from the current QUIC TX path*, which is a routing gap, not dead code.
- **`prepend_in_place`** — used by TLS/H3 small-header prepend; see contract 1.

**Stale docs (correctness of the map, not code):** `body.rs` calls the HTTPS read
buffer `Borrowed` (it's `Owned(Shared)`/`Owned(Heap)`); `worker/timer.rs`
references a `PendingTimers` MPSC + intrusive free-list that don't exist; MEMORY
said ChaCha (it's **AES-128-GCM** — corrected). Fix these at the source.
**Note:** the rx/tx trackers *intentionally* keep historical Bazel labels stale
(rx doc lines 3-8) — do **not** "normalize" labels in those docs. This doc uses
current `//crates/...` paths.

---

## Recommended sequencing

The contracts you can least afford to churn later — the **buffer currency** and
the **stream trait** — lock in first. Perf convergence and vtable→trait
ergonomics follow. Each phase routes its cost-bearing items to the owning doc.

1. **Phase 0 — Deletion.** The dead-code list above. Pure win; derisks the rest.
2. **Phase 1 — Lock the stream contract (net-new, this doc).** `net_io` with
   `ByteStream` + `ReadChunk`; move `HttpStream` onto it; add `QuicStream`
   (initially over today's copying recv — correctness first); unify the handler
   API on `&Request`; delete `NullStream`. *The lock-in you can't easily redo.*
3. **Phase 2 — Unify the buffer currency.** `Chain`/`Cursor` for QUIC `SendStream`
   and TLS plaintext (this doc); the `prepend_in_place` L2–L4 decision → tx doc.
4. **Phase 3 — Close the copy gap.** Owned UDP delivery → refcounted QUIC RX
   (**rx item L**); h3 streams via `BodyReader` (**rx HTTP/3-streaming follow-up**);
   SG-TX for the remaining TCP rtx copies (**tx item B**). *Stack B becomes as
   fast as Stack A.* Measure the per-conn heap slope in **high-conc** (H2/H3/H4 +
   ceiling-movers).
5. **Phase 4 — Vtables → traits + backpressure (net-new, this doc).** `NicOps →
   trait Nic` (+ `FnMut` RX callback); `TcpBackend`/`UdpBackend` → traits with
   associated `Conn`; the `SendProgress` enum across TCP+UDP.
6. **Phase 5 — Shared congestion core (net-new, this doc + the L1/L3/L4 backlog
   items).** Extract `CongestionControl` + the pacer; delegate `TcpConnection` to
   it; give QUIC its first controller through it (closes RFC 9002 step 5). Gated
   on Phase 4's `SendProgress` signal, and (for the L4 loss-detection half) on
   SACK/T7. *The BBR + pacing work, built once for both transports (CUBIC done).*

Phases 1–2 are the "right API" work; 3 is the perf payoff (owned by the cost
docs); 0 and 4 are cleanup/ergonomics; 5 is the transport-reliability convergence
(its own section above). This sequence's own phase numbers are local to this doc;
where it reuses an existing tracker item it names the item.

---

## Correctness-adjacent findings (cite/defer, not owned here)

- **QUIC frame retransmit** — **landed.** `detect_loss` re-queues a lost
  packet's STREAM frames into `retx_queue` (`conn/loss.rs`), drained before fresh
  data, and the behavior is regression-tested; see
  [`quic-golden.md`](quic-golden.md). CRYPTO/handshake retx is still PTO-PING-only
  (a follow-up → [`conformance-roadmap.md`](conformance-roadmap.md)). Any
  `SendStream` redesign (contract 1) must preserve the replay-from-offset path.
- **h3 content-length policy** — see contract 3.
- **TCP receive-window-update deadlock** on streamed uploads — **fixed in
  `ce562ff`**; preserve the recovery (see the regression hazard in the
  backpressure section).
- **Congestion-control parity with Linux** — RFC 7323 window scaling,
  RFC 3465 ABC, CUBIC (`net_cc::Cubic`), and TLP (`send_tlp_probe`) have
  **shipped** (the 64 KiB/RTT cap and the delayed-ACK
  slow-start penalty are gone); what remains is BBR, pacing, and the SACK-based
  RACK half, which should be built as the **shared TCP+QUIC congestion core**
  above → [`tcp-backlog.md`](tcp-backlog.md) (L1–L5).

## Explicitly out of scope (defer to siblings)

- All per-byte RX/TX memcpy reduction, HW GRO/RSC, TSO/UDP-GSO, SG-TX mechanism,
  conn-state/conn-future pools → rx/tx path docs.
- Per-conn heap slope, the cliff, OOM tolerance, load shedding → high-conc.
  (Note: the `TcpConnection` hot/cold split was **tested and rejected** —
  3-19% worse; don't re-propose layout splits. Working-set-blowup as the cliff
  cause was **falsified** — frame buffer-currency changes as heap-ceiling movers,
  not cliff-position movers.)
- The iobuf `Send` type model → iobuf-type-model.
- RFC conformance → the conformance docs.
