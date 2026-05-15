# RX path optimizations — tracker

A living plan for trimming the RX path between NIC RX and the
application handler. Covers TCP, HTTPS-over-TCP (TLS 1.3), and
HTTP/3 (QUIC) where applicable. Each item below is sized to land
as one (or a small batch of) commit(s); check items off as we
ship them.

Phase 1 of this work — streaming request body via `BodyReader`
— landed 2026-05-15 (commit `820a2e6`) and is documented at the
top of the progress log. This doc covers Phase 2 (IOBuf-based
zero-copy RX) and Phase 3 (multi-buf RX delivery + enable HW GRO)
which are bundled because the IOBufChain plumbing Phase 2
establishes is what makes Phase 3 safe.

**Target location in repo**: `docs/rx-path-optimizations.md`
(analogous to `docs/tx-path-optimizations.md`).

## Why this doc exists

The RX-path audit measured **2 memcpys per byte on the fast path**
(parked-recv) and **up to 6 memcpys per byte on the slow + cross-
core path** for HTTP body bytes:

1. Driver → callback (DMA-fed buffer, no copy at the boundary).
2. Cross-core dispatch: frame bytes copied into per-core
   `RxInbox.pool[i].data: [u8; 1514]`.
3. TCP slow path: bytes copied into per-conn `Box<[u8; 16384]>` ring.
4. TCP recv drain: bytes copied from ring into user buffer.
5. HTTP serve_conn: parse-buf to BodyReader prebuf.
6. BodyReader refill: stream.recv copies into 4 KiB internal scratch.

Phase 1 collapsed #6's logical equivalent (the parse-buf →
`Request.body` copy) by replacing the inline body buffer with
streaming. Bench: +9% on `upload_32k_tcp` 1c. This plan attacks
the remaining copies through the boundary between layers, using
`IOBuf`'s `ExternalOwned(buf_id, drop_fn)` variant for auto-repost
RAII semantics on DQO/virtio, and a recycle pool at the driver
boundary for GQI (where in-order repost forbids holding device
bufs past the callback).

## Current path — TCP (HTTP)

| # | Step | Site | Cost per byte | Notes |
|---|------|------|---|---|
| 1 | Device DMA → driver buf | gVNIC DQO / virtio-net / gVNIC GQI | 0 | DMA into per-driver pool buffer |
| 2 | Driver callback | [`uni-net/src/driver.rs`](uni-net/src/driver.rs), `NicOps::poll_qp` | 0 | Slice into device buf for callback duration |
| 3 | Cross-core inbox push | [`kernel/src/percpu.rs:115`](kernel/src/percpu.rs#L115) | **1× memcpy** (only multi-core path) | Copies frame into `RxPacket.data: [u8; 1514]` |
| 4 | TCP fast path (parked recv) | [`net/src/tcp.rs:331`](net/src/tcp.rs#L331) | **1× memcpy** | `ptr::copy_nonoverlapping` directly into user buf |
| 4'| TCP slow path (no parked recv) | [`net/src/tcp.rs:303`](net/src/tcp.rs#L303) | **1× memcpy** (into ring) + **1× memcpy** (out at recv) | Per-conn 16 KiB byte ring |
| 5 | HTTP parse-buf refill | [`uni-http/src/lib.rs`](uni-http/src/lib.rs) `serve_conn` | 0 (Phase 1: bytes flow through stream.recv into parse buf — same memcpy as step 4) | Headers + body prebuf land here |
| 6 | BodyReader::chunk past prebuf | [`uni-http/src/lib.rs`](uni-http/src/lib.rs) | **1× memcpy** | Into 4 KiB `refill` scratch via `stream.recv` |
| 7 | Handler reads body | app handler | 0 | Borrowed `&[u8]` (Phase 1) |

Active per-byte memcpys on **TCP RX** guest side: **2** for body
bytes past the prebuf on the fast path (one TCP-fast-path copy +
one BodyReader refill); **2 + 2 = 4** on the slow path (ring in,
ring out, prebuf, refill). Down from 5–6 before Phase 1.

## Current path — TCP (HTTPS / TLS 1.3)

| # | Step | Site | Cost per byte | Notes |
|---|------|------|---|---|
| 1–4 | Same as TCP HTTP | (above) | 1–2 | Ciphertext bytes flow through |
| 5 | TLS pump_rx into cipher_buf | [`uni-tls/src/lib.rs:501`](uni-tls/src/lib.rs#L501) | 0 (in-place pump from TcpStream::recv) | 8 KiB inline cipher_buf |
| 6 | AEAD decrypt | TLS state machine | **1× R/W** (ChaCha20) + **1× R** (Poly1305 verify) | Plaintext lands in `pt_buf` (17 KiB after Phase 1's bump) |
| 7 | TlsStream::recv pops plaintext | [`uni-tls/src/lib.rs:580`](uni-tls/src/lib.rs#L580) | **1× memcpy** | pt_buf → user buf |
| 8 | HTTP / BodyReader same as TCP | | 1× memcpy | refill |

Active per-byte memcpys on **TLS RX** guest side: **2** + the
fundamental AEAD R/W. AEAD is unremovable without offloading
crypto to a co-processor; the two structural memcpys (pt_buf→user
and BodyReader refill) are the target.

## Current path — QUIC / HTTP/3

| # | Step | Site | Cost per byte | Notes |
|---|------|------|---|---|
| 1 | UDP datagram delivered | virtio/gVNIC | 0–1 | Same driver path as TCP |
| 2 | QUIC AEAD open | uni-quic | 1× R/W | Plaintext into datagram-local scratch |
| 3 | H3 DATA frame accumulate | [`uni-http3/src/server.rs:528`](uni-http3/src/server.rs#L528) | **1× memcpy per frame** into `data: Vec<u8>` | Whole body buffered before handler invoked |
| 4 | BodyReader from buffered slice | uni-http (Phase 1) | 0 | Borrowed view of the accumulated Vec |

QUIC's body-buffering is out of scope for this plan (would OOM on
a 100 MB POST). See item L for the follow-on plan.

## Items

### A. `IOBuf::into_owned()` + `IOBufPool` infrastructure
- **Status**: [ ]
- **Where**: [`uni-iobuf/src/lib.rs`](uni-iobuf/src/lib.rs);
  possibly new [`uni-iobuf/src/pool.rs`](uni-iobuf/src/pool.rs).
- **What**:
  * `IOBuf::into_owned(self) -> IOBuf`: no-op for Heap / Shared /
    Static / ExternalOwned; copies-to-Heap for Borrowed. The
    escape hatch for "I have a Borrowed view but want Send-able
    ownership."
  * `IOBufPool`: fixed-size set of heap slabs (sized for one
    MTU + header reserves, ~1.6 KiB each). `alloc() -> Option<IOBuf>`
    returns an ExternalOwned IOBuf with drop_fn returning the slab
    to the pool free list. Free-list is a **tagged-pointer Treiber
    stack** (`AtomicU64` packing `(slot_index, version_tag)`,
    version increments on push to defeat ABA). Drop_fn is
    panic-safe (logs + leaks slab on impossible push failure,
    never panics).
- **Win**: enables A.1 (no perf win on its own; infrastructure).
- **Effort**: medium. ~250 LOC + unit tests.
- **Risk**: low. Pure additions, no behavior change. Treiber stack
  is well-trodden ground; unit-test concurrent push/pop under
  loom or std-test multi-thread.
- **Tests**: pool lifecycle round-trip (alloc N, drop in scrambled
  order, verify free count returns to initial); `into_owned()`
  correctness (Borrowed → Heap content identity).

### B. NicOps RX callback delivers `IOBufChain`
- **Status**: [ ]
- **Where**:
  * [`uni-net/src/driver.rs`](uni-net/src/driver.rs) — `NicOps`
    struct (change `poll_qp: fn(usize, fn(&[u8])) -> usize` to
    `fn(usize, fn(IOBufChain)) -> usize`; same for `poll_rx`).
  * [`uni-driver-gve/src/dqo.rs`](uni-driver-gve/src/dqo.rs) —
    wrap device buf as `ExternalOwned(buf_id)` via
    [`IOBuf::wrap_owned`](uni-iobuf/src/lib.rs#L483); drop_fn
    reposts buf_id to the data ring (atomic `fill_cnt.Release` +
    BAR2 doorbell). Remove the current explicit repost code path
    (now in drop_fn).
  * [`uni-driver-gve/src/gqi.rs`](uni-driver-gve/src/gqi.rs) —
    maintain per-qp `IOBufPool`; per frame: alloc slab → memcpy
    device bytes → wrap as ExternalOwned → repost device slot →
    deliver 1-part chain.
  * [`uni-driver-virtio-net/src/lib.rs`](uni-driver-virtio-net/src/lib.rs)
    — wrap descriptor buf as `ExternalOwned(desc_idx)`; drop_fn
    returns descriptor to avail ring.
  * [`net/src/lib.rs:411`](net/src/lib.rs#L411) — `distribute_frame`
    takes `IOBufChain`. Walk chain; parse each.
- **What**: change the driver↔net trait signature atomic across
  all three drivers + net dispatch. Drivers wrap their device
  bufs as 1-part chains (single-buf semantics preserved). Drop_fn
  must be **panic-safe** on every implementation.
- **Win**: zero direct perf delta. Sets up cross-core zero-copy
  (item C) and multi-buf RSC (item I).
- **Effort**: high (atomic across 5 files; the trait-signature
  change must hit driver + net layer together). ~400 LOC.
- **Risk**: medium. Cross-core repost safety: DQO uses atomic
  `fill_cnt.Release`; GQI uses lock-free pool from item A;
  virtio uses lock-free avail-ring push. **Driver-level commits
  are not exercised by `test_hvf`** — first real test is GCE.
- **Tests**: mock-driver test exercising drop_fn on a separate
  "core" (std-test multi-thread simulating cross-core drop);
  verify drop_fn fires with correct base+capacity; repost-counter
  advances.

### C. RxInbox holds `IOBufChain` (cross-core zero-copy)
- **Status**: [ ]
- **Where**: [`kernel/src/percpu.rs:55-137`](kernel/src/percpu.rs#L55-L137)
  — `RxPacket { len, data: [u8; 1514] }` replaced with
  `Option<IOBufChain>`.
- **What**: cross-core inbox push moves an IOBufChain into a
  slot instead of copying frame bytes. Pop takes the chain out
  and hands to `net_receive`. Bounded queue with drop-on-overflow
  (chain drops → IOBufs drop → auto-repost).
- **Win**: **-1 memcpy per byte** on the cross-core distribution
  path. Eliminates copy #3 from the path table. Most visible on
  multi-queue setups where flows get distributed off the core
  that received them.
- **Effort**: low. ~80 LOC. Storage shape changes; push/pop logic
  is moves not copies.
- **Risk**: low. `ExternalOwned` is `Send` (unsafe impl already
  in place at [uni-iobuf/src/lib.rs:338](uni-iobuf/src/lib.rs#L338));
  cross-core moves are sound.
- **Tests**: bounded-queue eviction (push N+1 chains, verify
  oldest's drop_fn fired).

### D. `tcp_receive` takes `IOBufChain`
- **Status**: [ ]
- **Where**: [`net/src/tcp.rs:1398`](net/src/tcp.rs#L1398) —
  signature change. Walk chain in body; for each part:
  * Fast path (parked recv): `ptr::copy_nonoverlapping` from part's
    `data()` into the registered user buf. Drop IOBuf.
  * Slow path: `rx_ring_push(part.data())`. Drop IOBuf.
- **What**: per-conn `rx_ring` stays `Box<[u8; 16384]>` — the
  1500-conn × 11-bufs/conn math forbids holding IOBufs in the
  ring. This commit is plumbing: same copy count, IOBuf-typed
  inputs instead of `&[u8]` inputs. No user-visible perf delta.
- **Win**: zero on its own. Enables items E + F.
- **Effort**: medium. ~120 LOC; touches TCP segment-processing
  path which is large.
- **Risk**: medium. TCP segment processing is intricate; easy to
  introduce subtle bugs. Test_hvf catches most via the existing
  HTTP/HTTPS round-trips.
- **Tests**: existing test_hvf must pass; **intermediate GCE
  bench checkpoint here** (expect ±0% on all workloads — the
  refactor must not regress before more changes pile on).

### E. Reject `Transfer-Encoding: chunked` with 400
- **Status**: [ ]
- **Where**: HTTP/1.1 parser in
  [`uni-http/src/lib.rs:810+`](uni-http/src/lib.rs#L810)
  (`parse_request_with_state`).
- **What**: header parser detects `Transfer-Encoding: chunked`
  and short-circuits to a 400 response + `Connection: close`.
  Today the parser silently treats body as length-0 then
  misinterprets body bytes as the next pipelined request's
  headers — a request-smuggling attack vector. This commit
  closes the smuggling hole. Chunked support proper is deferred
  to Phase 4 (HTTP parser refresh).
- **Win**: security-hardening. No perf delta.
- **Effort**: low. ~30 LOC.
- **Risk**: very low. Defensive, no shape change for clients
  that don't send chunked.
- **Tests**: unit test for the rejection path.

### F. `TcpStream::recv_chunk` API (guard-pattern)
- **Status**: [ ]
- **Where**:
  * [`uni-runtime/src/net/tcp.rs:122+`](uni-runtime/src/net/tcp.rs#L122)
    — new `TcpStream::recv_chunk(&mut self) -> impl Future<Output = Option<RecvChunkGuard<'_>>>`.
  * [`net/src/tcp.rs`](net/src/tcp.rs) — new backend hooks
    `set_chunk_buf_slot` / `register_chunk_waker` / `do_recv_chunk`;
    new per-`TcpConnection` field `pending_chunk: Option<IOBuf>`.
- **What**: new method alongside the existing fill-buf `recv`.
  Returns a `RecvChunkGuard<'a>` (borrows `&'a mut self`) wrapping
  the next IOBuf. Guard exposes `data() -> &[u8]` (in-place read)
  and `into_owned() -> IOBuf` (ownership transfer; zero copy for
  ExternalOwned, +1 memcpy for Borrowed-into-pt_buf).
  **The guard return type is critical** — bare `recv_chunk() -> Option<IOBuf>`
  would be borrow-unsafe on the TLS path (IOBuf has no lifetime
  parameter; pump_rx could overwrite pt_buf while a Borrowed
  IOBuf is held). Guard binds lifetime to `&mut self` so the
  compiler prevents the unsafe sequence.
  Stated invariant: at most 1 outstanding IOBuf per TcpStream.
- **Win**: enables item H (BodyReader::chunk returns guard) →
  -1 memcpy on body bytes past the prebuf on the fast path.
- **Effort**: medium. ~200 LOC across uni-runtime + net.
- **Risk**: medium. Guard-pattern lifetimes interact with the
  async-fn-in-trait machinery; expect HRTB pain similar to
  Phase 1.
- **Tests**: compile_fail test that holding two guards
  simultaneously doesn't compile; `into_owned()` round-trip
  preserves bytes.

### G. `TlsStream::recv_chunk`
- **Status**: [ ]
- **Where**: [`uni-tls/src/lib.rs:580`](uni-tls/src/lib.rs#L580) —
  new method alongside existing `recv`.
- **What**: returns a `RecvChunkGuard<'_>` wrapping a Borrowed
  IOBuf into `pt_buf` (already-decrypted plaintext from
  AEAD-open). Caller reads in place; advances `pt_pos` on guard
  drop. Plaintext memcpy from AEAD is unremovable (fundamental
  R/W of decrypt); this commit just exposes pt_buf's bytes
  without an extra pt_buf → user buf copy.
- **Win**: -1 memcpy per byte on the TLS RX path. Eliminates
  step 7 in the TLS path table.
- **Effort**: low. ~60 LOC.
- **Risk**: low. The guard lifetime prevents pump_rx from
  re-running pt_buf until the guard ends.

### H. `BodyReader::chunk` returns guard
- **Status**: [ ]
- **Where**: [`uni-http/src/lib.rs`](uni-http/src/lib.rs) `BodyReader`;
  [`apps/webserver/src/main.rs`](apps/webserver/src/main.rs) `/discard`
  handler update.
- **What**: change Phase 1's `BodyReader::chunk() -> &[u8]` to
  `BodyReader::chunk() -> Option<BodyChunkGuard<'_>>`. Guard
  exposes `data()` and `into_owned()`. Variants by source:
  * Prebuf bytes: guard wraps Borrowed IOBuf over the parse-buf
    slice. Default usage zero-copy; `into_owned()` materializes
    Heap for Send-able ownership.
  * Past-prebuf bytes: guard wraps whatever `stream.recv_chunk()`
    surfaced (ExternalOwned for DQO/virtio = zero copy on
    `into_owned`; Borrowed-into-pt_buf for TLS).
  Drop the 4 KiB `refill` scratch field on BodyReader (no longer
  needed).
  Update `/discard` handler to use `body.chunk().await ... data()`.
  For NullStream / HTTP/3: `recv_chunk` returns None; BodyReader
  serves from prebuf only (whole body already buffered).
- **Win**: **end-to-end zero copy for body bytes past prebuf on
  DQO/virtio**. For `upload_32k_tcp` 1c at 55 k req/s × 16 KiB of
  past-prebuf body = ~880 MB/s/core memcpy bandwidth eliminated.
- **Effort**: medium. ~150 LOC.
- **Risk**: low. Phase 1's BodyReader plumbing stays; just the
  return type changes.

### I. Multi-buf RX chain accumulation in DQO
- **Status**: [ ]
- **Where**: [`uni-driver-gve/src/dqo.rs:479`](uni-driver-gve/src/dqo.rs#L479)
  `poll_qp_inner`.
- **What**: build IOBufChain across non-EOP completions; emit
  chain on EOP. Stops dropping non-EOP fragments (the Phase-3
  root cause of the previous session's -99.9% regression on
  `upload_32k_tcp` with `enable_rsc=1`).
  New per-qp state: `pending_chain: Option<IOBufChain>` +
  `pending_chain_timestamp: u64`. Timeout (~100 ms) flushes a
  stuck pending chain by dropping it (auto-reposts all
  accumulated bufs, discards the in-flight packet). New counter
  `DQO_RX_PENDING_CHAIN_TIMEOUTS` for observability.
- **Win**: structural correctness for RSC. No perf delta with
  RSC still off.
- **Effort**: medium. ~80 LOC including timeout.
- **Risk**: medium. Multi-buf accumulation across poll batches
  is subtle; if a chain straddles `MAX_BATCH = 64`, the pending
  state must persist correctly.
- **Tests**: unit test that a chain held past the timeout
  deadline gets flushed correctly.

### J. Enable HW GRO (RSC) on DQO_RDA queues
- **Status**: [ ]
- **Where**: [`uni-driver-gve/src/lib.rs:1327`](uni-driver-gve/src/lib.rs#L1327)
  `build_create_rx_queue_cmd`: `cmd.set_byte(58, 1)` for DqoRda.
- **What**: the one-line flip that turns RSC on. Lives in this
  plan because items A–I make it safe (multi-buf delivery
  handled, IOBufs auto-repost, pending-chain timeout prevents
  stuck chains from pinning bufs).
- **Win**: per the bench memory note: RSC coalesces multiple
  same-flow MSS segments into super-segments, reducing
  per-packet overhead. Expected +10–30% on `upload_32k_tcp`.
- **Effort**: trivial. 1 line of code.
- **Risk**: low if I lands first; high if shipped standalone
  (the prior session's experience).
- **Tests**: GCE bench, before/after. `/stats` check:
  `dqo_rx_compl_skipped` may grow (chains now delivered, not
  skipped); pair with `RX_BUF_REPOST_COUNT` to verify every
  received frame's bufs repost.

## Recommended sequence

A → B → C → D → E → F → G → H → I → J

A is pure additions (infrastructure). B is the trait change that
forces all drivers + net dispatch to land atomically. C through
H build the IOBuf threading layer-by-layer; each is independently
buildable and testable atop the prior. E (chunked rejection)
slots anywhere after the parser stays touchable but is placed
between D and F to colocate with the HTTP-layer work. I sets up
the multi-buf delivery shape; J enables RSC on top.

## Test & regression-detection contract

### Per-commit local

- `bazel build //apps/webserver:webserver_qemu_x86_64`
- `bazel build //apps/webserver:webserver.elf --platforms=//bazel/platforms:aarch64_unikernel`
- `bazel test //apps/webserver:test_hvf`
- Per-item unit tests (see "Tests" sub-bullet on each item).

### Caveat

`test_hvf` does NOT exercise gve. Items B and I get their first
real test on GCE. Mock-driver unit tests from item B onward are
the partial mitigation.

### Bench regression-detection thresholds

| Workload | Phase-1 baseline (1c / 4c) | Tolerance |
|---|---|---|
| `get_tcp` | 197 k / 565 k | ±3% (control — must not regress) |
| `get_tls_fresh` | 4.7 k / 10.3 k | ±3% (control) |
| `upload_32k_tcp` | 51 k / 72 k | ±3% pre-H; +15–25% on 1c after H |
| `upload_32k_tls` | 47 k / 70 k | ±3% pre-H; +10–20% on 1c after H |

Protocol: 3 runs per workload per core count, take median.
Single-run > 3% deviation from baseline on a control workload
triggers "halt and investigate."

### Intermediate GCE bench checkpoints

- **After B** (NicOps signature change; GQI uses recycle pool):
  DQO bench (expect ±0% — pure refactor for DQO). GQI bench
  with `UNIKERNEL_GCE_MACHINE=n2-highcpu-8` (expect 5–15% RPS
  drop — the accepted GQI memcpy cost; > 20% triggers
  investigation).
- **After D** (`tcp_receive` takes IOBufChain): DQO bench
  (expect ±0% — heaviest upper-stack refactor; intermediate
  check catches regressions before more changes pile on).
- **After H** (zero-copy body path lands): full bench. Expected:
  `upload_32k_tcp` 1c climbs from ~51 k → ~62 k.
- **After I** (multi-buf chain handling, RSC still off): full
  bench. Expected ±0%. `/stats`: `dqo_rx_compl_skipped` stays
  at 0; `dqo_rx_pending_chain_timeouts` stays at 0.
- **After J** (RSC enabled): full bench. `upload_32k_*` should
  rise. Controls unchanged. `dqo_rx_compl_skipped` may grow
  (chains delivered, not skipped); `RX_BUF_REPOST_COUNT` per qp
  must match `rx_frames` (sanity check on cross-core drop_fn).

### Observability counters introduced

Exposed via `/stats`:
- `DQO_RX_PENDING_CHAIN_TIMEOUTS` (per qp; item I)
- `RX_INBOX_OVERFLOW_DROPS` (per core; item C)
- `RX_RING_FULL_BACKPRESSURE` (per conn / aggregated; item D)
- `GQI_RECYCLE_POOL_EXHAUSTED` (per qp; item B)
- `RX_BUF_REPOST_COUNT` (per qp; item B — pairs with
  `rx_frames` for cross-core drop_fn sanity)

## Scaling behavior — the design holds for

**Pipelining stream-to-stream (fanout / proxy)**: zero-copy.
Guard's `into_owned()` lets a proxy hold the inbound IOBuf
across `outbound.send.await`; the IOBuf drops after wire
transmit → auto-reposts. Backpressure propagates via the
per-conn ring fill → TCP window shrink → upstream slows. This
is the load-bearing reason we chose owned-IOBuf (via the guard
escape hatch) over a pure scoped-callback API.

**Large HTTP/TCP payloads** (e.g. 100 MB POST): works. DQO pool
of 512 bufs/qp cycles ~140× across a 100 MB body at 1460 B MSS.
Per-conn ring is the natural backpressure point.

**Large HTTPS payloads**: works. Each chunk is plaintext of one
TLS record (≤ 16 KiB); pt_buf holds at most one record;
"refuse to decrypt until pt_buf drained" is existing
backpressure. CPU-bound at ChaCha20-Poly1305 decrypt rate
(~2 GB/s).

## Out of scope / known limitations (Phase 4+)

- **Large HTTP/3 (QUIC) payloads**: uni-http3 reassembles all
  DATA frames before invoking the handler — OOMs on 100 MB
  QUIC POSTs. Fix is progressive DATA-frame delivery, mirroring
  the TCP/TLS path. Separate plan (see Follow-ups).
- **Streaming response bodies (large echo)**: `Response` is
  fully-buffered today. Echo-100-MB needs a streaming-source
  Response variant. Separate plan.
- **Streaming HTTP header parser**: a state-machine parser would
  shrink the per-conn parse buf from 16 KiB to ~256 B (saves
  ~22 MB/core at fanout_tcp's 1500 conn/core) AND eliminate the
  prebuf memcpy (the one remaining copy on the body path after
  this plan). Substantial parser rewrite; lives with the
  chunked-encoding support (item E rejects it; a real
  implementation goes in this Phase 4 work).
- **Per-conn `rx_ring` as IOBufs**: the math forbids it
  (1500 conn × 11 bufs/conn-of-window = 16 500 bufs/core vs the
  4 096-buf DQO pool across all qps). Stays `Box<[u8; 16384]>`.
- **TX path**: this plan is RX-only. Symmetric TX-side IOBuf
  threading is the natural follow-on.
- **Multi-buf RX for GQI**: in-order repost constraint forbids
  holding multi-buf views; recycle pool always materializes a
  single contiguous IOBuf. RSC isn't a GQI feature anyway.

## Pathological scenarios — how the design degrades

- **Many-proxy stall under symmetric upstream/downstream
  slowness**: pool depletion via held IOBufs in proxies; mitigated
  structurally by backpressure (TCP window shrinks before
  universal stall). Failure mode is packet drops + TCP retx
  (load-shed), not crash.
- **RSC chain with no EOP** (device error, dropped EOP fragment):
  per-qp pending-chain timeout (~100 ms; item I) flushes stuck
  chains.
- **Cross-core IOBuf drop**: ExternalOwned is `Send`. Drop_fn
  runs on consumer core; safe because DQO's data ring is atomic
  (Release ordering + per-write atomic doorbell), GQI's recycle
  pool uses a lock-free Treiber stack, virtio's avail ring is
  lock-free.
- **drop_fn panic**: each driver's drop_fn must be panic-safe.
  Log + leak on impossible failure, never panic.
- **HTTP smuggling via chunked encoding**: closed by item E.
- **Stuck worker (live-lock)**: bounded inbox drops bytes;
  degrades to TCP retx storm for affected flows, not full stall.
- **Slowloris-style partial headers**: parse-buf state
  accumulates but no IOBufs pinned; bounded by IDLE_TIMEOUT_US
  = 30 s.

## Follow-ups (post-this-plan)

### Near-term

- **`packet_buffer_size` 2048 → 4096**: DESCRIBE_DEVICE option
  id=10 advertises 4096; using it reduces RSC multi-buf events
  (more coalesces stay single-desc). Driver + buffer-pool sizing
  tweak; one commit.
- **Observability**: surface the new counters in
  `/stats`-style dashboards.
- **GCE IPv6 subnet enablement** so `get_tcp_v6` runs against
  the remote unikernel-webserver VM (currently HVF-only).

### Mid-term — Phase 4: HTTP parser refresh

- Streaming HTTP/1.1 header parser.
- Chunked transfer encoding + trailers (proper support; item E
  is just the security guard).
- Same security review covering both.

### Mid-term — Phase 5: TX-side zero-copy

- Symmetric outbound IOBufChain plumbing.
- `StreamingResponse` shape for large echo / proxy responses.

### Mid-term — HTTP/3 streaming body

- uni-http3 progressive DATA-frame delivery (unblocks 100 MB
  QUIC POST).

### TLS

- 0-RTT for TLS-over-TCP (server record-layer wiring).
- 0-RTT for QUIC (loadgen-side; server already supports).
- TLS resumption hot-path optimization.

### Bench TODO stubs (already registered)

`get_tls_fresh_0rtt`, `get_quic_fresh_0rtt`, `get_quic_fresh`,
`upload_32k_quic`, `get_tcp_pipeline`, `download_64k_tls_slow`,
`boot_cold` — in [`scripts/bench/cli.py`](scripts/bench/cli.py)
TODO section. `get_tcp_pipeline` is especially worth landing
as a validation probe for item J (ideal RSC shape).

### Operational

- Stuck-worker preemption / watchdog.
- Cross-core pool contention measurement (fall back to per-core
  pool partitions if Treiber stack becomes contended).

### Aspirational

- HTTP/2 support.
- WebSockets / long-lived streaming.

## Reuse rather than rebuild

Concrete utilities to lean on:
- [`IOBuf::wrap_owned`](uni-iobuf/src/lib.rs#L483) — exactly the
  constructor for ExternalOwned with drop_fn (NIC zero-copy RX
  is its documented canonical use case at
  [uni-iobuf/src/lib.rs:245-247](uni-iobuf/src/lib.rs#L245-L247)).
- [`IOBuf::borrow`](uni-iobuf/src/lib.rs#L538) for prebuf IOBufs +
  TLS pt_buf IOBufs; debug-mode `BorrowGuard` catches aliasing.
- [`IOBufChain`](uni-iobuf/src/lib.rs#L1295) — already
  smallvec-style (8 inline parts + lazy `VecDeque` overflow).
- [`ExternalOwned` is Send](uni-iobuf/src/lib.rs#L338) —
  cross-core inbox can move chains across workers.

## Progress log

### 2026-05-15 — Phase 1: streaming `BodyReader` ([x] **landed** — commit `820a2e6`)

Replaced `Request.body: [u8; 64K]` inline buffer with a streaming
reader. Handler signature changed to
`AsyncFn(&Request, &mut BodyReader<'_, S>) -> Response`, generic
over the stream type `S: HttpStream`. Added `NullStream` +
`BufferedBody` alias for HTTP/3 where the body is reassembled
before the handler runs.

Bench (Phase 1 baseline; subsequent items measure against this):

| Workload | 1c | 4c |
|---|---|---|
| `upload_32k_tcp` | **55 k** (was 51 k pre-Phase-1) | 71 k (client-bound) |
| `upload_32k_tls` | 47 k | 70 k |
| `get_tcp` | 197 k | 565 k |
| `get_tls_fresh` | 4.7 k | 10.3 k |

`upload_32k_tcp` 1c went +9%; the others stayed within run-to-run
noise (~2%). 4c numbers client-bound at `cli ≈ 5.5/8` cores.

Also discovered + fixed two latent uni-tls bugs that surfaced
when bench started doing TLS POSTs > 4 KiB: `RX_BUF_LEN` was 4 KiB
(too small for a 16 KiB TLS record), `PT_BUF_LEN` similarly.
Both bumped to 17 KiB (commits `5e6d59f`, `c357337`). `upload_32k_tls`
unblocked.
