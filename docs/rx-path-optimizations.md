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
- **Status**: [x] landed 2026-05-15 — commit `180e29c`
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
- **Status**: [x] landed 2026-05-16 — commit `103202d`
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

### C. RxInbox: intrusive-node cross-core inbox (zero-copy)
- **Status**: [x] landed 2026-05-17 — commits `dc5cc26` (virtio
  `rx_lock` prep), `35b4aff` (the `rx_inbox` data structure),
  `59121b4` (kernel + net wiring)
- **Where**: new [`kernel/src/rx_inbox.rs`](kernel/src/rx_inbox.rs)
  — generic `RxNode<T>` / `RxNodePool<T, N>` / `RxInbox`;
  [`kernel/src/percpu.rs`](kernel/src/percpu.rs) pins the payload
  (`RxChain = Chain<OwnedIOBuf>`) and the `static` node pool;
  `distribute_frame` / `net_drain_cb` in
  [`net/src/lib.rs`](net/src/lib.rs);
  [`uni-driver-virtio-net/src/lib.rs`](uni-driver-virtio-net/src/lib.rs)
  `rx_used_locked` (fix #1 below).
- **What**: the Tier 2 cross-core inbox stops copying frame bytes.
  `distribute_frame` *moves* the received `Chain<OwnedIOBuf>` into a
  pre-allocated `RxNode` and CAS-pushes the node onto the target
  core's lock-free intrusive MPSC inbox list; `net_drain_cb` swaps
  the list out, reverses it to arrival (FIFO) order, and runs
  `net_receive` per chain. **No drop-on-overflow policy** — the
  superseded first attempt's bounded ring tail-dropped fresh TCP
  ACKs and collapsed `download_64k`. One `RxNode` exists per slot
  in a fixed pool, and a frame in flight pins exactly one device RX
  buffer, so the inbox provably never needs more nodes than the RX
  queue has buffers (`RX_NODE_POOL_CAP` is sized ≥ that count). The
  pool free-list is a tagged-pointer Treiber stack, ABA-immune like
  `IOBufPool`.
  * **Fix #1 (virtio)** — a delivered chain now drops on a
    *non-polling* core, so `virtio_rx_repost` → `add_buf` races
    `poll_qp`'s `used()` on the shared descriptor free-list. Both
    are now serialised under `rx_lock`, via the encapsulated
    `rx_used_locked` helper (so an unlocked `used()` is not a
    reachable pattern in the RX path).
- **Win**: **-1 memcpy per byte** on the cross-core distribution
  path. Eliminates copy #3 from the path table. Per-core inbox
  shrinks from ~24 KB (`16 × [u8; 1514]`) to a single pointer.
- **Effort**: low–medium. ~330 LOC (`rx_inbox.rs` + wiring + the
  virtio race fix).
- **Risk**: low. The chain moves cross-core, not copies. The
  uni-iobuf type-model split landed first, so the inbox is typed
  `Chain<OwnedIOBuf>` — `Send` by derivation, no `unsafe impl Send`,
  no human-maintained "no `Borrowed` parts" invariant.
- **Node ownership** — kept in a kernel-side pool, *not* 1:1
  driver-side nodes. The 1:1 form (`sk_buff`-style: the node folded
  into per-buffer driver RX state, no pool) is the cleaner steady
  state but needs a `NicOps` RX-surface change across all three
  drivers, dead weight + untested for the two gve drivers (which
  always run Tier 1). Tracked as a planned redesign — see item K.
- **Tests**: [`kernel:rx_inbox_test`](../kernel/src/rx_inbox.rs) —
  host-native, two 8-thread stress tests modelled on `IOBufPool`'s:
  a pure tagged-free-list ABA hammer, and a 1-distributor /
  N-consumer distribute→drain run asserting per-inbox FIFO order +
  no node/payload leak.

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
- **Where**: [`uni-driver-gve/src/lib.rs:1401`](uni-driver-gve/src/lib.rs#L1401)
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

### K. Driver-delivered RX frame (fold the inbox node into the driver)
- **Status**: [ ]
- **Where**: the `NicOps` RX-callback surface
  ([`uni-net/src/driver.rs`](uni-net/src/driver.rs)); all three
  drivers; [`kernel/src/rx_inbox.rs`](kernel/src/rx_inbox.rs) — the
  `RxNodePool` free-list is deleted.
- **What**: item C's cross-core inbox node lives in a kernel-side
  pool *because the kernel cannot map a received `Chain` back to
  the driver's per-buffer RX state* — only the driver knows its
  buffer layout. The cleaner design (`sk_buff` / `mbuf` shape): the
  device RX buffer's owned-frame object carries the intrusive
  `next` link itself, and the driver delivers it up the RX path.
  Node-supply then *is* buffer-supply — the `RxNodePool` and its
  free-list vanish, and "the inbox provably never overflows" stops
  being a sizing argument and becomes a tautology (a frame on an
  inbox is a buffer not on the ring; there are only N buffers).
- **Win**: deletes the kernel node pool + free-list; the overflow
  proof becomes structural. No per-byte perf delta — item C
  already removed the cross-core memcpy.
- **Effort**: high. A `NicOps` RX-surface change atomic across all
  three drivers + net dispatch, plus folding the link into each
  driver's per-buffer RX state. Same blast radius as item B.
- **Risk**: medium. Re-touches all three driver RX paths; gve's
  first real test is GCE — so this item carries a **mandatory GCE
  checkpoint**, which is exactly why it was *not* bundled into item
  C (that session had no gve gate). The intrusive MPSC inbox +
  drain logic from item C is reused verbatim — only the node
  *storage* moves, so ~80% of `rx_inbox.rs` survives.
- **Tests**: `rx_inbox_test` (the inbox half is unchanged); GCE
  bench before/after on the kvm env (Tier 2 on real hardware).

## Recommended sequence

A → B → C → D → E → F → G → H → I → J. K is independent — it
supersedes item C's kernel node pool and can land any time after
C; it is sequenced last only because of its driver-wide blast
radius.

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
- ~~`RX_INBOX_OVERFLOW_DROPS`~~ — item C as landed has **no**
  overflow: the intrusive-node inbox is provably bounded by the RX
  buffer count, so there is no drop event to count.
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
- **Ring-size experiment**: `TX_RING_ENTRIES = 256` /
  `RX_RING_ENTRIES = 512` sit at the bottom of the
  MODIFY_RING-advertised envelope (`[256, 4096]` / `[512, 4096]`
  on c3-highcpu-8; logged at boot since commit `daad48b`). For
  workloads where the "DQO pool of 512 bufs/qp cycles ~140× across
  a 100 MB body" math above implies hot eviction, try
  `RX_RING_ENTRIES = 1024` to halve the cycle count. The
  bounds-assert added in `daad48b` is the guardrail so the runtime
  value can't drift out of range silently.
- **Observability**: surface the new counters in
  `/stats`-style dashboards.
- **GCE IPv6 subnet enablement** so `get_tcp_v6` runs against
  the remote unikernel-webserver VM (currently HVF-only).
- **Extract a shared `TaggedTreiberStack`**: `IOBufPool`
  ([`uni-iobuf/src/pool.rs`](../uni-iobuf/src/pool.rs)) and
  `RxNodePool` ([`kernel/src/rx_inbox.rs`](../kernel/src/rx_inbox.rs))
  each carry their own copy of the same tagged-pointer Treiber
  free-list (`AtomicU64` head packing `(index, version)`; the
  version bumps on push to defeat ABA). Lift the ~40-line stack
  core into a zero-dep `core`-only crate — à la `util/atomic_fn` —
  generic over the next-link accessor (a separate `[AtomicU32]`
  array for `IOBufPool`, an in-struct field for `RxNodePool`). One
  audited, stress-tested implementation instead of two. Needs the
  `tests_need_std` opt-in on the new crate so the dep-pulling
  `rust_test`s (`iobuf_test`, `rx_inbox_test`) still link under
  `-Cpanic=unwind`. Low urgency — a tagged Treiber stack is
  textbook and stable, and both copies are independently stressed.
- **Fuse the Tier-2 classify parse**: `classify_for_distribution`
  ([`net/src/lib.rs`](../net/src/lib.rs)) walks eth → IPv4 → L4
  ports purely to pick a target core, then discards the result;
  `net_receive_frame` then re-parses the eth + IPv4 headers from
  scratch (and `tcp_receive` / `udp_receive` re-cover the ports).
  Every Tier-2 frame thus has its L2/L3 headers parsed **twice** —
  the shadow cost of software distribution standing in for the
  hardware RSS that Tier 1 gets for free. Fix: parse once — carry a
  small `ParsedL3` value (ethertype, proto, src/dst `IpAddr`, L4
  offset) on the inbox node alongside the chain, so the receive
  path skips straight to `tcp_receive` / `udp_receive`. Eliminates
  one eth-parse + one IPv4-parse per Tier-2 frame; the TCP-header
  parse in `tcp_receive` stays — it needs seq/ack/flags/window, not
  just the ports `classify` previewed. `arp_learn` also fires in
  both `classify` and `net_receive_frame` (redundant for `Inline`
  frames) — fold that in at the same time.

### RX scheduler — unify the tier model

The Tier 1 / Tier 2 split is well-defined only at its endpoints;
the middle is frayed. "Tier 1 — each core polls its own queue" is
total **only on the diagonal `nqp == num_cores`**. Off it:

- `nqp < num_cores` — cores `>= nqp` poll nothing
  ([`net/src/lib.rs`](../net/src/lib.rs), `poll_tier1`'s
  `core >= nqp → return false`). That is a *degradation* (those
  cores fall back to compute-stealing), not a real handling.
- `nqp > num_cores` — queues `num_cores..nqp` are polled by
  nobody; an RSS-hashed flow landing there stalls. The boot-window
  "BSP polls every queue" special-case is evidence the code knows
  this edge exists, but it patches only the boot window.

Both the `core >= nqp` early-return and the boot-window hack are
symptoms: the code already treats `nqp == num_cores` as its real
domain. The cleanup, in two parts (one work item):

1. **Pin Tier 1 to the diagonal.** Driver bring-up requests
   exactly `num_cores` queue pairs (the HVF runner already sets
   `num_queue_pairs = cpu_count`); the tier predicate becomes
   `nqp == num_cores`, not `nqp > 1`. Tier 1 is then a precise
   contract — a core↔queue bijection, no software distribution,
   no unpolled queue.
2. **Per-queue cohort distribution** for the genuine off-diagonal
   (a NIC that cannot supply `num_cores` queues). Queue `q` is
   polled by the cohort `{c : c ≡ q (mod nqp)}`, with a per-queue
   rotating distributor (Tier 2's `RX_LOCK` + `JUST_DISTRIBUTED`
   fairness, replicated per queue). Tier 2 then *is* the
   `nqp == 1` case of this model, and `poll_tier1` / `poll_tier2`
   collapse into one function. Item C's cross-core inbox is the
   delivery mechanism unchanged — the cohort model only changes
   *who polls*, not how a frame crosses to its owner.

The taxonomy becomes three honest regimes — *bijection* (HW
distributes via RSS), *single queue* (SW distributes all, today's
Tier 2), *partial* (cohort: HW across `nqp` queues + SW the rest)
— instead of two tiers with ad-hoc edges.

**Dependency / caveat**: the cohort model routes every frame
through `classify_for_distribution`, whose owner verdict
(`flow_hash % num_cores`) must agree with the queue RSS chose, or
`nqp == num_cores` frames that are inline-and-free today start
crossing cores. So it is gated on **aligning the NIC's RSS key
with the software `flow_hash`** (queue `q` ⟺ core `q`). Worth
landing only once profiling shows real `nqp < num_cores`
deployments whose `nqp` polling cores bottleneck on `tcp_receive`.

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

### Test & bench infrastructure

Surfaced during item B's validation; deferred so they didn't
sprawl that session.

- **TCP conformance test harness.** `net_tcp` has no conformance
  suite — the receiver-side window-update bug (commit `171c68e`,
  found mid-item-B only because a QEMU upload anomaly got chased
  into a packet capture) is exhibit A for why that's a gap. Build
  an in-memory harness: a mock `NicOps` (the vtable is swappable
  via `set_active_ops()`) captures TX frames into a `Vec`, and
  `tcp_receive(src, dst, &[u8])` is already a `pub` RX entry point
  that takes crafted segments — so a test drives scripted packets
  in and asserts on captured output (packetdrill-in-a-unit-test).
  *Blocker:* `net_tcp`'s `os:none` dep chain (`kernel` /
  `uni-runtime`) must be made host-buildable — extend the
  `tests_need_std` mechanism in
  [`bazel/rules/rust.bzl`](bazel/rules/rust.bzl) (today only
  `util/atomic_fn` uses it) and `#[cfg]`-gate the genuinely
  bare-metal bits. First targets: a regression test for the
  window-update fix, and a real **RTO / retransmit timer** — the
  stack has none today (`net/src/tcp.rs` admits it in comments;
  a lost *outbound* segment is never retransmitted, a correctness
  gap on lossy paths, not just a perf one).

- **Tag-based bench workload matrix.** `scripts/bench/cli.py`'s
  `WORKLOADS` is hand-enumerated, but a workload is really a point
  in `shape × transport × ipver × size × concurrency`. Move to tag
  identity (`upload:1m:tls`) + a generator — but **sparse, not a
  dense product**: per-shape declared-valid dimensions (no
  `upload:quic` — no loadgen impl), v6 as a spot-check axis rather
  than a product axis, and keep the curated Δ-pairs that make the
  output readable. Port the existing registry as a
  no-behavior-change refactor first, then fill gaps.

### uni-iobuf type model — [x] landed 2026-05-16

`IOBuf` used to conflate borrowed (`!Send`) and owned (`Send`)
buffers in one `!Send` type, so every cross-core use needed a
manual `unsafe impl Send` plus a human-maintained "no `Borrowed`
parts" invariant. The split landed (commits `fb755a3`, `409b5dd`,
`d8b4c1e`): a `Send`-by-derivation `OwnedIOBuf`, born from
`wrap_owned` / `IOBufPool::alloc`, so the RX path is *typed*
`Chain<OwnedIOBuf>` rather than guarded by discipline; a one-way
`From<OwnedIOBuf> for IOBuf` widening at the app RX boundary; the
chain generic-ized as `Chain<B>`. Item C's `RxInbox<T: Send>`
inherits the `Send` guarantee by derivation, with no `unsafe impl
Send`. `into_owned` stayed item A's `IOBuf → IOBuf` (a cross-*time*
tool, not the cross-core gate). Full write-up:
[`uni-iobuf-type-model.md`](uni-iobuf-type-model.md).

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

### 2026-05-15 — Phase 2/3, item A: `IOBuf::into_owned` + `IOBufPool` ([x] **landed** — commit `180e29c`)

Pure-additions infrastructure step. Two additions to `uni-iobuf`:

- `IOBuf::into_owned(self) -> IOBuf` — zero-copy no-op for the four
  owning variants (`Heap` / `Shared` / `Static` / `ExternalOwned`);
  copies-to-`Heap` for `Borrowed`, the one non-owning variant. The
  ownership-transfer escape hatch the item-F / item-H guards'
  `into_owned()` will delegate to.
- `IOBufPool` — fixed-size MTU-slab pool ([`uni-iobuf/src/pool.rs`](uni-iobuf/src/pool.rs))
  with a lock-free tagged-pointer Treiber free list (`AtomicU64`
  head packing `(slot_index, version_tag)`; version bumps on push
  to defeat ABA; links in a dedicated `AtomicU32` array so they
  never alias slab payload). `alloc()` hands out an `ExternalOwned`
  IOBuf that recycles its slab on drop; the drop callback is
  panic-safe (leak + counter, never panic in a `#![no_std]` `Drop`).
  Consumed by item B's GQI recycle pool.

No perf delta expected or measured — no GCE bench for this item
per the plan (first checkpoint is after item B). Verified:
`bazel test //uni-iobuf:iobuf_test` (50 tests, +12 new, including
an 8-thread Treiber-stack ABA stress test), x86_64 + aarch64
unikernel builds, and `test_hvf`.

Next: item B (`NicOps` RX callback delivers `IOBufChain`) — a
larger atomic change across 5 files; tracked for its own session.

### 2026-05-16 — Phase 2/3, item B: `NicOps` RX callback delivers `IOBufChain` ([x] **landed** — commit `103202d`)

Atomic trait-signature change: `NicOps::poll_rx` / `poll_qp` now
deliver an owned `IOBufChain` per frame instead of a borrowed
`&[u8]`. The trait + all three NIC drivers + net dispatch landed in
one commit (`103202d`) — a signature change can't land
incrementally; the `/stats` counter wiring followed in `2579a13`.

- **DQO** wraps the device `buf_id` RX buffer as `ExternalOwned`;
  the `dqo_repost` drop callback reposts `buf_id` to the data ring
  (atomic `fill_cnt` + per-write BAR2 doorbell). The slice path's
  explicit inline repost is deleted.
- **GQI** can't lend device QPL pages (strict in-order repost), so
  it copies each frame into a slab from a per-qp `IOBufPool` (item
  A's pool), reposts the device page at the batch boundary, and
  delivers the slab — which recycles to the pool on drop.
- **virtio-net** wraps the descriptor buffer as `ExternalOwned`;
  the drop callback zeroes the virtio header and returns it to the
  avail ring.

Every drop callback is panic-safe — it runs from `IOBuf::drop`,
possibly cross-core, and leaks rather than panics on an impossible
bad queue index (a panic in a `no_std` `Drop` is poison). New
per-qp counters `RX_BUF_REPOST_COUNT` / `GQI_RECYCLE_POOL_EXHAUSTED`
surfaced via `/stats`.

Verified: x86_64 + aarch64 unikernel builds; `test_hvf` (exercises
the virtio-net repost path under the 30-conn TLS burst);
`iobuf_test` (new mock-driver test fires an `ExternalOwned` drop
callback from a separate thread, checking base/capacity + the
repost counter).

Perf — controlled pre-B (`ae14530`) vs post-B (`103202d`) benches,
identical hardware, 3 runs each so only the code differs.

**Local HVF (virtio-net), 1c** — the cleanest measurement:

| workload | pre-B | post-B | Δ |
|---|---|---|---|
| `get_tcp` | 194.3 k | 189.4 k | −2.6% |
| `get_tcp_single` | 37.4 k | 37.0 k | −1.2% |
| `get_tcp_fresh` | 26.6 k | 26.3 k | −1.2% |
| `get_tls_fresh` | 2994 | 2951 | −1.4% |
| `upload_32k_tcp` | 22.6 k | 22.1 k | −2.5% |
| `download_64k_tcp` | 8907 | 8654 | −2.8% |

Item B costs **~2 % on the virtio-net fast path** — a small,
*uniform* per-frame cost (`IOBuf::wrap_owned` + `IOBufChain::from`
+ chain walk + `ExternalOwned::drop`, once per received frame; the
uniformity across every workload is the signature of a fixed
per-frame cost). QEMU-TCG magnifies it to −5…−9 % on throughput
workloads — TCG translates every added guest instruction. This is
within the plan's ±3 % pre-H tolerance and is the expected shape of
"plumbing": items C and H *remove* memcpys and are budgeted to more
than recoup it. Item B is **not** perf-neutral — it is a small,
deliberate cost paid up front for the owned-chain architecture.

**GCE gve**, on-demand n2 / c3, pre-B vs post-B at 1/4/8 cores:

| path | `get_tcp` 1c/4c/8c | `get_tls_fresh` | `upload_32k_tcp` |
|---|---|---|---|
| DQO (c3 / `DQO_RDA`) | within ±2 % | −1.5 % | +0.4 % |
| GQI (n2 / `GQI_QPL`) | +1 % / −0.5 % / −0.1 % | +1 % | +3…+4 % |

On real gve the ~2 % RX-path cost sits below the measurement floor
(8 cores, PCIe/network latency dominates, ±2–3 % run noise) — DQO
and GQI both read flat. The GQI slab-copy specifically is ~0 %
(even slightly favourable on `upload`): the copy is one cache-hot
MTU read+write. The GQI 1/4/8 sweep was first attempted on spot
VMs and repeatedly corrupted by n2 preemption; the figures above
are a clean re-run on **on-demand** n2 (`UNIKERNEL_GCE_PREEMPTIBLE=0`).

**Functional validation** (the part that de-risks the new code):
>2 billion buffer reposts cycled across the DQO+GQI runs under
sustained load with **zero** `dqo_rx_compl_skipped` and **zero**
`gqi_recycle_pool_exhausted`. A leaking drop callback would have
starved the RX ring within seconds; none did.

Next: item C (`RxInbox` holds `IOBufChain` — cross-core zero-copy),
the natural follow-on now that the driver boundary yields owned
chains — and the first item that starts *removing* memcpys, which
recoups item B's ~2 %.

### 2026-05-17 — Phase 2/3, item C: intrusive-node cross-core RX inbox ([x] **landed**)

The Tier 2 cross-core RX inbox stops copying frame bytes. The
pre-item-C inbox `memcpy`'d every distributed frame into a per-core
`[u8; 1514]` ring slot; it now *moves* the received
`Chain<OwnedIOBuf>` — the chain owns the device RX buffer, so the
bytes never move. Copy #3 in the path table is eliminated.

**An intrusive-node lock-free inbox, not a bounded ring.** A first
attempt at item C — a bounded array ring with drop-on-overflow — was
abandoned: benchmarking caught a severe Tier-2 multi-core RX
regression (`get_tcp` 53k→4.7k, `download_64k`→0) from two bugs.
(1) A delivered chain reposting its virtio descriptor on a
non-polling core raced `poll_qp`'s `used()` on the shared descriptor
free-list. (2) Tail-dropping on overflow discarded fresh TCP ACKs,
stalling the sender's window. The landed design removes the overflow
itself:

- New [`kernel/src/rx_inbox.rs`](kernel/src/rx_inbox.rs) — generic,
  `core`-only: `RxNode<T>` (an intrusive `next` link + payload
  cell), `RxInbox` (per-core lock-free MPSC list — CAS-push,
  `swap`-then-reverse-to-FIFO drain), and `RxNodePool<T, N>` (fixed
  node pool; tagged-pointer Treiber free-list, ABA-immune like
  `IOBufPool`).
- One `RxNode` exists per pool slot, and a frame in flight pins
  exactly one device RX buffer; the pool is sized (`RX_NODE_POOL_CAP`
  = 512) ≥ the RX queue's buffer count. So the inbox **provably
  never overflows** — no drop policy, no overflow counter, there is
  no drop event to have.
- `distribute_frame` moves a chain into a node and CAS-pushes it
  onto the target core's inbox; `net_drain_cb` drains FIFO and runs
  `net_receive`. `percpu.rs` pins the payload (`RxChain =
  Chain<OwnedIOBuf>`) and the `static` pool.

**Fix #1 — virtio `used()` / `add_buf` race.** Now that a delivered
chain drops on a non-polling core, `virtio_rx_repost` → `add_buf`
runs concurrently with `poll_qp`. Both mutate the shared descriptor
free-list; `add_buf` was `rx_lock`-guarded, `used()` was not. The
new `rx_used_locked` helper harvests each descriptor — and reads its
buffer address — under `rx_lock`, releasing it before the per-frame
callback (which may itself repost). Encapsulating it means an
unlocked `used()` is not a reachable pattern in the RX path.

**Node ownership — kernel pool, not driver-side 1:1.** The cleaner
`sk_buff`-style design folds the node into per-buffer driver RX
state (no pool, no free-list — node-supply *is* buffer-supply), but
needs a `NicOps` RX-surface change across all three drivers and is
dead weight + untested for the two gve drivers (which always run
Tier 1). It is tracked as plan item K. The kernel pool keeps item C
self-contained: no driver changes, gve untouched.

The type-model split (`fb755a3` / `409b5dd` / `d8b4c1e`) landed
first, so `RxInbox<T: Send>` is `Send` by derivation — no `unsafe
impl Send`, no "no `Borrowed` parts" invariant.

Verified: x86_64 + aarch64 unikernel builds; `iobuf_test`;
`test_hvf`; new [`kernel:rx_inbox_test`](kernel/src/rx_inbox.rs) —
host-native, two 8-thread stress tests (a tagged-free-list ABA
hammer; a 1-distributor / N-consumer distribute→drain run asserting
per-inbox FIFO order + zero node/payload leak).

Perf — `test_hvf` is Tier 1 and structurally cannot exercise the
cross-core inbox; QEMU (single virtio queue = Tier 2) is the check.
Local, `main` vs item C, 10 s/workload, QEMU 3-core:

| workload (QEMU 3c, Tier 2) | `main` | item C |
|---|---|---|
| `get_tcp` | 55.4 k | 57.2 k |
| `echo_udp` | 73.3 k | 76.0 k |
| `download_64k_tcp` | 3845 | 3680 |

All at or above baseline — the abandoned attempt's 4.7 k / 0
collapse is gone; HVF (Tier 1 control) stayed flat at 3c. Local
QEMU 3c is **MTTCG** (each guest vCPU on its own host thread), so
the lock-free inbox is exercised under genuine multi-threaded
concurrency, not just emulation.

GCE, item C, unikernel as a real GCE VM (gVNIC = Tier 1 / gve;
item C touches no gve code — a no-regression check), 1/4/8 cores:

| workload (GCE remote, Tier 1) | 1c | 4c | 8c |
|---|---|---|---|
| `get_tcp` | 191 k | 539 k | 858 k |
| `echo_udp` | 323 k | 1.00 M | 1.72 M |
| `get_tls_fresh` | 4.8 k | 10.4 k | 12.4 k |
| `download_64k_tcp` | 31.7 k | 39.5 k | 39.0 k |

Healthy gve scaling — the kernel's new `RX_NODE_POOL` static and
the `net` dispatch changes leave the Tier-1 path untouched. (The
nested-KVM GCE bench path — Tier 2 on real x86 hardware — hit a
harness "not ready" snag this session; the Tier-2 cross-core inbox
is covered by local QEMU 3c MTTCG + the `rx_inbox_test` stress.)
