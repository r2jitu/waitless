# RX path optimizations — tracker

> **Note on Bazel labels.** Items below reference labels by their path
> at the time the work landed (e.g. `//crates/util/iobuf:iobuf_test`,
> `//net:tcp`). After the May 2026 crate reorganization those moved
> under `//crates/`; see [crates.md](crates.md) for the current map.
> Updates here are deliberately not retro-rewritten so the historical
> narrative still matches what each commit's diff actually said.

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
| 2 | Driver callback | [`crates/waitless/net/src/driver.rs`](crates/waitless/net/src/driver.rs), `NicOps::poll_qp` | 0 | Slice into device buf for callback duration |
| 3 | Cross-core inbox push | [`kernel/src/percpu.rs:115`](kernel/src/percpu.rs#L115) | **1× memcpy** (only multi-core path) | Copies frame into `RxPacket.data: [u8; 1514]` |
| 4 | TCP fast path (parked recv) | [`net/src/tcp.rs:331`](net/src/tcp.rs#L331) | **1× memcpy** | `ptr::copy_nonoverlapping` directly into user buf |
| 4'| TCP slow path (no parked recv) | [`net/src/tcp.rs:303`](net/src/tcp.rs#L303) | **1× memcpy** (into ring) + **1× memcpy** (out at recv) | Per-conn 16 KiB byte ring |
| 5 | HTTP parse-buf refill | [`proto/http/src/lib.rs`](proto/http/src/lib.rs) `serve_conn` | 0 (Phase 1: bytes flow through stream.recv into parse buf — same memcpy as step 4) | Headers + body prebuf land here |
| 6 | BodyReader::chunk past prebuf | [`proto/http/src/lib.rs:332`](proto/http/src/lib.rs#L332) | **0** (item H) | `recv_chunk` surfaces the transport buffer behind a `BodyChunkGuard`; the 4 KiB `refill` scratch is gone |
| 7 | Handler reads body | app handler | 0 | `BodyChunkGuard::data()` — in-place view (item H) |

Active per-byte memcpys on **TCP RX** guest side for body bytes
past the prebuf: **0** on the item-F stash fast path (the device
buffer moves straight through `recv_chunk` to the handler) and
**1** on the ring-drain fallback — item H removed the BodyReader
`refill` copy that used to sit on top of both. Down from 2 (fast)
/ 4 (slow) before this plan.

## Current path — TCP (HTTPS / TLS 1.3)

| # | Step | Site | Cost per byte | Notes |
|---|------|------|---|---|
| 1–4 | Same as TCP HTTP | (above) | 1–2 | Ciphertext bytes flow through |
| 5 | TLS pump_rx into cipher_buf | [`proto/tls/src/lib.rs:513`](proto/tls/src/lib.rs#L513) | 0 (in-place pump from TcpStream::recv) | 8 KiB inline cipher_buf |
| 6 | AEAD decrypt | TLS state machine | **1× R/W** (ChaCha20) + **1× R** (Poly1305 verify) | Plaintext lands in `pt_buf` (17 KiB after Phase 1's bump) |
| 7 | TlsStream::recv pops plaintext | [`proto/tls/src/lib.rs:685`](proto/tls/src/lib.rs#L685) | **1× memcpy** | pt_buf → user buf (item G's `recv_chunk` is the zero-copy sibling) |
| 8 | HTTP / BodyReader past prebuf | [`proto/http/src/lib.rs:332`](proto/http/src/lib.rs#L332) | **0** (items G + H) | `recv_chunk` hands a `Borrowed` view into `pt_buf`; the `refill` scratch is gone |

Active per-byte memcpys on **TLS RX** guest side: the fundamental
AEAD R/W only — items G and H removed both structural memcpys
(`pt_buf`→user buf, and the BodyReader `refill`). AEAD is
unremovable without offloading crypto to a co-processor. Note the
TLS body path is therefore AEAD-decrypt-bound, not memcpy-bound —
see item H's progress-log bench note.

## Current path — QUIC / HTTP/3

| # | Step | Site | Cost per byte | Notes |
|---|------|------|---|---|
| 1 | UDP datagram delivered | virtio/gVNIC | 0–1 | Same driver path as TCP |
| 2 | QUIC AEAD open | proto/quic | 1× R/W | Plaintext into datagram-local scratch |
| 3 | H3 DATA frame accumulate | [`proto/http3/src/server.rs:528`](proto/http3/src/server.rs#L528) | **1× memcpy per frame** into `data: Vec<u8>` | Whole body buffered before handler invoked |
| 4 | BodyReader from buffered slice | proto/http (Phase 1) | 0 | Borrowed view of the accumulated Vec |

QUIC's body-buffering is out of scope for this plan (would OOM on
a 100 MB POST) — the H3 `DATA` reassembly is a separate HTTP/3-layer
effort (see "HTTP/3 streaming body" under Follow-ups). **Item L**
does cover the UDP RX path up to that point: it removes the
*datagram*-delivery copy (NIC → per-bind inbox) that precedes QUIC
AEAD.

## Items

### A. `IOBuf::into_owned()` + `IOBufPool` infrastructure
- **Status**: [x] landed 2026-05-15 — commit `180e29c`
- **Where**: [`util/iobuf/src/lib.rs`](util/iobuf/src/lib.rs);
  possibly new [`util/iobuf/src/pool.rs`](util/iobuf/src/pool.rs).
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
  * [`crates/waitless/net/src/driver.rs`](crates/waitless/net/src/driver.rs) — `NicOps`
    struct (change `poll_qp: fn(usize, fn(&[u8])) -> usize` to
    `fn(usize, fn(IOBufChain)) -> usize`; same for `poll_rx`).
  * [`crates/drivers/gve/src/dqo.rs`](crates/drivers/gve/src/dqo.rs) —
    wrap device buf as `ExternalOwned(buf_id)` via
    [`IOBuf::wrap_owned`](util/iobuf/src/lib.rs#L483); drop_fn
    reposts buf_id to the data ring (atomic `fill_cnt.Release` +
    BAR2 doorbell). Remove the current explicit repost code path
    (now in drop_fn).
  * [`crates/drivers/gve/src/gqi.rs`](crates/drivers/gve/src/gqi.rs) —
    maintain per-qp `IOBufPool`; per frame: alloc slab → memcpy
    device bytes → wrap as ExternalOwned → repost device slot →
    deliver 1-part chain.
  * [`crates/drivers/virtio-crates/net/stack/src/lib.rs`](crates/drivers/virtio-crates/net/stack/src/lib.rs)
    — wrap descriptor buf as `ExternalOwned(desc_idx)`; drop_fn
    returns descriptor to avail ring.
  * [`crates/net/stack/src/lib.rs:411`](crates/net/stack/src/lib.rs#L411) — `distribute_frame`
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
  [`crates/net/stack/src/lib.rs`](crates/net/stack/src/lib.rs);
  [`crates/drivers/virtio-crates/net/stack/src/lib.rs`](crates/drivers/virtio-crates/net/stack/src/lib.rs)
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
  util/iobuf type-model split landed first, so the inbox is typed
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

### D. `tcp_receive` takes a `Chain<OwnedIOBuf>`
- **Status**: [x] landed 2026-05-17 — commits `bdd15ce` (util/iobuf
  `OwnedIOBuf::narrow`/`consume`/`trim_end`), `e940a10` (net
  plumbing). See the progress-log entry below for the design
  decisions.
- **Where**: [`net/src/tcp.rs`](net/src/tcp.rs) `tcp_receive`
  (signature + chain-walking payload delivery);
  [`crates/net/stack/src/lib.rs`](crates/net/stack/src/lib.rs) `net_receive` /
  `tcp_receive_segment` / `ipv6_receive_frame` (chain-as-unit
  dispatch + narrow-to-segment); [`util/iobuf/src/lib.rs`](util/iobuf/src/lib.rs)
  `OwnedIOBuf::narrow`.
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
- **Status**: [x] landed 2026-05-17 — commit `8c2cb69` (the guard
  + unit tests), `b98b499` (the `rust_test` target it needed).
  See the progress-log entry below.
- **Where**: [`proto/http/src/lib.rs`](proto/http/src/lib.rs) —
  `parse_request_with_state` sets the new `Request.reject` flag
  via the `transfer_encoding_is_chunked` helper; `serve_conn`
  short-circuits a flagged request to `Response::bad_request()` +
  `Connection: close`.
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
- **Status**: [x] landed 2026-05-17 — commits `ae9e850` (net-tcp
  backend hooks), `570e40a` (runtime/executor API). See the progress-log
  entry below.
- **Where**:
  * [`runtime/executor/src/net/tcp.rs:161`](runtime/executor/src/net/tcp.rs#L161)
    — new `TcpStream::recv_chunk(&mut self) -> RecvChunk<'_>`
    (`Future<Output = Option<RecvChunkGuard<'_>>>`); `RecvChunkGuard`
    / `RecvChunk` types and the three `TcpBackend` vtable fields.
  * [`net/src/tcp.rs:2147`](net/src/tcp.rs#L2147) — new backend hooks
    `set_chunk_buf_slot` / `clear_chunk_buf_slot` / `do_recv_chunk`
    (`register_chunk_waker` folded into the existing recv-side waker
    hooks — see the progress log); new per-`TcpConnection` fields
    `chunk_wanted: bool` + `pending_chunk: Option<IOBuf>`.
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
- **Effort**: medium. ~200 LOC across runtime/executor + net.
- **Risk**: medium. Guard-pattern lifetimes interact with the
  async-fn-in-trait machinery; expect HRTB pain similar to
  Phase 1.
- **Tests**: compile_fail test that holding two guards
  simultaneously doesn't compile; `into_owned()` round-trip
  preserves bytes.

### G. `TlsStream::recv_chunk`
- **Status**: [x] landed 2026-05-17 — commits `a0c9acf` (runtime/executor
  guard constructor), `74357c6` (proto/tls `recv_chunk`). See the
  progress-log entry below.
- **Where**: [`proto/tls/src/lib.rs:573`](proto/tls/src/lib.rs#L573) —
  `TlsStream::recv_chunk`, an inherent method alongside the existing
  fill-buf `recv` (the `HttpStream` trait impl, now at
  [`:685`](proto/tls/src/lib.rs#L685)); the `TlsServer` plaintext-window
  accessors it drives are at
  [`proto/tls/src/server.rs:502`](proto/tls/src/server.rs#L502).
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
- **Status**: [x] landed 2026-05-17 — commits `1e97350` (HttpStream
  trait `recv_chunk`), `ad85de4` (proto/tls fold), `91aa952`
  (`BodyReader::chunk` returns the guard). See the progress-log
  entry below.
- **Where**:
  * [`proto/http/src/lib.rs:254`](../proto/http/src/lib.rs#L254) —
    `BodyReader` struct (4 KiB `refill` scratch field dropped);
    [`:332`](../proto/http/src/lib.rs#L332) — `BodyReader::chunk`;
    [`:423`](../proto/http/src/lib.rs#L423) — new `BodyChunkGuard`
    type; [`:804`](../proto/http/src/lib.rs#L804) — `HttpStream`
    trait `recv_chunk` (default `-> None`);
    [`:892`](../proto/http/src/lib.rs#L892) — `HttpStream for
    TcpStream` `recv_chunk` (forwards to the inherent method).
  * [`proto/tls/src/lib.rs:804`](../proto/tls/src/lib.rs#L804) —
    `HttpStream for TlsStream` `recv_chunk` (item G's inherent
    method folded into the trait impl).
  * [`apps/webserver/src/main.rs:341`](../apps/webserver/src/main.rs#L341)
    — `/discard` handler updated to the `BodyChunkGuard` shape.
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
- **Where**: [`crates/drivers/gve/src/dqo.rs:479`](crates/drivers/gve/src/dqo.rs#L479)
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
- **Where**: [`crates/drivers/gve/src/lib.rs:1401`](crates/drivers/gve/src/lib.rs#L1401)
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
  ([`crates/waitless/net/src/driver.rs`](crates/waitless/net/src/driver.rs)); all three
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

### L. UDP datagram inbox — IOBuf-carrying slot

Items A–K are the **TCP/TLS** RX path. This is the **UDP** path —
the equivalent move-not-copy step for the per-bind datagram inbox.

- **Status**: [ ]
- **Where**:
  * [`net/src/udp.rs`](net/src/udp.rs) — `udp_receive` signature
    `&[u8]` → `Chain<OwnedIOBuf>` (the UDP-datagram-narrowed chain),
    mirroring item D's `tcp_receive`. `net::net_receive` grows a
    `udp_receive_segment` helper alongside `tcp_receive_segment`.
  * [`runtime/executor/src/net/udp.rs`](runtime/executor/src/net/udp.rs) —
    `deliver_udp` takes an owned `OwnedIOBuf` (datagram body), not
    `&[u8]`; the `Datagram` inbox slot's inline `[u8; 1500]` becomes
    an `Option<OwnedIOBuf>`; `WorkerInbox::try_push` *moves* the buf
    in instead of `copy_from_slice`.
- **What**: undo a documented regression. The `Datagram` slot's own
  comment records that it *used* to hold an `Option<IOBuf>` and move
  a driver descriptor straight in — "that shape is gone with the
  &[u8] driver callback." Item B restored the `Chain<OwnedIOBuf>`
  driver callback, so the precondition is back. This is the UDP
  analogue of item C (move, don't copy) for the per-bind inbox: it
  eliminates the up-to-1500-byte `try_push` memcpy. The consumer
  side is already zero-copy-capable — `recv_inplace` / `pop_with`
  read the slot in place; `recv_from` / `pop_into` still copy out,
  the caller's choice of API, not a structural copy.
- **Design question — device-buffer pool pressure**: an *occupied*
  inbox slot now pins a device RX buffer instead of holding a copy.
  Total pinned ≤ Σ capacities of occupied inboxes. Server binds
  (small set of declared ports) and request-response ephemerals
  (1–2 in flight, 8-deep) are fine; a pathological many-ephemeral
  backlog could pin enough buffers to pressure the DQO/virtio pool.
  Resolve in the item: cap total pinned bufs and fall back to
  copy-into-heap (`into_owned`) past the cap. (This is the UDP
  echo of item D's "the math forbids IOBufs in the TCP ring" — for
  UDP the per-bind depth is small, so it is mostly affordable, but
  the cap is the guard.)
- **Memory note**: an *empty* slot shrinks from 1508 B to a ~48 B
  `Option<OwnedIOBuf>` handle — at 5 000 ephemeral binds × 8 slots
  the doc-noted "~60 MB inbox memory" cost mostly evaporates (it
  reappears only as device-buffer pins under genuine backlog).
- **QUIC**: QUIC/H3 datagrams traverse the same `WorkerInbox`, so L
  delivers the ciphertext datagram to the QUIC AEAD with no copy.
  The post-AEAD H3 `DATA`-frame reassembly (whole-body buffering
  into `data: Vec<u8>`) is a separate HTTP/3-layer effort — see
  "HTTP/3 streaming body" under Follow-ups.
- **Win**: −1 memcpy per UDP datagram on the delivery boundary
  (≤ 1500 B each). Benefits `echo_udp`, gateway / DNS / NTP flows,
  and QUIC datagram delivery.
- **Effort**: medium. ~150 LOC across `net/src/udp.rs` +
  `runtime/executor/src/net/udp.rs`; the `udp_receive` / `deliver_udp` /
  `try_push` / slot-type changes land as one atomic signature chain.
- **Risk**: low–medium. The SPSC inbox ring shape is unchanged; only
  the slot payload type changes. `test_hvf` exercises UDP echo; the
  pool-pressure fallback wants a unit test.
- **Tests**: UDP echo round-trips in `test_hvf`; unit test for the
  pinned-buffer cap fallback; GCE `echo_udp` bench (expect ±0% —
  plumbing, like item D).
- **Sequencing**: independent of the TCP items D–J — a different
  data structure (per-bind `WorkerInbox`, not the per-conn TCP
  ring). Needs only item B; can land any time after it.

### M–O. RX offload — HW GRO / RSC and virtio large-receive

Items I–J enable HW GRO / RSC on the gve **DQO** datapath. Items
M–O (added 2026-05-18, after the `gcp-bench.sh --env kvm`
`upload_32k_tcp` stall — see [benchmarking.md](benchmarking.md))
complete the picture: N–O are the matching **virtio-net**
large-receive work, and M is the TCP/IP-stack precondition both
halves share. Until N–O land, the virtio-net driver masks the
guest RX-offload feature bits off (`VIRTIO_NET_RX_OFFLOAD_MASK`)
so it never negotiates a capability its single-descriptor RX path
cannot honour — the diagnosed cause of the `--env kvm` upload
stall.

### M. TCP/IP RX path accepts coalesced super-segments
- **Status**: [x] landed 2026-05-18 — commit `b73b946` (L3 parse
  clamp + tests). See the progress-log entry for the audit findings
  and the host-test blocker.
- **Where**: [`net/src/ipv4.rs`](net/src/ipv4.rs) `ipv4_receive`,
  [`net/src/ipv6.rs`](net/src/ipv6.rs) `ipv6_receive`,
  [`crates/net/stack/src/lib.rs`](crates/net/stack/src/lib.rs) `net_receive` /
  `tcp_receive_segment`, [`net/src/tcp.rs`](net/src/tcp.rs)
  `tcp_receive`.
- **What**: a HW-GRO / RSC / LRO frame arrives as a *single*
  IP+TCP header over a merged payload — one IP packet with
  `total_length` up to ~64 KiB and a TCP segment far larger than
  the negotiated MSS, its payload spanning several RX buffers.
  Audit two things: (1) the L3/L4 header parse — `ipv4_receive` /
  `ipv6_receive` take `&[u8]`; the headers still live in the first
  buffer, but confirm nothing assumes the whole frame is
  contiguous or MTU-bounded; (2) `tcp_receive` already takes a
  `Chain<OwnedIOBuf>` (item D), but confirm it walks a chain whose
  logical length exceeds MSS and advances `rcv.nxt` by the full
  amount. Flag any fixed `[u8; 1514]` / `[u8; 1500]` RX staging.
- **Win**: none on its own — a precondition. Unlocks items I+J and
  N+O: without it, either RSC path delivers a super-segment the
  stack mis-handles.
- **Effort**: low–medium. Mostly an audit plus a few bound bumps;
  no new data structures.
- **Risk**: low. Tightenings, not behaviour changes, until an
  offload item actually delivers a large segment.
- **Tests**: a unit test that feeds `tcp_receive` a `Chain` whose
  logical length spans many buffers and exceeds MSS; assert the
  bytes land in-order and the window advances by the full length.

### N. virtio-net multi-buf RX chain accumulation
- **Status**: [ ]
- **Where**: [`crates/drivers/virtio-crates/net/stack/src/lib.rs`](crates/drivers/virtio-crates/net/stack/src/lib.rs)
  `poll_qp` / `poll_batch_qp`.
- **What**: the virtio twin of item I. Today `poll_qp` reads one
  used-ring descriptor, treats `used_len - 12` bytes as a whole
  Ethernet frame, and never inspects the virtio-net header past
  its size. With `MRG_RXBUF` a frame spans `hdr.num_buffers`
  descriptors (the first carries the 12-byte header + data, the
  rest are pure continuation). Read `hdr.num_buffers`, pull that
  many used entries, and build a `Chain<OwnedIOBuf>` spanning them
  — one chain emitted per frame. Also decode `hdr.flags`
  (`VIRTIO_NET_HDR_F_DATA_VALID` ⇒ RX checksum already verified,
  skip validation; `NEEDS_CSUM` ⇒ validate/compute) and tolerate
  `gso_type != NONE` (an RSC/LRO-coalesced segment — informational
  once item M accepts the large length).
- **Win**: structural correctness for virtio large-receive. No
  perf delta while item O keeps the mask in place.
- **Effort**: medium. ~80–120 LOC; mirrors item I but on virtio's
  descriptor model rather than DQO completions. `poll_qp` and
  `poll_batch_qp` are separate code paths — both need it.
- **Risk**: medium. Multi-descriptor walk under `rx_lock`; a chain
  that straddles a poll batch needs the same pending-state care as
  item I. The single-buffer (`num_buffers == 1`) path must stay
  byte-identical.
- **Tests**: unit test that a synthetic `num_buffers = N` frame
  reassembles to the right bytes; the `--env kvm` `upload_32k_tcp`
  bench once item O re-enables negotiation.

### O. Re-negotiate virtio-net RX offloads (shrink the mask)
- **Status**: [ ]
- **Where**: [`drivers/src/virtio.rs`](drivers/src/virtio.rs)
  `VIRTIO_NET_RX_OFFLOAD_MASK`; the PCI feature negotiation in
  [`crates/drivers/virtio-crates/net/stack/src/lib.rs`](crates/drivers/virtio-crates/net/stack/src/lib.rs).
- **What**: the virtio twin of item J — the enable. With item N's
  reassembly in place, drop `MRG_RXBUF` + `GUEST_TSO4` / `TSO6`
  (and, once N honours `hdr.flags`, `GUEST_CSUM`) from the mask so
  the PCI path negotiates them again. Prefer a per-feature gate
  over a bare mask edit, so the negotiated set provably tracks
  what the RX path implements — the 2026-05-18 stall was precisely
  a negotiated feature with no RX support behind it.
- **Win**: vhost-net GRO-coalesces inbound TCP — fewer RX frames,
  fewer descriptor trips, fewer cross-core inbox pushes on the
  Tier-2 path. Expect a double-digit gain on `upload_*` (cf. item
  J's +10–30 % estimate for the gve side).
- **Effort**: trivial — a mask / negotiation edit. The work is all
  in item N.
- **Risk**: low if N lands first; high standalone — this is
  exactly the change whose missing item N caused the original
  `upload_32k_tcp` stall.
- **Tests**: `gcp-bench.sh --env kvm` before/after on
  `upload_32k_tcp` / `upload_32k_tls` (the stall workloads) plus
  `get_tcp` / `download_64k_tcp` controls; confirm no `--env qemu`
  regression.

## Recommended sequence

A → B → C → D → E → F → G → H → I → J. K and L are independent —
K supersedes item C's kernel node pool and can land any time after
C (sequenced last only for its driver-wide blast radius); L is the
UDP-side counterpart of items C–D and needs only B. The RX-offload
items sequence M → [I ∥ N] → [J ; O]: M (the TCP/IP-stack
precondition) first, then the two reassembly items — I (gve DQO)
and N (virtio-net) — in either order, then each driver's enable,
J (gve RSC) and O (virtio mask), each gated on its reassembly item.

A is pure additions (infrastructure). B is the trait change that
forces all drivers + net dispatch to land atomically. C through
H build the IOBuf threading layer-by-layer; each is independently
buildable and testable atop the prior. E (chunked rejection)
slots anywhere after the parser stays touchable but is placed
between D and F to colocate with the HTTP-layer work. I sets up
the multi-buf delivery shape; J enables RSC on top. N and O are
the virtio-net mirror of that pair; M is the shared TCP/IP-stack
precondition both driver families need before either RSC path can
deliver a coalesced super-segment.

## Test & regression-detection contract

### Per-commit local

- `bazel build //apps/webserver:webserver_qemu_x86_64`
- `bazel build //apps/webserver:webserver.elf --platforms=//bazel/platforms:aarch64_waitless`
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
| `upload_32k_tcp` | 51 k / 72 k | ±3% (item H landed perf-neutral on GCE — the `+15–25%` budget did not hold; see item-H log) |
| `upload_32k_tls` | 47 k / 70 k | ±3% (item H landed perf-neutral on GCE — the `+10–20%` budget did not hold; see item-H log) |

Protocol: 3 runs per workload per core count, take median.
Single-run > 3% deviation from baseline on a control workload
triggers "halt and investigate."

### Intermediate GCE bench checkpoints

- **After B** (NicOps signature change; GQI uses recycle pool):
  DQO bench (expect ±0% — pure refactor for DQO). GQI bench
  with `WAITLESS_GCE_MACHINE=n2-highcpu-8` (expect 5–15% RPS
  drop — the accepted GQI memcpy cost; > 20% triggers
  investigation).
- **After D** (`tcp_receive` takes IOBufChain): DQO bench
  (expect ±0% — heaviest upper-stack refactor; intermediate
  check catches regressions before more changes pile on).
- **After H** (zero-copy body path lands): [x] done — ran via
  `gcp-deploy-bench.sh` (Tier 1; nested-KVM `gcp-bench.sh` hit the
  `SKIP (not ready)` failure). Result: **perf-neutral on GCE** —
  `upload_32k_tcp` 1c +0.7 % (~44 k, inside run noise), controls
  within ±3 %. The expected ~51 k → ~62 k climb did **not**
  materialise; the win was HVF-path-specific. See the item-H
  progress-log entry.
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

- **Large HTTP/3 (QUIC) payloads**: proto/http3 reassembles all
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
- **In-place TLS RX decrypt** (zero-copy `into_owned()` on the
  TLS path): item G's `TlsStream::recv_chunk` surfaces a
  `Borrowed` view into `pt_buf` — `data()` is zero copy, but
  `into_owned()` costs one memcpy (`Borrowed` → `Heap`), where
  the TCP path's `ExternalOwned` chunk makes `into_owned()` free.
  Closing the gap means decrypting ChaCha20-Poly1305 *in place*
  into the device RX buffers that carried the ciphertext and
  surfacing a `Chain<ExternalOwned>` plaintext chunk. The crypto
  allows it — ChaCha20 is a stream cipher and the TX path already
  seals in place — but TLS records don't align to device buffers
  (a 16 KiB record spans ~11 MTU buffers) and AEAD is
  all-or-nothing (the Poly1305 tag must verify over the whole
  record before any plaintext byte is released), so the record
  layer must reassemble first. Today reassembly copies into
  `cipher_buf`; the zero-copy form is chain-threaded reassembly +
  in-place AEAD across a discontiguous chain + per-fragment
  `narrow` + content-type/padding strip — a `proto/tls` record-layer
  rearchitecture, well past item G's scope. A single-device-buffer
  fast path (a record that fits in one MTU buffer → decrypt in
  place there) is the tractable partial win. Needs **no API
  change**: `recv_chunk` keeps returning `RecvChunkGuard`, only
  the wrapped payload changes (`Borrowed` → `Chain<ExternalOwned>`)
  and `into_owned()` drops from 1 copy to 0 — the guard is the
  stable façade that makes this a non-breaking evolution. Cost to
  weigh: a held plaintext chunk then pins ~11 NIC buffers (the
  item-L device-pool-pressure concern).
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
  the remote waitless-webserver VM (currently HVF-only).

### RX scheduler — unify the tier model

The Tier 1 / Tier 2 split is well-defined only at its endpoints;
the middle is frayed. "Tier 1 — each core polls its own queue" is
total **only on the diagonal `nqp == num_cores`**. Off it:

- `nqp < num_cores` — cores `>= nqp` poll nothing
  ([`crates/net/stack/src/lib.rs`](../crates/net/stack/src/lib.rs), `poll_tier1`'s
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
- **Zero-copy TCP proxy endpoint + benchmark.** The canonical
  end-to-end zero-copy RX→TX showcase: a `proxy` handler that
  accepts a client TCP conn, opens a backend TCP conn, and pumps
  bytes `recv_chunk()` → `into_owned()` → `send()`. RX is already
  zero-copy (items F–H surface the device buffer); this becomes
  *genuinely* end-to-end only once TX-side IOBuf threading lands —
  hence Phase 5, not now. Building it before then showcases only
  the RX half (the `tcp_echo_64k` bench workload already measures
  that half — zero-copy RX, copying TX). Two gotchas to plan for:
  * a **full-duplex** proxy (both directions pumped concurrently)
    needs `TcpStream::split()` into read/write halves — a direct
    consequence of the per-stream-op `&mut self` hardening
    (`710d64c`); a request-response proxy is sequential and needs
    no `split()`. The proxy is the consumer that would justify
    adding `split()`.
  * the bench needs the loadgen to host a TCP backend (echo
    server), the way `fanout_tcp` hosts a UDP backend today.
  `gateway` is **not** the vehicle for this — TCP↔UDP, fixed-frame
  (`recv_exact`), and its UDP legs are gated on item L.

### Mid-term — HTTP/3 streaming body

- proto/http3 progressive DATA-frame delivery (unblocks 100 MB
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

- **TCP conformance test harness.** `tcp` has no conformance
  suite — the receiver-side window-update bug (commit `171c68e`,
  found mid-item-B only because a QEMU upload anomaly got chased
  into a packet capture) is exhibit A for why that's a gap. Build
  an in-memory harness: a mock `NicOps` (the vtable is swappable
  via `set_active_ops()`) captures TX frames into a `Vec`, and
  `tcp_receive(src, dst, &[u8])` is already a `pub` RX entry point
  that takes crafted segments — so a test drives scripted packets
  in and asserts on captured output (packetdrill-in-a-unit-test).
  *Blocker:* `tcp`'s `os:none` dep chain (`kernel` /
  `runtime/executor`) must be made host-buildable — extend the
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

### util/iobuf type model — [x] landed 2026-05-16

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
[`iobuf-type-model.md`](iobuf-type-model.md).

### Operational

- Stuck-worker preemption / watchdog.
- Cross-core pool contention measurement (fall back to per-core
  pool partitions if Treiber stack becomes contended).

### Aspirational

- HTTP/2 support.
- WebSockets / long-lived streaming.

## Reuse rather than rebuild

Concrete utilities to lean on:
- [`IOBuf::wrap_owned`](util/iobuf/src/lib.rs#L483) — exactly the
  constructor for ExternalOwned with drop_fn (NIC zero-copy RX
  is its documented canonical use case at
  [util/iobuf/src/lib.rs:245-247](util/iobuf/src/lib.rs#L245-L247)).
- [`IOBuf::borrow`](util/iobuf/src/lib.rs#L538) for prebuf IOBufs +
  TLS pt_buf IOBufs; debug-mode `BorrowGuard` catches aliasing.
- [`IOBufChain`](util/iobuf/src/lib.rs#L1295) — already
  smallvec-style (8 inline parts + lazy `VecDeque` overflow).
- [`ExternalOwned` is Send](util/iobuf/src/lib.rs#L338) —
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

Also discovered + fixed two latent proto/tls bugs that surfaced
when bench started doing TLS POSTs > 4 KiB: `RX_BUF_LEN` was 4 KiB
(too small for a 16 KiB TLS record), `PT_BUF_LEN` similarly.
Both bumped to 17 KiB (commits `5e6d59f`, `c357337`). `upload_32k_tls`
unblocked.

### 2026-05-15 — Phase 2/3, item A: `IOBuf::into_owned` + `IOBufPool` ([x] **landed** — commit `180e29c`)

Pure-additions infrastructure step. Two additions to `util/iobuf`:

- `IOBuf::into_owned(self) -> IOBuf` — zero-copy no-op for the four
  owning variants (`Heap` / `Shared` / `Static` / `ExternalOwned`);
  copies-to-`Heap` for `Borrowed`, the one non-owning variant. The
  ownership-transfer escape hatch the item-F / item-H guards'
  `into_owned()` will delegate to.
- `IOBufPool` — fixed-size MTU-slab pool ([`util/iobuf/src/pool.rs`](util/iobuf/src/pool.rs))
  with a lock-free tagged-pointer Treiber free list (`AtomicU64`
  head packing `(slot_index, version_tag)`; version bumps on push
  to defeat ABA; links in a dedicated `AtomicU32` array so they
  never alias slab payload). `alloc()` hands out an `ExternalOwned`
  IOBuf that recycles its slab on drop; the drop callback is
  panic-safe (leak + counter, never panic in a `#![no_std]` `Drop`).
  Consumed by item B's GQI recycle pool.

No perf delta expected or measured — no GCE bench for this item
per the plan (first checkpoint is after item B). Verified:
`bazel test //crates/util/iobuf:iobuf_test` (50 tests, +12 new, including
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
are a clean re-run on **on-demand** n2 (`WAITLESS_GCE_PREEMPTIBLE=0`).

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

### 2026-05-17 — Phase 2/3, item D: `tcp_receive` takes a `Chain<OwnedIOBuf>` ([x] **landed**)

`tcp_receive`'s entry signature changed from a borrowed `&[u8]`
segment to an owned `Chain<OwnedIOBuf>`. Pure plumbing — the per-conn
`rx_ring` stays `Box<[u8; 16384]>` (the 1500-conn × 11-bufs/conn math
forbids IOBufs in the ring), so the copy count is unchanged. The
point is an IOBuf-typed RX input so items F–H can later thread it to
the application zero-copy.

**Design decision 1 — how the TCP segment is represented.** The
chain that reaches `net_receive` is the whole Ethernet frame (one
`OwnedIOBuf` spanning eth + IP + TCP). `tcp_receive` wants just the
TCP segment. Two options were on the table: (A) narrow the
`OwnedIOBuf`'s window to the segment, or (B) pass the frame chain +
a payload-offset parameter. **Chose (A).** `net_receive` parses
eth + IP from the borrowed `data()`, computes the L4 segment's
`(offset, len)` by *pointer arithmetic* against `pkt.payload`
(`pkt.payload.as_ptr() - first.data().as_ptr()`), then
`narrow()`s part 0 to exactly that range and moves the chain into
`tcp_receive`. The `Chain<OwnedIOBuf>` type then *means* "the TCP
segment" — no offset travels alongside it, and items F–H will
`consume()` further past the TCP header to expose just the body.
Pointer arithmetic (not an `ETH + IP_HDR` constant) is robust across
IPv4 header options *and* IPv6 extension headers. This is also
consistent with the "Fuse the Tier-2 classify parse" follow-up:
once that lands, the carried L4 offset *is* the narrow.

**Why `narrow` (offset *and* length), not a bare `consume`.** The
device delivers the full wire frame *including ethernet trailing
padding* — a 54-byte pure ACK is padded to 60. `tcp_receive` derives
`payload_len` from the segment length; a chain that still carried
6 padding bytes would make a pure ACK look like a 6-byte payload and
desync `rcv_nxt`. Today `pkt.payload` is IP-total-length-trimmed;
`narrow(l4_off, l4_len)` reproduces that trim exactly. New
`OwnedIOBuf::narrow` / `consume` / `trim_end` (forwarders to the
existing `ExternalOwned` / `HeapStorage` offset arithmetic; landed
in the util/iobuf commit) — narrowing shifts only `offset`/`len`, so
`ExternalOwned`'s `base`/`capacity` are untouched and the drop
callback still reposts the *whole* device buffer.

**Design decision 2 — one chain is one frame; treat it as a unit.**
The first cut of this work had `net_receive` `pop_front`-split the
chain and re-dispatch each part as its own frame. That is **wrong
for RSC**: the driver invokes the RX callback once per frame, so a
chain is *one* frame — a single device buffer today, or (item I) a
hardware-coalesced super-segment spanning several buffers, where
parts 1..N are raw TCP payload continuation, not framed packets.
`net_receive` now parses the L2/L3/L4 headers from part 0 and hands
the *whole* narrowed chain to `tcp_receive`, which walks every part
for payload. This makes `net_receive` consistent with
`distribute_frame` (which the doc already noted treats the chain as
one flow), and removes a latent item-I landmine. `net_receive_frame`
folded into `net_receive` (no per-part loop left). The remaining
multi-part work is genuinely item I's: when it builds multi-part
chains it must also refresh the chain's cached `total_len` after the
part-0 narrow (`Chain::shrink_total_len`) — a `Single`-repr chain
computes `total_len` live, so item D needs nothing there.

**Design decision 3 — the RX path stays `OwnedIOBuf`-typed; no
widening to `IOBuf` at the target core.** Per the util/iobuf
type-model doc, `From<OwnedIOBuf> for IOBuf` is applied **per-chunk
at the app RX API boundary** (`BodyReader`, items F/H), not eagerly
to a `Chain` — an eager widen is an O(parts) re-tag + `VecDeque`
realloc on the hot path, and it would discard the `Send`-by-
derivation guarantee for nothing. `tcp_receive` needs only the read
surface (`data` to copy into the ring) plus `narrow` — all of which
`OwnedIOBuf` now has. The "rich" `IOBuf`-only surface
(`Borrowed`-mixing, `IOBufWriter`, `prepend`/`append`) is TX-path
and app-boundary, not RX-consume.

**UDP left on `&[u8]`.** Item D is TCP-focused. `udp_receive` keeps
its borrowed-slice shape; converting it with no consumer would be
dead plumbing. The genuine UDP RX optimization — restoring the
IOBuf-carrying datagram inbox — is now tracked as **item L** (added
this session); it picks up the `udp_receive` signature change there.

Verified: `bazel build //apps/webserver:webserver_qemu_x86_64`;
`bazel build //apps/webserver:webserver.elf
--platforms=//bazel/platforms:aarch64_waitless`;
`bazel test //crates/util/iobuf:iobuf_test` (+1 test —
`owned_iobuf_narrow_clamps_window_keeps_backing`, asserting a
narrowed buffer still reposts its original `(base, capacity)`);
`bazel test //apps/webserver:test_hvf` (TCP + TLS round-trips under
the 30-conn burst).

Local 3-run-median bench (hvf + QEMU, 1c/3c) shows no regression
above the host noise floor. `echo_udp` — whose code path item D does
*not* touch — varied ~±15 % run-to-run and so calibrates that floor;
every TCP/TLS workload sits inside it (`get_tcp` HVF 1c 191 k / 3c
189 k, QEMU 1c 44 k / 3c 55 k; `download_64k_tcp` and `upload_32k_*`
flat against the item-C numbers). The architectural guarantee —
identical copy count, and the chain drops on the same core in the
same poll cycle, one stack frame deeper — is the real basis for
perf-neutrality. The **GCE gve bench checkpoint the plan mandates
after D is the authoritative ±0 % gate and is still pending.**

### 2026-05-17 — Phase 2/3, item E: reject chunked `Transfer-Encoding` with 400 ([x] **landed**)

Security hardening, not perf — zero per-byte path touched, no GCE
checkpoint needed.

**The hole.** `parse_request_with_state` only ever read
`Content-Length` to size the request body. A `Transfer-Encoding:
chunked` request carries no `Content-Length`, so the parser sized
the body at 0 — and `serve_conn`'s keep-alive loop then re-parsed
the chunk-framed body bytes (`5\r\nhello\r\n0\r\n\r\n`) still
sitting in its buffer as a *second* pipelined request. That
request/response desync is the HTTP-request-smuggling primitive.

**The guard.** The parser now detects a `Transfer-Encoding`
header that lists `chunked` and sets a new `Request.reject` flag.
`Request::header` already matches the header *name* case-
insensitively; the new `transfer_encoding_is_chunked` helper
splits the value on commas and matches `chunked` against each
trimmed coding case-insensitively, so `chunked`, `Chunked`, and
`gzip, chunked` all trip it. `serve_conn` reads the flag right
after the parse and, instead of building a `BodyReader` and
calling the handler, answers `400 Bad Request` with
`Response::bad_request()` and forces `want_close` — which routes
through the *existing* response-send path (so `Connection: close`
falls out of the `!want_close` argument to
`write_response_into_iobuf`) and `return`s without parsing a body
or any further pipelined request on that connection.

**Why a `Request` flag rather than a parser return code.**
`parse_request_with_state` returns `body_start: usize`, with `0`
already meaning "headers incomplete, need more bytes". A reject
can't reuse `0`, and the parser's job is to produce a `Request`,
not a `Response` — so the third outcome rides on the `Request`.
The flag also keeps the HTTP/3 frontend untouched: it builds its
`Request` via `set_path` / `push_header` and never sees chunked
framing, so `reject` stays `false` there by construction.

Proper chunked decoding is still deferred to Phase 4 (HTTP parser
refresh) — item E is only the smuggling guard.

**Test target.** `proto/http` had a `#[cfg(test)]` module but no
`rust_test` target, so its tests had never run. A separate
commit (`b98b499`) added `//crates/proto/http:http_test` and flipped
the crate to the `#![cfg_attr(all(not(test), not(feature =
"std")), no_std)]` form (mirroring `//crates/proto/http3`). Item E adds
eight tests there — the `transfer_encoding_is_chunked` helper
(case-insensitivity, coding-list membership, non-chunked
codings) and the parser flag end-to-end (chunked request flagged,
case-insensitive header name, `gzip, chunked` list, plain
`Content-Length` *not* flagged, incomplete headers *not*
flagged).

Verified: `bazel build //apps/webserver:webserver_qemu_x86_64`;
`bazel build //apps/webserver:webserver.elf
--platforms=//bazel/platforms:aarch64_waitless`;
`bazel test //crates/proto/http:http_test` (13 tests — 8 new + the 5
now-running `host_port_tests`); `bazel test
//apps/webserver:test_hvf` (TCP + TLS round-trips, 30-conn
burst — confirms the `serve_conn` restructure left the
non-rejected path unchanged).

### 2026-05-17 — Phase 2/3, item F: `TcpStream::recv_chunk` guard-pattern API ([x] **landed** — commits `ae9e850`, `570e40a`)

The first item that threads an inbound `IOBuf` to the application
zero-copy. `recv_chunk` is the `recv` sibling that, instead of
copying bytes into a caller buffer, surfaces the transport's *own*
buffer behind a `RecvChunkGuard`. Items G (`TlsStream::recv_chunk`)
and H (`BodyReader::chunk` returns a guard) build directly on the
guard shape this commit fixes.

**The guard is the load-bearing design choice.** `recv_chunk`
returns `RecvChunkGuard<'a>`, not a bare `Option<IOBuf>`. `IOBuf`
carries no lifetime parameter, so a bare-`IOBuf` return would be
borrow-*unsafe* on the TLS path item G adds: a `Borrowed` IOBuf
viewing `pt_buf` could be left dangling when the next `pump_rx`
overwrites `pt_buf`. The guard binds the IOBuf's lifetime to the
`&'a mut self` of `recv_chunk`: holding it keeps the stream
mutably borrowed, so the compiler *itself* enforces the stated
"≤ 1 outstanding IOBuf per `TcpStream`" invariant — two live
guards do not borrow-check. `recv_chunk` therefore takes
`&mut self`. (This entry originally called the `recv`-`&self` /
`recv_chunk`-`&mut self` asymmetry deliberate; commit `710d64c`
later **closed** it — `recv` / `recv_exact` / `send` became
`&mut self` too, since `&self` left the same ≤1-outstanding
invariant *unenforced* for the fill-buffer path, a latent
slot-stealing hazard.) `RecvChunkGuard<'a>` carries the
borrow as `PhantomData<&'a mut ()>` — the inner type is opaque so
one guard type serves both `TcpStream` (here) and `TlsStream`
(item G). `data()` reads in place; `into_owned()` delegates to
`IOBuf::into_owned` (item A) — zero copy for an owned source, one
memcpy for a `Borrowed` one.

**Item F is perf-neutral by construction — the new path is dead
until item H.** The zero-copy delivery is gated on a new
per-`TcpConnection` flag `chunk_wanted`, which only
`set_chunk_buf_slot` sets, which only `RecvChunk::poll` calls —
and nothing calls `recv_chunk` until item H rewires `BodyReader`.
With `chunk_wanted` false the `tcp_receive` data path is
*byte-identical* to the pre-item-F code: the new branch is one
short-circuiting `&&` test against a false bool. So `test_hvf`
still fully exercises the only live path, and the bench below is
flat not because the new code is fast but because it is unreached.

**Two delivery sources, one ordering rule.** When `chunk_wanted`
is set and the next in-sequence segment is single-part with the
`rx_ring` empty, `tcp_receive` *moves* the segment's device
buffer straight into the new `pending_chunk: Option<IOBuf>` field
— `narrow`ed to the payload, widened `OwnedIOBuf → IOBuf` — with
no `rx_ring` round-trip. `do_recv_chunk` then hands that
`External` IOBuf out as-is (zero copy; `into_owned` stays zero
copy). If instead the ring already holds bytes, `do_recv_chunk`
drains it into a fresh `Heap` IOBuf. The stash only ever fires
while the ring is empty, so `pending_chunk` always holds the
*older* bytes — `do_recv_chunk` drains it strictly before the
ring and stream order is preserved without a sequence number
travelling alongside. Multi-part chains (item I's coalesced
super-segments) fall through to the existing copy path.

**`register_chunk_waker` folded into the recv-side waker hooks.**
The item sketch listed a `register_chunk_waker` hook; it was not
added. Readiness is a *connection*-level signal — `tcp_receive`
wakes one per-conn `recv_waker` when data lands — and a conn
never has both a `recv` and a `recv_chunk` future parked at once
(a `BodyReader` picks one API). `RecvChunk::poll` reuses the
existing `register_recv_waker` / `clear_recv_waker` vtable hooks;
a second waker field would have to be woken from `tcp_receive`
and `free_connection` too, for no behavioural gain. The genuinely
new hooks are `set_chunk_buf_slot` / `clear_chunk_buf_slot` (the
one-bit "deliver-as-IOBuf" request, cancel-safe via
`RecvChunk::Drop`) and `do_recv_chunk`.

**Test infrastructure.** `runtime/executor` had no `rust_test` target;
it flips to the workspace-standard `#![cfg_attr(not(test),
no_std)]` so `rust_test(crate = ":runtime/executor")` runs host-native.
The `compile_fail` test — "two guards must not compile" — cannot
be a `#[cfg(test)]` unit test (a crate with non-compiling code
does not compile at all); it is a `compile_fail` doc-test, run by
a new `rust_doc_test` wrapper in
[`bazel/rules/rust.bzl`](../bazel/rules/rust.bzl), gated on
`tests_need_std` exactly like `rust_test`. It is paired with a
sequential-use doc-test that *does* compile, so the negative is
pinned to the double-borrow and not to an unrelated error.

Verified: `bazel build //apps/webserver:webserver_qemu_x86_64`;
`bazel build //apps/webserver:webserver.elf
--platforms=//bazel/platforms:aarch64_waitless`; `bazel test
//apps/webserver:test_hvf` (TCP + TLS round-trips, 30-conn burst);
`bazel test //crates/runtime/executor:executor_test` (2 tests —
`RecvChunkGuard::into_owned` round-trips an owned `Heap` source
and a `Borrowed` source, bytes preserved either way); `bazel test
//crates/runtime/executor:executor_doc_test` (the `compile_fail` guard test
+ its sequential-use companion). Each of the two implementation
commits was gate-checked on its own tree.

Local 3-run-median bench (HVF, 1c/3c; the `--env hvf --cores 1,3`
protocol), confirming perf-neutrality:

| Workload | 1c | 3c |
|---|---|---|
| `get_tcp` (control) | 196.1 k | 198.4 k |
| `get_tls_fresh` (control) | 2985 | 7881 |
| `upload_32k_tcp` | 22.0 k | 41.4 k |
| `upload_32k_tls` | 4843 | 12.4 k |

The per-run spread was ~0.1 % on `get_tcp` — `get_tcp` 1c sits at
196 k against the doc's 197 k Phase-1 baseline (−0.5 %, well
inside the ±3 % control tolerance), and the uploads match item B's
HVF figures (~22 k / ~41 k — the 51 k upload baseline in the
threshold table is a GCE/QEMU number, not HVF). No control
regressed; the win is deferred to item H as planned. No GCE
checkpoint for F (the plan reserves those for B, D, H, I, J).

Next: item G (`TlsStream::recv_chunk` — a `RecvChunkGuard` over a
`Borrowed` view into `pt_buf`), the smaller TLS-side counterpart,
then item H wires `BodyReader::chunk` onto both and the zero-copy
body win lands.

### 2026-05-17 — Phase 2/3, item G: `TlsStream::recv_chunk` ([x] **landed** — commits `a0c9acf`, `74357c6`)

The TLS-side counterpart of item F. `TlsStream::recv_chunk` is the
zero-copy sibling of the fill-buffer `recv`: instead of copying
decrypted plaintext out of the TLS layer's `pt_buf` into a caller
buffer (step 7 of the TLS RX path table), it surfaces a
`RecvChunkGuard` over a `Borrowed` `IOBuf` viewing `pt_buf` in
place. Dead until item H rewires `BodyReader` onto it — perf-neutral
by construction, exactly as item F was.

**The guard knot — "advance `pt_pos` on guard drop" without a
cross-crate `Drop`.** Item G's sketch said the TLS guard "advances
`pt_pos` on guard drop." A typed mutate-the-`TlsStream`-on-drop is
*impossible*: `RecvChunkGuard` lives in `runtime/executor` and cannot
name `TlsStream` (the dependency runs `proto/tls → runtime/executor`), and
item F deliberately gave the guard no `Drop`. Two clean options
were on the table: (a) advance `pt_pos` **eagerly** when
`recv_chunk` hands out the guard; (b) give the guard a type-erased
drop hook. **Chose (a).** The guard carries the `&mut self` borrow
of `recv_chunk` for its whole life, so between the eager advance
and the guard's drop *no code can observe `pt_pos` / `pt_len` or
re-run `pump_rx`* — eager and on-drop advance are observationally
identical. Option (a) needs only a `pub` constructor on
`RecvChunkGuard` (the guard is otherwise unchanged — no `Drop`, no
hook field, the public API stays frozen); option (b) would add a
`Drop` impl + a hook field firing cross-crate for zero behavioural
gain. The cursor write is bookkeeping; the `&mut self` borrow is
what is load-bearing for safety — the same point item F's entry
makes about why the guard *return type* matters.

**Shape.** `TlsServer` gains two sans-io accessors: `has_plaintext`
(a peek) and `take_plaintext_chunk` (hands back
`pt_buf[pt_pos..pt_len]` as a `&mut [u8]` and resets the cursors —
the zero-copy sibling of `pop_plaintext`). `TlsStream::recv_chunk`
loops `pump_rx` until plaintext is buffered (handshake records
carry none, so the early iterations just drive the handshake,
exactly as `recv` does), then wraps the window in a `Borrowed`
`IOBuf` behind a `RecvChunkGuard`. The chunk is a *single
contiguous* view — `pt_buf` holds at most one record's plaintext,
so there is no chain; multi-part delivery is item I's concern and
the `RecvChunkGuard` API stays frozen single-part. `data()` reads
in place (zero copy); `into_owned()` is the `Borrowed → Heap` +1
memcpy case — the TLS path has no `ExternalOwned` plaintext buffer
to hand out for free. Closing that last copy (in-place AEAD into
the device RX buffers, surfacing a `Chain<ExternalOwned>`) is the
documented Phase-4 follow-up; it needs **no API change** — the
guard is the stable façade — and is explicitly out of item G's
scope.

**A pre-existing item-F miss, fixed in passing (commit `4d3dda2`).**
`tls_test` would not build: item F added three fields to the
`TcpBackend` vtable (`do_recv_chunk` / `set_chunk_buf_slot` /
`clear_chunk_buf_slot`) and updated the bare-metal initializer in
`net/src/tcp.rs`, but missed the native one in
`crates/waitless/backend/src/native/tcp.rs`. Item F's gate set — two bare-metal
`bazel build`s + `test_hvf` — never compiles the native backend
(it is `select`'d in only for host builds), so the breakage slipped
through; `tls_test` catches it because `proto/tls → uni →
crates/waitless/backend` pulls the native backend into a host-native test
compile. Fixed by wiring the three hooks as `None` — the documented
native-POSIX behaviour (`recv()` copies at the syscall boundary, so
there is no device buffer to lend; `recv_chunk` resolves to `None`
and callers fall back to `recv`).

No new unit test. The guard revision is a `pub` on an existing
constructor — already covered by item F's
`RecvChunkGuard::into_owned` *Borrowed-source* round-trip in
`executor_test`, which **is** the TLS-plaintext shape. A
TLS-side `compile_fail` doc-test of the two-guards borrow error
would need a full `TlsStream` to construct (a `TcpStream` +
`PooledTlsConn` + a live runtime); the borrow mechanism is anyway
*identical* to `TcpStream`'s — same guard, same `&mut self`
lifetime — and already has a `compile_fail` doc-test on the TCP
side. `test_hvf` (real TLS handshakes + the 30-conn TLS burst) is
the functional gate the plan designates for G.

Verified: `bazel build //apps/webserver:webserver_qemu_x86_64`;
`bazel build //apps/webserver:webserver.elf
--platforms=//bazel/platforms:aarch64_waitless`; `bazel test
//apps/webserver:test_hvf`; `bazel test //crates/runtime/executor:executor_test
//crates/runtime/executor:executor_doc_test //crates/proto/tls:tls_test` (the last
unblocked by the native-backend fix). The `4d3dda2` + `a0c9acf`
intermediate tree was gate-checked on its own before `74357c6`
landed on top.

Perf — a controlled **same-session A/B**: `main` vs item G, 3 runs
each, identical host, HVF 1c/3c (the `--env hvf --cores 1,3`
protocol), so only the code differs. Medians:

| Workload | `main` 1c/3c | item G 1c/3c | Δ 1c/3c |
|---|---|---|---|
| `get_tcp` (control) | 192.7 k / 191.3 k | 193.7 k / 193.9 k | +0.5 % / +1.3 % |
| `get_tls_fresh` (control) | 2923 / 7439 | 2928 / 7394 | +0.2 % / −0.6 % |
| `upload_32k_tcp` | 21.4 k / 39.7 k | 21.6 k / 39.2 k | +0.9 % / −1.3 % |
| `upload_32k_tls` | 4792 / 12.7 k | 4814 / 12.4 k | +0.5 % / −1.9 % |

Every workload sits within ±2 %, well inside the ±3 % control
tolerance — item G is perf-neutral, as expected for code nothing
calls until item H. The A/B against `main` (not against item F's
progress-log figures) is load-bearing here: a first pass compared
item G to item F's logged `get_tls_fresh` 3c of 7881 and read −6 %,
but re-benching `main` on this host *today* gives 7439 — the gap
was cross-session host drift, and the same-session control shows
−0.6 %. No GCE checkpoint for G (the plan reserves those for B, D,
H, I, J).

Next: item H — `BodyReader::chunk` returns a guard, wiring
`BodyReader` onto both `TcpStream::recv_chunk` and
`TlsStream::recv_chunk`. That is where the zero-copy body win
actually lands (the threshold table budgets +10–20 % on
`upload_32k_tls` 1c after H).

### 2026-05-17 — Phase 2/3, item H: `BodyReader::chunk` returns a guard ([x] **landed** — commits `1e97350`, `ad85de4`, `91aa952`)

The item that *spends* the `recv_chunk` guard pattern items F and G
built: `BodyReader::chunk` changes from `-> &[u8]` to
`-> Option<BodyChunkGuard<'_>>`, and request-body bytes past the
parse-buffer prebuf now reach the handler with no intermediate copy
— end-to-end zero-copy body delivery on the TCP path.

**The trait-method knot.** `BodyReader<S: HttpStream>` is generic
over the stream, so `recv_chunk` had to be reachable through the
`HttpStream` trait — F/G left it inherent on `TcpStream` /
`TlsStream` only, and the two had different shapes (`TcpStream`: a
non-`async fn` returning the `RecvChunk` future struct; `TlsStream`:
an `async fn`). The trait method is
`async fn recv_chunk(&mut self) -> Option<RecvChunkGuard<'_>>` with
a **default body returning `None`** — that default is load-bearing:
`NullStream` (the HTTP/3 pre-buffered-body transport) has no
streaming chunk path and inherits it, so a `BodyReader` over
`NullStream` serves the body from its prebuf alone. `TcpStream` and
`TlsStream` override it. The two impls resolve the name collision
differently, each cleanly:

- **`TlsStream` folds in.** `proto/tls` owns both `TlsStream` and its
  `impl HttpStream for TlsStream`, so the inherent `recv_chunk`
  (item G) just *becomes* the trait-impl override — body moved
  verbatim, inherent method deleted, no collision left to footgun.
- **`TcpStream` forwards.** `waitless::runtime::TcpStream` can't impl an
  proto/http trait (the dependency runs the other way) and item-F
  doc-tests call its inherent `recv_chunk`, so that method stays;
  the trait impl forwards to it. The forward is written as a plain
  `fn` returning the *concrete* `RecvChunk` future — not an
  `async fn` block, and not the trait's opaque `impl Future` — so it
  is type-checked against the inherent method. If the inherent
  method were ever deleted, `waitless::runtime::TcpStream::recv_chunk`
  would resolve to the *trait* method (opaque return), and the
  mismatch against `-> RecvChunk<'_>` is a compile error rather than
  the silent infinite recursion an `impl Future` return would let
  through. That concrete return refines the trait's `impl Trait`;
  the targeted `#[allow(refining_impl_trait_reachable)]` is
  intentional — the refinement *is* the footgun guard.

**`BodyChunkGuard`.** A new guard type in proto/http wrapping the body
chunk from either source behind one `data() -> &[u8]` (zero-copy in
place) / `into_owned() -> IOBuf` façade:

- *Prebuf bytes* — a `Borrowed` `IOBuf` over `serve_conn`'s parse
  buffer; `data()` zero-copy, `into_owned()` materialises `Heap`.
- *Past-prebuf bytes* — the `RecvChunkGuard` the transport surfaced:
  `ExternalOwned` (bare-metal TCP, zero-copy `into_owned`) or
  `Borrowed`-into-`pt_buf` (TLS, +1-memcpy `into_owned`).

It is kept **separate** from `RecvChunkGuard`, not merged — the
prebuf source is a plain `Borrowed` `IOBuf` with no `RecvChunkGuard`
behind it, so a merge would not actually cover both. Single-part and
frozen: `BodyReader` delivers one contiguous run per call;
multi-part delivery is item I. `BodyChunkGuard<'a>` borrows
`&'a mut BodyReader` — the `Stream` variant's `RecvChunkGuard<'a>`
and the `Prebuf` variant's `PhantomData<&'a mut ()>` both thread
that lifetime, so a live guard keeps the `BodyReader` (hence the
stream, hence `pt_buf` / the device buffer) borrowed: the item-F/G
borrow-safety property, one layer up. The 4 KiB `[u8; 4096]`
`refill` scratch field (plus `refill_start` / `refill_end`) is gone
— past-prebuf bytes come from `recv_chunk`, not `stream.recv` into
scratch.

**The over-read cap.** Phase-1's `chunk` capped `stream.recv` at the
remaining body length so it never read past `Content-Length` into
the next pipelined request; `recv_chunk` surfaces a *whole*
transport chunk and cannot be told a limit. `chunk` therefore caps
the *delivered* slice (`take = guard.data().len().min(want_max)`),
which keeps the handler and the `delivered` accounting correct. The
residue — a transport chunk straddling the `Content-Length`
boundary — is dropped when the guard drops. That straddle is
reachable only by pipelining a follow-up request into the tail
segment of a body that overflowed the 16 KiB parse buffer; the
pre-Phase-4 server has no streaming header parser and no test or
bench exercises it, so this is a documented limitation, not a
regression of a supported path. The proper fix lives with the
Phase-4 streaming parser (already an "Out of scope" bullet).

**Tests.** Four `body_reader_tests` added to `http_test`
(now 17 tests): prebuf `data()` zero-copy view, prebuf
`into_owned()` heap copy, the prebuf trim to `Content-Length`, and
the `NullStream` past-prebuf EOF case. They drive `chunk` through a
minimal single-poll executor — the prebuf path and the inherited
`NullStream::recv_chunk` `-> None` default both resolve without
suspending. The transport-`recv_chunk` source needs a live backend
and is exercised by `test_hvf` (which, with `/discard` on the new
path, now runs body bytes through it live).

Verified per commit: `bazel build
//apps/webserver:webserver_qemu_x86_64`; `bazel build
//apps/webserver:webserver.elf
--platforms=//bazel/platforms:aarch64_waitless`; `bazel test
//crates/proto/http:http_test //apps/webserver:test_hvf` (TCP + TLS
round-trips, 30-conn burst); plus `tls_test` on the proto/tls
commit.

**Perf — same-session A/B, `main` vs item H, HVF 1c/3c** (the
`--env hvf --cores 1,3` protocol). Item H is the first item with a
real win, so the A/B matters: a 3-round **interleaved** sweep
(`main`, item H, `main`, … — alternation cancels monotonic host
drift), 3 medians each:

| Workload | `main` 1c/3c | item H 1c/3c | Δ 1c/3c |
|---|---|---|---|
| `get_tcp` (control) | 199.4 k / 194.4 k | 211.6 k / 194.9 k | +6.1 % / +0.2 % |
| `get_tls_fresh` (control) | 2939 / 7587 | 2779 / 7473 | −5.4 % / −1.5 % |
| `upload_32k_tcp` | 21.6 k / 40.0 k | 24.5 k / 40.4 k | **+13.6 %** / +1.2 % |
| `upload_32k_tls` | 4853 / 12.6 k | 4866 / 12.6 k | +0.3 % / +0.5 % |

(A separate 3-run non-interleaved sweep agreed: `upload_32k_tcp` 1c
+14.5 %, `upload_32k_tls` 1c +1.1 %. A later same-host A/B of
`upload_1m_tcp` — 3-run medians, `4327a15` vs `main` — read
**+12.9 %** 1c / +2.2 % 3c: the win holds across upload sizes, as
expected for a steady-state per-chunk effect.)

Reading the numbers honestly:

- **`upload_32k_tcp` 1c +13.6 % — on HVF.** Bigger than a pure
  memcpy count predicts: `recv_chunk`'s item-F stash path moves a
  single-part in-sequence segment's device buffer *straight into
  the chunk*, skipping **both** the `tcp_receive`→`rx_ring` copy
  and the old `rx_ring`→`refill` copy. Reproducible across all
  three interleaved rounds. **But this is HVF-path-specific** — the
  GCE checkpoint below shows it does *not* carry over to real
  gVNIC hardware, where the `upload_32k_tcp` bottleneck is not the
  memcpy item H removed.
- **`upload_32k_tls` 1c +0.3 %** — essentially flat, *below* the
  table's `+10–20 %` budget. This is the honest finding: the TLS
  body path is **AEAD-decrypt-bound, not memcpy-bound**. `recv_chunk`
  surfaces a `Borrowed` view of `pt_buf` (AEAD must always decrypt
  *into* `pt_buf`), so item H removes exactly one ~16 KiB
  `pt_buf`→`refill` copy per request — at ~4.9 k req/s ≈ 80 MB/s of
  cache-hot memcpy, ~0.5–1 % of a core against the ChaCha20-Poly1305
  decrypt that dominates. The `+10–20 %` budget was optimistic; the
  win is real but small. Item H still achieves end-to-end zero-copy
  on the TLS body path — the bench just shows where the TLS
  bottleneck actually is.
- **`get_tcp` (control) +6.1 % @1c** — exceeds the ±3 % control
  band, favourably. Candidate explanation: `BodyReader` is
  constructed per request (GET included), and Phase-1's
  `BodyReader::new` zero-initialised the 4 KiB `refill` array every
  time; dropping the field removes a 4 KiB `memset` per request.
  But the GCE checkpoint below measured this same control at only
  +2.8 % @1c (inside ±3 %), so the HVF +6 % is mostly host
  artifact — the `memset` removal is real but its throughput
  effect sits inside the noise. Either way no regression: the GET
  path is byte-identical bar the dropped field.
- **`get_tls_fresh` (control) −5.4 % @1c / −1.5 % @3c** — within
  the noise envelope for this workload. No code path item H touches
  can systematically slow a TLS *handshake* (the body path runs
  after it); `get_tls_fresh` is a documented-noisy small-N crypto
  workload (item G's entry recorded a −6 % cross-session phantom on
  it), and the 3c reading sits inside the ±3 % band. The −5 % @1c
  is host noise.

**GCE checkpoint — done, and it overturns the headline.** The
nested-KVM `gcp-bench.sh --env kvm` path hit the documented
`SKIP (not ready)` failure (see `docs/benchmarking.md`), so the
checkpoint ran via `gcp-deploy-bench.sh` — the unikernel as the
real `waitless-webserver` GCE VM over gVNIC (**Tier 1**), loadgen
on `kvm-vm`. Same-session A/B, baseline `4327a15` vs `main`, 2 runs
per side (means):

| Workload | base 1c/3c | item H 1c/3c | Δ 1c/3c |
|---|---|---|---|
| `get_tcp` (control) | 186.5 k / 438 k | 191.7 k / 444 k | +2.8 % / +1.4 % |
| `get_tls_fresh` (control) | 4945 / 9337 | 4808 / 9237 | −2.8 % / −1.1 % |
| `upload_32k_tcp` | 44.3 k / 64.0 k | 44.6 k / 64.2 k | +0.7 % / +0.3 % |
| `upload_32k_tls` | 41.0 k / 63.0 k | 43.6 k / 62.8 k | +6.4 % / −0.2 % |

**The HVF `upload_32k_tcp` +13.6 % does not reproduce on GCE** —
+0.7 % at 1c, inside the ~10 % run-to-run spread (the two item-H
runs straddled the baseline). `upload_32k_tls` 1c reads +6.4 %, but
at n = 2 with comparable spread that is not separable from noise.
Every control sits within ±3 %; no regression anywhere. The plan's
"After H" expectation — `upload_32k_tcp` 1c ~51 k → ~62 k, the
threshold table's `+15–25 %` budget — **did not hold**: the GCE
baseline measures ~44 k, not 51 k, and item H moves it by noise.

Why the HVF/GCE divergence: HVF's RX path is virtio-net through a
*userspace* TCP proxy on the Mac host, where the guest-side memcpy
item H removes is a real fraction of a software path. GCE's gVNIC
is hardware DMA + the DQO descriptor ring. This entry's first cut
*hypothesised* that on a fast NIC the per-conn `rx_ring` is rarely
empty when `BodyReader` polls, so `do_recv_chunk` mostly takes the
copying ring-drain *fallback* rather than item F's zero-copy
*stash*. **The follow-up `/stats` instrumentation refuted that** —
see the 2026-05-17 verification entry below: the stash fires
**~52 %** of the time on GCE, edging out the fallback. The real
reason item H is flat on GCE is simpler: the `upload_32k_tcp` path
is **not memcpy-bound** — eliminating the copy for even half the
chunks stays inside run noise; the bottleneck is the NIC/DQO +
TCP-stack work. The GCE controls also confirm the HVF control
swings (`get_tcp` +6 %, `get_tls_fresh` −5 %) were mostly host
artifact.

So item H lands the end-to-end zero-copy body *architecture* —
correct, the 4 KiB `refill` scratch gone, no regression on either
host — but on real GCE hardware it is **perf-neutral**, not the win
the plan budgeted. The threshold table's `upload_32k_*` "after H"
budgets and the "After H" GCE-checkpoint expectation are corrected
in place. Caveats on the GCE figures: 3c upload is client-bound
(`cli` ≥ 70 % of the loadgen host — not load-bearing), and n = 2
runs per side is below the 3-run protocol — but the effect is
smaller than the run-to-run noise regardless, which is itself the
conclusion.

Next: item I (multi-buf RX chain accumulation in DQO), then item J
(enable RSC) — the genuine throughput items. RSC cuts per-packet
overhead, which *is* on the GCE upload critical path (unlike the
memcpy item H removed). The `recv_chunk` stash already fires ~52 %
of the time on GCE (verification entry below), so I/J's payoff
there is the per-packet-overhead reduction, not more stash hits.

### 2026-05-17 — Follow-up: universal `recv_chunk`, `tcp_echo` zero-copy, `/stats` verification ([x] **landed** — commits `5781f9a`, `eb4a029`, `fd41463`, `34d31f8`)

Not a numbered plan item — the `tcp_echo`/`gateway` zero-copy
follow-up flagged after item H, plus the `/stats` instrumentation
that settles item H's GCE question.

**Native `do_recv_chunk`** (`5781f9a`). Item F left the native
backend's chunk hooks `None`, so `TcpStream::recv_chunk` resolved to
`None` on native — and `None` is also the EOF signal, so a handler
could not tell "no chunk path" from "peer closed". That blocked
migrating any handler off the fill-buffer `recv`. Native now
implements `do_recv_chunk`: a POSIX `recv` into a heap buffer,
surfaced as a `Heap` `IOBuf`. Native still pays the one
syscall-boundary copy `do_recv` always paid — but `recv_chunk` now
resolves to a real chunk on **every** backend, so handlers get one
uniform API with no `recv` fallback. This is step 1 of deprecating
the non-zero-copy `recv`.

**`tcp_echo` zero-copy** (`eb4a029`). The first app handler to use
the guard's `into_owned()` escape hatch — the stream-to-stream
proxy zero-copy path the "Scaling behavior" section names as the
load-bearing reason for the owned-IOBuf guard, but which nothing
demonstrated. `recv_chunk()` → `into_owned()` → `IOBufChain` →
`send`; on bare-metal the `ExternalOwned` NIC RX buffer flows
RX→TX→repost with no intermediate copy (vs the old `recv` into a
stack buf + `send_bytes` — two copies).

`gateway` was **not** migrated: its `recv_exact` fixed-frame
(`GATEWAY_MSG_SIZE`) semantics need chunk reassembly — re-adding a
copy — and its UDP leg cannot go zero-copy until item L. Migrating
it would add copies, not remove them.

**`tcp_echo` HVF A/B — payload-size-dependent.** Baseline
(`2c4a864`, `recv`+`send_bytes`) vs the migration, HVF 1c/3c,
3-round medians via a baseline worktree:

| | base 1c/3c | zero-copy 1c/3c | Δ |
|---|---|---|---|
| `tcp_echo` (64 B msg) | 157.3 k / 183.1 k | 157.2 k / 178.8 k | −0.1 % / −2.4 % |
| `tcp_echo_64k` (64 KiB) | 3156 / 4814 | 4641 / 6940 | **+47 % / +44 %** |

At **64 bytes** the migration is flat: the copy it removes is 64
bytes, negligible against per-round-trip overhead. At **64 KiB**
it is +47 % (1c) — zero-copy wins are **payload-size-dependent**,
they bite at KB scale, not tiny messages. (Honest caveat: the
+47 % is the migration's *combined* effect — zero-copy RX *plus*
moving transport-sized chunks instead of the old handler's
artificially small 1 KiB stack buffer; both are real gains it
delivered, not pure memcpy elimination. And it measures the RX
half only — TX is still a copy until Phase 5.) The 64 B and
64 KiB workloads are registered as `tcp_echo` / `tcp_echo_64k`
(commit `f655f77`); `msg_size` is now a per-workload field.

**`/stats` verification — the headline result.** New `net::tcp`
counters `RX_CHUNK_STASH_HITS` / `RX_CHUNK_RING_DRAIN` (`fd41463`),
surfaced at `/stats` as `rx_chunk_stash_hits` / `rx_chunk_ring_drain`,
count the two `do_recv_chunk` paths: the zero-copy device-buffer
*stash* vs the copying *ring-drain* fallback. Deployed to the real
`waitless-webserver` gVNIC VM, ran `upload_32k_tcp`, read `/stats`:

```
rx_chunk_stash_hits  = 3_891_009   (52.0 %)
rx_chunk_ring_drain  = 3_589_149   (48.0 %)
```

**This refutes the item-H entry's hypothesis.** That entry reasoned
the ring-drain fallback *dominates* on GCE (segment bursts keeping
the ring non-empty). It does not — the zero-copy stash fires ~52 %
of the time, slightly *more* than the fallback. So zero-copy *is*
in place and firing on GCE for the majority of body chunks. Item H
was flat on GCE not because the stash misses, but because the
`upload_32k_tcp` path is genuinely **not memcpy-bound**: removing
the copy for half the chunks stays within run noise. The counter
was worth adding precisely because it overturned a plausible —
but wrong — story; the item-H GCE paragraph above is corrected to
match.

**Deprecating the non-zero-copy path — assessment.** `recv` is
deprecatable for proxy/echo handlers *now* (native `do_recv_chunk`
unblocked it; `tcp_echo` is migrated). It is **blocked for
`serve_conn`** until the Phase-4 streaming HTTP header parser —
`serve_conn` needs a contiguous parse buffer, `recv_chunk` delivers
discontiguous chunks. The ring-drain copy inside `do_recv_chunk` is
**never** deprecatable: the per-conn `rx_ring` is a structural
backpressure buffer (the math forbids IOBufs in it). Full `recv`
removal is a Phase-4 endgame.

Verified: `webserver_qemu_x86_64` + `webserver.elf` aarch64 builds;
`test_hvf`; `http_test`; native backend compile via
`tls_test`. GCE VMs stopped after the run.

### 2026-05-18 — Follow-up: shared `TaggedTreiberStack` ([x] **landed**)

The "Extract a shared `TaggedTreiberStack`" near-term follow-up.
`IOBufPool` ([`util/iobuf/src/pool.rs`](../util/iobuf/src/pool.rs)) and
`RxNodePool` ([`kernel/src/rx_inbox.rs`](../kernel/src/rx_inbox.rs))
each carried a byte-identical ~40-line copy of the tagged-pointer
Treiber free-list. Both now delegate to one audited copy — two
independent copies of subtle lock-free code collapse to one.

**New crate** [`util/tagged_treiber`](../util/tagged_treiber) — a
zero-dep `core`-only leaf crate, à la `util/atomic_fn`. It exports
`TaggedTreiberStack` (the `AtomicU64` head word + `push` / `pop` CAS
loops + `pack` / `unpack` + the version-bump-on-push ABA defence)
and the `NULL_INDEX` sentinel.

**Generic over the next-link accessor.** The two pools differ only
in where they store `next` links — `IOBufPool` in a dedicated
`Box<[AtomicU32]>` array (kept apart from slab payload), `RxNodePool`
in a per-node field. The stack stays storage-agnostic via a
one-method `TreiberLinks` trait (`fn next_link(&self, idx: u32) ->
&AtomicU32`); each pool implements it. The calls monomorphise per
consumer — no dynamic dispatch on the RX hot path.

**A faithful extraction, not a redesign.** Every memory ordering is
preserved byte-for-byte: head load `Acquire`, `next` link load/store
`Relaxed`, pop CAS `Acquire`/`Relaxed`, push CAS `Release`/`Relaxed`.
The one deliberate code-motion: the `free_count` observability
counter — and `IOBufPool`'s `leaked` counter — stay pool-side. They
are `Relaxed`, eventually-consistent, and not load-bearing for
lock-free correctness, so they fall outside "the stack *core*". The
per-op `free_count` bump consequently moves from inside the stack's
CAS-success branch to just after the `push` / `pop` call —
observationally identical, since nothing synchronises on a `Relaxed`
counter.

**Stress.** The new crate gets its own 8-thread ABA stress test,
ported from `iobuf_test` / `rx_inbox_test`: a tiny stack hammered by
8 threads × 20 000 iterations, then a post-run drain asserts every
slot came home distinct. Its `rust_test` uses the `tests_need_std`
wrapper from `//bazel/rules:rust.bzl`. Both pools' existing stress
suites — each with its own 8-thread Treiber test — still pass
unchanged against the shared implementation.

Verified: `bazel test //util/tagged_treiber:tagged_treiber_test
//crates/util/iobuf:iobuf_test //kernel:rx_inbox_test`; `webserver_qemu_x86_64`
+ `webserver.elf` aarch64 builds; `test_hvf`.

### 2026-05-18 — Follow-up: fuse the Tier-2 classify parse ([x] **landed**)

The Tier-2 distributor parsed every frame's L2/L3 headers **twice**:
`classify_for_distribution` walked eth → IPv4 → L4 ports to pick an
owning core and discarded the parse; `net_receive` then re-parsed
eth + IPv4 on the receiving core. `arp_learn` fired in both — the
shadow cost of software distribution standing in for the hardware
RSS Tier 1 gets free.

**Parse once.** A new `net_types::ParsedL3` (proto, src/dst `IpAddr`,
L4 `(off, len)`, on-subnet sender MAC) is built once by `parse_ipv4`
and carried to the receive path — on the cross-core inbox node for a
distributed frame (`percpu::RxChain` is now `{ parsed, chain }`),
directly for an `InlineParsed` same-core frame. The receiving core
reaches `tcp_receive` / `udp_receive` through `net_receive_parsed`
with no eth/IPv4 re-walk. The TCP-header parse in `tcp_receive` stays
— it needs seq/ack/flags/window, which `classify` never previewed.
`net_receive` (single-core / Tier-1 / ARP+IPv6 inline) funnels its
own IPv4 frames through `net_receive_parsed` too, so arp-snoop + L4
dispatch has one implementation.

**`arp_learn` fold.** `arp_fast_store` is per-core, so the snoop must
run on whichever core handles the frame. `classify` now learns only
for *distributed* frames (warming the distributor core, as before);
`net_receive_parsed` learns on the handling core. The pre-fuse inline
duplicate — `classify` + `net_receive` both snooping the same core —
is gone. `ParsedL3.arp` carries the on-subnet sender MAC for the
owning core's own snoop. A non-TCP/UDP IPv4 frame still parses and
still snoops; only `dispatch_l4` no-ops on the protocol.

`ParsedL3` lives in `net_types` (the zero-dep leaf) so `percpu.rs`
can name the `RxNode` payload type; `//kernel` gains an acyclic
`//net:types` dep.

**Bench.** A/B vs `a60a267`. QEMU TCG (Tier 2 — the mandatory path,
since HVF never runs `distribute_frame`), 5-round interleaved: 3c
`get_tcp` / `echo_udp` flat-to-positive, no collapse — but TCG on a
shared host was too noisy for a precise small-delta read (controls
swung ±10–30 %). HVF (Tier 1, steady hardware), 3-round interleaved,
settles it: `get_tcp` +0.3 % (1c) / +0.4 % (3c), `echo_udp` −0.4 % /
−0.0 % — the `net_receive` refactor is neutral, and a transient
QEMU-1c dip was pure TCG noise (the single-core path does provably
identical work). The fuse's gain — one eth + one IPv4 parse saved per
distributed Tier-2 frame — is real but below the measurement noise
floor: a remove-redundant-work change, not a measurable win at
request scale.

Verified: `webserver_qemu_x86_64` + `webserver_qemu_aarch64` builds;
`test_hvf`; `//kernel:rx_inbox_test`.

### 2026-05-18 — Item M: TCP/IP RX path accepts coalesced super-segments ([x] **landed**)

The shared TCP/IP-stack precondition for both RX-offload tracks —
gve RSC (items I + J) and virtio-net large-receive (N + O). An
audit-and-tighten item: nothing delivers a coalesced super-segment
today, so M is behaviour-neutral; it makes the stack *accept* one so
items I / N can later build big chained super-segments without the
stack mis-framing or truncating them.

**The one fix — the L3 parse.** `ipv4_receive` / `ipv6_receive` are
handed only part 0 of the RX chain (the buffer carrying the
L2/L3/L4 headers). A coalesced super-segment is one IP packet whose
declared length — IPv4 `total_length` / IPv6 `payload_length`, each
a 16-bit field, so ≤ 65535 — legitimately outruns part 0; the rest
rides in later chain parts. Both parsers rejected `declared >
data.len()`, which dropped *every* super-segment. Relaxed to a
clamp: the part-0 payload view is bounded by the bytes physically
present, and `tcp_receive` walks the rest of the chain. For an
ordinary single-buffer frame `declared <= data.len()`, so the clamp
is a no-op and ethernet trailing padding is still trimmed — the
behaviour-neutral property. The header-length bound the removed
check implied (`header_len > data.len()` for v4; `try_ref_from`'s
≥ `HEADER_LEN` guard for v6) is kept explicit so the payload slice
stays in bounds.

**`tcp_receive` — audited, already correct, zero changes.** Item D
left it chain-aware: `payload_len` is `segment.total_len()` (the
chain's *logical* length, summed across parts for a `Many` repr) −
`data_offset`, never MSS-clamped; the copy path walks `segment
.iter()` over every part, skipping the TCP header then
`deliver_payload`-ing each part's bytes; `rcv_nxt` advances by the
full delivered count. The zero-copy `pending_chunk` fast path is
gated on `part_count() == 1`, so a multi-part super-segment
correctly falls through to the chain walk. The FIN check uses the
same full `payload_len`. (`deliver_payload` truncates to the
receive window's free space and `rcv_nxt` advances only by what was
accepted — correct TCP, not an M bug: a properly coalesced
super-segment is bounded by the `rcv_wnd` we advertised, ≤
`RX_RING_BYTES − 1` = 16383, which the peer respects, so the ring
holds it.)

**`tcp_receive_segment` — the `Many`-chain `total_len` refresh is
item I's, not M's.** It narrows part 0 via `front_mut`, which
bypasses a `Many` chain's cached `total_len`. With the L3 clamp the
narrow is correct *for part 0* (`l4_len` is now part 0's L4
remainder, so the narrow consumes only the header bytes), but the
cached `total_len` would be stale by `l4_off`. M never delivers a
multi-part chain, so the existing `debug_assert_eq!(part_count(),
1, …)` tripwire never fires; the doc comment already assigns the
chain-aware narrow + `shrink_total_len` to item I.

**Fixed-size RX staging — audited, clean.** No `[u8; 1514]` /
`[u8; 1500]` on the receive path: item C removed the cross-core
inbox's; every remaining `1500`/`1514` array (`ethernet.rs`,
`ipv4_send`, `ipv6_send`, the ICMPv6 echo-reply builder, `tcp.rs`'s
`FRAME_BUF_LEN`) is a TX-side frame builder. The per-conn 16 KiB
`rx_ring` is a flow-control window, not an MTU buffer.

**Tests.** `ipv6_receive` gains a host-native super-segment test
exercising the real function (`net_ipv6` is a host-buildable leaf);
`protocol_tests` gains the IPv4 mirror. The old IPv6
`rejects_truncated_payload` test asserted the very reject M removes,
so it is repurposed (`accepts_coalesced_super_segment_length`) and
paired with `rejects_too_short_for_header` to pin the header guard
that the clamp still relies on.

**Not landed — the `tcp_receive` super-segment unit test (host-test
blocker).** Feeding `tcp_receive` a synthetic multi-part chain needs
`tcp` host-buildable, and `tcp` → `//kernel`, which is
hard-marked `target_compatible_with = ["@platforms//os:none"]`
(mach-o-hostile `#[link_section(".boot_bss")]`, MMU / APIC / IDT
code). That is exactly the blocker the "Test & bench infrastructure"
follow-up records — making `//kernel` host-buildable by `#[cfg]`-
gating its bare-metal bits is a substantial, separate effort, not an
M-sized tightening, so per the "report structural findings rather
than force them" guidance it stays with that follow-up. `runtime/executor`
is already host-buildable; `//kernel` is the remaining gate. Until
then the M change is covered by the two L3-parse tests above plus
the `tcp_receive` audit; the chain-walk itself is item D's code and
is exercised end-to-end by `test_hvf`.

Verified: `bazel build //apps/webserver:webserver_qemu_x86_64`;
`bazel build //apps/webserver:webserver.elf
--platforms=//bazel/platforms:aarch64_waitless`; `bazel test
//apps/webserver:test_hvf`; `bazel test //net:ipv6_test
//net:protocol_tests`.

### 2026-05-18 — Follow-up: `net` RX-pipeline refactor + IPv6 Tier-2 distribution fix ([x] **landed** — commits `c22e84d`, `a0a2f92`)

`crates/net/stack/src/lib.rs` had grown to 1028 lines holding four unrelated
concerns (backend wiring, the Tier 1/2 poll scheduler, the receive
pipeline, the IPv6 control plane), and the receive path itself was
*two* entangled pipelines: the Tier-2 distributor (`distribute_frame
→ classify_for_distribution`) looped **back** into the Tier-1 entry
(`net_receive`) for ARP and IPv6 via an `InlineReparse` verdict — a
call cycle, not a layered stack. The consequence was a latent bug.

**Pass 1 — module split (`c22e84d`).** Pure code motion: `lib.rs`
(1028 → 113 lines) keeps the crate root (backend vtables,
`init_stack`, bring-up, `pub use`); `sched` owns the poll scheduler;
`rx` the receive pipeline; `ipv6_nd` the IPv6 control plane. No
behaviour change — it makes pass 2 a pure-logic diff.

**Pass 2 — pipeline merge (`a0a2f92`).** The receive path collapses
to one shape, three verbs: `classify` (eth + L3 parse, once, IPv4
and IPv6 alike → `Classified::{Arp, Ip(ParsedL3), Drop}`, pure),
`owner` (Tier-2-only flow-hash → owning core), `deliver` (snoop +
L4 dispatch on the owning core). `net_receive` and `distribute_frame`
become thin tier adapters; `classify_for_distribution`,
`net_receive_parsed`, `dispatch_l4`, `ipv6_receive_frame`, and the
`InlineReparse` verdict all fold away. The cycle is gone.

**The bug this fixes.** Under `InlineReparse`, an IPv6 TCP segment in
Tier 2 ran on whatever core was the current rotating distributor —
*not* the flow-hashed owning core. `tcp_receive`'s per-core
connection pool would then miss any segment landing on a different
distributor than the one that handled the SYN: IPv6 TCP could not
complete a handshake under Tier-2 multi-core. It was masked because
GCE (the Tier-2 deployment) has no IPv6 subnet and IPv6 is otherwise
HVF-only (Tier 1, where the NIC's RSS keeps a flow on one core).
Post-merge, IPv6 flows through the same `classify`/`owner` path as
IPv4, so it is flow-distributed to a consistent owning core.

Supporting changes: `ParsedL3.arp` → `snoop_mac` (the field is
family-neutral — ARP cache for v4, NDP cache for v6 — only the name
was IPv4-specific); `ipv6_nd::handle_icmpv6` takes
`(src, dst, payload, src_mac)` so `deliver` dispatches ICMPv6 by
protocol number; `flow_hash` (IPv4) kept byte-identical so the GCE
bench is a true A/B control, with `flow_hash_v6` folding the 16-byte
addresses into the same FNV-1a + fmix32.

Verified: `webserver_qemu_x86_64` + `webserver.elf` (aarch64)
builds; `test_hvf`, `test_mc_hvf` (Tier-1 multi-core),
`test_qemu_x86_64`; `bench.py --env qemu --cores 3` get_tcp
(Tier-2 functional — 47 k req/s, no collapse); `//net:ipv6_test`,
`//net:protocol_tests`. GCE Tier-2 (`gcp-bench.sh --env kvm`,
KVM/virtio multi-core) `get_tcp` 1c/2c/3c = 225 k / 341 k / 386 k
req/s — positive scaling, p50 122–223 µs, confirming the rewrite is
perf-neutral on real Tier-2 hardware.

The `classify` verdict has no host-native unit test: `classify`
lives in `net_stack`, whose `os:none` dep chain (`//kernel`)
blocks a `rust_test` — the same blocker recorded for item M's
`tcp_receive` test and the "Test & bench infrastructure" follow-up.
IPv6 Tier-2 correctness rests on `ipv6_receive` being host-tested
(`//net:ipv6_test`) plus the shared distribute path being exercised
by IPv4 on QEMU-multicore and GCE — unification makes the two halves
compose.

### 2026-05-19 — Investigation: Tier-2 `RX_LOCK` hold — "option (1)" measured and rejected

**The question.** `sched::poll_tier2` holds `RX_LOCK` across the whole
`poll()` batch, and for every frame the distributor *owns*
(`rx::distribute_frame`) it runs `deliver` → `tcp_receive` **inline,
under the lock**. Frames owned by *other* cores are pushed to their
`rx_inbox` and delivered lock-free in `net_drain_cb`. Would moving the
owned-frame delivery off the lock too help? "Option (1)": push *every*
frame — own ones included — into its owning core's inbox; the
distributor then drains its own inbox via `net_drain_cb` after
releasing the lock. The distribution pass (classify + inbox push)
stays locked, so per-inbox FIFO order is preserved; only L4 delivery
moves out.

**Measurement.** A temporary probe instrumented the distributor —
`RX_LOCK` hold cycles, the inline-deliver share of the hold, frames
per distribution, owned/distributed split. Two findings reshaped the
approach:

- **TCG cannot answer this.** Local QEMU-TCG showed **0.8 frames per
  lock acquisition** — frames trickle in one at a time, so the
  distributor never builds a batch. GCE KVM showed **~24 frames per
  acquisition**: real hardware pipelines, the RX ring accumulates a
  backlog, and one `poll()` drains it as a batch. The whole question
  is about batched work under the lock; TCG's serialization erases the
  batching, so its numbers (inline ≈ 20% of hold) are unrepresentative.
- **`gcp-bench.sh --env kvm` runs Tier 1, not Tier 2.** QEMU's
  virtio-net on the GCE host negotiates modern virtio + multi-queue,
  the guest activates per-cpu queue pairs (`num_queue_pairs() == 3`),
  and `distribute_frame` never executes. Entries above that call
  `--env kvm` "GCE Tier-2" are mislabelled — that path is Tier 1.
  Exercising Tier 2 on GCE needs a single-queue device (drop `mq=on`
  from the `-device virtio-net-pci` line; the netdev tap keeps its
  queues so QEMU can still open the `IFF_MULTI_QUEUE` tap0).

GCE-KVM **Tier-2** baseline (`get_tcp`, 3 cores, single queue): inline
`tcp_receive` is **~38% of the `RX_LOCK` hold**; mean hold ~58 µs, max
~697 µs; the lock is held ~61% of wall-clock under load.

**A/B.** Option (1) was implemented and benched against the baseline
— 3 interleaved rounds, GCE KVM Tier-2, `get_tcp` 3c:

| metric | baseline | option (1) |
| --- | --- | --- |
| throughput (mean of 3) | 252.6 k req/s | 238.8 k req/s — **−5.4%** |
| p50 (mean of 3) | 363 µs | 385 µs — **+6%** |
| mean `RX_LOCK` hold | ~58 µs | ~32 µs — −45% |
| max `RX_LOCK` hold | 697 µs | 207 µs — −70% |

Every one of the 3 baseline runs beat every option-(1) run on both
throughput and p50 — the two distributions do not overlap.

**Verdict — rejected; inline delivery stays.** Option (1) did exactly
what it was designed to do — the lock hold dropped 45%, the worst-case
hold 70% — and **still lost 5%**. The `RX_LOCK` hold was never the
bottleneck: shortening it bought nothing, while the inbox round-trip
it adds for the ~40% of frames the distributor owns cost ~5%
throughput and ~6% p50. "Inline delivery is 38% of the hold" is true
but irrelevant — relocating work no core is blocked waiting on cannot
help; only the A/B could establish that, no counter or ratio could.

If Tier-2 RX ever does warrant attention, the lever is **not** the
lock hold. It is either the single-queue serialization itself (the
"RX scheduler — unify the tier model" follow-up above) or the
recognition that Tier 2 is a fallback regime — a multi-queue NIC runs
Tier 1 and never takes `RX_LOCK` at all.
