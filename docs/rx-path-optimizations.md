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

> **See also:** [`high-concurrency-perf.md`](high-concurrency-perf.md)
> for the high-conn cliff investigation. Items I + J + M–O below
> are P0 on that doc's gap list — RX coalescing is the biggest
> remaining lever on `cycles/request` past the data-structure
> work shipped in `bench/pareto-rig`.
>
> **See also:** [`stack-architecture.md`](stack-architecture.md) for
> the inter-layer API/contracts lens (peer to this doc). It owns the
> stream trait + `recv_chunk`-guard contract that items F/G/H build
> on, the buffer currency, and the UDP `IOBuf` inbox of item L.

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
| 3 | Cross-core inbox push | [`kernel/src/percpu.rs:115`](kernel/src/percpu.rs#L115) | **0** (item C; was 1× on the multi-core path) | `distribute_frame` *moves* the `Chain<OwnedIOBuf>` into the target core's intrusive `RxNode` inbox — no `[u8; 1514]` frame copy |
| 4 | TCP fast path (parked recv) | [`net/src/tcp.rs:331`](net/src/tcp.rs#L331) | **1× memcpy** | `ptr::copy_nonoverlapping` directly into user buf |
| 4'| TCP slow path (no parked recv) | [`net/src/tcp.rs:303`](net/src/tcp.rs#L303) | **1× memcpy** (into ring) + **1× memcpy** (out at recv) | Per-conn 16 KiB byte ring |
| 5 | HTTP header parse | [`proto/http/src/server.rs`](proto/http/src/server.rs) `serve_conn` + [`streaming.rs`](proto/http/src/streaming.rs) `StreamingRequestParser` | **0** | Parser reads chunk bytes in place off `recv_chunk`'s guard and writes parsed values straight into the per-conn `Request`; the 16 KiB inline parse buffer is gone. Leftover bytes ride forward in `carry: Option<IOBuf>` |
| 6 | BodyReader::chunk past prebuf | [`proto/http/src/body.rs`](proto/http/src/body.rs) `BodyReader::chunk` | **0** (item H) | `recv_chunk` surfaces the transport buffer behind a `BodyChunkGuard`; the 4 KiB `refill` scratch is gone |
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
| 1–4 | Same as TCP HTTP | (above) | 0 | Ciphertext flows through — `pump_rx` ingests via `recv_chunk` (the item-F zero-copy stash), and the cross-core push moves the chain (item C), so no guest-side ciphertext copy |
| 5 | TLS pump_rx takes the chunk | [`proto/tls/src/lib.rs`](proto/tls/src/lib.rs) `pump_rx` | 0 (in-place via TcpStream::recv_chunk) | No inline cipher_buf / rx_buf — the recv'd chunk is `into_owned()`'d (zero-copy for the NIC-RX buffer) and handed to `process_chunk` |
| 6 | AEAD decrypt | TLS state machine (`process_chunk`) | **1× R/W** (AES-128-GCM) + **0** (GCM tag verify is part of the same pass) | Decrypted **in place** — the chunk's ciphertext is overwritten with plaintext; no separate `pt_buf` |
| 7 | TlsStream::recv_chunk surfaces plaintext | [`proto/tls/src/lib.rs`](proto/tls/src/lib.rs) `TlsStream::recv_chunk` | **0** | The chunk is `share()`'d and each app-data record's plaintext range is queued as a refcount-shared `Owned(Shared)` view (`pending_plaintext`); the guard `into_owned()` is a no-op |
| 8 | HTTP / BodyReader past prebuf | [`proto/http/src/body.rs`](proto/http/src/body.rs) `BodyReader::chunk` | **0** (items G + H) | `recv_chunk` hands an `Owned(Shared)` view into the recv'd chunk's storage; the `refill` scratch is gone |

Active per-byte memcpys on **TLS RX** guest side: the fundamental
AEAD R/W only — items G and H removed both structural memcpys (the
old `pt_buf`→user buf copy and the BodyReader `refill`), and the
share-based plaintext queue (commit `5a8a74a`) since retired `pt_buf`
entirely by decrypting in place and refcount-sharing each record's
plaintext range. AEAD is unremovable without offloading crypto to a
co-processor. Note the TLS body path is therefore AEAD-decrypt-bound,
not memcpy-bound — see item H above.

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
AEAD. *Update:* the OOM hazard is now partly addressed in the QUIC
layer — RX reassembly is bounded by the flow-control window
(reorder bound = `recv_max`; `gap_budget` removed) and streaming
request/response bodies exist; see
[`quic-golden.md`](quic-golden.md) /
[`streaming-response.md`](streaming-response.md). This RX doc still
owns the TCP/TLS path.

## Items

### A. `IOBuf::into_owned()` + `IOBufPool` infrastructure — ✅ done (`180e29c`)
`IOBufPool` free-list is a tagged-pointer Treiber stack (ABA-immune); its `alloc()` drop_fn must stay panic-safe (leak + counter, never panic in a `no_std` `Drop`).

### B. NicOps RX callback delivers `IOBufChain` — ✅ done (`103202d`; counters `2579a13`)
Atomic `poll_qp`/`poll_rx` signature change across all three drivers + net dispatch. Costs a small *uniform* ~2% per-frame on the virtio fast path (sits below the GCE measurement floor); every driver's drop_fn must be panic-safe because it runs from `IOBuf::drop`, possibly cross-core. GQI copies into an `IOBufPool` slab (strict in-order repost forbids lending device QPL pages).

### C. RxInbox: intrusive-node cross-core inbox (zero-copy) — ✅ done (`dc5cc26`, `35b4aff`, `59121b4`)
**−1 memcpy/byte** on cross-core distribution (eliminates copy #3). Intrusive lock-free MPSC list, *not* a bounded ring — the abandoned bounded-ring first cut tail-dropped fresh TCP ACKs and collapsed `download_64k`; the landed pool is sized ≥ the RX queue's buffer count so the inbox provably never overflows (no drop counter). Do-not-redo: `used()` on the virtio descriptor free-list must stay under `rx_lock` (fix #1, the cross-core-drop race). The cleaner 1:1 `sk_buff`-style node lives as item K.

### D. `tcp_receive` takes a `Chain<OwnedIOBuf>` — ✅ done (`bdd15ce`, `e940a10`)
Pure plumbing, copy count unchanged (per-conn `rx_ring` stays `Box<[u8; 16384]>`; the 1500-conn × 11-buf math forbids IOBufs in the ring). Durable design facts: the chain is narrowed to the TCP segment via *pointer arithmetic* against `pkt.payload` (robust across IPv4 options + IPv6 ext headers), `narrow` not bare `consume` so ethernet trailing padding is trimmed (else a padded pure ACK desyncs `rcv_nxt`); and **one chain is one frame** — treat it as a unit, do not `pop_front`-split and re-dispatch parts (wrong for RSC: parts 1..N are payload continuation, not framed packets).

### E. Reject `Transfer-Encoding: chunked` with 400 — ✅ done (`8c2cb69`, `b98b499`)
Closes a request-smuggling hole (chunked body with no `Content-Length` was sized 0, then body bytes re-parsed as a pipelined request). Proper chunked decoding is deferred to Phase 4.

### F. `TcpStream::recv_chunk` API (guard-pattern) — ✅ done (`ae9e850`, `570e40a`)
The guard *return type* is load-bearing, not just convenience: `IOBuf` has no lifetime param, so a bare `Option<IOBuf>` would be borrow-unsafe on the TLS path (pump_rx could overwrite `pt_buf` under a held `Borrowed` view). `RecvChunkGuard<'a>` binds the IOBuf to `&'a mut self` so the compiler enforces ≤1 outstanding IOBuf per stream. The zero-copy "stash" path moves an in-sequence single-part segment's device buffer straight into `pending_chunk` while the ring is empty (so stash always holds the older bytes — ordering preserved without a sequence number); multi-part chains fall through to the copy path.

### G. `TlsStream::recv_chunk` — ✅ done (`a0c9acf`, `74357c6`)
Advances `pt_pos` *eagerly* on hand-out (not on guard drop): the guard holds `&mut self` for its whole life, so eager and on-drop advance are observationally identical and a cross-crate `Drop` hook is unnecessary. (Native-backend chunk hooks left `None` here were fixed in passing as `4d3dda2`.)

### H. `BodyReader::chunk` returns guard — ✅ done (`1e97350`, `ad85de4`, `91aa952`)
End-to-end zero-copy body delivery past the prebuf. The `HttpStream::recv_chunk` trait method has a **default `-> None`** body (load-bearing: `NullStream`/HTTP-3 inherits it and serves from prebuf). Measured **perf-neutral on real GCE gve hardware** — the HVF +13.6% on `upload_32k_tcp` did NOT reproduce; the path is NIC/DQO + TCP-stack-bound, not memcpy-bound, and the TLS body path is AEAD-decrypt-bound. The threshold table's `upload_32k_*` "after H" budgets were corrected to ±3%. Over-read residue (a transport chunk straddling `Content-Length`) is dropped on guard drop in the legacy `BodyReader::chunk` path — documented corner, not a regression.

### I. Multi-buf RX chain accumulation in DQO — ✅ done (landed as T4, see gvnic.md)
Per-qp `RxCoalescer`/`PENDING_CHAINS` stitches non-EOP completions, delivers on EOP, ~100ms stuck-chain timeout (`DQO_RX_PENDING_CHAIN_TIMEOUTS`).

### J. Enable HW GRO (RSC) on DQO_RDA queues — ✅ done (landed as T4, see gvnic.md)
`enable_rsc` byte set at `CREATE_RX_QUEUE` cmd-offset 58 (DQO only); c3-validated +14–19% upload RX. Safe only because items A–I land first; high risk standalone.

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

### M. TCP/IP RX path accepts coalesced super-segments — ✅ done (`b73b946`)
The shared precondition for both RX-offload tracks (I+J gve, N+O virtio). The one fix: `ipv4_receive`/`ipv6_receive` previously rejected `declared > data.len()`, dropping every super-segment; relaxed to a *clamp* of the part-0 payload view (no-op for ordinary single-buffer frames, so behaviour-neutral). `tcp_receive` was audited already-correct (chain-aware, `payload_len` never MSS-clamped). Caveat for item I: the `Many`-chain `total_len` refresh after the part-0 narrow is item I's to add (`shrink_total_len`); M only ever delivers single-part. Host test of `tcp_receive` blocked because `tcp → //kernel` is `os:none`-only.

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

A → B → C → D → E → F → G → H → I → J → M: **all done** (the IOBuf
threading layer-by-layer, the chunked-rejection guard, the gve DQO
RSC pair, and the shared TCP/IP-stack super-segment precondition).

**Remaining open work:**

- **K** (driver-delivered RX frame) supersedes item C's kernel node
  pool — can land any time; sequenced last only for its driver-wide
  blast radius (mandatory GCE checkpoint).
- **L** (UDP datagram inbox) is the UDP-side counterpart of items
  C–D; needs only B, can land any time after it.
- **N → O** (virtio-net large-receive): N (multi-buf reassembly,
  the virtio twin of I) first, then O (shrink the offload mask, the
  virtio twin of J) — O is high-risk standalone, gated on N. M is
  the shared precondition for N/O and is already done.

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
| `upload_32k_tcp` | 51 k / 72 k | ±3% (item H landed perf-neutral on GCE — the `+15–25%` budget did not hold; see item H above) |
| `upload_32k_tls` | 47 k / 70 k | ±3% (item H landed perf-neutral on GCE — the `+10–20%` budget did not hold; see item H above) |

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
  materialise; the win was HVF-path-specific (the path is NIC/DQO +
  TCP-stack-bound, not memcpy-bound — see item H and the progress
  log's durable-findings note on the ~52% stash hit rate).
- **After I** (multi-buf chain handling, RSC still off): full
  bench. Expected ±0%. `/obs`: `dqo_rx_compl_skipped` stays
  at 0; `dqo_rx_pending_chain_timeouts` stays at 0.
- **After J** (RSC enabled): full bench. `upload_32k_*` should
  rise. Controls unchanged. `dqo_rx_compl_skipped` may grow
  (chains delivered, not skipped); `RX_BUF_REPOST_COUNT` per qp
  must match `rx_frames` (sanity check on cross-core drop_fn).

### Observability counters introduced

Exposed via `/obs`:
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

**Large HTTPS payloads**: works. Each chunk decrypts in place and
its app-data records are queued as refcount-shared plaintext views
(`pending_plaintext`); the recv'd chunk's storage (a NIC RX slot)
is pinned only until the last queued view drops, and `pump_rx`
refuses to pull the next chunk until `has_plaintext()` is drained —
existing backpressure. CPU-bound at the AES-128-GCM decrypt rate.

## Out of scope / known limitations (Phase 4+)

- **Large HTTP/3 (QUIC) payloads**: proto/http3 reassembles all
  DATA frames before invoking the handler — OOMs on 100 MB
  QUIC POSTs. Fix is progressive DATA-frame delivery, mirroring
  the TCP/TLS path. Separate plan (see Follow-ups).
- **Streaming response bodies (large echo)**: `Response` is
  fully-buffered today. Echo-100-MB needs a streaming-source
  Response variant. Separate plan.
- **Streaming HTTP header parser** (DONE — `StreamingRequestParser`):
  byte-fed state machine writes parsed values directly into the
  per-conn `Request`; the 16 KiB inline parse buffer is gone (saves
  ~22 MB/core at fanout_tcp's 1500 conn/core). The prebuf memcpy on
  the body path is also gone — `carry` is an `IOBuf` that
  `BodyReader` reads from directly. Chunked-encoding support (item
  E) still rejects; a real implementation is separate Phase 4 work.
- **In-place TLS RX decrypt** (largely DONE — commits `0b537fd`,
  `5a8a74a`): the in-place-decrypt + zero-copy-`into_owned()` goal
  this item originally chased has landed. `process_chunk` now
  AEAD-decrypts each record **in place** in the recv'd chunk (the
  ciphertext is overwritten with plaintext), `share()`s the chunk,
  and queues each app-data record's plaintext range as an
  `Owned(Shared)` view (`pending_plaintext`); `TlsStream::recv_chunk`
  surfaces that view, so `into_owned()` is already a **no-op** — the
  `pt_buf`→user-buf copy and the `Borrowed`-into-`pt_buf` shape are
  both gone. The guard façade held: `recv_chunk` still returns
  `RecvChunkGuard`, only the wrapped payload changed (`Borrowed` →
  `Owned(Shared)`), exactly the non-breaking evolution this item
  predicted. What remains a limitation: a recv'd chunk stays pinned
  (its NIC RX slot held) until the *last* shared record view from it
  drops — coarser than per-record release — and a TLS record that
  straddles two recv chunks still copies through the `rx_partial`
  buffer (chunk-direct sharing only covers records wholly inside one
  chunk). Surfacing a multi-buffer record's plaintext as a
  fragment-granular `Chain` (per-fragment `narrow`, finer pinning)
  remains a `proto/tls` record-layer refinement, but the headline
  win (in-place AEAD, zero-copy `into_owned`) is no longer pending.
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
  `/obs`-style dashboards.
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

- **TCP conformance test harness** (DONE). The harness this item
  proposed has landed as
  [`crates/net/tcp/src/tests.rs`](../crates/net/tcp/src/tests.rs) —
  a packetdrill-in-a-unit-test built exactly as sketched: a mock
  `NicOps` (swapped via `set_active_ops()`) captures TX frames into a
  `Vec`, and scripted segments are driven into the real `tcp_receive`
  RX entry point with assertions on the captured output. The
  `os:none` dep-chain blocker was resolved (the crate is
  host-buildable for `cfg(test)`); ~60 scenarios run today. The
  receiver-side window-update bug (commit `171c68e`, found mid-item-B
  because a QEMU upload anomaly got chased into a packet capture)
  was its founding regression case. The **RTO / retransmit timer**
  the item flagged as missing has since landed too —
  [`crates/net/tcp/src/retransmit.rs`](../crates/net/tcp/src/retransmit.rs)
  implements RFC 6298 data/FIN retransmission, RFC 9293 §3.8.6.1
  zero-window persist probes, and the stalled-RX-consumer recovery
  (commit `ce562ff`); a lost outbound segment is now retransmitted,
  and the scenarios cover the rtx boundary-split / fast-retransmit
  corners. Remaining gaps are incremental coverage, not the
  structural hole this item named.

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

Items A–J + M and the early follow-ups (Phase-1 streaming `BodyReader`
`820a2e6`; util/iobuf type-model split `fb755a3`/`409b5dd`/`d8b4c1e`;
shared `TaggedTreiberStack` `util/tagged_treiber`; the Tier-2
classify-parse fuse; the `net` RX-pipeline module split + IPv6 Tier-2
distribution fix `c22e84d`/`a0a2f92`; native `do_recv_chunk` +
`tcp_echo` zero-copy + `/stats` stash/ring-drain counters `5781f9a`/
`eb4a029`/`fd41463`/`34d31f8`) all **landed** — their commit refs and
durable design facts are folded into the one-line ledger under
`## Items` above; the blow-by-blow narratives now live in git log.

A few durable findings worth keeping out of the ledger:

- **The `recv_chunk` zero-copy stash fires ~52% of the time on real
  GCE gve** (`/stats` `rx_chunk_stash_hits` ≈ 52% vs `rx_chunk_ring_drain`
  ≈ 48% on `upload_32k_tcp`). This refuted the hypothesis that the
  ring-drain fallback dominates on a fast NIC. Item H is flat on GCE
  not because the stash misses but because the path is **not
  memcpy-bound** — the ring-drain copy is never deprecatable (the
  per-conn `rx_ring` is a structural backpressure buffer).
- **Zero-copy proxy/echo wins are payload-size-dependent**: `tcp_echo`
  64 B msg is flat, `tcp_echo_64k` is +47% (HVF) — they bite at KB
  scale, not tiny messages. (RX half only; TX is still a copy until
  Phase 5.)
- **IPv6 Tier-2 distribution bug, fixed by the `net` pipeline merge
  (`a0a2f92`)**: pre-merge an IPv6 TCP segment ran on the rotating
  distributor core, not the flow-hashed owner, so a handshake could
  not complete under Tier-2 multi-core. Masked because GCE has no IPv6
  subnet (IPv6 is HVF-only = Tier 1). Post-merge IPv6 shares IPv4's
  `classify`/`owner` path.

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
