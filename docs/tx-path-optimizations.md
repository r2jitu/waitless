# TX path optimizations — tracker

A living plan for trimming the TX path between application-layer
encrypt and the wire. Covers both HTTPS-over-TCP and HTTPS-over-H3
(QUIC). Each item below is sized to land as one (or a small batch
of) commit(s); check items off as we ship them.

## Why this doc exists

We measured the per-byte guest-side memcpy count starting at **5
memcpys per byte** for HTTPS-over-TCP and **5 memcpys per byte** for
HTTPS-over-H3 (QUIC) (≈ 4.5 GB/s of memcpy traffic at 100 k rps for
a 9 KiB shell page). Most of those are mechanical header-prepend
memcpys that fall out of the way once the buffer is composed in
place. The encrypt step itself is a fundamental R/W and can only be
fused with the surrounding copy, not removed.

This doc captures the inventory, splits proposals across the two
segments the user named — *encrypt → NIC TX* and *network → browser
RX* — and tracks progress as we land them.

## Current path — TCP (HTTPS over TLS)

| # | Step | Site | Cost per byte | Cost per record | Notes |
|---|------|------|---|---|---|
| 1 | Handler renders body | `body_iobuf` writer | 1× memcpy (dynamic content only) | — | Static literals are zero-copy |
| 2 | Header build | `write_response_into_iobuf` | — | ~150 B memcpy | Into per-conn `header_storage` |
| 3 | **TLS coalesce** | `TlsStream::send` loop | **1× memcpy** | — | Chain → scratch (5 B head + 16 KiB plaintext + 17 B tail) |
| 4 | TLS encrypt + envelope | `seal_in_place` | 1× R/W (ChaCha20) + 1× R (Poly1305) | — | In place; header / type / tag written into scratch's reserved head/tail (item C ✓) |
| 5 | **TCP frame build** | `send_segment` / `send_segment_from_cursor` | **1× memcpy** | 14 + 20 + 20 B headers + 2 checksums | Cursor → one stack buffer with full [ETH][IP][TCP][PAYLOAD] (item A ✓) |
| 6 | ~~IPv4 wrap~~ | — | — | — | Folded into step 5 (item A ✓) |
| 7 | ~~Ethernet wrap~~ | — | — | — | Folded into step 5 (item A ✓) |
| 8 | **virtio-net submit** | `virtio_net::send` | **1× memcpy** | descriptor add + kick | → TX pool slot, then DMA |
| 9 | virtio host pickup | (HVF userspace_net or KVM) | depends on host | — | HVF: another memcpy to host TCP socket |
| 10 | Host TCP/IP/Eth | host kernel | host-side | — | TSO can fold this on real NICs |
| 11 | Wire | network stack | — | — | MTU, cwnd, RTT |
| 12 | Browser RX | TLS decrypt + HTTP parse | symmetric to ours | — | Out of our control |

Active per-byte memcpys on the guest side: **3** (steps 3, 5, 8) —
down from 5 before items A and C. Item B (virtio SG) targets
step 8 next.

## Current path — QUIC (HTTPS over H3)

| # | Step | Site | Cost per byte | Cost per packet | Notes |
|---|------|------|---|---|---|
| 1 | Handler renders body | `body_iobuf` writer | 1× memcpy (dynamic content only) | — | Same as TCP path |
| 2 | H3 frame encode | `uni-http3/src/*` | — | small `Vec::with_capacity` per frame | HEADERS / DATA / etc. |
| 3 | **QUIC packet encode** | `encode_one_rtt_packet` etc. (`uni-quic/src/conn.rs:2018+`) | **1× memcpy** | `Vec::with_capacity(1024)` for frames + `take_datagram_buf` (~1500 B, pooled with 62 B L2/L3/L4 headroom prefix after item Q) | Frame headers + STREAM data written into the datagram Vec; for 1-RTT packets writes directly (no temp staging Vec); Initial/Handshake still stage via temp `frames` Vec |
| 4 | QUIC AEAD seal | within `seal_packet` | 1× R/W (ChaCha20) + 1× R (Poly1305) | — | In place over the assembled packet bytes |
| 5 | `pop_packet_owned` | `uni-quic/src/endpoint.rs` | — (move) | — | Vec ownership transferred to the reactor |
| 6 | ~~UDP wrap~~ | — (item Q ✓) | — | — | Folded into step 3 — encoder writes packet bytes directly into the framing buffer's UDP-payload region; bare-metal `send_with_l2_headroom` fills UDP/IP/Eth headers in the pre-reserved headroom |
| 7 | ~~IPv4 wrap~~ | — | — | — | Folded into step 6 (item P ✓ and Q ✓) |
| 8 | ~~Ethernet wrap~~ | — | — | — | Folded into step 6 (item P ✓ and Q ✓) |
| 9 | **virtio-net submit** | `virtio_net::send` | **1× memcpy** | descriptor + kick | → TX pool slot |
| 10+ | Host pickup, host kernel, wire, browser | — | — | — | Same as TCP from this point on |

Active per-byte memcpys on the guest side: **2** (steps 3, 9) —
down from 5 before items A, P, and Q. Same as TCP after A. Item B
(virtio SG TX descriptors) targets step 9, dropping both paths to
**1 memcpy per byte** — the fundamental encoder write that can't
be removed without offloading AEAD to the NIC.

## Segment 1 — Inside the unikernel (TLS encrypt → NIC TX)

### A. Fold TCP/IP/Eth wrap memcpys into one buffer
- **Status**: [x] **landed 2026-05-08** (commits `bcf2e8d`, `e3c7e08`)
- **Result**: -2 memcpys per byte on the TCP TX hot path.
  Implementation built [ETH][IP][TCP][PAYLOAD] in one stack
  buffer in `tcp.rs` using new `fill_header` helpers in
  `ethernet.rs` / `ipv4.rs` / `ipv6.rs`, replacing the legacy
  `send_l3 → ipv4_send → ethernet_send` chain. Slow paths (UDP,
  ARP, ICMP) keep the layered functions.
- **Where**: `net/src/tcp.rs::send_segment_from_cursor`,
  `net/src/ipv4.rs::ipv4_send`, `net/src/ethernet.rs::ethernet_send`,
  `drivers/src/net.rs::send`.
- **What**: Today each layer allocates a stack buffer and `memcpy`s
  the payload to inject its header. Reserve 54 B of headroom on the
  TLS scratch IOBuf and have each layer `iobuf.prepend(&hdr)` in
  place. Final shape on the wire:
  `[ETH 14][IP 20][TCP 20][TLS 5][ciphertext...][type][tag]`.
- **Win**: -3 memcpys per byte. Same wire bytes; mostly mechanical.
- **Effort**: medium. Touches the L4/L3/L2 send signatures (each
  takes `&mut IOBuf` instead of `&[u8]`) and threads through to
  `drivers::net::send`.
- **Risk**: low. The IOBuf primitive already supports prepend; we
  just need the right amount of headroom plumbed from the top.

### B. Use virtio-net SG TX descriptors (TX pool as IOBuf source)
- **Status**: [ ] not started
- **Where**: `uni-driver-virtio-net/src/lib.rs::send`
  (the `ptr::copy_nonoverlapping` into `tx_pool` slot at line 1103).
- **What**: virtio-net supports multi-buffer (scatter-gather) TX
  descriptors. Re-shape the existing 64-slot `tx_pool` as a
  buffer pool that callers acquire from instead of `memcpy`'ing
  into. Each acquire returns an `IOBuf::External` wrapping a
  pool slot's `data` field, with reserved headroom for the
  virtio_net_header + the L2/L3/L4 stack. Caller fills in place;
  driver enqueues a descriptor pointing at the same storage
  (zero memcpy). Drop callback fires from `tx_drain_qp` when the
  device returns the descriptor — slot goes back to the pool.
- **Win**: -1 memcpy per byte on top of A and P. On Tier 1 (KVM,
  real NIC) this is the difference between "we copy data" and
  "the NIC DMAs from our buffers".
- **Side win**: today `send_on_qp` **busy-spins** when all 64
  slots are in flight (line 1070 — `loop { ... if found { break };
  flush_kick(); tx_drain_qp(); }`). Re-shaping acquire as
  IOBuf-borrowing makes it natural to return a future that
  parks until `tx_drain` frees a slot, instead of spinning.
  Lower priority but worth doing alongside.
- **Effort**: medium-high. Needs a TX completion path that drops
  the right IOBuf in `tx_drain_qp`, and the IOBuf has to survive
  across the descriptor's lifetime.
- **Risk**: medium. Subtle; needs careful audit of when the host
  is allowed to read the descriptor's referenced memory, and
  what happens if the IOBuf is dropped before the device
  returns the descriptor (must not happen — drop_fn is the
  pool-return).
- **Lays groundwork for**: G (TSO), Q (QUIC into framing buffer).

### C. Bake the record envelope into the scratch (no header/trailer allocs)
- **Status**: [x] **landed 2026-05-08** (commit `e6d9a28`)
- **Result**: -2 small Heap allocs per TLS record. `flush_record`
  now sizes the scratch as `[u8; 5 + 16384 + 17]` and routes
  through `send_app_data_iobuf` (which calls `seal_in_place`).
  Record header / type byte / tag all written into the scratch's
  reserved headroom + tailroom — no Heap IOBufs allocated.
- **Where**: `uni-tls/src/record.rs::seal_chain_in_place`,
  `uni-http/src/lib.rs::flush_record`.
- **What**: `seal_chain_in_place` allocates 2 small Heap IOBufs
  (5 B header, 17 B trailer) per record. Make the scratch
  `[u8; 5 + 16384 + 17]` — 16406 B — with reserved headroom and
  tailroom on the IOBuf. Write the TLS record header in place via
  `prepend`, write the inner-content-type byte + tag into tailroom.
  One contiguous record, zero allocs from the seal.
- **Win**: -2 small allocs per record (drops alloc churn under
  load), simpler chain shape.
- **Effort**: low. Local to `flush_record` + a small refactor of
  `seal_chain_in_place` to operate on a single pre-sized IOBuf
  instead of pushing chain parts.
- **Risk**: low.

### D. Fuse copy + encrypt in scratch
- **Status**: [ ] **deferred** — re-evaluate after profiling
- **Why deferred**: The chacha20 0.9 crate only exposes
  `apply_keystream(&mut [u8])` (in-place). A fused src→dst
  variant would require either (a) hand-rolling the XOR loop
  against `apply_keystream` over a stack-local 64-B keystream
  block, losing the crate's SIMD optimisations, or (b) moving
  to a newer cipher trait (`InOutBuf`) and revalidating
  KATs. Meanwhile the existing copy-then-encrypt path keeps
  the scratch L1-resident between passes — DRAM traffic is
  already ~1 R (chain) + 1 W (scratch) per byte; the second
  encrypt pass over scratch + Poly1305 read are
  cache-resident. The cycle savings are likely single-digit %
  rather than the wall-clock win the doc originally implied.
- **Re-trigger**: pick this back up if (1) profiling shows
  scratch churn is a hot spot under multi-core load (e.g.
  multiple TlsStreams' 16 KiB scratches contending L2), or
  (2) we move to a newer chacha20/cipher crate version that
  exposes `apply_keystream_inout`.
- **Where (when revived)**: `uni-tls/src/aead.rs` — new
  `chacha20poly1305_seal_chain_copy(...)` primitive.
- **Effort (when revived)**: medium. Test with same KAT
  vectors used by `seal_chain`.

### E. Skip `drain_tx()` no-op at top of the hot path
- **Status**: [ ] not started
- **Where**: `uni-http/src/lib.rs::TlsStream::send`,
  `uni-tls/src/lib.rs::TlsConnImpl`.
- **What**: Defensive `drain_tx().await?` at the top of `send` is
  a no-op when the TLS layer has no pending bytes. Track a
  `tx_pending` flag in `TlsConnImpl` and skip the call when
  clear.
- **Win**: small — one branch + zero await on the hot path.
- **Effort**: low.
- **Risk**: low.

### F. Drop checksums on loopback / negotiate `VIRTIO_NET_F_CSUM`
- **Status**: [ ] not started
- **Where**: virtio feature negotiation,
  `net/src/{tcp,ipv4}.rs` checksum sites.
- **What**: virtio negotiates `VIRTIO_NET_F_CSUM` to let the
  guest hand the host an unchecksummed segment. Tier-1 NICs
  offload checksums anyway. Skip the per-segment scan.
- **Win**: -1 read pass per byte (TCP checksum) on the offload
  path.
- **Effort**: low-medium. Negotiate the feature; conditionally
  zero out the cksum field.
- **Risk**: low.

### P. Apply A's `fill_header` pattern to UDP TX
- **Status**: [x] **landed 2026-05-08** (commit `1494f06`)
- **Result**: -2 memcpys per byte for any UDP traffic (incl.
  QUIC). `udp::send_to_addr` now builds [ETH][IP][UDP][payload]
  in one stack buffer using the `fill_header` helpers (added by
  A) and ships straight to the driver — no per-layer wrap
  memcpys. UDP bench numbers unchanged on small packets;
  per-byte savings scale with payload size.
- **Where**: `net/src/udp.rs::send_to_addr`. The current
  implementation builds [UDP][PAYLOAD] in a 1480 B stack buf,
  calls `ipv4_send` (which builds [IP][UDP][PAYLOAD] in a 1500 B
  stack buf), which calls `ethernet_send` (which builds
  [ETH][IP][UDP][PAYLOAD] in a 1514 B stack buf), which calls
  `drivers::net::send` (which memcpys into a TX pool slot).
- **What**: Mechanical mirror of item A — replace the layered
  `udp::send_to_addr → ipv4_send → ethernet_send` chain with one
  stack buffer that holds `[ETH 14][IP 20|40][UDP 8][payload]`,
  filled in place via the existing `ethernet::fill_header` /
  `ipv4::fill_header` / `ipv6::fill_header` helpers (added by
  item A). Hand the contiguous frame straight to
  `uni_drivers::net::send`.
- **Win**: -2 memcpys per byte on the **QUIC TX hot path** (UDP
  wrap + IP wrap + Eth wrap collapse to one frame build).
  Drops QUIC guest-side memcpys 5 → 3, matching the post-A TCP
  path. Also benefits any non-QUIC UDP traffic (DNS replies,
  NTP, future).
- **Effort**: low. Same shape as A; ~50 LOC; no new deps.
- **Risk**: low. Slow path callers (UDP socket reactor for
  short replies, DHCP, etc.) keep the layered API.

### Q. Encode QUIC packets directly into the TX framing buffer
- **Status**: [x] **landed 2026-05-08** (commits `2224cd7`, `46ab22e`)
- **Result**: -1 memcpy per byte on the QUIC TX hot path. The
  QUIC conn's `take_datagram_buf` now pre-reserves 62 B at the
  front of every outbound Vec; the encoder writes packet bytes
  starting at offset 62. The reactor calls a new
  `UdpSocket::send_to_with_l2_headroom`, which on bare-metal
  fills L2/L3/L4 headers in the pre-reserved space and ships
  straight to the driver — bypassing
  `udp::send_to_addr → ipv4_send → ethernet_send`.
  QUIC TX guest-side memcpys now match TCP at 2 per byte
  (encode + driver-pool); item B drops both to 1.
- **Where**: `uni-quic/src/conn.rs::encode_*_packet` family,
  the boundary between `pop_packet_owned` and
  `UdpSocket::send_to`, and the QUIC reactor's send loop in
  `uni-quic/src/endpoint.rs`.
- **What**: Today QUIC encodes each packet into a freshly-taken
  `Vec<u8>` from `outbound_pool`, plus a separate
  `Vec::with_capacity(1024)` for staging frames. The Vec then
  rides through `send_to` → UDP wrap → IP wrap → Eth wrap →
  driver TX pool — multiple memcpys to attach 14 + 20 + 8 = 42 B
  of headers around bytes the QUIC encoder already had to
  serialise.
  Re-shape the encoder to take a `&mut [u8]` view into the
  **UDP-payload region of a TX framing buffer** (the same buffer
  that ETH/IP/UDP headers will be filled into in place).
  The encoder writes packet bytes there directly; no Vec
  staging, no datagram-Vec hop. UDP/IP/Eth headers fill in
  place after the encoder reports the byte count. Driver gets
  the frame.
- **Win**:
  * -1 memcpy per byte (the QUIC-encode-into-Vec → UDP wrap
    chain becomes a single direct write).
  * -1 alloc per packet (the per-frame staging Vec; if the
    encoder composes directly into the framing buffer at known
    offsets, the staging Vec disappears entirely).
  * Combined with P and B, drops QUIC guest-side memcpys
    **5 → 1** — matching the structural argument the project
    makes for QUIC-on-unikernel.
- **Effort**: medium-high. The QUIC encoder has rollback
  semantics (e.g. don't emit an ACK-only packet if no frames
  due) — the buffer contract has to support truncate-on-rollback.
  Frame composers (`append_ack_frame`, `write_crypto`,
  STREAM frame builders) currently extend a Vec; they need to
  accept `&mut [u8]` + cursor.
- **Risk**: medium. Cryptographic correctness is testable, but
  the rollback / partial-write boundaries need careful audit.
- **Implementation note**: can land before B — the framing
  buffer can be stack-local in the QUIC reactor first (same
  pattern as the TLS scratch in `TlsStream::send`). B then
  upgrades it to a pool-borrowed IOBuf.

## Segment 2 — Wire & receive (NIC TX → browser RX)

### G. TSO (TCP Segmentation Offload)
- **Status**: [ ] not started
- **Where**: virtio feature negotiation
  (`VIRTIO_NET_F_HOST_TSO4`/`HOST_TSO6`), `net/src/tcp.rs` send
  loop.
- **What**: Hand the device a single super-segment (e.g. 16 KiB
  plaintext + envelope = one TLS record + one TCP/IP header)
  and let the NIC split into MSS-sized segments. The 12 calls to
  `send_segment_from_cursor` per record collapse to 1.
- **Win**: huge on Tier 1 / KVM with a real NIC. Limited on HVF
  because the userspace relay still has to split.
- **Effort**: medium-high. Needs B as a prerequisite (the
  super-segment can't fit in a single 1514 B TX pool slot, so we
  need SG descriptors).
- **Risk**: medium. Real interaction with host NIC offload
  capabilities.

### H. Push more traffic through HTTP/3
- **Status**: [ ] in progress (we already serve H3)
- **What**: H3 over QUIC removes TLS-record framing pressure
  (QUIC packets carry encrypted streams), removes head-of-line
  blocking, folds the handshake into 1-RTT. For real page loads
  with multiple subresources, H3 wins on RTT regardless of
  per-byte memcpy count.
- **Effort**: ongoing — already a project pillar.

### I. Right-size TLS records dynamically (transport feedback)
- **Status**: [ ] not started
- **What**: Today: 16 KiB records always. Bigger records lose
  less to per-record overhead but pay more on packet drop (whole
  record blocks until last byte arrives). The "dynamic chunk size
  from transport feedback" idea — adjust the record size from
  RTT/loss telemetry once QUIC's congestion controller exposes
  it.
- **Effort**: high (signals + policy + rolling window).
- **Risk**: medium.

### J. Body compression (br/gzip) before TLS
- **Status**: [ ] not started
- **What**: A 9 KiB shell page → ~2 KiB gzipped. 4× fewer wire
  bytes, 4× fewer cycles in steps 3–8. Pay CPU once at compress
  time. Big win for Internet-facing serving; pointless on
  loopback.
- **Effort**: medium. Library choice + `Accept-Encoding` gating.
- **Risk**: low.

### K. Connection reuse / 0-RTT resumption
- **Status**: [ ] not started
- **What**: H1 keep-alive is supported. Add 0-RTT (PSK_KE) for
  returning clients — first request inside the ClientHello.
  Replay-attack caveats apply.
- **Effort**: medium-high (handshake layer rework).
- **Risk**: medium (security review needed).

### L. HTTP `103 Early Hints` over H3
- **Status**: [ ] not started
- **What**: Tell the browser to start fetching subresources
  before the main body arrives. Saves wall-clock on page loads.
- **Effort**: low-medium if the H3 stack already supports it.
- **Risk**: low.

## Allocations (separate dimension from memcpy)

Measured: **/diagnostics over HTTPS/1.1 = 11 allocs**, **over H3 =
19 allocs** for a cold-conn first request. Decomposition:

| # | Alloc | Site | Per-… |
|---|-------|------|------|
| 1 | `Box::pin(async move {...})` (conn future) | `uni-runtime/src/net/tcp.rs:475` | conn-accept |
| 2 | spawn task struct | `crate::spawn_boxed` | conn-accept |
| 3 | `Box<TlsConnImpl>` | `uni-tls/src/lib.rs:163` | conn-accept |
| 4 | `rx_buf` `Box<[u8; 4096]>` | `TlsServer::new` | conn-accept |
| 5 | `tx_buf` `Box<[u8; 4096]>` | `TlsServer::new` | conn-accept |
| 6 | `pt_buf` `Box<[u8; 4096]>` | `TlsServer::new` | conn-accept |
| 7 | `body_scratch` `Box<[u8; 16384]>` | `handle_conn` | conn-accept |
| 8 | VecDeque overflow | first chain `push_back` past INLINE_PARTS | first request per conn |
| 9 | seal trailer Heap IOBuf (17 B) | `seal_chain_in_place` | per-record (also in TX memcpy table item C) |
| 10 | seal header Heap IOBuf (5 B) | `seal_chain_in_place` | per-record (also in TX memcpy table item C) |
| H3 +1..+8 | per-packet/frame `Vec::with_capacity` | `uni-quic/src/conn.rs` (frame & datagram encode) | per H3 packet |

Item **C** in the memcpy plan removes #9 and #10 by baking the
record envelope into the TLS scratch.

Item **#8** (VecDeque overflow) is one alloc per conn, amortized
on subsequent requests via retained capacity. Not tracked as a
separate task — tuning `INLINE_PARTS` to a specific page is
fragile and the cost is bounded.

The remaining per-conn-accept allocs (#1–#7) are the lever for
the work below.

### M. Conn-state pool
- **Status**: [ ] not started
- **Where**: `uni-runtime/src/net/tcp.rs` (accept site),
  `uni-tls/src/lib.rs::new_connection`,
  `uni-tls/src/server.rs::TlsServer::new`,
  `uni-http/src/lib.rs::handle_conn` (`body_scratch`).
- **What**: Recycle the chunky per-conn allocations across
  accept/close cycles instead of allocating fresh per accept.
  Pool the things that have stable shape and size:
  * `Box<TlsConnImpl>` and the 3 `Box<[u8; 4096]>` it holds inside
    (`rx_buf`, `tx_buf`, `pt_buf`). Reset on return: zero the seq
    counters + key state, leave the buffers untouched.
  * The 16 KiB `body_scratch` from `handle_conn`.
  * Optionally, the conn-accept `Box::pin` future and spawn task
    struct (smaller wins; folder N below).
- **Win**: -5..7 allocs **per conn-accept**. Heap-traffic + talc
  spinlock contention drops in proportion to conn churn.
  * Keep-alive bench (current local benches): noise.
  * Curl-style / Internet-facing serving: can drop the per-request
    alloc count from ~11 to ~4 on cold conns.
  * Also avoids the per-conn-Box-alloc bug class we hit earlier
    on 2c (HEAD~2 of this branch) where adding any `Box<[u8]>`
    field to `TlsStream` wedged half of accepted conns under
    multi-core load.
- **Effort**: medium. Per-worker SPSC free list keyed by the
  pool's struct shape; reset hooks on return; pool-watermark
  cap to avoid unbounded growth.
- **Risk**: medium. Reset semantics need care — leftover state
  (seq numbers, partial RX buffer contents) must not survive
  into the next conn.

### N. Conn future + spawn-task pool (follow-up to M)
- **Status**: [ ] not started, after M
- **Where**: `uni-runtime/src/net/tcp.rs:475` Box::pin site,
  `crate::spawn_boxed` task allocation.
- **What**: Once M lands the conn-state pool, the remaining two
  per-accept allocs are the boxed accept-body future and the
  task struct itself. Both are small and have stable layout.
  Pool either (a) the boxed future (a `Pin<Box<dyn Future>>`
  wrapping the same conn handler shape), or (b) the task slot
  the spawner places it in. Smaller individual win than M but
  closes out the conn-accept alloc count.
- **Effort**: medium-high (touches the spawner internals).
- **Risk**: medium.

### O. QUIC encode-side `Vec` recycling (H3 path)
- **Status**: [ ] not started, after M
- **Where**: per-frame and per-datagram encode sites in
  `uni-quic/src/conn.rs` (already an `outbound_pool` for the
  datagram-sized buffer at line 1011; per-frame Vecs are not
  yet pooled).
- **What**: H3 has 8 more allocs than H/1.1 per cold-conn
  /diagnostics request, almost all from `Vec::with_capacity` in
  the QUIC encode path. Same pooling pattern as M but at a
  different layer: each `Vec` recycled through a per-conn (or
  per-worker) free list. The existing `outbound_pool` provides
  the template.
- **Win**: -5..8 allocs per H3 request under load.
- **Effort**: medium.
- **Risk**: low.

## Recommended sequence

The order optimises for: (a) close the easy mechanical wins first,
(b) bring QUIC's per-byte memcpy count to parity with TCP before
chasing the structural QUIC payoff, (c) defer foundational/risky
items until they unlock something concrete.

1. ✓ **A + C** — TCP TX wrap memcpys + TLS seal envelope. Done.
2. ✓ **P** — UDP TX wrap fold (mirror of A). Done.
3. ✓ **Q** — QUIC packets into framing buffer. Done.
4. **B** (virtio SG TX descriptors) — drops the last guest-side
   memcpy on **both** paths (2 → 1 for TCP and QUIC) and
   replaces the `send_on_qp` busy-spin with parking-async. Lays
   the foundation for G.
5. **G** (TSO) — biggest single Tier 1 win once we benchmark on
   KVM/GCE. Depends on B.
6. **M** (conn-state pool) — the alloc-side equivalent of A+C;
   biggest *alloc-count* win whenever conn churn matters. Land
   any time after we have a conn-churn workload to bench against
   — local keep-alive bench won't show it.
7. **N + O** — close out the alloc tail once M is in. (O is
   partly mitigated by Q's headroom-prefix approach but the
   per-frame staging Vecs in `encode_initial_packet` /
   `encode_handshake_packet` remain — re-evaluate scope.)
8. **J** (compression) + **K** (0-RTT) + **L** (Early Hints) when
   we shift focus from local benchmarks to Internet-facing serving.

D (fused copy + encrypt) is **deferred** — see its entry above.

End state after step 6: **1 memcpy per byte** on the guest side
for both TCP TLS and QUIC — just the one fundamental encrypt R/W
pass for AEAD (or zero of the encrypt itself moves to NIC offload
via TLS-offload, but that's its own rabbit hole).

E and F are low-effort cleanups that can land any time.

## Progress log

- **2026-05-08** — Doc created. Per-byte guest-side memcpy count
  measured at 5 (steps 3, 5, 6, 7, 8). Bench baseline:
  `health_tls_max` ≈ 108 k req/s 1c HVF, ≈ 150 k 2c, ≈ 150 k 3c.
- **2026-05-08** — Allocations dimension added. /diagnostics
  cold-conn alloc count traced: 11 (H/1.1) / 19 (H3). 7 are
  conn-accept setup (item M), 1 is chain VecDeque overflow
  (untracked — page-specific tuning), 2 are TLS seal IOBufs
  (covered by item C), H3 extras are QUIC encode Vecs (item O).
- **2026-05-08** — Item **C landed** (`e6d9a28`): -2 allocs per
  TLS record. Scratch now sized 16406 B and routed through
  `send_app_data_iobuf` → `seal_in_place`. Bench unchanged
  (alloc-side opt, doesn't move keep-alive throughput).
- **2026-05-08** — Item **A landed** (`bcf2e8d`, `e3c7e08`):
  -2 memcpys per byte on the TCP TX hot path. Path table updated:
  active per-byte memcpys 5 → 3. Bench unchanged on /health
  (small response). Wins scale with payload size — show up on
  larger-body workloads (bench coverage gap; consider adding a
  shell-page bench).
- **2026-05-08** — Item **P landed** (`1494f06`): UDP TX wrap
  fold. -2 memcpys per byte for any UDP traffic (incl. QUIC).
  Drops QUIC guest-side memcpys 5 → 3, matching post-A TCP. UDP
  bench numbers within noise on small packets — wins scale with
  payload size; need a QUIC-throughput workload to surface
  (bench coverage gap, same as A).
- **2026-05-08** — Item **D deferred**. chacha20 0.9 only
  exposes in-place `apply_keystream`; a fused src→dst variant
  needs a hand-rolled XOR loop (loses crate SIMD) or a newer
  cipher trait. Today's copy-then-encrypt keeps scratch
  L1-resident between passes, so the actual DRAM cost is
  already ~1R+1W per byte. Likely single-digit % cycle win —
  not worth the complexity now. Re-trigger on profiling
  evidence or crate upgrade.
- **2026-05-08** — TX driver model + QUIC/UDP path traced:
  * TX is fully async — driver writes a virtio descriptor and
    kicks; completion is silent (no IRQ), drained lazily on the
    next `send_on_qp`. Backpressure today is a busy-spin when
    all 64 TX-pool slots are in flight.
  * QUIC TX path measured at 5 memcpys/byte vs TCP TLS's 3
    after item A — UDP wrap inherits the same layered
    `udp::send_to_addr → ipv4_send → ethernet_send` chain that
    A removed for TCP.
  * Two new items added: **P** (mechanical UDP fold, mirror of
    A) and **Q** (QUIC encode directly into the L2/L3/L4
    framing buffer, removing the QUIC-Vec → UDP wrap hop and
    several per-packet `Vec::with_capacity` allocs).
  * **B** rewritten to make the virtio TX pool an
    IOBuf-acquire/release source (vs memcpy-target), and
    flagged as the natural place to also fix the
    `send_on_qp` busy-spin (parking-async).
  * Recommended sequence updated: P → D → Q → B → G → M → N+O →
    J/K/L. End state after step 6 is 1 memcpy per byte on both
    TCP and QUIC TX paths.
- **2026-05-08** — Item **Q landed** (`2224cd7`, `46ab22e`):
  -1 memcpy per byte on the QUIC TX hot path. `take_datagram_buf`
  now pre-reserves 62 B at the front of each outbound Vec;
  encoder writes packet bytes at offset 62; the reactor calls a
  new `UdpSocket::send_to_with_l2_headroom` that fills L2/L3/L4
  headers in the headroom in place. QUIC TX memcpys now at 2
  per byte (encode + driver-TX-pool), matching TCP. End state
  after item B is 1 memcpy per byte for both paths.
