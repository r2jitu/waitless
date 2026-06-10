# TX path optimizations — tracker

A living plan for trimming the TX path between application-layer
encrypt and the wire. Covers both HTTPS-over-TCP and HTTPS-over-H3
(QUIC). Each item below is sized to land as one (or a small batch
of) commit(s); check items off as we ship them.

> **See also:** [`high-concurrency-perf.md`](high-concurrency-perf.md)
> for the high-conn cliff context — the encrypt-in-place + header-
> fusion work shipped here (items A–C, G) already moved
> `cycles/request` down significantly. (Item D's fused
> copy+encrypt also shipped, then reverted on the AES-GCM
> migration — see item D.) Remaining TX-side lever tracked there
> is the AES-GCM cipher choice.

## Why this doc exists

We measured the per-byte guest-side memcpy count starting at **5
memcpys per byte** for HTTPS-over-TCP and **5 memcpys per byte** for
HTTPS-over-H3 (QUIC) (≈ 4.5 GB/s of memcpy traffic at 100 k rps for
a 9 KiB shell page). Most of those are mechanical header-prepend
memcpys that fall out of the way once the buffer is composed in
place. The encrypt step itself is a fundamental R/W that can't be
removed; for QUIC the encoder writes plaintext straight into the
datagram and the AEAD seals it there in place (one pass), while
the TCP TLS chain path copies into the TX-slot and then seals in
place (two passes) — the AES-128-GCM crate exposes no fused
copy-and-encrypt API to collapse those into one (see item D).

This doc captures the inventory, splits proposals across the two
segments the user named — *encrypt → NIC TX* and *network → browser
RX* — and tracks progress as we land them.

## Current path — TCP (HTTPS over TLS)

| # | Step | Site | Cost per byte | Cost per record | Notes |
|---|------|------|---|---|---|
| 1 | Handler renders body | `body_iobuf` writer | 1× memcpy (dynamic content only) | — | Static literals are zero-copy |
| 2 | Header build | `write_response_into_iobuf` | — | ~150 B memcpy | Into per-conn `header_storage` |
| 3 | ~~TLS coalesce~~ | — | — | — | Folded into step 4 — `TlsStream::send_one_record` fast-fast path seals directly into the driver's TX-pool big-slot (item TLS-direct ✓) |
| 4 | TLS encrypt + envelope | `record::seal_chain` (→ `aead::seal_chain`) | 1× copy chain→slot + 1× R/W (AES-128-GCM, GHASH-authenticated) | — | Chain bytes copied into the TX-slot, then sealed in place. **Not** a fused copy+encrypt anymore: the AES-GCM crate exposes no fused copy-and-encrypt API, so item D's single-pass `seal_chain_to` was dropped on the ChaCha20→AES-128-GCM migration (item C + TLS-direct ✓; see item D) |
| 5 | **TCP frame build** | `try_send_tso` / `send_segment` | **0× extra memcpy** | 14 + 20 + 20 B headers + 1 cksum | Headers written into TX-slot prefix in place; payload already in slot from step 4 (TLS-direct ✓ + items A, B, G) |
| 6 | ~~IPv4 wrap~~ | — | — | — | Folded into step 5 (item A ✓) |
| 7 | ~~Ethernet wrap~~ | — | — | — | Folded into step 5 (item A ✓) |
| 8 | ~~virtio-net submit memcpy~~ | — (item B ✓ for TCP, B2 ✓ for QUIC) | — | descriptor add + kick | Both TCP and QUIC write directly into the TX pool slot via `acquire_tx_buf` + `submit_tx` |
| 9 | virtio host pickup | (HVF userspace_net or KVM) | depends on host | — | HVF: another memcpy to host TCP socket |
| 10 | Host TCP/IP/Eth | host kernel | host-side | — | TSO can fold this on real NICs |
| 11 | Wire | network stack | — | — | MTU, cwnd, RTT |
| 12 | Browser RX | TLS decrypt + HTTP parse | symmetric to ours | — | Out of our control |

Active per-byte memcpys on the **TCP TX** guest side: **2** —
the chain→TX-slot copy plus the in-place AES-128-GCM encrypt
R/W (GHASH reads the resulting ciphertext, no extra full pass).
There's no intermediate stack buffer or worker-scratch hop on
the fast-fast path — the copy lands straight in the TX-slot —
but the copy and the encrypt are now two passes, not the single
fused pass item D once delivered (the AES-GCM crate has no fused
copy-and-encrypt API; see item D). Down from 5 before items A,
C, B, G, and the TLS-direct-encrypt commit. The copy re-reads
L1-resident bytes, so the DRAM cost is closer to one R/W than
two. Same structure as the QUIC TX path (encoder write +
in-place seal).

## Current path — QUIC (HTTPS over H3)

| # | Step | Site | Cost per byte | Cost per packet | Notes |
|---|------|------|---|---|---|
| 1 | Handler renders body | `body_iobuf` writer | 1× memcpy (dynamic content only) | — | Same as TCP path |
| 2 | H3 frame encode | `proto/http3/src/*` | — | small `Vec::with_capacity` per frame | HEADERS / DATA / etc. |
| 3 | **QUIC packet encode** | `encode_one_rtt_packet` etc. (`proto/quic/src/conn/tx.rs`) | **1× memcpy** | `Vec::with_capacity(1024)` for frames + `take_datagram_buf` (~1500 B, pooled with 62 B L2/L3/L4 headroom prefix after item Q) | Frame headers + STREAM data written into the datagram Vec; for 1-RTT packets writes directly (no temp staging Vec); Initial/Handshake still stage via temp `frames` Vec |
| 4 | QUIC AEAD seal | within `seal_packet` (`aes128_gcm_seal`) | 1× R/W (AES-128-GCM, GHASH-authenticated) | — | In place over the assembled packet bytes — the encoder already wrote plaintext into the datagram (step 3), so no copy pass is needed here (unlike the TCP TLS chain path, which copies into the slot before sealing) |
| 5 | `pop_packet_owned` | `proto/quic/src/endpoint.rs` | — (move) | — | `DatagramBuf` ownership transferred to the reactor; `TxSlot` variant carries a `TxBufHandle` (zero-copy ship), `Heap` variant carries a `Vec<u8>` (recycled via the conn's pool) |
| 6 | ~~UDP wrap~~ | — (item Q ✓) | — | — | Folded into step 3 — encoder writes packet bytes directly into the framing buffer's UDP-payload region; bare-metal `send_with_l2_headroom` fills UDP/IP/Eth headers in the pre-reserved headroom |
| 7 | ~~IPv4 wrap~~ | — | — | — | Folded into step 6 (item P ✓ and Q ✓) |
| 8 | ~~Ethernet wrap~~ | — | — | — | Folded into step 6 (item P ✓ and Q ✓) |
| 9 | ~~virtio-net submit memcpy~~ | — (item B2 ✓) | — | descriptor + kick | QUIC encoder writes directly into a TX-pool slot via `take_datagram_buf` → `acquire_tx_buf`; reactor's `ship_datagram` extracts the handle and submits via `send_via_tx_handle`. IPv4 destinations do an in-place 20-byte payload memmove (driver expects L2 frame at slot offset 0); IPv6 is pure zero-copy. Heap fallback when the pool is empty. |
| 10+ | Host pickup, host kernel, wire, browser | — | — | — | Same as TCP from this point on |

Active per-byte memcpys on the guest side: **1** (step 3) — down
from 5 before items A, P, Q, B2. The fundamental encoder write
that can't be removed without offloading AEAD to the NIC; the
AES-128-GCM seal then runs in place over those same bytes (step
4), so no second copy. This is one pass fewer than the TCP TLS
path, which gained a chain→slot copy when the fused
`seal_chain_to` went away on the AES-GCM migration (see TCP
summary above and item D) — QUIC keeps its single-pass shape
because the encoder writes straight into the datagram and the
AEAD seals there.

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

### B. SG TX API (direct-fill from caller into the TX pool)
> The *shape* of this NIC TX submit-surface (acquire/fill/submit
> vs. memcpy-target) is owned by
> [`stack-architecture.md`](stack-architecture.md); this item owns
> the per-byte TX-cost it eliminates.
- **Status**: [x] **landed 2026-05-08** for **TCP** (commits
  `936f03f`, `84777e2`) and for **QUIC** (B2; commits `68f985f`
  + this commit).
- **Result**: -1 memcpy per byte on the TCP TX and QUIC TX hot
  paths. Driver exposes `acquire_tx_buf() -> Option<TxBufHandle>`
  + `submit_tx`; caller (TCP and QUIC) writes straight into a
  slot of the existing 64-slot `tx_pool`, no intermediate stack
  buffer + memcpy.
  * Implementation: new `TxBufHandle` struct in `crates/waitless/net::driver`
    with `Drop` returning the slot to the pool unused; `submit_tx`
    `mem::forget`s the handle to skip release.
  * virtio-net: per-qp scan, Tier-1 only (Tier-2 shared qp returns
    `None` to avoid cross-core lock contention on `tx_pool_used`).
  * GVE: stubbed `None`/`None`; callers fall back to `send(&[u8])`.
  * TCP: `send_segment` and `send_segment_from_cursor` route
    through a shared `build_and_send_frame(frame_len, fill)`
    helper that does the acquire-or-stack dance.
- **Bench (HVF, /health)**:
  * 1c: ~108 → ~114k req/s (+5%)
  * 2c: ~150 → ~170k       (+13%)
  * 3c: ~150 → ~171k       (+14%)
- **B2 (QUIC integration)**: `Connection::outbound:
  VecDeque<Vec<u8>>` is now `VecDeque<DatagramBuf>`. `DatagramBuf`
  is an enum with two variants: `Heap(Vec<u8>)` (heap fallback)
  and `TxSlot { handle: TxBufHandle, vec: ManuallyDrop<Vec<u8>> }`
  (the encoder's writes land in the slot's data region directly,
  with the Vec wrapper suppressing dealloc on drop).
  `take_datagram_buf` tries `acquire_tx_buf` first; the encoder's
  audited `&mut Vec<u8>` write surface (push / extend_from_slice
  / truncate / split_at_mut — never `reserve`) is safe with
  capacity 1514. The reactor's drain path collapses three
  duplicated loops (the `drain_outbound` method + the PTO probe
  drain + the main loop drain) into a shared `ship_datagram`
  helper that dispatches on the variant: TxSlot extracts the
  handle and ships via `send_via_tx_handle` (zero-copy on IPv6;
  20 B in-place memmove on IPv4 because the driver expects the
  L2 frame at slot offset 0); Heap falls back to
  `send_to_with_l2_headroom` and recycles the Vec into the
  conn's pool. End state: QUIC TX hot path is **1 memcpy per
  byte** — the fundamental encrypt R/W pass.
  > (History: the 2026-06-06 stream-retx work temporarily regressed this
  > to 2 R/W passes/byte — the retain-until-ACK retention copied every
  > queued STREAM payload via `pop_chunk().to_vec()`. Fixed 2026-06-10:
  > `pop_chunk` returns `clone_shared` IOBuf views, so the retention is
  > refcounted, not copied, and 1 memcpy/byte holds again. h3 /health
  > measured 8.4 → 6.0 allocs/req.)
- **Note (`send_on_qp` busy-spin)**: still there in the slow path
  used by ARP/DHCP/ICMP/UDP and the TCP fallback when the pool
  is full. With the new acquire path returning `None` on full,
  the TCP hot path no longer busy-spins — it falls back to the
  `send(&[u8])` slow path which still spins. Worth replacing
  with parking-async in a future cleanup.

### C. Bake the record envelope into the scratch (no header/trailer allocs)
- **Status**: [x] **landed 2026-05-08** (commit `e6d9a28`)
- **Result**: -2 small Heap allocs per TLS record. `flush_record`
  now sizes the scratch as `[u8; 5 + 16384 + 17]` and routes
  through `send_app_data_iobuf` (which calls `seal_in_place`).
  Record header / type byte / tag all written into the scratch's
  reserved headroom + tailroom — no Heap IOBufs allocated.
- **Where**: `proto/tls/src/record.rs::seal_chain_in_place`,
  `proto/http/src/lib.rs::flush_record`.
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
- **Status**: landed 2026-05-08 (commits `39c034e`, `fef3c63`,
  `25858e3`), then **reverted on the ChaCha20 → AES-128-GCM
  migration** — the audited `aes-gcm` crate exposes no fused
  copy-and-encrypt API (the `apply_keystream_b2b` trick below was
  ChaCha20-specific). The TLS chain path is back to copy-into-slot
  + `encrypt_in_place_detached` (see `aead::seal_chain` /
  `record::seal_chain`), so the TCP TLS summary now counts 2
  per-byte passes again. Re-trigger only if a profile justifies
  hand-rolling AES-CTR + GHASH as a fused pass (`aes::Aes128` +
  `ghash::GHash`). The 2026-05-08 narrative below is the
  historical record of the original (since-reverted) landing.
- **Result**: -1 R/W pass per byte through dst on the TLS
  single-record fast path. Earlier deferral reasoning was
  wrong — `chacha20` 0.9 (via `cipher` 0.4.4) does expose
  `StreamCipher::apply_keystream_b2b(input, output)`, which
  drives the same SIMD backends as in-place `apply_keystream`.
  Implementation:
  * New `chacha20poly1305_seal_chain_to` primitive in
    `proto/tls/aead.rs` — reads plaintext from an iterator,
    XORs while writing ciphertext to dst, accumulates Poly1305
    over the resulting ciphertext bytes.
  * `TrafficKey::seal_chain_to` + `record::seal_chain_to_in_place`
    + `TlsServer::send_app_data_chain_to` plumb it through the
    TLS layers.
  * `TlsConn::send_app_data_chain_to` trait method + override.
  * `TlsStream::send` uses the fused path on single-record
    chains (the common case); oversize chains keep the legacy
    copy-into-scratch + `seal_in_place` path until chain-
    splitting at byte offsets becomes worth implementing.
- **Bench impact**: within noise on /health (250 B body). The
  savings are per-byte and need a multi-KiB body to surface
  on the bench. Verified correctness via record-layer KAT
  comparing wire bytes to the existing in-place seal.

### E. Skip `drain_tx()` no-op at top of the hot path
- **Status**: [ ] not started — `TlsStream::send` still calls
  `self.drain_tx().await?` unconditionally.
- **Where**: `proto/tls/src/lib.rs` (`TlsStream::send` and its
  `drain_tx`).
- **What**: Defensive `drain_tx().await?` at the top of `send` is
  a no-op when the TLS layer has no pending bytes. Track a
  `tx_pending` flag and skip the call when clear.
- **Win**: small — one branch + zero await on the hot path.
- **Effort**: low.
- **Risk**: low.

### F. Drop checksums on loopback / negotiate `VIRTIO_NET_F_CSUM`
- **Status**: [x] **effectively landed by the 2026-05-19 uniform
  `send()`-side L4 checksum offload** (see progress log). virtio-net
  negotiates `VIRTIO_NET_F_CSUM` (`init.rs`, sets `has_csum`); the
  guest stamps only the cheap pseudo-header partial sum at the L4
  cksum field and hands the device an otherwise-unchecksummed
  segment via `VIRTIO_NET_HDR_F_NEEDS_CSUM` (`tx.rs`
  `submit_tx`/`send`, gated on `csum.is_some() && has_csum`). The
  full per-byte `internet_checksum` scan now runs only as the
  software fallback when the device never negotiated CSUM. The TCP
  `Current path` table's step-5 "+1 cksum" is that small partial
  stamp, not a full per-byte read, on offload-capable NICs.
- **Where (as landed)**: virtio-net `init.rs` feature negotiation
  + `tx.rs` (`has_csum` / `NEEDS_CSUM`); TCP partial stamp in
  `net/tcp/src/send.rs` (`checksum::l4_pseudo_partial`).
- **Residual**: the original "drop checksums on loopback" angle
  (skip even the partial when the path is host-loopback) is not
  done and is low-value — the partial stamp is a fixed ~20-byte
  cost, not per-payload-byte.

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
  `nic_api::net::send`.
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
- **Where**: `proto/quic/src/conn.rs::encode_*_packet` family,
  the boundary between `pop_packet_owned` and
  `UdpSocket::send_to`, and the QUIC reactor's send loop in
  `proto/quic/src/endpoint.rs`.
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

### R. UDP GSO on DQO TX
- **Status**: [x] **landed** — DQO segments UDP super-buffers via
  the same TSO descriptor path; GQI / virtio / HVF fall back to
  the per-datagram loop.
- **Result (when landed)**: UDP-heavy TX paths emit one
  GSO-segmented "big frame" instead of N MTU-sized sends. The
  device hardware segments on its side, eliminating
  ~per-segment driver overhead on the QUIC and raw-UDP paths.
  Linux's gve added the DQO variant in v1.4.10 ("Enable support
  for UDP GSO when using DQO format"); we're matching that
  capability on a path the GQI mode has had since the initial
  UDP-GSO landing.
- **Where**:
  * Dispatcher / wiring (DQO segments via the TSO path):
    [`crates/drivers/gve/src/lib.rs:704-706`](crates/drivers/gve/src/lib.rs#L704-L706)
    — `udp_gso_available: tx::udp_gso_enabled` +
    `acquire_tx_udp_gso_buf` / `submit_tx_udp_gso`.
  * Buf-acquire (DQO returns the TSO slot; GQI = None fallback):
    [`crates/drivers/gve/src/tx.rs:54-63`](crates/drivers/gve/src/tx.rs#L54-L63)
    `acquire_tx_udp_gso_buf` → `dqo::acquire_tx_tso_buf` on DQO,
    `None` on GQI.
  * GQI implementation to mirror:
    [`crates/drivers/gve/src/gqi.rs:571`](crates/drivers/gve/src/gqi.rs#L571)
    `submit_tx_udp_gso_inner`. Same arg shape: `handle`,
    `frame_len`, `hdr_len`, `csum_start`, `gso_size`.
  * DQO TX descriptor format reference:
    [`crates/drivers/gve/src/dqo.rs:21-65`](crates/drivers/gve/src/dqo.rs#L21-L65)
    documents the general-context + pkt-desc pair; lines 130-138
    cover the pkt-desc flags layout.
- **What**:
  1. Pull upstream Linux's `gve_tx_dqo.c` from
     `torvalds/linux/master` and locate UDP-GSO handling — grep
     for `SKB_GSO_UDP_L4`, `gso_size`, `udp_gso`. Identify the
     exact metadata-byte offsets in the general-context
     descriptor that carry hdr_len + gso_size (different
     placement than GQI's flat descriptor).
  2. Add `dqo::submit_tx_udp_gso_inner(handle, frame_len,
     hdr_len, csum_start, gso_size)` mirroring the GQI shape.
     Build the general-context descriptor with the GSO metadata
     fields populated, emit the pkt descriptor with the GSO
     flag set, ring the doorbell.
  3. Swap the dispatcher at
     [`lib.rs:1626-1628`](crates/drivers/gve/src/lib.rs#L1626-L1628)
     to call `dqo::submit_tx_udp_gso_inner` on DQO instead of
     `return;`.
  4. Extend `acquire_tx_udp_gso_buf` to allocate from the DQO TX
     bounce pool. Today it shares the GQI big-pool via
     `acquire_tx_tso_buf` which returns None on DQO; DQO needs
     its own slot acquire (or the shared acquire needs to know
     about the DQO bounce-pool slots). The DQO send path
     (`send_on_qp_dqo`) already manages bounce-buffer slots —
     extend that allocator to surface GSO-sized slots.
- **Win**: +20-50% expected on `h3_health_max` (QUIC keep-alive,
  one big UDP datagram per HTTP/3 response → currently fragments
  into ~10 sends/response without GSO) and `udp_peak` (raw UDP
  echo throughput) at 1c/4c on c3-highcpu-8. Non-UDP paths
  (`http_close_max`, `get_tcp`, `get_tls_fresh`) untouched.
- **Effort**: medium. ~150 LOC: new `dqo::submit_tx_udp_gso_inner`,
  dispatcher swap, DQO bounce-pool GSO-slot acquire. The
  descriptor-byte-level work needs the upstream Linux source
  for guidance.
- **Risk**: medium. Descriptor-byte-level bugs cause silent TX
  drops (device fetches descriptors, no packet emerges) — the
  same failure shape as the TSO bring-up bug documented in the
  2026-05-10 progress-log entry below. Mitigations:
  * Reuse the `/diag-gve` descriptor-capture pattern from the
    TSO bring-up: surface the raw 16-byte descriptors over an
    HTTP endpoint so we can inspect them from kvm-vm without
    serial-console access on GCE.
  * Bench dispatch: any descriptor regression manifests as a
    complete TX drop on the first GSO send → `h3_health_max`
    /`udp_peak` collapse to ~0 RPS in the bench, fail-fast.
- **Bench protocol**: pre/post on c3-highcpu-8 at 1c and 4c.
  Expected-win workloads: `h3_health_max`, `udp_peak`. Controls:
  `http_close_max`, `get_tcp`, `get_tls_fresh` (must stay ±3%).
  3-run median per workload-corecount. If no UDP win shows
  after a clean implementation, check the loadgen for
  `UDP_SEGMENT` setsockopt usage — without it the loadgen is
  splitting per-MSS host-side and the bench measures naked
  single-MSS UDP throughput rather than the GSO path.
- **Tests**: `test_hvf` must pass — it uses the HVF runner's
  userspace network and doesn't exercise the DQO descriptor
  format, so it only catches wider regressions in the
  dispatcher / TX-buf-acquire code, not the descriptor-bytes
  themselves. Driver-level correctness for the descriptor
  shape is GCE-only.

## Segment 2 — Wire & receive (NIC TX → browser RX)

### G. TSO (TCP Segmentation Offload)
- **Status**: [x] **landed for HVF + virtio-net (2026-05-08)** and
  **gve / GCE GQI_QPL (2026-05-10)**. See the 2026-05-10 entry in
  the progress log below for the gve unparking notes + the
  `try_send_tso` MSS-gate bug that the second deploy uncovered.
- **Approach**: bumped `MAX_ETH_FRAME` 1514 → 16512 in the
  virtio-net driver so a single TX-pool slot fits one TLS record's
  worth of TCP super-segment (Eth + IP + TCP + 16 KiB payload).
  Two new APIs at the driver layer: `tso_available()` and
  `submit_tx_tso(handle, frame_len, hdr_len, csum_start, gso_size)`.
  TCP layer's `async_try_send_chain` checks `tso_available()` and
  collapses the per-MSS frame-build loop into a single
  `send_super_segment_from_cursor` when the chain exceeds one MSS.
  The HVF userspace TCP proxy was already shape-compatible (it
  reads the virtio descriptor by `len` with no upper bound, parses
  the TCP header, forwards bytes to a host SOCK_STREAM where the
  host kernel handles segmentation — the gso fields are advisory
  on this path); just adding `VIRTIO_NET_F_CSUM` +
  `VIRTIO_NET_F_HOST_TSO4` to the runner's offered feature bits
  was sufficient.
- **Bench (HVF, /diagnostics ~9 KiB body, post-G)**:
  * 1c: 14163 → 17642 req/s (+25%)
  * 3c: 35815 req/s (2.03x scaling vs 1c)
  * `health_tls_max` (single-MSS body, doesn't trigger TSO):
    unchanged at ~105k 1c, 162k 2c.
  * `tls_handshake_max` (handshake also fits one MSS): unchanged
    at ~2.9k hs/s.
- **Tier 1 / KVM / GCE**: feature negotiation is generic; same
  driver code path will exercise host-side TSO when running on
  vhost-net or a real NIC. Not yet bench-verified on those targets
  — when GCE bench cycle returns we expect the same TX win plus
  whatever NIC-hardware offload latency reduction the underlying
  device adds. GVE driver (in crates/drivers/gve) reports
  `tso_available: || false` so it falls back to per-MSS sends
  until we wire the descriptor-side support there too.
- **Risk**: low for HVF (the userspace proxy just forwards bytes,
  ignoring gso fields). Medium for KVM/real-NIC (descriptor
  format compliance + checksum convention) — pending bench
  validation on those.
- **Memory cost**: +1 MB heap per worker for the larger TX pool
  (TX_POOL_SIZE=64 × MAX_ETH_FRAME=16512). Acceptable on the
  128 MB+ VMs we target. Could shrink TX_POOL_SIZE under TSO
  since one super-segment carries 12× the bytes — deferred.

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

> ⚠️ **Stale (2026-05-29 efficiency audit — see
> [`efficiency-audit.md`](efficiency-audit.md) for the verified current state).**
> The table below predates several changes: `rx_buf` (#4) and `pt_buf` (#6) were
> **removed** from `TlsServer` (only `tx_buf` remains), so the "11 allocs" cold
> figure is too high; the conn-future path is now `reactor/tcp.rs`, not
> `net/tcp.rs`. More importantly, the **steady-state keep-alive** figure is what
> matters and is now **1 alloc/req** (the borrowed-header `into_owned` retain in
> `tcp/state.rs` `rtx_push`; commit `e284d00` removed a second). The
> sub-MSS `/health` response takes a **3-memcpy scratch-seal fallback** (it
> misses the TSO direct-encrypt path) — the audit's #1 TX reduction target. Treat
> the audit as authoritative for current alloc/copy counts; this table is kept as
> the cold-first-request history.

| # | Alloc | Site | Per-… |
|---|-------|------|------|
| 1 | `Box::pin(async move {...})` (conn future) | `runtime/executor/src/net/tcp.rs:475` | conn-accept |
| 2 | spawn task struct | `crate::spawn_boxed` | conn-accept |
| 3 | `Box<TlsConnImpl>` | `proto/tls/src/lib.rs:163` | conn-accept |
| 4 | `rx_buf` `Box<[u8; 4096]>` | `TlsServer::new` | conn-accept |
| 5 | `tx_buf` `Box<[u8; 4096]>` | `TlsServer::new` | conn-accept |
| 6 | `pt_buf` `Box<[u8; 4096]>` | `TlsServer::new` | conn-accept |
| 7 | `body_scratch` `Box<[u8; 16384]>` | `handle_conn` | conn-accept |
| 8 | VecDeque overflow | first chain `push_back` past INLINE_PARTS | first request per conn |
| 9 | seal trailer Heap IOBuf (17 B) | `seal_chain_in_place` | per-record (also in TX memcpy table item C) |
| 10 | seal header Heap IOBuf (5 B) | `seal_chain_in_place` | per-record (also in TX memcpy table item C) |
| H3 +1..+8 | per-packet/frame `Vec::with_capacity` | `proto/quic/src/conn.rs` (frame & datagram encode) | per H3 packet |

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
- **Where**: `runtime/executor/src/net/tcp.rs` (accept site),
  `proto/tls/src/lib.rs::new_connection`,
  `proto/tls/src/server.rs::TlsServer::new`,
  `proto/http/src/lib.rs::handle_conn` (`body_scratch`).
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
- **Where**: `runtime/executor/src/net/tcp.rs:475` Box::pin site,
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
- **Status**: [x] **effectively landed by Q (2026-05-08)** — the
  per-packet staging Vecs that this item originally targeted
  were removed when `encode_one_rtt_packet` was reshaped to
  write directly into the datagram `out` buffer. The
  remaining `Vec::with_capacity` sites in `encode_initial_packet`
  / `encode_handshake_packet` fire only during conn handshake
  (~4-8 allocs over a conn's lifetime, not per request).
- **Verification**: `test_ctrlc_h3_persistent_session_no_leak`
  (aioquic, ~10 serial GETs over a single H3 conn, ^C) lands
  at delta=-55 allocs / -3680 bytes. `test_ctrlc_h3_hammer_no_per_conn_leak`
  (8-worker H3 hammer, ~hundreds of conns, ^C) lands the same.
  Both tests now assert strict `HEAP_LEAK_CHECK ok` (no LEAK
  line at all) instead of the earlier ≤4 alloc cushion.
- **Chrome residue (open, separate bug)**: a real Chrome
  refresh-spam session against `/diagnostics` over H3 leaks
  +9 allocs / ~8 KiB at shutdown — but only with Chrome, not
  aioquic. The leak shape is "first 3 requests clean, plateau
  at ~9 allocs after that," which doesn't match the encode-Vec
  hypothesis. Smoking-gun candidates are Chrome-specific frame
  patterns that aioquic doesn't send: PRIORITY_UPDATE on the
  H3 control stream (RFC 9218), QPACK encoder-stream probes
  (we negotiate capacity 0, but Chrome may still send insert
  instructions we discard), or Chrome's PING/keepalive cadence.
  Filed as a follow-up — small, bounded, won't gate the
  remaining items in this plan. See the smoking-gun analysis
  in commit message of the body_iobuf-scratch alignment.

## Recommended sequence

The order optimises for: (a) close the easy mechanical wins first,
(b) bring QUIC's per-byte memcpy count to parity with TCP before
chasing the structural QUIC payoff, (c) defer foundational/risky
items until they unlock something concrete.

1. ✓ **A + C** — TCP TX wrap memcpys + TLS seal envelope. Done.
2. ✓ **P** — UDP TX wrap fold (mirror of A). Done.
3. ✓ **Q** — QUIC packets into framing buffer. Done.
4. **D** — fused copy + encrypt for TLS single-record path.
   Landed 2026-05-08, then **reverted on the AES-GCM migration**
   (the `aes-gcm` crate has no fused copy-and-encrypt API). TCP
   TLS is back to copy-into-slot + in-place seal. See item D.
5. ✓ **B** (TCP) — direct-fill TX pool. Done.
6. ✓ **B2** (UDP/QUIC) — extend B to QUIC. Done. QUIC encoder
   writes directly into a TX pool slot via the `DatagramBuf::TxSlot`
   variant; reactor ships zero-copy via `send_via_tx_handle`. Heap
   fallback retained for pool exhaustion.
7. ✓ **O** — effectively landed by Q (per-frame staging Vecs gone
   on the steady-state path). Aioquic-driven H3 leak tests
   tightened to strict `HEAP_LEAK_CHECK ok`. Chrome-specific
   residue filed as a separate follow-up under the item bullet.
8. **M** (conn-state pool) — the alloc-side equivalent of A+C;
   biggest *alloc-count* win whenever conn churn matters. Land
   any time after we have a conn-churn workload to bench against
   — local keep-alive bench won't show it.
9. **N** — conn-future + spawn-task pool. After M, since N's
   wins compose on top of M's pooled conn-state lifetime.
10. ✓ **G** (TSO) — landed for HVF + virtio-net (2026-05-08).
    Single-super-segment TX path delivers +25% on
    `diagnostics_tls_max` 1c (multi-segment shape). KVM / GCE
    validation deferred until we're back on a Tier 1 bench
    cycle, but the descriptor-side support is generic so the
    next bench should exercise it without further code changes.
11. **J** (compression) + **K** (0-RTT) + **L** (Early Hints)
    when we shift focus from local benchmarks to Internet-facing
    serving.

End state after step 6: **1 memcpy per byte on QUIC**, and **2 on
TCP TLS** (a chain→slot copy + the in-place AES-128-GCM encrypt
R/W). The two paths were briefly at parity when item D's fused
copy+encrypt landed, but D was reverted on the ChaCha20 →
AES-128-GCM migration (the audited `aes-gcm` crate has no fused
copy-and-encrypt API), so TCP regained the copy pass. QUIC stays
at one because its encoder writes straight into the datagram and
the AEAD seals there. Dropping TCP back to 1 would mean
hand-rolling fused AES-CTR + GHASH (item D) or moving the encrypt
to NIC offload via TLS-offload — both their own rabbit holes.

E is a low-effort cleanup that can land any time; F is now
effectively covered by the 2026-05-19 uniform-checksum offload.

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
- **2026-05-08** — Cleanup pass after Q (`2beb525`, `47a0590`):
  * Factored `resolve_dst_mac` (duplicated in `tcp.rs` and
    `udp.rs`) into a new `:dst_mac` leaf module.
  * Collapsed `udp::send_to_addr` to delegate to
    `send_with_l2_headroom` (one site for header-fill logic;
    -120 LOC of duplicated code).
  * Updated stale comments in `proto/quic` referencing the
    pre-Q `sock.send_to(&vec)` flow.
- **2026-05-08** — Item **B landed for TCP** (`936f03f`,
  `84777e2`): SG TX API + TCP wiring. Driver exposes
  `acquire_tx_buf` / `submit_tx`; TCP `send_segment` /
  `send_segment_from_cursor` write directly into the TX pool
  slot, no intermediate memcpy through a stack buffer. Bench
  HVF /health: 1c +5%, 2c +13%, 3c +14%. UDP/QUIC integration
  is **B2** (separate item) — needs the QUIC encoder to write
  into a TX pool slot directly (replace `outbound: VecDeque<
  Vec<u8>>` with `VecDeque<TxBufHandle>`).
- **2026-05-08** — Item **D landed** (`39c034e`, `fef3c63`,
  `25858e3`): fused copy+encrypt for TLS single-record path.
  Earlier deferral was wrong — `cipher 0.4.4` exposes
  `apply_keystream_b2b` which uses the same SIMD backends as
  in-place. New `chacha20poly1305_seal_chain_to` primitive
  (with KAT against `seal_chain`), wired through TrafficKey
  → record::seal_chain_to_in_place → TlsServer →
  TlsConn::send_app_data_chain_to → TlsStream::send fused fast
  path on chains ≤ 16 KiB. Bench within noise on /health (need
  larger body to surface the per-byte savings).
- **2026-05-08** — Item **B2 landed** (`68f985f` + this commit):
  QUIC encoder writes directly into a driver TX-pool slot. New
  `DatagramBuf` enum with `Heap(Vec<u8>)` and
  `TxSlot { handle: TxBufHandle, vec: ManuallyDrop<Vec<u8>> }`
  variants. `Connection::take_datagram_buf` tries
  `executor::reactor::acquire_tx_buf` first and wraps the slot's
  data region as a `Vec` via `from_raw_parts` (capacity = 1514,
  len pre-set to 62 B headroom for L2/L3/L4). Encoder writes
  packet bytes via the existing `&mut Vec<u8>` surface (audited:
  push / extend_from_slice / truncate / split_at_mut only — no
  realloc-triggering calls). Reactor's three drain sites (the
  `drain_outbound` method + the PTO probe drain + the main loop
  drain) collapse into a shared `ship_datagram` helper that
  dispatches on the variant: TxSlot ships zero-copy via
  `send_via_tx_handle` (the bare-metal backend fills the
  L2/L3/L4 headers in the slot's headroom in place — IPv6 is
  pure zero-copy; IPv4 does an in-place `ptr::copy` to slide the
  payload back 20 bytes); Heap falls back to
  `send_to_with_l2_headroom` and recycles the Vec. End state:
  **1 memcpy per byte** on the QUIC TX hot path (just the
  encrypt R/W pass), matching post-B TCP. Bench HVF
  health_tls_max 1c steady at ~108 k req/s; QUIC integration
  test green (`test_hvf`, `test_mc_hvf`).

- **2026-05-09** — Multi-driver TX-path overhaul
  (`78bfc60`...`a301ef0`):

  * **`proto/http`**: per-worker TLS record scratch (cfg-gated
    bare-metal) — caps the 16 KiB per-conn future state at one
    worker-static buffer regardless of conn count. Removes the
    broken `TlsConn` trait defaults that made
    `send_app_data_chain_to` look like it ignored its `dst`.
    `body_iobuf` headroom cleanup (chain prepend supersedes it).

  * **`net::tcp`**: `async_try_send_chain` uses TSO
    unconditionally when the driver advertises it (was gated
    `total > mss`, missed the per-segment CSUM offload win on
    sub-MSS sends). `build_and_send_frame` simplified down to
    one direct-fill path; slice-shaped fallback retained for
    drivers that don't expose direct-fill.

  * **`crates/drivers/virtio-net`**: TX pool is now per-worker
    (`WorkerTxPool` indexed by worker id) regardless of
    `num_queue_pairs`. On Tier 2 (single shared qp + multi-core)
    slot allocation stays lock-free; only the virtq submit step
    takes `TX_LOCK`. `acquire_tx_buf` spin-drains on full pool.
    The legacy SPSC staging-ring path is retired.

  * **`net+drivers`**: `NicOps` gains `csum_tx_offload` +
    `csum_stamp_convention` query. `CsumOffload { start, offset }`
    rides on `submit_tx`. New `tcp_pseudo_partial` helper for
    pre-stamping. virtio-net wires `NEEDS_CSUM` for TCP control
    + per-MSS data fallback + UDP / QUIC datagrams (HVF
    `diagnostics_tls_max` +10%). Two stamp conventions
    encoded:
    `PseudoHeaderPartial` (virtio) and `Zero` (gve).

  * **`crates/drivers/gve`**: direct-fill TX path for GQI_QPL
    (validated on n2-highcpu-4 / GVNIC). DQO_RDA implementation
    exists with the spec-correct fixes from Linux's
    `gve_tx_dqo` (RE spaced ≥ 32 descs per
    `GVE_TX_MIN_RE_INTERVAL`; DESC completion's `tx_head`
    drives `done_cnt` instead of per-PKT counts), but is gated
    off (`acquire_tx_buf` returns `None` on DQO) — c3-standard-4
    still stalls under sustained parallel load even with the
    fixes. CSUM-offload bits are wired into both modes
    (`GVE_TXF_L4CSUM` for GQI; `checksum_offload_enable` byte-8
    bit 6 for DQO) but `csum_tx_offload` returns `false`:
    enabling regresses health_max -19/-32% across both stamp
    conventions, suggesting either an unnegotiated adminq
    feature or a different `type_flags` bit encoding than Linux's
    docs imply. Both gates flip on with one-line changes once
    debugged.

  GCE deploy/bench validation via `deploy-gcloud.sh`
  (`waitless-webserver-image` on n2 + c3) and
  `gcp-deploy-bench.sh`. n2 `health_max` 469K req/s the first
  bench session, ~322K subsequently — variance attributed to
  GCE network. Both VMs stopped between iterations to keep
  spend trivial.

  Open follow-ups: gve DQO direct-fill stall (needs on-host
  diagnostic counters); gve CSUM-offload negotiation; gve TSO
  (multi-descriptor with separate big QPL — substantial chunk
  of work, not started).

- **2026-05-09** — gve GQI fallback + CSUM offload re-enable
  (`2d7ecaa`, `d807ab1`):

  * **Queue-format priority flip**: `higher_priority` ranks
    `GQI_QPL > GQI_RDA > DQO_QPL > DQO_RDA` (Linux ranks DQO_RDA
    highest). C3 advertises both formats; our DQO TX still stalls
    under sustained parallel load even with all the spec-correct
    fixes from Linux's `gve_tx_dqo`. Falling back to GQI_QPL on
    c3 is a no-op on n2/n2d/e2 (GQI_QPL only) and unblocks c3.
    Bench on c3-standard-4 (4 vCPU, GQI_QPL direct-fill):
        health_max:        466 238 req/s
        health_tls_max:    298 431
        h3_health_max:      73 187
        udp_peak:          826 198

  * **CSUM TX offload re-enabled** with
    `CsumStampConvention::PseudoHeaderPartial` (matching Linux's
    `CHECKSUM_PARTIAL` skb path): caller pre-stamps the
    pseudo-header sum at the L4 cksum field; device adds data
    and folds. Earlier disabling was based on n2 numbers that
    didn't reproduce on c3 GQI direct-fill — now neutral perf
    with offload on.

  * **`tx_pages_per_qpl` parsing**: the offset-20 slot in
    `gve_device_descriptor` was previously read as `reserved2`;
    Linux's `gve_adminq.h` shows it's `tx_pages_per_qpl` (the
    device's advertised cap on TX QPL pages). Now parsed and
    logged. The cap is advisory: Linux uses `tx_desc_cnt /
    GVE_QPL_DIVISOR = 4` pages and FIFO-packs many packets per
    page; our 1-page-per-slot model uses 256 pages and the
    device permits the overflow on every gVNIC variant tested.

- **2026-05-09** — TX-path saturation + load-distribution
  diagnostics (`52430d8`). Adds `NicDiagOps::tx_diag` ↦ JSON in
  `/stats` so we can answer four questions live without
  redeploying:

  * **Are pool sizes saturating?**
    `tx_small_full_spins` and `tx_big_full_returns` count every
    pool-exhaustion event on the hot path. Stays at 0 for both
    drivers under c3 4-vCPU bench (14 M small-pool acquires,
    zero saturation events) — current sizing has plenty of
    headroom.

  * **Are linear scans expensive?**
    `tx_small_acquires` × `tx_small_scan_iters` lets the reader
    compute average scan depth on `[AtomicBool; N]` freelists.
    HVF: 1.24. c3 GCE: 3.37 (out of 256 = 1.3% of pool). Linear
    scan is effectively O(1) under measured loads — a real
    freelist refactor isn't motivated yet; revisit if future
    loads push avg depth into double digits.

  * **Are pools dynamically sized?**
    Not yet. virtio-net pool is per-worker fixed (64 small +
    16 big). gve TX QPL is `TX_RING_ENTRIES = 256` slots. The
    device advertises `tx_queue_entries` (and now
    `tx_pages_per_qpl`) which we log but don't yet use to
    drive runtime sizing. Future work: heap-allocate the per-qp
    `slot_used` arrays from the device-advertised count rather
    than the static `[AtomicBool; TX_RING_ENTRIES]` so a
    different gVNIC variant doesn't quietly waste or under-provision
    memory.

  * **Is load spreading evenly?**
    `tx_packets_per_qp[]` reveals the answer per run. c3 4-vCPU
    bench:
        qp 0: 25.3 %     qp 1: 21.6 %
        qp 2: 17.3 %     qp 3: 36.4 %    (← 2.1× of qp 2)
    Aggregate scaling still 4× (Remote 4c health_tls_max
    189 188 req/s) so total throughput isn't lost — but the
    hottest queue is 2× the load of the coldest. The bench
    client (`kvm-vm`, single source IP, many parallel src
    ports) hashes through the Microsoft Toeplitz key into our
    `i % num_qp` indirection table; under that traffic shape
    the key biases. Follow-up: try alternate keys + log a
    chi-squared p-value alongside the per-qp counts.

  Counter cost: one relaxed atomic per acquire / submit /
  saturation event. Bench rerun after wiring counters
  (health_tls_max 4c = 189 K) is within noise of the prior
  pre-counter run (190 K) — instrumentation is free.

- **2026-05-09** — gve TSO attempt (parked).
  TSO scaffolding implemented end-to-end (big-pool of 16×20 KiB
  slots carved from the same QPL, pool_id flag in driver_token,
  `acquire_tx_tso_buf` / `submit_tx_tso` writing the GQI TSO
  pkt_desc + SEG desc pair per Linux's `gve_tx_fill_pkt_desc` /
  `_seg_desc`, `tx_drain` branched on the descriptor type byte).
  Local `test_qemu_x86_64` and HVF tests pass — code is
  structurally correct.

  GCE c3-standard-4 deploy with `tso_available: || true` boot-
  hangs: HTTP /health probe never returns, regardless of the
  exact slot/page sizing. With `tso_available: || false` the
  pool-split itself runs but TLS-over-TCP returns 0 req/s, while
  HTTP/3 over UDP/QUIC works (TSO is bypassed there). The TCP
  path emits a TSO+SEG descriptor pair on every send (the layer
  unconditionally uses TSO when the driver advertises it),
  including the small HTTP /health response — so any descriptor
  bug in `submit_tx_tso` shows up as a complete TX-path
  failure on the first packet.

  Without serial-port-output access on the GCE VM (sandbox
  permission is gated), narrowing further from "first TSO
  send fails" requires either:
    1. a dev path that surfaces the gve-side panic over an
       HTTP `/diagnostic` endpoint (driver counters + last
       descriptor bytes), or
    2. tcpdump on the receive side (kvm-vm) to see what the
       device emits, or
    3. comparing wire bytes of a Linux gve TSO send against ours.

  Implementation reverted to keep the validated GQI-fallback
  + CSUM-offload state shippable. Resume TSO when one of the
  above debug paths is in place.

- **2026-05-10** — **gve TSO unparked, end-to-end working on GCE
  GQI_QPL** (`e4f8235`, `ad68340`).

  Reapplied the parked TSO scaffold (`ae692d3` content) on top of
  the multi-segment TSO gate (`2cdbbff`) and the /diag-gve
  descriptor capture (`955c9ed`). The new debug path made the
  remaining bug visible from the host side without serial-port
  access:

  * `tso_available: || true` + the `total > mss` gate in
    `async_try_send_chain` kept /health on the proven STD path,
    so the boot HTTP probe came up clean.
  * `/diag-gve` returned the 16-byte TSO + SEG pair as written.
    Bytes matched Linux's `gve_tx_fill_pkt_desc` /
    `gve_tx_fill_seg_desc`: TSO has
    `type=0x11 (TSO|L4CSUM), l4_csum_off=0x08, l4_hdr_off=0x11
    (=34/2), desc_cnt=2, len=total, seg_len=hdr_len,
    seg_addr=big_pool_qpl_off`; SEG has `type=0x20, l3_off=0x07,
    mss=0x05B4 (=1460), seg_len=payload, seg_addr=+hdr_len`.
  * Wire trace (tcpdump on kvm-vm receive side) confirmed the
    server's /diagnostics response landed intact — the receiver's
    GRO reassembles into one 9745 B PSH frame.

  Bug exposed by the path that *didn't* work: HTTPS /health
  (post-handshake response under MSS) timed out, while HTTPS
  /diagnostics (record over MSS) succeeded. Root cause: the
  TLS-direct `try_send_tso` path (proto/http `TlsStream::send`)
  gated only on `src.total_len() <= PLAINTEXT_CHUNK` — i.e. it
  used TSO for ANY chain fitting one record, including
  single-segment responses. **gve hardware silently drops
  sub-MSS TSO frames** (the descriptor pair lands on the ring,
  the device fetches them, but no packet emerges). The
  `async_try_send_chain` path had this gate (`total > mss`)
  but TLS-direct bypassed it.

  Fix: thread a `min_payload` lower bound through
  `TcpStream::try_send_tso` and the backend trait; TLS passes
  `src.total_len() + 22` (record-overhead constant); bare-metal
  `tcp::try_send_tso` short-circuits to `None` when
  `min_payload <= mss`, so TLS falls through to its worker-scratch
  + small-pool path.

  GCE n2-highcpu-4 (gVNIC, GQI_QPL) numbers, post-fix:

  | Workload                | req/s   | Note                  |
  |-------------------------|---------|-----------------------|
  | health_max              | 517 242 | STD small-pool        |
  | health_tls_max          | 335 549 | STD small-pool + TLS  |
  | h3_health_max           |  87 118 | UDP/QUIC (TSO bypassed) |
  | diagnostics_tls_max     |  33 606 | **TSO path**          |

  All counters healthy: `tx_big_acquires` increments per
  TSO send, `tx_big_full_returns = 0`, `tx_small_full_spins = 0`.
  100 % success on a 100× mixed-load mix of /health + /diagnostics
  over HTTPS.

  Open items unaffected:
  * **DQO direct-fill stall** (c3-standard-4 only). GQI_QPL is
    the priority format; c3 falls back to GQI_QPL until the DQO
    stall is debugged.
  * **HVF TSO bench** (G's prior +25% on diagnostics_tls_max 1c)
    still applies — virtio-net path unchanged.

- **2026-05-19** — Uniform `send()`-side L4 checksum offload
  (`12ad396`, `9eb0588`, `37eabf2`).

  The 2026-05-09 design had the guest pick full-vs-partial checksum
  from a global `csum_tx_offload()` query, but the driver `send()`
  paths disagreed on what to do with the frame: virtio-net and
  gve-GQI shipped it verbatim, gve-DQO self-classified and offloaded.
  Two bugs fell out of that split:

  * TCP `build_and_send_frame`'s slice-shaped fallback stamped the
    pseudo-header partial, then shipped via `send()` — on virtio-net
    / gve-GQI the partial went out uncorrected (corrupt segment;
    reachable on gve-GQI under TX-pool exhaustion).
  * UDP `send_with_l2_headroom` stamped the *full* checksum and
    shipped via `send()` — on gve-DQO, `send()` offloads, so the
    device double-counted the payload.

  Fix: `send()` is now a uniform contract. The guest always stamps
  the pseudo-header partial sum; `send()` gained a `CsumOffload`
  parameter (symmetric with `submit_tx`), and every driver finishes
  the checksum — device CSUM offload, or a software pass
  (`net_checksum::internet_checksum`) when the device never
  negotiated `VIRTIO_NET_F_CSUM`. virtio-net tracks `has_csum`
  apart from `has_tso4` for that decision.

  `NicOps::csum_tx_offload` and the `net_l4_tx` crate are gone — the
  guest no longer chooses. The `UdpCsum` enum and the dead
  `l4_checksum` / `l4_checksum_v4` helpers went with them. Supersedes
  the `csum_tx_offload` + `csum_stamp_convention` mechanism in the
  2026-05-09 "Multi-driver TX-path overhaul" entry above.

- **Item R landed** — DQO UDP-GSO. The device segments UDP
  super-buffers via the TSO descriptor path (it reads TCP vs UDP
  from the IP-protocol byte), so `acquire_tx_udp_gso_buf` returns
  the DQO TSO slot and `submit_tx_udp_gso` reuses `submit_tx_tso`
  verbatim; c3-validated. GQI / virtio / HVF stay on the
  per-datagram fallback. Wiring: `udp_gso_available:
  tx::udp_gso_enabled` (`lib.rs:704-706`) + `tx.rs:54-63`.
