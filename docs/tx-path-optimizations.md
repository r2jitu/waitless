# TX path optimizations — tracker

A living plan for trimming the HTTPS TX path between TLS encrypt and
the wire. Each item below is sized to land as one (or a small batch
of) commit(s); check items off as we ship them.

## Why this doc exists

We measured the per-byte memcpy count on the guest TX side at **5
memcpys per byte** of HTTPS response (≈ 4.5 GB/s of memcpy traffic at
100 k rps for a 9 KiB shell page). Most of those are mechanical
header-prepend memcpys that fall out of the way once the IOBuf chain
is plumbed through the L4/L3/L2 stack. The TLS encrypt itself is a
fundamental R/W and can only be fused with the surrounding copy, not
removed.

This doc captures the inventory, splits proposals across the two
segments the user named — *TLS-encrypt → NIC TX* and *network →
browser RX* — and tracks progress as we land them.

## Current path (one HTTPS response)

| # | Step | Site | Cost per byte | Cost per record | Notes |
|---|------|------|---|---|---|
| 1 | Handler renders body | `body_iobuf` writer | 1× memcpy (dynamic content only) | — | Static literals are zero-copy |
| 2 | Header build | `write_response_into_iobuf` | — | ~150 B memcpy | Into per-conn `header_storage` |
| 3 | **TLS coalesce** | `TlsStream::send` loop | **1× memcpy** | — | Chain → 16 KiB stack scratch |
| 4 | **TLS encrypt** | `seal_chain_in_place` | 1× R/W (ChaCha20) + 1× R (Poly1305) | 5 B header alloc + 17 B trailer alloc | In-place on scratch; tag computed alongside |
| 5 | **TCP segment build** | `send_segment_from_cursor` | **1× memcpy** | 20 B TCP header + checksum scan | Cursor → 1480 B stack buffer per MSS |
| 6 | **IPv4 wrap** | `ipv4_send` | **1× memcpy** | 20 B IP header + checksum | Stack → 1500 B stack buf |
| 7 | **Ethernet wrap** | `ethernet_send` | **1× memcpy** | 14 B Eth header | Stack → 1514 B stack buf |
| 8 | **virtio-net submit** | `virtio_net::send` | **1× memcpy** | descriptor add + kick | → TX pool slot, then DMA |
| 9 | virtio host pickup | (HVF userspace_net or KVM) | depends on host | — | HVF: another memcpy to host TCP socket |
| 10 | Host TCP/IP/Eth | host kernel | host-side | — | TSO can fold this on real NICs |
| 11 | Wire | network stack | — | — | MTU, cwnd, RTT |
| 12 | Browser RX | TLS decrypt + HTTP parse | symmetric to ours | — | Out of our control |

Steps 3, 5, 6, 7, 8 are the **5 guest-side memcpys per byte**. Items
A, B below collapse that to 1.

## Segment 1 — Inside the unikernel (TLS encrypt → NIC TX)

### A. Fold TCP/IP/Eth wrap memcpys into one IOBuf prepend
- **Status**: [ ] not started
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

### B. Use virtio-net SG TX descriptors
- **Status**: [ ] not started
- **Where**: `uni-driver-virtio-net/src/lib.rs::send`
  (the `ptr::copy_nonoverlapping` into `tx_pool` slot).
- **What**: virtio-net supports multi-buffer (scatter-gather) TX
  descriptors. Hand the device descriptors that point at our
  IOBuf storage directly instead of memcpy'ing into a TX pool
  slot. Drop callback returns the IOBuf to its pool when the
  device signals descriptor completion.
- **Win**: -1 memcpy per byte on top of A. On Tier 1 (KVM, real
  NIC) this is the difference between "we copy data" and "the
  NIC DMAs from our buffers".
- **Effort**: medium-high. Needs a TX completion path that drops
  the right IOBuf in `tx_drain`, and the IOBuf chain has to
  survive across the descriptor's lifetime.
- **Risk**: medium. Subtle; needs careful audit of when the host
  is allowed to read the descriptor's referenced memory.
- **Lays groundwork for**: G (TSO).

### C. Bake the record envelope into the scratch (no header/trailer allocs)
- **Status**: [ ] not started
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
- **Status**: [ ] not started
- **Where**: `uni-tls/src/aead.rs::chacha20poly1305_seal_chain`
  (or a new `_seal_copy` variant), `uni-http/src/lib.rs::send`
  loop.
- **What**: Today is two passes through the scratch — pass 1
  (`copy_from_slice` chain → scratch), pass 2 (ChaCha20 in
  place). Fuse to a single pass that reads from the chain part,
  XORs against the keystream, writes ciphertext to scratch. The
  RustCrypto trait doesn't expose this directly but it's
  straightforward to implement against `chacha20::ChaCha20`'s
  block-mode API.
- **Win**: -1 R/W pass per byte through L1/L2. Latency win,
  cache-pressure win.
- **Effort**: medium. New AEAD primitive plus tests against the
  existing single-buffer KAT.
- **Risk**: low (cryptographic correctness is testable with the
  same KAT vectors we already use).

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

## Recommended sequence

1. **A + C** together — mechanical, very testable, removes 3
   memcpys and 2 allocs per record. Tier 1 + Tier 2 both benefit.
2. **D (fused copy + encrypt)** — separable, lives in
   `uni-tls/aead`, latency win.
3. **B (virtio SG TX descriptors)** — one more memcpy gone, and
   the prerequisite for G.
4. **G (TSO)** — biggest single Tier 1 win once we benchmark on
   KVM/GCE.
5. **J (compression)** + **K (0-RTT)** + **L (Early Hints)** when
   we shift focus from local benchmarks to Internet-facing serving.

E and F are low-effort cleanups that can land any time.

## Progress log

- **2026-05-08** — Doc created. Per-byte guest-side memcpy count
  measured at 5 (steps 3, 5, 6, 7, 8). Bench baseline:
  `health_tls_max` ≈ 108 k req/s 1c HVF, ≈ 150 k 2c, ≈ 150 k 3c.
