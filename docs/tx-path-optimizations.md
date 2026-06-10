# TX path optimizations — tracker

A living plan for trimming the TX path between application-layer
encrypt and the wire. Covers both HTTPS-over-TCP and HTTPS-over-H3
(QUIC). Each item below is sized to land as one (or a small batch
of) commit(s); DONE items are collapsed to one-line ledger entries
(full implementation narrative lives in git log), open items are
kept in full.

> **See also:** [`high-concurrency-perf.md`](high-concurrency-perf.md)
> for the high-conn cliff context. Items A–C, G already moved
> `cycles/request` down significantly. Remaining TX-side lever
> tracked there is the AES-GCM cipher choice.

## Why this doc exists

We measured the per-byte guest-side memcpy count starting at **5
memcpys per byte** for both HTTPS-over-TCP and HTTPS-over-H3 (QUIC)
(≈ 4.5 GB/s of memcpy traffic at 100 k rps for a 9 KiB shell page).
Most of those were mechanical header-prepend memcpys that fall away
once the buffer is composed in place. The encrypt step itself is a
fundamental R/W that can't be removed; for QUIC the encoder writes
plaintext straight into the datagram and the AEAD seals it there in
place (one pass), while the TCP TLS chain path copies into the
TX-slot and then seals in place (two passes) — the AES-128-GCM crate
exposes no fused copy-and-encrypt API to collapse those into one
(see item D).

This doc captures the inventory, splits proposals across the two
segments the user named — *encrypt → NIC TX* and *network → browser
RX* — and tracks progress as we land them.

## Current path — TCP (HTTPS over TLS)

| # | Step | Site | Cost per byte | Cost per record | Notes |
|---|------|------|---|---|---|
| 1 | Handler renders body | `body_iobuf` writer | 1× memcpy (dynamic content only) | — | Static literals are zero-copy |
| 2 | Header build | `write_response_into_iobuf` | — | ~150 B memcpy | Into per-conn `header_storage` |
| 3 | ~~TLS coalesce~~ | — | — | — | Folded into step 4 — `TlsStream::send_one_record` fast-fast path seals directly into the driver's TX-pool big-slot (item TLS-direct ✓) |
| 4 | TLS encrypt + envelope | `record::seal_chain` (→ `aead::seal_chain`) | 1× copy chain→slot + 1× R/W (AES-128-GCM, GHASH-authenticated) | — | Chain bytes copied into the TX-slot, then sealed in place. **Not** a fused copy+encrypt anymore: the AES-GCM crate exposes no fused copy-and-encrypt API, so item D's single-pass `seal_chain_to` was dropped on the ChaCha20→AES-128-GCM migration (see item D) |
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
The copy lands straight in the TX-slot (no intermediate stack
buffer / worker-scratch hop), but copy and encrypt are two passes,
not the single fused pass item D once delivered (no fused
copy-and-encrypt API in the AES-GCM crate; see item D). Down from
5 before items A, C, B, G, and the TLS-direct-encrypt commit. The
copy re-reads L1-resident bytes, so the DRAM cost is closer to one
R/W than two. Same structure as the QUIC TX path (encoder write +
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
summary above and item D).

## Segment 1 — Inside the unikernel (TLS encrypt → NIC TX)

### A. Fold TCP/IP/Eth wrap memcpys into one buffer — ✅ done (`bcf2e8d`, `e3c7e08`)
-2 memcpys/byte on TCP TX. Slow paths (UDP, ARP, ICMP) keep the layered `send_l3 → ipv4_send → ethernet_send` functions; only the TCP hot path builds [ETH][IP][TCP][PAYLOAD] in one buffer via `fill_header` helpers.

### B. SG TX API (direct-fill from caller into the TX pool) — ✅ done (TCP `936f03f`/`84777e2`; QUIC B2 `68f985f`)
> The *shape* of this NIC TX submit-surface (acquire/fill/submit vs. memcpy-target) is owned by [`stack-architecture.md`](stack-architecture.md); this item owns the per-byte TX-cost it eliminates.
-1 memcpy/byte on TCP and QUIC TX. `acquire_tx_buf() -> Option<TxBufHandle>` + `submit_tx`; caller writes straight into the pool. Tier-2 shared qp returns `None` (avoids cross-core lock contention); GVE stubbed `None`, falls back to `send(&[u8])`. QUIC B2 reshaped `Connection::outbound` to `VecDeque<DatagramBuf>` (`Heap` / `TxSlot` enum); audited `&mut Vec<u8>` write surface (push/extend_from_slice/truncate/split_at_mut — never `reserve`, capacity 1514). The 2026-06-06 stream-retx work briefly regressed this to 2 R/W/byte (retain-until-ACK copied via `pop_chunk().to_vec()`); fixed 2026-06-10 — `pop_chunk` returns `clone_shared` refcounted IOBuf views (h3 /health 8.4 → 6.0 allocs/req).
- **Note (`send_on_qp` busy-spin)**: still present in the slow path (ARP/DHCP/ICMP/UDP + the TCP fallback when the pool is full). The hot path no longer busy-spins (acquire returns `None` on full → falls to `send(&[u8])` which still spins). Open: worth replacing with parking-async in a future cleanup.

### C. Bake the record envelope into the scratch — ✅ done (`e6d9a28`)
-2 small Heap allocs per TLS record. Scratch sized `[u8; 5 + 16384 + 17]`; record header via `prepend`, type byte + tag into tailroom — zero allocs from the seal.

### D. Fuse copy + encrypt in scratch — ✅ done then REVERTED (`39c034e`, `fef3c63`, `25858e3`; reverted on AES-GCM migration)
Do-not-redo without a profile: the audited `aes-gcm` crate exposes **no** fused copy-and-encrypt API (the original `apply_keystream_b2b` trick was ChaCha20-specific). The TLS chain path is back to copy-into-slot + `encrypt_in_place_detached`, so TCP counts 2 per-byte passes again. Re-trigger only if a profile justifies hand-rolling fused AES-CTR + GHASH (`aes::Aes128` + `ghash::GHash`). The copy-then-encrypt keeps scratch L1-resident between passes, so actual DRAM cost is already ~1R+1W/byte — likely single-digit % cycle win.

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

### F. Drop checksums on loopback / negotiate `VIRTIO_NET_F_CSUM` — ✅ done (2026-05-19 uniform `send()`-side L4 checksum offload)
virtio-net negotiates `VIRTIO_NET_F_CSUM` and the guest stamps only the cheap pseudo-header partial sum, handing the device an unchecksummed segment via `NEEDS_CSUM`; full per-byte `internet_checksum` runs only as the software fallback. The TCP table step-5 "+1 cksum" is that ~20-byte partial stamp, not a per-byte read.
- Open (low-value): the original "drop even the partial on host-loopback" angle is not done — the partial stamp is a fixed ~20-byte cost, not per-payload-byte.

### P. Apply A's `fill_header` pattern to UDP TX — ✅ done (`1494f06`)
-2 memcpys/byte for any UDP traffic (incl. QUIC); `udp::send_to_addr` builds [ETH][IP][UDP][payload] in one buffer. Slow-path callers (UDP socket reactor, DHCP) keep the layered API.

### Q. Encode QUIC packets directly into the TX framing buffer — ✅ done (`2224cd7`, `46ab22e`)
-1 memcpy/byte on QUIC TX. `take_datagram_buf` pre-reserves 62 B at the front of each outbound Vec; encoder writes at offset 62; reactor's `send_to_with_l2_headroom` fills L2/L3/L4 headers in the pre-reserved space. Encoder rollback semantics required truncate-on-rollback support in the buffer contract — the careful-audit point if this is ever touched again.

### R. UDP GSO on DQO TX — ✅ done (DQO via the TSO descriptor path; c3-validated)
The device reads TCP vs UDP from the IP-protocol byte, so `submit_tx_udp_gso` reuses `submit_tx_tso` verbatim and `acquire_tx_udp_gso_buf` returns the DQO TSO slot. GQI / virtio / HVF stay on the per-datagram fallback. Wiring: `udp_gso_available: tx::udp_gso_enabled` ([`gve/src/lib.rs:704-706`](crates/drivers/gve/src/lib.rs#L704-L706)) + [`gve/src/tx.rs:54-63`](crates/drivers/gve/src/tx.rs#L54-L63).

## Segment 2 — Wire & receive (NIC TX → browser RX)

### G. TSO (TCP Segmentation Offload) — ✅ done (HVF + virtio-net 2026-05-08; gve/GCE GQI_QPL 2026-05-10)
Bumped `MAX_ETH_FRAME` 1514 → 16512 so one TX-pool slot fits a 16 KiB super-segment; `tso_available()` + `submit_tx_tso(...)` at the driver layer; TCP collapses the per-MSS loop into one `send_super_segment_from_cursor`. HVF bench /diagnostics (~9 KiB) +25% 1c. **gve hardware silently drops sub-MSS TSO frames** — the TLS-direct path now threads a `min_payload` lower bound and short-circuits to the small-pool path when `min_payload <= mss` (see 2026-05-10 progress entry). Memory cost: +1 MB heap/worker for the larger TX pool (TX_POOL_SIZE 64 × 16512); could shrink TX_POOL_SIZE under TSO — deferred.

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

> ⚠️ **The cold-conn alloc table below is stale (2026-05-29 efficiency audit — see
> [`benchmark-results.md`](benchmark-results.md) for the verified current state).**
> `rx_buf` (#4) and `pt_buf` (#6) were **removed** from `TlsServer` (only `tx_buf`
> remains); the conn-future path is now `reactor/tcp.rs`, not `net/tcp.rs`. The
> **steady-state keep-alive** figure that matters is now **1 alloc/req** (the
> borrowed-header `into_owned` retain in `tcp/state.rs` `rtx_push`; `e284d00`
> removed a second). The sub-MSS `/health` response takes a **3-memcpy scratch-seal
> fallback** (misses the TSO direct-encrypt path) — the audit's #1 TX reduction
> target. Treat the audit as authoritative; this table is kept as cold-first-request
> history.

Original cold-conn measurement: **/diagnostics over HTTPS/1.1 = 11 allocs**,
**over H3 = 19 allocs** for a cold-conn first request.

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
| 9 | seal trailer Heap IOBuf (17 B) | `seal_chain_in_place` | per-record (removed by item C) |
| 10 | seal header Heap IOBuf (5 B) | `seal_chain_in_place` | per-record (removed by item C) |
| H3 +1..+8 | per-packet/frame `Vec::with_capacity` | `proto/quic/src/conn.rs` (frame & datagram encode) | per H3 packet |

Item **C** removed #9 / #10. Item **#8** (VecDeque overflow) is one
alloc per conn, amortized via retained capacity — not tracked
separately (page-specific `INLINE_PARTS` tuning is fragile, cost is
bounded). The remaining per-conn-accept allocs (#1–#7) are the lever
for items M / N below.

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

### O. QUIC encode-side `Vec` recycling (H3 path) — ✅ done (effectively landed by Q, 2026-05-08)
The per-packet staging Vecs were removed when `encode_one_rtt_packet` was reshaped to write directly into the datagram `out` buffer; remaining `Vec::with_capacity` sites fire only during conn handshake (~4-8 allocs/conn, not per request). Aioquic H3 leak tests (`test_ctrlc_h3_persistent_session_no_leak`, `test_ctrlc_h3_hammer_no_per_conn_leak`) tightened to strict `HEAP_LEAK_CHECK ok`.
- **Open (Chrome residue, separate bug)**: a real Chrome refresh-spam session against `/diagnostics` over H3 leaks +9 allocs / ~8 KiB at shutdown — Chrome-only, not aioquic. Shape: "first 3 requests clean, plateau at ~9 allocs after" — doesn't match the encode-Vec hypothesis. Smoking-gun candidates are Chrome-specific frames aioquic doesn't send: PRIORITY_UPDATE on the H3 control stream (RFC 9218), QPACK encoder-stream insert probes (we negotiate capacity 0 but discard them), or Chrome's PING/keepalive cadence. Bounded follow-up; doesn't gate other items.

## Recommended sequence

Optimises for: (a) close the easy mechanical wins first, (b) bring
QUIC's per-byte memcpy count to parity with TCP before chasing the
structural QUIC payoff, (c) defer foundational/risky items until
they unlock something concrete.

1. ✓ **A + C** — TCP TX wrap memcpys + TLS seal envelope.
2. ✓ **P** — UDP TX wrap fold (mirror of A).
3. ✓ **Q** — QUIC packets into framing buffer.
4. ✓/✗ **D** — fused copy+encrypt; landed then reverted on the AES-GCM migration. See item D.
5. ✓ **B** (TCP) — direct-fill TX pool.
6. ✓ **B2** (UDP/QUIC) — direct-fill extended to QUIC via `DatagramBuf::TxSlot`; heap fallback on pool exhaustion.
7. ✓ **O** — effectively landed by Q (Chrome residue filed as separate follow-up; see item O).
8. **M** (conn-state pool) — the alloc-side equivalent of A+C;
   biggest *alloc-count* win whenever conn churn matters. Land
   any time after we have a conn-churn workload to bench against
   — local keep-alive bench won't show it.
9. **N** — conn-future + spawn-task pool. After M, since N's
   wins compose on top of M's pooled conn-state lifetime.
10. ✓ **G** (TSO) — landed for HVF + virtio-net + gve GQI_QPL.
11. **J** (compression) + **K** (0-RTT) + **L** (Early Hints)
    when we shift focus from local benchmarks to Internet-facing
    serving.

End state: **1 memcpy per byte on QUIC**, **2 on TCP TLS** (chain→slot
copy + in-place AES-128-GCM encrypt R/W). The two paths were briefly
at parity when item D's fused copy+encrypt landed, but D was reverted
on the AES-GCM migration, so TCP regained the copy pass. Dropping TCP
back to 1 would mean hand-rolling fused AES-CTR + GHASH (item D) or
moving the encrypt to NIC offload — both their own rabbit holes.

E is a low-effort cleanup that can land any time; F is covered by the
2026-05-19 uniform-checksum offload.

## Progress log

Compact ledger; full narratives are in git log and the now-one-lined
items above. Only entries recording a non-obvious decision/reversal
are kept.

- **2026-05-08** — Doc created; baseline 5 memcpys/byte both paths. Items **A**, **C**, **P**, **Q**, **B** (TCP), **B2** (QUIC), **D** all landed same day (commits per items above). **D** initially deferred then landed once `cipher 0.4.4`'s `apply_keystream_b2b` was found, then later reverted on the AES-GCM migration.
- **2026-05-09** — Multi-driver TX-path overhaul (`78bfc60`…`a301ef0`): per-worker TLS record scratch + per-worker virtio-net TX pool (legacy SPSC staging-ring retired); `NicOps` gained `csum_tx_offload` + stamp-convention query (later removed 2026-05-19); gve GQI_QPL direct-fill validated. **Decision:** DQO_RDA direct-fill stalls under sustained parallel load even with all spec-correct `gve_tx_dqo` fixes — kept gated off.
- **2026-05-09** — Queue-format priority flipped `GQI_QPL > GQI_RDA > DQO_QPL > DQO_RDA` (Linux ranks DQO_RDA highest) so c3 falls back to GQI_QPL until the DQO stall is debugged — no-op on n2/n2d/e2 (GQI_QPL only). CSUM TX offload re-enabled with `PseudoHeaderPartial` (`2d7ecaa`, `d807ab1`). `tx_pages_per_qpl` (offset-20, was misread as `reserved2`) now parsed; cap is advisory (device permits our 256-page overflow on every gVNIC tested).
- **2026-05-09** — TX saturation diagnostics (`52430d8`, `tx_diag` → `/stats`). **Findings:** pools never saturate under c3 4-vCPU bench (0 events on 14 M acquires); linear-scan depth effectively O(1) (HVF 1.24, c3 3.37/256) — no freelist refactor motivated. RSS load-spread biased (hottest qp 2.1× coldest) under single-source-IP bench traffic through the Toeplitz `i % num_qp` table; aggregate scaling still 4×. Pools not yet dynamically sized from the device-advertised count — future work.
- **2026-05-09 → 2026-05-10** — gve TSO: first attempt parked (sub-MSS TSO sends silently dropped, no serial-port access on GCE to debug). Unparked via the `/diag-gve` descriptor-capture path (`e4f8235`, `ad68340`). **Root cause:** gve hardware silently drops sub-MSS TSO frames; the TLS-direct `try_send_tso` path bypassed the `total > mss` gate. Fix threads a `min_payload` lower bound (TLS passes `total_len + 22`) so sub-MSS TLS falls through to the small-pool path.
- **2026-05-19** — Uniform `send()`-side L4 checksum offload (`12ad396`, `9eb0588`, `37eabf2`). **Decision/supersedes:** removed the guest's `csum_tx_offload` choice (and `net_l4_tx` / `UdpCsum` / `l4_checksum*`) — `send()` is now a uniform contract: guest always stamps the pseudo-header partial, each driver finishes the checksum (device offload or software pass). Fixed two corruption bugs from the old split (uncorrected partial on virtio/GQI; double-counted full sum on DQO).
- **Item R landed** — DQO UDP-GSO via the TSO descriptor path (device reads TCP vs UDP from the IP-protocol byte); c3-validated. GQI / virtio / HVF stay on the per-datagram fallback.
