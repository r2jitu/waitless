# gVNIC (Google Virtual NIC)

The NIC GCE attaches to modern instances. Driver lives in
[crates/drivers/gve](../crates/drivers/gve/src/lib.rs); virtio-net is the
fallback on older shapes (see [crates.md](crates.md)).

PCI id `0x1ae0:0x0042`. BAR0 is the 32-bit-per-register config
window; BAR2 is the per-queue doorbell array.

## Two queue formats

gVNIC speaks two descriptor formats; the driver picks one at
bring-up from what DESCRIBE_DEVICE advertises.

| Format    | Where           | Buffers                                         |
|-----------|-----------------|-------------------------------------------------|
| `GQI_QPL` | every SKU       | Pre-registered Queue Page List; descriptors carry QPL offsets, not DMA addresses. TX fills the packet directly into its QPL slot (no separate bounce copy) and the descriptor points at that slot. |
| `DQO_RDA` | c3 / c4+        | Raw DMA addressing, split data + completion rings. Preferred on SKUs that offer it. |

The two TX paths are **not** at feature parity:

- **GQI_QPL** is the full TX path: a two-pool direct-fill allocator
  (small pool = one packet per 4 KiB QPL page; big pool = one
  super-segment per 5-page slot), plus TSO (v4/v6) and UDP-GSO via
  the `GVE_TXD_TSO` + `GVE_TXD_SEG` descriptor pair, plus L4-CSUM
  offload. The device segments super-segments host-side.
- **DQO_RDA** has direct-fill and TSO; UDP-GSO is still GQI-only.
  `acquire_tx_buf` hands the caller the next ring slot's bounce buffer
  to fill in place (no scratch→bounce memcpy); `submit_tx` emits the
  general-context + packet descriptor pair carrying that buffer's raw
  DMA address. `acquire_tx_tso_buf` / `submit_tx_tso` emit a
  TSO-context (dtype 0x5) + general-context + scatter-gather packet
  descriptors so the device segments a super-segment host-side (T3,
  hardware-validated). `acquire_tx_udp_gso_buf` still returns `None` in
  DQO mode so the QUIC path falls back to the per-datagram loop (T5).
  L4-CSUM offload is wired (the `DQO_TX_FLAG_CSUM` bit). The
  earlier DQO direct-fill stall was root-caused (RE-on-every-descriptor
  + a TX-completion field-decode bug, both long since fixed in the
  slice path) and direct-fill re-landed reusing that proven emission —
  validated stall-free on c3 (see T1 below).

  > **This is the gap, and it's closable.** Upstream Linux and
  > FreeBSD both run DQO TX *fully zero-copy with scatter-gather* on
  > this exact device — the bounce buffer is our simplification, not
  > a hardware requirement, and the c3 stall was an implementation
  > bug (RE-on-every-descriptor + a completion field-decode), not a
  > hardware wall. The large-body drop-on-full-ring that drove
  > RTO-cliff p99s of 6.7–8.0 s is **fixed** (T2): the TX path now
  > back-pressures — it sends only what the ring takes, leaves the
  > rest queued, and resumes on the ACK that retires the in-flight
  > burst (`tx_ring_full_drops` → 0, `/static-1m` p99 → ~22 ms). See
  > [§Upstream driver reference](#upstream-driver-reference-verified-2026-05-30)
  > and [§Optimization roadmap](#optimization-roadmap-trackable).

RX mirrors this split: DQO is zero-copy — the device's RX buffer is
lent straight up the stack (`OwnedIOBuf::wrap_owned`) and reposted
to the buffer ring when the chain drops. GQI cannot lend its device
QPL pages (strict in-order repost), so each frame is copied into a
recycle-pool slab and the QPL page is reposted at the poll-batch
boundary.

`GQI_RDA` (raw-addressing GQI) and `DQO_QPL` exist in the Linux
headers but GCE never advertises them — do not implement them.
QPL is mandatory for any GQI bring-up; DQO uses raw addressing only.

### Format by SKU family

DESCRIBE_DEVICE reply, logged at boot as `[gvnic] option id=N len=M`:

| SKU family    | Options advertised                                  |
|---------------|-----------------------------------------------------|
| n2 / n2d / e2 | id=3 (GQI_QPL), id=6, id=10, id=11                  |
| c3 / c4+      | id=3 (GQI_QPL), id=4 (DQO_RDA), id=6, id=9, id=10, id=11 |

## DESCRIBE_DEVICE option ids

Per Linux `gve_adminq.h`:

| id   | Name           | Notes                                       |
|------|----------------|---------------------------------------------|
| 0x2  | `GQI_RDA`      | Never offered by GCE                        |
| 0x3  | `GQI_QPL`      | Always offered                              |
| 0x4  | `DQO_RDA`      | Offered on c3 / c4+                         |
| 0x6  | `MODIFY_RING`  | Ring-size bounds — see below                |
| 0x7  | `DQO_QPL`      | Never offered                               |
| 0x9  | (GCE-private)  | Not in upstream headers; c3 only; all-zero payload, not a feature toggle |
| 0xa  | `BUFFER_SIZES` | len=8: `packet_buffer_size`, `header_buffer_size` |
| 0xb  | `FLOW_STEERING`| len=12: `max_num_rules`                     |
| 0xe  | `RSS_CONFIG`   |                                             |

### Option payloads (c3-highcpu-8 sample)

```
id=3  len=4   00 00 00 05                       GQI_QPL    features_mask=0x5
id=4  len=8   00 00 00 3d 04 00 04 00           DQO_RDA    features_mask=0x3d
id=6  len=12  00 00 00 00 10 00 10 00 02 00 01 00   MODIFY_RING
id=9  len=4   00 00 00 00                       GCE-private, all zero
id=10 len=8   00 00 00 00 10 00 00 80           BUFFER_SIZES  pkt=4096 hdr=128
id=11 len=12  00 00 00 00 00 00 4e 20 00 00 00 00 4e 20   FLOW_STEERING  ~20000 rules
```

`MODIFY_RING` payload is `u32 features_mask` then four big-endian
`u16`s — `max_rx`, `max_tx`, `min_rx`, `min_tx`. The sample decodes
to `max_rx=0x1000 max_tx=0x1000 min_rx=0x0200 min_tx=0x0100`. The
driver stashes these bounds and `assert!()`s that its compile-time
`TX_RING_ENTRIES` / `RX_RING_ENTRIES` fall inside them at
queue-create time.

`features_mask` bit meanings are not publicly documented; without a
spec there is no way to tell which bit gates which feature.

## Ring and QPL sizing

| Constant            | Value | Meaning                                  |
|---------------------|-------|------------------------------------------|
| `TX_RING_ENTRIES`   | 256   | TX descriptor ring depth                 |
| `RX_RING_ENTRIES`   | 512   | RX descriptor ring depth                 |
| `PAGE_SIZE`         | 4096  | QPL page size                            |

Device default ring size is 1024; `MODIFY_RING` lets the driver
shrink within `[min, max]`, which it does so a ring fits in fewer
pages. In GQI mode the RX QPL is one 4-KiB page per ring entry
(`RX_RING_ENTRIES` pages). The TX QPL is the two-pool split (176
single-page small slots + 16 five-page big slots = 256 pages, which
matches `TX_RING_ENTRIES` but isn't a per-entry mapping). In DQO
mode there are no QPLs — the RX buffer pool and TX bounce-buffer
pool are plain DMA-coherent allocations the descriptors address
directly.

`REGISTER_PAGE_LIST` (opcode 0x3) registers a QPL and returns a
`page_list_id`; CREATE_*_QUEUE then references that id. In DQO mode
the queue uses `queue_page_list_id = 0xFFFFFFFF`
(`GVE_RAW_ADDRESSING_QPL_ID`) instead — sending `0` makes the device
silently use QPL 0 and the data path breaks while the admin command
still PASSes.

## Doorbells

Per-queue doorbell registers live in the BAR2 window at byte offset
`db_index * 4`. Endianness differs by format:

- **GQI** writes the doorbell big-endian (`iowrite32be`) —
  [gqi.rs `doorbell_write`](../crates/drivers/gve/src/gqi.rs).
- **DQO** writes it little-endian (`writel`) —
  [dqo.rs `doorbell_write_le`](../crates/drivers/gve/src/dqo.rs).

Both wrappers issue an `sfence` (`host_dma_fence()`) before the MMIO
store — see the WB→UC hazard below.

## Hardware hazards

These are durable device/CPU-architecture facts, not transient bugs.
Every one cost a multi-round root-cause; respect them in any future
ring code.

**Masked-doorbell collision — never fill a ring completely.** A
doorbell carries the *masked* producer position (`producer & mask`).
The device compares that tail to its own head and treats
`tail == head` as "ring empty". If a ring fills completely, the
masked tail wraps onto the head, the device reads it as empty, and
**stops servicing the queue permanently** — per-qp, silent, every
egress packet dropped. Any gVNIC ring whose doorbell is a masked
position must keep at least one slot's worth of headroom. The RX
ring leaves its last slot empty for exactly this reason; the TX path
caps `in_flight` at `ring_entries - 2`.

**WB→UC store-buffer race — fence before every doorbell.** The
driver writes a descriptor to WB-cached DMA ring memory, then rings
the doorbell via a UC MMIO store. PCIe DMA reads snoop the CPU
caches but *cannot* snoop the private store buffer, so the doorbell
TLP can race the descriptor's drain — the device samples a stale
`valid == 0` and strands the packet with no completion. An `sfence`
immediately before the doorbell drains the store buffer.
`atomic::fence` / `compiler_fence` emit zero instructions on x86
(TSO) and are **not** sufficient.

**PCIe-TLP torn reads — read DMA fields with one aligned load.** A
multi-byte field in device-written DMA memory must be read with a
single aligned `read_volatile` (one `mov`), never assembled from
byte-wise loads. The device's PCIe write of the cache line can land
between two byte loads, yielding a half-old / half-new value. For a
DQO `buf_id` that aliases to the wrong RX buffer and the frame is
silently lost. Pair the gen-bit check with a `compiler_fence(Acquire)`
(Linux's `dma_rmb()`) so LLVM can't hoist the field loads above it.

## VPC fabric constraints

- **MTU = 1460, not 1500.** GCP's VPC reserves 40 bytes for its
  encapsulation (GENEVE/GRE). Frames over 1460 bytes are dropped.
  Size RX buffers and TCP MSS accordingly.
- **Checksum offload needs the explicit CSUM bit.** The net stack
  stamps a pseudo-header partial sum (`CHECKSUM_PARTIAL` shape). In
  DQO mode the `DQO_TX_FLAG_CSUM` bit must be set on the packet
  descriptor or the partial leaks onto the wire and the fabric drops
  the IP frame. DQO TX also requires a general-context descriptor
  (DTYPE 0x4) ahead of each packet descriptor.
- **Real Toeplitz RSS.** Unlike GCE's legacy virtio backend, gVNIC
  spreads 4-tuples across queues, so multi-queue (Tier 1) RX scales
  with cores on both network- and compute-heavy workloads.

## Launching a gVNIC instance on GCE

```
gcloud compute instances create NAME \
  --network-interface=nic-type=GVNIC,...
```

The image must carry `--guest-os-features=GVNIC`;
[scripts/deploy-gcloud.sh](../scripts/deploy-gcloud.sh) applies it
unconditionally (virtio-net instances just ignore it).

## Upstream driver reference (verified 2026-05-30)

The two authoritative gVNIC drivers are Google's own. Our descriptor
formats and constants were checked **byte-for-byte** against them and
match; the items below are facts we confirmed, not folklore. When in
doubt about device behaviour, read these first — they are the spec.

- **Linux (in-tree):** `drivers/net/ethernet/google/gve/` — esp.
  `gve_desc_dqo.h`, `gve_tx_dqo.c`, `gve_rx_dqo.c`, `gve_adminq.h`,
  `gve_main.c`. <https://github.com/torvalds/linux/tree/master/drivers/net/ethernet/google/gve>
- **FreeBSD:** `sys/dev/gve/` and Google's out-of-tree
  [compute-virtual-ethernet-freebsd](https://github.com/GoogleCloudPlatform/compute-virtual-ethernet-freebsd);
  the [`gve(4)` man page](https://man.freebsd.org/cgi/man.cgi?query=gve&sektion=4&format=html)
  is a concise feature summary.

What upstream proves (both OSes agree):

| Claim | Upstream evidence | Our status |
|---|---|---|
| DQO TX desc = 16 B; `dtype` 0–4 = `0xC`, `end_of_packet` b5, `checksum_offload` b6, `report_event` b7; `buf_size` 14-bit (max 16383); ctx dtype `0x4`, TSO ctx `0x5`; `GVE_TX_MIN_RE_INTERVAL = 32` | `gve_desc_dqo.h` (exact match) | ✅ ours is faithful |
| **DQO TX is scatter-gather**: a packet spans up to `GVE_TX_MAX_DATA_DESCS = 10` data descriptors; `end_of_packet` set only on the last | `gve_tx_dqo.c` loops `for i in nr_frags`, `is_eop = i==nr_frags-1`; FreeBSD `cur_eop = eop && cur_len==len` | ❌ we emit 1 bounce desc/pkt, always EOP |
| **DQO TX is truly zero-copy**: the no-copy path DMA-maps the packet's *own* memory (`dma_map_single`/`skb_frag_dma_map`; FreeBSD `bus_dmamap_load_mbuf_sg`). The bounce copy runs **only** when `tx->dqo.qpl` is set | `gve_tx_add_skb_no_copy_dqo` vs `_copy_dqo`; FreeBSD man: *"RDA … does not expect [packets] to be copied into or out of a fixed bounce buffer"* | ❌ we always bounce-copy (a simplification) |
| Buffer lifetime tracked by `pending_packets[completion_tag]`: hold the DMA map / skb until the matching TX completion arrives, then unmap+free | `gve_alloc_pending_packet` / `gve_handle_packet_completion` / `gve_unmap_packet`; FreeBSD `pending_pkts[compl_tag]` | ◑ analog exists: our rtx `share()`/`clone_shared` retains until ACK (⊇ TX completion) |
| **DQO RX RSC (HW-GRO)** emits coalesced super-frames as **multi-buffer** packets: RX compl desc carries `rsc`, `rsc_seg_len`, `header_len`; `end_of_packet` only on the last buffer; "HW-GRO only coalesces TCP" | `gve_rx_dqo.c` `gve_rx_complete_rsc` + multi-buf loop (`if (!end_of_packet) continue;`) | ❌ our RX drops non-EOP frags → `enable_rsc=1` alone is a no-op |
| `enable_rsc` is a real per-queue field in `CREATE_RX_QUEUE` (not a feature-mask) | `gve_adminq.h` `struct gve_adminq_create_rx_queue { … u8 enable_rsc; }` | ✅ we set it; needs the multi-buf RX path to do anything |
| The device supports **MSI-X + per-queue NAPI** (mgmt vector + per-queue `gve_intr_dqo` → `napi_schedule_irqoff`) | `gve_main.c` `pci_enable_msix_range`, `request_irq` | ❌ we are polling-only (`idle: None`) — our choice, not a HW limit |
| FreeBSD also ships **software LRO**, TSO, RX/TX csum, RSS, jumbo, and a `hw.gve.allow_4k_rx_buffers` tunable (4 KiB RX bufs, DQO only) | `gve(4)` man page | reference for feature scope |

Two corrections to earlier folklore this verification overturned:
1. "DQO has no scatter-gather / the bounce buffer is required" — **false.** SG + zero-copy are native; we just haven't wired them.
2. "the c3 DQO direct-fill stall might be a hardware limit" — **false.** Upstream runs no-copy SG TX in production on this device; our stall is a diagnosable driver bug (suspects: descriptor/ctx ordering, RE-interval spacing, completion-tag handling, masked-tail headroom).

## Optimization roadmap (trackable)

Goal: bring DQO (the c3/c4+ golden-path NIC) to feature + performance
parity with upstream, and close the measured gaps. **Scope honestly**
— per the GCE per-stage profile the saturated `/health` bottleneck is
per-frame driver work at ~1 frame/req; most items below are
**bulk-transfer or large-response** wins, *not* `/health` wins. Each
item lists: what · why · where · expected impact · how to verify ·
status.

Status legend: `[ ]` not started · `[~]` partial/landed-but-gated ·
`[x]` done · `[!]` blocked on diagnosis.

### Tier 1 — measured correctness gaps (do first)

- `[x]` **T1. Diagnose the DQO TX stall, then land direct-fill.**
  *What:* root-caused the stall and re-landed `acquire_tx_buf`
  direct-fill, killing the per-frame bounce memcpy.
  *Diagnosis (git archaeology, commits `1a1915d`→`f7711a4`→`abc6fac`):*
  the original direct-fill stall was **not** a hardware limit and
  **not** unique to direct-fill — it was two bugs in the shared DQO TX
  code, both **already fixed** in today's slice path: (1) the
  TX-completion drain decoded the generation bit / type from the
  *reserved* byte, so `done_cnt` never advanced and the qp froze once
  `fill_cnt - done_cnt` hit `ring_entries` (masked by sub-ring-depth
  traffic; saturated under parallel load) — fixed to byte-0
  bit-7/bits-0..3; (2) `report_event` was set on **every** descriptor,
  violating `GVE_TX_MIN_RE_INTERVAL = 32` so the device stopped
  emitting completions under load — fixed to RE every 32 descriptors.
  Plus the general-context (DTYPE 0x4) descriptor the device requires
  was added. The slice path embodying all three is the stable c3
  golden path, so its descriptor emission is proven correct.
  *Implementation:* extracted the slice path's capacity gate
  (`tx_reserve`) and descriptor emission (`emit_ctx_pkt`) into shared
  helpers; `dqo::acquire_tx_buf`/`submit_tx` fill the same per-slot
  bounce buffer in place and emit the identical (ctx, pkt) pair.
  Buffer lifetime, slot==pkt_idx convention, RE spacing, and the
  `ring_entries-2` masked-tail headroom are unchanged — no new hazard.
  *Verified on c3-highcpu-8 (gVNIC DQO), raw `wrk`/`/obs` output:*
  **no stall** — `/health` TLS c4000 -t8 = **467,960 rps**, 0 socket
  errors, 8 cores balanced (rx_max/min 1.12×); `/health` plain
  = **851,229 rps**. `/health` neutral vs the prior plateau (~454K)
  as predicted — direct-fill removes a memcpy but `/health` is at
  irreducible per-frame work. The `/static-*` win it unblocks is
  **gated on T2**: large bodies still hit the ring-full drop (see T2).
  *Status:* done, landed on main.

- `[x]` **T2. DQO TX back-pressure (stop dropping on a full ring).**
  *What:* stop the silent `let _ = send_on_qp` drop on a full TX ring;
  send only what the ring takes, leave the rest queued, and resume on
  the ACK that retires the in-flight burst.
  *Why:* with T1 landed this was the top lever — the large-response
  cliff was entirely here. Pre-T2 on c3-highcpu-8 (raw): `/static-64k`
  TLS c4000 = 33,179 rps, `tx_ring_full_drops` **+103,027**, p99
  **7.49 s**, 84 timeouts; `/static-1m` c1000 = 2,349 rps, **+27,719**
  drops, p99 **8.27 s**, 119 timeouts. Ring = 256 desc = 128 pkt/qp; a
  64 KB response ≈ 45 frames, 1 MB ≈ 715 — one response overran it and
  the overflow dropped → RTO.
  *Implementation (no new wake plumbing needed):* `nic::has_direct_fill()`
  distinguishes `acquire_tx_buf`'s two `None` cases (no direct-fill vs
  ring-full). `build_and_send_frame` returns `bool`, returning `false`
  on a full direct-fill ring **without** running `fill` so the chain
  cursor stays un-read. `send_segment_from_cursor` → `bool`;
  `send_per_mss_fallback`/`send_super_segment_from_cursor` →
  bytes-actually-sent; `async_try_send_chain` advances `snd_nxt` + the
  rtx queue by that `actually_sent` and returns `Ok(actually_sent)`.
  `Ok(0)` parks the reactor's `TcpSendChain` (existing); since the
  in-flight burst is now really on the wire (not dropped), the peer
  ACKs it and the existing `tcp_receive` `usable_window()>0` wake
  re-polls the send within an RTT once the ring has drained —
  RTT-clocked bursts instead of an RTO cliff.
  *Verified on c3-highcpu-8 (gVNIC DQO), raw `wrk`/`/obs` output:*
  **cliff eliminated** — `/static-1m` TLS c1000 p99 **8.27 s →
  22.24 ms** (370×); `/static-64k` c4000 p99 **7.49 s → ~2.0 s**;
  `tx_ring_full_drops` **0**, **0 timeouts** (were 84/119), and only
  **2** total `data_retransmits` (`rtx_giveups=0`) → no wire loss.
  `/health` TLS -t8 = **450,803 rps**, neutral (hot path unaffected).
  rps stays bandwidth-bound (~2.2 GB/s egress on one loadgen) — the
  win is latency + zero failed requests, not rps.
  *Residual:* the `/static-64k` c4000 p99 ~2 s tail is
  egress-saturation queueing under 4000 conns (no drops, no RTO) — we
  traded the drop+RTO cliff for bounded back-pressured queueing.
  *Status:* done, landed on main. ([[reference_tx_async_spin_measured]])
  *Sub-RTT TX-refill — TRIED + REVERTED (do not re-attempt as a plain
  yield).* The TX ring already drains every event-loop iteration
  (`poll_qp_inner`→`tx_drain` runs before `executor::tick`), so the
  obvious next step was: on a full ring with an open window, have the
  send future **yield** (self-wake → re-polled next tick, after the
  reap) instead of waiting for the ACK. No interrupts needed — TX is
  already polled. Implemented via `TcpBackend::send_should_yield`
  (`usable_window()>0` ⇒ ring-blocked ⇒ yield; else park on ACK) and
  validated on c3-highcpu-8 — **net negative, reverted:** it tightened
  *medium*-response tails (`/static-64k` c1000 p99 1.43 s → **77 ms**;
  c4000 ~2.0 s → ~540 ms) but **regressed large responses 42×**
  (`/static-1m` c1000 p99 22 ms → **932 ms**) and flattened the 64k
  distribution (p50 0.5 ms → 100 ms). Cause: a 1 MB response is ~715
  frames through a 128-slot ring, so "wake every ring-blocked sender
  each tick" is a thundering herd *and* round-robins large transfers
  into starvation — whereas TCP's ACK-clock already paces each conn by
  its `cwnd` and pipelines bursts. On GCE's low RTT, ACK-pacing is
  near-optimal and strictly more balanced; the poll-driven refill only
  helps when ACK arrival is the bottleneck (high BDP), which this
  fabric isn't. A *work-conserving* variant (wake exactly N senders for
  N freed slots, FIFO) would kill the herd but still wouldn't beat
  cwnd-clocked pacing for large transfers — so the whole direction is
  parked. Reverted before merge; ACK-paced back-pressure (above) is the
  shipped behaviour.
  *High-RTT check (the colocated bench can't see it) — settled the
  whole TX-ring-refill direction with data.* Real clients are 10–100s
  of ms away; colocated GCE RTT is ~0.1 ms, so per-conn BDP ≪ ring and
  the bench is blind to RTT effects. Induced one-way delay on the
  loadgen (`tc netem`) and measured single-conn `/static-1m`: throughput
  collapses **5,753 Mbps (≈0 RTT) → 18 Mbps (25 ms) → 8.6 Mbps (50 ms)**,
  scaling as `1/RTT`, and is **per-connection** (`-c4` ≈ 4×). But the
  yield build measured **byte-identical** at every RTT (2.25 / 1.08
  rps) — the sub-RTT refill changed *nothing*. Reason: the 128-pkt ring
  is *larger* than `cwnd` for most of a 1 MB transfer (slow-start ramps
  10→20→40→80→160 pkts over RTTs), so the conn is **window-limited,
  parking on ACK correctly** — never ring-limited, so `send_should_yield`
  never fires. **The high-RTT collapse is TCP congestion control
  (slow-start / cwnd growth), not the TX ring** — so SPSC frame queues,
  TX-completion wakers, and deeper rings (all of which target the ring)
  provably can't help it (measured). It also looks ~3× below textbook
  slow-start (8.6 vs ~26 Mbps for 1 MB/50 ms) — *that* gap, if real, is
  the lever for distant clients and lives in congestion control (IW,
  slow-start growth, idle-restart, delayed-ACK interaction), a separate
  subsystem from anything gve. Tools: `tc netem delay Nms` on the
  loadgen `ens3`, `wrk -t1 -c1 /static-1m`.

### Tier 2 — throughput offloads (after T1)

- `[x]` **T3. DQO TSO (TCP segmentation offload).**
  *What:* the device segments a super-segment host-side from a
  TSO-context descriptor (dtype `0x5`) + general-context descriptor +
  scatter-gather packet descriptors, instead of the driver framing
  ~11 per-MSS packets for a 16 KiB TLS record. Built on T1's
  direct-fill; mirrors the GQI TSO path.
  *Implementation:* `dqo::build_tso_ctx_desc` / `acquire_tx_tso_buf` /
  `submit_tx_tso` / `emit_tso_descs`; a ≈20 KiB-slot TSO big-pool
  appended to the DQO TX bounce alloc (reusing `TxQueue::big_slot_used`);
  big slots reclaimed by `compl_tag` (≥ `TX_RING_ENTRIES`) on the PKT
  completion in `tx_drain`. Descriptor format verified against verbatim
  upstream (`gve_desc_dqo.h` + `gve_tx_dqo.c`).
  *Verified on c3-highcpu-8 (gVNIC DQO), raw output:* **correct +
  hardware-validated.** `/static-1m`×3 returns the full 1,048,576 B,
  `/static-64k` returns 65,536 B (no silent drops); `DQO_TX_TSO_SENT`
  climbs to 2.8 M on `/static-1m` and `+1` on `/health` (sub-MSS skips
  TSO, as designed); 0 ring-full drops / 0 timeouts. `/diag-gve`
  readback decodes byte-perfect — TSO-ctx `tso_total_len=16406`
  (one TLS record), `mss=1460`, `header_len=54`, `cmd_dtype=0x25`; SG
  pkt descs `16383` (no EOP) + `77` (EOP), shared `compl_tag`,
  `addr += 16383`. *Throughput:* neutral vs T2 (`/static-1m` 2.4K rps
  p99 25 ms; `/static-64k` 35 K rps; `/health` 463 K) — **egress-
  bandwidth-capped** (~2 GB/s/8-vCPU on c3; cores idle-spin at
  `rt/loop≈0.004`, not request-saturated), so TSO's real win (cuts a
  64 KB response from ~90 descriptors to ~16, offloads per-segment
  framing+csum) shows as freed CPU, not rps, below the egress ceiling.
  Would manifest as rps only on a request-saturated (multi-loadgen /
  higher-egress) host. *Status:* done, landed on main.

- `[x]` **T4. DQO RX RSC (HW-GRO) = items I→J — done & c3-validated.**
  *What:* (I) multi-buffer RX chain accumulation — stitch non-EOP
  fragment completions into a per-qp pending chain (static
  `PENDING_CHAINS`, single-writer-per-qp), deliver on EOP, ~100 ms
  stuck-chain timeout; fast path (single-buf EOP) byte-identical to
  pre-I. (J) `enable_rsc=1` in `CREATE_RX_QUEUE` (DQO only).
  *Implementation:* `dqo::poll_qp_inner` (error-skip vs accumulate +
  fast/slow path), `lib.rs` `PendingChainCell`/`PENDING_CHAINS`,
  `net/stack/rx.rs` chain-aware `tcp_receive_segment`
  (`shrink_total_len`), `init.rs` `enable_rsc` byte at cmd-offset 58.
  *Device config verified against upstream `gve_adminq_create_rx_queue`
  / `gve_rx_compl_desc_dqo`:* `enable_rsc` is the ONLY create-queue
  field RSC needs — header-split is independent and NOT required
  (`header_buffer_size = 0`; HW-GRO carries full headers in frag[0]);
  our completion reads (packet_len/generation/EOP/buf_id) are unchanged
  under RSC; `rsc`/`rsc_seg_len` are GSO hints we ignore. So the prior
  branch's "device-config gap" was a misdiagnosis — the real
  prerequisite is the item-I accumulator.
  *Verified on c3-highcpu-4 (gVNIC DQO), raw `gcp-deploy-bench` 4c/8s,
  single-run:* **no catastrophe** + a real bulk-RX win — upload TCP rx
  throughput **+14–19%** (`upload_32k_tcp` 1998→2379 MB/s,
  `upload_256k` 2196→2588, `upload_1m` 2277→2588), **`upload_1m` p99
  60 ms → 20 ms (3×)**, `get_tcp` serve **neutral** (560K→555K).
  Counters clean both builds: `rx_compl_skipped=0`,
  `rx_pending_chain_timeouts=0`; `rx_buf_reposts` **107.8M → 43.1M for
  ~equal bytes** = RSC coalescing into ~2.5× fewer/denser buffers. The
  +% is single-run (near SPOT variance) but the structural signals
  (repost ratio, p99, clean counters, no catastrophe) are robust.
  *Status:* done on branch `t4-dqo-rsc`, merged to main. ([[reference_gve_rsc_investigation]])

- `[ ]` **T5. DQO UDP-GSO (QUIC/H3 TX).**
  *What:* mirror GQI's UDP-GSO for DQO (currently the DQO branch is
  a no-op stub). *Why:* one GSO send vs ~10 per-MSS sends on QUIC/H3
  bulk — +20–50% on `h3_*`/`udp_peak`. Nothing for TCP/`/health`.
  *Where:* `tx.rs:51` (`submit_tx_udp_gso` early-returns on DQO),
  `dqo.rs`. *Verify:* `h3_health_max` / `udp_peak` on c3. *Status:*
  blocked on T1; GQI is the reference impl.

### Tier 3 — lower priority / scoped-small

- `[ ]` **T6. DQO csum-offload re-enable.** Wired (`DQO_TX_FLAG_CSUM`)
  but `csum_tx_offload` returns false — enabling it regressed
  health_max −19/−32%, so it's off pending a descriptor-encoding
  debug. Small-packet win only. *Where:* `lib.rs` `csum_tx_offload`.
- `[x]` **T7 (idle path). gve idle-yield — e2-small idles at 99.3 %.**
  Goal: stop busy-spinning on a shared burstable host. **Done and
  measured on real e2-small.** A polling NIC (gve, `idle: None`, no RX
  IRQ) used to busy-spin an idle core at ~100 %. Now, once a core is
  *sustained*-idle (`idle_rounds >= DEEP_IDLE_ROUNDS`, entry.rs
  `idle_cb`), it issues the timer-bounded HLT — and the vCPU **actually
  sleeps**: live `/obs` delta, no traffic, 2 cores = **99.3 % idle,
  ~1010 HLT-wakeups/s, ~1.02 ms slept per HLT** (the 1 ms LAPIC timer).
  Stable across a stop/start (fresh host placement) and load-responsive
  (drops under load, returns to 99 % when quiet).
  **The key was the HLT *pattern*, not a capability.** An earlier
  prototype that HLT'd *unconditionally* (every idle commit, high
  frequency) measured only ~5 % idle / ~1–2 µs per HLT — which looked
  like "HLT doesn't block on e2". It was actually KVM's *adaptive
  halt-polling*: a high-frequency HLT stream keeps the poll window open
  (host busy-polls, never deschedules). Gating the HLT to fire only
  after the core has been busy-idle for a while resets that into the
  block regime, so KVM deschedules the vCPU on HLT and it sleeps the
  full 1 ms. (Earlier notes claiming a hard "platform wall / HLT is a
  NOP / MWAIT masked so it's hopeless" were wrong about the conclusion —
  MWAIT *is* masked, but plain HLT blocks fine given the right pattern.)
  **Default ON, safe by construction:** `idle_cb` is only reached after
  the event loop spins a full idle window with no work, and
  `idle_rounds` resets on any work, so under saturation the HLT path is
  never entered and the c3 throughput headline is untouched. Cost: the
  first packet after *sustained* idle waits up to the 1 ms re-poll
  (gve has no RX IRQ to wake sooner) — negligible for a website. Verified:
  both arches build, all host + qemu-x86_64 + HVF tests pass, qemu-TCG
  idle ~5 %. See [[reference_idle_cpu_spin]].
- `[x]` **T7 (MSI-X RX wake-on-packet) — DONE, both formats.** Erase
  the ~1 ms re-poll above: a deeply-idle core arms its RX notification
  block's MSI-X + IRQ doorbell (gve/src/irq.rs, via `nic::arm_rx_idle`
  from the same deep-idle gate) so the timer-bounded HLT wakes the
  instant a packet lands. gve stays `idle: None`; this only adds
  wake-on-packet to the gate, so the busy-poll/throughput path is
  unchanged. Entries are programmed **masked** and unmasked only from the
  gate, so a busy core never arms — the saturated path is interrupt-free
  by construction (the device config was already MSI-X-ready: base_idx=0,
  mgmt vector last per upstream, so no change to `CONFIGURE_DEVICE_RESOURCES`).
  **GCE-validated both formats:** GQI (e2/n2) and DQO (c3) each show 99 %
  idle preserved, 20/20 served after idle, ~2 IRQ/req, no storm, clean
  latency (~115-170 ms WAN, matching pre-T7). The IRQ-doorbell encoding
  differs by format (GQI `GVE_IRQ_*` big-endian; DQO `GVE_ITR_*`
  little-endian) but **both disable via the same `GVE_IRQ_MASK` bit-30
  mask** — the gap that took DQO so long. The DQO storm was first fixed by
  setting the ITR coalescing interval via update mode (`ENABLE | ((us>>1 &
  0xFFF)<<5)`, not `GVE_ITR_NO_UPDATE`); but a far worse regression then
  surfaced — the server worked until the first deep-idle arm, then went
  non-responsive (RX frames received, responses lost to a retransmit
  storm). Root cause, found by diffing **FreeBSD `gve_mask_all_queue_irqs`**:
  we were disabling the DQO interrupt by writing `0` (which re-evaluates
  the whole ITR register — enable+interval+update-mode — and disrupts the
  queue's RX→response path), where the correct disable is `GVE_IRQ_MASK`
  (bit 30), the universal mask bit FreeBSD writes for *both* formats.
  Ruled out along the way (each a c3 deploy): irq_db_index collision
  (logged the layout — distinct), steering (`topo.apic_ids[qp]` IS core
  qp's APIC id, smp.rs), multi-queue (GQI on n2-4core is clean → the bug
  was DQO-format-specific). Obs: `/obs` `nic.counters.rx_irq`.
  See [[reference_idle_cpu_spin]].
- `[ ]` **T8. 4 KiB RX buffers on DQO** (`BUFFER_SIZES` id=10
  advertises 4096; FreeBSD has `allow_4k_rx_buffers`). Lets more RSC
  coalesces stay single-descriptor, reducing T4 stitching pressure.
  Cheap; do alongside T4.

### What is NOT a lever (ruled out, don't re-litigate)

- **`/health` throughput micro-opts.** Allocation removal (magazine,
  rtx-inline), idle-poll tuning, and RX/TX batching are all already
  done or measured-flat; the saturated `/health` 39% NIC residual is
  irreducible per-frame DMA/descriptor work at 1 frame/req. The
  remaining levers above are bulk/large-response, not `/health`.
- **`GQI_RDA` / `DQO_QPL`.** GCE never advertises them.

> **Honest expectation-setting.** Every confirmed lever here is
> bulk-transfer (T3/T4/T5/T8), large-response latency (T1/T2), or
> low-load power (T7). The headline `/health` rps number is already
> at a well-tuned plateau and these will not move it. They make the
> *large-response and bulk-upload/QUIC* paths competitive with a
> Linux gVNIC host — which is the right next frontier now that the
> small-request path is saturated on irreducible work.
