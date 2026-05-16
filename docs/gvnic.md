# gVNIC (Google Virtual NIC)

The NIC GCE attaches to modern instances. Driver lives in
[uni-driver-gve](../uni-driver-gve/src/lib.rs); virtio-net is the
fallback on older shapes (see [crates.md](crates.md)).

PCI id `0x1ae0:0x0042`. BAR0 is the 32-bit-per-register config
window; BAR2 is the per-queue doorbell array.

## Two queue formats

gVNIC speaks two descriptor formats; the driver picks one at
bring-up from what DESCRIBE_DEVICE advertises.

| Format    | Where           | Buffers                                         |
|-----------|-----------------|-------------------------------------------------|
| `GQI_QPL` | every SKU       | Pre-registered Queue Page List; descriptors carry QPL offsets, not DMA addresses. TX is a memcpy into the QPL. |
| `DQO_RDA` | c3 / c4+        | Raw DMA addressing, split data + completion rings. Preferred on SKUs that offer it. |

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
pages. In GQI mode each ring needs a QPL of one 4-KiB page per
entry — `RX_RING_ENTRIES` pages of RX QPL, `TX_RING_ENTRIES` of TX.

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
  [gqi.rs `doorbell_write`](../uni-driver-gve/src/gqi.rs).
- **DQO** writes it little-endian (`writel`) —
  [dqo.rs `doorbell_write_le`](../uni-driver-gve/src/dqo.rs).

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
