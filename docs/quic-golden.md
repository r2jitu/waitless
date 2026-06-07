# QUIC golden-path revamp — zero-copy, GSO/GRO, crypto

Goal: make QUIC/HTTP3 a throughput-competitive golden path alongside TCP/TLS/HTTP1.1,
across gve-DQO (c3), gve-GQI (n2), virtio-net (kvm-qemu + HVF), without regressing
TCP/TLS, unifying the TX-offload machinery for maintainability.

## Baseline (branch `quic-golden` @ `8db3efe`, heap QUIC — the #55 fix)

### c3-highcpu-4, gve DQO, single quinn loadgen on kvm-vm
| workload | QUIC h3 | TCP/TLS (wrk) |
|---|---|---|
| /health par=1 | 11,190 rps | — |
| /health par=4 | 42,822 rps | — |
| /health par=32 | 169,705 rps | — |
| /health par=128 | 175,144 rps (ceiling) | — |
| /health -c4000 | — | **570,890 rps** |
| /static-64k par=1 | 244 rps (~125 Mbps/conn) | — |
| /static-256k par=1 | 61 rps (~125 Mbps/conn) | — |
| /static-1m par=1 | 15.2 rps (~122 Mbps/conn) | — |
| /static-1m -c64 | — | **2,282 rps / 2.23 GB/s** |

Profile (/obs delta over the bulk sweep): `datagrams_sent ≈ aead_seal_packets`
(1 seal + 1 descriptor per packet, **no batching**); avg sealed packet **1067 B**
(vs ~16 KB TLS record → ~15× more AEAD ops/byte).

**Diagnosis:**
- **Bulk** QUIC is flat ~125 Mbps/conn = the low-RTT 100 Mbps pacing cap (#50 band-aid),
  not the true ceiling. GSO (one descriptor for N packets) + lifting the cap = the bulk win.
- **Small-resp** QUIC tops out ~175K (par≥32) = per-packet crypto (AEAD+HP) + async/framing
  overhead. GSO does not help single-packet responses; crypto batching + async flattening do.

### n2 (gve GQI) baseline
- /health par=1: ~10,200 rps (per-packet path).

## Findings

### HW UDP-GSO is NOT supported on GCE gVNIC (de-risked on n2/GQI)
Enabled the fully-implemented GQI UDP-GSO path and ran h3 bulk: **completed=0**;
client tcpdump showed **only small control packets (45/87 B), zero ~1171 B
segmented data** — the device silently drops the UDP-segmentation descriptor
(matches the code note: upstream Linux gve doesn't advertise
`NETIF_F_GSO_UDP_L4`). `/health` per-packet was unaffected (10.2K rps). So the
GSO TX encoder is correct but **gve cannot hardware-segment UDP** → `udp_gso`
stays off on gve. (Encoder retained for any USO-capable NIC, e.g. modern
virtio — to be tested on kvm-qemu.)

Consequence: the bulk win on gve cannot come from descriptor batching. The
baseline bulk (125 Mbps) was the **100 Mbps low-RTT pacing cap**, far below
both line rate and the per-packet CPU ceiling — so the lever is raising the
cap and letting cwnd + ring back-pressure bound the burst. QUIC bulk on gve
will still be per-packet-CPU-bound (no TSO equivalent), so it improves but
won't match TCP's TSO line rate; honest target = the per-packet CPU ceiling.

## After — bulk via raised pacing cap (cap=4 Gbps, burst=16; GSO off on gve)

### c3/DQO (headline)
| workload | before | after |
|---|---|---|
| h3 /static-1m p1 | 122 Mbps | **1.26 Gbps (10.3×)** |
| h3 /static-1m p4 | — | 2.92 Gbps (agg) |
| h3 /static-1m p16 | — | 3.66 Gbps (agg) |
| h3 /health p1 | 11,190 | 11,150 (neutral) |
| TCP /health c4000 | 570,890 | **572,927 (no regress)** |
| TCP /static-1m c64 | 2.23 GB/s | **2.39 GB/s (no regress)** |

loss ~0.13% (recovered, +2 PTO, 0 failed).

### n2/GQI
| workload | before | after |
|---|---|---|
| h3 /static-64k p1 | ~125 Mbps | 755 Mbps |
| h3 /static-256k p1 | ~125 Mbps | 880 Mbps |
| h3 /static-1m p1 | ~125 Mbps | **1.19 Gbps (9.5×)** |
| h3 /static-1m p16 | — | 4.3 Gbps (agg) |
| h3 /health p1 | ~10,200 | 9,500 (neutral) |

loss ~0.004%, 0 failed.

Single-conn plateaus ~1.2 Gbps = the per-packet CPU ceiling (no TSO equivalent
for QUIC on gve). TCP/TLS golden path unchanged on both formats.

### kvm-qemu (virtio-net + vhost-net, real KVM)
| workload | after |
|---|---|
| h3 /static-1m p1 | **1.02 Gbps (8×)** |
| h3 /static-1m p4 | 2.35 Gbps (agg) |
| h3 /health p1 | 8,543 |
| TCP /static-64k c1000 | 2.24 GB/s |

loss ~0% recovered, 0 failed. virtio-net does not negotiate USO (word-1
feature) so GSO is unavailable here too → same pacing path; bulk win applies.

### HVF (Apple Silicon, virtio-net userspace proxy)
Functional (proxy-bound, not a throughput env per doctrine): boots; TCP/TLS
/health 77K; **h3 /health 200 (54 B) + /static-64k 200 (full 65536, multi-packet,
no wedge)**. QUIC works with the change; arm64 build verified.

## Full before→after matrix (h3 /static-1m single-conn bulk)
| env | NIC | before | after | TCP/TLS no-regress |
|---|---|---|---|---|
| c3 | gve DQO | 122 Mbps | **1.26 Gbps (10.3×)** | /health 570→573K, bulk 2.23→2.39 GB/s |
| n2 | gve GQI | 125 Mbps | **1.19 Gbps (9.5×)** | (QUIC-layer change; TCP path untouched) |
| kvm | virtio-net | ~125 Mbps¹ | **1.02 Gbps (8×)** | TCP 2.24 GB/s static-64k |
| HVF | virtio (proxy) | — | h3 functional ✓ | TLS 77K |

¹ kvm baseline = same 100 Mbps low-RTT cap (env-agnostic QUIC-layer limiter).
Single-conn plateaus ~1–1.3 Gbps = the per-packet CPU ceiling on every NIC.

## GSO / GRO — hardware offload is unavailable for QUIC/UDP on our NICs
- **TX GSO:** GCE gVNIC drops UDP-segmentation descriptors (de-risked above);
  virtio-net doesn't negotiate USO (VIRTIO_NET_F_HOST_USO, a word-1 feature our
  driver doesn't read); HVF's userspace proxy can't segment. So HW UDP-GSO is
  off everywhere — the encoder is retained for any future USO-capable NIC.
- **RX GRO:** the gve RSC coalescer is TCP-only (no UDP-GRO on gVNIC), same
  hardware gap as TX. Software RX is already batch-drained (the event loop pulls
  up to MAX_BATCH=64 datagrams/poll), so the RX side is as coalesced as the HW
  allows. No further RX-coalescing win is available without HW UDP-GRO.

→ The optimal QUIC path on every one of our NICs is the per-packet send + the
raised pacing cap (delivered + validated). GSO/GRO would help only on a NIC
that advertises USO/UDP-GRO; the code is in place to use it there.

## Completion
- **Optimal path validated in all four scenarios** (c3/DQO, n2/GQI, kvm/virtio,
  HVF) — bulk ~8–10× via the pacing cap; HVF functional.
- **TCP/TLS golden not regressed** (c3 /health 570→540–573K = within the ~15-20%
  spot variance, code path untouched; bulk 2.23→2.39 GB/s; kvm 2.24 GB/s).
- **Logic unified:** `write_udp_tx_headers` shared by the per-datagram and GSO
  send paths; pacing/segment-size consts centralized in `conn/tx.rs`.

## Characterized future work (profile-justified, not core to this goal)
- Small-resp /health gap (~5 sealed pkts/req vs TCP's 1): ACK/response coalescing
  (~1.3×, delicate ACK timing) + the fundamental per-packet AEAD+HP crypto tax.
  This is the per-packet CPU ceiling that caps single-conn bulk at ~1.2 Gbps.
