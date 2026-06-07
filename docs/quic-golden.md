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

## After (in progress)
