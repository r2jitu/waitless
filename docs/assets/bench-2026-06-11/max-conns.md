# Connection-ceiling probes (2026-06-11, post arena-32K bump `0292a82`)

Three 8-vCPU loadgens (kvm-vm, waitless-peer-nginx: c3-highcpu-8;
waitless-loadgen3: n2-highcpu-8), each driving N/3 conns, wrk -t8,
HTTPS /health, server waitless c3-highcpu-8 (fresh `instances reset`
before each shot). live = server-side /obs live_conns gauge.

| target | window | live (samples)            | sum rps | notes |
|-------:|-------:|---------------------------|--------:|-------|
| 100 K  | 90 s   | 89,708 @45s               | 820,519 | back-to-back with prior point (TIME_WAIT debris) |
| 128 K  | 90 s   | 82,978 @45s               | 672,348 | same, worse debris; kvm-vm 25 K connect errs |
| 150 K  | 90 s   | 111,443 @45s              | 578,173 | same |
| 150 K  | 180 s  | 131,960 @70s, 135,730 @130s | 720,601 | fresh server; 60 s client timeout |
| 160 K  | 180 s  | 140,046 @80s, **143,164** @140s | 696,637 | fresh server + drained loadgen TIME_WAIT |

Server-side at every point: pool_exhausted=0, spawn_failures=0, heap
2–3 GB of 16 GB, rps steady ~700 K. The shortfall vs target is
client-side: kvm-vm consistently lost ~30 K conns to connect timeouts
(its ephemeral-port pool: client tcp_tw_reuse needs TCP timestamps,
which waitless defers — T6), and abandoned-then-retried handshakes
collide with their own orphaned conns (RFC 5961 challenge-ACK, mostly
rate-limit-throttled: syn_rx 565 K vs synack_tx 328 K across the three
90 s probes). A 4th loadgen was quota-blocked (24 c3 + 8 n2 vCPUs).
