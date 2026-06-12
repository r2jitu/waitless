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

## Round 2 — six small loadgens (same day, hash 64 K `0e435b8`)

Redesigned rig: 6× e2-standard-4 (4 vCPU each; global-CPU quota caps
server 8 + loadgens 24), each driving only N/6 conns — far from any
per-IP port ceiling, so the round-1 client-side pathologies vanish.
wrk -t4, 240 s window, 60 s timeout, fresh `instances reset` per shot.

| target | live @90/150/210 s          | sum rps | errors (all LGs) |
|-------:|------------------------------|--------:|------------------|
| 200 K  | 199,995 / 199,995 / 199,995 | 421,601 | 30 read |
| 240 K  | 240,316 / 240,002 / 240,001 | 332,219 | 1,639 read, 8 timeout |
| 280 K  | dead — guest self-terminated | (5,358) | ~40 K connect |

**240,000 live TLS connections, rock-stable for 4 minutes.** The rps
drop vs the c3-loadgen runs is the clients (e2 vCPUs are weak; each
conn cycles ~1.4–2.1 req/s) — the server's /health p50 stayed ~240 ms
at 240 K conns under closed-loop load.

**280 K kills the server**: the GCE instance went TERMINATED
(guest-initiated shutdown — the panic→arch_shutdown path), reproduced
twice. Consistent with the documented 2026-05-24 heap-OOM signature
(~280 K × ~55 KB/conn ≈ 15.4 GB ≈ the whole 16 GB heap); serial
capture wasn't enabled so the exact panic site is unconfirmed. The
"refuse new work at 90 % heap" admission guard demonstrably does not
cover every allocation path at this scale — filed as a roadmap gap.

## Round 3 — tokio-hyper on the same six-loadgen rig (fairness check)

The 80 K tokio-hyper failure above was measured on the TWO-loadgen rig.
Re-measured on the identical six-loadgen rig (and on the 2-LG rig at
70 K/75 K, where it holds: 70,011 and 75,003 live):

| target | estab @90/150/210 s          | sum rps | errors |
|-------:|-------------------------------|--------:|--------|
| 100 K  | 99,990 / 99,990 / 99,990     | 460,537 | none |
| 160 K  | 159,991 / 159,991 / 159,991  | 448,569 | ~2.1 K read |
| 200 K  | 181,145 / 185,741 / 190,337  | 397,318 | 41 K connect + 71 K read — never converged |
| 240 K  | 91,932 / 80,659 / 73,409     |     492 | 1.15 M connect; p50 22–31 s — metastable collapse |

**Correction to round 1's implication:** tokio-hyper does NOT have a
~60 K connection ceiling — that was the 2-IP client herd interacting
with its accept path. Given six client IPs it serves 160 K cleanly.
The fair deltas: Waitless establishes the same 200 K/240 K targets
exactly and holds them (240,001 stable for 4 min); tokio-hyper churns
at 200 K and collapses completely at 240 K. Waitless also handled the
harsher 2-IP herd at 80 K that stalled tokio-hyper at 59,607.
