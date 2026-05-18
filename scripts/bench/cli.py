"""CLI entry — argparse, the WORKLOADS table, and the main dispatch
loop. Drives each (env, cpus, workload) tuple through
`envs.start_env_verified` + the matching `workloads.run_*` function
and prints a summary table at the end.
"""

import argparse
import fcntl
import os
import subprocess
import sys
import time
from contextlib import contextmanager


# Number of host CPU cores. Used to threshold when the load generator
# is saturating — e.g. on a 4-core MacBook running a 3-core HVF guest
# alongside a bench that spends 3.5 CPU-cores driving traffic, there
# isn't enough headroom left for the guest and the result is
# client-bound, not server-bound.
_HOST_CPUS = os.cpu_count() or 1


@contextmanager
def measure_client_cpu():
    """Measure how much CPU the load generator consumed while the
    block runs. Captures parent + all terminated children (wrk
    subprocesses, multiprocessing pool workers, C udp_bench, ...)
    via `os.times()`, which includes `children_user` and
    `children_system` in its tuple.

    Yields a dict that populates on exit with:
      * `cpu_sec`  — CPU-seconds used
      * `wall_sec` — wall-clock seconds elapsed
      * `cores`    — cpu_sec / wall_sec (1.0 = one fully-busy core)

    The caller prints `cores` alongside the throughput number so a
    run that reports "150k req/s, cli=3.8cpu" on a 4-core host is
    visibly client-bound (~95% of host capacity was the bench
    itself). A saturated load generator can't drive the server at
    its real peak, so that's a signal to either reduce target load,
    reduce client parallelism, or run the client on a different
    machine.
    """
    t0 = time.monotonic()
    start = os.times()
    info = {"cpu_sec": 0.0, "wall_sec": 0.0, "cores": 0.0}
    try:
        yield info
    finally:
        end = os.times()
        wall = max(time.monotonic() - t0, 1e-6)
        cpu = ((end.user - start.user)
               + (end.system - start.system)
               + (end.children_user - start.children_user)
               + (end.children_system - start.children_system))
        info["cpu_sec"] = cpu
        info["wall_sec"] = wall
        info["cores"] = cpu / wall


def _cpu_tag(cores):
    """Format load-gen CPU usage for the per-run output line.
    Flags with ⚠ when the client used >70% of host capacity, where
    a result is more likely client-bound than server-bound."""
    sat = "⚠" if cores >= 0.7 * _HOST_CPUS else ""
    return f"cli={cores:.1f}cpu{sat}"


def _throughput_tag(rps, nbytes, label):
    """Wire-throughput tag for a bulk workload — `rps` requests each
    moving `nbytes` of body. `label` is `rx` for uploads (bytes the
    server receives) or `tx` for downloads (bytes it sends). Empty
    for workloads with no fixed body size (`nbytes == 0`), so
    small-request/response rows stay terse."""
    if rps <= 0 or nbytes <= 0:
        return ""
    return f"  {label}={rps * nbytes / 1e6:.0f}MB/s"


def _alloc_tag(allocs_before, allocs_after, iterations):
    """Format the allocs-per-iteration delta for the per-run output
    line. Returns an empty string (no extra tag) when sampling
    failed (`/heap` not exposed on this env, or HTTPS fetch failed)
    or when iterations is too small to give a stable ratio (<10).

    Used by tls_handshake / tls_resume / diagnostics workloads to
    surface the M-validation metric: pre-M today's path costs ~7
    allocs per accept (TlsConnImpl + 3 buffers + body_scratch + the
    boxed accept future + spawn slot), post-M target ~0 once those
    are pooled across accept/close cycles.
    """
    if allocs_before is None or allocs_after is None:
        return ""
    if iterations < 10:
        return ""
    delta = allocs_after - allocs_before
    if delta < 0:
        # Counter wraparound or server restart mid-bench — discard.
        return ""
    per_iter = delta / iterations
    return f"  allocs/iter={per_iter:.2f}"


def _cycles_per_byte_tag(stats_before, stats_after):
    """Format the TLS-encrypt cycles-per-byte derived from `/stats`
    `tls_encrypt_bytes` + `tls_encrypt_cycles` snapshots. Returns
    an empty string when sampling failed or the delta is too small
    for a stable ratio.

    Independent of wrk-side throughput: this is server-side TSC
    cycles spent in the seal hot path divided by record-layer
    bytes encrypted, so it isolates AEAD cost from network/RTT.
    Useful to confirm whether a GHASH / AES-CTR optimisation
    actually landed at the cycle level (vs only moving wall-clock).
    """
    if stats_before is None or stats_after is None:
        return ""
    db = stats_after[0] - stats_before[0]
    dc = stats_after[1] - stats_before[1]
    if db <= 0 or dc <= 0:
        return ""
    # Below ~1 MiB sampled the cycle counter is noisy (record-layer
    # fixed cost dominates over inner-loop AES+GHASH).
    if db < (1 << 20):
        return ""
    return f"  cy/B={dc / db:.2f}"


from .envs import (
    ENV_MAP,
    HvfEnv,
    KvmEnv,
    QemuAarch64Env,
    QemuEnv,
    RemoteEnv,
    start_env_verified,
)
from .workloads import (
    _udp_with_retry,
    fetch_tls_encrypt_stats,
    fetch_total_allocs,
    next_port,
    run_loadgen_gateway,
    run_loadgen_h3_health,
    run_loadgen_http_close,
    run_loadgen_http_upload,
    run_loadgen_tcp_echo,
    run_loadgen_tls_handshake,
    run_loadgen_tls_resume,
    run_wrk,
    run_wrk_https,
    echo_udp_concurrent,
)


WORKLOADS = [
    # ── Plain HTTP (TCP) ──────────────────────────────────────────────
    #
    # Three shapes of the same trivial `/health` GET:
    #   `_single` — 1 keep-alive conn (latency probe)
    #   default   — N keep-alive conns × cpus (parallel throughput)
    #   `_fresh`  — fresh TCP per request (accept-path stress)
    # Δs read off cleanly: `_single` → per-req cost, `default` →
    # parallel scaling, `_fresh` − default → accept-path cost.
    {"name": "get_tcp_single", "type": "tcp", "endpoint": "/health",
     "threads": 1, "conns": 1,
     "desc": "/health × 1 conn (single-flow latency)"},
    {"name": "get_tcp", "type": "tcp", "endpoint": "/health",
     "threads_per_core": 1, "conns_per_core": 32,
     "desc": "/health throughput (32 conn × cpus)"},
    {"name": "get_tcp_fresh", "type": "http_close", "endpoint": "/health",
     "parallelism_per_core": 4,
     "desc": "/health throughput, fresh TCP per request (Connection: close)"},

    # ── UDP ───────────────────────────────────────────────────────────
    #
    # `echo_udp` measures peak sustained server throughput via a
    # windowed (in-flight) bench with adaptive concurrency. For each
    # (env, cpus), probes `N in {32,64,128,256,512}` per client
    # thread, doubling until throughput stops improving by >5%. Each
    # of `cpus` client pthread workers maintains N outstanding UDP
    # requests on its own SO_REUSEPORT-bound sockets; a slot fires
    # its next request only after its previous reply arrives or its
    # 100 ms timeout expires. Each slot has a distinct ephemeral
    # source port so SO_REUSEPORT 4-tuple hashing distributes load
    # across server siblings — exercises the NIC's RX hash path
    # together with the UDP socket layer.
    {"name": "echo_udp", "type": "echo_udp", "endpoint": "",
     "desc": "UDP echo peak throughput (windowed + adaptive concurrency ramp)"},

    # ── HTTPS (TLS 1.3) ───────────────────────────────────────────────
    #
    # `download_64k_tls` exercises TLS bulk encrypt over the bulk-TX
    # path — pairs with `download_64k_tcp` (same body, no TLS) to
    # isolate encrypt cost.
    #
    # `get_tls_fresh` measures full TLS 1.3 handshake throughput —
    # ECDSA P-256 sign + X25519 ECDHE + key schedule + transcript
    # SHA-256 on every iteration. Δ vs `get_tls_fresh_resume` (in
    # the available tier) reads full-vs-resumed handshake cost.
    {"name": "download_64k_tls", "type": "https", "endpoint": "/static-64k",
     "threads_per_core": 1, "conns_per_core": 8, "resp_bytes": 65536,
     "desc": "/static-64k throughput over TLS (~4 records, multi-segment TX)"},
    {"name": "get_tls_fresh", "type": "tls_handshake",
     "endpoint": "/health",
     "parallelism_per_core": 4,
     "desc": "TLS 1.3 full handshake + GET + close (4 workers × cpus)"},

    # ── HTTP/3 over QUIC ──────────────────────────────────────────────
    #
    # `download_64k_quic` is the QUIC analogue of
    # `download_64k_tls`: same 64 KiB static body, different
    # transport. Δ reads off QUIC encrypt + packet-encode + UDP-emit
    # cost vs TLS record + TCP segmentation cost. No rendering
    # confound on either side — body is a borrowed `&'static [u8]`.
    {"name": "download_64k_quic", "type": "h3_health",
     "endpoint": "/static-64k",
     "parallelism_per_core": 4, "resp_bytes": 65536,
     "desc": "/static-64k throughput over HTTP/3 (64 KiB body, multi-packet)"},

    # ── Async runtime / sidecar fan-out (guest:9000) ──────────────────
    #
    # Realistic microservice workload: every accepted TCP request at
    # the unikernel fans out to a UDP backend (tokio-hosted by the
    # same loadgen process), awaits the reply, returns it. Each
    # in-flight conn parks its handler future on the backend's UDP
    # recv waker — async + syscall-free datapath compound.
    # `conns_per_core: 1500` exercises deep fan-out scaling on the
    # unikernel side.
    # fanout_tcp is parked in the `available` tier (off the default
    # set). 1c runs clean (~70k req/s on hvf); 4c+ TIMEOUTs when
    # benched locally — co-locating an N-vCPU VM and the loadgen on
    # an 8-core laptop oversubscribes the host, so the loadgen gets
    # starved (cli≈0.2cpu) rather than the unikernel wedging. Expect
    # nothing useful above ~3c locally. Real multi-core fanout
    # numbers need GCE, which first needs the gateway backend IP made
    # configurable: the handler resolves it from `net.gateway()` (see
    # apps/webserver gateway()), which only points at the loadgen
    # host on local tap/SLIRP/bridge topologies — on GCE the gateway
    # is the Andromeda subnet router, not the loadgen VM.
    # Invoke explicitly via `--workload fanout_tcp`; kept off the
    # default set so a full bench doesn't eat the 4c+ TIMEOUT.
    {"name": "fanout_tcp", "type": "gateway",
     "conns_per_core": 1500, "tier": "available",
     "desc": "Gateway fan-out (TCP→UDP backend→TCP, 1500 conn × cpus; bench 1c locally — see comment)"},

    # ── Raw TCP echo (guest:9) ────────────────────────────────────────
    #
    # `tcp_echo` round-trips a message off the `tcp_echo` handler —
    # no HTTP, no TLS, just recv→send. The handler is `recv_chunk()`
    # → `into_owned()` → `send`: on bare-metal the device RX buffer
    # is surfaced zero-copy and handed to the TX path with no
    # intermediate copy (vs the old `recv` into a stack buffer +
    # `send_bytes` — two copies).
    #
    # Two sizes, two regimes:
    #   * `tcp_echo` (64 B) — round-trip *latency* probe. Too small
    #     for the eliminated copy to register; the rate is bounded
    #     by per-round-trip overhead, not bytes moved. (A 64 B A/B
    #     of the recv_chunk migration came back flat, as expected.)
    #   * `tcp_echo_64k` (64 KiB) — *throughput* probe. Large enough
    #     that the per-segment RX copy is a real fraction of the
    #     work, so this is the workload that actually surfaces the
    #     `recv_chunk` zero-copy-RX win. (TX is still a copy until
    #     the Phase-5 TX-side IOBuf work — see
    #     docs/rx-path-optimizations.md — so this measures the RX
    #     half, not yet end-to-end zero-copy.)
    # Both `available` tier — name them explicitly.
    {"name": "tcp_echo", "type": "tcp_echo",
     "conns_per_core": 8, "tier": "available", "msg_size": 64,
     "desc": "TCP echo round-trip latency probe (64 B msg)"},
    {"name": "tcp_echo_64k", "type": "tcp_echo",
     "conns_per_core": 8, "tier": "available", "msg_size": 65536,
     "desc": "TCP echo throughput (64 KiB msg) — surfaces the recv_chunk zero-copy RX path at scale"},

    # ── Bulk RX — POST /discard with sized body ──────────────────────
    #
    # Primary probe for the driver RX path under multi-segment
    # same-flow load. Each iteration POSTs 32 KiB on a keep-alive
    # conn — ~22 MSS segments per request, all same 4-tuple, which
    # is the shape HW GRO / RSC wants to coalesce.
    #
    # Server-side handler `/discard` consumes the body and returns
    # a tiny JSON 200 OK (so the bench cycles fast). 16 conn/core
    # × cpus matches the other `_max`-style scaling.
    {"name": "upload_32k_tcp", "type": "http_upload",
     "endpoint": "/discard", "msg_size": 32768,
     "conns_per_core": 16, "tls": False,
     "desc": "POST /discard 32 KiB body (16 conn × cpus, plain HTTP)"},
    # Same shape over TLS — `upload_32k_tls` ⊖ `upload_32k_tcp`
    # isolates TLS bulk decrypt cost at fixed body size.
    {"name": "upload_32k_tls", "type": "http_upload",
     "endpoint": "/discard", "msg_size": 32768,
     "conns_per_core": 16, "tls": True,
     "desc": "POST /discard 32 KiB body (16 conn × cpus, over TLS)"},
    # Larger bodies — sustained-RX probes. Each overruns the 16 KiB
    # per-conn `rx_ring` many times over, so they exercise the
    # ring-fill → window-backpressure → drain → window-update cycle
    # repeatedly (the path the `net-tcp` window-update fix hardened
    # — pre-fix a 256 KiB upload hit the 30 s client timeout). Read
    # the `rx=` MB/s tag rather than req/s here. `available` tier:
    # run with `--workload upload_256k_tcp,upload_1m_tcp`.
    {"name": "upload_256k_tcp", "type": "http_upload",
     "endpoint": "/discard", "msg_size": 262144,
     "conns_per_core": 16, "tls": False, "tier": "available",
     "desc": "POST /discard 256 KiB body (16 conn × cpus, plain HTTP)"},
    {"name": "upload_1m_tcp", "type": "http_upload",
     "endpoint": "/discard", "msg_size": 1048576,
     "conns_per_core": 16, "tls": False, "tier": "available",
     "desc": "POST /discard 1 MiB body (16 conn × cpus, plain HTTP)"},

    # ── Bulk TX — GET /static-64k ────────────────────────────────────
    #
    # Plain-HTTP companion to `download_64k_tls`. Same body, no TLS
    # — surfaces TCP TX path regressions (descriptor build, TSO,
    # checksum offload) without TLS encrypt confound.
    {"name": "download_64k_tcp", "type": "tcp", "endpoint": "/static-64k",
     "threads_per_core": 1, "conns_per_core": 8, "resp_bytes": 65536,
     "desc": "/static-64k throughput plain HTTP (~4 segments, multi-segment TX)"},

    # ── Available tier (off the default set) ─────────────────────────

    # TLS small-record framing throughput. Off by default — `_fresh`
    # variants exercise handshake cost, `download_64k_tls` exercises
    # bulk encrypt; small-body TLS is a poor signal-to-noise probe
    # outside specific record-layer work.
    {"name": "get_tls", "type": "https", "endpoint": "/health",
     "threads_per_core": 1, "conns_per_core": 32,
     "tier": "available",
     "desc": "/health throughput over TLS (32 conn × cpus, keep-alive)"},

    # TLS hot path at minimum concurrency. Δ vs `get_tcp_single` =
    # per-request TLS record overhead at quiescent load. Pairs with
    # `get_tls` (multi-conn throughput).
    {"name": "get_tls_single", "type": "https", "endpoint": "/health",
     "threads": 1, "conns": 1,
     "tier": "available",
     "desc": "/health × 1 conn over TLS 1.3 (record-layer hot path, latency)"},

    # TLS 1.3 PSK-DHE resumption rate. Δ vs `get_tls_fresh` =
    # cost saved by skipping cert / sign / cert-verify. Off by
    # default — only meaningful when actively working on the PSK
    # resumption path.
    {"name": "get_tls_fresh_resume", "type": "tls_resume",
     "endpoint": "/health",
     "parallelism_per_core": 4,
     "tier": "available",
     "desc": "TLS 1.3 PSK-DHE resumed handshake + GET + close (4 workers × cpus)"},

    # Single-flow UDP RTT. Replaces the dropped `udp_sync`; same
    # shape, new name. Off by default — `echo_udp` (throughput
    # sweep) covers the UDP path on every bench.
    {"name": "echo_udp_single", "type": "udp", "endpoint": "",
     "senders": 1,
     "tier": "available",
     "desc": "UDP echo single-flow latency (1 sender, sync RTT)"},

    # IPv6 datapath. Same shape as `get_tcp` but targets [::1] so
    # the v6 header parse + checksum path is exercised. Off by
    # default — the v4 path is the throughput-dominant case; v6 is
    # for catching regressions when ipv6.rs / ipv6_send.rs change.
    # Requires the env to route [::1] to the unikernel (HVF runner
    # binds both v4 and v6 listener sockets; RemoteEnv on GCE needs
    # a v6-enabled subnet — not currently configured).
    {"name": "get_tcp_v6", "type": "tcp", "endpoint": "/health",
     "threads_per_core": 1, "conns_per_core": 32,
     "host_override": "::1",
     "tier": "available",
     "desc": "/health throughput over IPv6 (v6 header parse + pseudo-header csum)"},

    # ── TODO stubs (registered placeholders, no implementation) ──────
    #
    # Each entry below names a concern we want a bench for but
    # don't have an implementation for yet. They print a `TODO
    # (reason)` row in the per-cores loop so the gap stays
    # visible every run; they never consume bench time.

    # TLS-over-TCP 0-RTT cold path. Server-side: TCP record-layer
    # never derives client_early_traffic_secret (uni-tls flag
    # exists, no record-path wire-up). Loadgen: needs 0-RTT mode
    # (ticket cache + early-data send).
    {"name": "get_tls_fresh_0rtt", "type": "todo",
     "tier": "todo",
     "reason": "server: wire up TCP early-data decrypt; loadgen: add 0-RTT mode",
     "desc": "TLS 1.3 0-RTT (early-data) cold path"},

    # QUIC 0-RTT cold path. Server-side IS implemented in
    # uni-quic (early-data sentinel + handshake wiring). Blocked
    # on loadgen: needs QUIC 0-RTT send (ticket cache + early data).
    {"name": "get_quic_fresh_0rtt", "type": "todo",
     "tier": "todo",
     "reason": "loadgen: add QUIC 0-RTT send (server side ready)",
     "desc": "QUIC 0-RTT cold path"},

    # QUIC fresh handshake (rate). The `download_64k_quic`
    # workload amortizes one handshake over many keep-alive GETs,
    # so handshake-specific regressions are invisible there.
    # Loadgen needs a `--quic-handshake-only` mode (or
    # fresh-conn-per-iter for h3-health).
    {"name": "get_quic_fresh", "type": "todo",
     "tier": "todo",
     "reason": "loadgen: add --quic-handshake-only / fresh-conn-per-iter mode",
     "desc": "QUIC handshake state machine (cold path)"},

    # HTTP/3 POST 32 KiB — bulk-RX over QUIC, mirrors
    # upload_32k_tcp/tls but exercises the QUIC packet-decrypt
    # path on the server. Loadgen's h3 client is GET-only today.
    {"name": "upload_32k_quic", "type": "todo",
     "tier": "todo",
     "reason": "loadgen: add HTTP/3 POST subcommand",
     "desc": "HTTP/3 POST 32 KiB (QUIC RX bulk, packet decrypt)"},

    # HTTP/1.1 pipelining — multiple GETs serialized into one
    # TCP write. Produces back-to-back same-4-tuple segments
    # (the ideal RSC probe — even cleaner than upload_32k_tcp
    # since it doesn't depend on POST body framing). Loadgen
    # needs a `--pipeline N` mode (no existing client speaks it).
    {"name": "get_tcp_pipeline", "type": "todo",
     "tier": "todo",
     "reason": "loadgen: add --pipeline N (serialized GETs per TCP write)",
     "desc": "HTTP/1.1 pipelined GETs — ideal RSC probe"},

    # TX backpressure: slow-receiver client that drains responses
    # slowly enough to fill the server's TX queue. Tests whether
    # the TX path yields gracefully (vs hanging / leaking) under
    # backpressure. Loadgen needs a throttled-receive mode
    # (--read-rate-bps cap).
    {"name": "download_64k_tls_slow", "type": "todo",
     "tier": "todo",
     "reason": "loadgen: add --read-rate-bps (throttled receive)",
     "desc": "TX backpressure under slow consumer (64 KiB TLS)"},

    # Cold boot to first 200 OK. Out-of-process: needs to start
    # the unikernel VM fresh, time until /health returns 200,
    # tear down. Doesn't fit the per-request bench harness;
    # needs a separate `scripts/bench_cold_boot.sh` wrapper that
    # `gcloud compute instances start`s a stopped instance and
    # polls /health.
    {"name": "boot_cold", "type": "todo",
     "tier": "todo",
     "reason": "needs separate harness: scripts/bench_cold_boot.sh",
     "desc": "Cold boot to first 200 OK"},
]


def main():
    # Force line-buffered stdout so bench output streams live over SSH
    # pipes (otherwise `gcp-bench.sh ... | tail` swallows everything
    # until exit and the bench appears stuck).
    sys.stdout.reconfigure(line_buffering=True)

    parser = argparse.ArgumentParser(description="Unikernel benchmark")
    parser.add_argument("--env", default="qemu",
                        help="Environments: qemu,hvf,docker,native,all (comma-separated)")
    parser.add_argument("--cores", default=None,
                        help="Core counts to test (comma-separated). "
                             "Default: '1,<host//2>' for local envs, or "
                             "'1,<host>' when --env includes remote.")
    parser.add_argument("--workload", default=None,
                        help="Workload name(s), comma-separated (default: all)")
    parser.add_argument("--duration", type=int, default=5,
                        help="Seconds per test (default: 5)")
    parser.add_argument("--elf", default=None,
                        help="Pre-built ELF path (kvm env; skips bazel build)")
    parser.add_argument("--native-bin", default=None,
                        help="Pre-built native binary path (native env; skips bazel build)")
    parser.add_argument("--target", default=None,
                        help="Target IP for --env remote (e.g. the GCE "
                             "unikernel-webserver internal IP). Required when "
                             "--env remote is used.")
    args = parser.parse_args()

    duration = args.duration

    if args.env == "all":
        env_names = ["qemu", "qemu-arm", "hvf", "docker", "native"]
    elif args.env == "vm":
        env_names = ["qemu", "qemu-arm", "hvf"]
    else:
        env_names = [e.strip() for e in args.env.split(",")]

    # Resolve --cores. An explicit value is parsed verbatim; otherwise
    # the default is env-dependent. Local envs co-locate the load
    # generator and the guest on this host, so benching past half the
    # host's cores starves the loadgen and the result goes
    # client-bound — the same reasoning behind the `threads_per_core`
    # host//2 cap further down. RemoteEnv runs the guest on a separate
    # VM, leaving this whole host free for the loadgen, so it benches
    # up to the full host core count. Either way a 1-core baseline is
    # always included so the scaling column has a denominator.
    if args.cores is not None:
        core_counts = [int(c) for c in args.cores.split(",")]
    else:
        top = _HOST_CPUS if "remote" in env_names else max(1, _HOST_CPUS // 2)
        core_counts = [1] if top <= 1 else [1, top]
        print(f"--cores not set; defaulting to "
              f"{','.join(str(c) for c in core_counts)} "
              f"({_HOST_CPUS}-core host)")

    # Workload tiers (`tier` field per entry, default = "default"):
    #   "default"   — run on every bench (no --workload override)
    #   "available" — implemented but off the default set; runs only
    #                 when the user explicitly names it
    #   "todo"      — registered placeholder for a concern we don't
    #                 yet have a workload for; never runs, prints
    #                 TODO row so the gap stays visible
    # `--workload <name>` overrides tier filtering: any named
    # workload runs (or, for `todo`, prints its SKIP row) regardless.
    if args.workload:
        # Comma-separated list; preserve the order the user supplied
        # rather than the WORKLOADS declaration order (useful for
        # running a specific sequence like "get_tcp_single,get_tls").
        requested = [w.strip() for w in args.workload.split(",") if w.strip()]
        by_name = {w["name"]: w for w in WORKLOADS}
        unknown = [name for name in requested if name not in by_name]
        if unknown:
            print(f"Unknown workload(s): {', '.join(unknown)}")
            print(f"Available: {', '.join(w['name'] for w in WORKLOADS)}")
            sys.exit(1)
        workloads = [by_name[name] for name in requested]
    else:
        workloads = [w for w in WORKLOADS if w.get("tier", "default") == "default"]

    # These environments only run single-core benchmarks.
    # ARM TCG: no MTTCG support.
    single_core_only = {"docker", "qemu-arm"}

    # Kill stale processes
    subprocess.run(["pkill", "-9", "-f", "qemu-system"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "run-hvf"], capture_output=True)
    # Anchor to argv[0] to avoid matching our own bench.py cmdline
    # when `--native-bin /path/webserver_bin` is passed. Bench spawns
    # the underlying `:webserver_bin` rust_binary directly, so that's
    # the argv[0] we need to reap.
    subprocess.run(["pkill", "-9", "-f", r"^\S*/webserver_bin( |$)"],
                   capture_output=True)
    time.sleep(2)

    # Create environment instances (build happens before each test group
    # because bazel-bin is shared and configs overwrite each other).
    envs = {}
    for name in env_names:
        if name not in ENV_MAP:
            print(f"Unknown env: {name}. Available: {','.join(ENV_MAP.keys())}")
            sys.exit(1)
        envs[name] = ENV_MAP[name]()
        if name == "kvm" and args.elf:
            envs[name].elf_override = os.path.abspath(args.elf)
        if name == "native" and args.native_bin:
            envs[name].bin_override = os.path.abspath(args.native_bin)
        if name == "remote":
            if not args.target:
                print("--env remote requires --target <ip>")
                sys.exit(1)
            envs[name].GUEST_IP = args.target

    # Collect results: results[(env_name, cpus, workload_name)] = (rps, p50, p99)
    results = {}
    # Client-side CPU cost of each run (CPU-cores-equivalent the
    # load generator burned). Parallel dict so result tuple shape
    # stays backward compatible for any external consumer.
    client_cpu = {}
    _current = {"env": None, "proc": None}  # for cleanup on Ctrl-C

    def _kill_current():
        if _current["proc"] is not None and _current["env"] is not None:
            try:
                _current["env"].stop(_current["proc"])
            except Exception:
                pass
            _current["proc"] = None
        subprocess.run(["pkill", "-9", "-f", "qemu-system"], capture_output=True)
        subprocess.run(["pkill", "-9", "-f", "run-hvf"], capture_output=True)
        # Anchor to argv[0] to avoid matching our own bench.py cmdline when
        # --native-bin /path/webserver_native is passed.
        subprocess.run(["pkill", "-9", "-f", r"^\S*/webserver_native( |$)"],
                       capture_output=True)

    try:
      for env_name, env in envs.items():
        _current["env"] = env
        # Rebuild before each environment group (bazel-bin is shared).
        # RemoteEnv opts out via `needs_build = False` — its binary
        # is already running on another VM, so the "==> Building …"
        # print + `build()` call are pure noise.
        if getattr(env, "needs_build", True):
            print(f"\n==> Building {env.label}...")
            env.build()

        for cpus in core_counts:
            if env_name in single_core_only and cpus > 1:
                continue

            label = env.core_label(cpus)
            print(f"\n==> {label}")

            consecutive_skips = 0
            for w in workloads:
                wname = w["name"]
                port = next_port()

                bench_port = port

                # Some workloads only make sense at or above a floor
                # core count — a heavy conn-storm workload pointed at
                # a too-small scheduler can overrun the accept path
                # and wedge every subsequent workload at that core
                # count (the readiness probe never recovers). Mark
                # those with `min_cpus` and skip cleanly at lower
                # counts — no SKIP-cascade, no consecutive-skip abort.
                if cpus < w.get("min_cpus", 0):
                    print(f"    {wname:<20s} SKIP (needs ≥{w['min_cpus']} cores)")
                    results[(env_name, cpus, wname)] = (0, "", "")
                    continue

                proc = start_env_verified(env, cpus, port)
                _current["proc"] = proc
                if proc is None:
                    print(f"    {wname:<20s} SKIP (not ready)")
                    # Print last few lines of serial log to show why it failed.
                    # Each env writes its guest serial somewhere different;
                    # the tail almost always holds the boot panic or the
                    # last-seen DHCP / network message that explains why
                    # `wait_http` never reached the guest.
                    if isinstance(env, HvfEnv):
                        serial_sources = [
                            (f"/tmp/hvf_{port}.serial.log", "serial"),
                            (f"/tmp/hvf_{port}.log", "stderr"),
                        ]
                    elif isinstance(env, (KvmEnv, QemuEnv, QemuAarch64Env)):
                        serial_sources = [
                            (f"/tmp/bench_{port}.log", "serial"),
                            (f"/tmp/bench_{port}.qemu.log", "qemu"),
                        ]
                    else:
                        serial_sources = []
                    for path, label in serial_sources:
                        try:
                            with open(path) as lf:
                                lines = lf.read().strip().splitlines()
                                if not lines:
                                    print(f"      {label}: (empty)")
                                for l in lines[-12:]:
                                    print(f"      {label}: {l}")
                        except Exception:
                            pass
                    results[(env_name, cpus, wname)] = (0, "", "")
                    consecutive_skips += 1
                    if consecutive_skips >= 3:
                        print(f"    -- 3 consecutive SKIPs on {label}; aborting "
                              f"this core-count to avoid wedging the bench.")
                        break
                    continue
                consecutive_skips = 0

                # KvmEnv uses a tap backend with a fixed guest IP/ports
                # rather than localhost hostfwd; other envs keep the old
                # localhost+ephemeral-port default.
                if isinstance(env, (KvmEnv, RemoteEnv)):
                    wrk_host = env.GUEST_IP
                    wrk_port = env.GUEST_PORT
                    tls_target_port = env.GUEST_TLS_PORT
                    udp_target_port = env.GUEST_UDP_PORT
                    h3_target_port = getattr(
                        env, "GUEST_H3_PORT", env.GUEST_TLS_PORT)
                    tcp_echo_target_port = getattr(
                        env, "GUEST_TCP_ECHO_PORT", None)
                    gateway_target_port = getattr(
                        env, "GUEST_GATEWAY_PORT", None)
                else:
                    # 127.0.0.1 explicit, NOT "localhost". macOS
                    # resolves localhost to both ::1 and 127.0.0.1;
                    # for 6 000+ concurrent loadgen connects the
                    # IPv6-first try fails immediately (the unikernel
                    # listens AF_INET only) but the fallback to IPv4
                    # adds enough latency per connect to push the
                    # fanout_tcp workload over its subprocess timeout.
                    wrk_host = "127.0.0.1"
                    wrk_port = bench_port
                    tls_off = getattr(env, 'tls_port_offset', 1000)
                    tls_target_port = bench_port + tls_off
                    udp_off = getattr(env, 'udp_port_offset', 1)
                    udp_target_port = bench_port + udp_off
                    h3_off = getattr(env, 'h3_port_offset', None)
                    h3_target_port = (
                        bench_port + h3_off if h3_off else None)
                    tcp_echo_off = getattr(env, 'tcp_echo_offset', None)
                    tcp_echo_target_port = (
                        bench_port + tcp_echo_off if tcp_echo_off else None)
                    gateway_off = getattr(env, 'gateway_offset', None)
                    gateway_target_port = (
                        bench_port + gateway_off if gateway_off else None)

                # Per-workload host override (e.g. `get_tcp_v6` pins
                # the target to `::1` to exercise the IPv6 path
                # regardless of what the env defaults to).
                if "host_override" in w:
                    wrk_host = w["host_override"]

                # Workloads that scale with cpu count compute their final
                # conn / thread / sender counts here. Static workloads keep
                # the literal "conns" / "threads" / "senders" fields.
                conns = w.get("conns", 0)
                threads = w.get("threads", 0)
                if "conns_per_core" in w:
                    conns = w["conns_per_core"] * cpus
                if "threads_per_core" in w:
                    # Scale with target cores, but for *local* envs cap
                    # at half the host count. `wrk` is event-loop
                    # (epoll/kqueue), not thread-per-conn — one thread
                    # can comfortably drive 100k req/s, so scaling 1:1
                    # with target cpus just burns host cores that the
                    # VM / native binary needs. Keeping this ≤ host/2
                    # leaves half the host for the server.
                    #
                    # `RemoteEnv` is the exception: server and loadgen
                    # live on separate VMs (the GCE deploy-bench shape),
                    # so the loadgen is free to use the whole host. The
                    # prior unconditional cap is exactly what made
                    # `get_tcp` plateau at cli=4.0cpu on a 8-vCPU
                    # kvm-vm — both 4c and 8c targets clamped to 4
                    # client threads and the server's real ceiling
                    # stayed invisible.
                    raw = max(1, w["threads_per_core"] * cpus)
                    cap = _HOST_CPUS if isinstance(env, RemoteEnv) else max(1, _HOST_CPUS // 2)
                    threads = min(raw, cap)
                # UDP workloads use a fixed sender count — tying senders
                # to vCPUs would conflate client-side concurrency with
                # the server's core count and make scaling curves
                # impossible to read. udp_bench caps senders at [1, 64].
                senders = max(1, min(64, w.get("senders", 0)))

                if w["type"] == "todo":
                    # Stub workload — concern is named in the
                    # registry but no implementation exists yet.
                    # Print a TODO row so the bench output makes
                    # the gap visible every run, and skip to next.
                    reason = w.get("reason", "not implemented")
                    print(f"    {wname:<22s} TODO ({reason})")
                    continue
                if w["type"] == "tcp":
                    with measure_client_cpu() as m:
                        rps, p50, p99 = run_wrk(
                            wrk_port, w["endpoint"], threads, conns, duration,
                            host=wrk_host)
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    print(f"    {wname:<20s} {rps:>10.0f} req/s  "
                          f"p50={p50}  p99={p99}  {_cpu_tag(m['cores'])}"
                          + _throughput_tag(rps, w.get("resp_bytes", 0), "tx"))
                elif w["type"] == "http_upload":
                    # Keep-alive HTTP POST of a sized body to
                    # /discard. The server reads + discards, returns
                    # 200 OK. Each iteration drives ~msg_size/MSS
                    # back-to-back RX segments on one 4-tuple —
                    # the shape that exposes RX-driver / HW-GRO
                    # behavior. `tls=True` wraps each conn in TLS;
                    # the Δ vs the plain version isolates bulk
                    # decrypt cost at fixed body size.
                    target_port = tls_target_port if w.get("tls") else wrk_port
                    with measure_client_cpu() as m:
                        rps, p50, p99 = run_loadgen_http_upload(
                            target_port, w["endpoint"], conns, duration,
                            host=wrk_host, msg_size=w.get("msg_size", 32768),
                            tls=w.get("tls", False))
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    print(f"    {wname:<20s} {rps:>10.0f} req/s  "
                          f"p50={p50}  p99={p99}  {_cpu_tag(m['cores'])}"
                          + _throughput_tag(rps, w.get("msg_size", 32768), "rx"))
                elif w["type"] == "http_close":
                    # Accept-rate-bound plain-HTTP workload. Each
                    # iter is a fresh TCP from a different
                    # ephemeral port; SO_LINGER={1,0} on the
                    # loadgen side skips TIME_WAIT so macOS's
                    # ephemeral pool doesn't exhaust. Pairs with
                    # `get_tls_fresh` to isolate the crypto
                    # share of HTTPS handshake throughput.
                    par = w.get("parallelism_per_core", 4) * cpus
                    allocs_before = fetch_total_allocs(
                        wrk_port, host=wrk_host)
                    with measure_client_cpu() as m:
                        rps, p50, p99 = run_loadgen_http_close(
                            wrk_port, w["endpoint"], duration,
                            host=wrk_host, parallelism=par)
                    allocs_after = fetch_total_allocs(
                        wrk_port, host=wrk_host)
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    alloc_tag = _alloc_tag(allocs_before, allocs_after,
                                           rps * duration)
                    print(f"    {wname:<20s} {rps:>10.0f} req/s  "
                          f"p50={p50}  p99={p99}  "
                          f"{_cpu_tag(m['cores'])}{alloc_tag}")
                elif w["type"] == "https":
                    # wrk over https://. Self-signed dev cert is fine
                    # because wrk doesn't verify by default.
                    #
                    # Two server-side snapshots flank the run:
                    #   * `/heap` → talc total_allocation_count for
                    #     the per-request alloc-per-iter readout.
                    #   * `/stats` → TLS-encrypt byte+cycle counters
                    #     so we can compute cycles-per-byte of the
                    #     server-side AEAD hot path directly (vs
                    #     inferring it from wrk req/s × body size,
                    #     which is muddied by RTT, TCP windowing,
                    #     etc.).
                    allocs_before = fetch_total_allocs(
                        tls_target_port, host=wrk_host, https=True)
                    aead_before = fetch_tls_encrypt_stats(
                        tls_target_port, host=wrk_host, https=True)
                    with measure_client_cpu() as m:
                        rps, p50, p99 = run_wrk_https(
                            tls_target_port, w["endpoint"], threads, conns, duration,
                            host=wrk_host)
                    allocs_after = fetch_total_allocs(
                        tls_target_port, host=wrk_host, https=True)
                    aead_after = fetch_tls_encrypt_stats(
                        tls_target_port, host=wrk_host, https=True)
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    alloc_tag = _alloc_tag(allocs_before, allocs_after,
                                           rps * duration)
                    cyb_tag = _cycles_per_byte_tag(aead_before, aead_after)
                    print(f"    {wname:<20s} {rps:>10.0f} req/s  "
                          f"p50={p50}  p99={p99}  "
                          f"{_cpu_tag(m['cores'])}{alloc_tag}{cyb_tag}"
                          + _throughput_tag(rps, w.get("resp_bytes", 0), "tx"))
                elif w["type"] == "tls_handshake":
                    # Connection-per-request: each iteration opens a
                    # fresh TCP socket, completes the full TLS 1.3
                    # handshake, sends one GET, reads the response,
                    # closes. Measures handshake throughput, not
                    # record-layer throughput. Client parallelism
                    # scales with server cpus to keep all server
                    # cores busy (mirrors the _max HTTP workloads).
                    # Driven by the Rust `loadgen` binary (rustls +
                    # tokio); falls back to Python if cargo isn't
                    # installed.
                    par = w.get("parallelism_per_core", 4) * cpus
                    # Alloc-count sampling: snapshot total cumulative
                    # talc allocations before + after the bench. The
                    # post-bench delta divided by handshakes_completed
                    # is allocs-per-handshake — the metric that item M
                    # (conn-state pool) targets. `total_allocation_count`
                    # is monotonic across the bench window so this is
                    # only meaningful when nothing else is allocating
                    # on the server, which is true for the duration of
                    # a single workload run.
                    allocs_before = fetch_total_allocs(
                        tls_target_port, host=wrk_host, https=True)
                    with measure_client_cpu() as m:
                        rps, p50, p99 = run_loadgen_tls_handshake(
                            tls_target_port, w["endpoint"], duration,
                            host=wrk_host, parallelism=par)
                    allocs_after = fetch_total_allocs(
                        tls_target_port, host=wrk_host, https=True)
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    alloc_tag = _alloc_tag(allocs_before, allocs_after,
                                           rps * duration)
                    print(f"    {wname:<20s} {rps:>10.0f} hs/s   "
                          f"p50={p50}  p99={p99}  "
                          f"{_cpu_tag(m['cores'])}{alloc_tag}")
                elif w["type"] == "tls_resume":
                    # Resumed-handshake hot path: each worker keeps
                    # its own ticket cache, the first handshake per
                    # worker is a fresh seed (excluded from the
                    # histogram), and every subsequent handshake
                    # offers the cached ticket via pre_shared_key.
                    # The unikernel matches it, verifies the binder,
                    # and skips Cert + CertVerify on the server flight
                    # — the work that dominates fresh-handshake time.
                    par = w.get("parallelism_per_core", 4) * cpus
                    allocs_before = fetch_total_allocs(
                        tls_target_port, host=wrk_host, https=True)
                    with measure_client_cpu() as m:
                        rps, p50, p99 = run_loadgen_tls_resume(
                            tls_target_port, w["endpoint"], duration,
                            host=wrk_host, parallelism=par)
                    allocs_after = fetch_total_allocs(
                        tls_target_port, host=wrk_host, https=True)
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    alloc_tag = _alloc_tag(allocs_before, allocs_after,
                                           rps * duration)
                    print(f"    {wname:<20s} {rps:>10.0f} hs/s   "
                          f"p50={p50}  p99={p99}  "
                          f"{_cpu_tag(m['cores'])}{alloc_tag}")
                elif w["type"] == "h3_health":
                    # HTTP/3 keep-alive throughput. Each worker
                    # opens its own QUIC connection (one full
                    # handshake, skipped from the histogram), then
                    # fires sequential GETs on the keep-alive
                    # connection. `h3_target_port` is a UDP forward
                    # to the unikernel's QUIC/H3 listener (guest
                    # UDP:443) — distinct from `udp_target_port`
                    # (which forwards UDP echo on guest UDP:7).
                    if h3_target_port is None:
                        # Env doesn't expose an H3 port (older env
                        # without h3_port_offset). Skip rather than
                        # silently mis-targeting.
                        results[(env_name, cpus, wname)] = (0.0, "NO_H3_PORT", "NO_H3_PORT")
                        client_cpu[(env_name, cpus, wname)] = 0.0
                        print(f"    {wname:<20s} (env has no H3 port — skipped)")
                        continue
                    par = w.get("parallelism_per_core", 4) * cpus
                    with measure_client_cpu() as m:
                        rps, p50, p99 = run_loadgen_h3_health(
                            h3_target_port, w["endpoint"], duration,
                            host=wrk_host, parallelism=par)
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    print(f"    {wname:<20s} {rps:>10.0f} req/s  "
                          f"p50={p50}  p99={p99}  {_cpu_tag(m['cores'])}"
                          + _throughput_tag(rps, w.get("resp_bytes", 0), "tx"))
                elif w["type"] == "udp":
                    # Let wait_http's TCP teardown settle before firing a
                    # UDP burst — without this the first sender very
                    # occasionally wins a race against vhost-net's
                    # per-queue worker thread and the test records 0.
                    time.sleep(0.5)
                    with measure_client_cpu() as m:
                        pps, p50, p99 = _udp_with_retry(
                            udp_target_port, senders, duration, wrk_host)
                    results[(env_name, cpus, wname)] = (pps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    print(f"    {wname:<20s} {pps:>10.0f} pkt/s  "
                          f"p50={p50}  p99={p99}  {_cpu_tag(m['cores'])}")
                elif w["type"] == "echo_udp":
                    time.sleep(0.5)
                    # Windowed mode with adaptive concurrency ramp:
                    # probe per-thread slot counts [32..512] and pick
                    # the level where throughput plateaus, so each
                    # platform gets the concurrency that actually
                    # exposes its ceiling without over-pressuring it.
                    with measure_client_cpu() as m:
                        pps, loss_pct, p50, p99, best_n = echo_udp_concurrent(
                            udp_target_port, duration, wrk_host,
                            client_cpus=cpus)
                    results[(env_name, cpus, wname)] = (pps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    print(f"    {wname:<20s} {pps:>10.0f} pkt/s  "
                          f"({best_n}x{cpus} in-flight, {loss_pct:.1f}% loss)  "
                          f"{_cpu_tag(m['cores'])}")
                elif w["type"] == "tcp_echo":
                    if tcp_echo_target_port is None:
                        print(f"    {wname:<20s} SKIP (env has no tcp_echo port)")
                        continue
                    time.sleep(0.5)
                    # Driven by the Rust `loadgen` binary (tokio +
                    # native sockets); falls back to Python if cargo
                    # isn't installed.
                    with measure_client_cpu() as m:
                        rps, p50, p99 = run_loadgen_tcp_echo(
                            tcp_echo_target_port, conns, duration,
                            host=wrk_host, msg_size=w.get("msg_size", 64))
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    print(f"    {wname:<20s} {rps:>10.0f} msg/s  "
                          f"p50={p50}  p99={p99}  {_cpu_tag(m['cores'])}")
                elif w["type"] == "gateway":
                    if gateway_target_port is None:
                        print(f"    {wname:<20s} SKIP (env has no gateway port)")
                        continue
                    time.sleep(0.5)
                    # Backend port is the unikernel-side hard-coded
                    # `GATEWAY_BACKEND_PORT`. Loadgen hosts the echo
                    # task on this port so the unikernel can fan out
                    # to it directly (under QEMU NAT / HVF user
                    # networking, the host is reachable via the
                    # gateway IP DHCP gives us).
                    backend_port = 7777
                    msg_size = w.get("msg_size", 32)
                    with measure_client_cpu() as m:
                        rps, p50, p99 = run_loadgen_gateway(
                            gateway_target_port, backend_port, conns,
                            duration, host=wrk_host, msg_size=msg_size)
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    print(f"    {wname:<20s} {rps:>10.0f} req/s  "
                          f"p50={p50}  p99={p99}  {_cpu_tag(m['cores'])}")

                env.stop(proc)
                _current["proc"] = None
    except KeyboardInterrupt:
        print("\nInterrupted — cleaning up...")
        _kill_current()
        sys.exit(1)

    # ── Summary table ────────────────────────────────────────────────────────

    # Restore blocking mode on stdout. Child processes (QEMU, run-hvf) can
    # leave fd 1 in O_NONBLOCK state because macOS shares file-description
    # flags across fork+exec. Without this, the summary print() calls below
    # raise BlockingIOError(errno 35) on long lines.
    fl = fcntl.fcntl(sys.stdout.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdout.fileno(), fcntl.F_SETFL, fl & ~os.O_NONBLOCK)

    # Build column list: (env_name, cpus) pairs that have data
    columns = []
    for env_name in env_names:
        for cpus in core_counts:
            if env_name in single_core_only and cpus > 1:
                continue
            columns.append((env_name, cpus))

    # Each cell shows throughput + a compact `(cX.X)` suffix for the
    # client-CPU cores the load generator consumed, e.g. "201452 (c1.2)".
    # A trailing `⚠` flags cells where the client likely saturated the
    # host — the measured rate may be client-bound rather than
    # server-bound.
    CELL = 18  # wide enough for "NNNNNNN (cN.N)⚠"

    print()
    print("=" * (24 + (CELL + 2) * len(columns) + 10))
    print(f"  Benchmark Results  ({duration}s per test, host has {_HOST_CPUS} CPUs)")
    print("=" * (24 + (CELL + 2) * len(columns) + 10))

    # Header
    hdr = f"  {'Workload':<22s}"
    for env_name, cpus in columns:
        env = envs[env_name]
        hdr += f" {env.core_label(cpus):>{CELL}s}"
    # Scaling columns: one per environment that has multiple core counts
    scaling_envs = []
    for env_name in env_names:
        env_cores = [c for c in core_counts if not (env_name in single_core_only and c > 1)]
        if len(env_cores) > 1:
            scaling_envs.append(env_name)
            hdr += f" {envs[env_name].label[:6]+' ×':>8s}"
    print(hdr)
    print(f"  {'─'*22}" + f" {'─'*CELL}" * len(columns) + (f" {'─'*8}" * len(scaling_envs)))

    def _fmt_cell(val, cores):
        if val <= 0:
            return f"{'-':>{CELL}s}"
        sat = "⚠" if cores >= 0.7 * _HOST_CPUS else " "
        return f"{val:>7.0f} (c{cores:.1f}){sat}"

    # Rows
    for w in workloads:
        wname = w["name"]
        row = f"  {wname:<22s}"
        for env_name, cpus in columns:
            val = results.get((env_name, cpus, wname), (0, "", ""))
            cores = client_cpu.get((env_name, cpus, wname), 0.0)
            row += f" {_fmt_cell(val[0], cores):>{CELL}s}"

        # Per-environment scaling columns
        for env_name in scaling_envs:
            env_cores = [c for c in core_counts if not (env_name in single_core_only and c > 1)]
            base = results.get((env_name, env_cores[0], wname), (0,))[0]
            top = results.get((env_name, env_cores[-1], wname), (0,))[0]
            if base > 0:
                row += f" {top/base:>6.2f}x"
            else:
                row += f" {'N/A':>7s}"
        print(row)

    print("=" * (24 + (CELL + 2) * len(columns) + 10))
    print(f"  Duration: {duration}s | /compute: 100K hash iters | /health: static JSON")
    print(f"  Cell format: `rate (cN.N)` — N.N = CPU cores the load gen used. "
          f"⚠ = client ≥ 70% of {_HOST_CPUS}-core host (result likely client-bound).")
    if any(c > 1 for c in core_counts):
        print(f"  Multi-core: MTTCG (x86_64) or hardware (HVF/KVM)")
    print("=" * (24 + (CELL + 2) * len(columns) + 10))

    # List workloads not in the default set so the gap inventory
    # stays visible every run. Available = implemented, off by
    # default; todo = stub for a concern we don't have a workload
    # for yet (intentional placeholder, never runs).
    if not args.workload:
        skipped = [w for w in WORKLOADS
                   if w.get("tier", "default") != "default"]
        if skipped:
            available = [w for w in skipped if w.get("tier") == "available"]
            todos = [w for w in skipped if w.get("tier") == "todo"]
            print()
            if available:
                print(f"  Off by default ({len(available)} — run with --workload <name>):")
                for w in available:
                    print(f"    {w['name']:<22s} {w.get('desc', '')}")
            if todos:
                print(f"  TODO stubs ({len(todos)} — concerns without an impl):")
                for w in todos:
                    print(f"    {w['name']:<22s} TODO ({w.get('reason', '')})")
