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
    fetch_total_allocs,
    next_port,
    run_loadgen_gateway,
    run_loadgen_h3_health,
    run_loadgen_tcp_echo,
    run_loadgen_tls_handshake,
    run_loadgen_tls_resume,
    run_wrk,
    run_wrk_https,
    udp_peak_concurrent,
)


WORKLOADS = [
    # Single-flow latency baselines: keep one connection regardless of
    # cpu count. Throughput reflects per-request cost on one core.
    {"name": "health_c1", "type": "tcp", "endpoint": "/health",
     "threads": 1, "conns": 1,
     "desc": "/health × 1 conn (single-flow latency)"},
    {"name": "compute_c1", "type": "tcp", "endpoint": "/compute",
     "threads": 1, "conns": 1,
     "desc": "/compute × 1 conn (single-flow CPU)"},

    # Multi-core throughput: connections + wrk threads scale with cpus.
    # A single multi-threaded wrk process beats `N parallel wrk × 1
    # thread` on Linux/tap (the parallel mode was a workaround for
    # macOS loopback SO_REUSEPORT not hashing source ports — irrelevant
    # here, and the per-process fork+epoll overhead just hurts).
    {"name": "health_max", "type": "tcp", "endpoint": "/health",
     "threads_per_core": 1, "conns_per_core": 32,
     "desc": "/health throughput (32 conn × cpus)"},
    {"name": "compute_max", "type": "tcp", "endpoint": "/compute",
     "threads_per_core": 1, "conns_per_core": 8,
     "desc": "/compute throughput (8 conn × cpus)"},

    # UDP echo benchmarks.
    #
    # `udp_sync` measures single-flow round-trip latency: 1 sender,
    # sync ping-pong, p50/p99 reported. The number is RTT-bound and
    # machine-independent in shape — same workload on every host,
    # only the absolute latency varies.
    #
    # `udp_peak` measures peak sustained server throughput via a
    # windowed (in-flight) bench with adaptive concurrency. For each
    # (env, cpus), probes `N in {32,64,128,256,512}` per client
    # thread, doubling until throughput stops improving by >5%. Each
    # of `cpus` client pthread workers maintains N outstanding UDP
    # requests on its own SO_REUSEPORT-bound sockets; a slot fires
    # its next request only after its previous reply arrives or its
    # 100 ms timeout expires. No rate-paced binary search;
    # throughput plateaus at the server's real capacity, and `loss%`
    # surfaces if the server over-saturates. Each slot has a
    # distinct ephemeral source port so SO_REUSEPORT 4-tuple hashing
    # distributes load across all server siblings (Tier 1 KVM
    # hardware RSS + Tier 2 HVF software RSS both exercised the same
    # way).
    {"name": "udp_sync", "type": "udp", "endpoint": "",
     "senders": 1,
     "desc": "UDP echo single-flow latency (1 sender, sync RTT)"},
    {"name": "udp_peak", "type": "udp_peak", "endpoint": "",
     "desc": "UDP echo peak throughput (windowed + adaptive concurrency ramp)"},

    # ── TLS 1.3 workloads ────────────────────────────────────────────
    #
    # `health_tls_c1` is the HTTPS analogue of `health_c1`: a single
    # keep-alive connection sending /health requests over TLS 1.3 +
    # ECDSA P-256 + ChaCha20-Poly1305. The TLS handshake happens once
    # at the start of the run and amortises over `duration` seconds
    # of record-layer-only requests, so this number isolates the
    # hot-path encryption + record framing cost from the (much
    # larger) one-time handshake cost. Compare against `health_c1`
    # to see the per-request TLS overhead.
    #
    # `tls_handshake_max` is the opposite: each "request" is a fresh
    # TCP+TLS connection, exercising the full ECDSA sign + X25519
    # ECDHE + key schedule + handshake message encoding cost on
    # every iteration. This is the metric that matters for clients
    # that don't keep connections alive (curl, wget, browsers
    # opening tabs, etc.) and for measuring the cold-path cost of
    # our hand-rolled TLS implementation.
    #
    # Client parallelism is scaled with `--cores` via
    # `parallelism_per_core` to match the other `_max` workloads:
    # 4 client workers per server core gives enough in-flight
    # handshakes to keep every server core busy without any worker
    # stalling on the server's previous handshake. This was
    # originally a fixed 4-worker constant, but that meant the
    # server was oversubscribed 4× at 1c and the client became the
    # bottleneck at 3c+ because it couldn't push enough pressure.
    # Scaling with cores keeps the workload shape comparable
    # across core counts the way health_tls_max does.
    {"name": "health_tls_c1", "type": "https", "endpoint": "/health",
     "threads": 1, "conns": 1,
     "desc": "/health × 1 conn over TLS 1.3 (record-layer hot path)"},
    {"name": "health_tls_max", "type": "https", "endpoint": "/health",
     "threads_per_core": 1, "conns_per_core": 32,
     "desc": "/health throughput over TLS (32 conn × cpus, keep-alive)"},
    # `diagnostics_tls_max` is `health_tls_max` against a multi-segment
    # body (~9 KiB rendered HTML) instead of /health's 80 B JSON. The
    # post-Q TX path emits the same 16 KB TLS record either way, but
    # only the multi-segment shape exercises the TCP segmentation work
    # — `health_tls_max` always fits in one MSS so it doesn't surface
    # TSO wins. Compare the two before/after item G to see how much of
    # /diagnostics' guest CPU was per-segment header building +
    # checksum vs the encryption itself.
    {"name": "diagnostics_tls_max", "type": "https", "endpoint": "/diagnostics",
     "threads_per_core": 1, "conns_per_core": 32,
     "desc": "/diagnostics throughput over TLS (~9 KB body, multi-segment)"},
    {"name": "tls_handshake_max", "type": "tls_handshake",
     "endpoint": "/health",
     "parallelism_per_core": 4,
     "desc": "TLS 1.3 full handshake + GET + close (4 workers × cpus)"},
    {"name": "tls_resume_max", "type": "tls_resume",
     "endpoint": "/health",
     "parallelism_per_core": 4,
     "desc": "TLS 1.3 resumed (PSK-DHE) handshake + GET + close (4 workers × cpus)"},

    # ── HTTP/3 over QUIC ──────────────────────────────────────────────
    #
    # The QUIC analogue of `health_tls_max`: each worker opens its
    # own QUIC connection (one full handshake, skipped from the
    # histogram), then loops sequential GETs on the keep-alive
    # connection. Hits the post-handshake hot path that item B2
    # (encoder writes directly into the driver TX-pool slot)
    # targets. Compare against `health_tls_max` to see the QUIC vs
    # TLS-over-TCP per-request cost on the same /health body.
    #
    # 4 workers × cpus mirrors the other `_max` workloads' shape.
    {"name": "h3_health_max", "type": "h3_health",
     "endpoint": "/health",
     "parallelism_per_core": 4,
     "desc": "/health throughput over HTTP/3 (4 workers × cpus, QUIC keep-alive)"},
    # Same shape as h3_health_max but pointed at /diagnostics
    # (~9 KiB HTML body) so the QUIC TX path's multi-packet
    # encrypt + send loop is the bottleneck, not the per-request
    # parsing overhead. Pairs with `diagnostics_tls_max` to give
    # a side-by-side QUIC-vs-TLS-over-TCP read on larger bodies
    # — the gap is where the QUIC encoder's encode-into-TX-slot
    # zero-copy (item B2) actually surfaces; on /health the
    # body is too small for any of the per-byte wins to register
    # above run-to-run noise.
    {"name": "h3_diagnostics_max", "type": "h3_health",
     "endpoint": "/diagnostics",
     "parallelism_per_core": 4,
     "desc": "/diagnostics throughput over HTTP/3 (~9 KB body, multi-packet)"},

    # ── Async TCP echo (guest:9 via `uni::runtime::TcpListener`) ─────────
    #
    # Validates the async TCP path end-to-end: accept reactor +
    # `TcpRecv` future + per-conn recv waker. The webserver echoes
    # each received message verbatim, so this is pure runtime
    # overhead plus the network stack, no HTTP parsing.
    #
    # tcp_echo_c1 is the single-flow latency / small-message rate,
    # tcp_echo_max is the scaled-conn throughput mirroring
    # health_max / compute_max.
    {"name": "tcp_echo_c1", "type": "tcp_echo",
     "conns": 1,
     "desc": "Async TCP echo × 1 conn (single-flow ping-pong)"},
    {"name": "tcp_echo_max", "type": "tcp_echo",
     "conns_per_core": 16,
     "desc": "Async TCP echo throughput (16 conn × cpus)"},

    # ── Async gateway / sidecar fan-out (guest:9000) ─────────────────
    #
    # The realistic microservice workload: every accepted TCP request
    # at the unikernel fans out to a UDP backend (tokio-hosted by the
    # same loadgen process), awaits the reply, returns it. Each
    # in-flight conn parks its handler future on the backend's UDP
    # recv waker — this is where async + the syscall-free datapath
    # compound. Sync runtimes can't service 64+ concurrent in-flight
    # forwards per worker without OS threads; native (Linux+Tokio
    # equivalent) pays ~5 syscalls per request just to push bytes.
    #
    # `conns_per_core: 1500` exercises the post-refactor scaling
    # path on the *unikernel side* — per-worker ephemeral UDP
    # pool with port-encoded owner, native O(1) port→fd table.
    # Native saturates at ~89 k req/s by 1500 conn (1c), and HVF
    # holds steady at ~73 k through 1500 conn now that the
    # loadgen's connect-timeout fix unblocks higher counts (a
    # missing timeout used to hang the start barrier when one
    # connect stalled, which masqueraded as a runner-side cap).
    # The loadgen throttles concurrent `connect(2)` to 64 (well
    # under macOS's `kern.ipc.somaxconn=128` default) so the
    # listener backlog drains during ramp.
    #
    # Loadgen-side TIME_WAIT used to bite at thousands of conns
    # (16 384-port macOS ephemeral pool, 15 s 2×MSL); the
    # `set_zero_linger()` fix in scripts/bench/loadgen makes
    # close() RST instead of FIN, removing that cap entirely.
    {"name": "gateway_max", "type": "gateway",
     "conns_per_core": 1500,
     "desc": "Gateway fan-out (TCP→UDP backend→TCP, 1500 conn × cpus)"},
]


def main():
    # Force line-buffered stdout so bench output streams live over SSH
    # pipes (otherwise `gcp-bench.sh ... | tail` swallows everything
    # until exit and the bench appears stuck).
    sys.stdout.reconfigure(line_buffering=True)

    parser = argparse.ArgumentParser(description="Unikernel benchmark")
    parser.add_argument("--env", default="qemu",
                        help="Environments: qemu,hvf,docker,native,all (comma-separated)")
    parser.add_argument("--cores", default="1,4",
                        help="Core counts to test (comma-separated)")
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
    core_counts = [int(c) for c in args.cores.split(",")]

    if args.env == "all":
        env_names = ["qemu", "qemu-arm", "hvf", "docker", "native"]
    elif args.env == "vm":
        env_names = ["qemu", "qemu-arm", "hvf"]
    else:
        env_names = [e.strip() for e in args.env.split(",")]

    workloads = WORKLOADS
    if args.workload:
        # Comma-separated list; preserve the order the user supplied
        # rather than the WORKLOADS declaration order (useful for
        # running a specific sequence like "health_c1,health_tls_c1").
        requested = [w.strip() for w in args.workload.split(",") if w.strip()]
        by_name = {w["name"]: w for w in WORKLOADS}
        unknown = [name for name in requested if name not in by_name]
        if unknown:
            print(f"Unknown workload(s): {', '.join(unknown)}")
            print(f"Available: {', '.join(w['name'] for w in WORKLOADS)}")
            sys.exit(1)
        workloads = [by_name[name] for name in requested]

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
                        serial_sources = [(f"/tmp/bench_{port}.log", "serial")]
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
                    # gateway_max workload over its subprocess timeout.
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

                # Workloads that scale with cpu count compute their final
                # conn / thread / sender counts here. Static workloads keep
                # the literal "conns" / "threads" / "senders" fields.
                conns = w.get("conns", 0)
                threads = w.get("threads", 0)
                if "conns_per_core" in w:
                    conns = w["conns_per_core"] * cpus
                if "threads_per_core" in w:
                    # Scale with target cores but cap at half the host
                    # count. `wrk` is event-loop (epoll/kqueue), not
                    # thread-per-conn — one thread can comfortably
                    # drive 100k req/s, so scaling 1:1 with target cpus
                    # just burns host cores that the VM / native binary
                    # needs. Keeping this ≤ host/2 leaves half the host
                    # for the server.
                    raw = max(1, w["threads_per_core"] * cpus)
                    threads = min(raw, max(1, _HOST_CPUS // 2))
                # UDP workloads use a fixed sender count — tying senders
                # to vCPUs would conflate client-side concurrency with
                # the server's core count and make scaling curves
                # impossible to read. udp_bench caps senders at [1, 64].
                senders = max(1, min(64, w.get("senders", 0)))

                if w["type"] == "tcp":
                    with measure_client_cpu() as m:
                        rps, p50, p99 = run_wrk(
                            wrk_port, w["endpoint"], threads, conns, duration,
                            host=wrk_host)
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    print(f"    {wname:<20s} {rps:>10.0f} req/s  "
                          f"p50={p50}  p99={p99}  {_cpu_tag(m['cores'])}")
                elif w["type"] == "https":
                    # wrk over https://. Self-signed dev cert is fine
                    # because wrk doesn't verify by default.
                    allocs_before = fetch_total_allocs(
                        tls_target_port, host=wrk_host, https=True)
                    with measure_client_cpu() as m:
                        rps, p50, p99 = run_wrk_https(
                            tls_target_port, w["endpoint"], threads, conns, duration,
                            host=wrk_host)
                    allocs_after = fetch_total_allocs(
                        tls_target_port, host=wrk_host, https=True)
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    client_cpu[(env_name, cpus, wname)] = m["cores"]
                    alloc_tag = _alloc_tag(allocs_before, allocs_after,
                                           rps * duration)
                    print(f"    {wname:<20s} {rps:>10.0f} req/s  "
                          f"p50={p50}  p99={p99}  "
                          f"{_cpu_tag(m['cores'])}{alloc_tag}")
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
                          f"p50={p50}  p99={p99}  {_cpu_tag(m['cores'])}")
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
                elif w["type"] == "udp_peak":
                    time.sleep(0.5)
                    # Windowed mode with adaptive concurrency ramp:
                    # probe per-thread slot counts [32..512] and pick
                    # the level where throughput plateaus, so each
                    # platform gets the concurrency that actually
                    # exposes its ceiling without over-pressuring it.
                    with measure_client_cpu() as m:
                        pps, loss_pct, p50, p99, best_n = udp_peak_concurrent(
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
                            tcp_echo_target_port, conns, duration, host=wrk_host)
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
