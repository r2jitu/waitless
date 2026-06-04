"""Workload drivers + port helpers shared by the envs loop.

Split out of the old flat bench.py: everything here is "given a
running server at (host, port), measure throughput/latency with wrk /
udp_bench / loadgen". No bazel / env-lifecycle logic.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

PORT_COUNTER = [38000]


def next_port():
    PORT_COUNTER[0] += 10
    return PORT_COUNTER[0]


def wait_http(port, timeout=20, host="localhost"):
    """Poll http://host:port/health once a second up to `timeout` seconds.

    A real boot reaches HTTP-ready in 1–3 seconds, so 20 s is generous and
    a 90 s default just means failures take 90 s to surface — which made
    the bench look stuck for many minutes during the tap+vhost rollout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = subprocess.run(
                ["curl", "-sf", "--max-time", "2", f"http://{host}:{port}/health"],
                capture_output=True,
                timeout=5,
            )
            if r.returncode == 0:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def fetch_total_allocs(port, host="localhost", https=False):
    """GET `/obs` and return `total_allocation_count` (cumulative
    talc allocations since boot) from the `kernel` block. Returns
    `None` on any failure (server not exposing /obs, network blip,
    parse error) so callers can fall back to "no alloc-stats"
    reporting without aborting the bench.

    On a unikernel target this number is the kernel heap's monotonic
    `Talc::counters().total_allocation_count`; on native/POSIX it's
    `0` (libstd's allocator exposes no counters), so callers should
    treat a constant `0` across before/after as "alloc-stats not
    available on this env" and skip the per-handshake derivation.
    """
    import json

    scheme = "https" if https else "http"
    url = f"{scheme}://{host}:{port}/obs"
    try:
        # `-k` for HTTPS so the self-signed dev cert doesn't trip
        # curl's verifier; the alternative is `subprocess.run` with
        # ssl.SSLContext, which adds Python imports for marginal
        # benefit on a tool we already shell out to elsewhere.
        flags = ["-sf", "--max-time", "3"]
        if https:
            flags.append("-k")
        r = subprocess.run(["curl", *flags, url], capture_output=True, timeout=5)
        if r.returncode != 0:
            return None
        kernel = json.loads(r.stdout).get("kernel", {})
        return int(kernel.get("total_allocation_count", 0))
    except Exception:
        return None


def fetch_tls_encrypt_stats(port, host="localhost", https=False):
    """GET `/obs` and return `(tls_encrypt_bytes, tls_encrypt_cycles)`
    — the TSC-cycle and byte totals the server has accumulated in the
    TLS record-layer seal path since boot, read from the `tls` block
    of the aggregate observability surface. Returns `None` on any
    failure or when both values are zero (counter not wired in this
    build).

    Snapshotting before + after a bench run and computing
    `(d_cycles) / (d_bytes)` yields cycles-per-byte for the TLS
    encrypt hot path — independent of client-side wrk/wait time, so
    it's a clean signal of where the per-record AEAD cost sits.
    """
    import json

    scheme = "https" if https else "http"
    url = f"{scheme}://{host}:{port}/obs"
    try:
        flags = ["-sf", "--max-time", "3"]
        if https:
            flags.append("-k")
        r = subprocess.run(["curl", *flags, url], capture_output=True, timeout=5)
        if r.returncode != 0:
            return None
        tls = json.loads(r.stdout).get("tls", {})
        b = int(tls.get("encrypt_bytes", 0))
        c = int(tls.get("encrypt_cycles", 0))
        if b == 0 and c == 0:
            return None
        return (b, c)
    except Exception:
        return None


def run_wrk(port, endpoint, threads, conns, duration, host="localhost"):
    # Hard-cap wrk's per-request timeout at 5 s so a stuck server can't
    # peg latency at the wrk default of 2 s and still appear "running"
    # for the entire duration. The subprocess timeout is `duration + 10`
    # so even a wedged wrk only blocks the bench by 10 s past its run.
    try:
        r = subprocess.run(
            [
                "wrk",
                f"-t{threads}",
                f"-c{conns}",
                f"-d{duration}s",
                "--timeout",
                "5s",
                "--latency",
                f"http://{host}:{port}{endpoint}",
            ],
            capture_output=True,
            text=True,
            timeout=duration + 10,
        )
        rps, p50, p99 = 0.0, "", ""
        for line in r.stdout.split("\n"):
            if "Requests/sec" in line:
                rps = float(line.split()[1])
            elif "50%" in line:
                p50 = line.split()[1]
            elif "99%" in line:
                p99 = line.split()[1]
        return rps, p50, p99
    except subprocess.TimeoutExpired:
        return 0.0, "TIMEOUT", "TIMEOUT"
    except Exception:
        return 0.0, "ERROR", "ERROR"


def run_wrk_https(port, endpoint, threads, conns, duration, host="localhost"):
    """Like `run_wrk` but issues `https://...` requests against a TLS
    1.3 endpoint. Brew's wrk is linked against OpenSSL and defaults
    to `SSL_VERIFY_NONE`, so our self-signed dev cert works without
    any extra `-k`/`--insecure` flag.

    Inside a single wrk session, all requests on the same connection
    reuse the same TLS context (keep-alive). With `conns=1` this
    means one full handshake at the start, then record-layer-only
    request/response cycles for the rest of the run — the right
    workload for measuring per-request hot-path latency over TLS.
    """
    try:
        r = subprocess.run(
            [
                "wrk",
                f"-t{threads}",
                f"-c{conns}",
                f"-d{duration}s",
                "--timeout",
                "5s",
                "--latency",
                f"https://{host}:{port}{endpoint}",
            ],
            capture_output=True,
            text=True,
            timeout=duration + 10,
        )
        rps, p50, p99 = 0.0, "", ""
        for line in r.stdout.split("\n"):
            if "Requests/sec" in line:
                rps = float(line.split()[1])
            elif "50%" in line:
                p50 = line.split()[1]
            elif "99%" in line:
                p99 = line.split()[1]
        return rps, p50, p99
    except subprocess.TimeoutExpired:
        return 0.0, "TIMEOUT", "TIMEOUT"
    except Exception:
        return 0.0, "ERROR", "ERROR"


def _tls_handshake_worker(args):
    """Process entry point for `run_tls_handshake_rate`.

    Runs in a child process via `multiprocessing` so workers get
    true parallelism instead of fighting over the GIL (which would
    cap aggregate throughput to ~1 core's worth of Python even
    with N worker threads). Each worker returns a list of
    post-warmup latencies (microseconds) plus an error count.

    Why child processes: Python's `ssl` module releases the GIL
    inside `SSL_do_handshake`, but reacquires it for every
    `send`/`recv` wrapper call. With N threads, the acquire/release
    serialises across workers and the effective parallelism drops
    to ~2x no matter how many threads you add. Child processes
    have no shared interpreter, so each one gets a full Python
    timeslice on its own core.
    """
    (port, endpoint, host, total_duration, warmup) = args
    import ssl
    import socket as sock_mod
    import struct
    import time as time_mod

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except AttributeError:
        pass

    connect_host = "127.0.0.1" if host in ("localhost", "127.0.0.1") else host
    request = (
        f"GET {endpoint} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    ).encode()

    # SO_LINGER={on=1,linger=0} → RST on close (no TIME_WAIT on the
    # client side). macOS default ephemeral port pool is ~16K; at
    # 2K hs/s × 10s × N workers we'd exhaust it mid-run without this.
    linger = struct.pack("ii", 1, 0)

    local_lat = []
    local_err = 0
    MAX_SAMPLES = 100_000
    total_start = time_mod.monotonic()
    warmup_end = total_start + warmup
    total_end = warmup_end + total_duration

    while time_mod.monotonic() < total_end:
        in_measure = time_mod.monotonic() >= warmup_end
        t0 = time_mod.monotonic_ns()
        try:
            s = sock_mod.create_connection((connect_host, port), timeout=5)
            s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_LINGER, linger)
            # TCP_NODELAY on the client side too. The Python ssl
            # module writes each TLS record via a separate
            # send() call during the client-side handshake
            # (ClientHello → ChangeCipherSpec + Finished → the
            # HTTP GET body). With Nagle on, Linux coalesces
            # those sends with delayed-ACK and the handshake
            # stalls ~40 ms per round-trip, capping
            # `tls_handshake_max` at ~20 hs/s on GCP. Disabling
            # it here matches the server-side fix in the native
            # backend's tcp_accept (`crates/waitless/backend/src/native/`).
            s.setsockopt(sock_mod.IPPROTO_TCP, sock_mod.TCP_NODELAY, 1)
            ssock = ctx.wrap_socket(s, server_hostname="waitless.local")
            ssock.send(request)
            resp = b""
            while b"\r\n\r\n" not in resp and len(resp) < 4096:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            try:
                ssock.close()
            except Exception:
                pass
            if b"200" in resp[:32]:
                if in_measure and len(local_lat) < MAX_SAMPLES:
                    elapsed_us = (time_mod.monotonic_ns() - t0) // 1000
                    local_lat.append(elapsed_us)
            else:
                local_err += 1
        except Exception:
            local_err += 1

    return (local_lat, local_err)


def run_tls_handshake_rate(
    port, endpoint, duration, host="localhost", parallelism=4, warmup=1.0
):
    """Measure full TLS 1.3 handshake throughput.

    Spawns `parallelism` *processes* (not threads — see
    `_tls_handshake_worker` for the GIL rationale). Each process
    repeatedly:
      1. Opens a TCP connection to (host, port)
      2. Completes the TLS 1.3 handshake (X25519 + ECDSA + ChaCha20-Poly1305)
      3. Sends one HTTP/1.1 GET with `Connection: close`
      4. Reads the response
      5. Aborts the connection with SO_LINGER=0 (RST, no TIME_WAIT)

    Runs for `duration + warmup` seconds and returns
    `(handshakes_per_sec, p50_us_string, p99_us_string)`. The first
    `warmup` seconds are discarded per worker — they absorb
    cold-cache effects, process-spawn overhead, DNS resolution, and
    the HVF runner's first-connection scheduling hiccup.

    ## Noise-reduction tricks applied here

    1. **Multiprocessing, not threading.** Python's `ssl` module
       releases the GIL inside `SSL_do_handshake` but reacquires
       it for every send/recv wrapper call; threaded workers on a
       fast loopback cap out at ~40% of theoretical rate. Child
       processes each get their own interpreter and scale cleanly.
       Old threaded implementation: 2173/1241/2001 hs/s across
       three runs (2x variance). Post-fix: much tighter.

    2. **SO_LINGER={on=1,linger=0}** on the client socket. On
       close the kernel sends a TCP RST instead of the usual
       FIN/ACK/FIN dance, so the client side skips TIME_WAIT
       entirely. Without this, a 10s run at ~2K hs/s creates 20K
       sockets all stuck in TIME_WAIT for macOS's default 15s,
       which exhausts the ephemeral port pool mid-run and causes
       the rate to cliff-edge halfway through. The server still
       does clean shutdown (close_notify + FIN); only the client
       half is RST'd, which is fine for a throughput benchmark.

    3. **Direct 127.0.0.1 instead of "localhost"**. Python's
       `socket.create_connection` calls `getaddrinfo` on every
       invocation; on macOS this occasionally blocks tens of ms
       (mDNS / resolver cache). Skipping it removes a big p99
       tail-latency contributor.

    4. **Per-worker SSL context**. Each child creates its own
       `SSLContext` once at startup and reuses it. `ctx.wrap_socket`
       is then just a per-connection `SSLObject` alloc, much
       cheaper than context rebuild.

    5. **Warmup discard**. The first `warmup` seconds of latencies
       are dropped before computing rps/p50/p99, stabilising
       numbers across back-to-back runs (caches warm, ephemeral
       port pool settles, HVF vCPU scheduling reaches steady
       state, child process finishes its cold-start imports).

    The Python `ssl` module fronts whatever TLS library is bundled
    with the current Python — on macOS that's typically OpenSSL
    3.x via Homebrew Python or LibreSSL via the system Python.
    Both support TLS 1.3 + ECDSA P-256 + X25519, so either works
    against our server.
    """
    import multiprocessing

    args = (port, endpoint, host, duration, warmup)
    with multiprocessing.Pool(processes=parallelism) as pool:
        results = pool.map(_tls_handshake_worker, [args] * parallelism)

    all_lat = []
    total_err = 0
    for lat, err in results:
        all_lat.extend(lat)
        total_err += err

    if not all_lat:
        return 0.0, "ERROR", "ERROR"

    # Rate = total post-warmup samples / measurement window.
    # All workers observed the same wall-clock window (they shared
    # total_duration and warmup via args), so dividing by that is
    # fair across workers even when one finishes slightly earlier.
    rps = len(all_lat) / duration
    all_lat.sort()
    p50 = all_lat[len(all_lat) // 2]
    p99_idx = min(len(all_lat) - 1, (len(all_lat) * 99) // 100)
    p99 = all_lat[p99_idx]
    return rps, f"{p50}us", f"{p99}us"


def _loadgen_bin():
    """Return the path to the compiled `loadgen` binary, building it
    via `cargo build --release` on first call.

    `loadgen` is a Rust async TCP/TLS load generator (sources at
    `scripts/bench/loadgen/`) that replaces the Python multiprocessing
    paths for `tls_handshake_max` and `tcp_echo_max` — both were
    Python-bound at ~6 k hs/s and ~210 k msg/s respectively, so
    benchmark numbers reflected client cost, not server ceiling.

    First-call build is ~30s (downloads tokio + rustls + ring,
    compiles); subsequent calls hit the cargo cache and return in
    milliseconds. If `cargo` isn't on PATH the helper returns None
    and the harness falls back to the Python implementations with a
    warning printed once.
    """
    here = os.path.dirname(__file__)
    crate_dir = os.path.join(here, "loadgen")
    if not os.path.isfile(os.path.join(crate_dir, "Cargo.toml")):
        return None
    bin_path = os.path.join(crate_dir, "target", "release", "loadgen")
    if os.path.isfile(bin_path):
        # Cheap sanity: rebuild if any source is newer than the binary.
        bin_mtime = os.path.getmtime(bin_path)
        for root, _, files in os.walk(os.path.join(crate_dir, "src")):
            for f in files:
                if os.path.getmtime(os.path.join(root, f)) > bin_mtime:
                    bin_path = None
                    break
            if bin_path is None:
                break
        if bin_path is not None:
            return bin_path
    cargo = shutil.which("cargo")
    if cargo is None:
        # rustup's `--no-modify-path` install leaves cargo at
        # `~/.cargo/bin/cargo` without touching shell rc files.
        # Non-interactive ssh sessions don't pick that up unless
        # the user manually edits `.bashrc`, so check the well-
        # known location before giving up.
        candidate = os.path.expanduser("~/.cargo/bin/cargo")
        if os.path.isfile(candidate):
            cargo = candidate
    if cargo is None:
        if not getattr(_loadgen_bin, "_warned_no_cargo", False):
            print(
                "warning: cargo not found; falling back to Python "
                "loadgen for tls_handshake / tcp_echo (slower).",
                file=sys.stderr,
            )
            _loadgen_bin._warned_no_cargo = True
        return None
    print("==> Building scripts/bench/loadgen (first-run, ~30s)...", file=sys.stderr)
    try:
        subprocess.run(
            [cargo, "build", "--release"], cwd=crate_dir, check=True, timeout=300
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(
            f"warning: loadgen cargo build failed ({e}); falling "
            "back to Python loadgen.",
            file=sys.stderr,
        )
        return None
    return os.path.join(crate_dir, "target", "release", "loadgen")


def _parse_loadgen_output(stdout):
    """Pull RPS / P50_US / P99_US from loadgen's stdout. Returns
    (rps_float, p50_str, p99_str). Anything else on stdout is
    informational; missing values are returned as zero / empty."""
    rps, p50, p99 = 0.0, "", ""
    for line in stdout.split("\n"):
        if line.startswith("RPS "):
            try:
                rps = float(line[4:])
            except ValueError:
                pass
        elif line.startswith("P50_US "):
            p50 = f"{line[7:].strip()}us"
        elif line.startswith("P99_US "):
            p99 = f"{line[7:].strip()}us"
    return rps, p50, p99


def run_loadgen_tls_handshake(port, endpoint, duration, host, parallelism, warmup=1):
    """Run the Rust loadgen TLS-handshake workload. Returns the same
    `(rps, p50, p99)` shape `run_tls_handshake_rate` does so the
    dispatcher can swap implementations transparently."""
    bin_path = _loadgen_bin()
    if bin_path is None:
        return run_tls_handshake_rate(
            port, endpoint, duration, host=host, parallelism=parallelism, warmup=warmup
        )
    try:
        r = subprocess.run(
            [
                bin_path,
                "tls-handshake",
                "--host",
                host,
                "--port",
                str(port),
                "--endpoint",
                endpoint,
                "--duration-secs",
                str(duration),
                "--warmup-secs",
                str(warmup),
                "--parallelism",
                str(parallelism),
            ],
            capture_output=True,
            text=True,
            timeout=duration + warmup + 30,
        )
        if r.returncode != 0:
            return 0.0, "ERROR", "ERROR"
        return _parse_loadgen_output(r.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return 0.0, "TIMEOUT", "TIMEOUT"


def run_loadgen_http_close(port, endpoint, duration, host, parallelism, warmup=1):
    """Run the Rust loadgen plain-HTTP fresh-conn workload. Each
    worker loops: TCP connect, GET with `Connection: close`, drain
    response, close. SO_LINGER={1,0} on the client side avoids
    macOS TIME_WAIT pile-up. Returns the standard
    `(rps, p50, p99)` triple.
    """
    bin_path = _loadgen_bin()
    if bin_path is None:
        return 0.0, "NO_LOADGEN", "NO_LOADGEN"
    try:
        r = subprocess.run(
            [
                bin_path,
                "http-close",
                "--host",
                host,
                "--port",
                str(port),
                "--endpoint",
                endpoint,
                "--duration-secs",
                str(duration),
                "--warmup-secs",
                str(warmup),
                "--parallelism",
                str(parallelism),
            ],
            capture_output=True,
            text=True,
            timeout=duration + warmup + 30,
        )
        if r.returncode != 0:
            return 0.0, "ERROR", "ERROR"
        return _parse_loadgen_output(r.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return 0.0, "TIMEOUT", "TIMEOUT"


def run_loadgen_tls_resume(port, endpoint, duration, host, parallelism, warmup=1):
    """Run the Rust loadgen TLS-resumption workload. Each worker
    seeds with one fresh handshake (excluded from the histogram) and
    then loops on resumed PSK-DHE handshakes — the server's flight
    skips Certificate + CertificateVerify, so wall-time per handshake
    drops sharply (~30 µs vs ~226 µs cold on the unikernel).

    No Python fallback: the Python harness path doesn't drive
    rustls's resumption store, so without `cargo` we just report a
    NO_LOADGEN sentinel rather than silently mis-measuring."""
    bin_path = _loadgen_bin()
    if bin_path is None:
        return 0.0, "NO_LOADGEN", "NO_LOADGEN"
    try:
        r = subprocess.run(
            [
                bin_path,
                "tls-resume",
                "--host",
                host,
                "--port",
                str(port),
                "--endpoint",
                endpoint,
                "--duration-secs",
                str(duration),
                "--warmup-secs",
                str(warmup),
                "--parallelism",
                str(parallelism),
            ],
            capture_output=True,
            text=True,
            timeout=duration + warmup + 30,
        )
        if r.returncode != 0:
            return 0.0, "ERROR", "ERROR"
        return _parse_loadgen_output(r.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return 0.0, "TIMEOUT", "TIMEOUT"


def run_loadgen_h3_health(port, endpoint, duration, host, parallelism, warmup=1):
    """Run the Rust loadgen HTTP/3 keep-alive workload. Each worker
    opens its own QUIC connection, completes the handshake (skipped
    from the histogram), then fires sequential GETs on the keep-
    alive connection. Mirrors `health_tls_max`'s shape; isolates the
    QUIC TX hot path that item B2 optimised.

    No Python fallback: the standard library has no HTTP/3 client,
    and brew's curl on macOS isn't built with quiche/ngtcp2 — without
    `cargo` we report NO_LOADGEN rather than silently skipping."""
    bin_path = _loadgen_bin()
    if bin_path is None:
        return 0.0, "NO_LOADGEN", "NO_LOADGEN"
    try:
        r = subprocess.run(
            [
                bin_path,
                "h3-health",
                "--host",
                host,
                "--port",
                str(port),
                "--endpoint",
                endpoint,
                "--duration-secs",
                str(duration),
                "--warmup-secs",
                str(warmup),
                "--parallelism",
                str(parallelism),
            ],
            capture_output=True,
            text=True,
            timeout=duration + warmup + 30,
        )
        if r.returncode != 0:
            return 0.0, "ERROR", "ERROR"
        return _parse_loadgen_output(r.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return 0.0, "TIMEOUT", "TIMEOUT"


def run_loadgen_http(
    proto, port, endpoint, duration, host, connections, streams=1, warmup=1
):
    """Run the Rust loadgen unified keep-alive HTTP workload for the
    given protocol version (`proto` in {"h1", "h2", "h3"}). `--streams`
    is the per-connection in-flight concurrency (h2/h3 only; h1 forces
    1). This is the apples-to-apples keep-alive GET hot path across all
    three HTTP versions — the analogue of `wrk` (h1) and `h3-health`
    (h3), now also covering HTTP/2. Returns `(rps, p50, p99)`.

    No Python fallback: there's no stdlib h2/h3 client and brew's curl
    isn't a load generator — without `cargo` we report NO_LOADGEN."""
    bin_path = _loadgen_bin()
    if bin_path is None:
        return 0.0, "NO_LOADGEN", "NO_LOADGEN"
    try:
        r = subprocess.run(
            [
                bin_path,
                "http",
                "--proto",
                proto,
                "--host",
                host,
                "--port",
                str(port),
                "--endpoint",
                endpoint,
                "--duration-secs",
                str(duration),
                "--warmup-secs",
                str(warmup),
                "--connections",
                str(connections),
                "--streams",
                str(streams),
            ],
            capture_output=True,
            text=True,
            timeout=duration + warmup + 30,
        )
        if r.returncode != 0:
            return 0.0, "ERROR", "ERROR"
        return _parse_loadgen_output(r.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return 0.0, "TIMEOUT", "TIMEOUT"


def run_loadgen_tcp_echo(port, conns, duration, host="127.0.0.1", msg_size=64):
    """Run the Rust loadgen TCP-echo workload. Returns the same
    `(rps, p50, p99)` shape as `run_tcp_echo`."""
    bin_path = _loadgen_bin()
    if bin_path is None:
        return run_tcp_echo(port, conns, duration, host=host, msg_size=msg_size)
    try:
        r = subprocess.run(
            [
                bin_path,
                "tcp-echo",
                "--host",
                host,
                "--port",
                str(port),
                "--duration-secs",
                str(duration),
                "--connections",
                str(conns),
                "--msg-size",
                str(msg_size),
            ],
            capture_output=True,
            text=True,
            timeout=duration + 30,
        )
        if r.returncode != 0:
            return 0.0, "ERROR", "ERROR"
        return _parse_loadgen_output(r.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return 0.0, "TIMEOUT", "TIMEOUT"


def run_loadgen_http_upload(port, endpoint, conns, duration, host, msg_size, tls=False):
    """Run the Rust loadgen `http-upload` workload — keep-alive
    POSTs of a sized body to `endpoint`, optionally over TLS.
    Returns `(rps, p50_us, p99_us)`."""
    bin_path = _loadgen_bin()
    if bin_path is None:
        return 0.0, "NO_LOADGEN", "NO_LOADGEN"
    argv = [
        bin_path,
        "http-upload",
        "--host",
        host,
        "--port",
        str(port),
        "--endpoint",
        endpoint,
        "--duration-secs",
        str(duration),
        "--connections",
        str(conns),
        "--msg-size",
        str(msg_size),
    ]
    if tls:
        argv.append("--tls")
    try:
        # `duration + 60` (was +30) — at higher core counts the
        # upload workload sometimes stalls in the loadgen-internal
        # scheduling for >10s under load, and the prior +30 budget
        # caught those legitimate-but-slow runs as TIMEOUT (saw it
        # as a 4c coin-flip between 60k req/s and TIMEOUT on
        # identical builds). +60 keeps real hangs bounded while
        # absorbing stall variance.
        r = subprocess.run(argv, capture_output=True, text=True, timeout=duration + 60)
        if r.returncode != 0:
            return 0.0, "ERROR", "ERROR"
        return _parse_loadgen_output(r.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return 0.0, "TIMEOUT", "TIMEOUT"


def run_loadgen_gateway(
    port, backend_port, conns, duration, host="127.0.0.1", msg_size=32
):
    """Run the Rust loadgen `gateway` workload. Hosts a UDP echo
    backend on `backend_port` (loadgen's own tokio task), then drives
    the unikernel's gateway listener at `host:port` with `conns`
    keep-alive TCP connections, each looping ping → forward → pong.
    Returns `(rps, p50_us, p99_us)`."""
    bin_path = _loadgen_bin()
    if bin_path is None:
        return 0.0, "NO_LOADGEN", "NO_LOADGEN"
    try:
        r = subprocess.run(
            [
                bin_path,
                "gateway",
                "--host",
                host,
                "--port",
                str(port),
                "--backend-port",
                str(backend_port),
                "--duration-secs",
                str(duration),
                "--connections",
                str(conns),
                "--msg-size",
                str(msg_size),
            ],
            capture_output=True,
            text=True,
            timeout=duration + 30,
        )
        if r.returncode != 0:
            return 0.0, "ERROR", "ERROR"
        return _parse_loadgen_output(r.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return 0.0, "TIMEOUT", "TIMEOUT"


def _udp_bench_bin():
    """Return the path to the compiled udp_bench binary, building if needed.

    Compiles `udp_bench.c` (colocated with this module) into a per-user
    `/tmp` cache dir so the source tree stays clean and the script is
    installable as read-only.
    """
    src = os.path.join(os.path.dirname(__file__), "udp_bench.c")
    if not os.path.isfile(src):
        return None

    cache = os.path.join(tempfile.gettempdir(), f"waitless_bench_{os.getuid()}")
    os.makedirs(cache, exist_ok=True)
    udp_bin = os.path.join(cache, "udp_bench")

    if not os.path.isfile(udp_bin) or os.path.getmtime(udp_bin) < os.path.getmtime(src):
        cc = subprocess.run(
            ["cc", "-O2", "-o", udp_bin, src, "-lpthread"],
            capture_output=True,
            timeout=30,
        )
        if cc.returncode != 0:
            return None
    return udp_bin if os.path.isfile(udp_bin) else None


def _parse_udp_bench_output(stdout):
    """Parse SENT, LOSS, and RESULT lines from udp_bench stdout.

    Returns (recv_pps, sent_pps, p50, p99, loss_pct) where sent_pps
    and loss_pct are None for modes that don't emit them (sync mode
    has neither; async mode has SENT but no LOSS).
    """
    recv_pps = sent_pps = None
    loss_pct = None
    p50 = p99 = ""
    for line in stdout.split("\n"):
        if line.startswith("SENT "):
            sent_pps = float(line.split()[1])
        elif line.startswith("LOSS "):
            loss_pct = float(line.split()[1])
        elif line.startswith("RESULT "):
            parts = line.split()
            recv_pps = float(parts[1])
            p50 = f"{int(parts[2])}us" if int(parts[2]) > 0 else ""
            p99 = f"{int(parts[3])}us" if int(parts[3]) > 0 else ""
    return recv_pps, sent_pps, p50, p99, loss_pct


def run_udp(port, senders, duration, host="127.0.0.1"):
    """Run UDP echo benchmark using the compiled C client.

    The C client (scripts/bench/udp_bench.c) uses fork() for parallelism,
    avoiding the Python GIL that throttled the old threading-based
    implementation to ~50k pkt/s regardless of sender count. The C
    client also collects a per-packet latency histogram from sender 0.
    """
    udp_bin = _udp_bench_bin()
    if udp_bin is None:
        return 0.0, "", ""
    cmd = [udp_bin, str(port), str(senders), str(duration)]
    if host != "127.0.0.1":
        cmd.append(f"--host={host}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
    except Exception:
        return 0.0, "", ""
    recv_pps, _, p50, p99, _ = _parse_udp_bench_output(r.stdout)
    if recv_pps is None:
        return 0.0, "", ""
    return recv_pps, p50, p99


def _udp_with_retry(port, senders, duration, host):
    """Run a UDP test, retrying up to two extra times if it returns 0.

    On tap+vhost the very first burst after a fresh VM boot occasionally
    races vhost-net warmup and yields zero replies even though a
    follow-up run on the same VM works. Retrying with a short pause
    masks the flake without hiding genuine failures (a broken config
    still records 0 after three attempts).
    """
    pps, p50, p99 = run_udp(port, senders, duration, host=host)
    for _ in range(2):
        if pps > 0:
            break
        time.sleep(0.5)
        pps, p50, p99 = run_udp(port, senders, duration, host=host)
    return pps, p50, p99


_UDP_PEAK_LEVELS = [8, 16, 32, 64, 128, 256, 512]


def _udp_concurrent_probe(
    port, slots_per_thread, duration, host, client_cpus, timeout_ms
):
    """Run one windowed udp_bench probe and return the parsed result.

    Returns `(recv_pps, loss_pct, p50, p99)`. All zeros on failure.
    """
    udp_bin = _udp_bench_bin()
    if udp_bin is None:
        return 0.0, 0.0, "", ""
    cmd = [
        udp_bin,
        str(port),
        str(slots_per_thread),
        str(duration),
        "--concurrent",
        f"--timeout={timeout_ms}",
    ]
    if client_cpus > 1:
        cmd.append(f"--client-cpus={client_cpus}")
    if host != "127.0.0.1":
        cmd.append(f"--host={host}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30)
    except Exception:
        return 0.0, 0.0, "", ""
    recv, _, p50, p99, loss = _parse_udp_bench_output(r.stdout)
    if recv is None:
        return 0.0, 0.0, "", ""
    return recv, loss or 0.0, p50, p99


def run_tcp_echo(port, conns, duration, host="127.0.0.1", msg_size=64):
    """Pump ping-pong messages over `conns` TCP connections for
    `duration` seconds. Returns (recv_rps, p50, p99, sent_msgs).

    Measures the full async TCP path: accept → recv.await → send.
    Latency samples are collected only from thread 0 to keep
    bookkeeping light; throughput aggregates across all threads.

    Python's GIL is a real ceiling here (~200 k msg/s on one thread
    is typical), so for high-conn counts we fork processes instead
    of threads — same trick `udp_bench.c` uses.
    """
    import multiprocessing as mp
    import socket
    import struct
    import time as _t

    msg = b"p" * msg_size
    msg_len = len(msg)
    deadline = _t.monotonic() + duration

    # SO_LINGER={on=1,linger=0} → close() RSTs instead of FIN, so the
    # loadgen side skips TIME_WAIT. macOS's 16K ephemeral pool would
    # otherwise fill up across back-to-back runs.
    linger = struct.pack("ii", 1, 0)

    def worker(sample_latency, barrier, result_q):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        sock.settimeout(5.0)
        try:
            sock.connect((host, port))
        except OSError:
            barrier.wait()
            result_q.put((0, b""))
            return

        sock.settimeout(None)
        buf = bytearray(msg_len)
        view = memoryview(buf)
        latencies = []
        count = 0
        # Synchronise start so per-worker ramp doesn't skew results.
        barrier.wait()
        while _t.monotonic() < deadline:
            if sample_latency:
                t0 = _t.monotonic_ns()
            sock.sendall(msg)
            got = 0
            while got < msg_len:
                n = sock.recv_into(view[got:], msg_len - got)
                if n == 0:
                    break
                got += n
            if got < msg_len:
                break
            if sample_latency:
                latencies.append(_t.monotonic_ns() - t0)
            count += 1
        sock.close()
        # Compact latency list into bytes to cheaply move across the
        # multiprocessing boundary.
        if latencies:
            lat_bytes = struct.pack(f"<{len(latencies)}Q", *latencies)
        else:
            lat_bytes = b""
        result_q.put((count, lat_bytes))

    procs = []
    ctx = mp.get_context("fork")
    barrier = ctx.Barrier(conns + 1, timeout=10)
    result_q = ctx.Queue()
    for i in range(conns):
        p = ctx.Process(target=worker, args=(i == 0, barrier, result_q))
        p.start()
        procs.append(p)
    try:
        barrier.wait()  # release workers — clock now starts
    except Exception:
        # Barrier timed out — some worker couldn't connect in 10 s
        # (slow TCG, unresponsive guest). Tear everything down.
        for p in procs:
            if p.is_alive():
                p.terminate()
        for p in procs:
            p.join(timeout=1)
        return 0.0, "", ""
    start = _t.monotonic()

    # Hard wall clock on result collection so a runaway worker can't
    # stall the whole benchmark.
    hard_deadline = _t.monotonic() + duration + 10
    total = 0
    lat_bytes = b""
    collected = 0
    try:
        for _ in procs:
            remaining = max(0.1, hard_deadline - _t.monotonic())
            c, lb = result_q.get(timeout=remaining)
            total += c
            collected += 1
            if lb and not lat_bytes:
                lat_bytes = lb
    except Exception:
        # Timed out waiting for results. Kill survivors and report
        # whatever we did collect; downstream will show low rps.
        pass
    for p in procs:
        if p.is_alive():
            p.terminate()
    for p in procs:
        p.join(timeout=1)

    elapsed = max(1e-6, _t.monotonic() - start)
    rps = total / elapsed if collected > 0 else 0.0

    if lat_bytes:
        count = len(lat_bytes) // 8
        lats = list(struct.unpack(f"<{count}Q", lat_bytes))
        lats.sort()
        p50_us = lats[len(lats) // 2] / 1000.0
        p99_us = lats[min(len(lats) - 1, len(lats) * 99 // 100)] / 1000.0
        return rps, f"{p50_us:.1f}us", f"{p99_us:.1f}us"
    return rps, "", ""


def echo_udp_concurrent(port, duration, host, client_cpus=1, timeout_ms=100):
    """Find peak windowed-UDP throughput by sweeping the concurrency
    levels in `_UDP_PEAK_LEVELS` and taking the max.

    Runs udp_bench in --concurrent mode at each per-thread slot count
    in turn and picks the run with the highest recv rate. We probe
    the whole ladder instead of stopping early on a non-improving
    doubling — 2 s probes are noisy enough on tap/vhost and KVM that
    an early stop gets fooled (KVM 2c was reporting 460k at N=64 and
    bailing before reaching N=128 where it sustains 700k+). Max-of-N
    is robust to those single-probe dips at the cost of running the
    full ladder every time.

    Each probe's duration is `duration / len(_UDP_PEAK_LEVELS)`
    (floor 2 s) so the total bench time is roughly `duration`.

    Returns `(recv_pps, loss_pct, p50, p99, n_slots_per_thread)` for
    the level that achieved `recv_pps`. All zeros if every probe
    failed.
    """
    probe_duration = max(2, duration // len(_UDP_PEAK_LEVELS))
    best_pps = 0.0
    best_loss = 0.0
    best_p50 = ""
    best_p99 = ""
    best_n = _UDP_PEAK_LEVELS[0]

    for n in _UDP_PEAK_LEVELS:
        pps, loss, p50, p99 = _udp_concurrent_probe(
            port, n, probe_duration, host, client_cpus, timeout_ms
        )
        if pps <= 0:
            continue
        if pps > best_pps:
            best_pps = pps
            best_loss = loss
            best_p50 = p50
            best_p99 = p99
            best_n = n

    return best_pps, best_loss, best_p50, best_p99, best_n
