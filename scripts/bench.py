#!/usr/bin/env python3
"""Unified unikernel benchmark: environments × core counts × workloads.

Usage:
    python3 scripts/bench.py                                  # default: QEMU x86_64, 1 vs 4 cores
    python3 scripts/bench.py --env hvf                        # HVF 1 vs 4 cores
    python3 scripts/bench.py --env qemu,hvf                   # both environments
    python3 scripts/bench.py --env all                        # QEMU + HVF + Docker + native
    python3 scripts/bench.py --cores 1,2,4,8                  # custom core counts
    python3 scripts/bench.py --workload compute_c8            # single workload
    python3 scripts/bench.py --duration 10                    # longer runs
    python3 scripts/bench.py --env hvf --cores 1,4            # HVF multi-core scaling
"""

import argparse
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time

# Force line-buffered stdout so the bench output streams live over SSH
# pipes (otherwise piping `gcp-bench.sh ... | tail` swallows everything
# until exit and the bench appears stuck).
sys.stdout.reconfigure(line_buffering=True)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
PORT_COUNTER = [38000]


def next_port():
    PORT_COUNTER[0] += 10
    return PORT_COUNTER[0]


def wait_port_pool(threshold=500, timeout=8):
    if sys.platform != "darwin":
        time.sleep(1)
        return
    for _ in range(timeout):
        try:
            r = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=5)
            tw = sum(1 for l in r.stdout.split("\n") if "TIME_WAIT" in l and "127.0.0.1" in l)
            if tw <= threshold:
                return
        except Exception:
            pass
        time.sleep(1)


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
                capture_output=True, timeout=5)
            if r.returncode == 0:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def run_wrk(port, endpoint, threads, conns, duration, host="localhost"):
    # Hard-cap wrk's per-request timeout at 5 s so a stuck server can't
    # peg latency at the wrk default of 2 s and still appear "running"
    # for the entire duration. The subprocess timeout is `duration + 10`
    # so even a wedged wrk only blocks the bench by 10 s past its run.
    try:
        r = subprocess.run(
            ["wrk", f"-t{threads}", f"-c{conns}", f"-d{duration}s",
             "--timeout", "5s", "--latency",
             f"http://{host}:{port}{endpoint}"],
            capture_output=True, text=True, timeout=duration + 10)
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


def run_wrk_parallel(port, endpoint, threads, conns, duration, instances, host="localhost"):
    """Run `instances` parallel wrk processes and aggregate results.

    Each process is a separate OS client with its own TCP source-port range,
    which forces the OS (SO_REUSEPORT) or unikernel flow-hash to distribute
    connections across server threads/cores. Without this, all connections
    from a single wrk process can land on one server thread (macOS loopback
    SO_REUSEPORT ignores source-port in its hash).

    conns and threads are split evenly across instances (minimum 1 each).
    Total req/s is summed; p50/p99 are the median across instances.
    """
    per_conns   = max(1, (conns   + instances - 1) // instances)
    per_threads = max(1, (threads + instances - 1) // instances)

    all_results = [None] * instances
    lock = threading.Lock()

    def run_one(idx):
        r = run_wrk(port, endpoint, per_threads, per_conns, duration, host=host)
        with lock:
            all_results[idx] = r

    ts = [threading.Thread(target=run_one, args=(i,)) for i in range(instances)]
    for t in ts: t.start()
    for t in ts: t.join()

    total_rps = sum(r[0] for r in all_results if r)
    p50s = sorted(r[1] for r in all_results if r and r[1])
    p99s = sorted(r[2] for r in all_results if r and r[2])
    p50 = p50s[len(p50s) // 2] if p50s else ""
    p99 = p99s[len(p99s) // 2] if p99s else ""
    return total_rps, p50, p99


def _udp_bench_bin():
    """Return the path to the compiled udp_bench binary, building if needed."""
    udp_bin = os.path.join(SCRIPT_DIR, "udp_bench")
    if not os.path.isfile(udp_bin):
        src = os.path.join(SCRIPT_DIR, "udp_bench.c")
        if os.path.isfile(src):
            subprocess.run(["cc", "-O2", "-o", udp_bin, src, "-lpthread"],
                           capture_output=True, timeout=30)
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


def run_udp(port, senders, duration, async_mode=False, host="127.0.0.1",
            rate_per_sender=0, client_cpus=1):
    """Run UDP echo benchmark using the compiled C client.

    The C client (scripts/udp_bench) uses fork() for parallelism,
    avoiding the Python GIL that throttled the old threading-based
    implementation to ~50k pkt/s regardless of sender count. The C
    client also collects a per-packet latency histogram from sender 0.

    In async mode (--async), each sender process forks a child that
    does the blocking recv() loop in parallel with the send loop —
    split across processes so the send spin can't starve recv on a
    single core. When `rate_per_sender` is set, each sender paces its
    sendto() loop to that many packets/sec, modelling realistic
    concurrent clients instead of blasting the server.

    `client_cpus` controls how many pthread workers drive the async
    senders in parallel — setting it equal to the server's vCPU count
    keeps the client from becoming the throughput ceiling at multi-core
    server configurations.

    Falls back to the old Python implementation if the C binary isn't
    found (first run before compilation).
    """
    udp_bin = _udp_bench_bin()
    if udp_bin:
        try:
            cmd = [udp_bin, str(port), str(senders), str(duration)]
            if async_mode:
                cmd.append("--async")
                if rate_per_sender > 0:
                    cmd.append(f"--rate={rate_per_sender}")
                if client_cpus > 1:
                    cmd.append(f"--client-cpus={client_cpus}")
            if host != "127.0.0.1":
                cmd.append(f"--host={host}")
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=duration + 10)
            recv_pps, _, p50, p99, _ = _parse_udp_bench_output(r.stdout)
            if recv_pps is not None:
                return recv_pps, p50, p99
        except Exception:
            pass

    # Fallback: old Python implementation (GIL-limited, sync only).
    recv = [0] * senders
    def sender(idx):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.bind(("", 0))
        end = time.monotonic() + duration
        while time.monotonic() < end:
            s.sendto(b"x", ("127.0.0.1", port))
            try:
                s.recvfrom(64)
                recv[idx] += 1
            except socket.timeout:
                pass
        s.close()
    threads = [threading.Thread(target=sender, args=(i,)) for i in range(senders)]
    for t in threads: t.start()
    for t in threads: t.join()
    return sum(recv) / duration, "", ""


def _udp_with_retry(port, senders, duration, host, async_mode, rate_per_sender=0):
    """Run a UDP test, retrying up to two extra times if it returns 0.

    On tap+vhost the very first udp_async burst after a fresh VM boot
    occasionally races vhost-net warmup and yields zero replies even
    though a follow-up run on the same VM works. Retrying with a short
    pause masks the flake without hiding genuine failures (a broken
    config still records 0 after three attempts).
    """
    pps, p50, p99 = run_udp(port, senders, duration, async_mode=async_mode,
                            host=host, rate_per_sender=rate_per_sender)
    for _ in range(2):
        if pps > 0:
            break
        time.sleep(0.5)
        pps, p50, p99 = run_udp(port, senders, duration, async_mode=async_mode,
                                host=host, rate_per_sender=rate_per_sender)
    return pps, p50, p99


_UDP_PEAK_LEVELS = [8, 16, 32, 64, 128, 256, 512]


def _udp_concurrent_probe(port, slots_per_thread, duration, host,
                          client_cpus, timeout_ms):
    """Run one windowed udp_bench probe and return the parsed result.

    Returns `(recv_pps, loss_pct, p50, p99)`. All zeros on failure.
    """
    udp_bin = _udp_bench_bin()
    if udp_bin is None:
        return 0.0, 0.0, "", ""
    cmd = [udp_bin, str(port), str(slots_per_thread), str(duration),
           "--concurrent", f"--timeout={timeout_ms}"]
    if client_cpus > 1:
        cmd.append(f"--client-cpus={client_cpus}")
    if host != "127.0.0.1":
        cmd.append(f"--host={host}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=duration + 30)
    except Exception:
        return 0.0, 0.0, "", ""
    recv, _, p50, p99, loss = _parse_udp_bench_output(r.stdout)
    if recv is None:
        return 0.0, 0.0, "", ""
    return recv, loss or 0.0, p50, p99


def udp_peak_concurrent(port, duration, host, client_cpus=1, timeout_ms=100):
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
            port, n, probe_duration, host, client_cpus, timeout_ms)
        if pps <= 0:
            continue
        if pps > best_pps:
            best_pps = pps
            best_loss = loss
            best_p50 = p50
            best_p99 = p99
            best_n = n

    return best_pps, best_loss, best_p50, best_p99, best_n


# ── Environment runners ──────────────────────────────────────────────────────

class QemuEnv:
    name = "qemu"
    label = "QEMU x86_64 TCG"

    def build(self):
        subprocess.run(
            ["bazel", "build", "--config=x86_64-qemu", "//apps/webserver:webserver.elf"],
            capture_output=True, cwd=PROJECT_ROOT, timeout=120)

    def start(self, cpus, port):
        elf = os.path.join(PROJECT_ROOT, "bazel-bin/apps/webserver/webserver.elf")
        cmd = ["qemu-system-x86_64", "-cpu", "qemu64",
               "-m", "128", "-smp", str(cpus), "-nographic",
               "-serial", f"file:/tmp/bench_{port}.log", "-no-reboot"]
        if cpus > 1:
            cmd += ["-accel", "tcg,thread=multi"]
        dev = "virtio-net-pci"
        if cpus > 1:
            dev += f",mq=on,vectors={2*cpus+2}"
        cmd += ["-device", f"{dev},netdev=net0",
                "-netdev", f"user,id=net0,hostfwd=tcp::{port}-:80,hostfwd=udp::{port+1}-:7",
                "-kernel", elf]
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()

    def core_label(self, cpus):
        return f"QEMU {cpus}c" + (" MTTCG" if cpus > 1 else "")


class KvmEnv:
    name = "kvm"
    label = "QEMU x86_64 KVM"

    # Guest IP served by dnsmasq on the GCP host tap0; see
    # /usr/local/sbin/bench-tap-setup.sh. Fixed MAC pins this address.
    TAP_IF = "tap0"
    GUEST_MAC = "52:54:00:12:34:56"
    GUEST_IP = "10.20.30.10"
    GUEST_PORT = 80
    GUEST_UDP_PORT = 7

    # Path to pre-staged ELF; set via --elf. If None, bazel build runs.
    elf_override = None

    def build(self):
        if self.elf_override:
            return  # Pre-staged binary; nothing to build.
        subprocess.run(
            ["bazel", "build", "--config=x86_64-qemu", "//apps/webserver:webserver.elf"],
            capture_output=True, cwd=PROJECT_ROOT, timeout=120)

    def start(self, cpus, port):
        elf = self.elf_override or os.path.join(
            PROJECT_ROOT, "bazel-bin/apps/webserver/webserver.elf")
        # tap backend with vhost-net + multi-queue. Multi-queue is only
        # requested when cpus > 1 because QEMU rejects queues=1 on tap.
        cmd = ["qemu-system-x86_64", "-accel", "kvm", "-cpu", "host",
               "-m", "128", "-smp", str(cpus), "-nographic",
               "-serial", f"file:/tmp/bench_{port}.log", "-no-reboot"]
        # The host tap0 is created with IFF_MULTI_QUEUE; QEMU rejects
        # opening it with queues=1 ("could not configure /dev/net/tun:
        # Invalid argument"), so use max(cpus, 2) on the netdev side.
        nqueues = max(cpus, 2)
        netdev = (f"tap,id=net0,ifname={self.TAP_IF},script=no,downscript=no,"
                  f"vhost=on,queues={nqueues}")
        # Always pass `mq=on` and `vectors` on the device, even at 1c.
        # Without it, vhost-net silently drops UDP under high send rates
        # when the netdev has more queues than the device exposes (the
        # guest still negotiates only `cpus` queue pairs because the
        # driver gates activation on cpu count, but the device side
        # needs mq=on to wire up vhost properly with the multi-queue tap).
        #
        dev = f"virtio-net-pci,mac={self.GUEST_MAC},mq=on,vectors={2*nqueues+2}"
        cmd += ["-device", f"{dev},netdev=net0",
                "-netdev", netdev,
                "-kernel", elf]
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()
        # vhost-net's per-queue worker threads occasionally hang on to a
        # multi-queue tap fd just long enough that the next QEMU instance
        # finds the device in a half-broken state — udp_async at 1c then
        # records 0 pkt/s for several runs in a row even though the same
        # command works in isolation. Tearing tap0 down and re-creating
        # it between iterations gives vhost a clean slate and eliminates
        # the flake. Cheap (~30ms) compared to a 6s test.
        try:
            subprocess.run(
                ["sudo", "ip", "link", "del", self.TAP_IF],
                capture_output=True, timeout=5)
            subprocess.run(
                ["sudo", "/usr/local/sbin/bench-tap-setup.sh"],
                capture_output=True, timeout=5)
        except Exception:
            pass

    def core_label(self, cpus):
        return f"KVM {cpus}c"


class QemuAarch64Env:
    name = "qemu-arm"
    label = "QEMU aarch64 TCG"

    def build(self):
        subprocess.run(
            ["bazel", "build", "--config=aarch64-qemu", "//apps/webserver:webserver.img"],
            capture_output=True, cwd=PROJECT_ROOT, timeout=120)

    def start(self, cpus, port):
        img = os.path.join(PROJECT_ROOT, "bazel-bin/apps/webserver/webserver.img")
        cmd = ["qemu-system-aarch64", "-machine", "virt", "-cpu", "max",
               "-m", "128", "-smp", str(cpus), "-nographic",
               "-serial", f"file:/tmp/bench_{port}.log", "-no-reboot",
               "-device", "virtio-net-device,netdev=net0",
               "-netdev", f"user,id=net0,hostfwd=tcp::{port}-:80,hostfwd=udp::{port+1}-:7",
               "-kernel", img]
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()

    def core_label(self, cpus):
        return f"ARM {cpus}c"


class DockerEnv:
    name = "docker"
    label = "Docker/Linux"
    cid = None

    def build(self):
        subprocess.run(
            ["bazel", "build", "--config=x86_64-linux", "//apps/webserver:webserver_native"],
            capture_output=True, cwd=PROJECT_ROOT, timeout=120)
        bench_dir = os.path.join(PROJECT_ROOT, "bench")
        src = os.path.join(PROJECT_ROOT, "bazel-bin/apps/webserver/webserver_native")
        if os.path.exists(src):
            os.makedirs(bench_dir, exist_ok=True)
            shutil.copy2(src, os.path.join(bench_dir, "webserver_native"))
            subprocess.run(["docker", "build", "-q", "-t", "webserver_linux", bench_dir],
                           capture_output=True, timeout=60)

    def start(self, cpus, port):
        r = subprocess.run(
            ["docker", "run", "--rm", "-d", "-p", f"{port}:80", "webserver_linux"],
            capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            self.cid = r.stdout.strip()
        return self  # return self as "proc" handle

    def stop(self, proc):
        if self.cid:
            subprocess.run(["docker", "stop", self.cid], capture_output=True, timeout=10)
            self.cid = None

    def poll(self):
        return None if self.cid else 1

    def core_label(self, cpus):
        return "Docker"


class NativeEnv:
    name = "native"
    label = "Native (POSIX)"

    # Path to pre-staged native binary; set via --native-bin. If None, bazel build runs.
    bin_override = None

    def build(self):
        if self.bin_override:
            return  # Pre-staged binary; nothing to build.
        config = "aarch64-macos" if platform.machine() in ("arm64", "aarch64") else "x86_64-linux"
        subprocess.run(
            ["bazel", "build", f"--config={config}", "//apps/webserver:webserver_native"],
            capture_output=True, cwd=PROJECT_ROOT, timeout=120)

    def start(self, cpus, port):
        bin_path = self.bin_override or os.path.join(
            PROJECT_ROOT, "bazel-bin/apps/webserver/webserver_native")
        if not os.path.exists(bin_path):
            return None
        env = os.environ.copy()
        env["PORT"] = str(port)
        env["UDP_PORT"] = str(port + 1)
        env["THREADS"] = str(cpus)
        return subprocess.Popen(
            [bin_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait()

    def core_label(self, cpus):
        return f"Native {cpus}t"


class HvfEnv:
    name = "hvf"
    label = "HVF"
    udp_port_offset = 10000  # host UDP port = guest port + 10000

    def build(self):
        subprocess.run(
            ["bazel", "build", "--config=qemu",
             "//apps/webserver:webserver.img"],
            capture_output=True, cwd=PROJECT_ROOT, timeout=120)
        subprocess.run(
            ["cargo", "build", "--release"],
            capture_output=True,
            cwd=os.path.join(PROJECT_ROOT, "tools/hvf-runner"), timeout=120)
        subprocess.run(
            ["codesign", "--force", "--sign", "-", "--entitlements",
             os.path.join(PROJECT_ROOT, "tools/hvf-runner/run-hvf.entitlements"),
             os.path.join(PROJECT_ROOT, "tools/hvf-runner/target/release/run-hvf")],
            capture_output=True, timeout=30)

    def start(self, cpus, port):
        img = os.path.join(PROJECT_ROOT, "bazel-bin/apps/webserver/webserver.img")
        run_hvf = os.path.join(PROJECT_ROOT, "tools/hvf-runner/target/release/run-hvf")
        log = open(f"/tmp/hvf_{port}.log", "w")
        udp_port = port + self.udp_port_offset
        # -p tcp:HOST:GUEST forwards HTTP to guest:80; -p udp:HOST:GUEST
        # forwards the UDP echo test to guest:7.
        return subprocess.Popen(
            [run_hvf, img,
             "--ram=128", f"--cpus={cpus}",
             "-p", f"tcp:{port}:80",
             "-p", f"udp:{udp_port}:7"],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log)

    def wait_proxy_ready(self, port, proc, timeout=30):
        """Wait for the HTTP server to be reachable on the proxy port."""
        return wait_http(port, timeout)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        time.sleep(0.5)

    def core_label(self, cpus):
        return f"HVF {cpus}c"


ENV_MAP = {
    "qemu": QemuEnv,
    "kvm": KvmEnv,
    "qemu-arm": QemuAarch64Env,
    "hvf": HvfEnv,
    "docker": DockerEnv,
    "native": NativeEnv,
}


def start_env_verified(env, cpus, port):
    """Start env and verify HTTP readiness.

    For HVF: wait for the proxy TCP port to be connectable, then poll
    HTTP for the VM to finish booting. Retry once if first attempt fails.
    For other envs: poll HTTP directly, no retry.
    """
    proc = env.start(cpus, port)
    if proc is None:
        return None

    if isinstance(env, HvfEnv):
        # Phase 1: wait for proxy TCP port to be connectable (fast, <1s normally).
        if not env.wait_proxy_ready(port, proc, timeout=30):
            env.stop(proc)
            # Retry once — network interface may not have been released yet.
            proc = env.start(cpus, port)
            if proc is None:
                return None
            if not env.wait_proxy_ready(port, proc, timeout=30):
                env.stop(proc)
                return None
        # Phase 2: poll HTTP until the VM finishes booting.
        if wait_http(port):
            return proc
        env.stop(proc)
        return None
    elif isinstance(env, KvmEnv):
        if wait_http(env.GUEST_PORT, host=env.GUEST_IP):
            return proc
        env.stop(proc)
        return None
    else:
        if wait_http(port):
            return proc
        env.stop(proc)
        return None

# ── Workload definitions ─────────────────────────────────────────────────────

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
]


def main():
    parser = argparse.ArgumentParser(description="Unikernel benchmark")
    parser.add_argument("--env", default="qemu",
                        help="Environments: qemu,hvf,docker,native,all (comma-separated)")
    parser.add_argument("--cores", default="1,4",
                        help="Core counts to test (comma-separated)")
    parser.add_argument("--workload", default=None,
                        help="Specific workload name (default: all)")
    parser.add_argument("--duration", type=int, default=5,
                        help="Seconds per test (default: 5)")
    parser.add_argument("--elf", default=None,
                        help="Pre-built ELF path (kvm env; skips bazel build)")
    parser.add_argument("--native-bin", default=None,
                        help="Pre-built native binary path (native env; skips bazel build)")
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
        workloads = [w for w in WORKLOADS if w["name"] == args.workload]
        if not workloads:
            print(f"Unknown workload: {args.workload}")
            print(f"Available: {', '.join(w['name'] for w in WORKLOADS)}")
            sys.exit(1)

    # These environments only run single-core benchmarks.
    # ARM TCG: no MTTCG support.
    single_core_only = {"docker", "qemu-arm"}

    # Kill stale processes
    subprocess.run(["pkill", "-9", "-f", "qemu-system"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "run-hvf"], capture_output=True)
    # Anchor to argv[0] to avoid matching our own bench.py cmdline when
    # --native-bin /path/webserver_native is passed.
    subprocess.run(["pkill", "-9", "-f", r"^\S*/webserver_native( |$)"],
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

    # Collect results: results[(env_name, cpus, workload_name)] = (rps, p50, p99)
    results = {}
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
                    if isinstance(env, HvfEnv):
                        for suffix, label in [(".serial.log", "serial"), (".log", "stderr")]:
                            try:
                                with open(f"/tmp/hvf_{port}{suffix}") as lf:
                                    lines = lf.read().strip().splitlines()
                                    for l in lines[-8:]:
                                        print(f"      {label}: {l}")
                            except Exception:
                                pass
                    results[(env_name, cpus, wname)] = (0, "", "")
                    wait_port_pool()
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
                if isinstance(env, KvmEnv):
                    wrk_host = env.GUEST_IP
                    wrk_port = env.GUEST_PORT
                    udp_target_port = env.GUEST_UDP_PORT
                else:
                    wrk_host = "localhost"
                    wrk_port = bench_port
                    udp_off = getattr(env, 'udp_port_offset', 1)
                    udp_target_port = bench_port + udp_off

                # Workloads that scale with cpu count compute their final
                # conn / thread / sender counts here. Static workloads keep
                # the literal "conns" / "threads" / "senders" fields.
                conns = w.get("conns", 0)
                threads = w.get("threads", 0)
                if "conns_per_core" in w:
                    conns = w["conns_per_core"] * cpus
                if "threads_per_core" in w:
                    threads = max(1, w["threads_per_core"] * cpus)
                # UDP workloads use a fixed sender count by default —
                # tying senders to vCPUs would conflate the workload's
                # client-side concurrency with the server's core count
                # and make scaling curves impossible to read.
                senders = w.get("senders", 0)
                if "senders_per_core" in w:
                    senders = max(1, w["senders_per_core"] * cpus)
                # udp_bench caps senders at 64 and below 1.
                senders = max(1, min(64, senders))

                if w["type"] == "tcp":
                    if w.get("parallel") and cpus > 1:
                        rps, p50, p99 = run_wrk_parallel(
                            wrk_port, w["endpoint"], threads, conns, duration, cpus,
                            host=wrk_host)
                    else:
                        rps, p50, p99 = run_wrk(
                            wrk_port, w["endpoint"], threads, conns, duration,
                            host=wrk_host)
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    print(f"    {wname:<20s} {rps:>10.0f} req/s  p50={p50}  p99={p99}")
                elif w["type"] == "udp":
                    # Let wait_http's TCP teardown settle before firing a
                    # UDP burst — without this the first sender very
                    # occasionally wins a race against vhost-net's
                    # per-queue worker thread and the test records 0.
                    time.sleep(0.5)
                    pps, p50, p99 = _udp_with_retry(
                        udp_target_port, senders, duration, wrk_host, async_mode=False)
                    results[(env_name, cpus, wname)] = (pps, p50, p99)
                    print(f"    {wname:<20s} {pps:>10.0f} pkt/s  p50={p50}  p99={p99}")
                elif w["type"] == "udp_async":
                    time.sleep(0.5)
                    rate = w.get("rate_per_sender", 0)
                    pps, p50, p99 = _udp_with_retry(
                        udp_target_port, senders, duration, wrk_host,
                        async_mode=True, rate_per_sender=rate)
                    results[(env_name, cpus, wname)] = (pps, p50, p99)
                    print(f"    {wname:<20s} {pps:>10.0f} pkt/s  (async recv rate)")
                elif w["type"] == "udp_peak":
                    time.sleep(0.5)
                    # Windowed mode with adaptive concurrency ramp:
                    # probe per-thread slot counts [32..512] and pick
                    # the level where throughput plateaus, so each
                    # platform gets the concurrency that actually
                    # exposes its ceiling without over-pressuring it.
                    pps, loss_pct, p50, p99, best_n = udp_peak_concurrent(
                        udp_target_port, duration, wrk_host,
                        client_cpus=cpus)
                    results[(env_name, cpus, wname)] = (pps, p50, p99)
                    print(f"    {wname:<20s} {pps:>10.0f} pkt/s  "
                          f"({best_n}x{cpus} in-flight, {loss_pct:.1f}% loss)")

                env.stop(proc)
                _current["proc"] = None
                wait_port_pool()
    except KeyboardInterrupt:
        print("\nInterrupted — cleaning up...")
        _kill_current()
        sys.exit(1)

    # ── Summary table ────────────────────────────────────────────────────────

    # Restore blocking mode on stdout. Child processes (QEMU, run-hvf) can
    # leave fd 1 in O_NONBLOCK state because macOS shares file-description
    # flags across fork+exec. Without this, the summary print() calls below
    # raise BlockingIOError(errno 35) on long lines.
    import fcntl
    fl = fcntl.fcntl(sys.stdout.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sys.stdout.fileno(), fcntl.F_SETFL, fl & ~os.O_NONBLOCK)

    # Build column list: (env_name, cpus) pairs that have data
    columns = []
    for env_name in env_names:
        for cpus in core_counts:
            if env_name in single_core_only and cpus > 1:
                continue
            columns.append((env_name, cpus))

    print()
    print("=" * (24 + 14 * len(columns) + 10))
    print(f"  Benchmark Results  ({duration}s per test)")
    print("=" * (24 + 14 * len(columns) + 10))

    # Header
    hdr = f"  {'Workload':<22s}"
    for env_name, cpus in columns:
        env = envs[env_name]
        hdr += f" {env.core_label(cpus):>12s}"
    # Scaling columns: one per environment that has multiple core counts
    scaling_envs = []
    for env_name in env_names:
        env_cores = [c for c in core_counts if not (env_name in single_core_only and c > 1)]
        if len(env_cores) > 1:
            scaling_envs.append(env_name)
            hdr += f" {envs[env_name].label[:6]+' ×':>8s}"
    print(hdr)
    print(f"  {'─'*22}" + f" {'─'*12}" * len(columns) + (f" {'─'*8}" * len(scaling_envs)))

    # Rows
    for w in workloads:
        wname = w["name"]
        row = f"  {wname:<22s}"
        for env_name, cpus in columns:
            val = results.get((env_name, cpus, wname), (0, "", ""))
            row += f" {val[0]:>10.0f}  "

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

    print("=" * (24 + 14 * len(columns) + 10))
    print(f"  Duration: {duration}s | /compute: 100K hash iters | /health: static JSON")
    if any(c > 1 for c in core_counts):
        print(f"  Multi-core: MTTCG (x86_64) or hardware (VZ)")
    print("=" * (24 + 14 * len(columns) + 10))


if __name__ == "__main__":
    main()
