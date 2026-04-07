#!/usr/bin/env python3
"""Unified unikernel benchmark: environments × core counts × workloads.

Usage:
    python3 scripts/bench.py                                  # default: QEMU x86_64, 1 vs 4 cores
    python3 scripts/bench.py --env vz                         # VZ 1 vs 4 cores
    python3 scripts/bench.py --env qemu,vz                    # both environments
    python3 scripts/bench.py --env all                        # QEMU + VZ + Docker + native
    python3 scripts/bench.py --cores 1,2,4,8                  # custom core counts
    python3 scripts/bench.py --workload compute_c8            # single workload
    python3 scripts/bench.py --duration 10                    # longer runs
    python3 scripts/bench.py --env vz --cores 1,4             # VZ multi-core scaling
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


def wait_http(port, timeout=40):
    for _ in range(timeout):
        try:
            r = subprocess.run(
                ["curl", "-sf", "--max-time", "2", f"http://localhost:{port}/health"],
                capture_output=True, timeout=5)
            if r.returncode == 0:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def run_wrk(port, endpoint, threads, conns, duration):
    try:
        r = subprocess.run(
            ["wrk", f"-t{threads}", f"-c{conns}", f"-d{duration}s",
             "--timeout", "10s", "--latency",
             f"http://localhost:{port}{endpoint}"],
            capture_output=True, text=True, timeout=duration + 15)
        rps, p50, p99 = 0.0, "", ""
        for line in r.stdout.split("\n"):
            if "Requests/sec" in line:
                rps = float(line.split()[1])
            elif "50%" in line:
                p50 = line.split()[1]
            elif "99%" in line:
                p99 = line.split()[1]
        return rps, p50, p99
    except Exception:
        return 0.0, "", ""


def run_udp(port, senders, duration):
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
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return sum(recv) / duration


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


class VzEnv:
    name = "vz"
    label = "VZ.framework"

    def build(self):
        subprocess.run(
            ["bazel", "build", "--config=aarch64-vz",
             "//apps/webserver:webserver.img", "//scripts:run_vz"],
            capture_output=True, cwd=PROJECT_ROOT, timeout=120)

    def start(self, cpus, port):
        img = os.path.join(PROJECT_ROOT, "bazel-bin/apps/webserver/webserver.img")
        run_vz = os.path.join(PROJECT_ROOT, "bazel-bin/scripts/run-vz")
        env = os.environ.copy()
        env["UNIKERNEL_CPUS"] = str(cpus)
        env["UNIKERNEL_MEMORY"] = "128"
        return subprocess.Popen(
            [run_vz, img, str(port)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()

    def core_label(self, cpus):
        return f"VZ {cpus}c"


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

    def build(self):
        config = "aarch64-macos" if platform.machine() in ("arm64", "aarch64") else "x86_64-linux"
        subprocess.run(
            ["bazel", "build", f"--config={config}", "//apps/webserver:webserver_native"],
            capture_output=True, cwd=PROJECT_ROOT, timeout=120)

    def start(self, cpus, port):
        bin_path = os.path.join(PROJECT_ROOT, "bazel-bin/apps/webserver/webserver_native")
        if not os.path.exists(bin_path):
            return None
        env = os.environ.copy()
        env["PORT"] = str(port)
        return subprocess.Popen(
            [bin_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait()

    def core_label(self, cpus):
        return "Native"


ENV_MAP = {
    "qemu": QemuEnv,
    "qemu-arm": QemuAarch64Env,
    "vz": VzEnv,
    "docker": DockerEnv,
    "native": NativeEnv,
}

# ── Workload definitions ─────────────────────────────────────────────────────

WORKLOADS = [
    {"name": "health_c1",  "type": "tcp", "endpoint": "/health",  "threads": 1, "conns": 1,
     "desc": "/health × 1 conn (single-flow IO)"},
    {"name": "health_c8",  "type": "tcp", "endpoint": "/health",  "threads": 2, "conns": 8,
     "desc": "/health × 8 conn (IO-bound)"},
    {"name": "compute_c1", "type": "tcp", "endpoint": "/compute", "threads": 1, "conns": 1,
     "desc": "/compute × 1 conn (single-flow CPU)"},
    {"name": "compute_c8", "type": "tcp", "endpoint": "/compute", "threads": 2, "conns": 8,
     "desc": "/compute × 8 conn (CPU-bound)"},
    {"name": "udp_8s",     "type": "udp", "endpoint": "",         "threads": 0, "conns": 8,
     "desc": "UDP echo × 8 senders"},
]


def main():
    parser = argparse.ArgumentParser(description="Unikernel benchmark")
    parser.add_argument("--env", default="qemu",
                        help="Environments: qemu,vz,docker,native,all (comma-separated)")
    parser.add_argument("--cores", default="1,4",
                        help="Core counts to test (comma-separated)")
    parser.add_argument("--workload", default=None,
                        help="Specific workload name (default: all)")
    parser.add_argument("--duration", type=int, default=5,
                        help="Seconds per test (default: 5)")
    args = parser.parse_args()

    duration = args.duration
    core_counts = [int(c) for c in args.cores.split(",")]

    if args.env == "all":
        env_names = ["qemu", "qemu-arm", "vz", "docker", "native"]
    elif args.env == "vm":
        env_names = ["qemu", "qemu-arm", "vz"]
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
    # VZ: multi-core networking has inbox visibility issues (vz_compat mode
    # uses single-core networking). Override with --env vz --cores 1,4.
    single_core_only = {"docker", "native", "vz", "qemu-arm"}

    # Kill stale processes
    subprocess.run(["pkill", "-9", "-f", "qemu-system"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "run-vz"], capture_output=True)
    time.sleep(2)

    # Create environment instances (build happens before each test group
    # because bazel-bin is shared and configs overwrite each other).
    envs = {}
    for name in env_names:
        if name not in ENV_MAP:
            print(f"Unknown env: {name}. Available: {','.join(ENV_MAP.keys())}")
            sys.exit(1)
        envs[name] = ENV_MAP[name]()

    # Collect results: results[(env_name, cpus, workload_name)] = (rps, p50, p99)
    results = {}

    for env_name, env in envs.items():
        # Rebuild before each environment group (bazel-bin is shared).
        print(f"\n==> Building {env.label}...")
        env.build()

        for cpus in core_counts:
            if env_name in single_core_only and cpus > 1:
                continue

            label = env.core_label(cpus)
            print(f"\n==> {label}")

            for w in workloads:
                wname = w["name"]
                port = next_port()

                proc = env.start(cpus, port)
                if proc is None:
                    print(f"    {wname:<20s} SKIP (failed to start)")
                    results[(env_name, cpus, wname)] = (0, "", "")
                    continue

                if not wait_http(port):
                    print(f"    {wname:<20s} SKIP (not ready)")
                    env.stop(proc)
                    results[(env_name, cpus, wname)] = (0, "", "")
                    wait_port_pool()
                    continue

                if w["type"] == "tcp":
                    rps, p50, p99 = run_wrk(port, w["endpoint"], w["threads"], w["conns"], duration)
                    results[(env_name, cpus, wname)] = (rps, p50, p99)
                    print(f"    {wname:<20s} {rps:>10.0f} req/s  p50={p50}  p99={p99}")
                else:
                    pps = run_udp(port + 1, w["conns"], duration)
                    results[(env_name, cpus, wname)] = (pps, "", "")
                    print(f"    {wname:<20s} {pps:>10.0f} pkt/s")

                env.stop(proc)
                wait_port_pool()

    # ── Summary table ────────────────────────────────────────────────────────

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
