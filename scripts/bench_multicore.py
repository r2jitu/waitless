#!/usr/bin/env python3
"""Multi-core scaling benchmark for the unikernel.

Measures throughput across workload types, connection counts, and core counts.
Produces a summary table with scaling factors.

Usage:
    ./scripts/bench_multicore.py
    BENCH_DURATION=10 ./scripts/bench_multicore.py
"""

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DURATION = int(os.environ.get("BENCH_DURATION", "5"))
BASE_PORT = [37600]  # mutable for next_port


def next_port():
    BASE_PORT[0] += 10
    return BASE_PORT[0]


def wait_port_pool(threshold=500, timeout=10):
    """Wait for TIME_WAIT socket count to drop below threshold."""
    if sys.platform != "darwin":
        time.sleep(2)
        return
    for _ in range(timeout):
        try:
            r = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=5)
            tw = sum(1 for line in r.stdout.split("\n") if "TIME_WAIT" in line and "127.0.0.1" in line)
            if tw <= threshold:
                return
        except Exception:
            pass
        time.sleep(1)


def build():
    print("==> Building x86_64 unikernel...")
    r = subprocess.run(
        ["bazel", "build", "--config=x86_64-qemu", "//apps/webserver:webserver.elf"],
        capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=120,
    )
    if r.returncode != 0:
        print(f"Build failed:\n{r.stderr}")
        sys.exit(1)
    print("    done")


def start_vm(cpus, port):
    elf = os.path.join(PROJECT_ROOT, "bazel-bin/apps/webserver/webserver.elf")
    log = f"/tmp/bench_mc_{cpus}_{port}.log"
    cmd = [
        "qemu-system-x86_64", "-cpu", "qemu64",
        "-m", "128", "-smp", str(cpus), "-nographic",
        "-serial", f"file:{log}", "-no-reboot",
    ]
    if cpus > 1:
        cmd += ["-accel", "tcg,thread=multi"]
    dev = "virtio-net-pci"
    if cpus > 1:
        vectors = 2 * cpus + 2
        dev += f",mq=on,vectors={vectors}"
    cmd += [
        "-device", f"{dev},netdev=net0",
        "-netdev", f"user,id=net0,hostfwd=tcp::{port}-:80,hostfwd=udp::{port+1}-:7",
        "-kernel", elf,
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Wait for HTTP ready
    for _ in range(40):
        try:
            r = subprocess.run(
                ["curl", "-sf", "--max-time", "2", f"http://localhost:{port}/health"],
                capture_output=True, timeout=5,
            )
            if r.returncode == 0:
                return proc, log
        except Exception:
            pass
        if proc.poll() is not None:
            return None, log
        time.sleep(1)
    return proc, log


def stop_vm(proc, log):
    if proc and proc.poll() is None:
        proc.kill()
        proc.wait()
    try:
        os.unlink(log)
    except OSError:
        pass


def run_wrk(port, endpoint, threads, conns, duration):
    """Run wrk and return (req/s, p50, p99)."""
    try:
        r = subprocess.run(
            ["wrk", f"-t{threads}", f"-c{conns}", f"-d{duration}s",
             "--timeout", "10s", "--latency",
             f"http://localhost:{port}{endpoint}"],
            capture_output=True, text=True, timeout=duration + 15,
        )
        rps = 0.0
        p50 = ""
        p99 = ""
        for line in r.stdout.split("\n"):
            if "Requests/sec" in line:
                rps = float(line.split()[1])
            elif "50%" in line and "%" in line:
                p50 = line.split()[1]
            elif "99%" in line and "%" in line:
                p99 = line.split()[1]
        return rps, p50, p99
    except Exception:
        pass
    return 0.0, "", ""


def run_udp(port, senders, duration):
    """Run UDP echo benchmark, return pkt/s."""
    recv_counts = [0] * senders

    def sender(idx):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.bind(("", 0))
        end = time.monotonic() + duration
        while time.monotonic() < end:
            s.sendto(b"x", ("127.0.0.1", port))
            try:
                s.recvfrom(64)
                recv_counts[idx] += 1
            except socket.timeout:
                pass
        s.close()

    threads = [threading.Thread(target=sender, args=(i,)) for i in range(senders)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return sum(recv_counts) / duration


# Workload definitions
WORKLOADS = [
    {"name": "health_c1",  "type": "tcp", "endpoint": "/health",  "threads": 1, "conns": 1,
     "desc": "HTTP /health, 1 connection (single-flow)"},
    {"name": "health_c8",  "type": "tcp", "endpoint": "/health",  "threads": 2, "conns": 8,
     "desc": "HTTP /health, 8 connections (IO-bound)"},
    {"name": "compute_c1", "type": "tcp", "endpoint": "/compute", "threads": 1, "conns": 1,
     "desc": "HTTP /compute, 1 connection (single-flow)"},
    {"name": "compute_c8", "type": "tcp", "endpoint": "/compute", "threads": 2, "conns": 8,
     "desc": "HTTP /compute, 8 connections (CPU-bound)"},
    {"name": "udp_8s",     "type": "udp", "endpoint": "",         "threads": 0, "conns": 8,
     "desc": "UDP echo, 8 concurrent senders"},
]

CORE_COUNTS = [1, 4]


def main():
    # Kill stale QEMUs
    subprocess.run(["pkill", "-9", "-f", "qemu-system"], capture_output=True)
    time.sleep(2)

    build()

    results = {}   # results[(name, cpus)] = value
    latencies = {} # latencies[(name, cpus)] = (p50, p99)

    for cpus in CORE_COUNTS:
        label = f"{cpus}-core" + (" MTTCG" if cpus > 1 else "")
        print(f"\n==> {label}")

        for w in WORKLOADS:
            name = w["name"]

            # Fresh VM per test to avoid connection state leaking between tests.
            port = next_port()
            proc, log = start_vm(cpus, port)
            if proc is None:
                print(f"    {name:<20s} FAILED (VM didn't start)")
                results[(name, cpus)] = 0
                stop_vm(proc, log)
                time.sleep(2)
                continue

            if w["type"] == "tcp":
                rps, p50, p99 = run_wrk(port, w["endpoint"], w["threads"], w["conns"], DURATION)
                results[(name, cpus)] = rps
                latencies[(name, cpus)] = (p50, p99)
                print(f"    {name:<20s} {rps:>10.0f} req/s  p50={p50}  p99={p99}")
            else:
                result = run_udp(port + 1, w["conns"], DURATION)
                results[(name, cpus)] = result
                latencies[(name, cpus)] = ("", "")
                print(f"    {name:<20s} {result:>10.0f} pkt/s")

            stop_vm(proc, log)
            # Wait for TIME_WAIT sockets to drain (macOS: 2*MSL ≈ 30s default,
            # but we use unique ports per test so this is mainly for port pool).
            wait_port_pool()

    # Summary table
    print()
    print("=" * 74)
    print(f"  Multi-Core Scaling Summary  ({DURATION}s per test, warmup before each)")
    print("=" * 74)

    header = f"  {'Workload':<20s}"
    for cpus in CORE_COUNTS:
        header += f" {'%d-core' % cpus:>12s}"
    header += f" {'Scaling':>10s}"
    print(header)

    sep = f"  {'─' * 20}"
    for _ in CORE_COUNTS:
        sep += f" {'─' * 12}"
    sep += f" {'─' * 10}"
    print(sep)

    base_cpus = CORE_COUNTS[0]
    for w in WORKLOADS:
        name = w["name"]
        unit = "req/s" if w["type"] == "tcp" else "pkt/s"
        row = f"  {name:<20s}"
        for cpus in CORE_COUNTS:
            val = results.get((name, cpus), 0)
            row += f" {val:>10.0f}  "
        # Scaling
        base = results.get((name, base_cpus), 0)
        top = results.get((name, CORE_COUNTS[-1]), 0)
        if base > 0:
            row += f" {top / base:>8.2f}x"
        else:
            row += f" {'N/A':>9s}"
        print(row)

    print("=" * 74)
    print(f"  QEMU: x86_64, MTTCG for multi-core, {DURATION}s per test")
    print(f"  /compute = 100K hash iterations (CPU-bound)")
    print(f"  /health  = static JSON response (IO-bound)")
    print(f"  UDP      = echo server, 8 senders")
    print("=" * 74)


if __name__ == "__main__":
    main()
