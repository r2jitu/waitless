#!/usr/bin/env python3
# h2_profile.py — drive the `loadgen http` workload at a server and
# derive per-request work + (for h2) per-phase CPU from the server's
# /obs deltas. The reusable home for the ad-hoc measurement scripts the
# h2-perf session kept rebuilding in /tmp.
#
# Runs wherever it can reach the server's https port AND run the
# loadgen binary — on `kvm-vm` against a deployed GCE unikernel (driven
# by `gce-h2-bench.sh`), or locally against an HVF VM. The metrics it
# prints are the ones that *don't* lie under HVF's proxy/spin noise
# (sends/req, TLS-records/req, allocs/req are exact counters; busy_cyc
# and throughput are only trustworthy on GCE / real NIC — see
# `feedback_gce_first_iteration`).
#
# Usage:
#   h2_profile.py <host> [--proto h1|h2|h3] [--port 443] [--endpoint /health]
#                 [--conns 25] [--streams 16] [--duration 6] [--warmup 1]
#
# Env: LOADGEN overrides the binary path (default: the kvm-vm deploy
# path, falling back to the in-repo release build).

import argparse, json, os, ssl, subprocess, sys, time, urllib.request

BLOCK = {"h1": "http", "h2": "http2", "h3": "http3"}


def loadgen_bin():
    if os.environ.get("LOADGEN"):
        return os.environ["LOADGEN"]
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (
        os.path.expanduser("~/bench/bench/loadgen/target/release/loadgen"),
        os.path.join(here, "loadgen", "target", "release", "loadgen"),
    ):
        if os.path.exists(p):
            return p
    return "loadgen"


def obs(host, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    last = None
    for _ in range(10):
        try:
            with urllib.request.urlopen(
                f"https://{host}:{port}/obs", timeout=8, context=ctx
            ) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001 - transient under load; retry
            last = e
            time.sleep(0.3)
    raise last


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--proto", default="h2", choices=["h1", "h2", "h3"])
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--endpoint", default="/health")
    ap.add_argument("--conns", type=int, default=25)
    ap.add_argument("--streams", type=int, default=16)
    ap.add_argument("--duration", type=int, default=6)
    ap.add_argument("--warmup", type=int, default=1)
    a = ap.parse_args()

    pre = obs(a.host, a.port)
    cmd = [
        loadgen_bin(), "http", "--proto", a.proto, "--host", a.host,
        "--port", str(a.port), "--endpoint", a.endpoint,
        "--connections", str(a.conns), "--streams", str(a.streams),
        "--duration-secs", str(a.duration), "--warmup-secs", str(a.warmup),
    ]
    out = subprocess.run(cmd, capture_output=True, text=True)
    post = obs(a.host, a.port)

    rps = p50 = p99 = "?"
    for line in out.stdout.splitlines():
        if line.startswith("RPS "):
            rps = line[4:]
        elif line.startswith("P50_US "):
            p50 = line[7:]
        elif line.startswith("P99_US "):
            p99 = line[7:]
    for line in out.stderr.strip().splitlines()[:3]:
        print("  [loadgen]", line)

    def d(block, key):
        return post.get(block, {}).get(key, 0) - pre.get(block, {}).get(key, 0)

    block = BLOCK[a.proto]
    reqs = d(block, "responses_sent")
    el, pr = post.get("event_loop", {}), pre.get("event_loop", {})
    cpu = el.get("cycles_per_us", 1) or 1
    busy = sum(b - z for z, b in zip(pr.get("core_busy_cycles", []), el.get("core_busy_cycles", [])))
    idle = sum(b - z for z, b in zip(pr.get("core_idle_cycles", []), el.get("core_idle_cycles", [])))
    tot = busy + idle
    per = (lambda x: x / reqs) if reqs else (lambda x: 0.0)

    print(f"== {a.proto} {a.endpoint}  c{a.conns} s{a.streams}  cpu={cpu}cyc/us ==")
    print(f"  RPS {rps}   p50 {p50}us   p99 {p99}us   reqs {reqs}")
    # Exact, contention-immune counters (trustworthy even on HVF):
    print(f"  sends/req     {per(d('tcp', 'send_calls')):.3f}")
    print(f"  tls_recs/req  {per(d('tls', 'encrypt_records')):.3f}")
    print(f"  allocs/req    {per(d('kernel', 'heap_total_allocation_count')):.3f}")
    print(f"  enc_bytes/req {per(d('tls', 'encrypt_bytes')):.0f}")
    # CPU — only meaningful on GCE / real NIC (idle~0 = truly saturated):
    print(f"  busy_cyc/req  {per(busy):.0f}  ({per(busy) / cpu:.2f} us)   idle% {100.0 * idle / tot if tot else 0:.1f}")
    if a.proto == "h2":
        for k in ("decode_cycles", "encode_cycles", "frame_cycles"):
            v = per(d("http2", k))
            print(f"    {k:14s} {v:8.0f} cyc/req  ({v / cpu:6.2f} us)")
    # Sanity: a healthy run drops nothing.
    print(f"  errs: frame {d('http2', 'frame_error')}  flow {d('http2', 'flow_control_error')}  "
          f"goaway {d('http2', 'goaway_sent')}  rst {d('tcp', 'rst_sent')}")


if __name__ == "__main__":
    main()
