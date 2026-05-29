#!/usr/bin/env python3
# Per-request CPU decomposition from two /obs snapshots (PRE, POST).
# Pairs with the per-stage cycle brackets in the runtime/http/tls/tcp
# diag blocks. On x86 (GCE) the cycle fields are real TSC cycles; on
# arm64 native they are 24 MHz timer ticks (ratios only).
import json
import sys


def load(p):
    return json.load(open(p))


def d(pre, post, block, key, default=0):
    return post.get(block, {}).get(key, default) - pre.get(block, {}).get(key, default)


def dsum(pre, post, block, key):
    a = pre.get(block, {}).get(key, []) or []
    b = post.get(block, {}).get(key, []) or []
    return sum(b) - sum(a)


def main():
    if len(sys.argv) != 4:
        print("usage: profile_obs.py LABEL PRE.json POST.json", file=sys.stderr)
        sys.exit(2)
    label, pre, post = sys.argv[1], load(sys.argv[2]), load(sys.argv[3])

    reqs = d(pre, post, "http", "requests_parsed")
    if reqs <= 0:
        print(f"[{label}] no requests in window (reqs={reqs})", file=sys.stderr)
        sys.exit(1)

    busy = dsum(pre, post, "event_loop", "core_busy_cycles")
    idle = dsum(pre, post, "event_loop", "core_idle_cycles")
    cyc_per_us = post.get("event_loop", {}).get("cycles_per_us", 0)

    runtime = d(pre, post, "runtime", "runtime_cycles")
    polls = dsum(pre, post, "runtime", "tasks_polled_per_worker")

    rx = d(pre, post, "tcp", "rx_cycles")
    tick = d(pre, post, "tcp", "tick_cycles")

    enc = d(pre, post, "tls", "encrypt_cycles")
    dec = d(pre, post, "tls", "decrypt_cycles")
    tls = enc + dec

    parse = d(pre, post, "http", "parse_cycles")
    hand = d(pre, post, "http", "handler_cycles")
    build = d(pre, post, "http", "build_cycles")
    http = parse + hand + build

    net = busy - runtime               # NIC driver + tcp_receive + flush + drain
    nic_drv = net - rx - tick          # net minus measured tcp stack
    serve_resid = runtime - tls - http # recv-plumbing + send + async dispatch

    def per(x):
        return x / reqs

    def ns(x):
        return (x / reqs) / cyc_per_us * 1000 if cyc_per_us else 0

    def pct(x):
        return 100 * x / busy if busy else 0

    print(f"==== [{label}] {reqs:,} requests   polls/req={polls/reqs:.3f}"
          f"   cyc/us={cyc_per_us} ====")
    print(f"  TOTAL busy        {per(busy):>10.0f} cy/req  {ns(busy):>8.0f} ns/req  100.0%"
          f"   (idle {100*idle/(busy+idle) if busy+idle else 0:.0f}%)")
    print(f"  ── NET path       {per(net):>10.0f} cy/req  {ns(net):>8.0f} ns/req  {pct(net):5.1f}%")
    print(f"       tcp_receive  {per(rx):>10.0f} cy/req  {ns(rx):>8.0f} ns/req  {pct(rx):5.1f}%")
    print(f"       tcp_tick     {per(tick):>10.0f} cy/req  {ns(tick):>8.0f} ns/req  {pct(tick):5.1f}%")
    print(f"       NIC driver*  {per(nic_drv):>10.0f} cy/req  {ns(nic_drv):>8.0f} ns/req  {pct(nic_drv):5.1f}%  (net-rx-tick: NIC RX/TX poll+flush)")
    print(f"  ── SERVE (runtime){per(runtime):>10.0f} cy/req  {ns(runtime):>8.0f} ns/req  {pct(runtime):5.1f}%")
    print(f"       tls_encrypt  {per(enc):>10.0f} cy/req  {ns(enc):>8.0f} ns/req  {pct(enc):5.1f}%")
    print(f"       tls_decrypt  {per(dec):>10.0f} cy/req  {ns(dec):>8.0f} ns/req  {pct(dec):5.1f}%")
    print(f"       http_parse   {per(parse):>10.0f} cy/req  {ns(parse):>8.0f} ns/req  {pct(parse):5.1f}%")
    print(f"       http_handler {per(hand):>10.0f} cy/req  {ns(hand):>8.0f} ns/req  {pct(hand):5.1f}%")
    print(f"       http_build   {per(build):>10.0f} cy/req  {ns(build):>8.0f} ns/req  {pct(build):5.1f}%")
    print(f"       serve resid* {per(serve_resid):>10.0f} cy/req  {ns(serve_resid):>8.0f} ns/req  {pct(serve_resid):5.1f}%  (recv-plumbing + send + async dispatch)")


if __name__ == "__main__":
    main()
