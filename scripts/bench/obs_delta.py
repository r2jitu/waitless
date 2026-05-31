#!/usr/bin/env python3
# scripts/bench/obs_delta.py — print the /obs delta between two
# snapshots. Used by `scripts/kvm-iterate.sh` and
# `scripts/c3-bench-once.sh` after a wrk run.
#
# Both scripts run wrk from `kvm-vm` against waitless and snapshot
# `/obs` before + after. They used to embed this script as an
# inline `python3 -` heredoc; extracted to here so the body lives
# in one place.
#
# Usage: obs_delta.py PRE.json POST.json
import json
import sys

if len(sys.argv) != 3:
    print("usage: obs_delta.py PRE.json POST.json", file=sys.stderr)
    sys.exit(2)

with open(sys.argv[1]) as f:
    pre = json.load(f)
with open(sys.argv[2]) as f:
    post = json.load(f)


def _diff_into(p, q, keys=None, prefix=""):
    for k in keys or sorted(set(p.keys()) | set(q.keys())):
        v1, v2 = p.get(k, 0), q.get(k, 0)
        # gve nests its driver counters under nic["counters"]; recurse
        # one level so e.g. tx_ring_full_drops shows up in the delta.
        if isinstance(v2, dict) or isinstance(v1, dict):
            _diff_into(v1 if isinstance(v1, dict) else {},
                       v2 if isinstance(v2, dict) else {}, prefix=k + ".")
        elif isinstance(v2, (int, float)) and isinstance(v1, (int, float)):
            d = v2 - v1
            if d != 0:
                print(f"    {prefix}{k:35s} {v1:>12} -> {v2:>12}  Δ={d:+d}")
        elif isinstance(v2, list) and v2 != v1:
            print(f"    {prefix}{k:35s} {v1} -> {v2}")


def delta_block(name, keys=None):
    print(f"  [{name}]")
    _diff_into(pre.get(name, {}), post.get(name, {}), keys)


delta_block("runtime")
delta_block("tcp")
delta_block("http")
delta_block(
    "nic",
    [
        "rx_frames",
        "tx_packets",
        "tx_bytes",
        "tx_small_full_spins",
        "tx_big_full_returns",
        "num_queue_pairs",
        "rx_max_min_ratio_x100",
        # gve renders DQO/GQI driver counters (tx_ring_full_drops,
        # tx_miss_compl, tx_reinject_compl, …) under this sub-dict.
        "counters",
    ],
)
tp, tq = pre.get("tls", {}), post.get("tls", {})
db = tq.get("encrypt_bytes", 0) - tp.get("encrypt_bytes", 0)
dc = tq.get("encrypt_cycles", 0) - tp.get("encrypt_cycles", 0)
if db > 0:
    print(f"  [tls] encrypt {db} B, {dc} cy, {dc / db:.2f} cy/B")
el_p, el_q = pre.get("event_loop", {}), post.get("event_loop", {})


def ed(f):
    return [b - a for a, b in zip(el_p.get(f, []), el_q.get(f, []))]


busy = ed("core_busy_cycles")
idle = ed("core_idle_cycles")
loops = ed("core_loops")
poll = ed("core_poll_work")
svc = ed("core_service_work")
rt = ed("core_runtime_work")
for i in range(len(busy)):
    tot = busy[i] + idle[i]
    ip = 100 * idle[i] / tot if tot > 0 else 0
    rpl = rt[i] / max(loops[i], 1)
    print(
        f"  c{i}: loops={loops[i]:>9} poll={poll[i]:>7} svc={svc[i]:>7} "
        f"rt={rt[i]:>7} idle={ip:5.1f}% rt/loop={rpl:.4f}"
    )
