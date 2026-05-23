#!/usr/bin/env python3
"""chart-pareto.py — Render the Pareto + supporting charts from the
JSONL output of `pareto-bench.sh`.

Inputs:  one or more *.jsonl files (rows from pareto-bench.sh).
Outputs: PNGs into the chart-results/ directory next to the inputs:
   * pareto.png         — $/M reqs vs throughput, one line per (peer,
                          workload). Lower-right is better.
   * p99-vs-conns.png   — p99 latency vs concurrency, one line per
                          (peer, workload). Flat is better.
   * rps-vs-conns.png   — rps vs concurrency, supporting view.

Usage:
   ./chart-pareto.py bench-results/*.jsonl
   ./chart-pareto.py bench-results/sanity-*.jsonl --out-dir charts/

This script intentionally embeds GCE spot pricing inline (with an
"as of" date) rather than depending on the gcloud SDK or pricing API
at chart-render time. Update the table when re-running for a new
deck.
"""

import argparse
import json
import os
import sys
from collections import defaultdict


# GCE spot pricing in us-west1, $/hour. As of 2026-05; verify with
# `gcloud compute machine-types describe ... --zone=us-west1-c` and
# the GCE pricing page before quoting these in a deck.
SPOT_HOURLY = {
    "c3-highcpu-4": 0.05,
    "c3-highcpu-8": 0.10,
    "c3-highcpu-22": 0.29,
    "c3-highcpu-44": 0.58,
    # n2 / e2 fallbacks in case the iteration sweep ran on cheap shapes.
    "n2-highcpu-2": 0.02,
    "n2-highcpu-4": 0.04,
    "n2-highcpu-8": 0.07,
    "e2-standard-2": 0.02,
    "e2-standard-4": 0.04,
}


# Peer rendering order + colors. Stable across charts so the legend
# colors match across the three output PNGs.
PEER_ORDER = ["waitless", "tokio-hyper", "nginx"]
PEER_COLOR = {
    "waitless": "tab:blue",
    "tokio-hyper": "tab:green",
    "nginx": "tab:orange",
}
WORKLOAD_MARKER = {
    "health": "o",
    "health-tls": "o",
    "static64k": "s",
    "static64k-tls": "s",
}


def cost_per_million_reqs(rps, machine):
    """$/M requests at sustained `rps` on `machine`. Returns None if
    rps is zero or the machine isn't priced in our table."""
    if rps <= 0:
        return None
    if machine not in SPOT_HOURLY:
        return None
    hourly = SPOT_HOURLY[machine]
    # $/sec = hourly / 3600; $/req = $/sec / rps; per million scale.
    return (hourly / 3600.0) / rps * 1e6


def load_jsonl_files(paths):
    """Read every JSONL row from `paths`. Skips blank lines and
    rows that fail to parse (with a stderr warning)."""
    rows = []
    for path in paths:
        with open(path) as f:
            for ln, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(
                        f"warning: {path}:{ln}: invalid JSON ({e}); skipping",
                        file=sys.stderr,
                    )
    return rows


def group_rows(rows):
    """Group rows by (peer, workload). Returns
       { (peer, workload): [row, row, ...] }
    sorted within each group by conns ascending."""
    groups = defaultdict(list)
    for r in rows:
        peer = r.get("peer", "?")
        workload = r.get("workload", "?")
        groups[(peer, workload)].append(r)
    for k in groups:
        groups[k].sort(key=lambda r: r.get("conns", 0))
    return groups


def render_pareto(groups, out_path):
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(10, 6))
    # x = throughput, y = $/M reqs. Lower-right = better (more rps,
    # cheaper per request).
    for (peer, workload), rows in sorted(
        groups.items(), key=lambda kv: (PEER_ORDER.index(kv[0][0]) if kv[0][0] in PEER_ORDER else 99, kv[0][1])
    ):
        xs, ys, labels = [], [], []
        for r in rows:
            machine = r.get("machine", "")
            cpm = cost_per_million_reqs(r.get("rps", 0), machine)
            if cpm is None:
                continue
            xs.append(r["rps"])
            ys.append(cpm)
            labels.append(str(r.get("conns", "?")))
        if not xs:
            continue
        color = PEER_COLOR.get(peer, "gray")
        marker = WORKLOAD_MARKER.get(workload, "x")
        ax.plot(
            xs, ys,
            marker=marker, markersize=8, linewidth=1.5,
            color=color, label=f"{peer} ({workload})",
        )
        for x, y, lab in zip(xs, ys, labels):
            ax.annotate(lab, xy=(x, y), xytext=(4, 4),
                        textcoords="offset points", fontsize=8, color=color)

    ax.set_xlabel("Throughput (req/s)")
    ax.set_ylabel("$/million requests (GCE spot, us-west1)")
    ax.set_title("Pareto frontier — peer cost-efficiency at fixed machine size\n"
                 "(point labels = concurrent connections; lower-right is better)")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(True, which="both", linestyle=":", alpha=0.5)
    ax.legend(loc="best", fontsize=9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"wrote {out_path}")


def render_p99_vs_conns(groups, out_path):
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(10, 6))
    for (peer, workload), rows in sorted(
        groups.items(), key=lambda kv: (PEER_ORDER.index(kv[0][0]) if kv[0][0] in PEER_ORDER else 99, kv[0][1])
    ):
        xs = [r.get("conns", 0) for r in rows]
        ys = [r.get("p99_us", 0) / 1000.0 for r in rows]  # convert to ms
        color = PEER_COLOR.get(peer, "gray")
        marker = WORKLOAD_MARKER.get(workload, "x")
        ax.plot(xs, ys, marker=marker, markersize=8, linewidth=1.5,
                color=color, label=f"{peer} ({workload})")

    ax.set_xlabel("Concurrent connections")
    ax.set_ylabel("p99 latency (ms)")
    ax.set_title("Tail latency vs concurrency — flat is better")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(True, which="both", linestyle=":", alpha=0.5)
    ax.legend(loc="best", fontsize=9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"wrote {out_path}")


def render_rps_vs_conns(groups, out_path):
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(10, 6))
    for (peer, workload), rows in sorted(
        groups.items(), key=lambda kv: (PEER_ORDER.index(kv[0][0]) if kv[0][0] in PEER_ORDER else 99, kv[0][1])
    ):
        xs = [r.get("conns", 0) for r in rows]
        ys = [r.get("rps", 0) for r in rows]
        color = PEER_COLOR.get(peer, "gray")
        marker = WORKLOAD_MARKER.get(workload, "x")
        ax.plot(xs, ys, marker=marker, markersize=8, linewidth=1.5,
                color=color, label=f"{peer} ({workload})")

    ax.set_xlabel("Concurrent connections")
    ax.set_ylabel("Throughput (req/s)")
    ax.set_title("Throughput vs concurrency")
    ax.set_xscale("log")
    ax.grid(True, which="both", linestyle=":", alpha=0.5)
    ax.legend(loc="best", fontsize=9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"wrote {out_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", nargs="+", help="JSONL file(s) from pareto-bench.sh")
    parser.add_argument("--out-dir", default=None,
                        help="Output directory (default: alongside first input)")
    args = parser.parse_args()

    rows = load_jsonl_files(args.jsonl)
    if not rows:
        print("no rows loaded; nothing to chart", file=sys.stderr)
        sys.exit(1)
    groups = group_rows(rows)

    out_dir = args.out_dir or os.path.dirname(os.path.abspath(args.jsonl[0]))
    os.makedirs(out_dir, exist_ok=True)

    render_pareto(groups, os.path.join(out_dir, "pareto.png"))
    render_p99_vs_conns(groups, os.path.join(out_dir, "p99-vs-conns.png"))
    render_rps_vs_conns(groups, os.path.join(out_dir, "rps-vs-conns.png"))

    print()
    print("==> Summary (rows loaded, by peer × workload):")
    for (peer, workload), rs in sorted(groups.items()):
        print(f"    {peer:<12s} {workload:<14s} {len(rs)} cells")


if __name__ == "__main__":
    main()
