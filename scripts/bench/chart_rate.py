#!/usr/bin/env python3
"""Render the open-loop latency-under-load chart from rate-sweep JSONL.

Input rows (one per offered rate, from the http-rate workload driven by
two loadgens): {"rate": N, "achieved": N, "p99_us": [lg1, lg2], ...}.
p99 plotted as the max across loadgens (conservative). Rates where the
server fell behind (achieved < 97 % of offered) are drawn with hollow
markers — the latency there is backlog, not service time.

Usage:
    chart_rate.py --series label=path.jsonl ... --out docs/assets/latency-under-load.svg
"""

import argparse
import json
import math

COLORS = ["#1f7a4d", "#6aa84f", "#9aa0ae", "#c27ba0"]
GRAY_TEXT = "#5a5a72"
DARK = "#1a1a2e"
AXIS = "#3a3a4a"
GRID = "#e5e5ec"


def load(path):
    rows = []
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            rows.append(
                {
                    "rate": r["rate"],
                    "achieved": r["achieved"],
                    "p99_ms": max(r["p99_us"]) / 1000.0,
                    "met": r["achieved"] >= 0.97 * r["rate"],
                }
            )
    return sorted(rows, key=lambda r: r["rate"])


def fmt_ms(v):
    if v < 1:
        return f"{v * 1000:.0f}µs"
    if v < 1000:
        return f"{v:.0f}ms"
    return f"{v / 1000:.0f}s"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--series", action="append", required=True, help="label=path.jsonl")
    ap.add_argument("--out", required=True)
    ap.add_argument("--title", default="Tail latency vs. offered load — open-loop (wrk2-style), HTTPS /health")
    ap.add_argument(
        "--subtitle",
        default="Fixed-rate schedule over 4,000 keep-alive TLS conns from two load generators; latency measured from each request's scheduled time (coordinated-omission-corrected). p99 shown.",
    )
    ap.add_argument("--footnote", action="append", default=[])
    args = ap.parse_args()

    series = []
    for s in args.series:
        label, path = s.split("=", 1)
        series.append((label, load(path)))

    rmax = max(r["rate"] for _, rows in series for r in rows) * 1.05
    lmin = 1.0  # 1 ms floor for the log axis
    lmax = max(r["p99_ms"] for _, rows in series for r in rows) * 1.5

    sub_lines = None  # computed after wrap() is defined; see below
    W = 900
    X0, X1 = 90, 850

    def xmap(rate):
        return X0 + (rate / rmax) * (X1 - X0)

    def ymap(ms):
        t = (math.log(max(ms, lmin)) - math.log(lmin)) / (math.log(lmax) - math.log(lmin))
        return Y1 - t * (Y1 - Y0)

    def wrap(text, width=128):
        lines, cur = [], ""
        for w in text.split():
            cand = f"{cur} {w}".strip()
            if len(cand) > width and cur:
                lines.append(cur)
                cur = w
            else:
                cur = cand
        if cur:
            lines.append(cur)
        return lines

    foot_lines = [ln for fn in args.footnote for ln in wrap(fn)]
    sub_lines = wrap(args.subtitle, 130)
    # Panel top clears however many lines the subtitle wrapped to —
    # the first render overlapped the axis label on a 2-line subtitle.
    Y0 = 78 + len(sub_lines) * 17 + 30
    Y1 = Y0 + 280
    H = Y1 + 64 + len(foot_lines) * 18 + 14

    s = []
    s.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
        f"font-family=\"-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif\">"
    )
    s.append(f'<rect width="{W}" height="{H}" fill="#ffffff"/>')
    s.append(f'<text x="40" y="40" font-size="20" font-weight="700" fill="{DARK}">{args.title}</text>')
    for i, ln in enumerate(sub_lines):
        s.append(f'<text x="40" y="{63 + i * 17}" font-size="13" fill="{GRAY_TEXT}">{ln}</text>')

    # y grid (log decades)
    v = lmin
    while v <= lmax:
        y = ymap(v)
        s.append(f'<line x1="{X0}" y1="{y:.1f}" x2="{X1}" y2="{y:.1f}" stroke="{GRID}"/>')
        s.append(f'<text x="{X0 - 8}" y="{y + 4:.1f}" text-anchor="end" font-size="12" fill="{GRAY_TEXT}">{fmt_ms(v)}</text>')
        v *= 10
    # x ticks every 100K
    t = 100_000
    while t < rmax:
        x = xmap(t)
        s.append(f'<line x1="{x:.1f}" y1="{Y1}" x2="{x:.1f}" y2="{Y1 + 5}" stroke="{AXIS}"/>')
        s.append(f'<text x="{x:.1f}" y="{Y1 + 20}" text-anchor="middle" font-size="12" fill="{GRAY_TEXT}">{t // 1000}K</text>')
        t += 100_000
    s.append(f'<text x="{(X0 + X1) / 2}" y="{Y1 + 42}" text-anchor="middle" font-size="13" fill="{AXIS}">offered load (requests / second)</text>')
    s.append(f'<text x="40" y="{Y0 - 12}" font-size="13" font-weight="700" fill="{AXIS}">p99 latency, log scale (lower is better)</text>')

    for i, (label, rows) in enumerate(series):
        color = COLORS[i % len(COLORS)]
        width = 3.5 if i == 0 else 2.5
        pts = " ".join(f"{xmap(r['rate']):.1f},{ymap(r['p99_ms']):.1f}" for r in rows)
        s.append(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="{width}" stroke-linejoin="round"/>')
        for r in rows:
            x, y = xmap(r["rate"]), ymap(r["p99_ms"])
            if r["met"]:
                s.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="{color}"/>')
            else:
                s.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="#ffffff" stroke="{color}" stroke-width="2"/>')
        # legend
        ly = Y0 + 10 + i * 22
        s.append(f'<line x1="{X0 + 16}" y1="{ly}" x2="{X0 + 44}" y2="{ly}" stroke="{color}" stroke-width="{width}"/>')
        s.append(f'<text x="{X0 + 52}" y="{ly + 4}" font-size="13" font-weight="700" fill="{color}">{label}</text>')

    s.append(
        f'<text x="{X1 - 4}" y="{Y0 + 10}" text-anchor="end" font-size="12" fill="{GRAY_TEXT}">hollow markers = offered rate not met (backlogged)</text>'
    )
    for i, fn in enumerate(foot_lines):
        s.append(f'<text x="40" y="{Y1 + 64 + i * 18}" font-size="12" fill="{GRAY_TEXT}">{fn}</text>')
    s.append("</svg>")
    with open(args.out, "w") as f:
        f.write("\n".join(s) + "\n")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
