#!/usr/bin/env python3
"""Render docs/assets/benchmark.svg from conn-sweep JSONL files.

Reads one JSONL per server (produced by scripts/bench/conn-sweep.sh) and
draws the throughput-vs-concurrency curve plus a p99 panel, in the same
visual language as the previous hand-written bar chart (white bg, green
Waitless, gray peer).

Usage:
    chart_sweep.py --waitless /tmp/sweep-waitless.jsonl \
                   --peer /tmp/sweep-tokio.jsonl --peer-name tokio-hyper \
                   --out docs/assets/benchmark.svg
"""

import argparse
import json
import math

GREEN = "#1f7a4d"
GRAY = "#9aa0ae"
GRAY_TEXT = "#5a5a72"
DARK = "#1a1a2e"
AXIS = "#3a3a4a"
GRID = "#e5e5ec"


def parse_latency(s):
    """wrk latency string ('283.00us', '1.09ms', '4.7s') -> milliseconds."""
    s = (s or "").strip()
    if not s:
        return None
    for suffix, mult in (("us", 1e-3), ("ms", 1.0), ("s", 1e3), ("m", 6e4)):
        if s.endswith(suffix) and s[: -len(suffix)].replace(".", "").isdigit():
            return float(s[: -len(suffix)]) * mult
    return None


def load(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            # wrk prints 0.00us when no requests completed — treat as missing.
            p99s = [parse_latency(r.get("p99_1")), parse_latency(r.get("p99_2"))]
            p99s = [x for x in p99s if x is not None and x > 0]
            p50s = [parse_latency(r.get("p50_1")), parse_latency(r.get("p50_2"))]
            p50s = [x for x in p50s if x is not None and x > 0]
            rows.append(
                {
                    "conns": r["conns"],
                    "rps": float(r["rps"]),
                    "p99": max(p99s) if p99s else None,
                    "p50": max(p50s) if p50s else None,
                }
            )
    return sorted(rows, key=lambda r: r["conns"])


def xmap(conns, x0, x1, c0, c1):
    """log-scale x position."""
    t = (math.log(conns) - math.log(c0)) / (math.log(c1) - math.log(c0))
    return x0 + t * (x1 - x0)


def polyline(rows, key, x0, x1, c0, c1, y_of, fmt="%.6g"):
    pts = []
    for r in rows:
        v = r[key]
        if v is None:
            continue
        pts.append((xmap(r["conns"], x0, x1, c0, c1), y_of(v)))
    return " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)


def fmt_rps(v):
    return f"{v / 1e6:.2f}M" if v >= 1e6 else f"{v / 1e3:.0f}K"


def fmt_ms(v):
    if v < 1:
        return f"{v * 1000:.0f}µs"
    if v < 1000:
        return f"{v:.3g}ms" if v < 10 else f"{v:.0f}ms"
    return f"{v / 1000:.3g}s"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--waitless", required=True)
    ap.add_argument("--peer", required=True)
    ap.add_argument("--peer-name", default="tokio-hyper")
    ap.add_argument("--out", default="docs/assets/benchmark.svg")
    ap.add_argument("--title", default="HTTPS throughput vs. concurrent connections — one 8-vCPU GCE c3 VM")
    ap.add_argument(
        "--subtitle",
        default="Byte-identical /health over TLS 1.3, same gVNIC, same two load generators, measured back-to-back.",
    )
    ap.add_argument("--footnote", action="append", default=[])
    args = ap.parse_args()

    wl = load(args.waitless)
    pr = load(args.peer)
    allrows = wl + pr

    c0 = min(r["conns"] for r in allrows)
    c1 = max(r["conns"] for r in allrows)
    rps_max = max(r["rps"] for r in allrows)
    ymax = math.ceil(rps_max / 250_000) * 250_000

    W, H = 900, 560
    # throughput panel
    TX0, TX1, TY0, TY1 = 90, 850, 100, 320
    # p99 panel
    LX0, LX1, LY0, LY1 = 90, 850, 380, 490

    def ty(v):  # rps -> y
        return TY1 - (v / ymax) * (TY1 - TY0)

    p50s_all = [r["p50"] for r in allrows if r["p50"] is not None]
    lmin = min(p50s_all) * 0.8
    lmax = max(p50s_all) * 1.3

    def ly(v):  # latency ms -> y (log)
        t = (math.log(v) - math.log(lmin)) / (math.log(lmax) - math.log(lmin))
        return LY1 - t * (LY1 - LY0)

    s = []
    s.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
        f"font-family=\"-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif\">"
    )
    s.append(f'<rect width="{W}" height="{H}" fill="#ffffff"/>')
    s.append(f'<text x="40" y="40" font-size="20" font-weight="700" fill="{DARK}">{args.title}</text>')
    s.append(f'<text x="40" y="63" font-size="13" fill="{GRAY_TEXT}">{args.subtitle}</text>')

    # ── throughput panel ──
    # y grid + labels
    step = 250_000
    v = 0
    while v <= ymax:
        y = ty(v)
        s.append(f'<line x1="{TX0}" y1="{y:.1f}" x2="{TX1}" y2="{y:.1f}" stroke="{GRID}" stroke-width="1"/>')
        s.append(
            f'<text x="{TX0 - 8}" y="{y + 4:.1f}" text-anchor="end" font-size="12" fill="{GRAY_TEXT}">{fmt_rps(v) if v else "0"}</text>'
        )
        v += step
    s.append(
        f'<text x="40" y="{TY0 - 12}" font-size="13" font-weight="700" fill="{AXIS}">Requests / second (higher is better)</text>'
    )

    # x ticks at the measured conn counts (subset to avoid clutter)
    ticks = sorted({r["conns"] for r in allrows})
    shown = [t for t in ticks if t in (1000, 2000, 4000, 8000, 16000, 32000, 50000, 80000)] or ticks
    for t in shown:
        x = xmap(t, TX0, TX1, c0, c1)
        label = f"{t // 1000}K"
        s.append(f'<line x1="{x:.1f}" y1="{TY1}" x2="{x:.1f}" y2="{TY1 + 5}" stroke="{AXIS}" stroke-width="1"/>')
        s.append(f'<text x="{x:.1f}" y="{TY1 + 20}" text-anchor="middle" font-size="12" fill="{GRAY_TEXT}">{label}</text>')
        # mirror ticks on latency panel
        s.append(f'<line x1="{x:.1f}" y1="{LY1}" x2="{x:.1f}" y2="{LY1 + 5}" stroke="{AXIS}" stroke-width="1"/>')
        s.append(f'<text x="{x:.1f}" y="{LY1 + 20}" text-anchor="middle" font-size="12" fill="{GRAY_TEXT}">{label}</text>')

    # curves
    for rows, color, width in ((pr, GRAY, 2.5), (wl, GREEN, 3.5)):
        pts = polyline(rows, "rps", TX0, TX1, c0, c1, ty)
        s.append(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="{width}" stroke-linejoin="round"/>')
        for r in rows:
            x = xmap(r["conns"], TX0, TX1, c0, c1)
            s.append(f'<circle cx="{x:.1f}" cy="{ty(r["rps"]):.1f}" r="3.5" fill="{color}"/>')

    # legend (top-right of the throughput panel)
    lx = TX1 - 170
    ly0 = TY0 + 10
    s.append(f'<line x1="{lx}" y1="{ly0}" x2="{lx + 28}" y2="{ly0}" stroke="{GREEN}" stroke-width="3.5"/>')
    s.append(f'<text x="{lx + 36}" y="{ly0 + 4}" font-size="13" font-weight="700" fill="{GREEN}">Waitless</text>')
    s.append(f'<line x1="{lx}" y1="{ly0 + 22}" x2="{lx + 28}" y2="{ly0 + 22}" stroke="{GRAY}" stroke-width="2.5"/>')
    s.append(f'<text x="{lx + 36}" y="{ly0 + 26}" font-size="13" font-weight="700" fill="{GRAY_TEXT}">{args.peer_name}</text>')

    # ── p99 panel ──
    s.append(
        f'<text x="40" y="{LY0 - 12}" font-size="13" font-weight="700" fill="{AXIS}">Median latency, log scale (lower is better)</text>'
    )
    for v in (1, 10, 100, 1000, 10000):
        if lmin <= v <= lmax:
            y = ly(v)
            s.append(f'<line x1="{LX0}" y1="{y:.1f}" x2="{LX1}" y2="{y:.1f}" stroke="{GRID}" stroke-width="1"/>')
            s.append(
                f'<text x="{LX0 - 8}" y="{y + 4:.1f}" text-anchor="end" font-size="12" fill="{GRAY_TEXT}">{fmt_ms(v)}</text>'
            )
    for rows, color, width in ((pr, GRAY, 2.5), (wl, GREEN, 3.5)):
        pts = polyline(rows, "p50", LX0, LX1, c0, c1, ly)
        s.append(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="{width}" stroke-linejoin="round"/>')
        for r in rows:
            if r["p50"] is None:
                continue
            x = xmap(r["conns"], LX0, LX1, c0, c1)
            s.append(f'<circle cx="{x:.1f}" cy="{ly(r["p50"]):.1f}" r="3" fill="{color}"/>')

    s.append(
        f'<text x="{(TX0 + TX1) / 2}" y="{LY1 + 42}" text-anchor="middle" font-size="13" fill="{AXIS}">concurrent connections (log scale)</text>'
    )

    for i, fn in enumerate(args.footnote):
        s.append(f'<text x="40" y="{LY1 + 70 + i * 18}" font-size="12" fill="{GRAY_TEXT}">{fn}</text>')

    s.append("</svg>")
    with open(args.out, "w") as f:
        f.write("\n".join(s) + "\n")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
