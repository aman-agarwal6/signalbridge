"""Draw the continuous-run chart (docs/endurance.svg) from the retained run journals.

Reads only timings and counts from the private run folder; no identifiers, digests or
content reach the chart. Run from the repository root with the project interpreter.
"""

import glob
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from integrations.enterprise.reliability import INTERRUPTIONS  # noqa: E402

RUN = "894fb388a2004b43b6b1643e93342df4"
EVIDENCE = ROOT / "var/enterprise/runs" / RUN / "evidence"
WAZUH_STOP_HOURS = 10.58
OUTPUT = ROOT / "docs/endurance.svg"
LABELS = {
    "workers": "Workers stopped 2 min (processing waits; delivery unaffected)",
    "collector": "Collector stopped 90 s",
    "source_delivery": "Source delivery cut 3 min",
}

W, H = 960, 512
LEFT, RIGHT = 70, 24
TOP_Y, TOP_H = 98, 84
LAG_Y, LAG_H = 228, 200
INK, MUTED, GRID = "#1f2933", "#52606d", "#e4e7eb"
BAR, LINE, SHADE, STOP = "#7b93ad", "#1d4ed8", "#fde68a", "#b42318"


def load():
    source = [json.loads(line) for line in open(EVIDENCE / "reliability-source/source.jsonl")]
    first = {}
    for path in glob.glob(str(EVIDENCE / "reliability-collector/*.jsonl")):
        for line in open(path):
            row = json.loads(line)
            if row["phase"] == "end" and row["result"] in ("accepted", "duplicate"):
                first[row["event_id"]] = min(first.get(row["event_id"], math.inf), row["end_ms"])
    reads = [(row["at_ms"], first[row["event_id"]] - row["at_ms"]) for row in source]
    if len(first) != len(source):
        raise SystemExit("every read must have an accepted delivery")
    return reads


def main():
    reads = load()
    last_ms = max(at for at, _ in reads)
    hours = math.ceil(last_ms / 3_600_000 * 2) / 2
    plot_w = W - LEFT - RIGHT

    def x(ms):
        return LEFT + plot_w * ms / (hours * 3_600_000)

    tens = [0] * (int(hours * 6) + 1)
    worst = {}
    for at, lag in reads:
        tens[at // 600_000] += 1
        minute = at // 60_000
        worst[minute] = max(worst.get(minute, 0), lag)
    p95 = sorted(lag for _, lag in reads)[int(len(reads) * 0.95)]
    windows = [(s, r) for name, s, e, r in INTERRUPTIONS if name in LABELS and e <= last_ms]
    outside = [lag for at, lag in reads if not any(s <= at < r for s, r in windows)]

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
        'font-family="Segoe UI, Helvetica, Arial, sans-serif" role="img" '
        'aria-label="Continuous run: reads per ten minutes and worst delivery delay per minute over 13.5 hours">',
        f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
        f'<text x="{LEFT}" y="26" font-size="17" font-weight="600" fill="{INK}">'
        f"Continuous run: {len(reads):,} reads delivered over {last_ms / 3_600_000:.1f} hours</text>",
        f'<text x="{LEFT}" y="48" font-size="12.5" fill="{MUTED}">'
        f"Delivery delay = source read to accepted by SignalBridge. p95 {p95} ms. The two tall "
        "spikes are planned outages, fully recovered.</text>",
        f'<text x="{LEFT}" y="66" font-size="12.5" fill="{MUTED}">'
        f"Outside the planned windows the worst delay was {max(outside) / 1000:.1f} s "
        f"({sum(1 for lag in outside if lag > 1000) / len(outside):.1%} of reads over 1 s). "
        "Every read was delivered.</text>",
    ]
    # Interruption windows the runner applied, shaded across both panels.
    for name, start, end, _recovery in INTERRUPTIONS:
        if end > last_ms or name not in LABELS:
            continue
        x0, x1 = x(start), max(x(end), x(start) + 3)
        out.append(
            f'<rect x="{x0:.1f}" y="{TOP_Y}" width="{x1 - x0:.1f}" '
            f'height="{LAG_Y + LAG_H - TOP_Y}" fill="{SHADE}"/>'
        )
    # Top panel: reads per ten minutes.
    peak = max(tens)
    out.append(
        f'<text x="{LEFT - 8}" y="{TOP_Y + 4}" font-size="11" fill="{MUTED}" text-anchor="end">{peak}</text>'
    )
    out.append(
        f'<text x="{LEFT - 8}" y="{TOP_Y + TOP_H}" font-size="11" fill="{MUTED}" text-anchor="end">0</text>'
    )
    out.append(
        f'<text x="{LEFT}" y="{TOP_Y - 6}" font-size="12" fill="{INK}">Reads per 10 minutes '
        "(taller bars are the planned one-minute bursts)</text>"
    )
    bar_w = plot_w / len(tens)
    for index, count in enumerate(tens):
        if not count:
            continue
        height = TOP_H * count / peak
        out.append(
            f'<rect x="{LEFT + index * bar_w + 0.5:.1f}" y="{TOP_Y + TOP_H - height:.1f}" '
            f'width="{max(bar_w - 1, 1):.1f}" height="{height:.1f}" fill="{BAR}"/>'
        )
    # Bottom panel: worst delivery delay per minute, log scale.
    low, high = math.log10(50), math.log10(300_000)

    def y(ms):
        value = math.log10(min(max(ms, 50), 300_000))
        return LAG_Y + LAG_H * (1 - (value - low) / (high - low))

    out.append(
        f'<text x="{LEFT}" y="{LAG_Y - 8}" font-size="12" fill="{INK}">'
        "Worst delivery delay per minute (log scale)</text>"
    )
    for ms, label in ((100, "0.1 s"), (1_000, "1 s"), (10_000, "10 s"), (100_000, "100 s")):
        out.append(
            f'<line x1="{LEFT}" x2="{W - RIGHT}" y1="{y(ms):.1f}" y2="{y(ms):.1f}" stroke="{GRID}"/>'
        )
        out.append(
            f'<text x="{LEFT - 8}" y="{y(ms) + 4:.1f}" font-size="11" fill="{MUTED}" '
            f'text-anchor="end">{label}</text>'
        )
    points = " ".join(f"{x(m * 60_000):.1f},{y(lag):.1f}" for m, lag in sorted(worst.items()))
    out.append(f'<polyline points="{points}" fill="none" stroke="{LINE}" stroke-width="1.4"/>')
    # Hour axis.
    base = LAG_Y + LAG_H
    out.append(f'<line x1="{LEFT}" x2="{W - RIGHT}" y1="{base}" y2="{base}" stroke="{MUTED}"/>')
    for hour in range(0, int(hours) + 1):
        out.append(
            f'<text x="{x(hour * 3_600_000):.1f}" y="{base + 16}" font-size="11" fill="{MUTED}" '
            f'text-anchor="middle">{hour}h</text>'
        )
    # Wazuh capture stop marker.
    stop = x(WAZUH_STOP_HOURS * 3_600_000)
    out.append(
        f'<line x1="{stop:.1f}" x2="{stop:.1f}" y1="{TOP_Y}" y2="{base}" stroke="{STOP}" '
        'stroke-dasharray="5 4" stroke-width="1.5"/>'
    )
    for offset, text in enumerate(("Wazuh capture stopped", "(log-folder limit, since fixed)")):
        out.append(
            f'<text x="{stop + 6:.1f}" y="{LAG_Y + 14 + offset * 14}" font-size="11.5" '
            f'fill="{STOP}">{text}</text>'
        )
    # Window labels under the axis.
    row = 0
    for name, start, end, _recovery in INTERRUPTIONS:
        if end > last_ms or name not in LABELS:
            continue
        out.append(
            f'<text x="{x(start) + 4:.1f}" y="{base + 34 + row * 14}" font-size="11" fill="{INK}">'
            f"▲ {LABELS[name]}</text>"
        )
        row += 1
    out.append("</svg>")
    OUTPUT.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    print("wrote", OUTPUT.relative_to(ROOT), "reads", len(reads), "p95_ms", p95)


if __name__ == "__main__":
    main()
