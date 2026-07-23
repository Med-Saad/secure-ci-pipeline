#!/usr/bin/env python3
"""Render the triage funnel as a dependency-free, theme-aware SVG.

A funnel is one series of descending magnitude, so: horizontal bars, a single
sequential blue hue (light->dark as the count shrinks), no legend (the title
names the series), every bar directly labelled with its count and share of raw.
Labels sit in theme ink (not on the fills) so contrast holds in light and dark.

Kept in pure Python/SVG on purpose — this repo is dependency-free, and an SVG the
README can inline beats a committed PNG binary.
"""

from __future__ import annotations

from pathlib import Path

# Human labels for the stage keys emitted by build_evidence / the gate.
STAGE_LABELS = {
    "raw": "Raw findings",
    "after_scoping": "After scoping (first-party SAST)",
    "gated": "Gated layers (image-lang set aside)",
    "after_suppression": "After suppression (build-only)",
    "meets_policy": "Meets policy (floor / KEV / EPSS)",
    "blocking": "Blocking",
}

# Single-hue sequential blue ramp, light -> dark, 6 steps.
RAMP = ["#c6dbef", "#9ecae1", "#6baed6", "#4292c6", "#2171b5", "#08519c"]


def render_svg(funnel: list[tuple[str, int]], out_path: str | Path, title: str = "") -> None:
    W, pad_l, pad_r, pad_t, pad_b = 900, 300, 90, 60, 30
    row_h, gap = 46, 12
    n = len(funnel)
    H = pad_t + n * row_h + (n - 1) * gap + pad_b
    raw = max((c for _, c in funnel), default=1) or 1
    bar_max = W - pad_l - pad_r

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
        f'font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" '
        f'role="img" aria-label="{_esc(title)}">',
        # theme-aware ink: dark ink on light, light ink on dark
        '<style>'
        ':root{--ink:#1a1a1a;--muted:#666;--track:#e8e8ec}'
        '@media (prefers-color-scheme:dark){:root{--ink:#e8e8e8;--muted:#9aa0a6;--track:#2a2d31}}'
        '.ink{fill:var(--ink)}.muted{fill:var(--muted)}.track{fill:var(--track)}'
        '</style>',
    ]
    if title:
        parts.append(
            f'<text x="{pad_l}" y="34" class="ink" font-size="19" '
            f'font-weight="600">{_esc(title)}</text>'
        )

    for i, (key, count) in enumerate(funnel):
        y = pad_t + i * (row_h + gap)
        w = max(3, round(bar_max * count / raw))
        color = RAMP[min(i, len(RAMP) - 1)]
        label = STAGE_LABELS.get(key, key)
        pct = f"{100 * count / raw:.0f}%" if raw else ""
        # stage label (left, right-aligned into the bar column)
        parts.append(
            f'<text x="{pad_l - 14}" y="{y + row_h/2 + 5}" text-anchor="end" '
            f'class="ink" font-size="15">{_esc(label)}</text>'
        )
        # faint full-width track for scale reference
        parts.append(
            f'<rect x="{pad_l}" y="{y}" width="{bar_max}" height="{row_h}" '
            f'rx="5" class="track" opacity="0.5"/>'
        )
        # the data bar, 4px rounded
        parts.append(
            f'<rect x="{pad_l}" y="{y}" width="{w}" height="{row_h}" rx="5" '
            f'fill="{color}"><title>{_esc(label)}: {count} ({pct} of raw)</title></rect>'
        )
        # count + share, in ink, to the right of the bar
        parts.append(
            f'<text x="{pad_l + w + 12}" y="{y + row_h/2 - 2}" class="ink" '
            f'font-size="16" font-weight="600">{count}</text>'
        )
        parts.append(
            f'<text x="{pad_l + w + 12}" y="{y + row_h/2 + 15}" class="muted" '
            f'font-size="11">{pct} of raw</text>'
        )

    parts.append("</svg>")
    Path(out_path).write_text("\n".join(parts))


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


if __name__ == "__main__":
    import csv
    import sys

    src = sys.argv[1] if len(sys.argv) > 1 else "examples/evidence/funnel.csv"
    dst = sys.argv[2] if len(sys.argv) > 2 else "docs/figures/triage-funnel.svg"
    rows = list(csv.DictReader(Path(src).read_text().splitlines()))
    data = [(r["stage"], int(r["count"])) for r in rows]
    render_svg(data, dst, title="Triage funnel")
    print(f"wrote {dst}")
