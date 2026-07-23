"""FIRST.org EPSS (Exploit Prediction Scoring System) scores.

EPSS gives, per CVE, the probability [0,1] that it will be exploited in the next
30 days, plus a percentile rank. In the gate it is an *escalation-only* signal:
a high EPSS can pull a below-floor finding up to blocking, but a low EPSS never
pardons a finding that is already above the floor or in KEV. That asymmetry is
deliberate — see DEFENSE.md — and lives in the engine; this module only supplies
the scores.

Injected, not fetched inside the engine, for the same purity/testability reason
as KEV. The daily bulk CSV (gzip) has two `#`-comment header lines followed by a
`cve,epss,percentile` table; this loader tolerates both the raw and gzip forms.
"""

from __future__ import annotations

import csv
import gzip
import io
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class EpssScores:
    # cve (upper) -> (score, percentile)
    scores: dict[str, tuple[float, float]] = field(default_factory=dict)

    @classmethod
    def empty(cls) -> "EpssScores":
        return cls(scores={})

    @classmethod
    def from_csv_text(cls, text: str) -> "EpssScores":
        out: dict[str, tuple[float, float]] = {}
        # Skip FIRST.org's leading '#model_version...' comment lines.
        lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
        reader = csv.DictReader(lines)
        for row in reader:
            cve = (row.get("cve") or "").strip().upper()
            if not cve:
                continue
            try:
                score = float(row.get("epss", "") or 0.0)
                pct = float(row.get("percentile", "") or 0.0)
            except ValueError:
                continue
            out[cve] = (score, pct)
        return cls(scores=out)

    @classmethod
    def from_file(cls, path: str | Path) -> "EpssScores":
        p = Path(path)
        data = p.read_bytes()
        if p.suffix == ".gz" or data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        return cls.from_csv_text(io.TextIOWrapper(io.BytesIO(data), encoding="utf-8").read())

    def score_for(self, cve: str) -> float | None:
        hit = self.scores.get(cve.strip().upper())
        return hit[0] if hit else None

    def max_score(self, cves: set[str]) -> float | None:
        """Highest EPSS across a finding's CVEs (None if none are scored)."""
        vals = [self.scores[c.upper()][0] for c in cves if c.upper() in self.scores]
        return max(vals) if vals else None
