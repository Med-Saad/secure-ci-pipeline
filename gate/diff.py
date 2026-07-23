"""Merge-base delta.

The gate blocks regressions, not inherited debt: a finding already present on the
branch you are merging into is not something this PR introduced. We express that
as a set of *baseline fingerprints* — the fingerprints of every finding seen on
the merge base. A PR-head finding whose fingerprint is in that set is INHERITED.

The baseline is produced by scanning the merge base with the same adapters and
serialising the fingerprints (see report.fingerprints_json). Keeping it to
fingerprints — not full findings — makes the baseline small and diffable, and
means a severity re-rating on the base branch cannot accidentally un-inherit a
finding (fingerprint deliberately excludes severity; see Finding.fingerprint).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .models import Finding


@dataclass
class Baseline:
    fingerprints: frozenset[str]

    @classmethod
    def empty(cls) -> "Baseline":
        return cls(fingerprints=frozenset())

    def contains(self, f: Finding) -> bool:
        return f.fingerprint() in self.fingerprints

    @classmethod
    def from_file(cls, path: str | Path | None) -> "Baseline":
        if not path:
            return cls.empty()
        p = Path(path)
        if not p.exists():
            return cls.empty()
        data = json.loads(p.read_text() or "{}")
        # Accept either a bare list of fingerprints or {"fingerprints": [...]}.
        if isinstance(data, dict):
            fps = data.get("fingerprints", [])
        else:
            fps = data
        return cls(fingerprints=frozenset(fps))
