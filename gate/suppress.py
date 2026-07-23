"""Suppressions: the author's explicit, auditable overrides.

A suppression is a *claim about code semantics* ("this finding does not apply
here, and here is why"). Under the autonomous protocol every suppression is the
highest-risk output in the project, so the format forces a reason and supports an
expiry, and the engine records which rule fired against which finding.

Two hard rules live in the engine, not here:
  - a KEV finding can never be suppressed;
  - an *expired* suppression does not apply, so the finding re-surfaces (the gate
    fails toward blocking, which is the safe direction).

Format (YAML or JSON — YAML needs the optional PyYAML extra):

    suppressions:
      - id: SUP-001
        reason: "vendored fixture, not shipped; see DEFENSE.md"
        expires: "2026-12-31"        # optional (ISO date)
        match:                        # ALL present keys must match
          domain: deps                # optional
          rule_id: GHSA-xxxx          # optional (exact)
          package: lodash             # optional (package name)
          fingerprint: 0a1b2c3d        # optional (exact 16-hex fingerprint)
          location_glob: "src/legacy/**"   # optional (fnmatch on location)
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .models import Domain, Finding


@dataclass
class Suppression:
    id: str
    reason: str
    expires: date | None = None
    domain: Domain | None = None
    rule_id: str | None = None
    package: str | None = None
    fingerprint: str | None = None
    location_glob: str | None = None

    def is_expired(self, today: date) -> bool:
        return self.expires is not None and self.expires < today

    def matches(self, f: Finding) -> bool:
        """True iff every specified criterion matches. An empty match is invalid
        (would suppress everything) and is rejected at load time."""
        if self.domain is not None and f.domain is not self.domain:
            return False
        if self.rule_id is not None and self.rule_id != f.rule_id and \
                self.rule_id not in f.identifiers:
            return False
        if self.package is not None and (f.package is None or f.package.name != self.package):
            return False
        if self.fingerprint is not None and self.fingerprint != f.fingerprint():
            return False
        if self.location_glob is not None and not fnmatch.fnmatch(f.location, self.location_glob):
            return False
        return True


def _parse_entry(raw: dict) -> Suppression:
    sid = raw.get("id")
    reason = raw.get("reason")
    if not sid or not reason:
        raise ValueError(f"suppression missing required id/reason: {raw!r}")
    match = raw.get("match", {}) or {}
    if not match:
        raise ValueError(f"suppression {sid} has an empty match (would suppress everything)")
    dom = match.get("domain")
    exp = raw.get("expires")
    return Suppression(
        id=sid,
        reason=reason,
        expires=date.fromisoformat(exp) if exp else None,
        domain=Domain(dom) if dom else None,
        rule_id=match.get("rule_id"),
        package=match.get("package"),
        fingerprint=match.get("fingerprint"),
        location_glob=match.get("location_glob"),
    )


def load_suppressions(path: str | Path | None) -> list[Suppression]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        return []
    text = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml  # optional dependency
        except ImportError as e:  # pragma: no cover
            raise SystemExit(
                f"{p} is YAML but PyYAML is not installed. Install `pip install "
                f"ci-gate[yaml]` or use a .json suppression file."
            ) from e
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text) if text.strip() else {}
    entries = data.get("suppressions", []) if isinstance(data, dict) else (data or [])
    return [_parse_entry(e) for e in entries]
