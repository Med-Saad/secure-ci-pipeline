"""OSV-Scanner adapter (application dependencies -> Domain.DEPS).

OSV rates severity in three overlapping places; we prefer, in order:
  1. `database_specific.severity` — GHSA's own text rating (CRITICAL..LOW), the
     most consistently present and the one a human reviewer sees on the advisory.
  2. `groups[].max_severity` — a numeric CVSS base score OSV precomputes; bucketed.
The CVSS *vector* strings are ignored: scoring a vector from scratch would add a
lot of surface for no gain when OSV already hands us (1) and (2).

Fix availability comes from the advisory's `affected[].ranges` carrying a
`fixed` event — a real signal, used by the fix-available gate policy.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Domain, Finding, Package, Severity


def _cvss_bucket(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.UNKNOWN


def _severity_of(vuln: dict, group_max: dict[str, float]) -> Severity:
    ds = (vuln.get("database_specific") or {}).get("severity")
    if ds:
        sev = Severity.parse(ds)
        if sev is not Severity.UNKNOWN:
            return sev
    ms = group_max.get(vuln.get("id", ""))
    if ms is not None:
        return _cvss_bucket(ms)
    return Severity.UNKNOWN


def _fix_available(vuln: dict) -> bool | None:
    """True if any affected range carries a 'fixed' event; None if unknowable."""
    saw_range = False
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                saw_range = True
                if "fixed" in ev:
                    return True
        # A discrete `versions` list with no ranges tells us nothing about a fix.
    return False if saw_range else None


def load(path: str | Path) -> list[Finding]:
    data = json.loads(Path(path).read_text())
    findings: list[Finding] = []
    for result in data.get("results", []) or []:
        source = (result.get("source") or {}).get("path", "")
        for pkg in result.get("packages", []) or []:
            p = pkg.get("package", {}) or {}
            package = Package(name=p.get("name", ""), version=p.get("version", ""))
            # Map each advisory id -> its group's max CVSS, for the fallback rating.
            group_max: dict[str, float] = {}
            for grp in pkg.get("groups", []) or []:
                try:
                    ms = float(grp.get("max_severity")) if grp.get("max_severity") else None
                except (TypeError, ValueError):
                    ms = None
                if ms is not None:
                    for vid in grp.get("ids", []) or []:
                        group_max[vid] = ms
            for vuln in pkg.get("vulnerabilities", []) or []:
                vid = vuln.get("id", "")
                aliases = set(vuln.get("aliases", []) or [])
                aliases.add(vid)
                findings.append(
                    Finding(
                        domain=Domain.DEPS,
                        tool="osv",
                        rule_id=vid,
                        title=vuln.get("summary", "") or (vuln.get("details", "")[:120]),
                        severity=_severity_of(vuln, group_max),
                        identifiers=frozenset(a.strip() for a in aliases if a),
                        package=package,
                        location=f"{source}:{package}",
                        fix_available=_fix_available(vuln),
                        raw=None,
                    )
                )
    return findings
