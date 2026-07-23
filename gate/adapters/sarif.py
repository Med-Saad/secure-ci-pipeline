"""Generic SARIF 2.1.0 adapter (Semgrep and any other SARIF-emitting SAST tool).

Severity comes from `result.level`, falling back to the rule's
`defaultConfiguration.level`, then to Semgrep's `security-severity` property if
present. SARIF findings are code findings (Domain.SAST), so KEV/EPSS never apply
to them; only the severity floor and merge-base delta do.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Domain, Finding, Severity


def _security_severity_bucket(props: dict) -> Severity:
    raw = props.get("security-severity")
    if raw is None:
        return Severity.UNKNOWN
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def load(path: str | Path) -> list[Finding]:
    data = json.loads(Path(path).read_text())
    findings: list[Finding] = []
    for run in data.get("runs", []) or []:
        driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
        tool_name = driver.get("name", "sarif").lower()
        rules = {r.get("id"): r for r in driver.get("rules", []) or []}
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId", "") or ""
            rule = rules.get(rule_id, {}) or {}
            level = res.get("level")
            if not level:
                level = (rule.get("defaultConfiguration", {}) or {}).get("level")
            sev = Severity.parse(level)
            if sev is Severity.UNKNOWN:
                sev = _security_severity_bucket(rule.get("properties", {}) or {})

            loc_uri, line = "", None
            locs = res.get("locations", []) or []
            if locs:
                phys = (locs[0].get("physicalLocation", {}) or {})
                loc_uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                line = (phys.get("region", {}) or {}).get("startLine")

            msg = (res.get("message", {}) or {}).get("text", "")
            findings.append(
                Finding(
                    domain=Domain.SAST,
                    tool=tool_name,
                    rule_id=rule_id,
                    title=msg[:200],
                    severity=sev,
                    location=loc_uri,
                    line=line,
                )
            )
    return findings
