"""Gitleaks adapter (committed secrets -> Domain.SECRET).

Gitleaks emits a JSON array of leaks. A committed secret has no CVSS severity;
the gate treats *any* secret as blocking (the SECRET domain has no severity
floor — see engine policy), so severity here is nominal (HIGH) purely for
display ordering. We reuse Gitleaks' own `Fingerprint` (commit:file:rule:line)
as the finding location so merge-base delta is stable across line shifts.

The secret value itself is never stored in a Finding — only its fingerprint and
location — so the gate's own artifacts cannot leak what the scanner found.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Domain, Finding, Severity


def load(path: str | Path) -> list[Finding]:
    text = Path(path).read_text().strip()
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):  # tolerate a wrapper object
        data = data.get("findings", data.get("results", []))
    findings: list[Finding] = []
    for leak in data or []:
        rule = leak.get("RuleID", leak.get("rule", "secret"))
        fp = leak.get("Fingerprint", leak.get("fingerprint", ""))
        file = leak.get("File", leak.get("file", ""))
        line = leak.get("StartLine", leak.get("startLine"))
        commit = leak.get("Commit", leak.get("commit", ""))[:12]
        findings.append(
            Finding(
                domain=Domain.SECRET,
                tool="gitleaks",
                rule_id=rule,
                title=leak.get("Description", leak.get("description", "committed secret")),
                severity=Severity.HIGH,  # nominal; SECRET domain has no floor
                location=fp or f"{commit}:{file}:{line}",
                line=line,
            )
        )
    return findings
