"""Hadolint adapter (Dockerfile lint -> Domain.DOCKERFILE).

Hadolint emits a JSON array of {line, code, level, message, file}. Its levels map
onto the shared severity scale via Severity.parse (error->HIGH, warning->MEDIUM,
info/style->LOW). Dockerfile findings are mostly advisory, so the engine gates
only the top level and reports the rest — the policy, not this adapter, decides.
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
    findings: list[Finding] = []
    for item in data or []:
        code = item.get("code", "")
        line = item.get("line")
        findings.append(
            Finding(
                domain=Domain.DOCKERFILE,
                tool="hadolint",
                rule_id=code,
                title=item.get("message", ""),
                severity=Severity.parse(item.get("level")),
                location=item.get("file", "Dockerfile"),
                line=line,
            )
        )
    return findings
