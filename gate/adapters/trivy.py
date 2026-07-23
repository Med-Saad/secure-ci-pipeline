"""Trivy adapter for a scanned image (`trivy image --format json`).

Trivy tags every Result with a `Class`. We split on it:
  - `os-pkgs`   -> Domain.IMAGE_OS   (gated: the pipeline owns the base image)
  - everything else with vulns (lang-pkgs) -> Domain.IMAGE_LANG (report-only;
    it overlaps OSV-Scanner's view of the same dependencies — see DEFENSE.md D1).

`FixedVersion` present == a fix exists, feeding the fix-available policy.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Domain, Finding, Package, Severity


def load(path: str | Path) -> list[Finding]:
    data = json.loads(Path(path).read_text())
    findings: list[Finding] = []
    for result in data.get("Results", []) or []:
        cls = result.get("Class", "")
        target = result.get("Target", "")
        domain = Domain.IMAGE_OS if cls == "os-pkgs" else Domain.IMAGE_LANG
        for v in result.get("Vulnerabilities", []) or []:
            vid = v.get("VulnerabilityID", "")
            ids = {vid}
            # Trivy folds aliases into the primary id; keep it simple and add vid.
            fixed = v.get("FixedVersion")
            findings.append(
                Finding(
                    domain=domain,
                    tool="trivy",
                    rule_id=vid,
                    title=v.get("Title", "") or v.get("PkgName", ""),
                    severity=Severity.parse(v.get("Severity")),
                    identifiers=frozenset(i for i in ids if i),
                    package=Package(
                        name=v.get("PkgName", ""),
                        version=v.get("InstalledVersion", ""),
                    ),
                    location=f"{target}:{v.get('PkgName','')}",
                    fix_available=bool(fixed) if fixed is not None else None,
                )
            )
    return findings
