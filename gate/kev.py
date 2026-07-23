"""CISA Known Exploited Vulnerabilities (KEV) catalog.

KEV is the load-bearing signal of the gate: a vulnerability in this catalog is
known to be exploited in the wild, so it blocks unconditionally — no severity
floor, no merge-base delta, no suppression. This module only answers "is this
CVE in the catalog"; the *unconditional* semantics live in the engine.

The catalog is injected (not fetched inside the engine) so the gate stays pure
and offline-testable. In CI the workflow fetches a fresh copy; tests load a
committed snapshot fixture.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .models import Finding

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


@dataclass
class KevCatalog:
    cve_ids: frozenset[str]
    catalog_version: str = ""

    @classmethod
    def empty(cls) -> "KevCatalog":
        return cls(cve_ids=frozenset())

    @classmethod
    def from_dict(cls, data: dict) -> "KevCatalog":
        """Parse the CISA catalog JSON shape: {"vulnerabilities":[{"cveID":..}]}."""
        vulns = data.get("vulnerabilities", []) or []
        ids = {
            v["cveID"].strip().upper()
            for v in vulns
            if isinstance(v, dict) and v.get("cveID")
        }
        return cls(cve_ids=frozenset(ids), catalog_version=data.get("catalogVersion", ""))

    @classmethod
    def from_file(cls, path: str | Path) -> "KevCatalog":
        return cls.from_dict(json.loads(Path(path).read_text()))

    def contains(self, cve: str) -> bool:
        return cve.strip().upper() in self.cve_ids

    def matched_cves(self, finding: Finding) -> set[str]:
        """Every CVE on this finding that is in the KEV catalog (usually 0 or 1)."""
        return {c for c in finding.cve_ids() if self.contains(c)}
