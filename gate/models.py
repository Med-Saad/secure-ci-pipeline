"""Core data model shared by every adapter and the engine.

Everything downstream of a scanner adapter speaks in these types. Keeping the
model small and explicit is what lets one gate policy apply uniformly across
five tools that otherwise have nothing in common.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum, Enum


class Severity(IntEnum):
    """Ordered severity. IntEnum so `finding.severity >= floor` just works.

    UNKNOWN sorts *below* LOW on purpose: an unrated finding must never satisfy
    a severity floor by accident. If a tool cannot rate a finding, the gate
    treats it as report-only unless some other axis (KEV, EPSS) escalates it.
    """

    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | None) -> "Severity":
        if not value:
            return cls.UNKNOWN
        v = value.strip().upper()
        # Common spellings across tools mapped onto the five-level scale.
        table = {
            "CRITICAL": cls.CRITICAL,
            "HIGH": cls.HIGH,
            "ERROR": cls.HIGH,          # Semgrep/Hadolint "error" == blocking-class
            "MODERATE": cls.MEDIUM,     # GitHub/npm advisory wording
            "MEDIUM": cls.MEDIUM,
            "WARNING": cls.MEDIUM,      # Semgrep/Hadolint "warning"
            "LOW": cls.LOW,
            "INFO": cls.LOW,            # Hadolint "info", Semgrep "info"
            "INFORMATIONAL": cls.LOW,
            "STYLE": cls.LOW,           # Hadolint "style"
            "NONE": cls.UNKNOWN,
            "UNKNOWN": cls.UNKNOWN,
        }
        return table.get(v, cls.UNKNOWN)

    def label(self) -> str:
        return self.name.capitalize()


class Domain(str, Enum):
    """What a finding is *about* — determines which policy applies to it.

    DEPS and IMAGE_OS are gated; IMAGE_LANG is report-only (it overlaps DEPS,
    see DEFENSE.md D1); SECRET has no severity floor (any secret blocks);
    DOCKERFILE gates only its highest level.
    """

    DEPS = "deps"            # application dependency vuln (OSV-Scanner)
    IMAGE_OS = "image_os"    # OS package vuln in the built image (Trivy)
    IMAGE_LANG = "image_lang"  # language-pkg vuln in the image (Trivy, report-only)
    SAST = "sast"            # static analysis finding (Semgrep)
    SECRET = "secret"        # committed secret (Gitleaks)
    DOCKERFILE = "dockerfile"  # Dockerfile lint (Hadolint)


class Decision(str, Enum):
    """Outcome of the gate for a single finding."""

    BLOCK = "block"          # fails the build
    REPORT = "report"        # surfaced, does not fail the build
    SUPPRESSED = "suppressed"  # matched a suppression rule
    INHERITED = "inherited"  # present on the merge base; not this PR's regression


@dataclass(frozen=True)
class Package:
    name: str
    version: str = ""

    def __str__(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name


@dataclass
class Finding:
    """One normalised finding from any scanner.

    `identifiers` holds every alias (CVE, GHSA, ...) so KEV/EPSS lookups — which
    are keyed by CVE — can match a finding whose primary id is a GHSA. `location`
    plus `fingerprint()` give a stable identity for merge-base delta and for
    suppression matching.
    """

    domain: Domain
    tool: str
    rule_id: str                       # primary id (CVE/GHSA/semgrep rule/etc.)
    title: str = ""
    severity: Severity = Severity.UNKNOWN
    identifiers: frozenset[str] = field(default_factory=frozenset)
    package: Package | None = None
    location: str = ""                 # file path, or file:line, or pkg@ver
    line: int | None = None
    fix_available: bool | None = None  # None == unknown (do not relax on unknown)
    epss: float | None = None          # filled in by the engine, not the adapter
    is_kev: bool = False               # filled in by the engine, not the adapter
    raw: dict | None = None

    def cve_ids(self) -> set[str]:
        """All CVE-form identifiers (for KEV/EPSS lookup)."""
        ids = {i for i in self.identifiers if i.upper().startswith("CVE-")}
        if self.rule_id.upper().startswith("CVE-"):
            ids.add(self.rule_id)
        return ids

    def fingerprint(self) -> str:
        """Stable identity for delta and suppression matching.

        Deliberately excludes severity/EPSS/fix-availability (those are ratings,
        not identity) so the same underlying finding fingerprints identically on
        the base branch and the PR head even if its rating changes.

        For dependency/image findings, identity is (domain, package, vuln-id) and
        is line-independent. For code findings it includes file and line, which
        makes it sensitive to line shifts — a known limitation documented in
        README/limitations and mitigated by preferring a tool-provided fingerprint
        (Gitleaks supplies one) when available.
        """
        if self.domain in (Domain.DEPS, Domain.IMAGE_OS, Domain.IMAGE_LANG):
            pkg = str(self.package) if self.package else self.location
            key = f"{self.domain.value}|{pkg}|{self.rule_id}"
        else:
            loc = self.location or ""
            line = "" if self.line is None else str(self.line)
            key = f"{self.domain.value}|{self.tool}|{self.rule_id}|{loc}|{line}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class EvaluatedFinding:
    """A finding after the gate has ruled on it."""

    finding: Finding
    decision: Decision
    reason: str                 # human-readable *why* (drives the report)
    suppression_ref: str | None = None  # which suppression rule matched, if any


@dataclass
class GateResult:
    """The full outcome of a gate run: the verdict plus the triage funnel."""

    evaluated: list[EvaluatedFinding]
    funnel: dict[str, int]      # ordered stages: raw -> scoped -> ... -> blocking
    blocked: bool               # True == fail the build

    def by_decision(self, decision: Decision) -> list[EvaluatedFinding]:
        return [e for e in self.evaluated if e.decision == decision]
