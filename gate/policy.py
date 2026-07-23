"""Gate policy — the tunable knobs, with defensible defaults.

The policy is data, not code: every threshold here is a decision the author must
be able to justify (see TUNING.md). Defaults encode the model from the tuning
record; a repo can override them with a JSON/YAML policy file.

Per-domain policy:
  - `gated`    : does this domain fail the build at all? (IMAGE_LANG is report-only)
  - `floor`    : minimum severity that blocks (SECRET has no floor -> LOW, i.e. any)
Global knobs:
  - `epss_escalate`      : EPSS >= this pulls a below-floor finding to blocking
  - `require_fix_available`: a floor-only block with no available fix downgrades
                             to report-only (KEV and EPSS escalation ignore this)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Domain, Severity


@dataclass
class DomainPolicy:
    gated: bool
    floor: Severity


# The defaults ARE the tuning decision. Changing one is a TUNING.md entry.
DEFAULT_DOMAIN_POLICY: dict[Domain, DomainPolicy] = {
    Domain.DEPS:       DomainPolicy(gated=True,  floor=Severity.HIGH),
    Domain.IMAGE_OS:   DomainPolicy(gated=True,  floor=Severity.HIGH),
    Domain.IMAGE_LANG: DomainPolicy(gated=False, floor=Severity.HIGH),  # report-only
    Domain.SAST:       DomainPolicy(gated=True,  floor=Severity.HIGH),  # Semgrep ERROR
    Domain.SECRET:     DomainPolicy(gated=True,  floor=Severity.LOW),   # any secret
    Domain.DOCKERFILE: DomainPolicy(gated=True,  floor=Severity.HIGH),  # Hadolint error
}


@dataclass
class Policy:
    domains: dict[Domain, DomainPolicy] = field(
        default_factory=lambda: dict(DEFAULT_DOMAIN_POLICY)
    )
    epss_escalate: float = 0.10          # 10% 30-day exploitation probability
    require_fix_available: bool = True   # keep the gate actionable
    # If True, findings already present on the merge base are demoted to
    # INHERITED (not blocked). Turned off for a full audit (target-scan).
    delta_enabled: bool = True

    def domain(self, d: Domain) -> DomainPolicy:
        return self.domains.get(d, DomainPolicy(gated=False, floor=Severity.HIGH))

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        p = cls()
        for name, dp in (data.get("domains") or {}).items():
            dom = Domain(name)
            base = p.domains.get(dom, DomainPolicy(True, Severity.HIGH))
            p.domains[dom] = DomainPolicy(
                gated=dp.get("gated", base.gated),
                floor=Severity.parse(dp["floor"]) if "floor" in dp else base.floor,
            )
        if "epss_escalate" in data:
            p.epss_escalate = float(data["epss_escalate"])
        if "require_fix_available" in data:
            p.require_fix_available = bool(data["require_fix_available"])
        if "delta_enabled" in data:
            p.delta_enabled = bool(data["delta_enabled"])
        return p
