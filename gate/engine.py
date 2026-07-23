"""The gate: apply one policy across every normalised finding.

Precedence, evaluated per finding (first rule that applies wins):

  1. KEV        -> BLOCK, unconditionally. Ignores the severity floor, the
                  merge-base delta, the report-only flag, fix-availability, AND
                  suppressions. Known-exploited is known-exploited; a suppression
                  cannot pardon it and inheriting it from the base does not excuse
                  it. This is the one rule with no escape hatch.
  2. Suppressed -> SUPPRESSED (only a non-expired suppression; expired ones do
                  not apply, so the finding falls through and re-surfaces).
  3. Inherited  -> INHERITED, when delta is enabled and the finding's fingerprint
                  is on the merge base. Not this PR's regression.
  4. Otherwise decide BLOCK vs REPORT for the surviving (new, un-suppressed,
     non-KEV) finding:
       - report-only domain (e.g. image language layer) -> REPORT
       - blocks if severity >= domain floor  OR  EPSS >= escalate threshold
       - fix-availability relaxation: a *floor-only* block (not EPSS-driven) whose
         fix_available is explicitly False downgrades to REPORT — you cannot act
         on it in this PR, so blocking the merge on it is noise. Unknown fix
         status (None) does NOT relax; EPSS-escalated blocks do NOT relax.

EPSS only ever escalates (rule 4, second disjunct); it never appears as a reason
to *lower* a decision. That asymmetry is the whole point of the model.
"""

from __future__ import annotations

from datetime import date

from .diff import Baseline
from .epss import EpssScores
from .kev import KevCatalog
from .models import Decision, EvaluatedFinding, Finding, GateResult, Severity
from .policy import Policy
from .suppress import Suppression


def _enrich(f: Finding, kev: KevCatalog, epss: EpssScores) -> Finding:
    """Attach KEV/EPSS signal to the finding (mutates and returns it)."""
    cves = f.cve_ids()
    f.is_kev = bool(kev.matched_cves(f)) if cves else False
    f.epss = epss.max_score(cves) if cves else None
    return f


def _first_matching_suppression(
    f: Finding, suppressions: list[Suppression], today: date
) -> Suppression | None:
    for s in suppressions:
        if s.is_expired(today):
            continue
        if s.matches(f):
            return s
    return None


def evaluate_one(
    f: Finding,
    policy: Policy,
    kev: KevCatalog,
    epss: EpssScores,
    suppressions: list[Suppression],
    baseline: Baseline,
    today: date,
) -> EvaluatedFinding:
    _enrich(f, kev, epss)

    # 1. KEV — unconditional, no escape hatch.
    if f.is_kev:
        hit = sorted(kev.matched_cves(f))
        return EvaluatedFinding(
            f, Decision.BLOCK,
            f"KEV: {', '.join(hit)} is in the CISA Known Exploited catalog "
            f"(blocks unconditionally — no floor, delta, fix, or suppression applies)",
        )

    # 2. Suppression (non-expired only).
    sup = _first_matching_suppression(f, suppressions, today)
    if sup is not None:
        return EvaluatedFinding(
            f, Decision.SUPPRESSED, f"suppressed by {sup.id}: {sup.reason}",
            suppression_ref=sup.id,
        )

    # 3. Merge-base delta.
    if policy.delta_enabled and baseline.contains(f):
        return EvaluatedFinding(
            f, Decision.INHERITED,
            "present on the merge base — inherited debt, not this PR's regression",
        )

    # 4. Block vs report.
    dp = policy.domain(f.domain)
    epss_escalated = f.epss is not None and f.epss >= policy.epss_escalate
    meets_floor = f.severity >= dp.floor

    # Report-only domains yield ONLY to KEV (handled in rule 1 above). EPSS must
    # not escalate them: a report-only layer (image language packages) overlaps a
    # gated layer (OSV app deps), so escalating here would double-count the same
    # CVE that is already gated at its owning layer. See DEFENSE.md D1.
    if not dp.gated:
        return EvaluatedFinding(
            f, Decision.REPORT,
            f"{f.domain.value} is report-only (overlaps a gated layer; "
            f"only KEV overrides this)",
        )

    if not (meets_floor or epss_escalated):
        return EvaluatedFinding(
            f, Decision.REPORT,
            f"below {dp.floor.label()} floor ({f.severity.label()}) and EPSS "
            f"{_fmt_epss(f.epss)} < {policy.epss_escalate:.2f}",
        )

    # fix-availability relaxation: floor-only block, no fix -> report.
    floor_only = meets_floor and not epss_escalated
    if policy.require_fix_available and floor_only and f.fix_available is False:
        return EvaluatedFinding(
            f, Decision.REPORT,
            f"{f.severity.label()} but no fix available — not actionable in this "
            f"PR, so surfaced not blocked (fix-availability relaxation)",
        )

    # Blocks. Describe which axis carried it.
    if epss_escalated and not meets_floor:
        reason = (f"EPSS {_fmt_epss(f.epss)} >= {policy.epss_escalate:.2f} escalates "
                  f"a below-floor {f.severity.label()} finding to blocking")
    elif epss_escalated:
        reason = (f"{f.severity.label()} >= {dp.floor.label()} floor "
                  f"(EPSS {_fmt_epss(f.epss)} also over threshold)")
    else:
        reason = f"{f.severity.label()} >= {dp.floor.label()} floor, fix available"
    return EvaluatedFinding(f, Decision.BLOCK, reason)


def _fmt_epss(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def evaluate(
    findings: list[Finding],
    policy: Policy,
    kev: KevCatalog,
    epss: EpssScores,
    suppressions: list[Suppression],
    baseline: Baseline | None = None,
    today: date | None = None,
) -> GateResult:
    baseline = baseline or Baseline.empty()
    today = today or date.today()
    evaluated = [
        evaluate_one(f, policy, kev, epss, suppressions, baseline, today)
        for f in findings
    ]

    counts = {d: 0 for d in Decision}
    for e in evaluated:
        counts[e.decision] += 1
    blocked = counts[Decision.BLOCK] > 0

    # Triage funnel: monotonic survival through each filter. KEV blocks bypass
    # suppression/delta, so they are added back explicitly to keep the story true.
    total = len(evaluated)
    n_supp = counts[Decision.SUPPRESSED]
    n_inh = counts[Decision.INHERITED]
    n_block = counts[Decision.BLOCK]
    n_report = counts[Decision.REPORT]
    n_kev = sum(1 for e in evaluated if e.finding.is_kev)
    # "meets policy" = everything that blocks, plus floor-only findings relaxed
    # away by fix-availability (they met the floor but had no fix).
    n_relaxed = sum(
        1 for e in evaluated
        if e.decision is Decision.REPORT and "fix-availability relaxation" in e.reason
    )

    funnel = {
        "raw": total,
        "not_suppressed": total - n_supp,
        "new_vs_base": total - n_supp - n_inh,
        "meets_policy": n_block + n_relaxed,
        "blocking": n_block,
        # side channels (not part of the monotonic chain):
        "reported": n_report,
        "suppressed": n_supp,
        "inherited": n_inh,
        "blocked_by_kev": sum(
            1 for e in evaluated if e.decision is Decision.BLOCK and e.finding.is_kev
        ),
        "kev_total": n_kev,
    }
    return GateResult(evaluated=evaluated, funnel=funnel, blocked=blocked)
