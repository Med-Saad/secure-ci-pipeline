"""Rendering a GateResult: JSON (machine), Markdown (the CI step summary),
fingerprints (the baseline export), and a funnel CSV (the triage chart data)."""

from __future__ import annotations

import json
from datetime import date

from .models import Decision, Finding, GateResult, Severity

# Order decisions worst-first for display.
_DECISION_ORDER = [Decision.BLOCK, Decision.REPORT, Decision.INHERITED, Decision.SUPPRESSED]
_SEV_ORDER = {s: -int(s) for s in Severity}


def to_json(result: GateResult) -> dict:
    return {
        "blocked": result.blocked,
        "funnel": result.funnel,
        "findings": [
            {
                "decision": e.decision.value,
                "reason": e.reason,
                "suppression": e.suppression_ref,
                "domain": e.finding.domain.value,
                "tool": e.finding.tool,
                "rule_id": e.finding.rule_id,
                "severity": e.finding.severity.label(),
                "package": str(e.finding.package) if e.finding.package else None,
                "location": e.finding.location,
                "line": e.finding.line,
                "is_kev": e.finding.is_kev,
                "epss": e.finding.epss,
                "fix_available": e.finding.fix_available,
                "fingerprint": e.finding.fingerprint(),
            }
            for e in result.evaluated
        ],
    }


def fingerprints(findings: list[Finding]) -> list[str]:
    return sorted({f.fingerprint() for f in findings})


def funnel_csv(result: GateResult) -> str:
    chain = ["raw", "not_suppressed", "new_vs_base", "meets_policy", "blocking"]
    lines = ["stage,count"]
    lines += [f"{s},{result.funnel.get(s, 0)}" for s in chain]
    return "\n".join(lines) + "\n"


def _sorted_blocks(result: GateResult):
    blocks = result.by_decision(Decision.BLOCK)
    return sorted(blocks, key=lambda e: (_SEV_ORDER[e.finding.severity], e.finding.rule_id))


def to_markdown(result: GateResult, title: str = "Security gate") -> str:
    f = result.funnel
    verdict = "❌ BLOCKED" if result.blocked else "✅ PASSED"
    out: list[str] = [f"## {title} — {verdict}", ""]

    out.append("### Triage funnel")
    out.append("")
    out.append("| stage | count |")
    out.append("|---|---:|")
    for label, key in [
        ("Raw findings", "raw"),
        ("After suppression", "not_suppressed"),
        ("New vs. merge base", "new_vs_base"),
        ("Meets policy", "meets_policy"),
        ("**Blocking**", "blocking"),
    ]:
        out.append(f"| {label} | {f.get(key, 0)} |")
    out.append("")
    out.append(
        f"_reported (non-blocking): {f.get('reported',0)} · "
        f"suppressed: {f.get('suppressed',0)} · "
        f"inherited: {f.get('inherited',0)} · "
        f"KEV blocks: {f.get('blocked_by_kev',0)}_"
    )
    out.append("")

    blocks = _sorted_blocks(result)
    if blocks:
        out.append("### Blocking findings")
        out.append("")
        out.append("| severity | domain | id | location | why |")
        out.append("|---|---|---|---|---|")
        for e in blocks:
            g = e.finding
            loc = g.location if len(g.location) < 60 else "…" + g.location[-57:]
            out.append(
                f"| {g.severity.label()} | {g.domain.value} | `{g.rule_id}` | "
                f"{loc} | {e.reason} |"
            )
        out.append("")
    else:
        out.append("_No blocking findings._\n")

    return "\n".join(out)
