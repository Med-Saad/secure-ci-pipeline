#!/usr/bin/env python3
"""Build the committed triage-funnel evidence from real scanner outputs.

This is the script behind examples/evidence/. It reads the raw scanner outputs
(not committed — they are large and regenerable), runs the gate, and writes the
staged funnel, the gate summary, a scan manifest, and the SVG chart. Committing
the script alongside its output means the numbers are reproducible, not typed.

    python scripts/build_evidence.py \
        --osv osv.json --trivy trivy-image.json \
        --semgrep-unscoped semgrep-unscoped.sarif \
        --semgrep-scoped semgrep-scoped.sarif \
        --kev kev.json --epss epss.csv.gz \
        --target-sha 29f3f16 --outdir examples/evidence

The funnel stages, in order (each a real count):
  raw            all scanners, SAST unscoped
  after_scoping  SAST restricted to first-party source
  gated          report-only image-language layer set aside (overlaps deps)
  meets_policy   severity floor / KEV / EPSS
  blocking       after fix-availability relaxation
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gate import adapters
from gate.diff import Baseline
from gate.engine import evaluate
from gate.epss import EpssScores
from gate.kev import KevCatalog
from gate.models import Decision, Domain
from gate.policy import Policy
from gate.report import to_markdown
from scripts.plot_funnel import render_svg  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--osv", required=True)
    ap.add_argument("--trivy", required=True)
    ap.add_argument("--semgrep-unscoped", required=True)
    ap.add_argument("--semgrep-scoped", required=True)
    ap.add_argument("--kev", required=True)
    ap.add_argument("--epss", required=True)
    ap.add_argument("--target-sha", default="unknown")
    ap.add_argument("--target-repo", default="polonel/trudesk")
    ap.add_argument("--outdir", default="examples/evidence")
    a = ap.parse_args()

    osv = adapters.load("osv", a.osv)
    trivy = adapters.load("trivy", a.trivy)
    sast_unscoped = adapters.load("semgrep", a.semgrep_unscoped)
    sast_scoped = adapters.load("semgrep", a.semgrep_scoped)
    kev = KevCatalog.from_file(a.kev)
    epss = EpssScores.from_file(a.epss)

    # Sanitise the scanning machine's absolute paths out of committed evidence so
    # the sample is portable and leaks no local filesystem layout.
    home = str(Path.home())
    for f in osv + trivy + sast_scoped:
        loc = f.location.replace(f"{home}/recon/", "").replace(f"{home}/", "")
        # collapse any remaining absolute target path to the repo-relative tail
        if "/trudesk/" in loc:
            loc = "trudesk/" + loc.split("/trudesk/", 1)[1]
        f.location = loc

    trivy_os = [f for f in trivy if f.domain is Domain.IMAGE_OS]
    trivy_lang = [f for f in trivy if f.domain is Domain.IMAGE_LANG]

    # The authoritative gate run: full audit over the scoped, real inputs.
    gated_input = osv + trivy + sast_scoped
    result = evaluate(gated_input, Policy(delta_enabled=False), kev, epss, [],
                      Baseline.empty(), today=date.today())

    n_block = result.funnel["blocking"]
    n_meets = result.funnel["meets_policy"]

    funnel = [
        ("raw", len(osv) + len(trivy) + len(sast_unscoped)),
        ("after_scoping", len(osv) + len(trivy) + len(sast_scoped)),
        ("gated", len(osv) + len(trivy_os) + len(sast_scoped)),
        ("meets_policy", n_meets),
        ("blocking", n_block),
    ]

    outdir = Path(a.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # funnel.csv
    csv = "stage,count\n" + "\n".join(f"{s},{c}" for s, c in funnel) + "\n"
    (outdir / "funnel.csv").write_text(csv)

    # gate summary
    (outdir / "gate-summary.md").write_text(to_markdown(result, title=f"trudesk @{a.target_sha}"))

    # scan manifest — traceability without the multi-MB raw files
    by_dom = {}
    for e in result.evaluated:
        d = e.finding.domain.value
        by_dom.setdefault(d, {"total": 0, "block": 0, "report": 0})
        by_dom[d]["total"] += 1
        if e.decision is Decision.BLOCK:
            by_dom[d]["block"] += 1
        elif e.decision is Decision.REPORT:
            by_dom[d]["report"] += 1

    kev_escalations = [
        {"id": e.finding.rule_id, "severity": e.finding.severity.label(),
         "epss": e.finding.epss, "package": str(e.finding.package)}
        for e in result.by_decision(Decision.BLOCK)
        if e.finding.severity.value < 3 and e.finding.epss  # below HIGH, blocked -> EPSS
    ]

    manifest = {
        "target": {"repo": a.target_repo, "sha": a.target_sha},
        "kev_catalog_version": kev.catalog_version,
        "raw_counts": {
            "osv_deps": len(osv),
            "trivy_image_os": len(trivy_os),
            "trivy_image_lang": len(trivy_lang),
            "semgrep_unscoped": len(sast_unscoped),
            "semgrep_scoped": len(sast_scoped),
        },
        "funnel": dict(funnel),
        "by_domain": by_dom,
        "kev_total_on_target": result.funnel["kev_total"],
        "epss_escalated_blocks": kev_escalations,
        "blocked": result.blocked,
    }
    (outdir / "scan-manifest.json").write_text(json.dumps(manifest, indent=2))

    # SVG chart
    fig = Path("docs/figures")
    fig.mkdir(parents=True, exist_ok=True)
    render_svg(funnel, fig / "triage-funnel.svg",
               title=f"trudesk triage funnel — {len(osv)+len(trivy)+len(sast_unscoped)} raw findings to {n_block} blocking")

    print(json.dumps(manifest["funnel"], indent=2))
    print(f"wrote {outdir}/ and docs/figures/triage-funnel.svg")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
