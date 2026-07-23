"""Command line entrypoint: `ci-gate` (also `python -m gate`).

Two subcommands:

  ci-gate evaluate  --osv osv.json --trivy trivy.json ... \
                    --kev kev.json --epss epss.csv \
                    --suppressions suppressions.yml --policy policy.json \
                    --baseline base-fingerprints.json \
                    --json out/gate.json --summary out/summary.md \
                    --funnel out/funnel.csv
        Runs the gate. Exit code 1 iff the gate blocks (0 otherwise), so a CI
        step just runs it and lets the exit code fail the job.

  ci-gate baseline  --osv osv.json --trivy trivy.json ... --out base-fp.json
        Emits the merge base's fingerprints for a later `evaluate --baseline`.

Scanner inputs are optional and additive: pass only the ones that ran.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from . import adapters
from .diff import Baseline
from .engine import evaluate
from .epss import EpssScores
from .kev import KevCatalog
from .policy import Policy
from .report import fingerprints, funnel_csv, to_json, to_markdown
from .suppress import load_suppressions

# CLI flag -> adapter name
SCANNER_FLAGS = {
    "osv": "osv",
    "trivy": "trivy",
    "semgrep": "semgrep",
    "gitleaks": "gitleaks",
    "hadolint": "hadolint",
}


def _strip_prefixes(findings: list, prefixes: list[str]) -> None:
    """Remove scan-root prefixes from finding locations, in place.

    A PR-head scan runs in `target/` and the merge-base scan runs in `base/`, so
    the same file surfaces as `target/x` vs `base/x`. Code-finding fingerprints
    include the path, so without normalisation nothing would ever match across the
    two scans and the delta would be permanently inert (this was a real bug). Deps
    are unaffected — their fingerprint keys on package, not path — but stripping is
    harmless there. Prefixes are matched longest-first so `target/` wins over `t`.
    """
    if not prefixes:
        return
    for p in sorted(prefixes, key=len, reverse=True):
        pref = p if p.endswith("/") else p + "/"
        for f in findings:
            if f.location.startswith(pref):
                f.location = f.location[len(pref):]


def _collect_findings(args) -> list:
    findings = []
    for flag, tool in SCANNER_FLAGS.items():
        path = getattr(args, flag, None)
        if path:
            if not Path(path).exists():
                print(f"warning: {flag} input {path} not found, skipping", file=sys.stderr)
                continue
            loaded = adapters.load(tool, path)
            print(f"  {flag}: {len(loaded)} findings from {path}", file=sys.stderr)
            findings.extend(loaded)
    _strip_prefixes(findings, getattr(args, "strip_prefix", None) or [])
    return findings


def _add_scanner_flags(p: argparse.ArgumentParser) -> None:
    for flag in SCANNER_FLAGS:
        p.add_argument(f"--{flag}", help=f"{flag} JSON/SARIF output")


def _write(path: str | None, text: str) -> None:
    if not path:
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text)


def cmd_evaluate(args) -> int:
    findings = _collect_findings(args)
    policy = Policy.from_dict(json.loads(Path(args.policy).read_text())) if args.policy else Policy()
    if args.full:
        policy.delta_enabled = False
    kev = KevCatalog.from_file(args.kev) if args.kev else KevCatalog.empty()
    epss = EpssScores.from_file(args.epss) if args.epss else EpssScores.empty()
    suppressions = load_suppressions(args.suppressions)
    baseline = Baseline.from_file(args.baseline) if not args.full else Baseline.empty()

    result = evaluate(findings, policy, kev, epss, suppressions, baseline, today=date.today())

    _write(args.json, json.dumps(to_json(result), indent=2))
    summary = to_markdown(result, title=args.title)
    _write(args.summary, summary)
    _write(args.funnel, funnel_csv(result))
    if not args.quiet:
        print(summary)

    print(
        f"\ngate: {'BLOCKED' if result.blocked else 'passed'} "
        f"({result.funnel['blocking']} blocking, {result.funnel['reported']} reported, "
        f"{result.funnel['suppressed']} suppressed, {result.funnel['inherited']} inherited)",
        file=sys.stderr,
    )
    if args.no_fail:
        return 0
    return 1 if result.blocked else 0


def cmd_baseline(args) -> int:
    findings = _collect_findings(args)
    fps = fingerprints(findings)
    out = json.dumps({"fingerprints": fps}, indent=2)
    _write(args.out, out)
    if not args.out:
        print(out)
    print(f"baseline: {len(fps)} fingerprints", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ci-gate", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    ev = sub.add_parser("evaluate", help="run the gate")
    _add_scanner_flags(ev)
    ev.add_argument("--strip-prefix", action="append", default=[],
                    help="strip this leading path prefix from finding locations "
                         "(repeatable) so head/base scans fingerprint comparably")
    ev.add_argument("--kev", help="CISA KEV catalog JSON")
    ev.add_argument("--epss", help="FIRST.org EPSS CSV (optionally .gz)")
    ev.add_argument("--suppressions", help="suppressions YAML/JSON")
    ev.add_argument("--policy", help="policy JSON overriding defaults")
    ev.add_argument("--baseline", help="merge-base fingerprints JSON (delta)")
    ev.add_argument("--full", action="store_true",
                    help="full audit: disable merge-base delta, gate everything")
    ev.add_argument("--json", help="write machine-readable result here")
    ev.add_argument("--summary", help="write Markdown summary here (CI step summary)")
    ev.add_argument("--funnel", help="write funnel CSV here (chart data)")
    ev.add_argument("--title", default="Security gate", help="summary heading")
    ev.add_argument("--no-fail", action="store_true",
                    help="always exit 0 (report-only run)")
    ev.add_argument("--quiet", action="store_true", help="do not print summary to stdout")
    ev.set_defaults(func=cmd_evaluate)

    bl = sub.add_parser("baseline", help="emit merge-base fingerprints")
    _add_scanner_flags(bl)
    bl.add_argument("--strip-prefix", action="append", default=[],
                    help="strip this leading path prefix from finding locations "
                         "(repeatable) so head/base scans fingerprint comparably")
    bl.add_argument("--out", help="write fingerprints JSON here")
    bl.set_defaults(func=cmd_baseline)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # python -m gate.cli
    raise SystemExit(main())
