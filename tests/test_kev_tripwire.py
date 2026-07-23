"""End-to-end assertion for the synthetic KEV tripwire.

The real target (trudesk) carries zero KEV vulnerabilities, so the 'always block
on KEV' rule has no organic trigger. This test scans the committed tripwire
fixture's real OSV output against a KEV snapshot containing CVE-2021-21315 and
asserts the gate blocks *via the KEV path* — proving the rule is wired, not just
written. If this ever goes green-without-blocking, the KEV path is broken.
"""

from datetime import date

from conftest import FIXTURES, SCANS

from gate import adapters
from gate.diff import Baseline
from gate.engine import evaluate
from gate.epss import EpssScores
from gate.kev import KevCatalog
from gate.models import Decision
from gate.policy import Policy


def test_tripwire_blocks_via_kev_path():
    findings = adapters.load("osv", SCANS / "osv-kev-tripwire.json")
    kev = KevCatalog.from_file(FIXTURES / "kev-snapshot.json")
    epss = EpssScores.from_file(FIXTURES / "epss-snapshot.csv")

    result = evaluate(findings, Policy(), kev, epss, [], Baseline.empty(),
                      today=date(2026, 7, 23))

    assert result.blocked, "tripwire must fail the gate"
    kev_blocks = [
        e for e in result.by_decision(Decision.BLOCK)
        if e.finding.is_kev and "KEV" in e.reason
    ]
    assert kev_blocks, "expected at least one block on the KEV path"
    blocked_cves = set().union(*(e.finding.cve_ids() for e in kev_blocks))
    assert "CVE-2021-21315" in blocked_cves


def test_tripwire_blocks_even_with_everything_suppressed_and_inherited():
    """KEV is unconditional: a blanket suppression + full inheritance must not
    let the tripwire through."""
    from gate.suppress import Suppression

    findings = adapters.load("osv", SCANS / "osv-kev-tripwire.json")
    kev = KevCatalog.from_file(FIXTURES / "kev-snapshot.json")
    base = Baseline(frozenset(f.fingerprint() for f in findings))  # all inherited
    sup = Suppression(id="SUP-ALL", reason="suppress the whole package",
                      package="systeminformation")

    result = evaluate(findings, Policy(), kev, EpssScores.empty(), [sup], base,
                      today=date(2026, 7, 23))
    assert result.blocked, "KEV must block despite suppression + inheritance"
