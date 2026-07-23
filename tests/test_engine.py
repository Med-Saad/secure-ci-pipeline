"""Precedence tests for the gate — the core of the project.

Each test isolates one rule of the precedence in engine.evaluate_one.
"""

from datetime import date

import pytest

from gate.diff import Baseline
from gate.engine import evaluate, evaluate_one
from gate.epss import EpssScores
from gate.kev import KevCatalog
from gate.models import Decision, Domain, Finding, Package, Severity
from gate.policy import Policy
from gate.suppress import Suppression

TODAY = date(2026, 7, 23)


def dep(rule_id="GHSA-x", sev=Severity.HIGH, cves=("CVE-2222-0001",),
        fix=True, pkg="lodash", ver="1.0.0"):
    return Finding(
        domain=Domain.DEPS, tool="osv", rule_id=rule_id, severity=sev,
        identifiers=frozenset({rule_id, *cves}),
        package=Package(pkg, ver), location=f"yarn.lock:{pkg}@{ver}",
        fix_available=fix,
    )


def gate_one(f, policy=None, kev=None, epss=None, sups=None, baseline=None):
    return evaluate_one(
        f,
        policy or Policy(),
        kev or KevCatalog.empty(),
        epss or EpssScores.empty(),
        sups or [],
        baseline or Baseline.empty(),
        TODAY,
    )


# --- KEV: unconditional --------------------------------------------------------

def test_kev_blocks_even_when_below_floor():
    f = dep(sev=Severity.LOW, cves=("CVE-2021-21315",))
    kev = KevCatalog(frozenset({"CVE-2021-21315"}))
    r = gate_one(f, kev=kev)
    assert r.decision is Decision.BLOCK
    assert "KEV" in r.reason


def test_kev_cannot_be_suppressed():
    f = dep(sev=Severity.LOW, cves=("CVE-2021-21315",))
    kev = KevCatalog(frozenset({"CVE-2021-21315"}))
    sup = Suppression(id="SUP-1", reason="try to hide it", rule_id="GHSA-x")
    r = gate_one(f, kev=kev, sups=[sup])
    assert r.decision is Decision.BLOCK  # suppression is ignored for KEV
    assert r.suppression_ref is None


def test_kev_blocks_even_if_inherited():
    f = dep(sev=Severity.LOW, cves=("CVE-2021-21315",))
    kev = KevCatalog(frozenset({"CVE-2021-21315"}))
    base = Baseline(frozenset({f.fingerprint()}))
    r = gate_one(f, kev=kev, baseline=base)
    assert r.decision is Decision.BLOCK


# --- Suppression ---------------------------------------------------------------

def test_suppression_blocks_by_package():
    f = dep(sev=Severity.CRITICAL)
    sup = Suppression(id="SUP-2", reason="vendored, not shipped", package="lodash")
    r = gate_one(f, sups=[sup])
    assert r.decision is Decision.SUPPRESSED
    assert r.suppression_ref == "SUP-2"


def test_expired_suppression_does_not_apply():
    f = dep(sev=Severity.CRITICAL)
    sup = Suppression(id="SUP-3", reason="stale", package="lodash",
                      expires=date(2020, 1, 1))
    r = gate_one(f, sups=[sup])
    assert r.decision is Decision.BLOCK  # re-surfaces (fails toward blocking)


def test_empty_match_suppression_is_rejected_at_load():
    from gate.suppress import _parse_entry
    with pytest.raises(ValueError):
        _parse_entry({"id": "SUP-4", "reason": "x", "match": {}})


# --- Delta ---------------------------------------------------------------------

def test_inherited_finding_does_not_block():
    f = dep(sev=Severity.CRITICAL)
    base = Baseline(frozenset({f.fingerprint()}))
    r = gate_one(f, baseline=base)
    assert r.decision is Decision.INHERITED


def test_delta_disabled_blocks_inherited():
    f = dep(sev=Severity.CRITICAL)
    base = Baseline(frozenset({f.fingerprint()}))
    pol = Policy()
    pol.delta_enabled = False
    r = gate_one(f, policy=pol, baseline=base)
    assert r.decision is Decision.BLOCK


# --- Floor / EPSS / fix-availability ------------------------------------------

def test_below_floor_low_epss_is_reported():
    f = dep(sev=Severity.MEDIUM)
    r = gate_one(f)
    assert r.decision is Decision.REPORT


def test_epss_escalates_below_floor_finding():
    f = dep(sev=Severity.MEDIUM, cves=("CVE-2222-9999",))
    epss = EpssScores({"CVE-2222-9999": (0.5, 0.99)})
    r = gate_one(f, epss=epss)
    assert r.decision is Decision.BLOCK
    assert "EPSS" in r.reason


def test_low_epss_never_relaxes_above_floor():
    # HIGH with a tiny EPSS still blocks — EPSS only escalates.
    f = dep(sev=Severity.HIGH, cves=("CVE-2222-1111",))
    epss = EpssScores({"CVE-2222-1111": (0.0001, 0.01)})
    r = gate_one(f, epss=epss)
    assert r.decision is Decision.BLOCK


def test_fix_unavailable_relaxes_floor_only_block():
    f = dep(sev=Severity.HIGH, fix=False)
    r = gate_one(f)
    assert r.decision is Decision.REPORT
    assert "no fix available" in r.reason


def test_fix_unavailable_does_not_relax_epss_block():
    f = dep(sev=Severity.MEDIUM, fix=False, cves=("CVE-2222-3333",))
    epss = EpssScores({"CVE-2222-3333": (0.9, 0.99)})
    r = gate_one(f, epss=epss)
    assert r.decision is Decision.BLOCK  # urgency beats actionability


def test_unknown_fix_status_does_not_relax():
    f = dep(sev=Severity.HIGH, fix=None)
    r = gate_one(f)
    assert r.decision is Decision.BLOCK  # only explicit False relaxes


def test_require_fix_available_can_be_disabled():
    f = dep(sev=Severity.HIGH, fix=False)
    pol = Policy()
    pol.require_fix_available = False
    r = gate_one(f, policy=pol)
    assert r.decision is Decision.BLOCK


# --- Domain policy -------------------------------------------------------------

def test_image_lang_is_report_only():
    f = Finding(domain=Domain.IMAGE_LANG, tool="trivy", rule_id="CVE-2021-3807",
                severity=Severity.HIGH, identifiers=frozenset({"CVE-2021-3807"}),
                package=Package("ansi-regex", "3.0.0"), fix_available=True)
    r = gate_one(f)
    assert r.decision is Decision.REPORT
    assert "report-only" in r.reason


def test_image_lang_kev_still_blocks():
    f = Finding(domain=Domain.IMAGE_LANG, tool="trivy", rule_id="CVE-2021-21315",
                severity=Severity.LOW, identifiers=frozenset({"CVE-2021-21315"}),
                package=Package("systeminformation", "5.3.0"))
    kev = KevCatalog(frozenset({"CVE-2021-21315"}))
    r = gate_one(f, kev=kev)
    assert r.decision is Decision.BLOCK  # KEV overrides report-only


def test_secret_blocks_with_no_floor():
    f = Finding(domain=Domain.SECRET, tool="gitleaks", rule_id="generic-api-key",
                severity=Severity.HIGH, location="fp")
    r = gate_one(f)
    assert r.decision is Decision.BLOCK


# --- Aggregate result ----------------------------------------------------------

def test_evaluate_builds_monotonic_funnel():
    findings = [
        dep(rule_id="GHSA-crit", sev=Severity.CRITICAL, pkg="a"),
        dep(rule_id="GHSA-high", sev=Severity.HIGH, pkg="b"),
        dep(rule_id="GHSA-med", sev=Severity.MEDIUM, pkg="c"),
        dep(rule_id="GHSA-nofix", sev=Severity.HIGH, pkg="d", fix=False),
    ]
    res = evaluate(findings, Policy(), KevCatalog.empty(), EpssScores.empty(), [],
                   Baseline.empty(), TODAY)
    f = res.funnel
    assert f["raw"] == 4
    assert f["new_vs_base"] >= f["meets_policy"] >= f["blocking"]
    assert f["blocking"] == 2          # crit + high; med below floor, nofix relaxed
    assert res.blocked is True
