from conftest import SCANS

from gate import adapters
from gate.models import Domain, Severity


def test_osv_adapter_real_tripwire_output():
    fs = adapters.load("osv", SCANS / "osv-kev-tripwire.json")
    assert fs, "expected findings from the tripwire lockfile"
    assert all(f.domain is Domain.DEPS for f in fs)
    # The KEV entry is reachable via its CVE alias even though OSV's primary id
    # is a GHSA — this is what lets the KEV lookup (CVE-keyed) match.
    all_cves = set().union(*(f.cve_ids() for f in fs))
    assert "CVE-2021-21315" in all_cves


def test_trivy_splits_os_from_lang():
    fs = adapters.load("trivy", SCANS / "trivy-image.json")
    os_pkgs = [f for f in fs if f.domain is Domain.IMAGE_OS]
    lang = [f for f in fs if f.domain is Domain.IMAGE_LANG]
    assert {f.rule_id for f in os_pkgs} == {"CVE-2022-37434", "CVE-2022-4904", "CVE-2022-0001"}
    assert [f.rule_id for f in lang] == ["CVE-2021-3807"]
    # FixedVersion "" -> no fix; present -> fix; absent -> unknown.
    by_id = {f.rule_id: f for f in os_pkgs}
    assert by_id["CVE-2022-37434"].fix_available is True
    assert by_id["CVE-2022-4904"].fix_available is False


def test_sarif_severity_from_level_and_property():
    fs = adapters.load("semgrep", SCANS / "semgrep.sarif")
    by_line = {f.line: f for f in fs}
    assert by_line[142].severity is Severity.HIGH      # level "error"
    assert by_line[142].domain is Domain.SAST
    assert by_line[7].severity is Severity.MEDIUM       # level "warning"


def test_gitleaks_never_stores_the_secret():
    fs = adapters.load("gitleaks", SCANS / "gitleaks.json")
    assert len(fs) == 1
    f = fs[0]
    assert f.domain is Domain.SECRET
    # The raw secret value must not leak into our own model.
    blob = repr(f).lower()
    assert "secret" not in f.location or "generic-api-key" in f.location
    assert f.severity is Severity.HIGH  # nominal for ordering


def test_hadolint_levels_map():
    fs = adapters.load("hadolint", SCANS / "hadolint.json")
    by_code = {f.rule_id: f for f in fs}
    assert by_code["DL3002"].severity is Severity.HIGH     # error
    assert by_code["DL3006"].severity is Severity.MEDIUM   # warning
    assert by_code["DL3059"].severity is Severity.LOW      # info
