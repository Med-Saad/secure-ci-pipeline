"""Suppression file loading (JSON always; YAML when PyYAML present)."""

from datetime import date

from gate.models import Domain
from gate.suppress import load_suppressions

YAML_DOC = """
suppressions:
  - id: SUP-YAML-1
    reason: "vendored copy under third_party/, not shipped in the image"
    expires: "2026-12-31"
    match:
      domain: deps
      package: left-pad
"""


def test_yaml_suppression_loads_and_matches(tmp_path):
    import importlib.util
    if importlib.util.find_spec("yaml") is None:  # pragma: no cover
        import pytest
        pytest.skip("PyYAML not installed")

    p = tmp_path / "suppressions.yml"
    p.write_text(YAML_DOC)
    sups = load_suppressions(p)
    assert len(sups) == 1
    s = sups[0]
    assert s.id == "SUP-YAML-1"
    assert s.domain is Domain.DEPS
    assert s.package == "left-pad"
    assert s.expires == date(2026, 12, 31)
    assert not s.is_expired(date(2026, 7, 23))


def test_json_suppression_needs_no_yaml(tmp_path):
    p = tmp_path / "suppressions.json"
    p.write_text('{"suppressions":[{"id":"S1","reason":"r","match":{"rule_id":"GHSA-x"}}]}')
    sups = load_suppressions(p)
    assert len(sups) == 1 and sups[0].rule_id == "GHSA-x"


def test_missing_file_is_empty():
    assert load_suppressions(None) == []
    assert load_suppressions("/nonexistent/path.yml") == []


def test_committed_example_and_trudesk_suppressions_are_valid():
    """The committed suppression files must always parse (a bare @scoped package
    name is a YAML token and must be quoted — this guards that regression)."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    ex = load_suppressions(root / "examples" / "suppressions.example.yml")
    assert len(ex) == 2
    tru = load_suppressions(root / "examples" / "suppressions.trudesk.yml")
    assert len(tru) == 19
    # every entry has a reason and a concrete match (never an empty match)
    for s in tru:
        assert s.reason and s.package and s.domain is not None
    # the @scoped names round-trip
    assert any(s.package == "@angular/compiler" for s in tru)
