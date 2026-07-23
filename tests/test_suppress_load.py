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
