from gate.models import Severity


def test_ordering_and_unknown_below_low():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
    # The load-bearing invariant: an unrated finding must not satisfy a floor.
    assert Severity.UNKNOWN < Severity.LOW
    assert not (Severity.UNKNOWN >= Severity.LOW)


def test_parse_cross_tool_spellings():
    assert Severity.parse("moderate") is Severity.MEDIUM     # npm/GitHub
    assert Severity.parse("ERROR") is Severity.HIGH          # Semgrep/Hadolint
    assert Severity.parse("warning") is Severity.MEDIUM
    assert Severity.parse("style") is Severity.LOW           # Hadolint
    assert Severity.parse("informational") is Severity.LOW
    assert Severity.parse(None) is Severity.UNKNOWN
    assert Severity.parse("nonsense") is Severity.UNKNOWN
