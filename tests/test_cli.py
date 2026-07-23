"""CLI contract: exit code 1 iff the gate blocks; baseline round-trips."""

import json

from conftest import FIXTURES, SCANS

from gate.cli import main


def test_evaluate_exit_1_when_blocked(tmp_path, capsys):
    out = tmp_path / "gate.json"
    rc = main([
        "evaluate",
        "--osv", str(SCANS / "osv-kev-tripwire.json"),
        "--kev", str(FIXTURES / "kev-snapshot.json"),
        "--json", str(out), "--quiet",
    ])
    assert rc == 1
    data = json.loads(out.read_text())
    assert data["blocked"] is True


def test_no_fail_flag_forces_exit_0(tmp_path):
    rc = main([
        "evaluate",
        "--osv", str(SCANS / "osv-kev-tripwire.json"),
        "--kev", str(FIXTURES / "kev-snapshot.json"),
        "--no-fail", "--quiet",
    ])
    assert rc == 0


def test_strip_prefix_makes_head_and_base_sast_fingerprints_match(tmp_path):
    """Regression: a head scan reports target/x and a base scan base/x. Without
    prefix stripping their SAST fingerprints differ and nothing ever inherits."""
    from gate import adapters
    from gate.cli import _strip_prefixes

    head = adapters.load("semgrep", SCANS / "semgrep.sarif")
    base = adapters.load("semgrep", SCANS / "semgrep.sarif")
    for f in head:
        f.location = "target/" + f.location
    for f in base:
        f.location = "base/" + f.location
    # Before stripping: no overlap.
    assert not ({f.fingerprint() for f in head} & {f.fingerprint() for f in base})
    _strip_prefixes(head, ["target"])
    _strip_prefixes(base, ["base"])
    # After stripping: identical findings fingerprint identically.
    assert {f.fingerprint() for f in head} == {f.fingerprint() for f in base}


def test_baseline_roundtrip_makes_findings_inherited(tmp_path):
    # 1. capture the tripwire's fingerprints as a baseline
    base = tmp_path / "base.json"
    rc = main(["baseline", "--osv", str(SCANS / "osv-kev-tripwire.json"),
               "--out", str(base)])
    assert rc == 0
    fps = json.loads(base.read_text())["fingerprints"]
    assert fps

    # 2. evaluate the same scan against that baseline, WITHOUT KEV data, so the
    #    only thing that could block is a non-inherited finding. Everything is
    #    inherited -> nothing blocks.
    out = tmp_path / "gate.json"
    rc = main(["evaluate", "--osv", str(SCANS / "osv-kev-tripwire.json"),
               "--baseline", str(base), "--json", str(out), "--quiet"])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["funnel"]["inherited"] == data["funnel"]["raw"]
    assert data["blocked"] is False
