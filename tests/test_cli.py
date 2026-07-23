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
