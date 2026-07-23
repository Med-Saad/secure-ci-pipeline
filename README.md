<!-- DRAFT: generated, pending author rewrite. Structure and numbers are real; the voice must become the author's before this repo is used in an application. -->

# secure-ci-pipeline

A security-hardened CI pipeline whose real contribution is a **portable gate
engine** that turns five scanners' raw output into an actionable merge decision —
blocking on *new, exploitable, fixable* findings instead of on a wall of CVSS
scores.

[![ci](https://github.com/Med-Saad/secure-ci-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/Med-Saad/secure-ci-pipeline/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![tests](https://img.shields.io/badge/tests-37%20passing-brightgreen)](tests/)

> **Status:** proven on GitHub hosted runners. CI runs pytest, dogfoods the gate
> on this repo (0 blocking), asserts the KEV tripwire blocks, and keyless-signs the
> SBOM with cosign + SLSA provenance. The merge-base delta was verified on a real
> PR (a finding on the base was inherited; a new finding on the head blocked). See
> `docs/DEFENSE.md` §0.

## Demo — the triage funnel

Run against a real, stale target (`polonel/trudesk`, 2402 packages), the gate
takes **1015 raw findings down to 209 blocking** — suppressing 33 findings in
build-only packages (measured absent from the image), blocking a MEDIUM-rated
OpenSSL CVE that a severity floor would miss, while *not* blocking on 233
Critical/High advisories that carry zero known exploitation.

![triage funnel](docs/figures/triage-funnel.svg)

Full reasoning: **[docs/TUNING.md](docs/TUNING.md)**. Evidence:
[`examples/evidence/`](examples/evidence/).

## Problem statement & threat model

**Problem.** Turning on scanners is easy; a gate that fails on every HIGH+ finding
trains developers to disable it. The hard part is signal-to-noise. This project
is the tuning that makes a gate actionable, plus the reasoning to defend every
finding it drops.

**Adversary & assumptions.**
- **In scope:** a contributor (or a compromised dependency/action) introducing an
  exploitable vulnerability, a committed secret, or a known-exploited CVE via a
  pull request; a supply-chain attack on the pipeline's own actions (addressed by
  SHA/digest pinning).
- **Trust boundary:** the gate trusts the scanners' *findings* but not their
  *thresholds* — it re-derives the block/report decision itself. It trusts CISA
  KEV and FIRST EPSS as external feeds.
- **Out of scope:** a malicious maintainer with merge rights; runtime/RASP
  concerns; correctness of the upstream advisory databases; secrets already
  leaked before history begins.
- **Fail direction:** ambiguity fails toward *blocking* (expired suppression
  re-surfaces; unknown fix-status does not relax; unrated severity is report-only
  but KEV still blocks).

## The gate model

A finding **blocks** iff it is **new vs. the merge base** AND **not suppressed**
AND at least one of:

1. it is in the **CISA KEV** catalog → blocks *unconditionally* (no floor, no
   delta, no fix requirement, and it cannot be suppressed);
2. it meets its domain's **severity floor** and (by default) has a fix available;
3. its **EPSS** score is over the escalation threshold (this can pull a
   below-floor finding up, but a low EPSS never pardons one — EPSS only escalates).

One owner per domain: OSV gates app deps, Trivy gates the image OS layer and only
*reports* the overlapping image-language layer, Semgrep/Gitleaks/Hadolint gate
their own domains. Secrets have no severity floor (any secret blocks).

## Quickstart

```bash
git clone <this-repo> && cd secure-ci-pipeline
pip install ".[dev]"      # zero runtime deps; dev extra adds pytest + PyYAML
pytest -q                 # 35 tests, ~0.05s

# Run the gate on scanner outputs you already have:
python -m gate evaluate \
  --osv osv.json --trivy trivy-image.json --semgrep semgrep.sarif \
  --kev kev.json --epss epss.csv.gz \
  --summary summary.md --funnel funnel.csv
# exits 1 iff the gate blocks
```

Reproduce the trudesk evidence and chart from raw scans:
`python scripts/build_evidence.py …` (invocation in the script header).

## Architecture

```
scanners ──▶ adapters ──▶ normalized Finding ──▶ engine ──▶ Verdict + funnel
(OSV,Trivy,   (one per      (domain, severity,   (KEV │ suppress │ delta │
 Semgrep,      tool, pure    KEV, EPSS, fix,       floor │ EPSS │ fix-avail)
 Gitleaks,     load())       fingerprint)
 Hadolint)
```

- **Portable core** (`gate/`): dependency-free Python, unit-tested, KEV/EPSS
  injected so it is offline-testable. Runs identically in CI and on a laptop.
- **Three workflows:** a reusable `workflow_call` core, a self-scan that dogfoods
  this repo (the badge), and a `workflow_dispatch` full audit of the pinned
  target. All actions SHA-pinned, all scanner images digest-pinned.

Details and rejected alternatives: **[docs/DEFENSE.md](docs/DEFENSE.md)**.

## Results (real, on trudesk @29f3f16)

| Metric | Value |
|---|---|
| Raw findings → blocking | 1015 → **209** |
| Measured build-only suppressions | 19 packages / 33 findings (absent from image) |
| CISA KEV matches on target | **0** (of 233 Critical/High) |
| EPSS-escalated below-floor blocks | 4 (OpenSSL; CVE-2023-2650 @ EPSS 0.751) |
| SAST scoping | 149 → 108 (first-party only) |
| Report-only image-lang layer | 402 (overlaps deps; not gated) |
| Gate runtime (over minutes of scanning) | **0.56 s** |
| SBOM | 1728-component CycloneDX 1.6 ([sample](examples/evidence/sbom-trudesk.cdx.json)) |

## Limitations

- **The external-target path is not yet CI-proven.** The self-scan path (incl.
  the delta on a real PR) is green on hosted runners; the `target-scan.yml` audit
  of trudesk has only been run locally. See `docs/DEFENSE.md` §0 / JC-3.
- **Code-finding fingerprints are line-sensitive.** Dependency findings are
  line-independent; SAST/Dockerfile delta can miss a moved-but-identical finding.
- **EPSS/KEV correctness is inherited** from external feeds; the gate does not
  second-guess them.
- **No scanner-emptiness assertion yet** — a scanner that silently returns zero
  (parse failure) reads as "clean" (JC-5).
- **Severity-count reconciliation** pending (26/202 vs 29/204; JC-7).

## References

- CISA Known Exploited Vulnerabilities Catalog — <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- FIRST EPSS — <https://www.first.org/epss/>
- CycloneDX SBOM specification — <https://cyclonedx.org/>
- SLSA supply-chain framework — <https://slsa.dev/>
- Sigstore / cosign keyless signing — <https://docs.sigstore.dev/>
- OSV / OSV-Scanner — <https://osv.dev/>
- tj-actions/changed-files compromise (2025-03-14) — the case for SHA-pinning actions.

## License

Apache-2.0 — see [LICENSE](LICENSE).
