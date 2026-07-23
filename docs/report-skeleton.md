<!-- DRAFT: raw material for the author to write the technical report from. NOT the report. -->

# Technical report — skeleton and raw material

Per `PLAN.md` §5: **the author writes the report.** This file is the raw material
— every measurement, table, and rejected alternative — so the prose can be
written without re-deriving anything. `DEFENSE.md` and this file overlap by
design. Target length 6–12 pages, LaTeX, PDF committed to `docs/`.

---

## 1. Abstract (150 words) — to write

Cover: the signal-to-noise problem in CI security gates; the delta+KEV+EPSS+
fix-availability model; the headline result (1015→242 on trudesk, 0 KEV, EPSS
catching below-floor OpenSSL CVEs); the portability claim (reused across the
later portfolio repos).

## 2. Background and motivation

- Scanners are commodity; the gate policy is not. A HIGH+-only gate is disabled
  by developers within weeks — cite the practitioner consensus, and frame it as
  the alert-fatigue problem.
- Regulatory push making inventory/gating real: NIS2, EU CRA (relevant for the
  consulting angle). SBOM mandates (US EO 14028) motivate the Syft step.
- Why *this* target: Stage-A selection (`tuning-record.md`) — trudesk chosen over
  mongo-express on finding volume (20× app-dep findings, a real OS Critical).

## 3. Threat model (state formally)

Lift from README "Problem statement & threat model" and make it precise:
- Assets: the merge (integrity of what lands on main), CI secrets, the release
  artifact/SBOM.
- Adversary capabilities: PR contributor, compromised dependency, compromised
  third-party action; NOT a malicious maintainer.
- Trust boundary: findings trusted, thresholds re-derived; KEV/EPSS feeds trusted.
- Security properties claimed: (a) no *new* exploitable finding merges silently;
  (b) any KEV blocks unconditionally; (c) the pipeline's own supply chain is
  pinned; (d) fail-toward-blocking on ambiguity.

## 4. Design and implementation — decisions AND rejected alternatives

**This is the section interviewers probe. It is the densest part of `DEFENSE.md`.**
Pull directly from the decision log:

- **D0** gate as Python package vs. (rejected) bash-in-YAML / OPA-Rego / each
  scanner's own `--fail-on`. Why owning the cross-cutting logic is the point.
- **D1** one-owner-per-domain layer split; the OSV(441)/Trivy(402) delta as the
  justification; why double-gating corrupts the funnel.
- **D2** SHA/digest pinning; the tj-actions/changed-files compromise; the
  immutability-vs-staleness tradeoff and the Dependabot mitigation.
- **D3** three-workflow topology; why check out the gate into `_gate/` vs.
  (rejected) publish to PyPI / vendor the YAML.
- **D4** merge-base delta by re-scanning the base ref vs. (rejected) source diff;
  why a lockfile diff cannot tell you a dependency vuln is new.
- **D5** least-privilege; signing isolated to a push-on-main job so fork PRs never
  see the OIDC token.
- Engine precedence design: why KEV is unconditional and unsuppressable; why EPSS
  escalates only; the fix-availability relaxation and its exceptions; why UNKNOWN
  severity sorts below LOW. (All five have worked answers in `DEFENSE.md` §3.)

## 5. Evaluation — numbers, tables, plots

All real, all in `examples/evidence/` and `TUNING.md`:

- The triage funnel: 1015 → 974 → 572 → 243 → 242. (Figure: `docs/figures/triage-funnel.svg`.)
- Per-domain block/report matrix (`scan-manifest.json`): deps 227/214, image_os
  13/10, image_lang 0/402, sast 2/106.
- KEV = 0 across 233 Critical/High.
- EPSS escalation table (§4b of TUNING): CVE-2023-2650 @ 0.751, CVE-2022-4304 @
  0.162 on libssl/libcrypto 1.1.1n.
- EPSS-inert-on-deps result: max below-floor dep EPSS = 0.073 < 0.10 threshold.
- Performance table (TUNING §7): OSV 2.8s, gate 0.56s, Semgrep ~90s/~35s.
- SBOM: 1728 components, CycloneDX 1.6.
- Test suite: 35 tests, precedence coverage.

## 6. Limitations (be unsparing)

From README + `DEFENSE.md` judgement calls:
- Workflows unproven on a hosted runner (JC-3) — the honest headline limitation.
- Line-sensitive code-finding fingerprints.
- No scanner-emptiness assertion (JC-5).
- EPSS/KEV feed correctness inherited, not verified.
- Severity-count reconciliation open (JC-7); Semgrep ruleset drift (149 vs 145).
- Suppression register intentionally empty on the real target — recall traded for
  defensibility.

## 7. Related work / references

- CISA KEV catalog; FIRST EPSS (cite the EPSS paper: Jacobs et al., *Exploit
  Prediction Scoring System*, Digital Threats, 2021).
- CycloneDX spec; SLSA framework; Sigstore/cosign (Newman et al.).
- OSV schema / OSV-Scanner; Semgrep; Trivy; Gitleaks; Hadolint; Syft.
- tj-actions/changed-files incident write-ups (verify a primary source, JC-2).
- Optionally: NIST SSDF (SP 800-218), EO 14028 for the SBOM motivation.

## 8. Conclusion and future work

- Wire Dependabot for action bumps; add the scanner-emptiness assertion; run on a
  hosted runner and publish a real Actions link + badge; reconcile severity
  counts; pin the Semgrep ruleset; extend the reusable workflow to repos A/C/#4/#5.
