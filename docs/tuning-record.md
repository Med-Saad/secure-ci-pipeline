# Tuning record — secure CI/CD pipeline

The deliverable of this project is *this record*: the reasoning behind each gate
decision, backed by measured scan output. The tool list is incidental.

## Gate model (the thing being tuned)

- **Block only on findings that are new vs. the merge base**, above a severity
  floor, and not suppressed. A finding present on the base branch is inherited
  debt, not a regression the PR introduced.
- **Always block on CISA KEV**, unconditionally — no severity floor, no delta,
  no EPSS relaxation. Known-exploited is known-exploited.
- **EPSS escalates only, never relaxes.** A high EPSS can pull a
  below-floor finding above the line; a low EPSS never pardons one above it.
- **Layer split:** OSV-Scanner *gates* application dependencies (lockfiles).
  Trivy runs *report-only* on the same built image's language layer to publish
  the manifest-vs-image delta, and *gates* the image OS layer.
- `fetch-depth: 0` in CI so the merge base is reachable for a reliable diff.

## Target decision — LOCKED 2026-07-23

**Target: `trudesk`. Fallback: `mongo-express`.**

Criterion zero (does it build) eliminated neither — both build clean locally
under Docker, contradicting the earlier prediction that trudesk would fail on
node-gyp and mongo-express on a pinned `bash=5.1.16-r2` against EOL Alpine 3.16.
So the decision rests on finding volume, where the split is decisive.

### Measured scan matrix (2026-07-23, local)

| Signal | trudesk | mongo-express |
|---|---:|---:|
| OSV app deps — vuln entries / affected pkgs | **441 / 185** | 22 / 14 |
| OSV — distinct CVEs | 242 | 19 |
| OSV — Critical / High | 29 / 204 | 1 / 10 |
| Trivy image — node-pkg layer | 402 | 46 |
| Trivy image — Alpine OS layer (gated) | 23 (1 C / 8 H) | 12 (0 C / 2 H) |
| Semgrep — unscoped findings | 145 | 31 |
| Semgrep — scoped to app source | 91 (`src/`) | 19 (`lib/`) |
| **CISA KEV overlap — all layers** | **0** | **0** |
| Yarn Berry lockfile parse | ✅ v6 (Yarn 3) | ✅ v8 (Yarn 4) |

trudesk gives the gate real work: ~20× the app-dep findings, a genuine OS-layer
CRITICAL that mongo-express lacks, a non-trivial merge-base delta, and live EPSS
signal (of 80 sampled CVEs, 67 at EPSS ≥ 0.01; top CVE-2022-2564 at 0.327 /
98.2nd percentile).

## Findings

### F1 — Zero known-exploited vulnerabilities is the empirical case against severity-only gating

trudesk's `yarn.lock` resolves **2402 packages**, roughly three years stale,
carrying **437 vulnerabilities** (185 affected packages; 29 Critical, 204 High)
— and **zero** appear in the CISA KEV catalog. Same result at every layer for
both candidates: KEV overlap is 0 across OSV app-deps and Trivy image/OS.

A wall of 200+ High/Critical with no known-exploited signal is exactly the noise
a severity-floor-only gate would dump on a reviewer. It is the argument for the
delta + KEV + EPSS model: the delta strips inherited debt, KEV forces action on
what is actually being exploited, and EPSS ranks the rest by real-world
probability rather than CVSS theater.

### F2 — The OSV/Trivy layer split is justified by a measured delta

OSV sees **441** on the source `yarn.lock`; Trivy sees **402** node-pkg on the
*built image*. The difference is a real manifest-vs-image delta (build-time
pruning, transitive resolution, dev-dep stripping) — precisely the report-only
comparison the design publishes. The split is not redundant tooling; each side
sees something the other does not.

### F3 — Yarn Berry parsing is not a constraint on the choice

The load-bearing worry was that OSV-Scanner would silently return zero on a Berry
lockfile. It does not: it parsed trudesk's `__metadata: version 6` (Yarn 3) and
mongo-express's `version 8` (Yarn 4), normalizing both into OSV's `npm`
ecosystem, with full package resolution (2402 and 1008 packages). The non-zero
counts prove a real parse, not a silent skip.

### F4 — KEV rule cannot fire organically; exercised by a synthetic tripwire

Because F1 holds (0 KEV on the real target), the `always block on KEV` rule has
no natural trigger in this codebase. Rather than ship an unexercised rule, a
**synthetic tripwire fixture** lives at `tests/fixtures/kev-tripwire/`, pinning
`systeminformation@5.3.0` → **CVE-2021-21315** (GHSA-2m8v-572m-ff2v), a real
npm-ecosystem KEV entry added to the catalog **2022-01-18**. Verified: OSV-Scanner
flags the pin, and CVE-2021-21315 is in the KEV catalog, so scanning the fixture
must block via the KEV path regardless of every other knob.

The fixture is quarantined to `tests/fixtures/` and never merged into trudesk's
real manifest, so the target's scan counts stay reproducible against its upstream
commit. (The old pin also carries unrelated advisories; the KEV assertion targets
CVE-2021-21315 specifically.) See the fixture README for the refresh procedure.

### F5 — The fallback carries its own historical KEV (context only)

`mongo-express` itself has a KEV entry: **CVE-2019-10758** (RCE, pre-0.54.0),
added 2021-12-10. The shipped/scanned version is patched, so it does not appear
in the fallback's dependency scan — noted only so the fact isn't rediscovered as
a surprise if mongo-express is promoted from fallback.

## Environment (for reproduction)

- WSL2 Ubuntu; Docker working.
- OSV-Scanner 2.4.0 (`~/tools/osv-scanner`), Semgrep 1.171.0 (pipx),
  Trivy 0.72.0 (via `aquasec/trivy:latest` container), jq, gh.
- Repos cloned shallow at `~/recon/trudesk` and `~/recon/mongo-express`.
- Built images `recon-trudesk:latest`, `recon-mongo:latest` scanned by Trivy.
- Recon workflow: `.github/workflows/recon.yml` — **removed after target selection**
  (its own header instructed deletion once a target was chosen; it was a
  deliberately tag-pinned throwaway and became a source of self-scan findings).
  Preserved in git history; the matrix above is its output.

## Open / next

- [ ] **GitHub Actions clean-runner confirmation.** Needs `gh auth login`
  (interactive) — `gh` is currently unauthenticated. Then create the public repo
  and run the Actions recon to confirm counts reproduce on a clean hosted runner.
  Decision does **not** wait on this; it is confirmation, not a gate.
- [ ] Wire the `kev-tripwire` fixture into a CI assertion (scan must fail on it).
