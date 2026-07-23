<!-- DRAFT: generated, pending author rewrite -->

# DEFENSE.md — reasoning of record

This file is the reasoning behind the repository. The deliverables (workflows,
gate engine, docs) are recoverable by reading the code; the *why* is not. This
is the file to read before an interview, and the file the author uses to verify
or overturn every autonomous decision on the catch-up pass.

It is maintained **continuously**, not at the end. Four running sections:

1. **Decision log** — every significant decision, the alternatives, why rejected.
2. **Suppression register** — every suppression: finding, file, line, surrounding
   code, and the reasoning that makes it safe, *with a confidence label*.
3. **Interview questions** — five per component, with answers.
4. **Judgement calls to verify** — the running list the author checks first.

**Confidence labels** used throughout: `[measured]` (rests on scan output or a
test), `[high]`, `[medium]`, `[low]` (rests on inference about code semantics —
the author should re-derive before trusting it in a room).

---

## 1. Decision log

### D0 — What "the pipeline" is, and how it relates to trudesk

**Decision.** The deliverable is a **portable gate engine** (a small Python
package, `gate/`) plus a **reusable GitHub Actions workflow** that drives the
scanners into it. The scan *target* (trudesk) is an input, never hardcoded into
the engine.

The engine is exercised three ways, all sharing one gate implementation:

- **Self-scan (dogfood).** Runs on this repo's own pushes/PRs. Produces the CI
  badge. Proves the pipeline runs green on a clean repo and blocks the planted
  secret / KEV tripwire.
- **Reusable workflow (`workflow_call`).** The portable artifact the plan calls
  for — later repos (A, C, #4, #5) call it instead of copying YAML.
- **Target-scan (`workflow_dispatch`).** Checks out trudesk at the pinned SHA and
  runs the full gate, producing the real-code evidence for `TUNING.md` and the
  triage funnel.

**Alternatives considered.**

- *Hardcode the pipeline to scan trudesk only.* Rejected: the plan (§1, §2B)
  requires the pipeline be reused across four later repos. A target-specific
  pipeline is a demo, not infrastructure.
- *A monolithic bash gate inside the workflow YAML.* Rejected: the gate model
  (delta vs. merge-base, KEV-unconditional, EPSS-escalate-only, suppression,
  fix-available) is real logic with edge cases. Logic that must be *defended
  line by line* (Golden Rule) and *tested* does not belong in step-script bash;
  it belongs in a Python package with unit tests. YAML orchestrates; Python
  decides.
- *Use an off-the-shelf policy engine (OPA/Rego, or each scanner's own
  `--fail-on`).* Rejected: no single scanner's threshold expresses the model —
  none of them do "new-vs-merge-base AND (severity floor OR KEV OR high-EPSS)
  AND not-suppressed". The whole differentiator of this project (§2B: "the
  differentiator is tuning, not tooling") lives in that cross-cutting logic, so
  owning it is the point, not a cost. OPA/Rego would be a reasonable alternate
  home for the *policy* but adds a second language to defend for no gain at this
  size.

**Confidence:** `[high]` on the architecture; it follows directly from the plan.

### D1 — Which findings the gate *owns* vs. reports (layer split)

**Decision.** Carried from Stage A and the tuning record, restated here because
the engine encodes it:

- **OSV-Scanner gates** application dependencies (the lockfile).
- **Trivy gates** the image **OS layer**.
- **Trivy is report-only** on the image **language layer** (it overlaps OSV; the
  delta between them is published, not gated — see tuning record F2).
- **Semgrep, Gitleaks, Hadolint** gate their own domains (SAST, secrets,
  Dockerfile) under the same delta+floor+suppression rules; **secrets and KEV
  never get a severity floor** — any secret blocks, any KEV blocks.

**Alternative:** gate every layer of every tool. Rejected: double-gating the
language layer (OSV + Trivy-fs) double-counts the same CVE and makes the funnel
lie. One owner per domain keeps the numbers honest.

**Confidence:** `[measured]` — the OSV(441)/Trivy-fs(402) delta is real (F2).

### D2 — Every action pinned to a SHA, every scanner image to a digest

**Decision.** In the three production workflows, `actions/*`, `github/codeql-action`,
`sigstore/cosign-installer`, `anchore/sbom-action`, and `actions/attest-build-provenance`
are pinned to full commit SHAs (version in a trailing comment); Trivy, Hadolint,
and Gitleaks images are pinned to `@sha256:` digests. Scanner CLIs (Semgrep, OSV)
are pinned to exact versions.

**Why.** On 2025-03-14 `tj-actions/changed-files` was compromised: an attacker
force-updated the tags (including `@v44` and others) to point at a malicious
commit that dumped runner memory — leaking CI secrets from thousands of repos
that trusted a mutable tag. A pipeline whose job is to *close* supply-chain holes
cannot itself depend on mutable references. A SHA is immutable; a tag is not.

**Cost, stated honestly.** SHA pins do not auto-update, so they rot — a pinned
action misses security patches until someone bumps it. The standard mitigation is
Dependabot's `github-actions` ecosystem, which opens PRs to move the SHA while
preserving the pin. That is noted as future work (not wired, since CI isn't live
yet). This is the real tradeoff an interviewer will probe: immutability vs.
staleness, resolved in favour of immutability + a bump bot.

**Confidence:** `[high]`. The incident is real (JC-2 records the "verify the date"
check).

### D3 — Three-workflow topology, one gate implementation

**Decision.**
- `security-scan.yml` — `workflow_call`, the portable core. Checks out the gate
  tooling (this repo) into `_gate/`, `pip install`s it, checks out the *scan
  target* separately, runs the scanners, and calls `python -m gate`.
- `ci.yml` — `push`/`pull_request`: runs pytest, then calls the reusable workflow
  to scan *this* repo (dogfood → the badge), then a `main`-only `sign` job.
- `target-scan.yml` — `workflow_dispatch`: full audit of trudesk at its pinned SHA.

**Why check out the gate into `_gate/` rather than `pip install` from PyPI.** The
gate isn't published to PyPI, and vendoring the YAML into every later repo would
fork the logic. Installing the package from its own repo keeps one implementation
that A/C/#4/#5 all call. **Alternative rejected:** a published PyPI package —
premature at this size and adds a release process to maintain.

**Confidence:** `[high]` on topology; `[medium]` that the cross-repo `_gate`
checkout + `pip install ./_gate` works exactly as written on a hosted runner —
this is JC-3, the untested-on-real-runner gap (gh is unauthenticated locally).

### D4 — Merge-base delta via a base-ref worktree scan

**Decision.** On `pull_request`, the workflow adds a git worktree at
`pull_request.base.sha`, re-runs OSV + Semgrep there, and exports the base
fingerprints via `ci-gate baseline`. The main evaluation passes `--baseline`, and
the engine demotes any finding whose fingerprint is on the base to INHERITED.

**Why re-scan the base rather than diff the source.** A source diff cannot tell
you whether a *dependency* vuln is new — a lockfile line can be unchanged while a
new advisory lands against it, or changed while the vuln is identical. Scanning
both refs and diffing *findings* (by fingerprint) is the only way to answer "did
this PR introduce this?" honestly. **Cost:** it roughly doubles scan time on PRs;
acceptable because it only runs the two cheap scanners (OSV, Semgrep), not the
image build.

**Confidence:** `[high]` on the approach; `[medium]` on the exact worktree
commands under all PR event shapes (JC-4).

### D5 — Least privilege, signing isolated

**Decision.** The scan job requests only `contents: read` +
`security-events: write`. `id-token: write` / `attestations: write` live *only* in
the `sign` job, which runs on push-to-main (never on fork PRs). So a malicious PR
can never reach the OIDC token that keyless signing uses.

**Confidence:** `[high]`.

---

## 2. Suppression register

_(populated as suppressions are added; every entry carries file:line, the
surrounding code, and a confidence label — see TUNING.md for the narrative)_

**The authoritative trudesk audit applies ZERO suppressions** (TUNING.md §6). This
is deliberate: a suppression is a semantic claim about the target's code, and
verifying trudesk internals well enough to make those claims safely is out of
autonomous scope. A confident-but-wrong suppression is the worst failure mode of
this working mode, so none were written against the real target.

The two entries below live in `examples/suppressions.example.yml` and are
**illustrative only** — they exercise the mechanism and document the format; they
are not applied to any real scan.

| id | target | reason (abridged) | confidence | applied? |
|---|---|---|---|---|
| SUP-EXAMPLE-1 | `deps` pkg `some-dev-only-package` | dev-only build tool, stripped from prod image | `[low]` — needs dep-graph + image verification | no (example) |
| SUP-EXAMPLE-2 | `sast` under `third_party/**` | vendored code owned upstream | `[medium]` scoping / `[low]` per-line | no (example) |

**Judgement call:** if a real user *does* need to suppress a trudesk finding, the
register must gain a real entry with the surrounding code quoted and a confidence
label — that is the audit trail, and it is intentionally empty right now rather
than filled with guesses.

---

## 3. Interview questions per component

### Gate engine (gate/)

1. **Why does UNKNOWN severity sort below LOW, and what breaks if it sorts
   above?** — A floor check is `severity >= floor`. If UNKNOWN outranked LOW, any
   finding a scanner failed to rate would satisfy a LOW floor and could block or,
   worse, be treated as HIGH-adjacent. Sorting it lowest means an unrated finding
   is report-only unless KEV/EPSS escalates it — fail-safe toward *not* blocking
   on noise, while still never hiding a known-exploited one.

2. **KEV blocks even when the finding is inherited from the base branch. Defend
   that against "but it's not this PR's regression."** — The delta rule exists to
   avoid punishing a PR for pre-existing debt. KEV is different in kind: a
   known-exploited vuln is an active incident regardless of who introduced it.
   Letting it ride because "it was already there" is exactly how exploited CVEs
   sit unpatched for months. Inheritance excuses *noise*, not *exploitation*.

3. **Why can EPSS only escalate, never relax?** — EPSS is a probability estimate
   with real error bars. Using a *low* EPSS to pardon a HIGH finding would let a
   model's uncertainty override a concrete severity rating — you'd suppress real
   risk on a prediction. Using a *high* EPSS to escalate a MEDIUM only ever adds
   caution. Asymmetry keeps the model's errors on the safe side.

4. **The fix-availability relaxation downgrades a HIGH with no fix to
   report-only. Isn't that hiding a real vuln?** — It surfaces it (REPORT), it
   does not hide it. The claim is narrower: blocking a *merge* on something the
   developer cannot fix in that PR produces a gate people learn to bypass. So a
   floor-only, no-fix finding is reported; but if EPSS says it's being exploited,
   urgency overrides actionability and it blocks anyway. Unknown fix status does
   NOT relax — only a confirmed "no fix."

5. **A suppression can hide a CRITICAL. What stops it being abused?** — Four
   things: it cannot suppress a KEV finding (hard rule); it requires a written
   reason; it supports an expiry after which the finding re-surfaces (fails toward
   blocking); and every fired suppression is recorded in the gate output with its
   id. The register in this file is the human audit trail. It's a deliberate,
   logged risk acceptance, not a silent mute.

### Pipeline / workflows (.github/workflows/)

1. **Why SHA-pin actions when `@v4` is more maintainable?** — See D2: the
   tj-actions/changed-files compromise (2025-03-14) moved a tag to a malicious
   commit and exfiltrated secrets from every repo trusting that tag. Immutability
   beats convenience for anything running in a privileged CI context; Dependabot
   bumps the pins so you don't lose patches.

2. **Your gate re-scans the merge base on every PR. Why not just diff the
   changed files?** — See D4: a file diff can't tell you a dependency vuln is new
   (a new advisory can land against an unchanged lockfile line). Diffing
   *findings* by fingerprint across two scans is the only honest delta.

3. **Why is OSV gating the language deps but Trivy only reporting them?** — They
   see overlapping sets from different vantage points (source lockfile vs. built
   image). Gating both double-counts the same CVE and corrupts the funnel. One
   owner per domain; the Trivy-vs-OSV delta is published as signal (tuning F2).

4. **What stops a malicious fork PR from stealing your signing token?** — See
   D5: `id-token: write` exists only in the `sign` job, which is gated to
   push-on-main. Fork PRs run the scan job, which holds no write scopes beyond
   code-scanning upload.

5. **Semgrep, Trivy, etc. all run with `continue-on-error: true`. Doesn't that
   let a broken scanner pass the gate silently?** — The scanners are non-fatal so
   one tool's crash doesn't lose the other four's findings, but the *gate* step is
   fatal: it fails the job on a blocking verdict. The risk this trades in is a
   scanner silently producing *no* findings (parse failure looking like "clean").
   That is exactly why the recon stage asserted OSV actually parsed the Berry
   lockfile (non-zero package count) rather than trusting a zero — the same
   defensive check belongs in the gate (tracked as future work, JC-5).

---

## 4. Judgement calls to verify

Running list for the author's catch-up pass. Each is a place where a reasonable
choice was made autonomously and should be confirmed.

- **JC-1.** Architecture D0: gate logic in Python, not Rego/OPA. Confirm you are
  happy defending "why not OPA" in a consulting interview (the honest answer is
  "size"; a NIS2/CRA consultant might expect policy-as-code in a standard
  engine). `[decision recorded, low regret]`
- **JC-2.** Verify the tj-actions/changed-files compromise details before citing
  them in a room (date 2025-03-14, mutable-tag → memory-dump → secret exfiltration).
  Written from training knowledge, not re-checked against a primary source this
  session. `[medium confidence — verify the specifics]`
- **JC-3.** The three workflows have **never run on a hosted runner** — `gh` is
  unauthenticated locally so nothing was pushed. YAML + actionlint are clean, but
  the cross-repo `_gate` checkout, the `pip install ./_gate`, the OSV checksum
  step, and the EPSS `-current.csv.gz` URL are all unverified end to end. This is
  the single biggest untested surface. First real push will shake out issues.
- **JC-4.** The merge-base worktree step (`git worktree add ../base <sha>`) is
  written for the standard `pull_request` event; confirm it behaves on
  `pull_request_target` and on first-PR-to-empty-base cases if those arise.
- **JC-5.** The gate does not yet assert that each scanner *actually produced
  output* (vs. silently emitting zero on a parse failure). Recon did this check
  manually; it should become a gate feature (a `--require-scanners osv,semgrep`
  flag that fails if an expected input is empty). Noted, not built.
- **JC-6.** Pinned action/image versions (checkout v4.2.2, trivy 0.58.1, etc.)
  are current as of 2026-07-23 but not the newest; wire Dependabot
  `github-actions` before relying on them long-term.
- **JC-7.** Severity-count reconciliation: the OSV adapter reports trudesk as
  **26 Critical / 202 High** (from GHSA text severity), vs. the recon record's
  **29 / 204** (a different counting path). Small, but pick one method and make
  the tuning record and the engine agree. `[measured, needs reconciliation]`
