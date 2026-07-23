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

---

## 2. Suppression register

_(populated as suppressions are added; every entry carries file:line, the
surrounding code, and a confidence label — see TUNING.md for the narrative)_

Nothing suppressed yet.

---

## 3. Interview questions per component

_(five per component, added as each component lands)_

---

## 4. Judgement calls to verify

Running list for the author's catch-up pass. Each is a place where a reasonable
choice was made autonomously and should be confirmed.

- **JC-1.** Architecture D0: gate logic in Python, not Rego/OPA. Confirm you are
  happy defending "why not OPA" in a consulting interview (the honest answer is
  "size"; a NIS2/CRA consultant might expect policy-as-code in a standard
  engine). `[decision recorded, low regret]`
