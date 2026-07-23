# Security & PQC Portfolio Plan

Five GitHub repositories with working demos and technical reports — enough breadth for general security roles in Munich, enough depth for crypto and hardware positions.

**Targets:** Infineon, Giesecke+Devrient, Rohde & Schwarz Cybersecurity, genua, secunet, Siemens, BMW, Continental, the consultancies, TUM chair HiWi.

**Realistic timeline:** ~16 weeks part-time. Apply from week 3 onward — do not wait for completion.

---

## EXECUTION MODE — read this first

**This project is currently running autonomously.** The author is in exam period and cannot review incrementally. Claude Code executes project B end to end without waiting for approval on individual decisions.

This changes *how* the work happens. It does not change the standard the work is held to, and it creates one additional obligation.

**Operating rules while autonomous:**

1. **Proceed without asking.** Do not stop for decisions. If something is ambiguous, make the reasonable choice, proceed, and log it in `docs/DEFENSE.md` under "judgement calls to verify."

2. **Stop only for:** anything that would change the agreed architecture; anything requiring credentials or a browser flow the session cannot complete; anything that would modify the scan target's real manifests or otherwise break reproducibility against the pinned upstream SHA.

3. **`docs/DEFENSE.md` is a first-class deliverable.** Maintain it continuously, not at the end. It carries:
   - Every significant decision, the alternatives considered, and why they were rejected.
   - Every suppression: the finding, file and line, the surrounding code, and the reasoning that makes the suppression safe.
   - Five interview questions per component, with answers.
   - A running list of judgement calls the author should verify.

   The deliverables are recoverable by reading the repo. The reasoning is not. This file is the most important thing produced.

4. **Mark generated prose as provisional.** Any README, report section, or narrative document written autonomously gets a top-of-file marker: `<!-- DRAFT: generated, pending author rewrite -->`. See "The catch-up debt" below.

5. **Commit incrementally** in small logical units with real messages. Section 3 is explicit that a few large commits are a tell. Do not batch the work into one commit at the end.

**The catch-up debt.** Section 0's golden rule is not suspended, it is deferred. Everything produced autonomously is owed a review pass before this repo is used in an application. `docs/DEFENSE.md` exists to make that pass an evening rather than a reconstruction. The files that specifically require the author's own rewrite — not editing, rewriting — are the README, the technical report, and the narrative sections of `TUNING.md`.

---

## 0. The Golden Rule

> **If you cannot whiteboard it in an interview, do not merge it.**

Everything below is designed around this. Claude Code can produce a working timing-leakage harness in an afternoon; that is worth nothing if you cannot explain what Welch's t-test is doing in it. A modest repo you can defend line by line beats a sophisticated one you cannot.

**Under autonomous execution this rule becomes a debt rather than a gate.** Work merges without the whiteboard test having been passed. The test still has to happen — it happens on the catch-up pass, against `docs/DEFENSE.md`. A repo that reaches an interview without that pass is worse than no repo, because a project you cannot defend damages you in the room.

A useful weekly check, once normal working resumes: pick a random file from the week's work and explain it out loud, from memory, as if to an interviewer. If you stall, that is your reading list for the week.

---

## 1. Schedule at a Glance

| Weeks | Project | Output | Primary targets |
|---|---|---|---|
| 1–2 | **B — CI/CD Hardening** | Pipeline + `TUNING.md` | DevSecOps, consulting |
| 3–6 | **A — Crypto-Agility Scanner** | Tool + CBOM + findings on real repos | Crypto, consulting, DevSecOps |
| 7–9 | **#4 — Constant-Time Analysis of ML-KEM** | Leakage report + harness | Infineon, G+D, R&S |
| 10–12 | **C — Detection Lab** | Sigma rules + ATT&CK coverage | BMW, SOC roles |
| 13–16 | **#5 — LWE → RLWE → BFV (FHE)** | Working leveled HE scheme | Research, depth signal |

Order rationale: B is fastest to something demonstrable and builds infrastructure the rest reuse. A is the biggest differentiator, so it gets the largest block. #4 sits third because crypto/hardware is your top target — by week 9 you cover DevSecOps, crypto tooling, and crypto implementation. C can wait because your existing CICIDS2017 IDS carries some SOC weight in the interim. #5 is last: highest depth signal, lowest job-market density.

**Autonomous scope is project B only.** Do not begin A, C, #4 or #5 without explicit instruction. They are described here so that B is built to serve them — in particular, B's pipeline is reused across all four later repos and should be portable rather than hardcoded to this target.

---

## 2. The Projects

### B — Security-Hardened CI/CD Pipeline

**Start here.** Mostly configuration, so it will not stall you the way an implementation project can. It also makes Gitleaks and Trivy — already on your CV — genuinely real.

**MVP**
- SAST with Semgrep
- Dependency scanning with Trivy or OSV-Scanner
- Secrets detection with Gitleaks, scanning full history rather than just diffs
- Container image scanning with Trivy
- Dockerfile linting with Hadolint
- SBOM generation with Syft, CycloneDX output
- Build gates on severity thresholds; branch protection with required checks

**Stretch**
- Artifact signing with keyless `cosign` via OIDC
- SLSA provenance attestation
- Policy-as-code: fail only on HIGH+ findings that have a fix available, so the gate stays actionable

**The differentiator is tuning, not tooling.** Anyone can enable five scanners. Your actual deliverable is `TUNING.md`: initial finding count, which were false positives and why, what you suppressed and the justification, resulting count, scan duration before and after. This shows you understand that signal-to-noise is the hard part.

**Under autonomous execution, suppression reasoning is the highest-risk output.** A suppression is a claim about code semantics. Every one goes into `docs/DEFENSE.md` with the finding, the file and line, the surrounding code quoted, and the reasoning — enough that the author can verify or overturn it later without re-deriving the analysis. Where confidence is low, say so explicitly rather than writing a confident-sounding justification.

**Apply the pipeline to your other repos.** Cross-linked repositories read as a coherent body of work rather than scattered exercises. Build it portable for that reason.

**Demo artifact:** the CI badge itself, plus a screenshot of a failing run that catches a deliberately planted secret, plus a public link to a real Actions run.

**Defend:** SBOM vs. CBOM; what SLSA solves; how you handle a false positive without disabling a check; why secrets scanning needs history; the speed-vs-depth tradeoff.

---

### A — Crypto-Agility Scanner / CBOM Generator

**Highest employability-per-hour in this plan.** Enterprises are being pushed into cryptographic inventory by CNSA 2.0, NIS2, and the EU Cyber Resilience Act, and almost nobody has built one. It also evolves directly from your CVE monitor and TLS analyser, which makes it a story rather than a random entry.

**MVP**
- Detect asymmetric primitives in source: RSA, ECDSA, ECDH, DH, DSA
- Cover two ecosystems well — Python (`cryptography`, `pycryptodome`) and Go (`crypto/*`) are the cleanest pair
- Parse X.509 certificates and SSH keys for algorithm and key size
- Parse TLS configs (nginx, Apache) for cipher suites
- Classify into three buckets:
  - **Broken by Shor** — RSA, ECC, DH, DSA
  - **Weakened by Grover** — AES-128, SHA-256 (halved security, not broken)
  - **PQC-ready** — ML-KEM, ML-DSA, SLH-DSA, LMS/XMSS
- Map each finding to its NIST replacement: FIPS 203, 204, 205
- Emit CycloneDX 1.6 CBOM JSON, schema-validated
- Human-readable migration report

**Stretch**
- Risk weighting by data lifetime, modelling harvest-now-decrypt-later exposure
- Detection through dependency manifests, not just direct usage
- Per-finding confidence scoring

**Stack:** Python with `tree-sitter`. Real AST parsing rather than regex is the single biggest quality signal here — a grep-based scanner is a weekend toy, an AST-based one is a tool.

**Differentiator:** run it against three real open-source projects and publish what you found. Actual findings on real code separates a tool from a demo. Handle false positives explicitly — the string `"RSA"` in a comment is not a finding — and report your precision.

**Demo artifact:** terminal GIF of a live scan, plus the generated HTML report published to GitHub Pages so a reviewer can click and see it.

**Defend:** why Shor breaks RSA/ECC but Grover only weakens symmetric crypto, and why AES-256 survives; ML-KEM vs. ML-DSA vs. SLH-DSA and when each applies; what CNSA 2.0 mandates and roughly when; what crypto-agility means and why inventory precedes it; why hybrid (X25519 + ML-KEM) is what actually ships today.

---

### #4 — Constant-Time Analysis of ML-KEM Implementations

Software only, no lab hardware. This is the project that makes you credible to Infineon and G+D specifically, and your *Advanced Cryptographic Implementations* course backs it directly.

**MVP**
- Target reference ML-KEM implementations (`pq-crystals/kyber`, or via `liboqs`)
- Build a `ctgrind`-style harness: mark secret data as uninitialised under Valgrind, so any secret-dependent branch or memory access surfaces as an error
- Add statistical timing analysis in the style of `dudect` — Welch's t-test across two input classes
- Report which functions leak, and why

**Stretch**
- Compare reference vs. AVX2-optimised implementations
- Show a case where compiler optimisation reintroduces a branch the source avoided — this is a genuinely interesting result and interviewers love it
- Extend to ML-DSA

**Differentiator:** most student crypto projects implement something. Almost none *attack* an implementation. Even a negative result ("I found no exploitable leakage in these functions, here is my methodology and its limits") is a strong report, because the methodology is the contribution.

**Demo artifact:** t-test plots committed as PNG, plus a notebook a reviewer can run.

**Defend:** what a timing side channel is and how it becomes a key recovery; why secret-dependent branching and table lookups leak; what Welch's t-test measures here and what it does *not* prove; why constant-time is hard to guarantee across compilers; dudect vs. TVLA.

---

### C — Detection Engineering Lab

Maps onto the BMW detection role and equivalent SOC positions, and is the honest upgrade path for your CICIDS2017 work.

**MVP**
- Docker Compose stack: Wazuh (or Elastic + Filebeat), a victim Linux host, an attacker container
- Generate attacks with Atomic Red Team
- Write Sigma rules, converted with `sigma-cli`
- Map every rule to its MITRE ATT&CK technique ID
- Produce an ATT&CK Navigator layer JSON showing coverage

**Stretch**
- At least one custom rule for a technique Atomic Red Team does not cover, written from your own reading
- Sysmon telemetry if you can run a Windows VM
- Measure time-to-detect

**Differentiator: report your gaps.** A Navigator layer showing twelve techniques covered plus an explicit list of what you cannot detect and why beats any broad coverage claim. Detection engineers respect gap analysis and distrust coverage percentages. Also report false positive rates under benign background activity, not just true positives against your own attacks.

**On your existing IDS project:** don't delete it. Write a short post-mortem on why ML-on-CICIDS2017 results are typically inflated — the dataset has documented labelling errors and generation artifacts that let models learn shortcuts. Publicly critiquing your own earlier work is unusually strong signal and costs one afternoon.

**Demo artifact:** hosted ATT&CK Navigator layer (Navigator loads layers from a URL, so GitHub Pages works), plus screenshots of triggered alerts.

**Defend:** signature vs. anomaly detection and where each fails; why FP rate is the binding constraint in a real SOC; ATT&CK structure (tactics vs. techniques vs. procedures); one technique end to end — attacker action, telemetry produced, rule logic, evasion.

---

### #5 — LWE → RLWE → BFV

Extends the LWE scheme you already built, so the portfolio reads as an arc rather than a scatter. Low job density, high depth signal — this is the project that makes a research group want to talk to you.

**MVP**
- Move from LWE to Ring-LWE: polynomial arithmetic in `Z_q[X]/(X^n + 1)`
- Implement NTT for fast polynomial multiplication
- Build BFV: plaintext encoding in `R_t`, scaling by `Δ = q/t`, keygen, encrypt, decrypt
- Homomorphic addition and multiplication with relinearisation
- **Track the noise budget explicitly** and show how many multiplications you get before decryption fails

**Stretch**
- Modulus switching
- Validate correctness against OpenFHE or SEAL on the same parameters
- A small applied demo: encrypted mean or encrypted linear model inference

**Scope discipline matters here.** Correct add and multiply with noise tracking is a complete project. Do not attempt bootstrapping.

**Demo artifact:** Colab notebook with a badge in the README, so a reviewer runs your scheme in their browser in thirty seconds. Plus a noise-growth plot.

**Defend:** why RLWE rather than plain LWE (key size, efficiency); what the NTT buys you; why multiplication grows noise so much faster than addition; what relinearisation does and why ciphertexts grow without it; what modulus switching is for; why bootstrapping is expensive.

---

## 3. Repository Standard — Definition of Done

Apply this checklist to every repo. A brilliant project in a sloppy repo reads as a student exercise.

**README, in this order**
- [ ] One-sentence description — what it does, immediately
- [ ] Badges: CI status, license, language version
- [ ] **Demo first** — GIF, screenshot, or live link above the fold
- [ ] **Threat model / problem statement** — adversary capabilities, assumptions, what is out of scope. Most student repos have no such section; its presence marks you as a security engineer rather than a hobbyist.
- [ ] Quickstart that works from a clean clone
- [ ] Architecture — short diagram or a few paragraphs
- [ ] **Results table with real numbers** — scan times, detection rates, findings on real code, benchmarks
- [ ] **Limitations** — what it misses, what it gets wrong, known false positive sources
- [ ] Link to the technical report PDF
- [ ] References to primary sources: FIPS 203/204/205, CycloneDX spec, MITRE ATT&CK pages
- [ ] License

**Repository hygiene**
- [ ] Meaningful tests running in CI, with a real badge
- [ ] 25–40 commits developed over weeks, in your own words. Three commits reading "initial commit", "update", "final" is an immediate tell that the work was dumped in at the end.
- [ ] `LICENSE` (MIT or Apache-2.0), `.gitignore`, pinned dependencies
- [ ] `examples/` with committed real output — sample CBOM, sample report, sample rules
- [ ] No dead code, no commented-out blocks, no stray `TODO`s
- [ ] Repo description and topics set on GitHub (people forget these; empty ones look abandoned)

**On any cryptographic code**
- [ ] Prominent disclaimer: *"Educational implementation. Not constant-time, not audited, not for production use."*

That last line signals maturity. Its absence signals you don't know what you don't know — and crypto reviewers check for it specifically.

**Write the README in your own voice.** Reviewers have become good at recognising generated README prose, and it undermines everything below it.

> **Autonomous note.** The README written during autonomous execution is a *structural draft* — it exists so the checklist above is satisfiable and so real numbers are captured while they are fresh. Mark it `<!-- DRAFT: generated, pending author rewrite -->` at the top. The author rewrites the prose before the repo is used in any application. Keep the structure, the tables, and the numbers; the voice is the part that has to change.

---

## 4. Demos — How to Actually Build Them

**The five-minute rule:** a reviewer should get from landing on your repo to seeing real output in under five minutes. Most never clone anything, so the demo has to live in the README.

### Terminal GIFs — for A and #4

Use `vhs` (charmbracelet/vhs). You write a `.tape` script, it renders a GIF, and you **commit the tape file** — meaning your demo is reproducible and regenerable rather than a stale recording. That detail alone reads as senior.

```
# demo.tape
Output docs/demo.gif
Set FontSize 16
Set Width 1200
Type "cqa scan ./examples/target-repo"
Enter
Sleep 3s
```

Alternative: `asciinema` recording piped through `svg-term-cli` to produce an SVG that renders inline in the README and stays crisp.

### Hosted output — for A and C

Turn on GitHub Pages for the repo and publish:
- **Project A:** the HTML migration report from a real scan. One click, reviewer sees the actual product.
- **Project C:** the ATT&CK Navigator layer JSON. Navigator loads layers from a URL, so you can link straight to a rendered coverage map.

### Runnable notebooks — for #4 and #5

Add a Colab badge to the README. A reviewer runs your BFV scheme or your t-test analysis in-browser without installing anything. For a scheme like #5, this is by far the strongest demo available.

### Screenshots and plots — all projects

Commit them to `docs/figures/`. Every project should have at least one chart with real measurements: noise growth per multiplication, t-statistic over sample count, scan time vs. codebase size, detection latency.

For project B under autonomous execution, the chart that matters is the triage funnel: initial finding count per tool → after scoping → after suppression → gate-blocking count. Generate it from real numbers and commit both the plot and the data behind it.

### One-command startup

Every repo gets either `make demo` or `docker compose up` producing visible output. Then **test it in a clean container** — the single most common failure is a quickstart that only works on the author's machine.

```bash
docker run --rm -it -v $(pwd):/repo -w /repo python:3.12 bash
# now follow your own README exactly as written
```

This clean-container test is not optional under autonomous execution, because the author cannot verify the quickstart by hand. Run it, and record the result.

---

## 5. The Technical Report

One per project. 6–12 pages, LaTeX (you have the toolchain), PDF committed to `docs/` and linked from the README.

1. **Abstract** — 150 words
2. **Background and motivation** — why this problem, why now
3. **Threat model** — adversary capabilities, assumptions, scope boundaries, stated formally
4. **Design and implementation** — decisions made *and alternatives rejected*. The rejected alternatives are the most interesting part of any engineering report and the part interviewers probe.
5. **Evaluation** — numbers, tables, plots, real measurements on real inputs
6. **Limitations** — the strongest maturity signal in the document. Be specific and unsparing.
7. **Related work** — five to ten real citations. For PQC, cite the NIST FIPS documents directly rather than blog posts.
8. **Conclusion and future work**

**Write these yourself.** The report is where an interviewer hears your voice and judges whether you understand your own project. Use Claude to critique drafts, tighten prose, and check technical claims — not to author them. A report you didn't write is a liability the moment someone asks about section 4.

> **Autonomous note.** Do not author the report. Produce instead `docs/report-skeleton.md`: the section structure above, populated with the raw material the author needs — every measurement, every table, every rejected alternative with its reasoning, and the citation list. Section 4 in particular should be a dense record of decisions and discarded options, since that is the section interviewers probe and the one that cannot be reconstructed after the fact. The author writes the prose from this skeleton. `docs/DEFENSE.md` and the skeleton will overlap; that is fine.

---

## 6. Working with Claude Code — Autonomous Protocol

The original protocol below assumed incremental review. It is preserved because it is the mode to return to. The autonomous substitute follows it.

**Original protocol (return to this after exams):**

1. **Design before code.** Open each module by asking for the design space, not an implementation. You choose. Record the choice and your reasoning — that becomes section 4 of the report.
2. **Small increments, reviewed.** One module at a time. Read every line before it lands.
3. **Get quizzed.** After each module: *"Ask me five interview questions about the code we just wrote, at the level of an Infineon security engineer. Do not give me the answers first."* If you can't answer, you don't understand your own project yet.
4. **Commit yourself.** Your messages, your increments.
5. **You write the prose.** README, report, and tuning docs are yours. Claude edits.

**Autonomous substitute, in force now:**

1. **Design before code, recorded not discussed.** Still enumerate the design space for each module. Since there is nobody to choose, choose — and write the full option set and the rejection reasoning into `docs/DEFENSE.md`. The author needs the alternatives, not just the outcome.

2. **Small increments, committed not reviewed.** Same granularity as if reviewed. Commit messages carry what a review conversation would have carried: what changed and why this approach.

3. **Quiz in writing.** Per component, write five interview questions at the level of an Infineon or secunet security engineer, *with* answers, into `docs/DEFENSE.md`. These become the author's revision material. Favour questions that probe the reasoning behind a choice over questions that ask what a tool does.

4. **Commit history shape still matters.** 25–40 commits across the project, ordered so the history reads as work developing rather than output landing. Do not squash.

5. **Prose is drafted, not owned.** Structural drafts with real numbers, marked as drafts. The author rewrites. Never present generated prose as finished.

6. **Confidence labelling.** Anywhere a claim rests on inference about code semantics rather than on a measurement — most importantly every false-positive determination — say so and say how confident. A wrong suppression the author knows to check is recoverable. A wrong suppression stated confidently is a trap in an interview.

**Kickoff prompt (for future projects, once normal working resumes):**

```
I'm a cybersecurity master's student at TUM building a portfolio project
for Werkstudent applications in Munich. I need to defend every design
decision in a technical interview.

Project: [name]
Goal: [one sentence]
Scope (MVP): [bullets from this plan]
Stack: [language/tools]

Start by walking me through the design space and the tradeoffs — don't
write code yet. Ask clarifying questions if the scope is ambiguous.
```

**Demo prompt, once the tool works:**

```
Set up a vhs tape file that demos this tool end to end in under 30
seconds, and a GitHub Pages workflow publishing the HTML report from
examples/. Commit the tape file so the demo is reproducible.
```

---

## 7. CV and Profile Integration

**On the CV**
- GitHub URL in the header, beside your email
- Two lines per project: what it does, and one concrete result *with a number*
- Every entry links to its repository
- Reorder per application to lead with the relevant project — two minutes of work, meaningful effect

**On GitHub**
- Pin the repos in priority order
- Profile README: who you are, what you focus on, what you're looking for
- Real bio, TUM affiliation, link to CV

**Per-role selection**

| Target | Lead with |
|---|---|
| Infineon, G+D, R&S | #4 + A |
| BMW, Continental (automotive) | C + B |
| SOC / detection | C + B |
| DevSecOps / AppSec | B + A |
| Consulting (NIS2 / CRA) | A + B |
| TUM chair HiWi | #5 + #4 |

**What a reviewer checks in 90 seconds:** repo description, the top third of the README, whether the demo is visible without cloning, commit history shape, whether tests exist, date of last commit. Optimise for exactly that.

**Sequencing note.** A repo produced autonomously can be listed on the CV as soon as the catch-up pass is done — not before. The gap between "repo exists" and "repo is defensible" is the whole risk of this working mode, and the catch-up pass is what closes it.

---

## 8. Parallel Track — Income Now

The portfolio is a three-to-four month investment. It does not pay rent in the meantime.

- **Apply through ASTRA** (`astra.cit.tum.de`) for winter semester tutoring. Recruitment runs now for an October start. TUM's HiWi office handles international students' documentation as routine business rather than as a compliance exception, which makes it by far the most accessible option while your permit is pending.
- **Check the mytum Schwarzes Brett HiWi board** — individual chairs post positions there that never reach ASTRA.
- A TUM teaching contract is also a real credential when you approach EISEC or Eckert's chair later.

**Start applying to Werkstudent roles in week 3.** One finished repo plus two visibly in progress already beats most applicants, and hiring cycles are slow enough that you'll have three or four done by the time interviews happen.
