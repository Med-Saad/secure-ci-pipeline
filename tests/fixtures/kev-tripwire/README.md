# KEV tripwire fixture

A **synthetic** manifest that pins one known-exploited dependency so the gate's
`always block on CISA KEV` rule can be exercised in CI. This directory is the
*only* place the tripwire lives — it is never merged into the target
application's real manifest, so the target's scan counts stay reproducible
against its upstream commit.

## The pinned vulnerability

| Field | Value |
|---|---|
| Package | `systeminformation@5.3.0` (npm) |
| CVE | **CVE-2021-21315** |
| Advisory | GHSA-2m8v-572m-ff2v |
| Affected range | `< 5.3.1` |
| CISA KEV `dateAdded` | **2022-01-18** |
| KEV product string | "Npm package / System Information Library for Node.JS" |
| Verified in OSV | yes — `POST /v1/query {package: systeminformation, version: 5.3.0}` returns the advisory |

## Why this CVE

- It is a **real npm package** with a version OSV-Scanner and Trivy both resolve,
  so the tripwire fires through the normal scan path rather than a mocked result.
- It is a **stable, long-standing KEV entry** (added 2022-01-18), so the fixture
  does not depend on catalog churn.

## Expected gate behavior

Scanning this fixture MUST block the pipeline via the KEV path **regardless of
severity floor, merge-base delta, or EPSS** — KEV is unconditional. If a change
to the gate logic lets this fixture pass, the KEV rule has regressed.

## Refresh note

If CVE-2021-21315 is ever removed from the KEV catalog, replace the pin with
another verified npm-ecosystem KEV entry and update the table above with the new
CVE and its `dateAdded`. Candidates observed 2026-07-23: CVE-2020-11023 (jQuery,
added 2025-01-23), CVE-2019-10758 (mongo-express, added 2021-12-10).
