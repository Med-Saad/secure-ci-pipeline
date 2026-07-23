"""ci-gate: a portable security-CI gate.

The pipeline's scanners (OSV-Scanner, Trivy, Semgrep, Gitleaks, Hadolint) each
emit findings in their own format. This package normalises those into a single
`Finding` model and applies one gate policy across all of them:

    block iff  new-vs-merge-base  AND  not-suppressed  AND (
                   is-KEV                                   # unconditional
                 OR meets-severity-floor (with fix-avail)   # actionable floor
                 OR EPSS-escalated                          # real-world urgency
               )

KEV always blocks and cannot be suppressed; EPSS only escalates, never relaxes.
The engine is pure and dependency-free so it runs on a clean runner and is
unit-testable without network access — KEV and EPSS data are injected.
"""

from .models import Domain, Finding, Severity, Decision, GateResult

__all__ = ["Domain", "Finding", "Severity", "Decision", "GateResult"]
