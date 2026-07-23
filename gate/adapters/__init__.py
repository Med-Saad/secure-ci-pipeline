"""Scanner adapters: native tool output -> normalised `Finding` list.

Each adapter is a pure function `load(path) -> list[Finding]`. Keeping them
side-effect-free and one-per-tool means a new scanner is a new file, not a
change to the engine.
"""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from . import osv, trivy, sarif, gitleaks, hadolint

# name used on the CLI / in workflows -> loader
REGISTRY = {
    "osv": osv.load,
    "trivy": trivy.load,          # both image classes; splits OS vs lang internally
    "semgrep": sarif.load,        # Semgrep emits SARIF
    "sarif": sarif.load,          # generic SARIF (reusable for other SAST tools)
    "gitleaks": gitleaks.load,
    "hadolint": hadolint.load,
}


def load(tool: str, path: str | Path) -> list[Finding]:
    if tool not in REGISTRY:
        raise KeyError(f"unknown scanner adapter: {tool!r} (have {sorted(REGISTRY)})")
    return REGISTRY[tool](path)


__all__ = ["load", "REGISTRY", "osv", "trivy", "sarif", "gitleaks", "hadolint"]
