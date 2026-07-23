# examples/

Committed real output and worked config, so a reviewer sees the product without
running anything.

| Path | What it is |
|---|---|
| `evidence/funnel.csv` | The triage funnel counts behind `docs/figures/triage-funnel.svg` (real, from trudesk) |
| `evidence/gate-summary.md` | The gate's own Markdown verdict for the trudesk audit |
| `evidence/scan-manifest.json` | Traceable summary: target SHA, tool versions, per-domain counts, EPSS escalations |
| `evidence/sbom-trudesk.cdx.json` | A real 1728-component CycloneDX 1.6 SBOM of the built image |
| `suppressions.example.yml` | Suppression file format (illustrative entries, not applied) |
| `policy.example.json` | Policy override format (mirrors the defaults) |

Regenerate the evidence from raw scans with `python scripts/build_evidence.py`
(invocation in the script header).
