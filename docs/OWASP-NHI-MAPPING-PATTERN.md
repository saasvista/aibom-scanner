# Option: OWASP Non-Human Identities Top 10 (2025) Control Mapping

**Status:** Recorded option. Not proposed, not scheduled, not implemented.
**Recorded:** 2026-09-11
**Purpose:** Show that the in-repo control mapper is a proven pattern an OWASP NHI Top 10 mapping can copy, so the option is visible when it is decided.

## 1. The pattern already in this repo

aibom-scanner already maps scan findings to framework controls with a coverage model. Anchors (as of 1.2.0):

| Piece | Location | What it does |
|---|---|---|
| Framework tables | `src/aibom_scanner/control_mapper.py:8`, `:34`, `:52` | `NIST_AI_RMF` (23 controls), `ISO_42001` (15), `EU_AI_ACT` (11). Each entry: `control_id -> (label, description)` |
| Framework registry | `src/aibom_scanner/control_mapper.py:66` | `ALL_FRAMEWORKS` name -> table |
| Mapper | `src/aibom_scanner/control_mapper.py:73` | `map_controls(risks)` sets `MAPPED` / `PARTIAL` / `GAP` per control from risk `framework_refs`, `mitigation_status`, `evidence_qualifier` and hedging titles |
| Coverage model | `src/aibom_scanner/models.py:15`, `:22` | `CoverageStatus` enum and `ControlMapping` dataclass |
| Finding-to-control links | `src/aibom_scanner/risk_engine.py` rule dicts | each rule lists `framework_refs`, e.g. `["NIST-MANAGE-4.1", "ISO-42001-A.8.6", "EU-AI-ACT-ART-15"]` |
| Wiring | `src/aibom_scanner/scanner.py:213` | `control_mappings = map_controls(risks)` |
| Test | `tests/test_scanner.py:25` | `test_scan_produces_control_mappings` asserts mappings exist per framework |

## 2. What a copy would take

1. Add an `OWASP_NHI_TOP10` table to `control_mapper.py` with ids `OWASP-NHI-1` .. `OWASP-NHI-10` and the official 2025 titles.
2. Register it in `ALL_FRAMEWORKS`.
3. Append `OWASP-NHI-*` ids to `framework_refs` on the risk rules that produce NHI evidence. Edit per rule: `risk_engine.py:146` and `:155` carry identical ref lists, so a string replace links both.
4. Add tests: table present, ids resolve, `MAPPED` / `PARTIAL` / `GAP` behave for NHI controls.

No new models or CLI surface. Output reach differs by format (checked 2026-09-11 by running steps 1-3 in a throwaway copy; 207 existing tests still pass):

| Format | What shows | NHI result |
|---|---|---|
| JSON | full `control_mappings` | all 10 NHI controls with `MAPPED` / `PARTIAL` / `GAP` |
| SARIF | no `control_mappings`; rule `tags` from `framework_refs` (`formatters/sarif_fmt.py:42`) | linked ids only, e.g. `OWASP-NHI-2`; `GAP` controls absent |
| Table | no control-mapping section; `Frameworks:` shows the first 3 `framework_refs` (`formatters/table_fmt.py:50`) | an appended NHI id is not shown |

Showing NHI coverage in SARIF or table output needs formatter work.

## 3. Candidate links from existing rules

Official titles: https://owasp.github.io/www-project-non-human-identities-top-10/2025/

| NHI item | Existing signal | Coverage today |
|---|---|---|
| NHI1 Improper Offboarding | none | GAP |
| NHI2 Secret Leakage | "API keys potentially exposed in source code" + `detectors/secrets.py` hardcoded-key evidence | candidate |
| NHI3 Vulnerable Third-Party NHI | "AI dev tools may transmit code to external services" (weak) | candidate, weak |
| NHI4 Insecure Authentication | "MCP server exposes tools without governance controls" (auth on MCP endpoints) | candidate |
| NHI5 Overprivileged NHI | "AI agent tool use without access controls" | candidate |
| NHI6 Insecure Cloud Deployment Configurations | none | GAP |
| NHI7 Long-Lived Secrets | `_adjust_credential_risk` secrets-manager vs env-only evidence (no rotation signal) | candidate, partial |
| NHI8 Environment Isolation | none | GAP |
| NHI9 NHI Reuse | none | GAP |
| NHI10 Human Use of NHI | none | GAP |

These links are candidates for review, not decisions. Five items have no detection signal, so an honest first version reports them as `GAP`.

## 4. Cautions before publishing anything about this

1. **Absence claims need a clone and grep.** GitHub code search returned 0 hits for "AI RMF" against this repo, which names the framework in 10 files. Any claim that other tools lack an NHI mapping must be verified by cloning and grepping, not by code search.
2. **Credibility surface.** Shipping an NHI mapping is a public claim of coverage. Section 3 shows most items are GAP or weak today.
3. **Test depth.** No test calls `map_controls` directly. A copy should add unit tests for the mapper, not only the scan-level assertion.
