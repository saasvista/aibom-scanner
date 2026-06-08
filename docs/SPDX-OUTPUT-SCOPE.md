# Scope: SPDX Output Format for aibom-scanner

**Status:** Proposed (scope only, not yet implemented)
**Author:** scoped 2026-06-08
**Target version:** 1.1.0
**Tracking:** README "New output formats" contribution item (CycloneDX, SPDX, HTML reports)

## 1. Why

CycloneDX and SPDX are the two de facto AIBOM serialization formats. Every comparable tool emits at least one. Cisco AI Defense's open-source `aibom` (the closest competitor, shipped 2026-02-10) outputs **SPDX 3.0 with the AI and Dataset profiles** plus CycloneDX 1.6. aibom-scanner currently emits only `table`, `json`, and `sarif`. SPDX output closes the single largest credibility gap versus the field: it makes scan results consumable by SPDX-native supply-chain tooling and aligns with the CISA "SBOM for AI" direction.

This scope covers **SPDX only**. CycloneDX is a separate, parallel effort (similar shape, different schema) and is out of scope here.

## 2. Constraints (non-negotiable, inherited from the codebase)

1. **Zero runtime dependencies.** `pyproject.toml` declares `dependencies = []`. The SPDX formatter must use the standard library only (`json`). SPDX 3.0 serializes as JSON-LD, which is plain JSON plus a `@context`, so this is achievable without a dependency. Any SPDX library is dev/test-only, never runtime.
2. **Python 3.10+** (`requires-python = ">=3.10"`).
3. **Formatter contract.** Match the existing pattern exactly: one module `src/aibom_scanner/formatters/spdx_fmt.py` exposing `format_spdx(result: ScanResult) -> str` that returns a serialized string. No I/O inside the formatter (the CLI prints).
4. **No new CLI surface beyond a format choice.** Add `"spdx"` to the existing `--format` choices and one dispatch branch. Do not restructure the CLI.

## 3. Format decision: SPDX 3.0 AI Profile (primary)

| Option | Pros | Cons | Decision |
|---|---|---|---|
| **SPDX 3.0 + AI Profile + Dataset Profile** | Matches Cisco's output; native AI model fields (`ai_safetyRiskAssessment`, `ai_standardCompliance`); current direction of the standard | New model (Element/Relationship graph, JSON-LD); fewer mature validators | **Primary target** |
| SPDX 2.3 (tag-value or JSON) | Simplest; most mature validators | No AI profile; cannot express model/compliance richness; reads as dated | Fallback only if 3.0 proves too costly |

Recommendation: build **SPDX 3.0 AI Profile** output. It is the version that makes the AIBOM claim real and reaches parity with the competition. If 3.0 stalls during implementation, 2.3-JSON is the documented fallback, but it should not ship as the headline.

## 4. Data mapping: `ScanResult` to SPDX 3.0

The current `ScanResult` model (`src/aibom_scanner/models.py`) carries: `detections`, `dependencies`, `dev_tools`, `secrets`, `guardrails`, `transparency`, `hitl`, `risks`, `control_mappings`, `summary`, `metadata`. Detection dicts expose `provider`, `sdk_name`, `file_path`, `line_number`, `detection_type`, and (when found) `model_name`.

Proposed SPDX 3.0 element graph:

| Source data | SPDX element | Notes |
|---|---|---|
| The scanned project (from `metadata`) | one root `software_Sbom` + `software_Package` | `rootElement` of the document |
| Required document header | `CreationInfo` + `SpdxDocument` | `createdBy` a `Tool` agent named `aibom-scanner` at `__version__`; **`created` timestamp must be passed in, not generated inside the formatter** (see Open Questions) |
| Each detected SDK / dependency (`detections`, `dependencies`) | `software_Package` | one per unique `provider`+`sdk_name`; `software_dependsOn` Relationship from the root package |
| Each distinct detected model (`model_name`) | `ai_AIPackage` | `Relationship` `dependsOn` / `ai_` usage from the codebase; populate AI-profile fields below |
| `risks` severity | `ai_safetyRiskAssessment` | map `critical`/`high` to `serious`/`high`, `medium`/`low` to `medium`/`low` (SPDX enum: serious, high, medium, low) |
| `control_mappings` frameworks | `ai_standardCompliance` | distinct framework names (NIST AI RMF, ISO 42001, EU AI Act) |
| `risks` and unmapped findings | `Annotation` elements | SPDX core does not model risk findings natively; attach as `Annotation` (review type) on the relevant package so nothing is silently dropped |
| `file_path` + `line_number` | `software_Snippet` (optional, phase 2) | precise location; defer to keep phase 1 small |

**Known modeling gap to call out honestly:** SPDX is asset-inventory-centric. aibom-scanner's differentiated value (risk rules, compliance control coverage) only partially maps, via the AI Profile's `ai_safetyRiskAssessment` and `ai_standardCompliance` fields plus `Annotation`. The full 34-risk-rule / 48-control detail does not round-trip into SPDX. That is expected and is a property of the standard, not a defect. JSON remains the lossless format; SPDX is the interchange format.

## 5. Implementation plan

1. **`src/aibom_scanner/formatters/spdx_fmt.py`**: `format_spdx(result: ScanResult) -> str`. Build the element list (CreationInfo, SpdxDocument, root Sbom/Package, per-SDK Packages, per-model AIPackages, Relationships, Annotations), wrap in the SPDX 3.0 JSON-LD envelope (`@context` pointing at the SPDX 3.0 context URL, `@graph` array), `json.dumps(..., indent=2)`. Stdlib only. Estimated 150-250 lines.
2. **SpdxId scheme**: deterministic URIs, e.g. `https://spdx.org/spdxdocs/aibom-scanner/<run-id>/<element-type>-<slug>`. Must be stable for a given input (no randomness) so output is diffable and reproducible.
3. **CLI wiring** (`src/aibom_scanner/cli.py`): import `format_spdx`; add `"spdx"` to the `--format` `choices` list (currently `["table", "json", "sarif"]`); add `elif fmt == "spdx": output = format_spdx(result)`. Three edits.
4. **Tests** (`tests/`): match the existing 43-test bar. Cover: document validity (parses as JSON, has `@context` and `@graph`), required CreationInfo present, one Package per unique SDK, AIPackage emitted per model, severity-to-`ai_safetyRiskAssessment` mapping, framework-to-`ai_standardCompliance` mapping, empty-scan edge case, deterministic SpdxId output. Target 8-12 tests.
5. **Schema validation in CI (dev-only)**: validate sample output against the SPDX 3.0 JSON schema using a dev dependency (e.g. `check-jsonschema` or the SPDX online validator in a manual step). Pin the schema file in `tests/fixtures/`. This dependency lives in a dev/optional extra, never in runtime `dependencies`.
6. **Docs**: README moves SPDX from "contribution opportunities" to the supported-formats list and add a usage example (`aibom-scanner scan . --format spdx`). CHANGELOG: new entry. CONTRIBUTING: note CycloneDX is still open.
7. **Version bump**: `1.0.0` to `1.1.0` (additive feature, semver minor) in `pyproject.toml` and `__init__.py`.

## 6. Acceptance criteria

- `aibom-scanner scan <dir> --format spdx` emits SPDX 3.0 JSON-LD with a valid `CreationInfo`, exactly one root element, and a connected Relationship graph.
- Output validates against the SPDX 3.0 JSON schema in CI.
- Every detected SDK appears as a `software_Package`; every detected model appears as an `ai_AIPackage` with `ai_safetyRiskAssessment` and `ai_standardCompliance` populated when corresponding risk/control data exists.
- Identical input produces byte-identical output (deterministic SpdxIds, no embedded wall-clock unless supplied).
- Runtime dependency count remains zero.
- New tests pass; existing 43 tests still pass.

## 7. Effort and risk

- **Effort:** roughly 1 to 2 focused days including schema validation and tests. The formatter itself is the bulk; CLI wiring is trivial.
- **Primary risk:** SPDX 3.0 model fidelity. The Element/Relationship/JSON-LD structure is more involved than SARIF. Mitigation: validate early against the official 3.0 schema and a sample fixture before wiring deep field mappings.
- **Secondary risk:** the risk/compliance data not fully round-tripping (see section 4). Mitigation: document the lossy mapping in the README so consumers know JSON is canonical.

## 8. Open questions (decisions needed before build)

1. **Timestamp source.** Formatters must stay pure and deterministic, but SPDX `CreationInfo.created` wants a real timestamp. Pass `created` in through `ScanResult.metadata` (set once by the scanner/CLI), or accept it as a `format_spdx(result, created=...)` argument. Decision needed; recommend `metadata["scan_started_at"]` so all formatters can share it.
2. **3.0 vs 2.3 commitment.** Confirm SPDX 3.0 AI Profile is the target (recommended) and 2.3 is fallback-only.
3. **Snippet-level locations.** Include `software_Snippet` with file/line in phase 1, or defer to phase 2? Recommend defer; keep phase 1 to Packages, AIPackages, Relationships, Annotations.
4. **Dataset Profile.** aibom-scanner does not currently detect training datasets. Emit `dataset_DatasetPackage` only if/when dataset detection exists, or stub it now? Recommend omit until there is data to populate it (no empty stubs).
