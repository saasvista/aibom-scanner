# aibom-scanner feature map
<!-- feature-map-synced-at: e6e292c529e6172218baf112f177971f13760316 -->
<!-- feature-map-covers: src/aibom_scanner/**/*.py; src/aibom_scanner/data/*.json; action.yml; .github/workflows/*.yml -->
Last synced: 2026-11-08 at `e6e292c`. Kept current by the docs-sync skill. Check: `python3 scripts/check_feature_map.py`. Format: `_planning/feature-map-format.md`.

## How to use this map

- Find the feature in the index, then go to its section.
- The "Verify" line is the minimum check after a change to that feature.
- When a path in the map is wrong, fix the map in the same commit.
- This is a CLI and a GitHub Action. It has no HTTP routes, pages, database or login. "API" lines name CLI flags and Python entry points.
- Pipeline: `scanner.py:scan_directory` lists files, runs each detector per file, then `risk_engine` -> `control_mapper` -> a formatter.

## Index

| Feature | Area | One line | Section |
|---|---|---|---|
| CLI scan command | Interface | `aibom-scanner scan`: flags, output format, exit codes | [CLI scan command](#cli-scan-command) |
| GitHub Action | Interface | Composite Action that installs the pinned release and runs a scan | [GitHub Action](#github-action) |
| File discovery and confinement | Scan | Lists files (git or os.walk) and refuses paths that leave the scan root | [File discovery and confinement](#file-discovery-and-confinement) |
| Coverage accounting | Scan | Reports what could not be read or analysed | [Coverage accounting](#coverage-accounting) |
| AI SDK and model detection | Detect | Finds AI SDK calls and model names in source | [AI SDK and model detection](#ai-sdk-and-model-detection) |
| Dependency detection | Detect | Finds AI packages in manifests (Python, JS, .NET) | [Dependency detection](#dependency-detection) |
| MCP server inventory | Detect | Lists MCP servers from config files and Python code | [MCP server inventory](#mcp-server-inventory) |
| Tool capability classes | Detect | Classifies agent tools and MCP servers by capability | [Tool capability classes](#tool-capability-classes) |
| Secrets management and hardcoded keys | Detect | Finds how secrets are loaded and flags hardcoded keys | [Secrets management and hardcoded keys](#secrets-management-and-hardcoded-keys) |
| AI dev tool detection | Detect | Flags AI coding tool config files by path | [AI dev tool detection](#ai-dev-tool-detection) |
| Risk classification | Assess | Turns detections into risk findings with framework refs | [Risk classification](#risk-classification) |
| Control mapping | Assess | Maps risks to NIST AI RMF, ISO 42001, EU AI Act, OWASP controls | [Control mapping](#control-mapping) |
| Output formatters | Output | JSON, table and SARIF output | [Output formatters](#output-formatters) |
| Release and versioning | Release | Version string and PyPI publish | [Release and versioning](#release-and-versioning) |

### CLI scan command
A developer or CI job runs `aibom-scanner scan --path <dir>` and gets a report plus an exit code.

- API: `aibom-scanner scan` -> `src/aibom_scanner/cli.py:main`, `_run_scan`; `python -m aibom_scanner` -> `src/aibom_scanner/__main__.py`; console script `aibom-scanner = aibom_scanner.cli:main` (`pyproject.toml`)
- Settings: flags `--path/-p` (required), `--format/-f` (`table|json|sarif`; default table on a TTY, json when piped), `--output/-o`, `--severity-threshold` (`low|medium|high|critical`), `--fail-on-incomplete-coverage`, `--version`
- Exit codes: 0 ok; 1 an observed finding at or above `--severity-threshold` (inferred findings are ignored); 2 bad path, no subcommand or interrupt; 3 incomplete coverage with `--fail-on-incomplete-coverage`
- Tests: `tests/test_cli.py`, `tests/test_cli_coverage.py`, `tests/test_run2_coverage.py`, `tests/test_unread_source.py`, `tests/test_scan_root_symlink.py`, `tests/test_table_control_chars.py`
- Verify: `PYTHONPATH=src pytest tests/test_cli.py tests/test_cli_coverage.py -q`
- Watch: coverage warnings go to stderr so piped JSON/SARIF stays valid (`cli.py:_run_scan`).

### GitHub Action
A repo workflow uses `saasvista/aibom-scanner` to scan and fail the job on findings.

- API: `action.yml` (composite): `pip install "aibom-scanner==<pin>"`, then `aibom-scanner scan`
- Settings: inputs `path`, `format` (default `sarif`), `severity-threshold` (default `high`), `fail-on-incomplete-coverage`; passed as env `INPUT_PATH`, `INPUT_FORMAT`, `INPUT_SEVERITY_THRESHOLD`, `INPUT_FAIL_ON_INCOMPLETE_COVERAGE`
- Tests: none in `tests/`; the publish workflow checks that the `action.yml` pin equals the tag
- Docs: `README.md`
- Verify: the pin in `action.yml` equals `version` in `pyproject.toml`
- Watch: the Action installs the pinned PyPI release, not the code in this repo, so an Action change ships only after a release.

### File discovery and confinement
The scanner lists the files to read and refuses anything that leaves the scan root.

- API: `src/aibom_scanner/scanner.py:scan_directory`
- Services: `src/aibom_scanner/scanner.py` (`_get_file_tree`: `git ls-files -z` inside a work tree, `os.walk` otherwise; `_git_argv` sets `core.fsmonitor=false` and `core.hooksPath=/dev/null`; `_confined_files` rejects symlinks and submodules; `MAX_SOURCE_BYTES`)
- Tests: `tests/test_tree_confinement.py`, `tests/test_scan_root_symlink.py`, `tests/test_git_fsmonitor.py`, `tests/test_git_nonascii.py`, `tests/test_scanner.py`
- Verify: `PYTHONPATH=src pytest tests/test_tree_confinement.py tests/test_scan_root_symlink.py tests/test_git_fsmonitor.py -q`
- Watch: a scan path below the working directory that resolves through a symlink raises `ValueError` (`scan_directory`).

### Coverage accounting
The report says how many source files were read and which inputs were not fully analysed.

- Services: `src/aibom_scanner/scanner.py` (`build_coverage_report`, `_source_extension`, `_is_path_skipped`; per-file detector failures are marked by `guarded` as `parse_error` or `analysis_incomplete`)
- Data: `src/aibom_scanner/models.py` (`CoverageReport`, `CoverageStatus`, `ScanResult`)
- Tests: `tests/test_coverage_accounting.py`, `tests/test_unread_source.py`, `tests/test_extension_coverage.py`, `tests/test_cli_coverage.py`, `tests/test_run2_coverage.py`, `tests/test_formatters_coverage.py`
- Verify: `PYTHONPATH=src pytest tests/test_coverage_accounting.py tests/test_unread_source.py -q`

### AI SDK and model detection
The scanner finds AI SDK imports and calls, and the model names near them, in source files.

- Services: `src/aibom_scanner/detectors/ai_sdk.py` (`scan_file`, `AI_SDK_PATTERNS`, `MODEL_PATTERNS`, `_extract_model_name`, `should_scan_file`, `is_skipped_path`, `classify_risk_tier`)
- Tests: `tests/test_ai_sdk_detector.py`, `tests/test_false_positives.py`, `tests/test_extension_coverage.py`, `tests/test_regex_cost.py`, `tests/test_snippet_redaction.py`
- Verify: `PYTHONPATH=src pytest tests/test_ai_sdk_detector.py tests/test_false_positives.py tests/test_regex_cost.py -q`
- Watch: `scan_hitl`, `scan_guardrails` and `scan_transparency` in `ai_sdk.py` are defined but not called anywhere in `src/` at this marker.

### Dependency detection
The scanner finds AI packages in dependency manifests.

- Services: `src/aibom_scanner/detectors/ai_sdk.py` (`scan_dependencies`, `DEPENDENCY_MAP`, `NUGET_DEPENDENCY_MAP`, `_toml_dependencies`, `_parse_requirement`)
- Tests: `tests/test_ai_sdk_detector.py`, `tests/test_dotnet_detection.py`, `tests/test_run2_detector_fixes.py`, `tests/test_false_positives.py`
- Verify: `PYTHONPATH=src pytest tests/test_dotnet_detection.py tests/test_run2_detector_fixes.py -q`

### MCP server inventory
The scanner lists each MCP server it finds, with transport, package, pin state and redacted args.

- Services: `src/aibom_scanner/detectors/mcp_servers.py` (`scan_mcp_json` and `scan_mcp_config` for config files with `mcpServers` or `servers` keys; `scan_mcp_python` / `_McpVisitor` for Python clients; `scan_mcp_file`; `compute_pinned`; `redact_args`; `server_package`; `MCP_SERVERS_NOTE`)
- Tests: `tests/test_mcp_servers.py`, `tests/test_mcp_line_lookup.py`, `tests/test_detector_robustness.py`
- Verify: `PYTHONPATH=src pytest tests/test_mcp_servers.py tests/test_mcp_line_lookup.py -q`
- Watch: args and env values are redacted; only names are kept (`redact_args`).

### Tool capability classes
The scanner classifies agent tools (Python imports) and MCP servers (package spec) into capability classes.

- Services: `src/aibom_scanner/detectors/tool_capabilities.py` (`scan_tool_imports`, `mcp_capabilities`, `capability_classes`, `load_data`; classes `untrusted_content_in`, `sensitive_data_access`, `external_side_effect`, `code_execution`, `model_call`)
- Data: `src/aibom_scanner/data/tool_capabilities.json` (python_tools data from splx-ai/agentic-radar, Apache-2.0; see `NOTICE`)
- Tests: `tests/test_tool_capabilities.py`, `tests/test_detector_robustness.py`
- Verify: `PYTHONPATH=src pytest tests/test_tool_capabilities.py -q`
- Watch: an MCP server whose package is not in the JSON table gets no classes; classes are never guessed from a name.

### Secrets management and hardcoded keys
The scanner finds how the repo loads secrets and flags hardcoded keys, with values masked.

- Services: `src/aibom_scanner/detectors/secrets.py` (`detect_secrets_management`, `detect_hardcoded_keys`, `mask_secrets`, `redact_key`)
- Tests: `tests/test_secrets_r2.py`, `tests/test_unquoted_credentials.py`, `tests/test_snippet_redaction.py`, `tests/test_regex_cost.py`
- Verify: `PYTHONPATH=src pytest tests/test_secrets_r2.py tests/test_unquoted_credentials.py tests/test_snippet_redaction.py -q`
- Watch: hardcoded keys are still checked in skipped paths (tests, examples, vendor) and reported with `skipped_path: true` (`scan_directory`); `raw_value` is dropped from output.

### AI dev tool detection
The scanner flags AI coding tool config files (Cursor, Copilot, Codeium, Tabnine, Aider, Continue, Claude Code) by path.

- Services: `src/aibom_scanner/detectors/dev_tools.py` (`detect_dev_tools`, `DEV_TOOL_INDICATORS`)
- Verify: `PYTHONPATH=src python3 -c "from aibom_scanner.detectors.dev_tools import detect_dev_tools as d; print(d(['.cursorrules']))"`
- Watch: `scan_directory` calls `detect_dev_tools(rel_path)` with one path string, not a list, so it loops over characters and no dev tool is ever reported in a scan (seen at this marker: a temp dir with `.cursorrules` and `CLAUDE.md` gave `dev_tools == []`). No test covers it.

### Risk classification
The engine turns detections into risk findings with severity, framework refs and an evidence basis.

- Services: `src/aibom_scanner/risk_engine.py` (`classify_risks`, `consolidate_risks`, `set_evidence_basis`, `RISK_RULES`, `RISK_IMPACT_METHODOLOGY`, `_capability_risk`, `_unpinned_mcp_risk`, `_code_execution_risk`, `_adjust_credential_risk`)
- Data: `src/aibom_scanner/models.py` (`Severity`, `RiskFinding`)
- Tests: `tests/test_risk_engine.py`, `tests/test_owasp_mappings.py`, `tests/test_evidence_basis.py`, `tests/test_mcp_servers.py`
- Verify: `PYTHONPATH=src pytest tests/test_risk_engine.py tests/test_owasp_mappings.py tests/test_evidence_basis.py -q`
- Watch: findings marked `inferred` (no supporting evidence) never trip `--severity-threshold` (`cli.py:_run_scan`).

### Control mapping
Each risk is mapped to framework controls with a coverage status.

- Services: `src/aibom_scanner/control_mapper.py` (`map_controls`; control tables for NIST AI RMF, ISO 42001, EU AI Act, OWASP LLM and Agentic Top 10)
- Data: `src/aibom_scanner/models.py` (`ControlMapping`, `CoverageStatus`)
- Tests: `tests/test_owasp_mappings.py`, `tests/test_scanner.py`
- Docs: `docs/OWASP-NHI-MAPPING-PATTERN.md` (OWASP NHI mapping, recorded option, not implemented)
- Verify: `PYTHONPATH=src pytest tests/test_owasp_mappings.py -q`

### Output formatters
The `ScanResult` is written as JSON, a terminal table or SARIF 2.1.0.

- Services: `src/aibom_scanner/formatters/json_fmt.py` (`format_json`, `neutralize_workflow_commands`), `src/aibom_scanner/formatters/table_fmt.py` (`format_table`, `_safe`, `INFERRED_PREAMBLE`), `src/aibom_scanner/formatters/sarif_fmt.py` (`format_sarif`, `_risk_location`, stable `ruleId` via `_slug`)
- Tests: `tests/test_formatters_coverage.py`, `tests/test_workflow_commands_and_sarif.py`, `tests/test_table_control_chars.py`, `tests/test_table_unicode_escape.py`, `tests/test_snippet_redaction.py`, `tests/test_mcp_servers.py`, `tests/test_tool_capabilities.py`
- Docs: `examples/sample-output.json`; `docs/SPDX-OUTPUT-SCOPE.md` (SPDX output, proposed, not implemented)
- Verify: `PYTHONPATH=src pytest tests/test_formatters_coverage.py tests/test_workflow_commands_and_sarif.py tests/test_table_control_chars.py -q`
- Watch: `##[` in scanned content is escaped in all three formats so it cannot forge GitHub Actions workflow commands (CHANGELOG 1.3.5). SARIF emits results for observed findings only.

### Release and versioning
A GitHub release publishes the package to PyPI.

- Services: `src/aibom_scanner/__init__.py` (`__version__`)
- Settings: `version` in `pyproject.toml`; the `action.yml` pin; GitHub environment `pypi` (trusted publishing, `id-token: write`)
- Tests: `tests/test_version.py`
- Docs: `CHANGELOG.md`
- Verify: tag, `pyproject.toml` version, `__version__` and the `action.yml` pin are equal (checked by `.github/workflows/publish.yml`)

## Background jobs

| Job | Started in | Schedule | Lock | File |
|---|---|---|---|---|
| CI tests (Python 3.10, 3.11, 3.12) | GitHub Actions | push and pull request to `main` | none | `.github/workflows/ci.yml` |
| Publish to PyPI | GitHub Actions | release published | environment `pypi` | `.github/workflows/publish.yml` |

## Public (no login) routes

None. This project serves no HTTP routes.

## Not a feature

| Path | Why |
|---|---|
| `docs/diagram/` | Builds the README pipeline diagram; not shipped |
