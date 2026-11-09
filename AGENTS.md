# AGENTS.md - aibom-scanner

aibom-scanner is a zero-dependency Python CLI and GitHub Action that scans a codebase for AI SDK usage, MCP servers and agent tools, and maps the risks it finds to NIST AI RMF, ISO 42001, the EU AI Act and the OWASP LLM and Agentic Top 10.

## Stack and commands

- Stack: Python 3.10+ standard library only (runtime); pytest for tests; hatchling build.
- Test: `PYTHONPATH=src pytest tests/ -q`
- Run: `PYTHONPATH=src python -m aibom_scanner scan --path <dir>`
- Deploy: a published GitHub release runs `.github/workflows/publish.yml` and uploads to PyPI. A push to `main` deploys nothing. Releases need Mike.

## Feature map

`docs/feature-map.md` lists each feature with its entry points, services, data, settings, tests, a Verify line and known traps. Read it before you search the code. Format and rules: `_planning/feature-map-format.md`.

- Before you mark a work item done, run the `docs-sync` skill. Its feature map steps add your change to the map. Then `python3 scripts/check_feature_map.py` must exit 0.
- When you find a wrong path in the map, fix it in the same commit.

## Session lifecycle

`prime-update` at the close (`/prime-update` in Claude Code, `$prime-update` in Codex). Skills live in `.agents/skills/`; `.claude/skills/` holds symlinks to them. Add a new skill under `.agents/skills/<name>/`, then run `python3 ~/proj/Big-Brain/scripts/agent_parity.py init .` to link it for Claude.
