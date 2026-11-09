---
name: docs-sync
description: "Update the code graph, bring docs/feature-map.md up to date with every commit since its synced-at marker, then make the status and orientation docs match reality. Use at prime-update, before a work item is marked done, after a deploy, or when asked to sync the docs. Changes status claims and the feature map only, never decisions or rationale."
---

# docs-sync

Status docs fall behind what shipped, because people update them by hand. A heartbeat sees commit age. It does not see a recent doc whose claims are false. This skill finds and fixes that drift for this repo, and it keeps the feature map current, so agents can find code without searching.

Repeat the doc steps until a pass finds no drift. Stop after 3 reconcile passes and report what is left.

## Scope

In scope:
- Status claims: stage, milestone, next action, "shipped / not started" lines, queue item state, metric cells, and `Status:` headers in design docs.
- Orientation facts: host, port, URL, stack and deploy path in every `README.md`, the `docs/` index and the runbooks.
- `docs/feature-map.md` (see "Feature map").

Out of scope: decisions, intent and rationale; code comments; prose quality; files under `archive/`.

If you cannot tell whether a line is status or a decision, do not edit it. Flag it in the report.

## Order

Do the steps in this order. Each step uses the output of the step before it:

1. Update the code graph. It is the cheapest step, and the feature map uses it.
2. Update the feature map from the commits since its marker, with the graph as input.
3. Make the status and orientation docs match reality, with the map as input.

## Step 0: Is a pass needed?

A pass is needed when: there are commits since the feature map marker, a ticket closed, a deploy happened, or Mike asked. If none of these is true, report "clean" and stop.

## Step 1: Update the code graph

CodeGraph is the local code index (symbols, callers, callees, affected tests). Update it before you read any code:

```
codegraph sync .
```

It takes seconds. In a git worktree the CodeGraph MCP tools report "not indexed": use the shell CLI there (`codegraph explore`, `codegraph node`, `codegraph callers`), which finds the parent checkout's index. Explore can miss a symbol; confirm with `codegraph node <name>` or a grep.

If `.codegraph/` does not exist, the repo is not indexed: set it up (README of the agent scaffold, "CodeGraph"), or continue without the graph and say so in the report.

## Step 2: Feature map

`docs/feature-map.md` is how build, QA and security agents find code. The format and rules are in `_planning/feature-map-format.md`. The pass is not clean until the map covers every commit up to HEAD.

1. Run the check. It prints the synced-at marker and each covered file that changed after the marker:

   ```
   python3 scripts/check_feature_map.py
   ```

2. List the commits and the changed files since the marker:

   ```
   git log --oneline <marker>..HEAD
   ```

   ```
   git diff --name-status <marker>..HEAD
   ```

3. Use the graph to find what each change touches. Do not read whole files to find this:
   - `codegraph explore "<feature or route name>"`: the symbols, their source and the call paths.
   - `codegraph callers <symbol>`: the pages and routes that reach a changed service.
   - `codegraph affected <changed files>`: a cross-check only, never the source of a `Tests` line. It over-reports badly (806 files for one corralsync service, 2026-10-21). Name the tests that exercise the feature, then use `affected` to look for one you missed.
4. For each commit that adds or changes a feature, update the map:
   - Put new pages, routes, services, models, migrations, background jobs, settings and tests in the feature's section. For a new feature, add a section and an index row.
   - Remove or rename a path in the map when the code removed or renamed it.
   - Add a new route that needs no login to `## Public (no login) routes`.
   - Update the feature's `Verify` line when its checks changed.
   - Put the ticket or work-item number from the commit message in the `Docs` line. Do not copy the commit message.
5. A commit with no feature change (docs, tests only, tooling) needs no map edit.
6. Set the marker to the full sha of HEAD, and update the "Last synced" line.
7. Run the check again. It must exit 0. It proves only that each file is named and that no covered file changed after the marker. Step 4 is the real check that a new route or setting got its line.

## Step 3: Status and orientation docs

1. Get ground truth for this repo:
   - `git log --oneline -20`
   - `python3 /home/mike/proj/Big-Brain/scripts/ledger.py search --project aibom-scanner --include-closed`
   - Deploy state: a PyPI package plus a GitHub composite Action (`action.yml`). There is no server. A published GitHub release runs `.github/workflows/publish.yml`, which uploads to PyPI; a push to `main` deploys nothing. Live version: `pip index versions aibom-scanner`. The version must match in `pyproject.toml`, `src/aibom_scanner/__init__.py` and the `action.yml` pin.
   - Test gates: `PYTHONPATH=src pytest tests/ -q` (the CI and publish gate, `.github/workflows/ci.yml`, Python 3.10-3.12). This repo has no STATUS.md; doc surface: `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `docs/*.md`, `docs/diagram/README.md`, `action.yml` input descriptions.
   - The feature map: use it to check claims about what exists.
2. For each in-scope claim, compare it with ground truth. Make a list: file, section, claimed, actual.
3. Edit the smallest span that makes each claim true. Keep the format and the voice. Do not guess. If ground truth is not clear, flag the claim.
4. Dated records (story reports, audits, incident reports) describe the past. Do not rewrite them. Add `<!-- historical-record -->` and one line under the title that says what changed and which doc is current.
5. Read the edited docs again against ground truth. If you find new drift, go to step 3.

## Output

Report: the drift found in each doc (claimed, actual), what you changed, what you flagged for a human, and clean or dirty. Inside prime-update, put the doc fixes in that session's commit.
