---
name: prime-update
description: "End-of-session update. Run before ending work."
---

End-of-session update for aibom-scanner. Run before ending work.

This repo has no STATUS.md or priority queue. Its state lives in `CHANGELOG.md`, `docs/feature-map.md` and the Big-Brain ledger.

## Step 1: Gather changes

```
date -u
git log --oneline --since="8 hours ago"
```

No commits -> widen to `--since="24 hours ago"`. Still none -> `git status --short`. Nothing changed -> report "No changes to record" and stop.

## Step 2: Categorize commits

Group commits by scope: `feat`, `fix`, `docs`, `refactor`, `ci`, `chore`, `chore(release)`.

## Step 3: Update CHANGELOG.md

Add user-visible `feat`, `fix` and security changes under a `## Unreleased` heading at the top (create it if missing), with the `### Security` / `### Fixed` subsections the released entries use. Do not edit released entries. The release commit renames the heading to `## <version> (<date>)`.

## Step 3b: Run docs-sync (orientation docs and the feature map)

Run the `docs-sync` skill. It makes the orientation docs (`README.md`, `docs/*.md`, `action.yml` input descriptions) match reality, and it brings `docs/feature-map.md` up to date with every commit since its synced-at marker.

This step is not done until this command exits 0:

```
python3 scripts/check_feature_map.py
```

Skip it on a no-op session.

## Step 4: Close completed Big-Brain work

- Find open work: `python3 ~/proj/Big-Brain/scripts/ledger.py search --project aibom-scanner`
- Close only what this session verifiably completed: `python3 ~/proj/Big-Brain/scripts/ledger.py close <id> --reason "Done in <sha>: <one line>."`
- Before you close a ticket for code work, bring the feature map up to date (Step 3b).
- Code work closes with glanceable proof (test output, command output). Docs work closes with a one-line "what I verified".

## Step 5: Commit

Gate first:

```
PYTHONPATH=src pytest tests/ -q          # gate: the CI test suite
python3 scripts/check_feature_map.py     # gate: exits 1 when the feature map misses a file or is behind
python3 ~/proj/Big-Brain/scripts/agent_parity.py check .   # gate: exits 1 on Claude/Codex harness drift
```

```
git add CHANGELOG.md docs/feature-map.md [other files by name]
git commit -m "docs(ops): prime-update - [1-line summary of session work]"
```

Add files by name, no `git add .`. A push to `main` deploys nothing; publishing happens only from a GitHub release (`.github/workflows/publish.yml`), which needs Mike.

## Output format

```
## Prime Update - YYYY-MM-DD

### Session Summary
[2-3 sentences]

### Changes Recorded
- CHANGELOG.md: [entries] or [no changes needed]
- docs-sync: [clean | drift fixed | flagged]

### Commit
[hash and message]
```

$ARGUMENTS
