# Feature map: format and rules

Source: the CorralSync feature map, Mike 2026-10-21. The map lets build, QA and security agents find a feature's code in one lookup. It is a set of paths, not a description of behaviour.

## Files

- `docs/feature-map.md`: the map, one file.
- `scripts/check_feature_map.py`: the check. It exits 1 when a covered file is not named in the map, or when a covered file changed after the synced-at marker.
- The `docs-sync` skill keeps the map current.

## Covered files

The `feature-map-covers` comment at the top of the map lists the glob patterns of the files that must appear in it. Set it when you scaffold the project. Example for a FastAPI and React app:

```
<!-- feature-map-covers: backend/app/api/**/*.py; backend/app/services/**/*.py; backend/app/models/*.py; frontend/src/pages/**/*.tsx -->
```

The check skips `__init__.py`, `*.test.*`, `*.spec.*` and anything under `__tests__/`. A path counts as named when the repo-relative path is in the map text. A covered file that is not a feature (a shared helper, a base class) goes in `## Not a feature` with a reason.

## Layout of docs/feature-map.md

1. The title, the two marker comments, and the line `Last synced: <YYYY-MM-DD> at <short sha>.`
2. `## How to use this map`: no more than 6 lines.
3. `## Index`: a table with the columns Feature | Area | One line | Section. Sort it by area, then by feature. Choose the areas for the project and keep them stable.
4. One section for each feature:

   ```
   ### <Feature name>
   <One sentence: what a user, the owner or the system does with it.>

   - Who: <roles that can use it; plan gate if any>
   - Pages: `<route>` -> `<page file>`
   - API: `<METHOD> <path>` -> `<file>:<function>` (every route, with the prefix applied)
   - Services: `<file>` (key functions)
   - Data: tables (model file); migrations that created or changed them
   - Settings: names of the env vars and settings that control it (names only)
   - Tests: test files that cover it
   - Docs: specs, tickets, work items
   - Verify: the minimum check after a change to this feature
   - Watch: 1-3 known traps, each with a link, only when one exists
   ```

   Leave out a line that has nothing in it. Never write "N/A".
5. `## Background jobs`: Job | Started in | Schedule | Lock | File.
6. `## Public (no login) routes`: every route that needs no authentication. Security reviews use this table.
7. `## Not a feature`: Path | Why.

## Rules

- Write only facts that you read in the code at the marker commit. If you cannot confirm a line, leave it out.
- Use plain words and short lines. Do not paste code.
- Never write a secret or real customer data. Write setting names only.
- Get the route list from the running app when you can, not only from the files.
- When you find a wrong path in the map, fix it in the same commit.

## When to update it

The `docs-sync` skill updates the map from every commit since the marker. Run it:
- before you mark a work item done (AGENTS.md, "Feature map");
- at prime-update, the end-of-session wrap-up.
