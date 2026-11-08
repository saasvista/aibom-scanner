#!/usr/bin/env python3
"""Check docs/feature-map.md against the code. Python 3 stdlib only.

Exit 1 (and print each problem) when:
- the map has no synced-at marker, or the marker is not a commit in this repo;
- the map has no covers patterns;
- a covered file is not named in the map (coverage);
- a covered file changed in a commit after the marker (the map is behind).

Exit 0 otherwise. It proves that each file is named and that the map is not behind.
It does not prove that a new route or setting got its own line: the docs-sync
skill does that. Format: _planning/feature-map-format.md.

Usage: python3 scripts/check_feature_map.py [--map docs/feature-map.md]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARKER = re.compile(r"<!--\s*feature-map-synced-at:\s*([0-9a-f]{40})\s*-->")
COVERS = re.compile(r"<!--\s*feature-map-covers:\s*(.*?)\s*-->")
SKIP_NAMES = {"__init__.py"}
SKIP_PARTS = {"__tests__", "node_modules"}
SKIP_SUFFIX = re.compile(r"\.(test|spec)\.[a-z]+$")


def skipped(rel: str) -> bool:
    p = Path(rel)
    return p.name in SKIP_NAMES or bool(SKIP_PARTS & set(p.parts)) or bool(SKIP_SUFFIX.search(p.name))


def covered_files(patterns: list[str]) -> list[str]:
    out: set[str] = set()
    for pat in patterns:
        for f in ROOT.glob(pat):
            rel = f.relative_to(ROOT).as_posix()
            if f.is_file() and not skipped(rel):
                out.add(rel)
    return sorted(out)


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)


def changed_since(marker: str, patterns: list[str]) -> list[str]:
    specs = [f":(glob){p}" for p in patterns]
    r = git("diff", "--name-only", f"{marker}..HEAD", "--", *specs)
    return sorted(f for f in r.stdout.split() if not skipped(f))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--map", default="docs/feature-map.md")
    args = ap.parse_args()
    path = ROOT / args.map
    if not path.is_file():
        print(f"FAIL: {args.map} not found")
        return 1
    text = path.read_text(encoding="utf-8")
    problems: list[str] = []

    m = COVERS.search(text)
    raw = m.group(1) if m and "[" not in m.group(1) else ""  # "[glob; ...]" = not filled in yet
    patterns = [p.strip() for p in raw.split(";") if p.strip()]
    if not patterns:
        problems.append("no covers patterns: set the feature-map-covers comment")

    marker_m = MARKER.search(text)
    marker = marker_m.group(1) if marker_m else ""
    if not marker:
        problems.append("no synced-at marker: set feature-map-synced-at to a full 40-char sha")
    elif git("cat-file", "-e", f"{marker}^{{commit}}").returncode != 0:
        problems.append(f"synced-at marker {marker[:12]} is not a commit in this repo")
        marker = ""

    if patterns:
        for rel in covered_files(patterns):
            if rel not in text:
                problems.append(f"not in map: {rel}")
        if marker:
            for rel in changed_since(marker, patterns):
                problems.append(f"changed after marker {marker[:12]}: {rel}")

    print(f"marker: {marker[:12] or '-'}  patterns: {len(patterns)}")
    for p in problems:
        print(f"FAIL: {p}")
    if problems:
        print(f"{len(problems)} problem(s). Run the docs-sync skill, feature map steps.")
        return 1
    print("feature map OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
