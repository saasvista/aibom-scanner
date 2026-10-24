"""Scan a directory for AI SDK usage, risks, and compliance gaps."""

import os
import stat
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from aibom_scanner import __version__
from aibom_scanner.control_mapper import map_controls
from aibom_scanner.detectors.ai_sdk import (
    SCANNABLE_EXTENSIONS,
    SOURCE_EXTENSIONS,
    Detection,
    is_skipped_path,
    scan_dependencies,
    scan_file,
    should_scan_file,
)
from aibom_scanner.detectors.dev_tools import DevToolDetection, detect_dev_tools
from aibom_scanner.detectors.mcp_servers import (
    MAX_JSON_BYTES,
    MCP_SERVERS_NOTE,
    is_mcp_config_path,
    scan_mcp_file,
    scan_mcp_json,
)
from aibom_scanner.detectors.tool_capabilities import (
    capability_classes,
    mcp_capabilities,
    scan_tool_imports,
)
from aibom_scanner.detectors.secrets import (
    detect_hardcoded_keys,
    detect_secrets_management,
)
from aibom_scanner.models import CoverageReport, ScanResult
from aibom_scanner.risk_engine import classify_risks, consolidate_risks, set_evidence_basis


MAX_SOURCE_BYTES = 1_000_000


# The scanned repository controls .git/config. Switch off the config keys that
# make git run a program named in it (a file system monitor, hooks).
_GIT_SAFE_ARGS = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]


def _git_argv(*args: str) -> list[str]:
    return ["git", *_GIT_SAFE_ARGS, *args]


_WALK_PRUNE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".eggs", "dist", "build"}


def _inside_work_tree(path: Path) -> bool:
    """True when path is inside a git work tree (the repo root or a subdirectory)."""
    try:
        result = subprocess.run(
            _git_argv("rev-parse", "--is-inside-work-tree"),
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def _get_file_tree(path: Path) -> tuple[list[str], str, set[str]]:
    """List files under path: git ls-files inside a git work tree, os.walk otherwise.

    Returns (relative paths, listing mode "git" or "walk", pruned). In walk mode
    the source files below directories the walk does not scan (node_modules,
    venv, build, ...) are still listed and returned in `pruned`, so the coverage
    report counts them as skipped instead of dropping them silently.
    """
    if _inside_work_tree(path):
        try:
            result = subprocess.run(
                _git_argv("ls-files", "-z"),
                cwd=str(path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="surrogateescape",
                timeout=30,
            )
            if result.returncode == 0 and result.stdout:
                return [p for p in result.stdout.split("\0") if p], "git", set()
        except (subprocess.TimeoutExpired, FileNotFoundError, UnicodeDecodeError):
            pass

    print(
        f"notice: {path} has no tracked files in a git work tree; "
        "listing files with os.walk (build, dist, venv and node_modules source files count as skipped)",
        file=sys.stderr,
    )
    files: list[str] = []
    pruned: set[str] = set()
    pruned_roots: list[str] = []
    for root, dirs, filenames in os.walk(path):
        keep = []
        for d in dirs:
            if d == ".git":
                continue
            if d in _WALK_PRUNE_DIRS:
                pruned_roots.append(os.path.join(root, d))
            else:
                keep.append(d)
        dirs[:] = keep
        for f in filenames:
            files.append(os.path.relpath(os.path.join(root, f), path))
    for top in pruned_roots:
        for root, dirs, filenames in os.walk(top):
            dirs[:] = [d for d in dirs if d != ".git"]
            for f in filenames:
                rel = os.path.relpath(os.path.join(root, f), path)
                if _source_extension(rel):
                    files.append(rel)
                    pruned.add(rel)
    return files, "walk", pruned


def _confined_files(root: Path, listing: list[str]) -> tuple[dict[str, int], dict[str, str]]:
    """Keep only regular files that sit inside the scan root.

    Drops absolute paths, '..' entries, symlinks, devices, FIFOs, sockets and
    missing paths, and anything whose real path leaves the resolved root. The
    listing comes from the scanned repository (a git index or the file system),
    so it is untrusted. Returns ({relative path: lstat size} in listing order,
    {rejected relative path: reason}). A reason is "symlink", "not_regular_file"
    or "submodule" (a directory in the listing is a git gitlink). Entries that
    are missing on disk are dropped without a reason.
    """
    kept: dict[str, int] = {}
    rejected: dict[str, str] = {}
    for rel in listing:
        if not rel:
            continue
        if os.path.isabs(rel) or ".." in rel.replace("\\", "/").split("/"):
            rejected[rel] = "not_regular_file"
            continue
        full = root / rel
        try:
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                rejected[rel] = "symlink"
                continue
            if stat.S_ISDIR(st.st_mode):
                rejected[rel] = "submodule"
                continue
            if not stat.S_ISREG(st.st_mode):
                rejected[rel] = "not_regular_file"
                continue
            if not full.resolve().is_relative_to(root):
                rejected[rel] = "symlink"
                continue
        except (OSError, ValueError, RuntimeError):
            continue
        kept[rel] = st.st_size
    return kept, rejected


def _source_extension(file_path: str) -> str | None:
    """Return the SOURCE_EXTENSIONS extension of a path, or None if not source."""
    lower = file_path.lower()
    for ext in SOURCE_EXTENSIONS:
        if lower.endswith(ext):
            return ext
    return None


def _is_path_skipped(file_path: str) -> bool:
    """True when a file is excluded for being test/fixture/example/vendor code."""
    return is_skipped_path(file_path)


def build_coverage_report(
    file_paths: list[str],
    scanned_paths: list[str],
    pruned: set[str] | None = None,
    incomplete_inputs: dict[str, int] | None = None,
    listing_mode: str = "git",
) -> CoverageReport:
    """Measure how much of the repo's source the scanner could actually read.

    Separates the two reasons a source file was not read:
      - skipped_by_path: intentional exclusion (tests, fixtures, examples, vendor)
      - unscanned_by_extension: this scanner version cannot parse the language

    Every source file is attributed to exactly one bucket, so
    files_scanned + skipped_by_path + sum(unscanned_by_extension) == source_files_seen.

    pruned lists paths from directories the os.walk fallback does not scan; they
    count as skipped_by_path. skipped_paths carries up to 100 of those paths.

    unread_source_files is a view inside unscanned_by_extension: the files whose
    extension the scanner does support but that were still not read (too large,
    unreadable, or rejected by should_scan_file). They stay counted in
    unscanned_by_extension too, so the invariant above holds.
    """
    scanned = set(scanned_paths)
    source_files_seen = 0
    source_files_scanned = 0
    skipped_by_path = 0
    unscanned_by_extension: dict[str, int] = {}
    unread_source_files: dict[str, int] = {}
    skipped_paths: list[str] = []
    pruned = pruned or set()

    for path in file_paths:
        ext = _source_extension(path)
        if ext is None:
            continue
        source_files_seen += 1
        if path in scanned:
            source_files_scanned += 1
        elif path in pruned or _is_path_skipped(path):
            skipped_by_path += 1
            skipped_paths.append(path)
        else:
            unscanned_by_extension[ext] = unscanned_by_extension.get(ext, 0) + 1
            if ext in SCANNABLE_EXTENSIONS:
                unread_source_files[ext] = unread_source_files.get(ext, 0) + 1

    readable = source_files_seen - skipped_by_path
    coverage_pct = round((source_files_scanned / source_files_seen) * 100, 1) if source_files_seen > 0 else 0.0
    readable_coverage_pct = round((source_files_scanned / readable) * 100, 1) if readable > 0 else 0.0

    unsupported_languages = sorted(
        ext for ext in unscanned_by_extension if ext not in SCANNABLE_EXTENSIONS
    )

    return CoverageReport(
        files_in_tree=len(file_paths),
        source_files_seen=source_files_seen,
        files_scanned=source_files_scanned,
        skipped_by_path=skipped_by_path,
        unscanned_by_extension=unscanned_by_extension,
        coverage_pct=coverage_pct,
        readable_coverage_pct=readable_coverage_pct,
        unsupported_languages=unsupported_languages,
        unread_source_files=unread_source_files,
        incomplete_inputs=dict(incomplete_inputs or {}),
        listing_mode=listing_mode,
        skipped_paths=sorted(skipped_paths)[:100],
    )


def scan_directory(path: str | Path) -> ScanResult:
    """Scan a local directory for AI SDK usage and compliance risks.

    Returns a ScanResult with detections, risks, and control mappings.
    """
    # Anchor at the real working directory. A path below it that resolves to a
    # different place goes through a symlink (maybe one the scanned repository
    # committed), so refuse it. Paths outside the working directory are the
    # operator's choice and stay as given.
    base = Path(os.path.realpath(os.getcwd()))
    lexical = Path(os.path.normpath(os.path.join(base, path)))
    resolved = lexical.resolve()
    if lexical.is_relative_to(base) and resolved != lexical:
        raise ValueError(f"Scan path contains a symlink: {lexical}")
    path = resolved
    if not path.is_dir():
        raise ValueError(f"Not a directory: {path}")

    scan_start = datetime.now(timezone.utc).isoformat()
    listing, listing_mode, pruned = _get_file_tree(path)
    sizes, rejected = _confined_files(path, listing)
    files = list(sizes)
    pruned &= set(files)

    # reason -> paths of inputs that were not fully analysed (counted once per path)
    flagged: dict[str, set[str]] = {}

    def flag(reason: str, rel: str) -> None:
        flagged.setdefault(reason, set()).add(rel)

    for rel, reason in rejected.items():
        if reason == "submodule" or _source_extension(rel):
            flag(reason, rel)

    def guarded(rel: str, detector, *args) -> list:
        """Run one detector on one file. A failure marks the file, never the scan."""
        try:
            return detector(*args)
        except RecursionError as e:
            flag("analysis_incomplete", rel)
            partial = getattr(e, "partial", [])
            return partial if isinstance(partial, list) else []
        except Exception:
            flag("parse_error", rel)
            return []

    all_detections: list[Detection] = []
    all_dep_detections: list[Detection] = []
    all_dev_tools: list[DevToolDetection] = []
    all_hardcoded = []
    skipped_hardcoded = []
    all_mcp_servers: list[dict] = []
    all_tool_caps: list[dict] = []
    code_contexts: list[str] = []
    file_contents: dict[str, str] = {}
    files_scanned = 0
    files_with_detections = 0

    # Read .gitignore if present
    gitignore_content = None
    gitignore_path = path / ".gitignore"
    gitignore_files, _ = _confined_files(path, [".gitignore"])
    if gitignore_files.get(".gitignore", MAX_SOURCE_BYTES + 1) <= MAX_SOURCE_BYTES:
        try:
            gitignore_content = gitignore_path.read_text(errors="ignore")
        except OSError:
            pass

    for rel_path in files:
        if rel_path in pruned:
            continue
        full_path = path / rel_path

        # Dev tool detection (by file path)
        dev_tools = detect_dev_tools(rel_path)
        all_dev_tools.extend(dev_tools)

        # MCP client configs: named files, or any .json file that mentions "mcpServers"
        if rel_path.lower().endswith(".json") and not _is_path_skipped(rel_path):
            try:
                if sizes[rel_path] <= MAX_JSON_BYTES:
                    all_mcp_servers.extend(
                        guarded(rel_path, scan_mcp_json, rel_path, full_path.read_text(errors="ignore"))
                    )
                elif is_mcp_config_path(rel_path) or should_scan_file(rel_path):
                    flag("too_large", rel_path)
            except (OSError, PermissionError):
                if is_mcp_config_path(rel_path) or should_scan_file(rel_path):
                    flag("parse_error", rel_path)

        is_source = _source_extension(rel_path) is not None

        if not should_scan_file(rel_path):
            # Source files in skipped paths (tests, examples, vendor) are not
            # analysed, but a hardcoded key in them is still a leak.
            if (
                _source_extension(rel_path) in SCANNABLE_EXTENSIONS
                and _is_path_skipped(rel_path)
                and sizes[rel_path] <= MAX_SOURCE_BYTES
            ):
                try:
                    skipped_content = full_path.read_text(errors="ignore")
                except (OSError, PermissionError):
                    continue
                skipped_hardcoded.extend(
                    guarded(rel_path, detect_hardcoded_keys, rel_path, skipped_content)
                )
            continue

        if sizes[rel_path] > MAX_SOURCE_BYTES:
            if not is_source:
                flag("too_large", rel_path)
            continue

        try:
            content = full_path.read_text(errors="ignore")
        except (OSError, PermissionError):
            if not is_source:
                flag("parse_error", rel_path)
            continue

        files_scanned += 1
        file_contents[rel_path] = content

        # Per-server MCP inventory (Python code; config files were handled above)
        if not is_mcp_config_path(rel_path):
            all_mcp_servers.extend(guarded(rel_path, scan_mcp_file, rel_path, content))
        all_tool_caps.extend(guarded(rel_path, scan_tool_imports, rel_path, content))

        # AI SDK detection
        detections = guarded(rel_path, scan_file, rel_path, content)
        if detections:
            files_with_detections += 1
            all_detections.extend(detections)
            code_contexts.extend(d.code_snippet for d in detections if d.code_snippet)

        # Dependency scanning
        dep_detections = guarded(rel_path, scan_dependencies, rel_path, content)
        all_dep_detections.extend(dep_detections)

        # Hardcoded key detection
        hardcoded = guarded(rel_path, detect_hardcoded_keys, rel_path, content)
        all_hardcoded.extend(hardcoded)

    all_tool_caps.extend(mcp_capabilities(all_mcp_servers))

    # Batch secrets management detection (uses file paths + contents)
    all_secrets = detect_secrets_management(
        file_paths=[f for f in files if f not in pruned and not _is_path_skipped(f)],
        file_contents=file_contents,
        gitignore_content=gitignore_content,
    )

    # Combine all secrets evidence
    combined_secrets = all_secrets + all_hardcoded + skipped_hardcoded

    # Extract unique providers (detections are Detection objects, deps are dicts)
    providers = list(
        {d.provider for d in all_detections}
        | {d["provider"] for d in all_dep_detections if isinstance(d, dict)}
    )

    # Risk classification
    raw_risks = classify_risks(
        # a configured MCP server counts as MCP detected, even with no MCP import
        detected_providers=providers + (['mcp'] if all_mcp_servers and 'mcp' not in providers else []),
        detections=all_detections,
        secrets_management=combined_secrets,
        code_contexts=code_contexts,
        mcp_servers=all_mcp_servers,
        tool_capabilities=all_tool_caps,
        mcp_config_only=bool(all_mcp_servers) and not providers,
    )
    risks = consolidate_risks(raw_risks)
    set_evidence_basis(risks)

    # Control mapping
    control_mappings = map_controls(risks)

    scan_end = datetime.now(timezone.utc).isoformat()

    coverage = build_coverage_report(
        files,
        list(file_contents),
        pruned=pruned,
        incomplete_inputs={r: len(p) for r, p in sorted(flagged.items()) if p},
        listing_mode=listing_mode,
    )

    # Provider summary
    provider_counts: dict[str, int] = {}
    for d in all_detections:
        provider_counts[d.provider] = provider_counts.get(d.provider, 0) + 1
    for d in all_dep_detections:
        prov = d["provider"] if isinstance(d, dict) else d.provider
        provider_counts[prov] = provider_counts.get(prov, 0) + 1

    return ScanResult(
        detections=[asdict(d) for d in all_detections],
        dependencies=all_dep_detections,  # already dicts from scan_dependencies
        dev_tools=[asdict(d) for d in all_dev_tools],
        secrets=[{k: v for k, v in asdict(s).items() if k != "raw_value"} for s in all_secrets + all_hardcoded]
        + [
            {**{k: v for k, v in asdict(s).items() if k != "raw_value"}, "skipped_path": True}
            for s in skipped_hardcoded
        ],
        mcp_servers=all_mcp_servers,
        tool_capabilities=all_tool_caps,
        risks=[_serialize_risk(r) for r in risks],
        control_mappings=[
            {
                "framework": m.framework,
                "control_id": m.control_id,
                "control_name": m.control_name,
                "status": m.status.value,
                "notes": m.notes,
            }
            for m in control_mappings
        ],
        summary={
            "providers": provider_counts,
            "total_detections": len(all_detections),
            "total_dependencies": len(all_dep_detections),
            "total_dev_tools": len(all_dev_tools),
            "total_mcp_servers": len(all_mcp_servers),
            "mcp_servers_note": MCP_SERVERS_NOTE,
            "capability_classes": capability_classes(all_tool_caps),
            "files_scanned": files_scanned,
            "files_with_detections": files_with_detections,
            "risk_counts": _count_severities(risks),
        },
        metadata={
            "scanner_version": __version__,
            "scan_start": scan_start,
            "scan_end": scan_end,
            "path": str(path),
        },
        coverage=coverage,
    )


def _serialize_risk(risk: dict) -> dict:
    """Serialize a risk dict, converting enums to strings."""
    result = dict(risk)
    if hasattr(result.get("severity"), "value"):
        result["severity"] = result["severity"].value
    return result


def _count_severities(risks: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in risks:
        sev = r.get("severity", "medium")
        if hasattr(sev, "value"):
            sev = sev.value
        counts[sev] = counts.get(sev, 0) + 1
    return counts
