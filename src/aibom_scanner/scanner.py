"""Scan a directory for AI SDK usage, risks, and compliance gaps."""

import os
import stat
import subprocess
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


def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


def _get_file_tree(path: Path) -> list[str]:
    """Get file list — git ls-files for git repos, os.walk otherwise."""
    if _is_git_repo(path):
        try:
            result = subprocess.run(
                ["git", "ls-files", "-z"],
                cwd=str(path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="surrogateescape",
                timeout=30,
            )
            if result.returncode == 0 and result.stdout:
                return [p for p in result.stdout.split("\0") if p]
        except (subprocess.TimeoutExpired, FileNotFoundError, UnicodeDecodeError):
            pass

    # Fallback: os.walk
    files = []
    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".eggs", "dist", "build"}
    for root, dirs, filenames in os.walk(path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in filenames:
            rel = os.path.relpath(os.path.join(root, f), path)
            files.append(rel)
    return files


def _confined_files(root: Path, listing: list[str]) -> dict[str, int]:
    """Keep only regular files that sit inside the scan root.

    Drops absolute paths, '..' entries, symlinks, devices, FIFOs, sockets and
    missing paths, and anything whose real path leaves the resolved root. The
    listing comes from the scanned repository (a git index or the file system),
    so it is untrusted. Returns {relative path: lstat size} in listing order.
    """
    kept: dict[str, int] = {}
    for rel in listing:
        if not rel or os.path.isabs(rel) or ".." in rel.replace("\\", "/").split("/"):
            continue
        full = root / rel
        try:
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                continue
            if not full.resolve().is_relative_to(root):
                continue
        except (OSError, ValueError, RuntimeError):
            continue
        kept[rel] = st.st_size
    return kept


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


def build_coverage_report(file_paths: list[str], scanned_paths: list[str]) -> CoverageReport:
    """Measure how much of the repo's source the scanner could actually read.

    Separates the two reasons a source file was not read:
      - skipped_by_path: intentional exclusion (tests, fixtures, examples, vendor)
      - unscanned_by_extension: this scanner version cannot parse the language

    Every source file is attributed to exactly one bucket, so
    files_scanned + skipped_by_path + sum(unscanned_by_extension) == source_files_seen.

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

    for path in file_paths:
        ext = _source_extension(path)
        if ext is None:
            continue
        source_files_seen += 1
        if path in scanned:
            source_files_scanned += 1
        elif _is_path_skipped(path):
            skipped_by_path += 1
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
    )


def scan_directory(path: str | Path) -> ScanResult:
    """Scan a local directory for AI SDK usage and compliance risks.

    Returns a ScanResult with detections, risks, and control mappings.
    """
    path = Path(path).resolve()
    if not path.is_dir():
        raise ValueError(f"Not a directory: {path}")

    scan_start = datetime.now(timezone.utc).isoformat()
    sizes = _confined_files(path, _get_file_tree(path))
    files = list(sizes)

    all_detections: list[Detection] = []
    all_dep_detections: list[Detection] = []
    all_dev_tools: list[DevToolDetection] = []
    all_hardcoded = []
    all_mcp_servers: list[dict] = []
    all_tool_caps: list[dict] = []
    code_contexts: list[str] = []
    file_contents: dict[str, str] = {}
    files_scanned = 0
    files_with_detections = 0

    # Read .gitignore if present
    gitignore_content = None
    gitignore_path = path / ".gitignore"
    gitignore_files = _confined_files(path, [".gitignore"])
    if gitignore_files.get(".gitignore", MAX_SOURCE_BYTES + 1) <= MAX_SOURCE_BYTES:
        try:
            gitignore_content = gitignore_path.read_text(errors="ignore")
        except OSError:
            pass

    for rel_path in files:
        full_path = path / rel_path

        # Dev tool detection (by file path)
        dev_tools = detect_dev_tools(rel_path)
        all_dev_tools.extend(dev_tools)

        # MCP client configs: named files, or any .json file that mentions "mcpServers"
        if rel_path.lower().endswith(".json") and not _is_path_skipped(rel_path):
            try:
                if sizes[rel_path] <= MAX_JSON_BYTES:
                    all_mcp_servers.extend(scan_mcp_json(rel_path, full_path.read_text(errors="ignore")))
            except (OSError, PermissionError):
                pass

        if not should_scan_file(rel_path):
            continue

        if sizes[rel_path] > MAX_SOURCE_BYTES:
            continue

        try:
            content = full_path.read_text(errors="ignore")
        except (OSError, PermissionError):
            continue

        files_scanned += 1
        file_contents[rel_path] = content

        # Per-server MCP inventory (Python code; config files were handled above)
        if not is_mcp_config_path(rel_path):
            all_mcp_servers.extend(scan_mcp_file(rel_path, content))
        all_tool_caps.extend(scan_tool_imports(rel_path, content))

        # AI SDK detection
        detections = scan_file(rel_path, content)
        if detections:
            files_with_detections += 1
            all_detections.extend(detections)
            code_contexts.extend(d.code_snippet for d in detections if d.code_snippet)

        # Dependency scanning
        dep_detections = scan_dependencies(rel_path, content)
        all_dep_detections.extend(dep_detections)

        # Hardcoded key detection
        hardcoded = detect_hardcoded_keys(rel_path, content)
        all_hardcoded.extend(hardcoded)

    all_tool_caps.extend(mcp_capabilities(all_mcp_servers))

    # Batch secrets management detection (uses file paths + contents)
    all_secrets = detect_secrets_management(
        file_paths=files,
        file_contents=file_contents,
        gitignore_content=gitignore_content,
    )

    # Combine all secrets evidence
    combined_secrets = all_secrets + all_hardcoded

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

    coverage = build_coverage_report(files, list(file_contents))

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
        secrets=[{k: v for k, v in asdict(s).items() if k != "raw_value"} for s in combined_secrets],
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
