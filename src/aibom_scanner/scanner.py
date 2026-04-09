"""Scan a directory for AI SDK usage, risks, and compliance gaps."""

import os
import subprocess
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from aibom_scanner import __version__
from aibom_scanner.control_mapper import map_controls
from aibom_scanner.detectors.ai_sdk import (
    Detection,
    scan_dependencies,
    scan_file,
    should_scan_file,
)
from aibom_scanner.detectors.dev_tools import DevToolDetection, detect_dev_tools
from aibom_scanner.detectors.secrets import (
    detect_hardcoded_keys,
    detect_secrets_management,
)
from aibom_scanner.models import ScanResult
from aibom_scanner.risk_engine import classify_risks, consolidate_risks


def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


def _get_file_tree(path: Path) -> list[str]:
    """Get file list — git ls-files for git repos, os.walk otherwise."""
    if _is_git_repo(path):
        try:
            result = subprocess.run(
                ["git", "ls-files"],
                cwd=str(path),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().splitlines()
        except (subprocess.TimeoutExpired, FileNotFoundError):
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


def scan_directory(path: str | Path) -> ScanResult:
    """Scan a local directory for AI SDK usage and compliance risks.

    Returns a ScanResult with detections, risks, and control mappings.
    """
    path = Path(path).resolve()
    if not path.is_dir():
        raise ValueError(f"Not a directory: {path}")

    scan_start = datetime.now(timezone.utc).isoformat()
    files = _get_file_tree(path)

    all_detections: list[Detection] = []
    all_dep_detections: list[Detection] = []
    all_dev_tools: list[DevToolDetection] = []
    all_hardcoded = []
    code_contexts: list[str] = []
    file_contents: dict[str, str] = {}
    files_scanned = 0
    files_with_detections = 0

    # Read .gitignore if present
    gitignore_content = None
    gitignore_path = path / ".gitignore"
    if gitignore_path.is_file():
        try:
            gitignore_content = gitignore_path.read_text(errors="ignore")
        except OSError:
            pass

    for rel_path in files:
        full_path = path / rel_path

        # Dev tool detection (by file path)
        dev_tools = detect_dev_tools(rel_path)
        all_dev_tools.extend(dev_tools)

        if not should_scan_file(rel_path):
            continue

        try:
            content = full_path.read_text(errors="ignore")
        except (OSError, PermissionError):
            continue

        files_scanned += 1
        file_contents[rel_path] = content

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

    # Batch secrets management detection (uses file paths + contents)
    all_secrets = detect_secrets_management(
        file_paths=files,
        file_contents=file_contents,
        gitignore_content=gitignore_content,
    )

    # Combine all secrets evidence
    combined_secrets = all_secrets + all_hardcoded

    # Extract unique providers
    providers = list({d.provider for d in all_detections + all_dep_detections})

    # Risk classification
    raw_risks = classify_risks(
        detected_providers=providers,
        detections=all_detections,
        secrets_management=combined_secrets,
        code_contexts=code_contexts,
    )
    risks = consolidate_risks(raw_risks)

    # Control mapping
    control_mappings = map_controls(risks)

    scan_end = datetime.now(timezone.utc).isoformat()

    # Provider summary
    provider_counts: dict[str, int] = {}
    for d in all_detections + all_dep_detections:
        provider_counts[d.provider] = provider_counts.get(d.provider, 0) + 1

    return ScanResult(
        detections=[asdict(d) for d in all_detections],
        dependencies=[asdict(d) for d in all_dep_detections],
        dev_tools=[asdict(d) for d in all_dev_tools],
        secrets=[asdict(s) for s in combined_secrets],
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
